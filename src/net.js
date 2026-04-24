import { Agent, setGlobalDispatcher } from "undici";
import { CONFIG } from "./config.js";
import { logScan } from "./log.js";
import { profStart, profEnd } from "./profile.js";
import { getPool } from "./endpoints.js";

setGlobalDispatcher(new Agent({
  connections: 32,
  keepAliveTimeout: 30_000,
  keepAliveMaxTimeout: 60_000,
  pipelining: 1,
  headersTimeout: 30_000,
  bodyTimeout: 60_000,
}));

export const RETRY = {
  maxAttempts: (CONFIG.retry && CONFIG.retry.maxAttempts) || 8,
  baseDelayMs: (CONFIG.retry && CONFIG.retry.baseDelayMs) || 500,
  maxDelayMs:  (CONFIG.retry && CONFIG.retry.maxDelayMs) || 30000,
  timeoutMs:   (CONFIG.retry && CONFIG.retry.timeoutMs) || 30000,
};

export const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

export const REQ_STATS = { total: 0, lastReset: Date.now(), windowCount: 0 };
function _bumpReq() { REQ_STATS.total++; REQ_STATS.windowCount++; }

export function reqRatePerSec() {
  const now = Date.now();
  const dtSec = Math.max(0.001, (now - REQ_STATS.lastReset) / 1000);
  const r = REQ_STATS.windowCount / dtSec;
  REQ_STATS.windowCount = 0;
  REQ_STATS.lastReset = now;
  return r;
}

const _rateBuckets = new Map();

function _getBucket(host, ratePerSec) {
  if (!ratePerSec || ratePerSec <= 0) return null;
  let b = _rateBuckets.get(host);
  if (!b || b.capacity !== ratePerSec) {
    b = { tokens: ratePerSec, last: Date.now(), capacity: ratePerSec, refillPerMs: ratePerSec / 1000 };
    _rateBuckets.set(host, b);
  }
  return b;
}

async function rateLimitWait(url) {
  const ratePerSec = (CONFIG.daemon && CONFIG.daemon.rateLimit) || 0;
  if (!ratePerSec) return;
  let host;
  try { host = new URL(url).host; } catch { return; }
  const b = _getBucket(host, ratePerSec);
  if (!b) return;
  while (true) {
    const now = Date.now();
    b.tokens = Math.min(b.capacity, b.tokens + (now - b.last) * b.refillPerMs);
    b.last = now;
    if (b.tokens >= 1) { b.tokens -= 1; return; }
    const wait = Math.ceil((1 - b.tokens) / b.refillPerMs);
    await sleep(wait);
  }
}

export async function fetchWithTimeout(url, opts = {}, timeoutMs = RETRY.timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(new Error("timeout " + timeoutMs + "ms")), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function esploraFetch(base, path) {
  const pool = getPool(base);
  let lastErr;
  let lastUrl = base + path;
  let notFoundCount = 0;
  const totalEndpoints = pool.size();

  for (let attempt = 1; attempt <= RETRY.maxAttempts; attempt++) {
    let ep = pool.pick();
    if (!ep) {
      const wait = Math.max(500, Math.min(RETRY.maxDelayMs, pool.nextAvailableInMs()));
      logScan("RETRY", "semua endpoint cooldown, tunggu " + wait + "ms (percobaan " + attempt + "/" + RETRY.maxAttempts + ")");
      await sleep(wait);
      ep = pool.pick();
      if (!ep) { lastErr = new Error("semua endpoint dalam cooldown"); continue; }
    }
    const url = ep.url + path;
    lastUrl = url;
    try {
      await rateLimitWait(url);
      _bumpReq();
      profStart("http");
      const t0 = Date.now();
      const r = await fetchWithTimeout(url, { headers: { "user-agent": "btc-sig-analyzer/1.0" } });
      const latency = Date.now() - t0;
      profEnd("http");
      if (r.ok) {
        pool.markOk(ep, r.status, latency);
        const ct = r.headers.get("content-type") || "";
        return ct.includes("json") ? await r.json() : await r.text();
      }
      if (r.status === 404) {
        notFoundCount++;
        if (notFoundCount >= Math.min(2, totalEndpoints)) {
          throw new Error("HTTP 404 " + url);
        }
        logScan("RETRY", "HTTP 404 di " + ep.url + ", coba mirror lain");
        continue;
      }
      lastErr = new Error("HTTP " + r.status + " " + url);
      pool.markFail(ep, "HTTP " + r.status, r.status);
      const ra = r.headers.get("retry-after");
      if (ra) {
        const sec = parseFloat(ra);
        if (isFinite(sec)) pool.setCooldownFromRetryAfter(ep, sec);
      }
      logScan("RETRY", "HTTP " + r.status + " ep=" + ep.url + " percobaan " + attempt + "/" + RETRY.maxAttempts + " (rotate)");
    } catch (e) {
      if (e && e.message && e.message.startsWith("HTTP 404")) throw e;
      lastErr = e;
      pool.markFail(ep, e.message || String(e), 0);
      logScan("RETRY", "network/timeout (" + (e.message || e) + ") ep=" + ep.url + " percobaan " + attempt + "/" + RETRY.maxAttempts + " (rotate)");
    }
  }
  logScan("ERROR", "fetch gagal total setelah " + RETRY.maxAttempts + " percobaan · " + lastUrl + " · " + (lastErr && lastErr.message));
  throw lastErr || new Error("Gagal fetch setelah " + RETRY.maxAttempts + " percobaan: " + lastUrl);
}
