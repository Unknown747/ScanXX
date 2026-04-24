import { Agent, setGlobalDispatcher } from "undici";
import { CONFIG } from "./config.js";
import { logScan } from "./log.js";
import { profStart, profEnd } from "./profile.js";

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
  const url = base + path;
  let lastErr;
  for (let attempt = 1; attempt <= RETRY.maxAttempts; attempt++) {
    try {
      await rateLimitWait(url);
      _bumpReq();
      profStart("http");
      const r = await fetchWithTimeout(url, { headers: { "user-agent": "btc-sig-analyzer/1.0" } });
      profEnd("http");
      if (r.ok) {
        const ct = r.headers.get("content-type") || "";
        return ct.includes("json") ? await r.json() : await r.text();
      }
      if (r.status === 404) throw new Error("HTTP 404 " + url);
      lastErr = new Error("HTTP " + r.status + " " + url);
      const ra = r.headers.get("retry-after");
      let waitMs;
      if (ra) {
        const sec = parseFloat(ra);
        waitMs = isFinite(sec) ? Math.min(RETRY.maxDelayMs, sec * 1000) : null;
      }
      if (waitMs == null) {
        const exp = Math.min(RETRY.maxDelayMs, RETRY.baseDelayMs * 2 ** (attempt - 1));
        waitMs = Math.floor(exp * (0.5 + Math.random() * 0.5));
      }
      logScan("RETRY", "HTTP " + r.status + " percobaan " + attempt + "/" + RETRY.maxAttempts + " tunggu " + waitMs + "ms · " + url);
      if (attempt < RETRY.maxAttempts) await sleep(waitMs);
    } catch (e) {
      lastErr = e;
      if (attempt < RETRY.maxAttempts) {
        const exp = Math.min(RETRY.maxDelayMs, RETRY.baseDelayMs * 2 ** (attempt - 1));
        const waitMs = Math.floor(exp * (0.5 + Math.random() * 0.5));
        logScan("RETRY", "network/timeout (" + (e.message || e) + ") percobaan " + attempt + "/" + RETRY.maxAttempts + " tunggu " + waitMs + "ms · " + url);
        await sleep(waitMs);
      }
    }
  }
  logScan("ERROR", "fetch gagal total setelah " + RETRY.maxAttempts + " percobaan · " + url + " · " + (lastErr && lastErr.message));
  throw lastErr || new Error("Gagal fetch setelah " + RETRY.maxAttempts + " percobaan: " + url);
}
