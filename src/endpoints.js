import { CONFIG } from "./config.js";
import { c, C } from "./ui.js";

const KNOWN_DEFAULTS = [
  "https://mempool.space/api",
  "https://blockstream.info/api",
  "https://mempool.emzy.de/api",
];

const VALID_STRATEGIES = new Set(["latency", "round-robin", "primary"]);

function normalize(url) {
  if (!url || typeof url !== "string") return null;
  return url.trim().replace(/\/+$/, "");
}

class EndpointPool {
  constructor(primary, opts = {}) {
    const fromConfig = Array.isArray(CONFIG.endpoints) ? CONFIG.endpoints : [];
    const useDefaults = CONFIG.endpointDefaults !== false;
    const seen = new Set();
    const all = [];
    const push = (u) => {
      const n = normalize(u);
      if (n && !seen.has(n)) { seen.add(n); all.push(n); }
    };
    push(primary);
    fromConfig.forEach(push);
    if (useDefaults) KNOWN_DEFAULTS.forEach(push);

    this.primary = normalize(primary);
    this.endpoints = all.map((url, idx) => ({
      url,
      idx,
      cooldownUntil: 0,
      consecutiveFails: 0,
      totalReq: 0,
      totalOk: 0,
      totalFail: 0,
      total429: 0,
      total5xx: 0,
      lastStatus: null,
      lastError: null,
      lastUsed: 0,
      latencyMs: null,
      lastProbeMs: 0,
    }));
    this.cooldownBaseMs = (CONFIG.cooldown && CONFIG.cooldown.baseMs) || 5000;
    this.cooldownMaxMs  = (CONFIG.cooldown && CONFIG.cooldown.maxMs)  || 5 * 60 * 1000;

    const stratRaw = opts.strategy || CONFIG.endpointStrategy || "latency";
    this.strategy = VALID_STRATEGIES.has(stratRaw) ? stratRaw : "latency";

    const probeCfg = CONFIG.latencyProbe || {};
    this.probeEnabled  = probeCfg.enabled !== false;
    this.probeInterval = probeCfg.intervalMs || 300_000;
    this.probeTimeout  = probeCfg.timeoutMs  || 5_000;
    this.bucketSizeMs  = (CONFIG.latencyBucketMs) || 100;
    this._probeTimer = null;
    this._probing = false;
  }

  size() { return this.endpoints.length; }

  available() {
    const now = Date.now();
    return this.endpoints.filter((e) => e.cooldownUntil <= now);
  }

  // ===== Strategi pemilihan =====
  // - "latency"     : kelompokkan per-bucket latency, RR dalam grup tercepat
  // - "round-robin" : urut by lastUsed (legacy)
  // - "primary"     : selalu primary kecuali cooldown
  pick() {
    const now = Date.now();
    const ready = this.endpoints.filter((e) => e.cooldownUntil <= now);
    if (ready.length === 0) return null;

    let ep;
    if (this.strategy === "primary") {
      const prim = ready.find((e) => e.url === this.primary);
      ep = prim || this._sortByFailsLastUsed(ready)[0];
    } else if (this.strategy === "latency") {
      const bucketSize = this.bucketSizeMs;
      const bucket = (e) => {
        if (e.latencyMs == null || !isFinite(e.latencyMs)) return Number.MAX_SAFE_INTEGER;
        return Math.floor(e.latencyMs / bucketSize);
      };
      const sorted = ready.slice().sort((a, b) => {
        if (a.consecutiveFails !== b.consecutiveFails) return a.consecutiveFails - b.consecutiveFails;
        const ba = bucket(a), bb = bucket(b);
        if (ba !== bb) return ba - bb;
        return a.lastUsed - b.lastUsed;
      });
      ep = sorted[0];
    } else {
      ep = this._sortByFailsLastUsed(ready)[0];
    }

    ep.lastUsed = now;
    ep.totalReq++;
    return ep;
  }

  _sortByFailsLastUsed(list) {
    return list.slice().sort((a, b) => {
      if (a.consecutiveFails !== b.consecutiveFails) return a.consecutiveFails - b.consecutiveFails;
      return a.lastUsed - b.lastUsed;
    });
  }

  nextAvailableInMs() {
    const now = Date.now();
    let soonest = Infinity;
    for (const e of this.endpoints) {
      const dt = e.cooldownUntil - now;
      if (dt < soonest) soonest = dt;
    }
    return Math.max(0, soonest === Infinity ? 0 : soonest);
  }

  markOk(ep, status, latencyMs) {
    ep.consecutiveFails = 0;
    ep.lastStatus = status;
    ep.lastError = null;
    ep.totalOk++;
    if (latencyMs != null && isFinite(latencyMs)) {
      // EWMA: 70% history + 30% sample → smooth spike, cepat adaptif
      ep.latencyMs = (ep.latencyMs == null || !isFinite(ep.latencyMs))
        ? latencyMs
        : Math.round(ep.latencyMs * 0.7 + latencyMs * 0.3);
    }
  }

  markFail(ep, reason, status) {
    ep.consecutiveFails++;
    ep.totalFail++;
    if (status === 429) ep.total429++;
    else if (status >= 500) ep.total5xx++;
    ep.lastStatus = status || null;
    ep.lastError = reason;
    const exp = Math.min(this.cooldownMaxMs, this.cooldownBaseMs * 2 ** (ep.consecutiveFails - 1));
    const jitter = 0.5 + Math.random() * 0.5;
    ep.cooldownUntil = Date.now() + Math.floor(exp * jitter);
  }

  setCooldownFromRetryAfter(ep, retryAfterSec) {
    if (!isFinite(retryAfterSec)) return;
    const ms = Math.min(this.cooldownMaxMs, retryAfterSec * 1000);
    ep.cooldownUntil = Math.max(ep.cooldownUntil, Date.now() + ms);
  }

  // ===== Probing =====
  async probe(timeoutMs) {
    if (this._probing) return;
    this._probing = true;
    const tmo = timeoutMs || this.probeTimeout;
    try {
      await Promise.allSettled(this.endpoints.map(async (ep) => {
        const t0 = Date.now();
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), tmo);
        try {
          const r = await fetch(ep.url + "/blocks/tip/height", {
            signal: ctrl.signal,
            headers: { "user-agent": "btc-sig-analyzer/probe" },
          });
          clearTimeout(timer);
          ep.lastProbeMs = Date.now();
          if (r.ok) {
            ep.latencyMs = Date.now() - t0;
          } else {
            ep.latencyMs = Infinity;
          }
        } catch {
          clearTimeout(timer);
          ep.lastProbeMs = Date.now();
          ep.latencyMs = Infinity;
        }
      }));
    } finally {
      this._probing = false;
    }
  }

  startProbeLoop() {
    if (!this.probeEnabled || this._probeTimer) return;
    this.probe().catch(() => {});
    this._probeTimer = setInterval(() => { this.probe().catch(() => {}); }, this.probeInterval);
    if (typeof this._probeTimer.unref === "function") this._probeTimer.unref();
  }

  stopProbeLoop() {
    if (this._probeTimer) { clearInterval(this._probeTimer); this._probeTimer = null; }
  }

  list() { return this.endpoints.slice(); }

  summary() {
    const now = Date.now();
    const total = this.endpoints.length;
    const active = this.endpoints.filter((e) => e.cooldownUntil <= now).length;
    return { total, active, cooled: total - active };
  }

  // Daftar terurut sesuai strategi aktif (untuk display)
  ranked() {
    const ready = this.endpoints.slice();
    if (this.strategy === "latency") {
      const bucket = (e) => (e.latencyMs == null || !isFinite(e.latencyMs))
        ? Number.MAX_SAFE_INTEGER
        : Math.floor(e.latencyMs / this.bucketSizeMs);
      return ready.sort((a, b) => bucket(a) - bucket(b) || a.idx - b.idx);
    }
    if (this.strategy === "primary") {
      return ready.sort((a, b) => (a.url === this.primary ? -1 : b.url === this.primary ? 1 : a.idx - b.idx));
    }
    return ready.sort((a, b) => a.idx - b.idx);
  }
}

let _pool = null;
let _extraEndpoints = [];
let _strategyOverride = null;

export function getPool(primary) {
  if (!_pool) {
    if (_extraEndpoints.length > 0) {
      const existing = Array.isArray(CONFIG.endpoints) ? CONFIG.endpoints : [];
      CONFIG.endpoints = [..._extraEndpoints, ...existing];
    }
    _pool = new EndpointPool(primary, { strategy: _strategyOverride });
    if (_pool.strategy === "latency") _pool.startProbeLoop();
  }
  return _pool;
}

export function resetPool() {
  if (_pool) _pool.stopProbeLoop();
  _pool = null;
}

export function setExtraEndpoints(list) {
  _extraEndpoints = (list || []).map(normalize).filter(Boolean);
  resetPool();
}

export function setStrategyOverride(s) {
  _strategyOverride = VALID_STRATEGIES.has(s) ? s : null;
  resetPool();
}

function fmtLatency(ep) {
  if (ep.latencyMs == null) return c(C.dim, "  -    ");
  if (!isFinite(ep.latencyMs)) return c(C.red, " down ");
  const ms = ep.latencyMs;
  const col = ms < 300 ? C.green : ms < 800 ? C.yellow : C.red;
  return c(col, String(ms).padStart(5) + "ms");
}

export function printPoolReport(pool) {
  const now = Date.now();
  console.log();
  console.log(c(C.bold + C.yellow, "  Pool Endpoint (" + pool.size() + " total · strategi: " + pool.strategy + ")"));
  console.log(c(C.gray, "  " + "─".repeat(70)));
  for (const e of pool.ranked()) {
    const cd = e.cooldownUntil - now;
    const status = cd > 0
      ? c(C.red, "COOLDOWN " + Math.ceil(cd / 1000) + "s")
      : c(C.green, "READY");
    const tag = e.url === pool.primary ? c(C.yellow, " (primary)") : "";
    const stats = "req=" + e.totalReq + " ok=" + e.totalOk + " fail=" + e.totalFail
      + (e.total429 ? " 429=" + e.total429 : "")
      + (e.total5xx ? " 5xx=" + e.total5xx : "");
    console.log("  " + status + "  " + fmtLatency(e) + "  " + c(C.cyan, e.url) + tag);
    console.log("    " + c(C.dim, stats + (e.lastError ? "  · err: " + e.lastError : "")));
  }
  console.log();
}
