import { CONFIG } from "./config.js";
import { c, C } from "./ui.js";

const KNOWN_DEFAULTS = [
  "https://mempool.space/api",
  "https://blockstream.info/api",
  "https://mempool.emzy.de/api",
];

function normalize(url) {
  if (!url || typeof url !== "string") return null;
  return url.trim().replace(/\/+$/, "");
}

class EndpointPool {
  constructor(primary) {
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
    this.endpoints = all.map((url) => ({
      url,
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
    }));
    this.cooldownBaseMs = (CONFIG.cooldown && CONFIG.cooldown.baseMs) || 5000;
    this.cooldownMaxMs  = (CONFIG.cooldown && CONFIG.cooldown.maxMs)  || 5 * 60 * 1000;
  }

  size() { return this.endpoints.length; }

  available() {
    const now = Date.now();
    return this.endpoints.filter((e) => e.cooldownUntil <= now);
  }

  pick() {
    const now = Date.now();
    const ready = this.endpoints
      .filter((e) => e.cooldownUntil <= now)
      .sort((a, b) => {
        if (a.consecutiveFails !== b.consecutiveFails) return a.consecutiveFails - b.consecutiveFails;
        return a.lastUsed - b.lastUsed;
      });
    if (ready.length === 0) return null;
    const ep = ready[0];
    ep.lastUsed = now;
    ep.totalReq++;
    return ep;
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

  markOk(ep, status) {
    ep.consecutiveFails = 0;
    ep.lastStatus = status;
    ep.lastError = null;
    ep.totalOk++;
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

  list() { return this.endpoints.slice(); }

  summary() {
    const now = Date.now();
    const total = this.endpoints.length;
    const active = this.endpoints.filter((e) => e.cooldownUntil <= now).length;
    return { total, active, cooled: total - active };
  }
}

let _pool = null;
let _extraEndpoints = [];

export function getPool(primary) {
  if (!_pool) {
    if (_extraEndpoints.length > 0) {
      const existing = Array.isArray(CONFIG.endpoints) ? CONFIG.endpoints : [];
      CONFIG.endpoints = [..._extraEndpoints, ...existing];
    }
    _pool = new EndpointPool(primary);
  }
  return _pool;
}

export function resetPool() { _pool = null; }

export function setExtraEndpoints(list) {
  _extraEndpoints = (list || []).map(normalize).filter(Boolean);
  _pool = null;
}

export function printPoolReport(pool) {
  const now = Date.now();
  console.log();
  console.log(c(C.bold + C.yellow, "  Pool Endpoint (" + pool.size() + " total)"));
  console.log(c(C.gray, "  " + "─".repeat(70)));
  for (const e of pool.endpoints) {
    const cd = e.cooldownUntil - now;
    const status = cd > 0
      ? c(C.red, "COOLDOWN " + Math.ceil(cd / 1000) + "s")
      : c(C.green, "READY");
    const stats = "req=" + e.totalReq + " ok=" + e.totalOk + " fail=" + e.totalFail
      + (e.total429 ? " 429=" + e.total429 : "")
      + (e.total5xx ? " 5xx=" + e.total5xx : "");
    console.log("  " + status + "  " + c(C.cyan, e.url));
    console.log("    " + c(C.dim, stats + (e.lastError ? "  · err: " + e.lastError : "")));
  }
  console.log();
}
