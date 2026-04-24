import {
  existsSync, mkdirSync, readFileSync, writeFileSync, renameSync,
  rmSync, statSync, readdirSync, createWriteStream,
} from "node:fs";
import { CONFIG, CACHE_ENABLED } from "./config.js";
import { esploraFetch } from "./net.js";

// ============================================================
// LRU Set & Map
// ============================================================
export class LRUSet {
  constructor(max) { this.max = max; this.m = new Map(); }
  has(k) { return this.m.has(k); }
  add(k) {
    if (this.m.has(k)) return;
    this.m.set(k, 1);
    if (this.m.size > this.max) {
      const it = this.m.keys().next();
      if (!it.done) this.m.delete(it.value);
    }
  }
  get size() { return this.m.size; }
}

export class LRUMap {
  constructor(max) { this.max = max; this.m = new Map(); }
  has(k) { return this.m.has(k); }
  get(k) {
    const v = this.m.get(k);
    if (v !== undefined) {
      this.m.delete(k);
      this.m.set(k, v);
    }
    return v;
  }
  set(k, v) {
    if (this.m.has(k)) this.m.delete(k);
    this.m.set(k, v);
    if (this.m.size > this.max) {
      const it = this.m.keys().next();
      if (!it.done) this.m.delete(it.value);
    }
  }
  get size() { return this.m.size; }
}

// ============================================================
// Paths
// ============================================================
export const CACHE_DIR     = ".btc-cache";
export const CACHE_TX      = CACHE_DIR + "/tx";
export const CACHE_TX_DAILY = CACHE_DIR + "/tx-daily";
export const CACHE_LIST    = CACHE_DIR + "/addr";
export const CACHE_RESUME  = CACHE_DIR + "/resume";
export const SEEN_FILE     = CACHE_DIR + "/daemon-seen.json";

// CACHE_STATS is a stable object reference — mutate fields, don't reassign,
// supaya importer lain melihat update lewat live binding.
export const CACHE_STATS = { hexHits: 0, hexMisses: 0, listHits: 0, listMisses: 0 };

export function resetCacheStats() {
  CACHE_STATS.hexHits = 0;
  CACHE_STATS.hexMisses = 0;
  CACHE_STATS.listHits = 0;
  CACHE_STATS.listMisses = 0;
}

export function ensureCacheDir() {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR);
  if (!existsSync(CACHE_TX_DAILY)) mkdirSync(CACHE_TX_DAILY);
  if (!existsSync(CACHE_LIST)) mkdirSync(CACHE_LIST);
}

// ============================================================
// Hits append stream (hindari appendFileSync di hot path daemon)
// ============================================================
export const _hitsStreams = new Map();

export function appendHit(path, text) {
  let s = _hitsStreams.get(path);
  if (!s) { s = createWriteStream(path, { flags: "a" }); _hitsStreams.set(path, s); }
  s.write(text);
}

export function closeAllHitsStreams() {
  for (const s of _hitsStreams.values()) { try { s.end(); } catch {} }
  _hitsStreams.clear();
}

// ============================================================
// Cache TX hex: NDJSON shard per hari + LRUMap in-memory bounded
// ============================================================
const _shardName = (d = new Date()) => {
  const p = (n) => String(n).padStart(2, "0");
  return "tx-" + d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + ".ndjson";
};

const TX_INDEX_CAP = (CONFIG.cache && CONFIG.cache.txIndexCap) || 50_000;
let _txIndex = null;
let _txWriteStream = null;
let _txWriteShardName = null;

function _buildTxIndex() {
  _txIndex = new LRUMap(TX_INDEX_CAP);
  if (!existsSync(CACHE_TX_DAILY)) return;
  let files = [];
  try { files = readdirSync(CACHE_TX_DAILY); } catch { return; }
  files.sort();
  for (const f of files) {
    if (!f.startsWith("tx-") || !f.endsWith(".ndjson")) continue;
    const fpath = CACHE_TX_DAILY + "/" + f;
    let raw;
    try { raw = readFileSync(fpath, "utf8"); } catch { continue; }
    let start = 0;
    while (start < raw.length) {
      let nl = raw.indexOf("\n", start);
      if (nl < 0) nl = raw.length;
      if (nl > start) {
        const line = raw.slice(start, nl);
        try {
          const o = JSON.parse(line);
          if (o && o.t && o.h) _txIndex.set(o.t, o.h);
        } catch {}
      }
      start = nl + 1;
    }
  }
  if (existsSync(CACHE_TX)) {
    let legacy = [];
    try { legacy = readdirSync(CACHE_TX); } catch {}
    for (const f of legacy) {
      if (!f.endsWith(".hex")) continue;
      const txid = f.slice(0, -4);
      if (_txIndex.has(txid)) continue;
      try { _txIndex.set(txid, readFileSync(CACHE_TX + "/" + f, "utf8").trim()); } catch {}
    }
  }
}

function _ensureTxStream() {
  ensureCacheDir();
  const want = _shardName();
  if (_txWriteStream && _txWriteShardName === want) return _txWriteStream;
  if (_txWriteStream) { try { _txWriteStream.end(); } catch {} }
  _txWriteShardName = want;
  _txWriteStream = createWriteStream(CACHE_TX_DAILY + "/" + want, { flags: "a" });
  return _txWriteStream;
}

export function pruneOldCache(maxAgeHours) {
  if (!existsSync(CACHE_TX_DAILY)) return 0;
  const cutoff = Date.now() - maxAgeHours * 3600 * 1000;
  let removed = 0;
  let files = [];
  try { files = readdirSync(CACHE_TX_DAILY); } catch { return 0; }
  for (const f of files) {
    if (!f.startsWith("tx-") || !f.endsWith(".ndjson")) continue;
    const fpath = CACHE_TX_DAILY + "/" + f;
    try {
      const st = statSync(fpath);
      if (st.mtimeMs < cutoff) { rmSync(fpath, { force: true }); removed++; }
    } catch {}
  }
  if (existsSync(CACHE_TX)) {
    let legacy = [];
    try { legacy = readdirSync(CACHE_TX); } catch {}
    for (const f of legacy) {
      const fpath = CACHE_TX + "/" + f;
      try {
        const st = statSync(fpath);
        if (st.mtimeMs < cutoff) { rmSync(fpath, { force: true }); removed++; }
      } catch {}
    }
  }
  return removed;
}

export async function fetchTxHexCached(base, txid) {
  if (CACHE_ENABLED) {
    if (_txIndex === null) _buildTxIndex();
    const cached = _txIndex.get(txid);
    if (cached) { CACHE_STATS.hexHits++; return cached; }
  }
  CACHE_STATS.hexMisses++;
  const hex = await esploraFetch(base, "/tx/" + txid + "/hex");
  if (CACHE_ENABLED) {
    try {
      _ensureTxStream().write(JSON.stringify({ t: txid, h: hex }) + "\n");
      if (_txIndex) _txIndex.set(txid, hex);
    } catch {}
  }
  return hex;
}

// ============================================================
// Address list cache
// ============================================================
export function loadAddressListCache(address) {
  if (!CACHE_ENABLED) return null;
  const file = CACHE_LIST + "/" + address + ".json";
  if (!existsSync(file)) return null;
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    if (data && Array.isArray(data.txs) && typeof data.ts === "number") return data;
  } catch {}
  return null;
}

export function saveAddressListCache(address, txs) {
  if (!CACHE_ENABLED) return;
  try {
    ensureCacheDir();
    writeFileSync(CACHE_LIST + "/" + address + ".json",
      JSON.stringify({ ts: Date.now(), address, txs }));
  } catch {}
}

// ============================================================
// Resume state per-address
// ============================================================
function ensureResumeDir() {
  ensureCacheDir();
  if (!existsSync(CACHE_RESUME)) mkdirSync(CACHE_RESUME);
}

const resumeFilePath = (address) => CACHE_RESUME + "/" + address + ".json";

export function loadResume(address) {
  const f = resumeFilePath(address);
  if (!existsSync(f)) return null;
  try {
    const d = JSON.parse(readFileSync(f, "utf8"));
    if (d && Array.isArray(d.processed) && Array.isArray(d.sigs)) return d;
  } catch {}
  return null;
}

export function saveResume(address, processedTxids, sigs) {
  try {
    ensureResumeDir();
    const tmp = resumeFilePath(address) + ".tmp";
    writeFileSync(tmp, JSON.stringify({
      ts: Date.now(), address,
      processed: Array.from(processedTxids),
      sigs,
    }));
    renameSync(tmp, resumeFilePath(address));
  } catch {}
}

export function clearResume(address) {
  try { const f = resumeFilePath(address); if (existsSync(f)) rmSync(f, { force: true }); } catch {}
}

// ============================================================
// Daemon snapshot (seenTxids)
// ============================================================
export function loadSeenSnapshot(maxAgeHours = 48) {
  if (!existsSync(SEEN_FILE)) return null;
  try {
    const st = statSync(SEEN_FILE);
    if (Date.now() - st.mtimeMs > maxAgeHours * 3600 * 1000) return null;
    const raw = JSON.parse(readFileSync(SEEN_FILE, "utf8"));
    if (!raw || !Array.isArray(raw.ids)) return null;
    return raw.ids;
  } catch { return null; }
}

export function saveSeenSnapshot(lruSet) {
  try {
    ensureCacheDir();
    const ids = Array.from(lruSet.m.keys());
    const tmp = SEEN_FILE + ".tmp";
    writeFileSync(tmp, JSON.stringify({ ts: Date.now(), ids }));
    renameSync(tmp, SEEN_FILE);
  } catch {}
}

// ============================================================
// Watchlist
// ============================================================
export function loadWatchlist(file) {
  if (!file || !existsSync(file)) return null;
  try {
    const lines = readFileSync(file, "utf8").split(/\r?\n/);
    const set = new Set();
    for (const ln of lines) {
      const t = ln.trim();
      if (!t || t.startsWith("#")) continue;
      set.add(t);
    }
    return set.size > 0 ? set : null;
  } catch { return null; }
}
