import { existsSync, readFileSync } from "node:fs";

export const CONFIG_FILE = "config.json";

const DEFAULT_CONFIG = {
  api: "https://mempool.space/api",
  concurrency: 8,
  hitsFile: "hits.txt",
  logFile: "scan.log",
  logEnabled: true,
  cache: {
    enabled: true,
    listMaxAgeHours: 6,
    txMaxAgeHours: 48,
    pruneOnStart: true,
  },
  explore: {
    mode: "mempool",
    limit: 0,
  },
  daemon: {
    mode: "mempool",
    interval: 60,
    limit: 0,
    realtime: true,
    watchFile: null,
    seenLimit: 200_000,
    poolMaxAgeHours: 24,
    rateLimit: 0,
  },
  telegram: { enabled: false, botToken: "", chatId: "", notifyOnLiveOnly: true },
};

function loadConfig() {
  if (!existsSync(CONFIG_FILE)) return DEFAULT_CONFIG;
  try {
    const raw = JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
    return {
      ...DEFAULT_CONFIG,
      ...raw,
      cache: { ...DEFAULT_CONFIG.cache, ...(raw.cache || {}) },
      explore: { ...DEFAULT_CONFIG.explore, ...(raw.explore || {}) },
      daemon: { ...DEFAULT_CONFIG.daemon, ...(raw.daemon || {}) },
      telegram: { ...DEFAULT_CONFIG.telegram, ...(raw.telegram || {}) },
    };
  } catch (e) {
    console.error("Peringatan: config.json tidak valid (" + e.message + "), pakai default.");
    return DEFAULT_CONFIG;
  }
}

export const CONFIG = loadConfig();
export const DEFAULT_API = CONFIG.api;

export let CACHE_ENABLED = CONFIG.cache.enabled;
export function setCacheEnabled(v) { CACHE_ENABLED = !!v; }
