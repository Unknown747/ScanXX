import { existsSync, readFileSync, rmSync } from "node:fs";
import { CONFIG, setCacheEnabled, CACHE_ENABLED } from "./src/config.js";
import { logScan } from "./src/log.js";
import { c, C } from "./src/ui.js";
import { CACHE_DIR, pruneOldCache } from "./src/cache.js";
import { PROFILE } from "./src/profile.js";
import { help } from "./src/commands/help.js";
import { interactiveMenu } from "./src/commands/menu.js";
import { analyzeTx, analyzeManual, analyzeByTxid } from "./src/commands/analyze.js";
import { analyzeAddress, batchAddresses } from "./src/commands/address.js";
import { scanExplore } from "./src/commands/explore.js";
import { runDaemon } from "./src/commands/daemon.js";
import { showStats } from "./src/commands/stats.js";
import { showEndpoints } from "./src/commands/endpoints.js";
import { setExtraEndpoints } from "./src/endpoints.js";

const rawArgv = process.argv.slice(2);
const FLAG_KEYS_WITH_VALUE = new Set([
  "api", "out", "hits", "concurrency", "amount",
  "mode", "limit", "date", "interval", "endpoints", "watch",
]);
const posArgs = [];
for (let i = 0; i < rawArgv.length; i++) {
  const a = rawArgv[i];
  if (a.startsWith("--")) {
    if (FLAG_KEYS_WITH_VALUE.has(a.slice(2))) i++;
  } else {
    posArgs.push(a);
  }
}
const cmd = posArgs[0];
const getOpt = (k) => {
  const i = rawArgv.indexOf("--" + k);
  return i >= 0 ? rawArgv[i + 1] : null;
};
const hasFlag = (k) => rawArgv.includes("--" + k);

async function main() {
  if (hasFlag("no-cache")) setCacheEnabled(false);
  if (hasFlag("profile")) PROFILE.enabled = true;
  const epFlag = getOpt("endpoints");
  if (epFlag) {
    const list = epFlag.split(",").map((s) => s.trim()).filter(Boolean);
    if (list.length > 0) setExtraEndpoints(list);
  }
  if (cmd === "clear-cache") {
    if (existsSync(CACHE_DIR)) {
      rmSync(CACHE_DIR, { recursive: true, force: true });
      console.log(c(C.green, "Cache .btc-cache/ dihapus."));
    } else {
      console.log("Tidak ada cache untuk dihapus.");
    }
    return;
  }
  if (CACHE_ENABLED && CONFIG.cache.pruneOnStart && cmd !== "help" && cmd !== "stats") {
    try {
      const removed = pruneOldCache(CONFIG.cache.txMaxAgeHours || 48);
      if (removed > 0) logScan("INFO", "auto-prune cache: " + removed + " file dihapus (ttl=" + (CONFIG.cache.txMaxAgeHours || 48) + "h)");
    } catch {}
  }
  if (!cmd) {
    await interactiveMenu();
    return;
  }
  if (cmd === "help" || cmd === "-h" || cmd === "--help") {
    help();
  } else if (cmd === "menu" || cmd === "i" || cmd === "interactive") {
    await interactiveMenu();
  } else if (cmd === "txid") {
    if (!posArgs[1]) throw new Error("TXID wajib diisi");
    await analyzeByTxid(posArgs[1], { api: getOpt("api") });
  } else if (cmd === "address") {
    if (!posArgs[1]) throw new Error("Address wajib diisi");
    await analyzeAddress(posArgs[1], {
      api: getOpt("api"),
      verbose: hasFlag("verbose"),
      out: getOpt("out"),
      hitsFile: getOpt("hits") || CONFIG.hitsFile,
      concurrency: getOpt("concurrency") ? Math.max(1, parseInt(getOpt("concurrency"), 10)) : CONFIG.concurrency,
    });
  } else if (cmd === "tx" || cmd === "tx-file") {
    const hex = cmd === "tx" ? posArgs[1] : readFileSync(posArgs[1], "utf8").trim();
    if (!hex) throw new Error("Hex transaksi kosong");
    const amounts = {};
    for (let i = 0; i < rawArgv.length - 1; i++) {
      if (rawArgv[i] !== "--amount") continue;
      const m = rawArgv[i + 1].match(/^(\d+)=(\d+)$/);
      if (m) amounts[Number(m[1])] = Number(m[2]);
    }
    await analyzeTx(hex, { amounts });
  } else if (cmd === "sig") {
    const r = getOpt("r"), s = getOpt("s"), z = getOpt("z"), pub = getOpt("pub");
    if (!r || !s || !z) throw new Error("Wajib --r, --s, --z");
    await analyzeManual([{ r, s, z, pubkey: pub }]);
  } else if (cmd === "reuse") {
    if (!posArgs[1]) throw new Error("Path file JSON wajib diisi");
    const data = JSON.parse(readFileSync(posArgs[1], "utf8"));
    if (!Array.isArray(data)) throw new Error("File harus berupa array JSON");
    await analyzeManual(data);
  } else if (cmd === "stats") {
    showStats(posArgs[1] || CONFIG.logFile, getOpt("date"));
  } else if (cmd === "endpoints") {
    await showEndpoints({ api: getOpt("api"), test: hasFlag("test") });
  } else if (cmd === "batch") {
    if (!posArgs[1]) throw new Error("Path file daftar address wajib diisi");
    await batchAddresses(posArgs[1], {
      api: getOpt("api"),
      verbose: hasFlag("verbose"),
      out: getOpt("out"),
      hitsFile: getOpt("hits") || CONFIG.hitsFile,
      concurrency: getOpt("concurrency") ? Math.max(1, parseInt(getOpt("concurrency"), 10)) : CONFIG.concurrency,
    });
  } else if (cmd === "explore") {
    const cfgEx     = CONFIG.explore || {};
    const modeRaw   = getOpt("mode") || cfgEx.mode || "mempool";
    const limitVal  = getOpt("limit");
    const limitNum  = limitVal != null ? parseInt(limitVal, 10) : (cfgEx.limit != null ? cfgEx.limit : 0);
    await scanExplore({
      api: getOpt("api") || CONFIG.api,
      mode: (modeRaw === "blocks" || modeRaw === "blok") ? "blocks" : "mempool",
      limit: limitNum,
      hitsFile: getOpt("hits") || CONFIG.hitsFile,
      concurrency: getOpt("concurrency") ? Math.max(1, parseInt(getOpt("concurrency"), 10)) : CONFIG.concurrency,
    });
  } else if (cmd === "daemon") {
    const cfgD       = CONFIG.daemon || {};
    const modeRaw    = getOpt("mode") || cfgD.mode || "mempool";
    const intervalVal= getOpt("interval");
    const limitVal   = getOpt("limit");
    const intervalN  = intervalVal != null ? Math.max(5, parseInt(intervalVal, 10)) : (cfgD.interval || 60);
    const limitN     = limitVal != null ? parseInt(limitVal, 10) : (cfgD.limit != null ? cfgD.limit : 0);
    await runDaemon({
      api:         getOpt("api") || CONFIG.api,
      mode:        (modeRaw === "blocks" || modeRaw === "blok") ? "blocks" : "mempool",
      interval:    intervalN,
      limit:       limitN,
      hitsFile:    getOpt("hits") || CONFIG.hitsFile,
      concurrency: getOpt("concurrency") ? Math.max(1, parseInt(getOpt("concurrency"), 10)) : CONFIG.concurrency,
      realtime:    hasFlag("realtime") ? true : !!cfgD.realtime,
      watchFile:   getOpt("watch") || cfgD.watchFile || null,
    });
  } else {
    console.error(c(C.red, "Perintah tidak dikenal: " + cmd));
    help();
    process.exit(1);
  }
}

process.on("unhandledRejection", (reason) => {
  const msg = reason && reason.message ? reason.message : String(reason);
  console.error("\n" + c(C.red, "[unhandledRejection] " + msg));
});
process.on("uncaughtException", (e) => {
  console.error("\n" + c(C.red, "[uncaughtException] " + (e && e.message ? e.message : String(e))));
});

main().catch((e) => {
  console.error(c(C.red, "Error: " + (e && e.message ? e.message : String(e))));
  process.exit(1);
});
