import { writeFileSync, readFileSync } from "node:fs";
import { CONFIG, DEFAULT_API, CACHE_ENABLED } from "../config.js";
import { logScan } from "../log.js";
import { padHex } from "../bytes.js";
import { c, C, header, kv, sep, drawProgress } from "../ui.js";
import {
  CACHE_STATS, resetCacheStats,
  loadAddressListCache, saveAddressListCache,
  loadResume, saveResume, clearResume,
} from "../cache.js";
import {
  fetchAllTxsForAddress, processTxForAddress,
  runWithConcurrency, detectReuse,
} from "../analysis.js";

export async function analyzeAddress(address, opts) {
  if (!opts) opts = {};
  const base = opts.api || DEFAULT_API;
  const concurrency = opts.concurrency || 8;
  console.log();
  header("Scan Address Wallet", address);
  logScan("SCAN", "mulai scan address=" + address + " concurrency=" + concurrency);
  kv("API", base, C.cyan);
  kv("Paralel", concurrency + " request", C.bold);
  kv("Cache", CACHE_ENABLED ? "AKTIF (.btc-cache/)" : "NONAKTIF",
     CACHE_ENABLED ? C.green : C.yellow);
  resetCacheStats();

  let txs;
  const cached = loadAddressListCache(address);
  const useCachedList = cached && (Date.now() - cached.ts) < (opts.listMaxAgeMs || CONFIG.cache.listMaxAgeHours * 3600 * 1000);
  if (useCachedList) {
    CACHE_STATS.listHits++;
    const ageMin = ((Date.now() - cached.ts) / 60000).toFixed(1);
    console.log("Daftar tx  :", c(C.cyan, "DARI CACHE (umur " + ageMin + " menit, " + cached.txs.length + " tx)"));
    txs = cached.txs;
  } else {
    CACHE_STATS.listMisses++;
    process.stdout.write("Mengambil daftar transaksi\u2026 ");
    txs = await fetchAllTxsForAddress(base, address);
    console.log(c(C.green, txs.length + " tx"));
    saveAddressListCache(address, txs);
  }

  if (txs.length === 0) {
    console.log(c(C.yellow, "Tidak ada transaksi untuk address ini."));
    clearResume(address);
    return [];
  }

  const resume = opts.noResume ? null : loadResume(address);
  const processedSet = new Set(resume ? resume.processed : []);
  const allSigs = resume ? resume.sigs.slice() : [];
  if (resume) {
    const knownTxids = new Set(txs.map((t) => t.txid));
    for (const id of Array.from(processedSet)) if (!knownTxids.has(id)) processedSet.delete(id);
  }
  const remainingTxs = txs.filter((t) => !processedSet.has(t.txid));
  if (resume && processedSet.size > 0) {
    console.log(c(C.cyan,
      "Resume        : melanjutkan dari " + processedSet.size + "/" + txs.length +
      " tx (sisa " + remainingTxs.length + ", " + allSigs.length + " sig sudah terkumpul)"));
  }

  if (remainingTxs.length === 0) {
    console.log(c(C.green, "Semua tx sudah pernah diproses (dari resume)."));
  }

  const startTs = Date.now();
  const errors = [];
  let saveCounter = 0;
  const SAVE_EVERY = 25;

  drawProgress(0, remainingTxs.length, startTs);
  await runWithConcurrency(
    remainingTxs,
    concurrency,
    async (tx) => {
      const r = await processTxForAddress(tx, address, base);
      if (r.err) errors.push(r.err);
      for (const s of r.sigs) { s.index = allSigs.length; allSigs.push(s); }
      processedSet.add(tx.txid);
      return r;
    },
    (done, tx) => {
      saveCounter++;
      if (saveCounter >= SAVE_EVERY || done === remainingTxs.length) {
        saveCounter = 0;
        saveResume(address, processedSet, allSigs);
      }
      drawProgress(done, remainingTxs.length, startTs, tx.txid.slice(0, 16) + "\u2026");
    }
  );
  process.stdout.write("\r\x1b[K");
  saveResume(address, processedSet, allSigs);
  const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
  console.log(
    c(C.green, "Selesai dalam " + elapsed + " dtk \u2014 ") +
    c(C.bold, allSigs.length + " signature") +
    " dari " + txs.length + " tx" +
    (remainingTxs.length < txs.length ? c(C.dim, " (" + (txs.length - remainingTxs.length) + " dilewati via resume)") : "")
  );
  logScan("SCAN", "selesai address=" + address + " durasi=" + elapsed + "s sigs=" + allSigs.length + " tx=" + txs.length + " errors=" + errors.length);
  clearResume(address);
  if (CACHE_ENABLED) {
    const total = CACHE_STATS.hexHits + CACHE_STATS.hexMisses;
    const pct = total ? ((CACHE_STATS.hexHits / total) * 100).toFixed(1) : "0";
    console.log(c(C.dim,
      "Cache tx hex: " + CACHE_STATS.hexHits + " hit, " + CACHE_STATS.hexMisses +
      " miss (" + pct + "% hit-rate)"));
  }
  if (errors.length) {
    console.log(c(C.yellow, errors.length + " error saat ambil/parse:"));
    for (const e of errors.slice(0, 5)) console.log(c(C.dim, "  - " + e));
    if (errors.length > 5) console.log(c(C.dim, "  \u2026 dan " + (errors.length - 5) + " lagi"));
  }

  if (opts.verbose) {
    for (const s of allSigs) {
      sep("tx " + s.txid.slice(0, 12) + "… vin#" + s.inputIndex);
      console.log("R :", c(C.yellow, padHex(s.r)));
      console.log("S :", c(C.yellow, padHex(s.s)));
      console.log("Z :", c(C.yellow, padHex(s.z)));
      console.log("Pubkey:", c(C.magenta, s.pubkey));
    }
  } else {
    console.log(c(C.dim, "(gunakan --verbose untuk melihat tiap R/S/Z)"));
  }
  if (opts.out) {
    const out = allSigs.map((s) => ({
      txid: s.txid, inputIndex: s.inputIndex,
      r: padHex(s.r), s: padHex(s.s), z: padHex(s.z), pubkey: s.pubkey,
    }));
    writeFileSync(opts.out, JSON.stringify(out, null, 2));
    console.log(c(C.green, "Disimpan ke: " + opts.out));
  }
  await detectReuse(allSigs, {
    scannedAddress: address,
    hitsFile: opts.hitsFile || "hits.txt",
    saveHits: opts.saveHits !== false,
    checkBalance: opts.checkBalance !== false,
    api: base,
  });
  return allSigs;
}

export async function batchAddresses(filePath, opts = {}) {
  const raw = readFileSync(filePath, "utf8");
  const addresses = raw.split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  if (addresses.length === 0) {
    console.log(c(C.yellow, "Tidak ada address yang valid di file: " + filePath));
    return;
  }
  console.log();
  header("Batch Scan", addresses.length + " address dari " + filePath);
  kv("Hits file", opts.hitsFile || CONFIG.hitsFile, C.cyan);
  kv("API", opts.api || DEFAULT_API);
  kv("Paralel", (opts.concurrency || CONFIG.concurrency) + " request");

  const summary = [];
  const pool = [];
  const startAll = Date.now();
  for (let i = 0; i < addresses.length; i++) {
    const addr = addresses[i];
    sep("[" + (i + 1) + "/" + addresses.length + "] " + addr);
    try {
      const sigs = await analyzeAddress(addr, opts);
      summary.push({ addr, ok: true, sigCount: sigs ? sigs.length : 0 });
      if (sigs && sigs.length) {
        for (const s of sigs) {
          pool.push({ ...s, address: s.address || addr });
        }
      }
    } catch (e) {
      console.log(c(C.red, "Gagal scan " + addr + ": " + e.message));
      summary.push({ addr, ok: false, error: e.message });
    }
  }
  const elapsed = ((Date.now() - startAll) / 1000).toFixed(1);
  sep("Ringkasan batch (" + elapsed + " dtk)");
  for (const s of summary) {
    if (s.ok) {
      console.log(c(C.green, "  ✓ ") + s.addr + c(C.dim, "  " + s.sigCount + " sig"));
    } else {
      console.log(c(C.red, "  ✗ ") + s.addr + c(C.dim, "  " + s.error));
    }
  }
  const okCount = summary.filter((s) => s.ok).length;
  console.log(c(C.bold, okCount + "/" + addresses.length + " address sukses, total " + pool.length + " signature di pool."));

  if (pool.length >= 2) {
    const baseHits = opts.hitsFile || CONFIG.hitsFile;
    const crossHits = baseHits.replace(/\.txt$/, "") + "_CROSS.txt";
    await detectReuse(pool, {
      hitsFile: crossHits,
      crossAddressOnly: true,
      api: opts.api || DEFAULT_API,
      saveHits: true,
      checkBalance: true,
    });
  }
}
