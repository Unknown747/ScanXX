import { CONFIG, DEFAULT_API } from "../config.js";
import { c, C, header, kv, sep, drawProgress } from "../ui.js";
import { esploraFetch } from "../net.js";
import { getPool } from "../endpoints.js";
import {
  processTxAllInputs, runWithConcurrency, detectReuse,
} from "../analysis.js";

export async function scanExplore(opts = {}) {
  const base = opts.api || DEFAULT_API;
  const mode = opts.mode || (CONFIG.explore && CONFIG.explore.mode) || "mempool";
  const rawLimit = (opts.limit !== undefined) ? opts.limit : ((CONFIG.explore && CONFIG.explore.limit) || 0);
  const unlimited = !rawLimit || rawLimit <= 0;
  const limit = unlimited ? Infinity : rawLimit;
  const limitLabel = unlimited ? "tanpa batas" : String(rawLimit);
  const concurrency = opts.concurrency || CONFIG.concurrency;

  console.log();
  header(
    "Scan Explorer",
    (mode === "mempool" ? "Mempool live" : "Blok terbaru") +
    " · " + limitLabel + " tx · " + base
  );
  kv("Mode", mode === "mempool" ? "Mempool (unconfirmed)" : "Blok terbaru", C.cyan);
  kv("Maks TX", limitLabel, C.bold);
  kv("Paralel", concurrency + " request", C.bold);
  {
    const pool = getPool(base);
    const sum = pool.summary();
    const epColor = sum.active === sum.total ? C.green : (sum.active > 0 ? C.yellow : C.red);
    kv("Endpoint", sum.active + "/" + sum.total + " aktif (rotasi otomatis)", epColor);
    kv("Primary", base, C.dim);
  }

  let txids = [];

  if (mode === "mempool") {
    process.stdout.write(c(C.dim, "Mengambil TXID dari mempool… "));
    try {
      const all = await esploraFetch(base, "/mempool/txids");
      txids = Array.isArray(all) ? (unlimited ? all : all.slice(0, limit)) : [];
      console.log(c(C.green, txids.length + " txid dari mempool"));
    } catch (e) {
      console.log(c(C.red, "Gagal ambil mempool txids: " + e.message));
      return;
    }
  } else {
    process.stdout.write(c(C.dim, "Mengambil info blok terbaru… "));
    try {
      const blocks = await esploraFetch(base, "/blocks");
      console.log(c(C.green, blocks.length + " blok"));
      for (const blk of blocks) {
        if (txids.length >= limit) break;
        process.stdout.write(c(C.dim, "  Blok #" + blk.height + " (" + blk.id.slice(0, 12) + "…) → "));
        try {
          const tids = await esploraFetch(base, "/block/" + blk.id + "/txids");
          const take = tids.slice(0, limit - txids.length);
          txids.push(...take);
          console.log(c(C.dim, take.length + " tx"));
        } catch (e) {
          console.log(c(C.yellow, "skip: " + e.message));
        }
      }
    } catch (e) {
      console.log(c(C.red, "Gagal ambil blok: " + e.message));
      return;
    }
  }

  if (txids.length === 0) {
    console.log(c(C.yellow, "Tidak ada txid yang ditemukan."));
    return;
  }
  console.log(c(C.bold, "Total " + txids.length + " TXID akan dianalisis."));

  console.log();
  sep("Pipeline · Ambil metadata + ekstrak R/S/Z");
  const allSigs = [];
  const errors = [];
  const metaErrors = [];
  let metaOk = 0;
  const startTs = Date.now();
  drawProgress(0, txids.length, startTs);
  await runWithConcurrency(
    txids,
    concurrency,
    async (txid) => {
      let meta;
      try {
        meta = await esploraFetch(base, "/tx/" + txid);
        metaOk++;
      } catch (e) {
        metaErrors.push(txid.slice(0, 12) + "…: " + e.message);
        return null;
      }
      const r = await processTxAllInputs(meta, base);
      if (r.err) errors.push(r.err);
      for (const s of r.sigs) { s.index = allSigs.length; allSigs.push(s); }
      return r;
    },
    (done) => drawProgress(done, txids.length, startTs, "fetch+extract")
  );
  process.stdout.write("\r\x1b[K");
  const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
  console.log(
    c(C.green, "  Selesai " + elapsed + " dtk — ") +
    c(C.bold, allSigs.length + " signature") +
    c(C.gray, " dari " + metaOk + " tx") +
    (metaErrors.length ? c(C.yellow, "  · " + metaErrors.length + " meta gagal") : "")
  );
  if (errors.length) {
    console.log(c(C.yellow, "  " + errors.length + " error:"));
    for (const e of errors.slice(0, 5)) console.log(c(C.dim, "    - " + e));
    if (errors.length > 5) console.log(c(C.dim, "    … dan " + (errors.length - 5) + " lagi"));
  }
  if (allSigs.length < 2) {
    console.log(c(C.yellow, "Signature terlalu sedikit untuk deteksi R-reuse."));
    return;
  }
  await detectReuse(allSigs, {
    hitsFile: opts.hitsFile || CONFIG.hitsFile,
    saveHits: true,
    checkBalance: true,
    api: base,
  });
}
