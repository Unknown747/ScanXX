import { existsSync, readFileSync, rmSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { CONFIG, DEFAULT_API, CACHE_ENABLED } from "../config.js";
import { c, C, ICON, W, banner, visLen } from "../ui.js";
import { CACHE_DIR } from "../cache.js";
import { getPool, compactPoolBadge } from "../endpoints.js";
import { analyzeTx, analyzeManual, analyzeByTxid } from "./analyze.js";
import { analyzeAddress, batchAddresses } from "./address.js";
import { scanExplore } from "./explore.js";
import { runDaemon } from "./daemon.js";
import { help } from "./help.js";

function poolHeaderBadge() {
  const pool = getPool(CONFIG.api || DEFAULT_API);
  const sum = pool.summary();
  const color = sum.active === sum.total ? C.green : (sum.active > 0 ? C.yellow : C.red);
  return c(C.dim, "endpoint ") + c(color, sum.active + "/" + sum.total);
}

function printPoolMini() {
  const pool = getPool(CONFIG.api || DEFAULT_API);
  const { badge, top } = compactPoolBadge(pool);
  console.log("  " + badge);
  if (top) console.log("    " + c(C.gray, "› ") + c(C.dim, top));
  console.log();
}

export async function interactiveMenu() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => rl.question(q);
  try {
    console.log();
    banner();
    console.log();

    const tg = CONFIG.telegram.enabled ? c(C.green, "ON") : c(C.gray, "OFF");
    const api = (CONFIG.api || DEFAULT_API).replace("https://", "");
    console.log(c(C.gray, "  ") +
      c(C.dim, "API ") + c(C.cyan, api) +
      c(C.gray, "  ·  ") +
      poolHeaderBadge() +
      c(C.gray, "  ·  ") +
      c(C.dim, "paralel ") + c(C.white, String(CONFIG.concurrency)) +
      c(C.gray, "  ·  ") +
      c(C.dim, "Telegram ") + tg +
      c(C.gray, "  ·  ") +
      c(C.dim, "cache ") + (CACHE_ENABLED ? c(C.green, "ON") : c(C.gray, "OFF"))
    );
    console.log();

    const GW = W - 2;
    const menuTop  = (label) => {
      const dash = "─".repeat(GW - 4 - visLen(label) - 2);
      console.log(c(C.gray, "  ┌─ ") + c(C.bold + C.yellow, label) + c(C.gray, " " + dash + "┐"));
    };
    const menuBot  = () => console.log(c(C.gray, "  └" + "─".repeat(GW - 2) + "┘"));
    const menuItem = (n, icon, title, hint) => {
      const inner = GW - 2;
      const left  = " " + c(C.yellow + C.bold, n) + "  " + icon + "  " + c(C.bold + C.white, title);
      const right = hint ? c(C.dim, hint) + " " : "";
      const used  = 1 + visLen(n) + 2 + visLen(icon) + 2 + visLen(title) + (hint ? visLen(hint) + 1 : 0);
      const gap   = Math.max(1, inner - used);
      console.log(c(C.gray, "  │") + left + " ".repeat(gap) + right + c(C.gray, "│"));
    };

    menuTop("SCAN ONLINE");
    menuItem("1", ICON.scan,   "Scan Address",    "Semua tx dari 1 wallet, cari R-reuse");
    menuItem("2", ICON.search, "Analisis TXID",   "1 transaksi via TXID");
    menuItem("3", ICON.file,   "Batch Scan File", "Daftar address, 1 per baris");
    menuItem("4", ICON.btc,    "Scan Explorer",   "Langsung dari mempool / blok terbaru");
    menuItem("5", "⚡",        "Daemon Auto-Scan","Loop terus, alert real-time jika hit");
    menuBot();

    console.log();
    menuTop("ANALISIS MANUAL");
    menuItem("6", ICON.tool,   "Raw TX Hex",         "Tempel hex raw transaksi");
    menuItem("7", ICON.tool,   "Signature Manual",   "Masukkan R, S, Z secara manual");
    menuItem("8", ICON.file,   "R-Reuse dari JSON",  "File daftar signature [{r,s,z}]");
    menuBot();

    console.log();
    menuTop("LAINNYA");
    menuItem("9", ICON.info,  "Bantuan Lengkap", "Tampilkan semua perintah & opsi");
    menuItem("C", ICON.tool,  "Hapus Cache",     "Bersihkan folder .btc-cache/");
    menuItem("0", ICON.err,   "Keluar",          "");
    menuBot();

    console.log();
    const choice = (await ask(
      "  " + c(C.yellow + C.bold, ICON.arrow + " Pilihan [0-9 / C]: ")
    )).trim();

    if (choice === "0" || choice === "") { rl.close(); return; }

    const inp = (label) => ask("  " + c(C.gray, "┃ ") + c(C.dim, label + " ") + c(C.yellow, "❯ "));

    if (choice === "1") {
      const addr = (await inp("Address Bitcoin  ")).trim();
      if (!addr) throw new Error("Address kosong");
      rl.close();
      await analyzeAddress(addr, {
        api: CONFIG.api || DEFAULT_API,
        concurrency: CONFIG.concurrency,
        verbose: !!CONFIG.verbose,
        out: CONFIG.out || null,
        hitsFile: CONFIG.hitsFile,
      });
    } else if (choice === "2") {
      const txid = (await inp("TXID             ")).trim();
      if (!txid) throw new Error("TXID kosong");
      rl.close();
      await analyzeByTxid(txid, { api: CONFIG.api || DEFAULT_API });
    } else if (choice === "3") {
      const fpath = (await inp("Path file address")).trim();
      rl.close();
      if (!fpath) throw new Error("Path file kosong");
      await batchAddresses(fpath, {
        api: CONFIG.api || DEFAULT_API,
        concurrency: CONFIG.concurrency,
        hitsFile: CONFIG.hitsFile,
      });
    } else if (choice === "6") {
      const hex = (await inp("Raw TX hex       ")).trim();
      if (!hex) throw new Error("Hex kosong");
      rl.close();
      await analyzeTx(hex, { amounts: {} });
    } else if (choice === "7") {
      const r   = (await inp("R (hex)          ")).trim();
      const s   = (await inp("S (hex)          ")).trim();
      const z   = (await inp("Z / sighash (hex)")).trim();
      const pub = (await inp("Public key (opt) ")).trim();
      rl.close();
      if (!r || !s || !z) throw new Error("R, S, dan Z wajib diisi");
      await analyzeManual([{ r, s, z, pubkey: pub || undefined }]);
    } else if (choice === "8") {
      const path = (await inp("Path file JSON   ")).trim();
      rl.close();
      const data = JSON.parse(readFileSync(path, "utf8"));
      if (!Array.isArray(data)) throw new Error("File harus berupa array JSON");
      await analyzeManual(data);
    } else if (choice === "9") {
      rl.close();
      help();
    } else if (choice === "C" || choice === "c") {
      rl.close();
      if (existsSync(CACHE_DIR)) {
        rmSync(CACHE_DIR, { recursive: true, force: true });
        console.log("  " + ICON.ok + " " + c(C.green, "Cache .btc-cache/ berhasil dihapus."));
      } else {
        console.log("  " + ICON.info + " " + c(C.dim, "Tidak ada cache untuk dihapus."));
      }
    } else if (choice === "4") {
      console.log();
      console.log(c(C.gray, "  ┌─ ") + c(C.bold + C.yellow, "SUMBER DATA") + c(C.gray, " ─────────────────────────────────────────────────┐"));
      console.log(c(C.gray, "  │") + " " + c(C.yellow + C.bold, "1") + "  " + ICON.scan + "  " + c(C.bold + C.white, "Mempool") +
        c(C.dim, "      Transaksi belum terkonfirmasi (live)") + c(C.gray, "      │"));
      console.log(c(C.gray, "  │") + " " + c(C.yellow + C.bold, "2") + "  " + ICON.btc  + "  " + c(C.bold + C.white, "Blok Terbaru") +
        c(C.dim, "  Transaksi sudah dikonfirmasi") + c(C.gray, "           │"));
      console.log(c(C.gray, "  └" + "─".repeat(W - 4) + "┘"));
      console.log();
      printPoolMini();
      const cfgMode = (CONFIG.explore && CONFIG.explore.mode) || "mempool";
      const defSrc = cfgMode === "blocks" ? "2" : "1";
      const src = (await ask("  " + c(C.yellow + C.bold, ICON.arrow + " Sumber [1/2, default " + defSrc + "]: "))).trim() || defSrc;
      const mode = src === "2" ? "blocks" : "mempool";
      rl.close();
      await scanExplore({
        api: CONFIG.api || DEFAULT_API,
        concurrency: CONFIG.concurrency,
        hitsFile: CONFIG.hitsFile,
        mode,
      });
    } else if (choice === "5") {
      console.log();
      console.log(c(C.gray, "  ┌─ ") + c(C.bold + C.yellow, "⚡ DAEMON AUTO-SCAN") + c(C.gray, " ────────────────────────────────────────────┐"));
      console.log(c(C.gray, "  │") + " " + c(C.yellow + C.bold, "1") + "  " + ICON.scan + "  " + c(C.bold + C.white, "Mempool") +
        c(C.dim, "      Unconfirmed txs (real-time)") + c(C.gray, "                │"));
      console.log(c(C.gray, "  │") + " " + c(C.yellow + C.bold, "2") + "  " + ICON.btc  + "  " + c(C.bold + C.white, "Blok Terbaru") +
        c(C.dim, "  Confirmed txs") + c(C.gray, "                              │"));
      console.log(c(C.gray, "  └" + "─".repeat(W - 4) + "┘"));
      console.log();
      printPoolMini();
      const cfgDmode = (CONFIG.daemon && CONFIG.daemon.mode) || "mempool";
      const defDsrc  = cfgDmode === "blocks" ? "2" : "1";
      const dsrc = (await ask("  " + c(C.yellow + C.bold, ICON.arrow + " Sumber [1/2, default " + defDsrc + "]: "))).trim() || defDsrc;
      const dmode = dsrc === "2" ? "blocks" : "mempool";
      rl.close();
      await runDaemon({
        api:         CONFIG.api || DEFAULT_API,
        concurrency: CONFIG.concurrency,
        hitsFile:    CONFIG.hitsFile,
        mode:        dmode,
        watchFile:   (CONFIG.daemon && CONFIG.daemon.watchFile) || null,
      });
    } else {
      rl.close();
      console.log("  " + ICON.err + " " + c(C.red, "Pilihan tidak valid: " + choice));
    }
  } finally {
    try { rl.close(); } catch {}
  }
}
