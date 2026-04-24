import { hexToBytes, bytesToHex, bytesToBigInt, padHex, concat, reverseBytes } from "../bytes.js";
import { hash160 } from "../hash.js";
import { c, C, header, kv, sep } from "../ui.js";
import { parseDER, parseScriptPushes, parseTx } from "../tx.js";
import { legacySighash, bip143Sighash } from "../sighash.js";
import { p2pkhAddress } from "../address.js";
import { DEFAULT_API } from "../config.js";
import { esploraFetch } from "../net.js";
import { fetchTxHexCached } from "../cache.js";
import { detectReuse } from "../analysis.js";

export async function analyzeTx(rawHex, opts = {}) {
  const buf = hexToBytes(rawHex);
  const tx = parseTx(buf);
  console.log();
  header("Analisis Transaksi Bitcoin", "Ekstraksi R/S/Z dari setiap input");
  kv("Versi", tx.version);
  kv("Input", tx.vin.length);
  kv("Output", tx.vout.length);
  kv("Locktime", tx.locktime);
  kv("SegWit", tx.hasWitness ? "Ya" : "Tidak", tx.hasWitness ? C.cyan : C.dim);

  const sigs = [];

  for (let i = 0; i < tx.vin.length; i++) {
    const vi = tx.vin[i];
    sep(`Input #${i}`);
    console.log("Prev TXID :", c(C.cyan, bytesToHex(reverseBytes(vi.prevTxid))));
    console.log("Prev Vout :", vi.prevVout);

    let pushes = parseScriptPushes(vi.scriptSig);
    let isWitness = false;
    if (pushes.length < 2 && vi.witness.length >= 2) { pushes = vi.witness; isWitness = true; }
    if (pushes.length < 2) {
      console.log(c(C.yellow, "  (Tidak ada signature+pubkey yang dapat dibaca otomatis pada input ini)"));
      continue;
    }
    const sigBytes = pushes[0];
    const pubBytes = pushes[1];
    let parsed;
    try { parsed = parseDER(sigBytes); }
    catch (e) { console.log(c(C.red, "  Gagal parse DER: " + e.message)); continue; }
    const pubHash = hash160(pubBytes);
    const addr = p2pkhAddress(pubHash);

    console.log("Tipe       :", isWitness ? "P2WPKH (witness)" : "P2PKH/legacy (scriptSig)");
    console.log("Public Key :", c(C.magenta, bytesToHex(pubBytes)));
    console.log("PubKey Hash:", c(C.magenta, bytesToHex(pubHash)));
    console.log("Address    :", c(C.green, addr));
    console.log("Signature  :", c(C.dim, bytesToHex(sigBytes)));
    console.log("  R        :", c(C.yellow, padHex(parsed.r)));
    console.log("  S        :", c(C.yellow, padHex(parsed.s)));
    console.log("  Sighash  :", "0x" + (parsed.sighashType ?? 1).toString(16).padStart(2, "0"));

    let z = null;
    try {
      const scriptCode = concat(new Uint8Array([0x76, 0xa9, 0x14]), pubHash, new Uint8Array([0x88, 0xac]));
      const sht = parsed.sighashType ?? 1;
      if (isWitness) {
        const amount = opts.amounts?.[i];
        if (amount === undefined) {
          console.log(c(C.yellow, "  Z        : (perlu --amount " + i + "=<satoshi> untuk hitung sighash BIP143)"));
        } else {
          const h = bip143Sighash(tx, i, scriptCode, amount, sht);
          z = bytesToBigInt(h);
          console.log("  Z (msg)  :", c(C.yellow, bytesToHex(h)));
        }
      } else {
        const h = legacySighash(tx, i, scriptCode, sht);
        z = bytesToBigInt(h);
        console.log("  Z (msg)  :", c(C.yellow, bytesToHex(h)));
      }
    } catch (e) {
      console.log(c(C.red, "  Gagal hitung Z: " + e.message));
    }

    sigs.push({
      index: i, r: parsed.r, s: parsed.s, z,
      pubkey: bytesToHex(pubBytes),
      pubkeyHash: bytesToHex(pubHash),
      address: addr,
    });
  }

  await detectReuse(sigs);
}

export async function analyzeManual(items) {
  console.log();
  header("Analisis Manual R / S / Z", items.length + " signature akan dianalisis");
  const sigs = items.map((it, i) => {
    const r = BigInt("0x" + it.r.replace(/^0x/, ""));
    const s = BigInt("0x" + it.s.replace(/^0x/, ""));
    const z = BigInt("0x" + it.z.replace(/^0x/, ""));
    let pubHex = it.pubkey || null;
    let pubHash = null, addr = null;
    if (pubHex) {
      const pb = hexToBytes(pubHex);
      pubHash = bytesToHex(hash160(pb));
      addr = p2pkhAddress(hash160(pb));
    }
    sep("Signature #" + i);
    kv("R", padHex(r), C.yellow);
    kv("S", padHex(s), C.yellow);
    kv("Z", padHex(z), C.yellow);
    if (pubHex) {
      kv("Public Key", pubHex, C.magenta);
      kv("PubKey Hash", pubHash, C.magenta);
      kv("Address", addr, C.green);
    }
    return { index: i, r, s, z, pubkey: pubHex, pubkeyHash: pubHash, address: addr };
  });
  await detectReuse(sigs);
}

export async function analyzeByTxid(txid, opts = {}) {
  const base = opts.api || DEFAULT_API;
  const meta = await esploraFetch(base, "/tx/" + txid);
  const hex = await fetchTxHexCached(base, txid);
  const amounts = {};
  for (let i = 0; i < meta.vin.length; i++) {
    if (meta.vin[i].prevout && meta.vin[i].prevout.value !== undefined) {
      amounts[i] = meta.vin[i].prevout.value;
    }
  }
  await analyzeTx(hex.trim(), { amounts });
}
