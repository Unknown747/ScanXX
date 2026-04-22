#!/usr/bin/env node
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { readFileSync } from "node:fs";

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
        if (d === 0n || d >= N) continue;
        // Verifikasi: pubkey dari d harus konsisten dengan tanda tangan
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
function analyzeTx(rawHex, opts = {}) {
  const buf = hexToBytes(rawHex);
  const tx = parseTx(buf);
  const txid = bytesToHex(reverseBytes(dsha256(buf))); // approx untuk legacy
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
      const scriptCode = isWitness
        ? // P2WPKH scriptCode: OP_DUP OP_HASH160 <20> <pkh> OP_EQUALVERIFY OP_CHECKSIG
          concat(
            new Uint8Array([0x76, 0xa9, 0x14]),
            pubHash,
            new Uint8Array([0x88, 0xac])
          )
        : concat(
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
function detectReuse(sigs) {
  sep("Deteksi R-reuse");
  const groups = new Map();
  for (const s of sigs) {
    const key = padHex(s.r);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(s);
  }
  let found = false;
  for (const [r, list] of groups) {
    if (list.length < 2) continue;
    found = true;
    console.log(c(C.red, `\n!! R berulang ditemukan pada R = ${r}`));
    console.log("   Tanda tangan terkait:");
    for (const s of list) {
      console.log(
        `   - input #${s.index}  pubkey ${s.pubkey.slice(0, 16)}…`
      );
    }
    // Coba pulihkan
    for (let i = 0; i < list.length; i++) {
      for (let j = i + 1; j < list.length; j++) {
        const a = list[i],
          b = list[j];
        if (a.z === null || b.z === null) {
          console.log(
            c(
              C.yellow,
              "   (lewati: Z belum diketahui, sediakan --amount untuk segwit)"
            )
          );
          continue;
        }
        const cands = recoverPrivateKey(a.r, a.s, a.z, b.s, b.z);
        for (const { k, d } of cands) {
          // Verifikasi pubkey
          try {
            const pub = secp256k1.getPublicKey(
              hexToBytes(padHex(d)),
              true
            );
            const pubHex = bytesToHex(pub);
            if (pubHex === a.pubkey || pubHex === b.pubkey) {
              console.log(c(C.green, "\n   ✓ PRIVATE KEY DIPULIHKAN"));
              console.log("     k (nonce) :", c(C.magenta, padHex(k)));
              console.log("     d (priv)  :", c(C.green + C.bold, padHex(d)));
              console.log("     WIF       :", c(C.green, toWIF(d)));
              console.log("     Pubkey    :", pubHex);
            }
          } catch {}
        }
      }
    }
  }
  if (!found) console.log(c(C.green, "Tidak ada R-reuse terdeteksi."));
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
function analyzeManual(items) {
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
  detectReuse(sigs);
}

// ============================================================
// CLI
// ============================================================
function help() {
  console.log(`
${c(C.bold, "btc-sig-analyzer")} — Penganalisis tanda tangan Bitcoin (CLI)

Penggunaan:
  node index.mjs tx <hex>                Analisis raw transaksi (hex)
  node index.mjs tx-file <path>          Analisis raw transaksi dari file (hex)
  node index.mjs sig --r <hex> --s <hex> --z <hex> [--pub <hex>]
                                         Analisis satu signature manual
  node index.mjs reuse <file.json>       Cari R-reuse dari daftar signature JSON
                                         Format: [{r,s,z,pubkey?}, ...]
  node index.mjs help                    Tampilkan bantuan

Opsi tambahan untuk 'tx':
  --amount <i>=<satoshi>                 Nilai input ke-i (wajib untuk SegWit)
                                         dapat diulang untuk beberapa input

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

const argv = process.argv.slice(2);
const cmd = argv[0];

try {
  if (!cmd || cmd === "help" || cmd === "-h" || cmd === "--help") {
    help();
  } else if (cmd === "tx" || cmd === "tx-file") {
    const hex =
      cmd === "tx" ? argv[1] : readFileSync(argv[1], "utf8").trim();
    if (!hex) throw new Error("Hex transaksi kosong");
    const amounts = {};
    for (const a of argv.slice(2)) {
      const m = a.match(/^--amount[= ](\d+)=(\d+)$/) || (a === "--amount" ? null : null);
      if (m) amounts[Number(m[1])] = Number(m[2]);
    }
    // dukung "--amount 0=12345" sebagai dua arg
    for (let i = 0; i < argv.length - 1; i++) {
      if (argv[i] === "--amount") {
        const m = argv[i + 1].match(/^(\d+)=(\d+)$/);
        if (m) amounts[Number(m[1])] = Number(m[2]);
      }
    }
    analyzeTx(hex, { amounts });
  } else if (cmd === "sig") {
    const get = (k) => {
      const i = argv.indexOf("--" + k);
      return i >= 0 ? argv[i + 1] : null;
    };
    const r = get("r"),
      s = get("s"),
      z = get("z"),
      pub = get("pub");
    if (!r || !s || !z) throw new Error("Wajib --r, --s, --z");
    analyzeManual([{ r, s, z, pubkey: pub }]);
  } else if (cmd === "reuse") {
    const data = JSON.parse(readFileSync(argv[1], "utf8"));
    if (!Array.isArray(data)) throw new Error("File harus berupa array JSON");
    analyzeManual(data);
  } else {
    console.error(c(C.red, "Perintah tidak dikenal: " + cmd));
    help();
    process.exit(1);
  }
} catch (e) {
  console.error(c(C.red, "Error: " + e.message));
  process.exit(1);
}
