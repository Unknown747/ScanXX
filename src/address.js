import { concat, hexToBytes, padHex } from "./bytes.js";
import { dsha256, hash160 } from "./hash.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes) {
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

export function p2pkhAddress(hash160Bytes, prefix = 0x00) {
  const v = concat(new Uint8Array([prefix]), hash160Bytes);
  const checksum = dsha256(v).slice(0, 4);
  return base58Encode(concat(v, checksum));
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32CreateChecksum(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((polymod >>> (5 * (5 - i))) & 31);
  return out;
}

function bech32Encode(hrp, data) {
  const combined = data.concat(bech32CreateChecksum(hrp, data));
  let s = hrp + "1";
  for (const v of combined) s += BECH32_CHARSET.charAt(v);
  return s;
}

function convertBits(data, fromBits, toBits, pad = true) {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << toBits) - 1;
  for (const v of data) {
    if (v < 0 || v >> fromBits) throw new Error("bech32 convertBits: nilai tidak valid");
    acc = (acc << fromBits) | v;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) { if (bits) out.push((acc << (toBits - bits)) & maxv); }
  else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) throw new Error("bech32 convertBits: padding salah");
  return out;
}

export function p2wpkhAddress(hash160Bytes, hrp = "bc") {
  const data = [0].concat(convertBits(Array.from(hash160Bytes), 8, 5, true));
  return bech32Encode(hrp, data);
}

export function p2shP2wpkhAddress(hash160Bytes, prefix = 0x05) {
  const redeem = concat(new Uint8Array([0x00, 0x14]), hash160Bytes);
  return p2pkhAddress(hash160(redeem), prefix);
}

export function toWIF(d, prefix = 0x80, compressed = true) {
  const key = hexToBytes(padHex(d));
  let payload = concat(new Uint8Array([prefix]), key);
  if (compressed) payload = concat(payload, new Uint8Array([0x01]));
  const checksum = dsha256(payload).slice(0, 4);
  return base58Encode(concat(payload, checksum));
}
