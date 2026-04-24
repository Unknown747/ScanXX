import { bytesToBigInt, readVarInt } from "./bytes.js";

export function parseDER(sig) {
  if (sig[0] !== 0x30) throw new Error("DER tidak valid: byte awal bukan 0x30");
  if (sig[2] !== 0x02) throw new Error("DER tidak valid: marker R");
  const rLen = sig[3];
  const r = sig.slice(4, 4 + rLen);
  const sMarker = 4 + rLen;
  if (sig[sMarker] !== 0x02) throw new Error("DER tidak valid: marker S");
  const sLen = sig[sMarker + 1];
  const s = sig.slice(sMarker + 2, sMarker + 2 + sLen);
  const sighashType = sig[sMarker + 2 + sLen];
  return {
    r: bytesToBigInt(r),
    s: bytesToBigInt(s),
    sighashType,
  };
}

export function parseScriptPushes(script) {
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
  }
  return pushes;
}

export function parseTx(buf) {
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
