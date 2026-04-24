import { concat, writeVarInt, u32le, u64le } from "./bytes.js";
import { dsha256 } from "./hash.js";

export function legacySighash(tx, inputIndex, scriptCode, sighashType = 0x01) {
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
  return dsha256(concat(...parts));
}

export function bip143Context(tx) {
  if (tx._bip143Ctx) return tx._bip143Ctx;
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
  const ctx = { hashPrevouts, hashSequence, hashOutputs };
  Object.defineProperty(tx, "_bip143Ctx", { value: ctx, enumerable: false });
  return ctx;
}

export function bip143Sighash(tx, inputIndex, scriptCode, amount, sighashType = 0x01) {
  const { hashPrevouts, hashSequence, hashOutputs } = bip143Context(tx);
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
