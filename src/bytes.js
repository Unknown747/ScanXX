export const hexToBytes = (h) => {
  h = h.replace(/^0x/, "").replace(/\s+/g, "").toLowerCase();
  if (h.length % 2) throw new Error("Hex panjangnya harus genap");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
};

const _HEX = new Array(256);
for (let i = 0; i < 256; i++) _HEX[i] = i.toString(16).padStart(2, "0");

export const bytesToHex = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i++) s += _HEX[b[i]];
  return s;
};

export const bytesToBigInt = (b) => {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
};

export const concat = (...arr) => {
  const total = arr.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arr) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};

export const reverseBytes = (b) => {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
};

export const padHex = (n, len = 64) => n.toString(16).padStart(len, "0");

export function readVarInt(buf, off) {
  const f = buf[off];
  if (f < 0xfd) return { value: f, size: 1 };
  if (f === 0xfd) return { value: buf[off + 1] | (buf[off + 2] << 8), size: 3 };
  if (f === 0xfe)
    return {
      value:
        buf[off + 1] |
        (buf[off + 2] << 8) |
        (buf[off + 3] << 16) |
        (buf[off + 4] << 24),
      size: 5,
    };
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(buf[off + 1 + i]) << BigInt(8 * i);
  return { value: Number(v), size: 9 };
}

export function writeVarInt(n) {
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

export function u32le(n) {
  const out = new Uint8Array(4);
  out[0] = n & 0xff;
  out[1] = (n >>> 8) & 0xff;
  out[2] = (n >>> 16) & 0xff;
  out[3] = (n >>> 24) & 0xff;
  return out;
}

export function u64le(n) {
  const out = new Uint8Array(8);
  if (typeof n === "number" && Number.isSafeInteger(n) && n >= 0) {
    let lo = n >>> 0;
    let hi = Math.floor(n / 0x100000000) >>> 0;
    out[0] = lo & 0xff;
    out[1] = (lo >>> 8) & 0xff;
    out[2] = (lo >>> 16) & 0xff;
    out[3] = (lo >>> 24) & 0xff;
    out[4] = hi & 0xff;
    out[5] = (hi >>> 8) & 0xff;
    out[6] = (hi >>> 16) & 0xff;
    out[7] = (hi >>> 24) & 0xff;
    return out;
  }
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
