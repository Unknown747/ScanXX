import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";

export const dsha256 = (b) => sha256(sha256(b));
export const hash160 = (b) => ripemd160(sha256(b));

export const N = secp256k1.CURVE.n;
export const mod = (a, m = N) => ((a % m) + m) % m;

export const invMod = (a, m = N) => {
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

export { secp256k1, sha256, ripemd160 };
