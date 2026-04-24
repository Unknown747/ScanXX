import { mod, invMod } from "./hash.js";

export function recoverPrivateKey(r, s1, z1, s2, z2) {
  const rs = [];
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
