import { c, C } from "./ui.js";

export const PROFILE = { enabled: false, marks: new Map() };

export function profStart(label) {
  if (!PROFILE.enabled) return;
  let m = PROFILE.marks.get(label);
  if (!m) { m = { totalMs: 0, calls: 0, _t: 0 }; PROFILE.marks.set(label, m); }
  m._t = Date.now();
}

export function profEnd(label) {
  if (!PROFILE.enabled) return;
  const m = PROFILE.marks.get(label);
  if (!m || !m._t) return;
  m.totalMs += Date.now() - m._t;
  m.calls++;
  m._t = 0;
}

export function profReport() {
  if (!PROFILE.enabled || PROFILE.marks.size === 0) return;
  console.log();
  console.log(c(C.gray, "  ┌─ PROFILE ───────────────────────────────────────────────┐"));
  const rows = Array.from(PROFILE.marks.entries()).sort((a, b) => b[1].totalMs - a[1].totalMs);
  for (const [label, m] of rows) {
    const avg = m.calls ? (m.totalMs / m.calls).toFixed(1) : "0.0";
    const line = "  " + label.padEnd(20) + " total=" + (m.totalMs + "ms").padEnd(10) +
                 " calls=" + String(m.calls).padEnd(6) + " avg=" + avg + "ms";
    console.log(c(C.dim, "  │") + line);
  }
  console.log(c(C.gray, "  └─────────────────────────────────────────────────────────┘"));
}
