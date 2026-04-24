export const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  red:     "\x1b[31m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  magenta: "\x1b[35m",
  cyan:    "\x1b[36m",
  white:   "\x1b[97m",
  gray:    "\x1b[90m",
  bgRed:   "\x1b[41m",
};

export const useColor = !process.env.NO_COLOR && (process.stdout.isTTY || !!process.env.FORCE_COLOR);
export const c = (col, s) => (useColor ? col + s + C.reset : s);

export const W = (() => {
  const cols = (process.stdout && process.stdout.columns) || 0;
  if (!cols) return 74;
  return Math.min(120, Math.max(60, cols - 2));
})();

const isWideCodePoint = (cp) => {
  if (
    (cp >= 0x1100 && cp <= 0x115F) ||
    (cp >= 0x2E80 && cp <= 0x303E) ||
    (cp >= 0x3041 && cp <= 0x33FF) ||
    (cp >= 0x3400 && cp <= 0x4DBF) ||
    (cp >= 0x4E00 && cp <= 0x9FFF) ||
    (cp >= 0xA000 && cp <= 0xA4CF) ||
    (cp >= 0xAC00 && cp <= 0xD7A3) ||
    (cp >= 0xF900 && cp <= 0xFAFF) ||
    (cp >= 0xFE30 && cp <= 0xFE4F) ||
    (cp >= 0xFF00 && cp <= 0xFF60) ||
    (cp >= 0xFFE0 && cp <= 0xFFE6)
  ) return true;
  if (
    (cp >= 0x231A && cp <= 0x231B) ||
    (cp >= 0x23E9 && cp <= 0x23EC) || cp === 0x23F0 || cp === 0x23F3 ||
    (cp >= 0x25FD && cp <= 0x25FE) ||
    (cp >= 0x2614 && cp <= 0x2615) ||
    (cp >= 0x2648 && cp <= 0x2653) ||
    cp === 0x267F || cp === 0x2693 ||
    cp === 0x26A1 ||
    (cp >= 0x26AA && cp <= 0x26AB) ||
    (cp >= 0x26BD && cp <= 0x26BE) ||
    (cp >= 0x26C4 && cp <= 0x26C5) ||
    cp === 0x26CE || cp === 0x26D4 || cp === 0x26EA ||
    (cp >= 0x26F2 && cp <= 0x26F3) || cp === 0x26F5 || cp === 0x26FA || cp === 0x26FD ||
    cp === 0x2705 || (cp >= 0x270A && cp <= 0x270B) ||
    cp === 0x2728 || cp === 0x274C || cp === 0x274E ||
    (cp >= 0x2753 && cp <= 0x2755) || cp === 0x2757 ||
    (cp >= 0x2795 && cp <= 0x2797) || cp === 0x27B0 || cp === 0x27BF ||
    (cp >= 0x2B1B && cp <= 0x2B1C) || cp === 0x2B50 || cp === 0x2B55
  ) return true;
  if (cp >= 0x1F000 && cp <= 0x1FFFF) return true;
  return false;
};

export const visLen = (s) => {
  const stripped = s.replace(/\x1b\[[0-9;]*m/g, "");
  let width = 0;
  for (const ch of stripped) {
    const cp = ch.codePointAt(0);
    if (cp === 0xFE0F || cp === 0xFE0E) continue;
    if (cp === 0x200D) continue;
    if (cp >= 0x0300 && cp <= 0x036F) continue;
    if (cp >= 0xFE00 && cp <= 0xFE0F) continue;
    width += isWideCodePoint(cp) ? 2 : 1;
  }
  return width;
};

export const sep = (t = "") => {
  if (!t) {
    console.log(c(C.gray, "  " + "─".repeat(W - 2)));
    return;
  }
  const prefix = "  ┄┄ ";
  const suffix = " " + "┄".repeat(Math.max(2, W - prefix.length - visLen(t) - 1));
  console.log(c(C.gray, prefix) + c(C.bold + C.yellow, t) + c(C.gray, suffix));
};

export function header(title, subtitle) {
  const inner = W - 2;
  const top = "╔" + "═".repeat(inner) + "╗";
  const div = "╠" + "═".repeat(inner) + "╣";
  const bot = "╚" + "═".repeat(inner) + "╝";
  const row = (s, col) => {
    const vis = visLen(s);
    const pad = Math.max(0, inner - vis - 2);
    return c(col || C.yellow, "║ ") + s + " ".repeat(pad) + c(col || C.yellow, " ║");
  };
  console.log(c(C.yellow + C.bold, top));
  console.log(row(c(C.bold + C.white, "  " + title), C.yellow));
  if (subtitle) {
    console.log(c(C.yellow, div));
    console.log(row(c(C.dim, "  " + subtitle), C.yellow));
  }
  console.log(c(C.yellow + C.bold, bot));
}

export function kv(label, value, color) {
  const LAB = 11;
  const lab = label.length >= LAB ? label : label.padEnd(LAB);
  const dots = c(C.gray, " ··· ");
  const val = color ? c(color, String(value)) : c(C.white, String(value));
  console.log(c(C.gray, "  ") + c(C.dim, lab) + dots + val);
}

export function box(title, lines, accent) {
  accent = accent || C.green;
  const inner = W - 2;
  const top = "╔" + "═".repeat(inner) + "╗";
  const div = "╠" + "═".repeat(inner) + "╣";
  const bot = "╚" + "═".repeat(inner) + "╝";
  const row = (s) => {
    const vis = visLen(s);
    const pad = Math.max(0, inner - vis - 2);
    return c(accent, "║ ") + s + " ".repeat(pad) + c(accent, " ║");
  };
  console.log(c(accent + C.bold, top));
  console.log(row(c(accent + C.bold, "  " + title)));
  console.log(c(accent, div));
  for (const ln of lines) console.log(row("  " + ln));
  console.log(c(accent + C.bold, bot));
}

export const ICON = {
  ok:     useColor ? "\x1b[32m✔\x1b[0m"  : "[OK]",
  err:    useColor ? "\x1b[31m✘\x1b[0m"  : "[ERR]",
  info:   useColor ? "\x1b[36mℹ\x1b[0m"  : "[i]",
  key:    useColor ? "\x1b[33m🔑\x1b[0m" : "[KEY]",
  money:  useColor ? "\x1b[32m💰\x1b[0m" : "[$]",
  alert:  useColor ? "\x1b[31m🚨\x1b[0m" : "[!!]",
  arrow:  useColor ? "\x1b[33m❯\x1b[0m"  : ">",
  btc:    useColor ? "\x1b[33m₿\x1b[0m"  : "BTC",
  scan:   useColor ? "\x1b[36m⬡\x1b[0m"  : "[S]",
  search: useColor ? "\x1b[36m⌕\x1b[0m"  : "[?]",
  file:   useColor ? "\x1b[35m◈\x1b[0m"  : "[F]",
  tool:   useColor ? "\x1b[90m◆\x1b[0m"  : "[T]",
  bolt:   useColor ? "\x1b[33m⚡\x1b[0m" : "[!]",
  dot:    useColor ? "\x1b[90m·\x1b[0m"  : ".",
  bullet: useColor ? "\x1b[90m›\x1b[0m"  : ">",
  pipe:   useColor ? "\x1b[90m│\x1b[0m"  : "|",
};

// Spinner (Braille) untuk status berjalan
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
export function spinner(i) { return SPINNER_FRAMES[i % SPINNER_FRAMES.length]; }

// Multi-segment status line: [["label","value",color], ...]
export function statusLine(segments) {
  const sep = c(C.gray, " " + (useColor ? "│" : "|") + " ");
  return segments.map(([k, v, col]) =>
    c(C.dim, k + "=") + c(col || C.white, String(v))
  ).join(sep);
}

// Sub-bullet item yang konsisten dgn kv()
export function subItem(text, color) {
  console.log("  " + c(C.gray, (useColor ? "›" : ">") + " ") + (color ? c(color, text) : text));
}

// Pretty cycle/section banner dengan chevron
export function cycleBanner(n, summary, color) {
  const tag = c((color || C.yellow) + C.bold, " ❯ Siklus #" + n + " ");
  const dash = c(C.gray, "─".repeat(Math.max(2, W - visLen(tag) - visLen(summary || "") - 4)));
  console.log("  " + tag + dash + (summary ? "  " + c(C.dim, summary) : ""));
}

export function banner() {
  if (!useColor) {
    console.log("=".repeat(W));
    console.log(" BTC-SIG-ANALYZER  —  Bitcoin ECDSA Signature Analyzer & Key Recovery");
    console.log("=".repeat(W));
    return;
  }
  const I = W - 2;
  const ln = (s, col) => {
    const pad = Math.max(0, I - visLen(s) - 2);
    return c(col, "║ ") + s + " ".repeat(pad) + c(col, " ║");
  };
  const G = C.yellow + C.bold;
  const D = C.gray;
  console.log(c(G, "╔" + "═".repeat(I) + "╗"));
  console.log(ln("", D));
  console.log(ln(
    c(C.yellow + C.bold, "  ₿  BTC-SIG-ANALYZER") +
    c(C.gray, "  ·  ") +
    c(C.white + C.bold, "Bitcoin ECDSA Signature Analyzer"),
    C.yellow
  ));
  console.log(ln(
    c(C.dim, "     Deteksi R-Reuse  ·  Ekstrak R/S/Z  ·  Pulihkan Private Key"),
    C.yellow
  ));
  console.log(ln("", D));
  console.log(c(G, "╚" + "═".repeat(I) + "╝"));
}

// Smooth 8-step block progress bar
const BAR_BLOCKS = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];
function smoothBar(pct, w) {
  const eighths = Math.max(0, Math.min(w * 8, Math.round(pct * w * 8)));
  const full = Math.floor(eighths / 8);
  const rem  = eighths - full * 8;
  let s = "█".repeat(full);
  if (rem > 0 && full < w) s += BAR_BLOCKS[rem];
  const empty = w - full - (rem > 0 && full < w ? 1 : 0);
  return s + "░".repeat(empty);
}

export function drawProgress(done, total, startTs, label = "") {
  const w = 28;
  const pct = total ? done / total : 0;
  const barRaw = smoothBar(pct, w);
  // Split bar agar bisa kasih warna gradient (filled vs empty)
  const fillCount = barRaw.split("░")[0].length;
  const filled = barRaw.slice(0, fillCount);
  const empty  = barRaw.slice(fillCount);
  const fillColor = pct < 0.33 ? C.cyan : pct < 0.75 ? C.yellow : C.green;
  const bar = c(C.gray, "▕") + c(fillColor + C.bold, filled) + c(C.gray, empty) + c(C.gray, "▏");

  const elapsed = (Date.now() - startTs) / 1000;
  const rate = done / Math.max(elapsed, 0.001);
  const eta = rate > 0 ? Math.max(0, (total - done) / rate) : 0;
  const fmt = (s) => {
    if (!isFinite(s)) return "--";
    const m = Math.floor(s / 60), sec = Math.floor(s % 60);
    return m + "m" + String(sec).padStart(2, "0") + "s";
  };
  const sep = c(C.gray, " " + (useColor ? "│" : "|") + " ");
  const line =
    "\r" + bar + " " +
    c(C.bold + C.white, (pct * 100).toFixed(1).padStart(5) + "%") + sep +
    c(C.cyan, done + "/" + total) + sep +
    c(C.magenta, rate.toFixed(1) + "/dtk") + sep +
    c(C.dim, "ETA " + fmt(eta)) +
    (label ? sep + c(C.dim, label) : "") +
    "\x1b[K";
  process.stdout.write(line);
}
