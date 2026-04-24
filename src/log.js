import { appendFileSync } from "node:fs";
import { CONFIG } from "./config.js";

function _ts() {
  const d = new Date();
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
    " " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()) +
    "." + p(d.getMilliseconds(), 3);
}

export function logScan(level, msg) {
  if (!CONFIG.logEnabled || !CONFIG.logFile) return;
  try {
    appendFileSync(CONFIG.logFile, "[" + _ts() + "] [" + level + "] " + msg + "\n");
  } catch {}
}
