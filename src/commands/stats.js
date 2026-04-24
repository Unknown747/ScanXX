import { existsSync, readFileSync } from "node:fs";
import { c, C, ICON, header, kv, sep } from "../ui.js";

export function showStats(logPath, dateFilter) {
  if (!logPath || !existsSync(logPath)) {
    console.log(c(C.yellow, "File log tidak ditemukan: " + (logPath || "(tidak diset)")));
    console.log(c(C.dim, "Aktifkan logging via config.json (\"logEnabled\": true) lalu jalankan scan dulu."));
    return;
  }
  let raw;
  try { raw = readFileSync(logPath, "utf8"); }
  catch (e) { console.log(c(C.red, "Gagal baca log: " + e.message)); return; }

  const lines = raw.split("\n").filter(Boolean);
  const re = /^\[(\d{4}-\d{2}-\d{2}) ([\d:.]+)\] \[(\w+)\] (.*)$/;
  const parsed = [];
  for (const ln of lines) {
    const m = ln.match(re);
    if (!m) continue;
    if (dateFilter && m[1] !== dateFilter) continue;
    parsed.push({ date: m[1], time: m[2], level: m[3], msg: m[4] });
  }

  console.log();
  header("Ringkasan scan.log", logPath + (dateFilter ? "  (filter tanggal: " + dateFilter + ")" : ""));

  if (parsed.length === 0) {
    console.log(c(C.yellow, "Tidak ada baris yang cocok."));
    return;
  }

  const byLevel = {};
  for (const p of parsed) byLevel[p.level] = (byLevel[p.level] || 0) + 1;

  const scans = [];
  const startedAt = {};
  const retryByAddr = {};
  const errorByAddr = {};
  const hits = [];

  const tsMs = (date, time) => Date.parse(date + "T" + time + "Z");

  for (const p of parsed) {
    if (p.level === "SCAN") {
      const mStart = p.msg.match(/^mulai scan address=(\S+)/);
      const mEnd = p.msg.match(/^selesai address=(\S+) durasi=([\d.]+)s sigs=(\d+) tx=(\d+) errors=(\d+)/);
      if (mStart) startedAt[mStart[1]] = tsMs(p.date, p.time);
      else if (mEnd) {
        scans.push({
          address: mEnd[1],
          durasi: parseFloat(mEnd[2]),
          sigs: parseInt(mEnd[3], 10),
          tx: parseInt(mEnd[4], 10),
          errors: parseInt(mEnd[5], 10),
        });
      }
    } else if (p.level === "RETRY" || p.level === "ERROR" || p.level === "WARN") {
      const mAddr = p.msg.match(/\/address\/([a-zA-Z0-9]{20,})/) ||
                    p.msg.match(/pagination\[([^\]]+)\]/);
      const key = mAddr ? mAddr[1] : "(lain)";
      if (p.level === "RETRY") retryByAddr[key] = (retryByAddr[key] || 0) + 1;
      else errorByAddr[key] = (errorByAddr[key] || 0) + 1;
    } else if (p.level === "HIT") {
      hits.push(p);
    }
  }

  const totalSigs = scans.reduce((s, x) => s + x.sigs, 0);
  const totalTx = scans.reduce((s, x) => s + x.tx, 0);
  const totalDur = scans.reduce((s, x) => s + x.durasi, 0);
  const avgDur = scans.length ? (totalDur / scans.length) : 0;

  sep("Distribusi Level Log");
  for (const lvl of ["SCAN", "HIT", "RETRY", "WARN", "ERROR"]) {
    const n = byLevel[lvl] || 0;
    const col = lvl === "HIT" ? C.green : lvl === "ERROR" ? C.red : lvl === "WARN" ? C.yellow : lvl === "RETRY" ? C.cyan : C.bold;
    kv(lvl, String(n), col);
  }

  console.log();
  sep("Aktivitas Scan");
  kv("Scan selesai",    String(scans.length),                         C.white);
  kv("Total tx",        totalTx.toLocaleString("id-ID"),              C.cyan);
  kv("Total signature", totalSigs.toLocaleString("id-ID"),            C.cyan);
  kv("Total durasi",    totalDur.toFixed(1) + " dtk / " + (totalDur / 60).toFixed(1) + " mnt", C.dim);
  kv("Rata-rata",       avgDur.toFixed(1) + " dtk/scan",              C.dim);

  if (hits.length > 0) {
    console.log();
    sep("Private Key Dipulihkan (" + hits.length + ")");
    for (const h of hits.slice(-10)) {
      console.log("  " + ICON.key + " " + c(C.dim, h.date + " " + h.time + "  ") + c(C.green, h.msg));
    }
    if (hits.length > 10) console.log(c(C.dim, "  … (" + (hits.length - 10) + " hit lebih lama)"));
  }

  const topRetry = Object.entries(retryByAddr).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topRetry.length > 0) {
    console.log();
    sep("Top 10 Sumber Retry");
    for (const [k, v] of topRetry) console.log("  " + c(C.cyan, String(v).padStart(5)) + "  " + c(C.dim, k));
  }

  const topErr = Object.entries(errorByAddr).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topErr.length > 0) {
    console.log();
    sep("Top 10 Sumber Error");
    for (const [k, v] of topErr) console.log("  " + c(C.red, String(v).padStart(5)) + "  " + c(C.dim, k));
  }
  console.log();
}
