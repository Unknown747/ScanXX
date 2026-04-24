import { c, C, header, kv, sep } from "../ui.js";
import { getPool, printPoolReport } from "../endpoints.js";
import { fetchWithTimeout } from "../net.js";

export async function showEndpoints(opts = {}) {
  const base = opts.api || (await import("../config.js")).DEFAULT_API;
  const pool = getPool(base);

  header("Pool Endpoint", "Status, latency & uji koneksi multi-endpoint");
  kv("Total endpoint", String(pool.size()), C.cyan);
  kv("Primary", pool.primary, C.yellow);
  kv("Strategi", pool.strategy + (pool.strategy === "latency" ? " (auto-rank tercepat)" : ""), C.magenta);
  sep("Daftar");

  if (opts.test) {
    console.log(c(C.dim, "  Menguji setiap endpoint (GET /blocks/tip/height) ...\n"));
    const results = await Promise.all(pool.list().map(async (ep) => {
      const url = ep.url + "/blocks/tip/height";
      const t0 = Date.now();
      try {
        const r = await fetchWithTimeout(url, { headers: { "user-agent": "btc-sig-analyzer/1.0" } }, 10000);
        const dt = Date.now() - t0;
        if (r.ok) {
          const tip = (await r.text()).trim().slice(0, 12);
          ep.latencyMs = dt;
          ep.lastProbeMs = Date.now();
          return { ep, dt, ok: true, status: r.status, tip };
        }
        ep.latencyMs = Infinity;
        ep.lastProbeMs = Date.now();
        return { ep, dt, ok: false, status: r.status };
      } catch (e) {
        const dt = Date.now() - t0;
        ep.latencyMs = Infinity;
        ep.lastProbeMs = Date.now();
        return { ep, dt, ok: false, err: e.message || String(e) };
      }
    }));

    const ranked = results.slice().sort((a, b) => {
      if (a.ok !== b.ok) return a.ok ? -1 : 1;
      return a.dt - b.dt;
    });
    let rankN = 1;
    for (const r of ranked) {
      const tag = r.ep.url === pool.primary ? c(C.yellow, " (primary)") : "";
      const rankStr = c(C.dim, "#" + String(rankN++).padStart(2));
      if (r.ok) {
        console.log("  " + rankStr + "  " + c(C.green, "OK   ") + " " + c(C.cyan, r.ep.url) + tag + c(C.dim, "  (" + r.dt + "ms · tip=" + r.tip + ")"));
      } else if (r.status) {
        console.log("  " + rankStr + "  " + c(C.red, "HTTP " + r.status) + " " + c(C.cyan, r.ep.url) + tag + c(C.dim, "  (" + r.dt + "ms)"));
      } else {
        console.log("  " + rankStr + "  " + c(C.red, "FAIL ") + " " + c(C.cyan, r.ep.url) + tag + c(C.dim, "  (" + r.dt + "ms · " + r.err + ")"));
      }
    }
    const okCount = ranked.filter((r) => r.ok).length;
    console.log();
    console.log(c(C.dim, "  " + okCount + "/" + ranked.length + " endpoint sehat. Strategi '" + pool.strategy + "' akan utamakan endpoint paling cepat & sehat."));
    console.log();
  } else {
    printPoolReport(pool);
    console.log(c(C.dim, "  Tip: --test untuk uji koneksi & ranking latency."));
    console.log(c(C.dim, "  Strategi: --strategy latency|round-robin|primary  atau config → endpointStrategy"));
    console.log(c(C.dim, "  Tambah endpoint via --endpoints \"url1,url2\" atau config → endpoints: []\n"));
  }
}
