import { c, C, header, kv, sep } from "../ui.js";
import { getPool, printPoolReport } from "../endpoints.js";
import { fetchWithTimeout } from "../net.js";

export async function showEndpoints(opts = {}) {
  const base = opts.api || (await import("../config.js")).DEFAULT_API;
  const pool = getPool(base);

  header("Pool Endpoint", "Status & uji koneksi multi-endpoint");
  kv("Total endpoint", String(pool.size()), C.cyan);
  kv("Primary", pool.primary, C.yellow);
  sep("Daftar");

  if (opts.test) {
    console.log(c(C.dim, "  Menguji setiap endpoint (GET /blocks/tip/height) ...\n"));
    for (const ep of pool.list()) {
      const url = ep.url + "/blocks/tip/height";
      const t0 = Date.now();
      try {
        const r = await fetchWithTimeout(url, { headers: { "user-agent": "btc-sig-analyzer/1.0" } }, 10000);
        const dt = Date.now() - t0;
        if (r.ok) {
          const txt = (await r.text()).trim().slice(0, 12);
          console.log("  " + c(C.green, "OK   ") + " " + c(C.cyan, ep.url) + c(C.dim, "  (" + dt + "ms · tip=" + txt + ")"));
        } else {
          console.log("  " + c(C.red, "HTTP " + r.status) + " " + c(C.cyan, ep.url) + c(C.dim, "  (" + dt + "ms)"));
        }
      } catch (e) {
        const dt = Date.now() - t0;
        console.log("  " + c(C.red, "FAIL ") + " " + c(C.cyan, ep.url) + c(C.dim, "  (" + dt + "ms · " + (e.message || e) + ")"));
      }
    }
    console.log();
  } else {
    printPoolReport(pool);
    console.log(c(C.dim, "  Tip: jalankan dengan --test untuk uji koneksi tiap endpoint."));
    console.log(c(C.dim, "  Tambah endpoint via --endpoints \"url1,url2\" atau config.json → endpoints: []\n"));
  }
}
