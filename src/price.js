import { esploraFetch } from "./net.js";

let _BTC_USD = { price: null, ts: 0 };

export async function fetchBtcUsdPrice() {
  if (_BTC_USD.price && Date.now() - _BTC_USD.ts < 10 * 60 * 1000) return _BTC_USD.price;
  const sources = [
    { url: "https://mempool.space/api/v1/prices", pick: (j) => j.USD },
    { url: "https://api.coinbase.com/v2/prices/BTC-USD/spot", pick: (j) => Number(j.data && j.data.amount) },
    { url: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd", pick: (j) => j.bitcoin && j.bitcoin.usd },
  ];
  for (const src of sources) {
    try {
      const r = await fetch(src.url, { headers: { "user-agent": "btc-sig-analyzer/1.0" } });
      if (!r.ok) continue;
      const j = await r.json();
      const p = Number(src.pick(j));
      if (Number.isFinite(p) && p > 0) {
        _BTC_USD = { price: p, ts: Date.now() };
        return p;
      }
    } catch {}
  }
  return null;
}

export function formatUSD(usd) {
  if (usd == null || !Number.isFinite(usd)) return "—";
  return "$" + usd.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

export async function fetchAddressBalance(base, address) {
  try {
    const info = await esploraFetch(base, "/address/" + address);
    const cs = info.chain_stats || {};
    const ms = info.mempool_stats || {};
    const funded = (cs.funded_txo_sum || 0) + (ms.funded_txo_sum || 0);
    const spent = (cs.spent_txo_sum || 0) + (ms.spent_txo_sum || 0);
    const txCount = (cs.tx_count || 0) + (ms.tx_count || 0);
    return { balanceSat: funded - spent, totalReceivedSat: funded, txCount };
  } catch (e) {
    return { balanceSat: null, totalReceivedSat: null, txCount: null, error: e.message };
  }
}

export function formatBTC(sats) {
  if (sats == null) return "?";
  const btc = Number(sats) / 1e8;
  return btc.toFixed(8) + " BTC (" + sats.toLocaleString("en-US") + " sat)";
}
