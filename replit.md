# btc-sig-analyzer

CLI Node.js (ESM) untuk ekstraksi `R/S/Z` dari transaksi Bitcoin & pemulihan private key saat ada R-reuse (ECDSA nonce reuse). Antarmuka Bahasa Indonesia.

## Stack
- Node.js >= 18 (ESM, `"type": "module"`)
- `@noble/curves` (secp256k1), `@noble/hashes` (sha256, ripemd160)
- Tanpa framework web, tanpa server. Single-file CLI.

## Struktur
- `index.js` — seluruh CLI (~1.2k baris)
- `package.json` — `bin: btc-sig`, script `start: node ./index.js`
- `.btc-cache/` — runtime cache (di-gitignore)
- `hits.txt` / `hits.jsonl` / `hits_LIVE.txt` — output runtime (di-gitignore)
- `README.md` — dokumentasi pengguna (Bahasa Indonesia)

## Default
- API: `https://mempool.space/api` (blockstream.info sering memblokir IP cloud)
- Concurrency scan address: 8
- TTL daftar tx address di cache: 6 jam; cache hex tx: permanen (tx final)

## Perintah utama
- `node index.js` — menu interaktif
- `node index.js txid <txid>`
- `node index.js address <addr> [--concurrency N]`
- `node index.js tx <hex>` / `tx-file <path>` (`--amount i=sats` untuk SegWit)
- `node index.js sig --r --s --z [--pub]`
- `node index.js reuse <file.json>`
- `node index.js clear-cache`
- Flag global: `--api`, `--out`, `--hits`, `--verbose`, `--no-cache`

## Roadmap (belum dikerjakan)
- Pooling R-reuse lintas address (ingat sig dari scan sebelumnya)
- Batch scan address dari file
- Retry otomatis pada HTTP 429
- Dukungan Taproot (BIP-341)
- Cek saldo segwit `bc1q...`
- Notifikasi Telegram saat hit live
