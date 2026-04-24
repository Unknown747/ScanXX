# btc-sig-analyzer

CLI Node.js (ESM) untuk ekstraksi `R/S/Z` dari transaksi Bitcoin & pemulihan private key saat ada R-reuse (ECDSA nonce reuse). Antarmuka Bahasa Indonesia.

## Stack
- Node.js >= 18 (ESM, `"type": "module"`)
- `@noble/curves` (secp256k1), `@noble/hashes` (sha256, ripemd160)
- Tanpa framework web, tanpa server. Single-file CLI (~2540 baris).

## Struktur
- `index.js` — seluruh CLI (single file, semua logic + UI)
- `package.json` — `@noble/curves ^1.6.0`, `@noble/hashes ^1.5.0`, ESM type module
- `.btc-cache/` — runtime cache (di-gitignore)
- `hits.txt` / `hits_LIVE.txt` / `hits_CROSS.txt` — output runtime (di-gitignore)
- `config.json` — konfigurasi opsional (di-gitignore)

## Visual / UI Theme
- Lebar W=74, tema emas/Bitcoin (gold, orange, yellow)
- Banner: kotak `╔═╗` double-line
- `header(title, sub)` — header kotak per sub-command
- `sep(label)` — separator baris tipis `┄`
- `kv(key, val, color)` — baris dot-leader `  Key ··· Value`
- `box(title, lines, color)` — kotak notifikasi
- ICON set: scan, search, ok, err, key, info, btc, alert, dll

## Default
- API: `https://mempool.space/api`
- Concurrency scan address: 8
- TTL cache daftar tx address: 6 jam; cache hex tx: permanen
- Hits file: `hits.txt`

## Perintah utama
- `node index.js` — menu interaktif (pilihan 0-9, C)
- `node index.js txid <txid>`
- `node index.js address <addr> [--concurrency N]`
- `node index.js tx <hex>` / `tx-file <path>` (`--amount i=sats` untuk SegWit)
- `node index.js sig --r --s --z [--pub]`
- `node index.js reuse <file.json>`
- `node index.js explore [--mode mempool|blocks] [--limit N]` — scan tx dari explorer
- `node index.js daemon [--mode mempool|blocks] [--interval <dtk>] [--limit N]` — loop otomatis + alert R-reuse
- `node index.js stats [logfile] [--date YYYY-MM-DD]`
- `node index.js clear-cache`
- Flag global: `--api`, `--out`, `--hits`, `--verbose`, `--no-cache`, `--limit`, `--mode`, `--interval`

## Menu Interaktif (pilihan)
- 1: Scan Address
- 2: Analisis TXID
- 3: Batch Scan File
- 4: Scan Explorer (mempool/blocks)
- 5: Daemon Auto-Scan (loop berkelanjutan)
- 6: Raw TX Hex
- 7: Signature Manual (R/S/Z)
- 8: R-Reuse dari JSON
- 9: Bantuan Lengkap
- C: Hapus Cache
- 0: Keluar

## Daemon (runDaemon)
- Loop tiap N detik (default 60), ambil txids baru dari mempool atau blok terbaru
- Track `seenTxids` Set supaya tidak proses tx yang sama dua kali
- Akumulasi `sigPool` lintas siklus untuk deteksi R-reuse lintas tx
- Alert di terminal + simpan ke hits file + Telegram jika R-reuse ditemukan
- Countdown timer countdown antar siklus, Ctrl+C untuk berhenti gracefully
- Ringkasan akhir: total siklus, tx, sig, hit

## Konfigurasi
- `config.json` (opsional): `api`, `concurrency`, `hitsFile`,
  `cache.{enabled,listMaxAgeHours}`,
  `telegram.{enabled,botToken,chatId,notifyOnLiveOnly}`.
- Telegram `notifyTelegram()` dipanggil saat ada hit R-reuse.

## Roadmap
- Dukungan Taproot (BIP-341)
- Cek saldo segwit `bc1q...` di daemon hit
