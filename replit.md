# btc-sig-analyzer

CLI Node.js (ESM) untuk ekstraksi `R/S/Z` dari transaksi Bitcoin & pemulihan private key saat ada R-reuse (ECDSA nonce reuse). Antarmuka Bahasa Indonesia.

## Stack
- Node.js >= 18 (ESM, `"type": "module"`)
- `@noble/curves` (secp256k1), `@noble/hashes` (sha256, ripemd160)
- `undici` (HTTP/1.1 keep-alive Agent untuk fetch), `ws` (WebSocket realtime)
- Tanpa framework web, tanpa server. Single-file CLI (~2820 baris).

## Struktur
- `index.js` — seluruh CLI (single file, semua logic + UI)
- `package.json` — `@noble/curves ^1.6.0`, `@noble/hashes ^1.5.0`, ESM type module
- `.btc-cache/` — runtime cache (di-gitignore)
- `hits.txt` / `hits_LIVE.txt` / `hits_CROSS.txt` — output runtime (di-gitignore)
- `config.json` — konfigurasi opsional (di-gitignore)

## Visual / UI Theme
- Lebar W=auto (clamp 60..120 dari `process.stdout.columns`, fallback 74)
- Tema emas/Bitcoin (gold, orange, yellow)
- Banner: kotak `╔═╗` double-line
- `header(title, sub)` — header kotak per sub-command
- `sep(label)` — separator baris tipis `┄`
- `kv(key, val, color)` — baris dot-leader `  Key ··· Value`
- `box(title, lines, color)` — kotak notifikasi
- ICON set: scan, search, ok, err, key, info, btc, alert, dll

## Default
- API: `https://mempool.space/api`
- Concurrency scan address: 8
- TTL cache daftar tx address: 6 jam
- TTL cache hex tx: 48 jam (auto-prune saat startup)
- Hits file: `hits.txt`
- HTTP keep-alive: pool 32 koneksi per origin (undici Agent global)

## Perintah utama
- `node index.js` — menu interaktif (pilihan 0-9, C)
- `node index.js txid <txid>`
- `node index.js address <addr> [--concurrency N]`
- `node index.js tx <hex>` / `tx-file <path>` (`--amount i=sats` untuk SegWit)
- `node index.js sig --r --s --z [--pub]`
- `node index.js reuse <file.json>`
- `node index.js explore [--mode mempool|blocks] [--limit N]` — scan tx dari explorer
- `node index.js daemon [--mode mempool|blocks] [--interval <dtk>] [--limit N] [--realtime]` — loop otomatis + alert R-reuse (`--realtime` = WebSocket mempool.space, kick siklus saat ada update)
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

## Daemon (runDaemon) — bounded state + persistent
- Loop tiap N detik (default 60), ambil txids baru dari mempool atau blok terbaru
- `seenTxids` = LRUSet (cap `daemon.seenLimit`, default 200k) — memory-bounded
- **Persisted seenTxids**: snapshot ke `.btc-cache/daemon-seen.json` tiap 5 siklus & saat exit (atomic write via `.tmp` + rename). Restore saat startup kalau snapshot < 48 jam → restart daemon tidak re-scan ribuan tx yang sudah dilihat.
- `sigPool` di-evict by waktu (cutoff `daemon.poolMaxAgeHours`, default 24 jam)
- Realtime opsional via WebSocket `wss://mempool.space/api/v1/ws` — pesan WS "kick" memotong sleep agar siklus jalan segera
- **Address watchlist** (`--watch <file>`): file daftar address (1/baris, `#` = komentar). Hit yang nyentuh address watchlist dapat alert merah ekstra + tag `[WATCHLIST!]` di Telegram.
- **Telegram fire-and-forget**: notify pakai `.catch(() => {})` tanpa await — daemon loop tidak ke-block kalau Telegram lambat/timeout.
- Append hits via `WriteStream` (tidak block event loop seperti `appendFileSync`)
- Status bar tiap siklus: `siklus / tx / sig / hit / pool / seen / mem MB / req/s`
- Countdown timer antar siklus, Ctrl+C untuk berhenti gracefully (cleanup WS + stream + save snapshot)
- Ringkasan akhir: total siklus/tx/sig/hit/req + lokasi snapshot

## Cache (daily NDJSON shards)
- Cache hex tx disimpan di `.btc-cache/tx-daily/tx-YYYY-MM-DD.ndjson`
  (1 baris per tx: `{"t":"<txid>","h":"<hex>"}`)
- Index in-memory `Map<txid,hex>` dibangun lazy saat cache hit pertama
- Auto-prune: file shard yang lebih tua dari `cache.txMaxAgeHours` (default 48 jam) dihapus saat startup
- Backward-compat: kalau folder lama `.btc-cache/tx/<txid>.hex` masih ada, dibaca otomatis & ikut diprune saat startup

## Optimasi performa
- HTTP keep-alive: `undici` Agent global (pool 32 koneksi), hindari handshake TCP+TLS berulang
- Token-bucket rate limiter per host (aktif jika `daemon.rateLimit > 0`)
- Retry dengan jitter + `Retry-After` header (anti-429)
- Daily NDJSON cache: 1 file/hari menggantikan ribuan file kecil (jauh lebih cepat di filesystem CoW)
- Bounded daemon state (LRU seenTxids, time-window sigPool) — daemon bisa jalan berhari-hari tanpa OOM
- Persisted seenTxids snapshot — restart daemon tidak re-scan
- Telegram fire-and-forget — notify tidak nge-block daemon loop
- WebSocket realtime mempool.space (opsional, fallback otomatis ke polling)
- Auto terminal width detection
- `detectReuse` O(n) via Map grouping per R (inner pair-loop hanya per group)
- Resume scan address (state file per address di `.btc-cache/`) — Ctrl+C lalu lanjut tanpa kehilangan progress
- `--profile` flag: tampilkan timing per fase di akhir run (label `http`, dll)

## Konfigurasi
- `config.json` (opsional): `api`, `concurrency`, `hitsFile`,
  `cache.{enabled, listMaxAgeHours, txMaxAgeHours, pruneOnStart}`,
  `daemon.{realtime, seenLimit, poolMaxAgeHours, rateLimit, watchFile}`,
  `telegram.{enabled, botToken, chatId, notifyOnLiveOnly}`.
- File watchlist: 1 address per baris, baris kosong & `# komentar` diabaikan.
- Telegram `notifyTelegram()` dipanggil saat ada hit R-reuse.

## Roadmap
- Dukungan Taproot (BIP-341)
- Cek saldo segwit `bc1q...` di daemon hit
