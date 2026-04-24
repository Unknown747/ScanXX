# btc-sig-analyzer

CLI Node.js (ESM) untuk ekstraksi `R/S/Z` dari transaksi Bitcoin & pemulihan private key saat ada R-reuse (ECDSA nonce reuse). Antarmuka Bahasa Indonesia.

## Stack
- Node.js >= 18 (ESM, `"type": "module"`)
- `@noble/curves` (secp256k1), `@noble/hashes` (sha256, ripemd160)
- `undici` (HTTP/1.1 keep-alive Agent untuk fetch), `ws` (WebSocket realtime)
- Tanpa framework web, tanpa server. CLI modular (~3000 baris terbagi ke modul-modul kecil).

## Struktur
- `index.js` — entry tipis (~150 baris): parsing argv, dispatch ke command handlers
- `src/` — modul library inti
  - `config.js` — load `config.json`, `CACHE_ENABLED` live binding + `setCacheEnabled()`
  - `log.js` — `logScan(level, msg)` ke `scan.log`
  - `bytes.js` — `hexToBytes`, `bytesToHex`, `padHex`, `concat`, `reverseBytes`, `u32le`, `u64le`, dll
  - `hash.js` — re-export `secp256k1`, `sha256d`, `hash160`, `pubkeysFromPriv(dHex)` (single scalar mult via ProjectivePoint, dipakai analysis.js + daemon.js)
  - `ui.js` — palette `C`, `ICON`, `banner`, `header`, `kv`, `sep`, `box`, `drawProgress`, `visLen`, `W`
  - `profile.js` — `PROFILE.enabled`, `profStart/End/Report`
  - `tx.js` — `parseDER`, `parseScriptPushes`, `readVarInt/writeVarInt`, `parseTx`
  - `sighash.js` — `legacySighash`, `bip143Context`, `bip143Sighash`
  - `address.js` — `base58Encode`, `bech32Encode`, `p2pkhAddress`, `p2wpkhAddress`, `p2shP2wpkhAddress`, `toWIF`
  - `ecdsa.js` — `recoverPrivateKey(r,s1,z1,s2,z2)`
  - `net.js` — undici Agent global, `esploraFetch`, `fetchWithTimeout`, `rateLimitWait`, `REQ_STATS`, `reqRatePerSec`, `RETRY`, `sleep`
  - `telegram.js` — `notifyTelegram(text)`
  - `price.js` — `fetchBtcUsdPrice`, `formatBTC`, `formatUSD`, `fetchAddressBalance`
  - `cache.js` — `LRUSet` (+`toArray()`), `LRUMap`, `CACHE_DIR`, `SEEN_FILE`, daily NDJSON shards dengan **lazy load** (`fetchTxHexCached`, `pruneOldCache`, `_listShards`, `_loadShard`, legacy `.hex` migration+delete), `RECENT_SHARDS` window, address-list cache, resume state, watchlist, `appendHit` **WriteStream** + `closeAllHitsStreams`, `CACHE_STATS`
  - `analysis.js` — `detectReuse`, `processTxInputs` (shared core), `processTxForAddress`/`processTxAllInputs` (thin wrappers), `runWithConcurrency`, `fetchAllTxsForAddress`, internal `formatHitText`, `buildScriptCodeP2PKH`
- `src/commands/` — handler per sub-command
  - `analyze.js` — `analyzeTx`, `analyzeManual`, `analyzeByTxid`
  - `address.js` — `analyzeAddress`, `batchAddresses`
  - `explore.js` — `scanExplore` (single-pipeline)
  - `daemon.js` — `runDaemon` (loop + WS)
  - `stats.js` — `showStats` (parse `scan.log`)
  - `help.js` — `help()` banner
  - `menu.js` — `interactiveMenu()`
- `package.json` — `@noble/curves ^1.6.0`, `@noble/hashes ^1.5.0`, `undici`, `ws`, ESM type module
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
- **Trending nonce (Top R ≥2)**: baris bonus muncul kalau ada R muncul ≥2× di pool — top-3 ditampilkan dengan format `N× <r-prefix>…`. Diam saat tidak ada (hindari noise). Bermanfaat memantau R yang "hot" sebelum menjadi hit.
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
- **Bounded `_txIndex`**: LRUMap cap 50k entri (`cache.txIndexCap`) — daemon long-run tidak meledakkan heap saat NDJSON shard jadi gemuk
- Persisted seenTxids snapshot — restart daemon tidak re-scan
- Telegram fire-and-forget — notify tidak nge-block daemon loop
- WebSocket realtime mempool.space (opsional, fallback otomatis ke polling) dengan **exponential backoff + jitter** (cap 30 dtk) untuk reconnect
- Auto terminal width detection
- `detectReuse` O(n) via Map grouping per R (inner pair-loop hanya per group)
- Resume scan address (state file per address di `.btc-cache/`) — Ctrl+C lalu lanjut tanpa kehilangan progress
- `--profile` flag: tampilkan timing per fase di akhir run (label `http`, dll)
- **Hot-path micro-opts**: `_HEX[256]` lookup table (`bytesToHex`), `bytesToBigInt(b)` langsung dari Uint8Array (skip hex roundtrip di sighash/Z-compute), `u32le/u64le` pakai scratch buffer + fast number-path
- **BIP143 memoization**: `hashPrevouts/hashSequence/hashOutputs` di-cache per-tx via `bip143Context()` — hemat banyak SHA256d kalau tx punya >1 input
- **scanExplore single-pipeline**: fetch metadata + ekstrak R/S/Z digabung dalam 1 jalur konkuren (sebelumnya 2 fase serial bikin idle time besar)
- **Daemon block-mode parallel**: fetch txid list per blok pakai `runWithConcurrency` (sebelumnya serial per blok), urutan tetap dijaga

## Konfigurasi (semua dari config.json — menu hanya tanya minimum)
- `config.json` (opsional, ada default kalau tidak ada): `api`, `concurrency`, `hitsFile`,
  `cache.{enabled, listMaxAgeHours, txMaxAgeHours, pruneOnStart, txIndexCap}`,
  `explore.{mode, limit}`,
  `daemon.{mode, interval, limit, realtime, watchFile, seenLimit, poolMaxAgeHours, rateLimit}`,
  `telegram.{enabled, botToken, chatId, notifyOnLiveOnly}`.
- **`limit: 0` artinya unlimited** (tidak ada batas tx) — ini default sekarang untuk explore & daemon.
- Menu interaktif: pilihan #4 (explore) dan #5 (daemon) sekarang **hanya tanya sumber (mempool/blok)**, sisanya otomatis dari config.json — langsung start scan.
- File watchlist: 1 address per baris, baris kosong & `# komentar` diabaikan.
- Telegram `notifyTelegram()` dipanggil saat ada hit R-reuse.

## Optimasi terbaru (round-16)
1. **Single scalar mult**: `pubkeysFromPriv()` di hash.js — 1× ProjectivePoint untuk dua format pubkey (compressed + uncompressed) di tiap hit (sebelumnya 2× scalar mult).
2. **rIndex incremental** di daemon: `Map<rHex, sig[]>` di-maintain sinkron dengan sigPool; saat detect cycle, hanya iterasi R yang baru muncul siklus ini (`checkedR`) — bukan O(pool²) lagi.
3. **freshTxidSet hoisted**: dibangun 1× per siklus, dipakai oleh banyak group fetch (sebelumnya rebuild per group).
4. **/mempool/recent endpoint** saat `--realtime`: hanya tarik tx baru ~10 menit terakhir, bukan full mempool list.
5. **processTxInputs** shared core: `processTxForAddress` & `processTxAllInputs` jadi thin wrapper (dedup parser + sighash logic).
6. **formatHitText** helper: format hits.txt terpusat — dipakai analysis.js & daemon.js (sebelumnya 2 copy).
7. **appendHit pakai WriteStream**: tidak `appendFileSync` lagi — non-blocking, auto-batch via stream buffer; `closeAllHitsStreams` saat exit/SIGINT.
8. **Promise.allSettled** di telegram batch: kegagalan 1 channel tidak gagalkan yang lain.
9. **Lazy shard loading** (`RECENT_SHARDS`): index di-build hanya untuk N shard terbaru (= ceil(txMaxAgeHours/24)+1), shard lama di-load on-demand saat cache miss.
10. **Removed sleep(120)** di akhir scan address — tidak ada gunanya, hanya delay total runtime.
11. **buildScriptCodeP2PKH**: pre-alloc Uint8Array(25) langsung (bukan concat 5 chunk).
12. **Legacy .hex migration+delete**: scan folder lama 1×, masukkan ke shard NDJSON, hapus setelah migrate.
13. **Removed redundant `seen` Set** di scanExplore — `uniqueTxids` sudah dedupe.
14. **ws.on("error")** di daemon: log WARN ke scan.log, tidak silent.
15. **runWithConcurrency** cleaner: tidak return wrapper `{sigs,err}` (langsung throw), kode pemanggil lebih ringkas.
16. **LRUSet.toArray()**: snapshot daemon-seen.json pakai 1 method, bukan iterasi manual.

## Roadmap
- Dukungan Taproot (BIP-341)
- Cek saldo segwit `bc1q...` di daemon hit
