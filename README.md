# btc-sig-analyzer

CLI Node.js (ESM) untuk membedah tanda tangan ECDSA pada transaksi Bitcoin. Mengekstrak komponen `R`, `S`, `Z`, public key, dan pubkey hash dari setiap input transaksi — lalu otomatis mendeteksi **R-reuse** (nonce dipakai ulang) dan memulihkan **private key** beserta alamat-alamatnya.

Antarmuka sepenuhnya **Bahasa Indonesia**, tanpa framework web, tanpa server. Cukup `node index.js`.

---

## Fitur

- Ekstraksi `R / S / Z` dari berbagai jenis input:
  - Legacy P2PKH
  - SegWit v0 (P2WPKH, P2SH-P2WPKH) dengan sighash BIP-143
- Deteksi **R-reuse** lintas input/transaksi/address
- Pemulihan private key otomatis bila menemukan R-reuse:
  - `k = (z1 − z2) / (s1 − s2)  mod n`
  - `d = (s1·k − z1) / r        mod n`
- Verifikasi pemulihan dengan mencocokkan public key
- Derivasi alamat (compressed & uncompressed) + WIF mainnet:
  - P2PKH (`1...`), P2WPKH (`bc1q...`), P2SH-P2WPKH (`3...`)
- Cek saldo otomatis tiap alamat hasil pemulihan via mempool.space
- Notifikasi opsional via Telegram (fire-and-forget)
- Mode **daemon** loop berkelanjutan + opsi **realtime** WebSocket mempool.space
- **Watchlist** alamat khusus (alert merah ekstra saat ke-hit)
- Cache lokal di `.btc-cache/` (NDJSON shard harian + auto-prune)
- Scan address paralel dengan progress bar (`--concurrency`)
- Mode interaktif (menu) jika dijalankan tanpa argumen

---

## Stack

- Node.js >= 18 (ESM, `"type": "module"`)
- [`@noble/curves`](https://www.npmjs.com/package/@noble/curves) — secp256k1
- [`@noble/hashes`](https://www.npmjs.com/package/@noble/hashes) — SHA-256, RIPEMD-160
- [`undici`](https://www.npmjs.com/package/undici) — HTTP/1.1 keep-alive Agent untuk fetch
- [`ws`](https://www.npmjs.com/package/ws) — WebSocket client (mode realtime daemon)

---

## Instalasi

```bash
# Node.js >= 18
npm install
# atau
pnpm install
```

---

## Cara Pakai

### Mode interaktif (paling mudah)

```bash
node index.js
```

Pilih dari menu:

```
1) Scan Address
2) Analisis TXID
3) Batch Scan File
4) Scan Explorer (mempool/blocks)
5) Daemon Auto-Scan (loop berkelanjutan)
6) Raw TX Hex
7) Signature Manual (R/S/Z)
8) R-Reuse dari JSON
9) Bantuan Lengkap
C) Hapus Cache
0) Keluar
```

### Mode perintah langsung

```bash
# Analisis 1 transaksi via TXID (online, fetch dari mempool.space)
node index.js txid <txid>

# Scan SELURUH transaksi dari sebuah address
node index.js address 1XPTgDRhN8RFnzniWCddobD9iKZatrvH4 --concurrency 8

# Batch scan banyak address dari file (1 address per baris)
node index.js batch ./addresses.txt

# Analisis raw transaksi (hex) langsung
node index.js tx <hex>
node index.js tx-file ./tx.hex --amount 0=12345 --amount 1=67890

# Analisis satu signature manual
node index.js sig --r <rhex> --s <shex> --z <zhex> [--pub <pubkeyhex>]

# Cek R-reuse dari kumpulan signature dalam file JSON
node index.js reuse ./sigs.json
# Format: [{ "r": "...", "s": "...", "z": "...", "pubkey": "..." }, ...]

# Scan tx langsung dari explorer (mempool atau blok terbaru)
node index.js explore --mode mempool --limit 100
node index.js explore --mode blocks  --limit 50

# Daemon — loop otomatis + alert R-reuse
node index.js daemon --mode mempool --interval 60 --limit 200
node index.js daemon --mode mempool --realtime          # WebSocket kick
node index.js daemon --watch ./watchlist.txt            # alert ekstra

# Statistik dari scan.log
node index.js stats
node index.js stats ./scan.log --date 2026-04-24
```

### Opsi global

| Opsi               | Keterangan                                                              |
| ------------------ | ----------------------------------------------------------------------- |
| `--api <url>`      | Endpoint Esplora kustom. Default: `https://mempool.space/api`           |
| `--concurrency n`  | Jumlah request paralel saat scan address (default `8`)                  |
| `--out <file>`     | Simpan ringkasan hasil scan ke file JSON                                |
| `--hits <file>`    | Lokasi file hit R-reuse (default `hits.txt`)                            |
| `--verbose`        | Tampilkan tiap R/S/Z selama scan address                                |
| `--no-cache`       | Nonaktifkan cache lokal                                                 |
| `--amount i=sats`  | Nilai input ke-i untuk transaksi SegWit (boleh berkali-kali)            |
| `--limit n`        | Jumlah tx per siklus (`explore` / `daemon`)                             |
| `--mode m`         | `mempool` atau `blocks` (`explore` / `daemon`)                          |
| `--interval dtk`   | Jeda antar siklus daemon (default 60)                                   |
| `--realtime`       | Daemon: aktifkan WebSocket kick dari mempool.space                      |
| `--watch <file>`   | Daemon: file watchlist address (1 per baris, `#` = komentar)            |
| `--profile`        | Tampilkan timing per fase di akhir run                                  |

Perintah utilitas:

- `node index.js clear-cache` — hapus seluruh isi `.btc-cache/`
- `node index.js help` — bantuan lengkap

> **Catatan:** Endpoint default `mempool.space`. Untuk testnet pakai
> `--api https://mempool.space/testnet/api`. `blockstream.info` kadang
> memblokir IP cloud — gunakan mempool.space jika dapat error 403.

---

## Konfigurasi (`config.json`)

Opsional. Letakkan di root project:

```json
{
  "telegram": {
    "enabled": false,
    "botToken": "",
    "chatId": ""
  },
  "daemon": {
    "seenLimit": 200000,
    "poolMaxAgeHours": 24
  }
}
```

- **Telegram**: aktifkan `telegram.enabled = true` agar setiap hit dikirim ke chat. Notifikasi bersifat fire-and-forget (`.catch(() => {})`) sehingga loop daemon tidak ke-block bila Telegram lambat/timeout.
- **Daemon**: `seenLimit` = kapasitas LRU `seenTxids` (memory-bounded). `poolMaxAgeHours` = TTL signature pool (evict by waktu).

---

## Output File

Saat R-reuse terdeteksi & private key berhasil dipulihkan:

- **`hits.txt`** — laporan ramah-baca:
  ```
  ── HIT ──────────────────────────────────────
  TXID-A    : ...
  TXID-B    : ...
  R (reuse) : ...
  PrivKey   : <hex>
  WIF (cmp) : K...
  WIF (unc) : 5...
  Address   : 1AbC... (compressed)
              1XyZ... (uncompressed)
  Saldo     : 0.00012345 BTC
  ─────────────────────────────────────────────
  ```
- **`hits_LIVE.txt`** — hanya alamat dengan saldo > 0
- **`hits_CROSS.txt`** — hit lintas-transaksi (R-reuse antar tx berbeda)
- **`scan.log`** — log scan harian (dikonsumsi `node index.js stats`)

---

## Cache

Untuk menghemat request ke API publik:

- `.btc-cache/tx-daily/tx-YYYY-MM-DD.ndjson` — shard harian hex tx (TTL 48 jam, auto-prune saat startup)
- `.btc-cache/addr/<addr>.json` — daftar tx per-address (TTL 6 jam)
- `.btc-cache/daemon-seen.json` — snapshot `seenTxids` daemon (TTL 48 jam, atomic write via `.tmp` + rename) — restart daemon tidak re-scan ribuan tx

Statistik cache (hit/miss + persentase) ditampilkan di akhir scan address. Gunakan `--no-cache` untuk menonaktifkannya, atau `node index.js clear-cache` untuk membersihkan.

HTTP fetch memakai undici Agent global dengan keep-alive (pool 32 koneksi per origin) untuk mengurangi overhead handshake.

---

## Daemon (loop bounded + persistent)

Mode `daemon` mengulang siklus tiap N detik:

- Ambil txids baru dari mempool atau blok terbaru
- `seenTxids` = LRU set (cap dari `daemon.seenLimit`) — memory-bounded, di-snapshot ke `.btc-cache/daemon-seen.json` tiap 5 siklus & saat exit
- `sigPool` di-evict by waktu (`daemon.poolMaxAgeHours`)
- **Realtime** (`--realtime`): WebSocket `wss://mempool.space/api/v1/ws` — pesan WS "kick" memotong sleep agar siklus jalan segera
- **Watchlist** (`--watch`): hit yang menyentuh address watchlist mendapat alert merah ekstra + tag `[WATCHLIST!]` di Telegram
- Append hits via `WriteStream` (non-blocking)
- Status bar tiap siklus: `siklus / tx / sig / hit / pool / seen / mem MB / req/s`
- `Ctrl+C` berhenti graceful (cleanup WS + stream + simpan snapshot)

---

## Cara Kerja Singkat

ECDSA pada secp256k1 menghasilkan `(r, s)` dari pesan `z` dan kunci privat `d`:

```
k          = nonce acak per signature
r          = (k·G).x  mod n
s          = k⁻¹·(z + r·d)  mod n
```

Bila satu kunci memakai `k` yang **sama** untuk dua signature `(r, s1, z1)` & `(r, s2, z2)`:

```
k = (z1 − z2) / (s1 − s2)  mod n
d = (s1·k − z1) / r        mod n
```

Tool ini mencari pasangan `r` yang sama lintas semua input yang diekstrak, lalu memverifikasi `d` dengan mencocokkan public key turunannya.

---

## Struktur Proyek

```
.
├── index.js                  # entry tipis (~150 baris): parsing argv, dispatch
├── package.json              # type: module, bin: btc-sig
├── README.md
├── replit.md
├── src/                      # modul library inti
│   ├── config.js             # load config.json, CACHE_ENABLED live binding
│   ├── log.js                # logScan() ke scan.log
│   ├── bytes.js              # hex/bytes helpers, varint, LE encoders
│   ├── hash.js               # secp256k1, sha256d, hash160
│   ├── ui.js                 # palette, banner, header, kv, sep, box, progress
│   ├── profile.js            # timing per fase (--profile)
│   ├── tx.js                 # parseDER, parseScriptPushes, parseTx
│   ├── sighash.js            # legacySighash, BIP143 context & sighash
│   ├── address.js            # base58, bech32, P2PKH/P2WPKH/P2SH-P2WPKH, WIF
│   ├── ecdsa.js              # recoverPrivateKey(r, s1, z1, s2, z2)
│   ├── net.js                # undici Agent, esploraFetch, rate limit, retry
│   ├── telegram.js           # notifyTelegram(text)
│   ├── price.js              # BTC/USD, format BTC/USD, balance address
│   ├── cache.js              # LRU set/map, daily NDJSON cache, watchlist, hits stream
│   ├── analysis.js           # detectReuse, processTx*, runWithConcurrency
│   └── commands/             # handler per sub-command
│       ├── analyze.js        # analyzeTx, analyzeManual, analyzeByTxid
│       ├── address.js        # analyzeAddress, batchAddresses
│       ├── explore.js        # scanExplore (single-pipeline)
│       ├── daemon.js         # runDaemon (loop + WS)
│       ├── stats.js          # showStats (parse scan.log)
│       ├── help.js           # banner bantuan
│       └── menu.js           # interactiveMenu()
└── .btc-cache/               # dibuat saat runtime (di-gitignore)
    ├── tx-daily/
    ├── addr/
    └── daemon-seen.json
```

---

## Disclaimer

Tool edukasional untuk riset kriptografi & forensik blockchain. Hanya gunakan pada data publik atau aset yang **Anda miliki sendiri**. Mengakses dompet milik orang lain melanggar hukum di banyak yurisdiksi.
