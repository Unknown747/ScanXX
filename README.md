# btc-sig-analyzer

CLI Node.js (ESM) untuk membedah tanda tangan ECDSA pada transaksi Bitcoin.
Mengekstrak komponen `R`, `S`, `Z`, public key, dan pubkey hash dari setiap
input transaksi — lalu mendeteksi **R-reuse** (nonce yang dipakai ulang) dan
memulihkan **private key** beserta semua alamatnya (P2PKH / P2WPKH / P2SH-P2WPKH).

Antarmuka sepenuhnya **Bahasa Indonesia**. Tidak ada server, tidak ada
framework web, tidak butuh node Bitcoin lokal. Cukup `node index.js`.

```
╔════════════════════════════════════════════════════════════════════════╗
║                                                                        ║
║   ₿  BTC-SIG-ANALYZER  ·  Bitcoin ECDSA Signature Analyzer             ║
║      Deteksi R-Reuse  ·  Ekstrak R/S/Z  ·  Pulihkan Private Key        ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝
```

---

## Daftar Isi

1. [Fitur Utama](#fitur-utama)
2. [Stack & Dependensi](#stack--dependensi)
3. [Instalasi](#instalasi)
4. [Quick Start](#quick-start)
5. [Mode Interaktif (Menu)](#mode-interaktif-menu)
6. [Daftar Perintah CLI](#daftar-perintah-cli)
7. [Multi-Endpoint Pool & Strategi](#multi-endpoint-pool--strategi)
8. [Daemon: Polling, Realtime & Top-R Trending](#daemon-polling-realtime--top-r-trending)
9. [config.json — Referensi Lengkap](#configjson--referensi-lengkap)
10. [Output File](#output-file)
11. [Tampilan Terminal](#tampilan-terminal)
12. [Troubleshooting](#troubleshooting)
13. [Disclaimer](#disclaimer)
14. [Lisensi](#lisensi)

---

## Fitur Utama

- **Ekstraksi `R / S / Z`** dari berbagai jenis input:
  - Legacy P2PKH (sighash legacy)
  - SegWit v0 — P2WPKH & P2SH-P2WPKH (sighash BIP-143)
- **Deteksi R-reuse** lintas input, transaksi, address, dan siklus daemon.
- **Pemulihan private key otomatis** saat R-reuse ditemukan
  (`k = (z₁ − z₂) / (s₁ − s₂) mod n`, lalu `d = (s₁·k − z₁) / r mod n`).
- Verifikasi pemulihan dengan mencocokkan public key (single scalar mult).
- Derivasi semua alamat (compressed & uncompressed) + WIF mainnet untuk tiap
  key yang ditemukan.
- Cek saldo otomatis tiap alamat hasil pemulihan via Esplora.
- **Multi-endpoint pool** dengan rotasi & failover otomatis (lihat
  [Multi-Endpoint Pool & Strategi](#multi-endpoint-pool--strategi)).
- **Mode daemon** loop berkelanjutan dengan dua sumber:
  - Polling interval (default tiap 60 dtk)
  - **Realtime** WebSocket `wss://mempool.space/api/v1/ws` + endpoint
    `/mempool/recent` sebagai fallback.
- **Top-R Trending** — daemon menampilkan 3 nilai R yang paling sering
  muncul di pool (count ≥ 2). Disorot kuning bold jika count ≥ 3.
- Watchlist alamat khusus (alert merah ekstra saat ke-hit).
- Notifikasi opsional ke **Telegram** (fire-and-forget, tidak memblokir).
- Cache lokal di `.btc-cache/` (NDJSON shard harian, lazy-load, auto-prune).
- Resume per-address — scan address besar bisa dilanjutkan setelah Ctrl+C.
- Mode interaktif (menu) jika dijalankan tanpa argumen — hanya menanyakan
  satu hal (sumber data); selebihnya dibaca dari `config.json`.

---

## Stack & Dependensi

- Node.js **>= 18** (ESM, `"type": "module"`)
- [`@noble/curves`](https://www.npmjs.com/package/@noble/curves) — secp256k1
- [`@noble/hashes`](https://www.npmjs.com/package/@noble/hashes) — SHA-256, RIPEMD-160
- [`undici`](https://www.npmjs.com/package/undici) — HTTP/1.1 keep-alive Agent
- [`ws`](https://www.npmjs.com/package/ws) — WebSocket client (mode realtime daemon)

Tidak ada dependency lain. Tidak ada native binary.

---

## Instalasi

```bash
git clone https://github.com/Unknown747/btc-sig-analyzer.git
cd btc-sig-analyzer
npm install
```

Salin & sunting konfigurasi default (opsional, default sudah masuk akal):

```bash
cp config.example.json config.json
$EDITOR config.json
```

> `config.json` masuk `.gitignore` — boleh berisi token Telegram pribadi,
> daftar endpoint kustom, dll.

Cek instalasi:

```bash
node index.js help
```

---

## Quick Start

Cara tercepat — **mode interaktif**:

```bash
node index.js
```

Menu hanya menanyakan satu hal: sumber data (mempool / blok terbaru).
Sisanya — interval, limit, realtime on/off, output file — diambil dari
`config.json`.

Beberapa contoh perintah satu baris:

```bash
# Analisis 1 transaksi via TXID
node index.js txid f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16

# Scan seluruh history sebuah address
node index.js address bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq --concurrency 8

# Scan banyak address dari file
node index.js batch addresses.txt

# Scan mempool tanpa batas (bisa 50.000+ tx)
node index.js explore --mode mempool

# Daemon realtime (Ctrl-C untuk berhenti)
node index.js daemon --realtime

# Lihat status pool endpoint + uji latency
node index.js endpoints --test

# Cek 1 signature manual (hex)
node index.js sig --r aaaa1234 --s bbbb5678 --z cccc9abc

# Statistik dari scan.log
node index.js stats --date 2026-04-24
```

---

## Mode Interaktif (Menu)

```
  ┌─ SCAN ONLINE ──────────────────────────────────────────────────────┐
  │  1  ⬡  Scan Address       Semua tx dari 1 wallet, cari R-reuse     │
  │  2  ⌕  Analisis TXID      1 transaksi via TXID                     │
  │  3  ◈  Batch Scan File    Daftar address, 1 per baris              │
  │  4  ₿  Scan Explorer      Langsung dari mempool / blok terbaru     │
  │  5  ⚡ Daemon Auto-Scan   Loop terus, alert real-time jika hit     │
  └────────────────────────────────────────────────────────────────────┘

  ┌─ ANALISIS MANUAL ──────────────────────────────────────────────────┐
  │  6  ◆  Raw TX Hex          Tempel hex raw transaksi                │
  │  7  ◆  Signature Manual    Masukkan R, S, Z secara manual          │
  │  8  ◈  R-Reuse dari JSON   File daftar signature [{r,s,z}]         │
  └────────────────────────────────────────────────────────────────────┘

  ┌─ LAINNYA ──────────────────────────────────────────────────────────┐
  │  9  ℹ  Bantuan Lengkap     Tampilkan semua perintah & opsi         │
  │  C  ◆  Hapus Cache         Bersihkan folder .btc-cache/            │
  │  0  ✘  Keluar                                                      │
  └────────────────────────────────────────────────────────────────────┘
```

Pilihan #4 dan #5 sengaja **dibuat minimal**: cukup pilih sumber
(`mempool` / `blok terbaru`), parameter lain (limit, interval, realtime
on/off, output file) dibaca otomatis dari section `explore` / `daemon`
di `config.json`. Untuk override sekali jalan, gunakan flag CLI.

---

## Daftar Perintah CLI

| Perintah | Keterangan |
|---|---|
| `node index.js` | Mode interaktif (menu) |
| `node index.js help` | Bantuan lengkap |
| `node index.js txid <txid>` | Ambil & analisis 1 transaksi via TXID |
| `node index.js tx <hex>` | Analisis raw hex transaksi |
| `node index.js tx-file <path>` | Sama, tapi raw hex dibaca dari file |
| `node index.js sig --r --s --z [--pub]` | Analisis 1 signature manual |
| `node index.js reuse <file.json>` | R-reuse dari `[{r,s,z,pubkey?}]` |
| `node index.js address <addr>` | Scan semua tx wallet, deteksi R-reuse |
| `node index.js batch <file>` | Scan banyak address dari file (1 per baris, `#` = komentar) |
| `node index.js explore` | Scan tx langsung dari explorer (`--mode mempool\|blocks`, `--limit n`) |
| `node index.js daemon` | Scan otomatis loop (`--mode`, `--interval`, `--limit`, `--realtime`, `--watch <file>`) |
| `node index.js endpoints [--test]` | Status pool endpoint + uji latency live |
| `node index.js stats [logfile]` | Ringkasan scan.log (`--date YYYY-MM-DD`) |
| `node index.js clear-cache` | Hapus seluruh isi folder `.btc-cache/` |

### Opsi global

| Flag | Fungsi |
|---|---|
| `--api <url>` | Endpoint Esplora primer (default `https://mempool.space/api`) |
| `--endpoints <a,b,c>` | Tambah endpoint mirror (comma-separated) |
| `--strategy <s>` | Pilih strategi pool: `latency` \| `round-robin` \| `primary` |
| `--concurrency <n>` | Request paralel saat scan address (default 8) |
| `--hits <file.txt>` | File simpan hit R-reuse (default `hits.txt`) |
| `--out <file.json>` | Simpan hasil scan ke JSON |
| `--verbose` | Tampilkan tiap R/S/Z saat scan address |
| `--no-cache` | Nonaktifkan cache lokal |
| `--amount <i>=<sat>` | Nilai input ke-i dalam satoshi (untuk SegWit raw) |
| `--profile` | Tampilkan timing per fase di akhir run |

---

## Multi-Endpoint Pool & Strategi

Tool ini mengelola **kumpulan endpoint Esplora-compatible** secara otomatis.
Daftar dasar (mempool.space, blockstream.info, mempool.emzy.de, dll.)
sudah tersedia di `config.example.json`. Saat satu endpoint kena rate-limit
(HTTP 429), timeout, atau error 5xx — pool langsung **rotate** ke endpoint
lain dan menerapkan **cooldown exponential** pada yang gagal.

### Tiga strategi tersedia

| Strategi | Perilaku |
|---|---|
| `latency` *(default)* | Probe periodik ke `/blocks/tip/height` semua endpoint, urutkan dari tercepat. Endpoint paling responsif selalu didahulukan. |
| `round-robin` | Bergiliran fair antar semua endpoint sehat. Cocok jika ingin merata. |
| `primary` | Selalu pakai endpoint pertama; fallback ke berikutnya hanya saat error. |

Set via `config.json` (`"endpointStrategy": "latency"`) atau flag
`--strategy latency` per-run.

### Lihat pool secara real-time

```bash
node index.js endpoints --test
```

Output:

```
  Strategi    ··· latency (auto-rank tercepat)
  Total       ··· 6 endpoint  ·  6 sehat  ·  0 cooldown

  ✔  mempool.space         245ms   READY   req=12  ok=12  fail=0
  ✔  blockstream.info      312ms   READY   req=10  ok=10  fail=0
  ✔  mempool.emzy.de       407ms   READY   req=8   ok=8   fail=0
  ✔  btcscan.org           512ms   READY   req=8   ok=8   fail=0
  …
  6/6 endpoint sehat. Strategi 'latency' akan utamakan endpoint paling cepat & sehat.
```

Header tiap perintah scan juga menampilkan badge ringkas:

```
  Endpoint    ··· 6/6 endpoint · strategi: latency
              › mempool.space 245ms · blockstream.info 312ms · mempool.emzy.de 407ms  +3 mirror
```

### Cooldown otomatis

- HTTP 429 / `Retry-After` → endpoint masuk cooldown sesuai header
- Error jaringan / 5xx → cooldown exponential `baseMs … maxMs`
- 404 dianggap "data tidak ada di mirror itu" → tidak menghukum endpoint,
  request langsung di-retry ke mirror berikutnya.
- Pool melaporkan `--/--` aktif/total di status line tiap siklus daemon.

---

## Daemon: Polling, Realtime & Top-R Trending

### Polling

```bash
node index.js daemon --mode mempool --interval 30 --limit 200
```

Setiap 30 detik, ambil maks 200 tx baru dari mempool, ekstrak signature,
masukkan ke pool R-reuse global. Output per siklus:

```
  ❯ Siklus #12 ─────────────────────────  187 tx baru · pool 1542 sig · 19.30.45
    ✔  342 sig dari 187 tx · 4.1s (83.4 sig/dtk) · pool: 1542 sig
    siklus=12 │ tx=2104 │ sig=1542 │ hit=0 │ pool=1542 │ seen=2104 │ mem=112MB │ req/s=6.2 │ ep=6/6
    Top R (≥2): 8a2f… ×3  ·  3b91… ×2  ·  c0ee… ×2
    ⠹ Menunggu siklus berikutnya · 23s [ws]  (Ctrl+C untuk berhenti)
```

Baris `Top R` muncul otomatis bila ada R yang berulang ≥ 2× di pool aktif.
Yang count-nya ≥ 3 disorot kuning **bold**. Baris ini hilang sendiri saat
tidak ada repeat.

### Realtime

```bash
node index.js daemon --realtime
```

Membuka WebSocket ke `wss://mempool.space/api/v1/ws`, subscribe channel
`blocks`, `mempool-blocks`, `stats`. Setiap pesan dari WS langsung
"kick" loop polling agar siklus dimulai lebih cepat (tidak perlu nunggu
interval). Sebagai jaring pengaman, endpoint `/mempool/recent` di-poll
juga untuk menangkap tx yang terlewat saat WS reconnect. Indicator `[ws]`
hijau di status line menandakan WebSocket terhubung.

### Watchlist

```bash
node index.js daemon --watch addresses.txt
```

Format file: 1 address per baris, `#` = komentar. Setiap signature dari
address di file ini ditampilkan dengan label `[WATCHLIST!]` merah, terlepas
dari ada R-reuse atau tidak. Hit R-reuse pada watchlist juga di-tag khusus
di Telegram (`🚨🚨 *WATCHLIST HIT!*`).

---

## config.json — Referensi Lengkap

```jsonc
{
  "api": "https://mempool.space/api",

  "endpoints": [
    "https://mempool.space/api",
    "https://blockstream.info/api",
    "https://mempool.emzy.de/api",
    "https://mempool.bitcoin-21.org/api",
    "https://btcscan.org/api",
    "https://bitcoin.lu.ke/api"
  ],
  "endpointDefaults": true,             // true = include default mirrors
  "endpointStrategy": "latency",        // latency | round-robin | primary

  "latencyProbe": {
    "enabled":   true,
    "intervalMs": 300000,               // 5 menit antar probe
    "timeoutMs":  5000
  },
  "latencyBucketMs": 100,               // bucket pengelompokan latency

  "cooldown": {
    "baseMs": 5000,                     // cooldown awal saat error
    "maxMs":  300000                    // cooldown maksimum (5 menit)
  },

  "concurrency": 8,
  "hitsFile":    "hits.txt",
  "logFile":     "scan.log",
  "logEnabled":  true,

  "cache": {
    "enabled":         true,
    "listMaxAgeHours": 6,               // umur cache list tx per address
    "txMaxAgeHours":   48,              // umur cache hex per tx
    "pruneOnStart":    true             // bersih-bersih file kadaluarsa
  },

  "explore": {
    "mode":  "mempool",                 // "mempool" | "blocks"
    "limit": 0                          // 0 = tanpa batas (scan SEMUA)
  },

  "daemon": {
    "mode":            "mempool",       // "mempool" | "blocks"
    "interval":        60,              // detik antar siklus polling
    "limit":           0,               // 0 = tanpa batas per siklus
    "realtime":        true,            // sambungkan WebSocket mempool.space
    "watchFile":       null,            // path file watchlist (null = off)
    "seenLimit":       200000,          // LRU dedup tx (mencegah re-scan)
    "poolMaxAgeHours": 24,              // umur signature di pool R-reuse
    "rateLimit":       0                // 0 = no limit; n = max n req/dtk/host
  },

  "telegram": {
    "enabled":          false,
    "botToken":         "",
    "chatId":           "",
    "notifyOnLiveOnly": true            // hanya alert untuk hit dari live
  }
}
```

> `limit: 0` ⇒ **tanpa batas** (Infinity). Pada label terlihat sebagai
> `"tanpa batas"`.

---

## Output File

| File | Isi | Catatan |
|---|---|---|
| `hits.txt` | Ringkasan R-reuse + private key (manusia-baca) | Append-only |
| `hits.jsonl` | Sama, format JSONL (1 hit per baris) | Untuk scripting |
| `hits_LIVE.txt` | Khusus hit dari mempool live (bukan replay cache) | Append-only |
| `scan.log` | Log per siklus daemon (CSV-style) | Dipakai `stats` |
| `.btc-cache/tx-daily/` | Cache hex tx (NDJSON shard harian) | Auto-prune |
| `.btc-cache/addr/` | Cache list tx per address (TTL `listMaxAgeHours`) | |
| `.btc-cache/resume/` | State resume per-address (auto-clear setelah selesai) | |
| `.btc-cache/daemon-seen.json` | Snapshot LRU `seenTxids` daemon | TTL 48 jam |

Semua file di atas sudah masuk `.gitignore`.

---

## Tampilan Terminal

UI memakai Unicode + ANSI — bekerja di terminal modern (xterm-256color,
iTerm, Windows Terminal). Fitur visual yang dipakai:

- **Smooth progress bar 8-step** (▏▎▍▌▋▊▉█) dengan warna gradient
  cyan → kuning → hijau sesuai persentase.
- **Multi-segment status line** (`siklus=12 │ tx=2104 │ sig=1542 │ …`) —
  satu baris ringkas, tidak bertele-tele.
- **Spinner Braille** (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`) saat menunggu siklus berikutnya.
- **Banner cycle** dengan chevron + dash-fill yang adaptif lebar terminal.
- **Compact pool badge** — `6/6 endpoint · strategi: latency` + sub-bullet
  top-3 host.
- **Box-drawing** untuk private-key recovery (sangat menonjol).

Set `NO_COLOR=1` untuk mematikan warna, `FORCE_COLOR=1` untuk memaksakan
warna (mis. saat output dipipe).

---

## Troubleshooting

**"Tidak ada signature+pubkey yang dapat dibaca otomatis pada input ini"**
Input bukan P2PKH/P2WPKH/P2SH-P2WPKH (mungkin P2PK murni, P2TR / Taproot,
multisig non-standard, atau coinbase). Ini wajar — tidak semua tx
mengekspos signature ECDSA standar.

**Permintaan API gagal / 429 / timeout terus**
- Tambah mirror via `--endpoints url1,url2,...` atau edit `endpoints` di
  `config.json`.
- Pakai `--strategy round-robin` agar beban tersebar merata.
- Set `daemon.rateLimit` ke nilai > 0 (mis. `4` request/dtk/host).
- Kurangi `--concurrency` (default 8 → 4).

**Memori naik saat daemon jalan lama**
Turunkan `daemon.poolMaxAgeHours` (default 24 jam) atau `seenLimit`.
Cache file otomatis di-prune sesuai `cache.txMaxAgeHours`.

**`hits.txt` tidak muncul**
File baru dibuat saat ada hit pertama. Untuk uji coba pemulihan kunci,
siapkan file JSON `[{"r":"...","s":"...","z":"...","pubkey":"..."}]`
dengan dua signature ber-R sama, lalu:

```bash
node index.js reuse sample-reuse.json
```

**Telegram tidak terkirim**
Pastikan `telegram.enabled: true`, `botToken` & `chatId` benar. Pesan
salah/timeout tidak akan memblokir scan — hanya warning kuning di log.

---

## Disclaimer

Tool ini dibuat untuk **riset, edukasi, dan audit forensik**. Pemulihan
private key hanya berhasil bila signer benar-benar memakai ulang nonce —
yang merupakan bug implementasi (kebanyakan dari wallet lama / RNG buruk),
bukan kelemahan ECDSA itu sendiri.

**Jangan** menggunakan tool ini untuk mencuri dana orang lain. Repository
ini tidak menyediakan dan tidak mendukung penggunaan jahat. Penulis tidak
bertanggung jawab atas penyalahgunaan.

---

## Lisensi

MIT.
