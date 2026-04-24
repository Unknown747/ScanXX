# btc-sig-analyzer

CLI Node.js (ESM) untuk membedah tanda tangan ECDSA pada transaksi Bitcoin.
Mengekstrak komponen `R`, `S`, `Z`, public key, dan pubkey hash dari setiap input
transaksi — lalu otomatis mendeteksi **R-reuse** (nonce yang dipakai ulang) dan
memulihkan **private key** beserta semua alamatnya (P2PKH / P2WPKH / P2SH-P2WPKH).

Antarmuka sepenuhnya **Bahasa Indonesia**. Tidak ada server, tidak ada framework
web, tidak butuh node Bitcoin lokal. Cukup `node index.js`.

```
==========================================================================
 BTC-SIG-ANALYZER  —  Bitcoin ECDSA Signature Analyzer & Key Recovery
==========================================================================
```

---

## Daftar Isi

1. [Fitur Utama](#fitur-utama)
2. [Stack & Dependensi](#stack--dependensi)
3. [Instalasi](#instalasi)
4. [Quick Start](#quick-start)
5. [Mode Interaktif (Menu)](#mode-interaktif-menu)
6. [Daftar Perintah CLI](#daftar-perintah-cli)
7. [config.json — Referensi Lengkap](#configjson--referensi-lengkap)
8. [Daemon: Polling, Realtime & Top-R Trending](#daemon-polling-realtime--top-r-trending)
9. [Output File](#output-file)
10. [Optimasi yang Diterapkan](#optimasi-yang-diterapkan)
11. [Troubleshooting](#troubleshooting)
12. [Disclaimer](#disclaimer)
13. [Lisensi](#lisensi)

---

## Fitur Utama

- **Ekstraksi `R / S / Z`** dari berbagai jenis input:
  - Legacy P2PKH (sighash legacy)
  - SegWit v0 — P2WPKH & P2SH-P2WPKH (sighash BIP-143)
- **Deteksi R-reuse** lintas input, transaksi, address, dan siklus daemon.
- **Pemulihan private key otomatis** saat R-reuse ditemukan:
  - `k = (z1 − z2) / (s1 − s2) mod n`
  - `d = (s1·k − z1) / r mod n`
- Verifikasi pemulihan dengan mencocokkan public key (single scalar mult).
- Derivasi semua alamat (compressed & uncompressed) + WIF mainnet untuk tiap key.
- Cek saldo otomatis tiap alamat hasil pemulihan via mempool.space.
- Notifikasi opsional ke **Telegram** (fire-and-forget, tidak memblokir scan).
- **Mode daemon** loop berkelanjutan dengan dua sumber:
  - Polling interval (default tiap 60 dtk)
  - **Realtime** WebSocket `wss://mempool.space/api/v1/ws` + endpoint
    `/mempool/recent` sebagai fallback.
- Watchlist alamat khusus (alert merah ekstra saat ke-hit).
- **Top-R Trending** — daemon menampilkan 3 nilai R yang paling sering
  muncul di pool (count ≥ 2). Disorot jika count ≥ 3.
- Cache lokal di `.btc-cache/` (NDJSON shard harian, lazy-load, auto-prune).
- Scan address paralel dengan progress bar (`--concurrency`).
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
git clone https://github.com/<user>/btc-sig-analyzer.git
cd btc-sig-analyzer
npm install
```

Salin & sunting konfigurasi default:

```bash
cp config.example.json config.json   # bila belum ada
$EDITOR config.json
```

> `config.json` masuk `.gitignore` (boleh berisi token Telegram pribadi).

Cek instalasi:

```bash
node index.js help
```

---

## Quick Start

Yang paling cepat: jalankan **mode interaktif**:

```bash
node index.js
```

Menu hanya menanyakan satu hal: sumber data (mempool, blocks, atau watchlist
file). Sisanya — interval, limit, realtime, output file — diambil dari
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

# Cek 1 signature manual (hex)
node index.js sig --r aaaa1234 --s bbbb5678 --z cccc9abc

# Statistik dari scan.log
node index.js stats --date 2026-04-24
```

---

## Mode Interaktif (Menu)

```
┌──────────────────────────────────────────────────────────────────────┐
│  1) Analisis 1 transaksi (TXID atau raw hex)                         │
│  2) Scan satu alamat (full history)                                  │
│  3) Scan banyak alamat dari file (batch)                             │
│  4) Explore mempool / blok terbaru          ← hanya tanya sumber     │
│  5) Daemon scan otomatis (loop / realtime)  ← hanya tanya sumber     │
│  6) Lihat statistik scan.log                                         │
│  0) Keluar                                                           │
└──────────────────────────────────────────────────────────────────────┘
```

Pilihan #4 dan #5 sengaja **dibuat minimal**: cukup pilih sumber
(`mempool` / `blocks` / file watchlist), parameter lain (limit, interval,
realtime on/off, output file) dibaca otomatis dari section `explore` /
`daemon` di `config.json`. Untuk override sekali jalan, gunakan flag CLI.

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
| `node index.js stats [logfile]` | Ringkasan scan.log (`--date YYYY-MM-DD`) |
| `node index.js clear-cache` | Hapus seluruh isi folder `.btc-cache/` |

### Opsi global

| Flag | Fungsi |
|---|---|
| `--api <url>` | Endpoint Esplora kustom (default `https://mempool.space/api`) |
| `--concurrency <n>` | Request paralel saat scan address (default 8) |
| `--hits <file.txt>` | File simpan hit R-reuse (default `hits.txt`) |
| `--out <file.json>` | Simpan hasil scan ke JSON |
| `--verbose` | Tampilkan tiap R/S/Z saat scan address |
| `--no-cache` | Nonaktifkan cache lokal |
| `--amount <i>=<sat>` | Nilai input ke-i dalam satoshi (untuk SegWit raw) |
| `--profile` | Tampilkan timing per fase di akhir run |

---

## config.json — Referensi Lengkap

```jsonc
{
  "api": "https://mempool.space/api",
  "concurrency": 8,
  "hitsFile": "hits.txt",
  "logFile":  "scan.log",
  "logEnabled": true,

  "cache": {
    "enabled": true,
    "listMaxAgeHours": 6,    // umur cache list tx per address
    "txMaxAgeHours":   48,   // umur cache hex per tx
    "pruneOnStart": true     // bersih-bersih file kadaluarsa di startup
  },

  "explore": {
    "mode":  "mempool",      // "mempool" | "blocks"
    "limit": 0               // 0 = tanpa batas (scan SEMUA tx mempool)
  },

  "daemon": {
    "mode":      "mempool",  // "mempool" | "blocks" | "watchlist"
    "interval":  60,         // detik antar siklus polling
    "limit":     0,          // 0 = tanpa batas per siklus
    "realtime":  true,       // sambungkan WebSocket mempool.space
    "watchFile": null,       // path file watchlist (null = tidak dipakai)
    "seenLimit":      200000,// LRU dedup tx (mencegah re-scan)
    "poolMaxAgeHours": 24,   // umur signature di pool R-reuse
    "rateLimit":       0     // 0 = tanpa rate-limit; n = max n req/dtk
  },

  "telegram": {
    "enabled":       false,
    "botToken":      "",
    "chatId":        "",
    "notifyOnLiveOnly": true   // hanya alert untuk signature live (bukan replay cache)
  }
}
```

> `limit: 0` ⇒ **tanpa batas** (Infinity). Pada label terlihat sebagai
> `"tanpa batas"`.

---

## Daemon: Polling, Realtime & Top-R Trending

### Polling

```bash
node index.js daemon --mode mempool --interval 30 --limit 200
```

Setiap 30 detik, ambil maks 200 tx baru dari mempool, ekstrak signature,
masukkan ke pool R-reuse global. Output per siklus:

```
❯ Siklus #12  187 tx baru  ·  pool=1542 sig  ·  19.30.45
  Total: siklus=12  tx=2104  sig=1542  hit=0  pool=1542  seen=2104  mem=112MB  req/s=6.2
  Top R: 8a2f… ×3  ·  3b91… ×2  ·  c0ee… ×2
```

Baris `Top R` muncul otomatis bila ada R yang berulang ≥ 2x di pool aktif.
Yang count-nya ≥ 3 disorot kuning **bold**. Baris ini hilang sendiri saat
tidak ada repeat.

### Realtime

```bash
node index.js daemon --realtime
```

Membuka WebSocket ke `wss://mempool.space/api/v1/ws`, subscribe channel
`mempool-blocks` & track tx baru. Sebagai jaring pengaman, endpoint
`/mempool/recent` di-poll juga (interval pendek) untuk menangkap tx yang
terlewat saat WS reconnect.

### Watchlist

```bash
node index.js daemon --watch addresses.txt
```

Format file: 1 address per baris, `#` = komentar. Setiap signature dari
address di file ini ditampilkan dengan label `[WATCH]` merah, terlepas dari
ada R-reuse atau tidak.

---

## Output File

| File | Isi | Catatan |
|---|---|---|
| `hits.txt` | Ringkasan R-reuse + private key (manusia-baca) | Append-only |
| `hits.jsonl` | Sama, format JSONL (1 hit per baris) | Untuk scripting |
| `hits_LIVE.txt` | Khusus hit dari mempool live (bukan replay cache) | Append-only |
| `scan.log` | Log per siklus daemon (CSV-style) | Dipakai `stats` |
| `.btc-cache/` | Cache list tx per address + hex per tx (NDJSON shard harian) | Auto-prune |

Semua file di atas sudah masuk `.gitignore`.

---

## Optimasi yang Diterapkan

Ringkasan teknis (16 perubahan utama dari versi awal):

1. Single scalar multiplication via `pubkeysFromPriv` — derivasi semua
   alamat dari satu key tanpa multi-mult berulang.
2. `rIndex` Map incremental di daemon — O(1) lookup R-reuse, hindari
   rebuild full scan tiap siklus.
3. Lazy-load shard cache — hanya load file shard tanggal saat diperlukan.
4. `appendHit` streaming — `fs.createWriteStream` reused, tidak `open`/`close`
   tiap hit.
5. Dedup LRU `seen` set di daemon (`seenLimit` configurable).
6. Concurrency adaptif untuk fetch tx hex (default 8, override `--concurrency`).
7. Prefetch pipeline (fetch hex tx N+1 saat parsing tx N).
8. Profile mode (`--profile`) untuk timing per fase.
9. Resume per-address (state disimpan, scan bisa lanjut).
10. Cache list address dengan TTL (default 6 jam).
11. Cache hex tx dengan TTL (default 48 jam).
12. Auto-prune cache di startup.
13. `detectReuse` null-pubkey safe (tidak crash bila pubkey tidak terbaca).
14. Menu streamlining — pilihan #4 & #5 hanya tanya sumber.
15. Default `limit: 0 = unlimited` di explore & daemon.
16. **Top-R trending line** di daemon (count ≥ 2, top-3 sorted, bold ≥ 3).

---

## Troubleshooting

**“Tidak ada signature+pubkey yang dapat dibaca otomatis pada input ini”**
Input bukan P2PKH/P2WPKH/P2SH-P2WPKH (mungkin P2PK murni, P2TR, multisig
non-standard, atau coinbase). Ini wajar.

**Permintaan API gagal / timeout**
Pakai `--api` untuk endpoint Esplora alternatif. Kurangi `--concurrency`
bila terkena rate-limit. Atau set `daemon.rateLimit` ke nilai > 0.

**Memori naik saat daemon jalan lama**
Turunkan `daemon.poolMaxAgeHours` (default 24 jam) atau `seenLimit`.
Cache file otomatis di-prune sesuai `cache.txMaxAgeHours`.

**Hits.txt tidak muncul**
File baru dibuat saat ada hit pertama. Untuk uji coba, gunakan:

```bash
# generate sample R-reuse yang valid
node -e "..."   # lihat docs/test-fixtures.md (opsional)
node index.js reuse sample-reuse.json
```

---

## Disclaimer

Tool ini dibuat untuk **riset, edukasi, dan audit forensik**. Pemulihan
private key hanya berhasil bila signer benar-benar memakai ulang nonce —
yang merupakan bug implementasi, bukan kelemahan ECDSA itu sendiri.

**Jangan** menggunakan tool ini untuk mencuri dana orang lain. Repository
ini tidak menyediakan dan tidak mendukung penggunaan jahat. Penulis tidak
bertanggung jawab atas penyalahgunaan.

---

## Lisensi

MIT.
