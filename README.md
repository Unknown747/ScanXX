# btc-sig-analyzer

CLI Node.js untuk membedah tanda tangan ECDSA pada transaksi Bitcoin. Mengekstrak komponen `R`, `S`, `Z`, public key, dan pubkey hash dari setiap input transaksi — lalu otomatis mendeteksi **R-reuse** (nonce dipakai ulang) dan memulihkan **private key** beserta alamat P2PKH-nya.

Antarmuka sepenuhnya **Bahasa Indonesia**, tanpa framework web, tanpa dependensi berat. Cukup `node index.js`.

---

## Fitur

- Ekstraksi `R / S / Z` dari berbagai jenis input:
  - Legacy P2PKH
  - SegWit v0 (P2WPKH, P2SH-P2WPKH) dengan sighash BIP-143
- Pemulihan private key otomatis bila menemukan **R-reuse** (nonce `k` sama):
  - `k = (z1 − z2) / (s1 − s2)  mod n`
  - `d = (s1·k − z1) / r        mod n`
- Verifikasi pemulihan dengan mencocokkan public key
- Derivasi alamat P2PKH (compressed & uncompressed) + WIF mainnet
- Cek saldo otomatis tiap alamat hasil pemulihan via mempool.space
- Simpan setiap "hit" ke file:
  - `hits.txt`     — laporan teks per-hit
  - `hits.jsonl`   — satu JSON per baris (mudah di-grep / di-pipe)
  - `hits_LIVE.txt` — khusus alamat dengan saldo > 0
- Cache lokal di `.btc-cache/` untuk hex transaksi & daftar tx per-address
- Scan address paralel dengan progress bar (`--concurrency`)
- Mode interaktif (menu) jika dijalankan tanpa argumen

---

## Instalasi

```bash
# Node.js >= 18
npm install
# atau
pnpm install
```

Dependensi:

- [`@noble/curves`](https://www.npmjs.com/package/@noble/curves) — secp256k1
- [`@noble/hashes`](https://www.npmjs.com/package/@noble/hashes) — SHA-256, RIPEMD-160

---

## Cara Pakai

### Mode interaktif (paling mudah)

```bash
node index.js
```

Pilih dari menu:

```
1) Scan Address (semua TX)
2) Analisis TXID
3) Raw TX hex
4) Signature manual (R, S, Z)
5) Cek R-reuse dari file JSON
6) Bantuan lengkap
7) Hapus cache (.btc-cache/)
0) Keluar
```

### Mode perintah langsung

```bash
# Analisis 1 transaksi via TXID (online, fetch dari mempool.space)
node index.js txid <txid>

# Scan SELURUH transaksi dari sebuah address
node index.js address 1XPTgDRhN8RFnzniWCddobD9iKZatrvH4 --concurrency 8

# Analisis raw transaksi (hex) langsung
node index.js tx <hex>
node index.js tx-file ./tx.hex --amount 0=12345 --amount 1=67890

# Analisis satu signature manual
node index.js sig --r <rhex> --s <shex> --z <zhex> [--pub <pubkeyhex>]

# Cek R-reuse dari kumpulan signature dalam file JSON
node index.js reuse ./sigs.json
# Format: [{ "r": "...", "s": "...", "z": "...", "pubkey": "..." }, ...]
```

### Opsi global

| Opsi              | Keterangan                                                                |
| ----------------- | ------------------------------------------------------------------------- |
| `--api <url>`     | Endpoint Esplora kustom. Default: `https://mempool.space/api`             |
| `--concurrency n` | Jumlah request paralel saat scan address (default `8`)                    |
| `--out <file>`    | Simpan ringkasan hasil scan ke file JSON                                  |
| `--hits <file>`   | Lokasi file hit R-reuse (default `hits.txt`)                              |
| `--verbose`       | Tampilkan tiap R/S/Z selama scan address                                  |
| `--no-cache`      | Nonaktifkan cache lokal                                                   |
| `--amount i=sats` | Nilai input ke-i untuk transaksi SegWit (boleh berkali-kali)              |

Perintah utilitas:

- `node index.js clear-cache` — hapus seluruh isi `.btc-cache/`

> **Catatan:** Endpoint default `mempool.space`. Untuk testnet pakai
> `--api https://mempool.space/testnet/api`. `blockstream.info` kadang
> memblokir IP cloud — gunakan mempool.space jika dapat error 403.

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
- **`hits.jsonl`** — satu objek JSON per baris (mudah dimasukkan ke pipeline lain)
- **`hits_LIVE.txt`** — hanya alamat dengan saldo > 0

---

## Cache

Untuk menghemat request ke API publik:

- `.btc-cache/tx/<txid>.hex` — hex mentah tiap transaksi (selamanya, tx final)
- `.btc-cache/addr/<addr>.json` — daftar tx per-address (TTL 6 jam)

Statistik cache (hit/miss + persentase) ditampilkan di akhir scan address. Gunakan `--no-cache` untuk menonaktifkannya, atau `node index.js clear-cache` untuk membersihkan.

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
├── index.js          # seluruh CLI (~1.2k baris, ESM)
├── package.json      # type: module, bin: btc-sig
├── README.md
└── .btc-cache/       # dibuat saat runtime (di-ignore)
    ├── tx/
    └── addr/
```

---

## Disclaimer

Tool edukasional untuk riset kriptografi & forensik blockchain. Hanya gunakan pada data publik atau aset yang **Anda miliki sendiri**. Mengakses dompet milik orang lain melanggar hukum di banyak yurisdiksi.
