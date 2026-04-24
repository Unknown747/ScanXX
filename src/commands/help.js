import { c, C, W, banner, visLen } from "../ui.js";

export function help() {
  console.log();
  banner();
  console.log();

  const HL = W - 2;
  const sect = (label) => {
    const dash = "─".repeat(HL - 4 - visLen(label) - 2);
    console.log(c(C.gray, "  ┌─ ") + c(C.bold + C.yellow, label) + c(C.gray, " " + dash + "┐"));
  };
  const sectEnd = () => console.log(c(C.gray, "  └" + "─".repeat(HL - 2) + "┘\n"));
  const row = (cmd, desc) => {
    const gap = Math.max(1, HL - 2 - visLen(cmd) - visLen(desc) - 2);
    console.log(c(C.gray, "  │ ") + c(C.cyan, cmd) + " ".repeat(gap) + c(C.dim, desc) + c(C.gray, " │"));
  };
  const sub = (text) => {
    console.log(c(C.gray, "  │  ") + c(C.dim, "  " + text) + " ".repeat(Math.max(0, HL - 4 - visLen(text) - 2)) + c(C.gray, "│"));
  };
  const flag = (f, desc) => {
    const gap = Math.max(1, HL - 2 - visLen(f) - visLen(desc) - 2);
    console.log(c(C.gray, "  │ ") + c(C.magenta, f) + " ".repeat(gap) + c(C.dim, desc) + c(C.gray, " │"));
  };
  const blank = () => console.log(c(C.gray, "  │" + " ".repeat(HL - 2) + "│"));

  sect("PERINTAH");
  row("node index.js",                           "Mode interaktif (menu)");
  row("node index.js txid <txid>",               "Ambil & analisis tx via TXID");
  row("node index.js address <addr>",            "Scan semua tx wallet, cek R-reuse");
  row("node index.js batch <file>",              "Scan banyak address dari file");
  row("node index.js explore",                   "Scan tx langsung dari explorer");
  sub("--mode mempool|blocks    --limit <n>  (default: mempool, 100 tx)");
  row("node index.js daemon",                    "Scan otomatis loop (alert R-reuse)");
  sub("--mode mempool|blocks  --interval <dtk>  --limit <n/siklus>  --realtime");
  sub("--watch <file.txt>   (alert ekstra utk address di watchlist)");
  row("node index.js tx <hex>",                  "Analisis raw hex transaksi");
  row("node index.js tx-file <path>",            "Analisis raw hex dari file");
  row("node index.js sig --r --s --z [--pub]",   "Analisis 1 signature manual");
  row("node index.js reuse <file.json>",         "R-reuse dari [{r,s,z,pubkey?}]");
  row("node index.js stats [logfile]",           "Ringkasan scan.log");
  sub("--date YYYY-MM-DD   (filter tanggal)");
  row("node index.js endpoints",                 "Lihat status pool endpoint (rotasi)");
  sub("--test   (uji koneksi tiap endpoint)");
  row("node index.js help",                      "Tampilkan bantuan ini");
  sectEnd();

  sect("OPSI GLOBAL");
  flag("--api <url>",         "Endpoint Esplora utama (default: mempool.space)");
  flag("--endpoints \"u1,u2\"", "Tambah endpoint mirror (rotasi otomatis + failover)");
  flag("--concurrency <n>",   "Request paralel saat scan address (default: 8)");
  flag("--hits <file.txt>",   "File simpan hit R-reuse (default: hits.txt)");
  flag("--out <file.json>",   "Simpan hasil scan ke JSON");
  flag("--verbose",           "Tampilkan tiap R/S/Z saat scan address");
  flag("--no-cache",          "Nonaktifkan cache lokal");
  flag("--amount <i>=<sat>",  "Nilai input ke-i dalam satoshi (untuk SegWit)");
  flag("--profile",           "Tampilkan timing per fase di akhir run");
  flag("clear-cache",         "Hapus seluruh isi folder .btc-cache/");
  sectEnd();

  sect("YANG DIANALISIS");
  blank();
  const dataRow = (key, desc) => {
    const content = "  " + key + "  " + desc;
    const pad = Math.max(0, HL - 2 - visLen(content));
    console.log(c(C.gray, "  │") + c(C.yellow, "  " + key) + c(C.dim, "  " + desc) + " ".repeat(pad) + c(C.gray, "│"));
  };
  dataRow("R, S      ", "Komponen ECDSA dari DER signature");
  dataRow("Z         ", "Message hash / sighash (BIP143 atau legacy)");
  dataRow("Public Key", "Dari scriptSig (legacy) atau witness (SegWit)");
  dataRow("Address   ", "P2PKH (1...), P2WPKH (bc1q...), P2SH-P2WPKH (3...)");
  blank();
  sectEnd();

  sect("RUMUS PEMULIHAN PRIVATE KEY");
  blank();
  const fmDesc = "Jika dua signature memakai nonce R yang sama:";
  console.log(c(C.gray, "  │  ") + c(C.dim, fmDesc) + " ".repeat(HL - 4 - visLen(fmDesc)) + c(C.gray, "│"));
  blank();
  const f1 = "k  =  (z1 − z2) / (s1 − s2)  mod n";
  const f2 = "d  =  (s1·k − z1) / r        mod n";
  console.log(c(C.gray, "  │     ") + c(C.yellow + C.bold, f1) + " ".repeat(HL - 7 - visLen(f1)) + c(C.gray, "│"));
  console.log(c(C.gray, "  │     ") + c(C.yellow + C.bold, f2) + " ".repeat(HL - 7 - visLen(f2)) + c(C.gray, "│"));
  blank();
  sectEnd();

  console.log(c(C.dim, "  Konfigurasi: edit config.json di root project."));
  console.log(c(C.dim, "  Telegram   : aktifkan di config.json → telegram.enabled = true\n"));
}
