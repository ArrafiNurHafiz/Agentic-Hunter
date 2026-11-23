# Checkpoint pengembangan offline

## Batas kerja

Eksekusi assessment ofensif, pembuatan payload, dan reproduksi otomatis tetap
di luar cakupan. Integrasi 9Router baru hanya untuk saran remediasi dari metadata
yang disanitasi; jangan mengirim bukti mentah.

## Progres

- `attack --dry-run` dan laporan sesi offline sudah tersedia sebelum checkpoint ini.
- Append bukti sekarang memverifikasi seluruh rantai dan anchor di bawah lock
  sebelum menulis. Hash lokal mendeteksi perubahan tetapi tidak melindungi dari
  penulisan ulang log dan anchor oleh pihak yang menguasai keduanya.
- Verifikasi: `uv run --with pytest python -m pytest -q
  tests/test_evidence_provenance.py tests/test_attack_session_report.py`:
  16 lulus; `uv run --with pytest python -m pytest -q tests/`: 1219 lulus.

## Pekerjaan berikutnya

1. Tinjau integritas artefak sesi lainnya dan kasus kegagalan saat penyimpanan;
   tambahkan fixture dan tes sebelum perubahan.
2. Tingkatkan laporan menggunakan bukti terverifikasi, tanpa menyimpulkan
   verdict yang tidak didukung bukti dan tanpa membocorkan data sensitif.
3. Tambahkan perbandingan offline dua snapshot terverifikasi; jangan menimpa
   bukti atau laporan historis, dan jangan menyebut perbedaan sebagai perbaikan
   kerentanan tanpa bukti yang memadai.
4. Tinjau harness yang sudah ada sebelum mengintegrasikan bagian defensif; jangan
   mengaktifkan komponen ofensif dalam rencana yang bertentangan dengan batas di atas.
5. Jalankan tes terarah dan suite penuh setelah setiap tahap; catat bagian
   spesifikasi yang belum terpenuhi dan jangan klaim seluruh milestone selesai.
