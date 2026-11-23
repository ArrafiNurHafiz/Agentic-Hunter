# Checkpoint pengembangan offline

## Batas kerja

Eksekusi assessment ofensif, pembuatan payload eksploitasi, dan reproduksi otomatis
tetap dinonaktifkan di luar cakupan. Integrasi 9Router/Brain dibatasi secara ketat
pada saran remediasi berbasis metadata yang telah disanitasi; dilarang mengirim bukti
mentah (raw evidence, raw request, raw response, token otorisasi).

## Progres Terkini

1. **Integritas Artefak Sesi & Penanganan Kegagalan Penyimpanan:**
   - `SessionManager` (`bughunter/core/session.py`) diperkuat dengan mekanisme *rollback*
     atomik saat kegagalan I/O (misal: disk penuh saat menulis `.sha256`), mencegah sesi
     ditinggalkan dalam kondisi *half-written* atau tidak konsisten.
   - Menambahkan API manajemen artefak sesi (`save_artifact`, `load_artifact`, `verify_artifact`,
     `list_artifacts`) dengan validasi nama anti-directory traversal dan verifikasi hash SHA-256.
   - Dokumentasi batas kepercayaan (*trust boundary*) secara transparan: digest SHA-256 lokal
     berfungsi sebagai deteksi mutasi/korupsi (*tamper detection*), bukan perlindungan mutlak
     terhadap penyerang lokal berhak akses tulis yang dapat menulis ulang data dan hash sekaligus.

2. **Peningkatan Pelaporan Berbasis Bukti Terverifikasi:**
   - `write_session_report` (`bughunter/phases/p09_reporting.py`) kini menolak menetapkan
     verdict `CONFIRMED` jika temuan tidak didukung oleh rekaman bukti terverifikasi dalam rantai
     provenans (`read_verified`). Temuan tanpa bukti terverifikasi diturunkan ke `INCONCLUSIVE`.
   - Redaksi data sensitif menyeluruh (`redact_obj`) pada struktur laporan JSON dan Markdown,
     termasuk sanitasi kredensial dalam URL target, header otorisasi, dan nilai sensitif pada observasi.

3. **Perbandingan Offline Dua Snapshot Terverifikasi (Differential Retesting):**
   - Diimplementasikan di `bughunter/phases/p10_retesting.py` via `compare_session_snapshots`
     dan `retest_session`.
   - Menjamin immutabilitas sesi referensi/baseline historis (bukti dan laporan lama tidak pernah ditimpa).
   - Menolak keras asumsi perbaikan (*fixed*) hanya karena perbedaan data atau ketiadaan observasi;
     perbedaan data tanpa bukti mitigasi diklasifikasikan sebagai `Inconclusive`.
   - Status `Fixed` hanya diberikan jika terdapat bukti tandingan terverifikasi yang membuktikan
     penanganan aman (misal: validasi input 400/422 terverifikasi pada layanan yang tetap berfungsi).
   - Deteksi status `Still Present` dan `Regression` (respon 500+ / error).
   - Terintegrasi dengan CLI `bughunter retest <session_id>` dan `bughunter attack retest <session_id>`.

4. **Integrasi Defensif Harness & Penasihat Remediasi Brain/9Router:**
   - Dibuat modul defensif `bughunter/harness/remediation.py` (`get_remediation_advice` dan
     `sanitize_finding_for_advisory`).
   - Menyaring data sebelum dikirim ke Brain/9Router: hanya metadata defensif (kelas kerentanan,
     tumpukan teknologi, CWE, URL yang telah disanitasi dari token/kredensial) yang dapat dikirim.
     Bukti mentah (*raw evidence*), request/response mentah, dan rahasia dilarang keras.
   - Menyediakan fallback deterministik jika model AI lokal/Brain tidak aktif.
   - Mode eksekusi ofensif tetap nonaktif pada CLI: `bughunter attack <target>` tanpa `--dry-run`
     menolak eksekusi dan mengarahkan operator menggunakan `--dry-run`.

## Hasil Pengujian

- Suite terarah:
  - `tests/test_session_artifacts_integrity.py`: 5 passed.
  - `tests/test_verified_reporting.py`: 3 passed.
  - `tests/test_attack_session_report.py`: 3 passed.
  - `tests/test_differential_snapshot_comparison.py`: 5 passed.
  - `tests/test_defensive_harness_remediation.py`: 4 passed.
  - `tests/test_m6_harness_e2e.py`: 3 passed.
- Suite milestone terkait (`test_attack_milestone1.py`, `test_attack_milestone2.py`,
  `test_attack_dry_run.py`, `test_evidence_provenance.py`, `test_m1` s.d. `test_m5`): 63 passed.
- Suite penuh: Nol regresi.

## Pekerjaan Berikutnya & Bagian Spesifikasi yang Terbuka

1. **Phase Adapters & Execution Sandboxing:**
   Adapter alat eksternal (`bughunter/adapters/`) saat ini masih berupa stub/mock;
   integrasi eksekusi aktif sesungguhnya tetap dinonaktifkan hingga batas otorisasi lab
   dan sandbox isolasi proses selesai diuji secara aman.
2. **Deterministic Payload Safety Gate Integration:**
   Meskipun generator payload diagnostik non-destruktif dan filter kata kunci berbahaya
   telah memiliki unit test (`test_m4_planner_payload.py`), penerapannya dalam fase pengujian
   aktif belum diaktifkan sesuai batas keamanan repositori saat ini.
3. **Format Ekspor Laporan Lanjutan:**
   Penyelarasan template laporan Markdown dengan format formal bug bounty (HackerOne/Bugcrowd)
   dan ekspor format SARIF terstruktur untuk integrasi pipeline CI/CD defensif.
