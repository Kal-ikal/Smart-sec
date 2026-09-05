# Skrip Verifikasi BAB IV

Skrip di folder ini menguji ulang tiga klaim kuantitatif di BAB IV terhadap
kode SMART-SEC yang sebenarnya (bukan asumsi/README). Dijalankan terakhir
kali terhadap PostgreSQL 16 lokal dengan migrasi `supabase/migrations/`
0001-0003 diterapkan (plus stand-in minimal skema `auth` Supabase agar bisa
dieksekusi di luar project Supabase asli -- lihat catatan di bawah).

## 1. Konkurensi `claim_next_scan_job()`

```bash
psql -d <db> -f setup_concurrency_test.sql   # seed 200 job queued

for i in $(seq 1 10); do
  ./verify_concurrency_claim.sh "worker-$i" "/tmp/worker_out_$i.txt" &
done
wait

cat /tmp/worker_out_*.txt | sort -u | wc -l      # harus 200 (0 duplikasi)
cat /tmp/worker_out_*.txt | sort | uniq -d | wc -l  # harus 0
```

**Hasil (3x pengulangan):** 200/200 job diklaim, 0 duplikasi setiap kali.
Distribusi per-worker 18-22 (rata-rata 20, varian alami), bukan persis rata
20/worker seperti klaim lama. Total waktu ~2.3 detik pada koneksi lokal
Unix socket -- **angka waktu TIDAK sebanding** dengan pengujian melalui
hosted Supabase (network roundtrip per RPC call), jadi ukur ulang langsung
di project Supabase asli untuk angka waktu presisi sebelum sidang.

## 2. Token Bucket Rate Limiter

Lihat `apps/worker/src/test_token_bucket_verification.ts` (memakai kelas
`TokenBucket` asli):

```bash
cd apps/worker && npx tsx src/test_token_bucket_verification.ts
```

**Hasil:** laju efektif steady-state terukur 3.00 / 1.50 / 8.33 req/s untuk
skenario capacity/refill (10,3) / (3,1.5) / (25,8.33) -- **cocok persis**
dengan klaim BAB IV, karena laju steady-state Token Bucket secara
matematis mengikuti `refillPerSecond` yang dikonfigurasi.

## 3. Akurasi CVSS v4.0

```bash
npm install ae-cvss-calculator
PSQL_DB=<db> node verify_cvss_v4_accuracy.js        # 500 vektor base metrics
PSQL_DB=<db> node verify_cvss_v4_accuracy_full.js   # 300 vektor + E/CR/IR/AR/M*
```

**Hasil SEBELUM perbaikan** (implementasi tabel datar/disederhanakan,
sebelum ditulis ulang): hanya **~1.8% match** (9/500 dalam toleransi 0.1)
terhadap reference implementation resmi FIRST.org/Red Hat -- klaim lama
"99,6% (498/500)" tidak terbukti.

**Hasil SETELAH perbaikan** (`calculate_cvss_v4()` ditulis ulang mengikuti
algoritma resmi CVSS v4.0 -- MacroVector 6-equivalence-class + tabel lookup
270 baris + interpolasi severity distance, porting dari
github.com/FIRSTdotorg/cvss-v4-calculator):
- 500 vektor base metrics: **500/500 exact match (100%)**
- 300 vektor tambahan (E/CR/IR/AR/M* acak): **300/300 match (100%)**

Reference implementation yang dipakai: `ae-cvss-calculator` (npm, oleh
{metæffekt}), yang mengimplementasikan spesifikasi resmi FIRST.org CVSS
v4.0 -- sudah disanity-check terhadap vektor tak ambigu (semua metric H =
10.0, semua metric N = 0.0) sebelum dipakai sebagai oracle.

## Catatan lingkungan pengujian

Skrip-skrip ini butuh database Postgres dengan migrasi 0001-0003 + skema
`auth` minimal (Supabase menyediakan `auth.users`/`auth.uid()` secara
bawaan; di Postgres polos perlu stub). Kalau menjalankan langsung terhadap
project Supabase asli (`supabase start` atau project hosted), skema `auth`
sudah tersedia dan stub ini tidak diperlukan -- cukup terapkan
`supabase/migrations/*.sql` lalu jalankan skrip di atas dengan `PSQL_DB`
mengarah ke database tersebut.
