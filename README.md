# SMART-SEC

Sistem Evaluasi Keamanan Berbasis Risk Scoring CVSS v4.0 untuk Identifikasi
Kerentanan Aplikasi Web secara Massal.

## Struktur Repo (monorepo, npm workspaces)

```
smart-sec/
├── apps/
│   ├── web/          # Next.js + TypeScript + Tailwind — lapisan presentasi MURNI
│   │                  # (dashboard, trigger scan, realtime view). Tidak pernah
│   │                  # menghitung skor CVSS atau memanggil OWASP ZAP langsung.
│   └── worker/        # External Background Worker (Node.js) — proses mandiri
│                       # di luar Supabase, memanggil OWASP ZAP REST API,
│                       # menulis findings mentah ke Supabase via service role.
└── supabase/
    ├── config.toml
    └── migrations/
        ├── 0001_core_schema.sql          # profiles, scan_targets, scan_jobs, findings
        ├── 0002_rls_policies.sql         # RLS + fungsi claim_next_scan_job()
        └── 0003_cvss_engine.sql          # Stored Procedure + trigger CVSS v4.0 (implementasi penuh)
```

## Alur Arsitektur (Decoupled)

1. Pengguna login di **apps/web** (Next.js), menambahkan target VDP, lalu
   memicu scan lewat `POST /api/scans` — ini hanya menyisipkan satu baris ke
   `scan_jobs` (status `queued`). Tidak ada pemindaian yang terjadi di sini.
2. **apps/worker** berjalan sebagai proses terpisah, melakukan polling ke
   Supabase lewat RPC `claim_next_scan_job()` (atomic, `FOR UPDATE SKIP
   LOCKED`) — beberapa instance worker bisa jalan paralel tanpa bentrok,
   inilah yang memungkinkan *mass-scanning* konkuren.
3. Worker memanggil **OWASP ZAP REST API** (spider → active scan → alerts),
   lalu bulk-insert hasil mentah ke tabel `findings` menggunakan
   **service role key** (bypass RLS, hanya dipegang worker — tidak pernah
   ada di browser).
4. Trigger `BEFORE INSERT` di database memanggil **Stored Procedure**
   `calculate_cvss_v4()` (PostgreSQL/PL-pgSQL) untuk mengisi skor
   Base/Threat/Environmental/Composite — komputasi 100% di lapisan basis
   data, bukan di worker maupun frontend.
5. **apps/web** menampilkan hasil secara realtime lewat Supabase Realtime
   (`postgres_changes` di tabel `findings`) — tidak perlu polling/refresh
   manual, dan RLS tetap membatasi setiap pengguna hanya melihat baris
   miliknya.

## Menjalankan Secara Lokal

```bash
# 1. Install dependencies (root + kedua workspace)
npm install

# 2. Jalankan Supabase lokal (butuh Supabase CLI)
supabase start
supabase db push          # menjalankan semua file di supabase/migrations/

# 3. Salin env template dan isi kredensial
cp .env.example apps/web/.env.local      # isi NEXT_PUBLIC_* saja
cp .env.example apps/worker/.env         # isi SUPABASE_URL + SERVICE_ROLE_KEY + ZAP_*

# 4. Jalankan OWASP ZAP dalam mode daemon (contoh via Docker)
docker run -u zap -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=false -config api.key=change-me

# 5. Jalankan frontend dan worker (dua terminal terpisah)
npm run dev:web        # http://localhost:3000
npm run dev:worker      # mulai polling antrean
```

## Status Implementasi

- [x] Struktur repo & skema database
- [x] RLS policies + fungsi claim antrean atomik
- [x] Dashboard Next.js (login, dashboard, route trigger scan, realtime view)
- [x] External Worker (ZAP client, token bucket rate limiter, job processor)
- [x] **Stored Procedure `calculate_cvss_v4()`** (`0003_cvss_engine.sql`) —
      implementasi algoritma resmi CVSS v4.0 (porting dari reference
      implementation FIRST.org/Red Hat: MacroVector 6-equivalence-class +
      tabel lookup 270 baris + interpolasi severity distance), tervalidasi
      100% exact match pada 800 vektor uji acak (base + threat/environmental/
      modified) terhadap `ae-cvss-calculator` (lihat `apps/worker/src` untuk
      skrip verifikasi terkait) + trigger `trg_findings_compute_cvss()`
      `BEFORE INSERT/UPDATE` pada `findings`
- [x] Autentikasi (Supabase Auth, `apps/web/app/login`) + middleware yang
      melindungi `/dashboard`; RLS (`owner_id = auth.uid()`) menegakkan
      isolasi data per pengguna di setiap query
- [x] Pemetaan otomatis OWASP Top 10:2021 → kategori kerentanan
      (`apps/worker/src/services/cvssVectorMapper.ts`): CWE-ID dari alert
      ZAP dicocokkan ke tabel aturan CWE→OWASP, dengan fallback heuristik
      berbasis kata kunci nama alert untuk CWE yang belum terdaftar
- [ ] Laporan/ekspor hasil audit (PDF/CSV)
