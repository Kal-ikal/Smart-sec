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
        └── 0003_cvss_trigger_stub.sql    # hook trigger untuk CVSS v4.0 (stub)
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
- [x] Skeleton Next.js (dashboard, route trigger scan, realtime view)
- [x] Skeleton External Worker (ZAP client, token bucket rate limiter, job processor)
- [ ] **Stored Procedure `calculate_cvss_v4()`** — baru berupa stub yang
      melempar exception; implementasi Base/Threat/Environmental Metrics
      (consensus table CVSS v4.0) belum ditulis
- [ ] Autentikasi & manajemen role admin di UI
- [ ] Pemetaan otomatis OWASP Top 10:2021 → kategori kerentanan (saat ini manual)
- [ ] Laporan/ekspor hasil audit
