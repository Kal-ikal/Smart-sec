-- =====================================================================
-- SMART-SEC | 0001_core_schema.sql
-- Skema inti: profil pengguna, target VDP, antrean pemindaian (queue),
-- dan tabel temuan kerentanan mentah dari OWASP ZAP.
--
-- Prinsip desain:
--   * Semua tabel operasional ber-owner (org_id) untuk mendukung RLS
--     per-tenant, meskipun untuk skripsi ini konteksnya single-tenant
--     (satu komite keamanan / satu peneliti).
--   * scan_jobs adalah "antrean" yang dibaca oleh External Background
--     Worker secara polling/subscribe -- BUKAN dieksekusi oleh Supabase
--     Edge Function, supaya tidak kena batas timeout serverless.
--   * Semua kolom skor (base/threat/environmental/composite) SENGAJA
--     dibiarkan NULL saat insert oleh worker; nilainya baru diisi oleh
--     Stored Procedure CVSS v4.0 (lihat 0003_cvss_trigger_stub.sql)
--     lewat trigger BEFORE INSERT pada findings.
-- =====================================================================

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------
-- 1. PROFILES
-- Melekat 1:1 ke auth.users (Supabase Auth). Menyimpan role aplikasi
-- karena auth.users tidak boleh diperluas langsung.
-- ---------------------------------------------------------------------
create type app_role as enum ('admin', 'analyst', 'viewer');

create table public.profiles (
    id          uuid primary key references auth.users (id) on delete cascade,
    full_name   text,
    role        app_role not null default 'analyst',
    created_at  timestamptz not null default now()
);

comment on table public.profiles is
    'Profil aplikasi 1:1 dengan auth.users. Sumber kebenaran untuk role-based access di RLS.';

-- ---------------------------------------------------------------------
-- 2. SCAN_TARGETS
-- Daftar URL yang SAH untuk dipindai (VDP / sandbox) sesuai Batasan
-- Masalah proposal (kepatuhan UU ITE).
-- ---------------------------------------------------------------------
create table public.scan_targets (
    id              uuid primary key default gen_random_uuid(),
    owner_id        uuid not null references public.profiles (id) on delete cascade,
    url             text not null,
    program_name    text,               -- nama program VDP / sandbox
    is_authorized   boolean not null default false, -- gerbang kepatuhan; harus true sebelum masuk antrean
    notes           text,
    created_at      timestamptz not null default now(),
    unique (owner_id, url)
);

comment on column public.scan_targets.is_authorized is
    'Wajib true (verifikasi manual/checklist VDP) sebelum target ini boleh diikutkan dalam scan_jobs.';

-- ---------------------------------------------------------------------
-- 3. SCAN_JOBS  (antrean asinkron)
-- Baris di sini adalah "pekerjaan" yang ditarik oleh External Worker.
-- Status berpindah: queued -> claimed -> running -> completed/failed.
-- ---------------------------------------------------------------------
create type job_status as enum ('queued', 'claimed', 'running', 'completed', 'failed');

create table public.scan_jobs (
    id              uuid primary key default gen_random_uuid(),
    owner_id        uuid not null references public.profiles (id) on delete cascade,
    target_id       uuid not null references public.scan_targets (id) on delete cascade,
    status          job_status not null default 'queued',
    zap_scan_id     text,               -- id scan dari OWASP ZAP API, diisi worker
    claimed_by      text,               -- identifier worker instance (untuk audit, bukan FK auth)
    claimed_at      timestamptz,
    started_at      timestamptz,
    finished_at     timestamptz,
    error_message   text,
    created_at      timestamptz not null default now()
);

create index idx_scan_jobs_status_created on public.scan_jobs (status, created_at);

comment on table public.scan_jobs is
    'Antrean pekerjaan pemindaian massal. Worker melakukan claim via UPDATE ... WHERE status=''queued'' RETURNING untuk mencegah double-processing (lihat fungsi claim_next_scan_job di 0002).';

-- ---------------------------------------------------------------------
-- 4. FINDINGS  (temuan mentah dari OWASP ZAP + skor CVSS v4.0)
-- ---------------------------------------------------------------------
create table public.findings (
    id                  uuid primary key default gen_random_uuid(),
    owner_id            uuid not null references public.profiles (id) on delete cascade,
    job_id              uuid not null references public.scan_jobs (id) on delete cascade,
    target_id           uuid not null references public.scan_targets (id) on delete cascade,

    -- Data mentah dari OWASP ZAP
    zap_alert_id        text,
    zap_plugin_id       text,
    name                text not null,
    description         text,
    solution             text,
    owasp_category       text,          -- pemetaan manual/otomatis ke OWASP Top 10:2021 (mis. "A03:2021")
    risk_zap             text,          -- risk rating asli dari ZAP (Informational/Low/Medium/High)
    evidence              text,
    cwe_id                integer,

    -- Vektor CVSS v4.0 mentah (string vektor, mis. "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    cvss_vector           text,

    -- Kolom skor -- DIISI OLEH STORED PROCEDURE, bukan oleh worker/frontend
    cvss_base_score        numeric(3,1),
    cvss_threat_score      numeric(3,1),
    cvss_environmental_score numeric(3,1),
    cvss_composite_score   numeric(3,1),
    cvss_severity           text,       -- None/Low/Medium/High/Critical, turunan dari composite score

    created_at             timestamptz not null default now()
);

create index idx_findings_job on public.findings (job_id);
create index idx_findings_target on public.findings (target_id);
create index idx_findings_severity on public.findings (cvss_severity);

comment on column public.findings.cvss_vector is
    'Vektor CVSS v4.0 mentah yang disusun worker dari hasil ZAP + heuristik pemetaan OWASP->metric. Perhitungan skornya sepenuhnya di database (Stored Procedure), bukan di worker maupun frontend.';
