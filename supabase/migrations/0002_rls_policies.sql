-- =====================================================================
-- SMART-SEC | 0002_rls_policies.sql
-- Row Level Security untuk isolasi data per-owner, plus fungsi
-- claim_next_scan_job() yang dipakai External Background Worker untuk
-- menarik pekerjaan dari antrean secara aman (atomic claim).
--
-- Model akses:
--   * anon              -> tidak ada akses sama sekali (RLS default deny)
--   * authenticated      -> hanya boleh baca/tulis baris miliknya sendiri
--                           (owner_id = auth.uid()), sesuai role di profiles
--   * service_role        -> dipakai HANYA oleh External Background Worker
--                           (server-side, service key), melewati RLS
--                           sepenuhnya. Frontend TIDAK PERNAH memegang
--                           service key ini.
-- =====================================================================

alter table public.profiles       enable row level security;
alter table public.scan_targets   enable row level security;
alter table public.scan_jobs      enable row level security;
alter table public.findings       enable row level security;

-- ---------------------------------------------------------------------
-- PROFILES
-- ---------------------------------------------------------------------
create policy "profiles: user can read own profile"
    on public.profiles for select
    using (id = auth.uid());

create policy "profiles: user can update own profile"
    on public.profiles for update
    using (id = auth.uid());

-- Baris profile dibuat otomatis oleh trigger saat auth.users baru dibuat
create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, full_name)
    values (new.id, new.raw_user_meta_data ->> 'full_name');
    return new;
end;
$$;

create trigger on_auth_user_created
    after insert on auth.users
    for each row execute procedure public.handle_new_user();

-- ---------------------------------------------------------------------
-- SCAN_TARGETS -- CRUD penuh, tapi hanya untuk baris milik sendiri
-- ---------------------------------------------------------------------
create policy "targets: owner full access"
    on public.scan_targets for all
    using (owner_id = auth.uid())
    with check (owner_id = auth.uid());

-- ---------------------------------------------------------------------
-- SCAN_JOBS
-- authenticated: boleh SELECT & INSERT (memicu antrean) baris miliknya.
-- authenticated TIDAK BOLEH UPDATE status job -- itu wewenang worker
-- (service_role), supaya klien tidak bisa memalsukan status "completed".
-- ---------------------------------------------------------------------
create policy "jobs: owner can read own jobs"
    on public.scan_jobs for select
    using (owner_id = auth.uid());

create policy "jobs: owner can enqueue own jobs"
    on public.scan_jobs for insert
    with check (
        owner_id = auth.uid()
        and exists (
            select 1 from public.scan_targets t
            where t.id = target_id
              and t.owner_id = auth.uid()
              and t.is_authorized = true   -- gerbang kepatuhan VDP/legal
        )
    );

-- (Sengaja tidak ada policy UPDATE/DELETE untuk role authenticated di
-- scan_jobs -- worker mengubah status lewat service_role yang bypass RLS.)

-- ---------------------------------------------------------------------
-- FINDINGS -- read-only bagi pengguna, insert hanya oleh worker
-- ---------------------------------------------------------------------
create policy "findings: owner can read own findings"
    on public.findings for select
    using (owner_id = auth.uid());

-- Tidak ada policy INSERT/UPDATE/DELETE untuk authenticated: findings
-- HANYA ditulis oleh External Background Worker via service_role,
-- yang otomatis melewati RLS. Ini menjamin integritas hasil scan --
-- klien di lapisan presentasi tidak bisa menyuntikkan temuan palsu.

-- ---------------------------------------------------------------------
-- FUNGSI: claim_next_scan_job
-- Dipanggil worker (via RPC, memakai service_role) untuk mengambil satu
-- job berikutnya dari antrean secara atomik, mencegah dua instance
-- worker memproses job yang sama (race condition pada mass-scanning).
-- ---------------------------------------------------------------------
create function public.claim_next_scan_job(p_worker_id text)
returns setof public.scan_jobs
language plpgsql
security definer set search_path = public
as $$
declare
    v_job_id uuid;
begin
    select id into v_job_id
    from public.scan_jobs
    where status = 'queued'
    order by created_at asc
    limit 1
    for update skip locked;      -- kunci baris, lewati yang sudah dikunci worker lain

    if v_job_id is null then
        return;
    end if;

    return query
        update public.scan_jobs
        set status = 'claimed',
            claimed_by = p_worker_id,
            claimed_at = now()
        where id = v_job_id
        returning *;
end;
$$;

comment on function public.claim_next_scan_job is
    'Atomic dequeue untuk External Background Worker. FOR UPDATE SKIP LOCKED memungkinkan banyak instance worker berjalan paralel tanpa memproses job yang sama dua kali -- kunci untuk skenario mass-scanning konkuren.';

-- Hanya service_role (worker) yang boleh mengeksekusi fungsi claim ini.
revoke execute on function public.claim_next_scan_job(text) from public, anon, authenticated;
grant execute on function public.claim_next_scan_job(text) to service_role;

-- ---------------------------------------------------------------------
-- REALTIME REPLICATION
-- Mengaktifkan event realtime Supabase untuk tabel findings dan scan_jobs
-- agar frontend (apps/web) menerima update instan tanpa polling.
-- ---------------------------------------------------------------------
alter publication supabase_realtime add table public.findings;
alter publication supabase_realtime add table public.scan_jobs;

