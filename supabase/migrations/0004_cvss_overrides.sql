-- =====================================================================
-- SMART-SEC | 0004_cvss_overrides.sql
-- Penilaian Kontekstual CVSS v4.0 oleh Analis (Threat & Environmental
-- Metrics)
--
-- Menambahkan kemampuan bagi analis pemilik data untuk mengontekstualisasi
-- skor risiko dengan Threat Metrics (Exploit Maturity) dan Environmental
-- Metrics (Security Requirements CR/IR/AR, serta Modified Base Metrics)
-- TANPA mengubah string cvss_vector mentah yang dituliskan worker --
-- penilaian analis disimpan terpisah di kolom cvss_overrides dan
-- digabung (merge) dengan vektor mentah hanya pada saat komputasi skor.
--
-- Ini tetap menjaga prinsip shift-computation: penggabungan dan
-- kalkulasi ulang skor terjadi 100% di database (trigger BEFORE UPDATE),
-- bukan di client -- klien hanya mengirim objek JSONB override melalui
-- RPC submit_cvss_assessment(), tidak pernah menghitung skor sendiri.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. KOLOM cvss_overrides
-- ---------------------------------------------------------------------
alter table public.findings
    add column if not exists cvss_overrides jsonb;

comment on column public.findings.cvss_overrides is
    'Penilaian kontekstual analis (Threat/Environmental Metrics: E, CR, IR, AR, M<metric>) sebagai JSONB metric:value, digabung dengan cvss_vector mentah saat komputasi skor. NULL berarti belum ada penilaian analis -- skor sepenuhnya berasal dari cvss_vector.';

-- ---------------------------------------------------------------------
-- 2. calculate_cvss_v4 -- diganti dengan versi 2-argumen. Versi lama
-- 1-argumen HARUS di-drop dulu -- CREATE OR REPLACE dengan signature
-- berbeda akan membuat overload baru, bukan mengganti, dan menyebabkan
-- pemanggilan 1-argumen jadi ambigu di antara keduanya.
-- ---------------------------------------------------------------------
drop function if exists public.calculate_cvss_v4(text);

-- calculate_cvss_v4 -- sekarang menerima p_overrides sebagai argumen
-- kedua. Base score TETAP murni dari cvss_vector (tidak pernah
-- dipengaruhi override, sesuai spesifikasi CVSS v4.0: Base Score adalah
-- properti intrinsik kerentanan). Threat & Environmental score
-- menggabungkan p_overrides ke atas metric hasil parse vector
-- (override menang jika ada konflik key).
-- ---------------------------------------------------------------------
create or replace function public.calculate_cvss_v4(p_vector text, p_overrides jsonb default '{}'::jsonb)
returns table (
    base_score          numeric(3,1),
    threat_score        numeric(3,1),
    environmental_score numeric(3,1),
    composite_score     numeric(3,1),
    severity            text
)
language plpgsql
immutable
as $$
declare
    m jsonb;
    m_full jsonb;
    v_base numeric(3,1);
    v_threat numeric(3,1);
    v_env numeric(3,1);
    v_composite numeric(3,1);
    v_severity text;
    v_has_e boolean;
    v_has_env_inputs boolean;
begin
    if p_vector is null or trim(p_vector) = '' then
        return query select 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 'None'::text;
        return;
    end if;

    m := public.parse_cvss_v4_vector(p_vector);
    m_full := m || coalesce(p_overrides, '{}'::jsonb);

    -- Base score: murni dari vector mentah, TIDAK menerima override.
    v_base := public.cvss_v4_compute_score(m, false, false);
    -- Threat score: vector + E (dari vector ATAU override analis).
    v_threat := public.cvss_v4_compute_score(m_full, true, false);
    -- Environmental score: vector + E + CR/IR/AR + M* (vector ATAU override analis).
    v_env := public.cvss_v4_compute_score(m_full, true, true);

    v_has_e := (m_full ? 'E') and (m_full ->> 'E') <> 'X';
    v_has_env_inputs :=
        ((m_full ? 'CR') and (m_full ->> 'CR') <> 'X') or
        ((m_full ? 'IR') and (m_full ->> 'IR') <> 'X') or
        ((m_full ? 'AR') and (m_full ->> 'AR') <> 'X') or
        ((m_full ? 'MAV') and (m_full ->> 'MAV') <> 'X') or
        ((m_full ? 'MAC') and (m_full ->> 'MAC') <> 'X') or
        ((m_full ? 'MAT') and (m_full ->> 'MAT') <> 'X') or
        ((m_full ? 'MPR') and (m_full ->> 'MPR') <> 'X') or
        ((m_full ? 'MUI') and (m_full ->> 'MUI') <> 'X') or
        ((m_full ? 'MVC') and (m_full ->> 'MVC') <> 'X') or
        ((m_full ? 'MVI') and (m_full ->> 'MVI') <> 'X') or
        ((m_full ? 'MVA') and (m_full ->> 'MVA') <> 'X') or
        ((m_full ? 'MSC') and (m_full ->> 'MSC') <> 'X') or
        ((m_full ? 'MSI') and (m_full ->> 'MSI') <> 'X') or
        ((m_full ? 'MSA') and (m_full ->> 'MSA') <> 'X');

    if v_has_env_inputs then
        v_composite := v_env;
    elsif v_has_e then
        v_composite := v_threat;
    else
        v_composite := v_base;
    end if;

    if v_composite = 0.0 then
        v_severity := 'None';
    elsif v_composite <= 3.9 then
        v_severity := 'Low';
    elsif v_composite <= 6.9 then
        v_severity := 'Medium';
    elsif v_composite <= 8.9 then
        v_severity := 'High';
    else
        v_severity := 'Critical';
    end if;

    return query select v_base, v_threat, v_env, v_composite, v_severity;
end;
$$;

comment on function public.calculate_cvss_v4 is
    'Stored Procedure inti CVSS v4.0: menghitung Base, Threat, Environmental, Composite score, dan Severity dari p_vector digabung p_overrides (penilaian kontekstual analis), mengikuti algoritma resmi FIRST.org CVSS v4.0.';

-- ---------------------------------------------------------------------
-- 3. Trigger -- sekarang juga bereaksi pada perubahan cvss_overrides,
-- dan meneruskannya ke calculate_cvss_v4.
-- ---------------------------------------------------------------------
create or replace function public.trg_findings_compute_cvss()
returns trigger
language plpgsql
as $$
declare
    r record;
begin
    if new.cvss_vector is null or trim(new.cvss_vector) = '' then
        new.cvss_base_score          := null;
        new.cvss_threat_score        := null;
        new.cvss_environmental_score := null;
        new.cvss_composite_score     := null;
        new.cvss_severity            := null;
        return new;
    end if;

    select * into r from public.calculate_cvss_v4(new.cvss_vector, coalesce(new.cvss_overrides, '{}'::jsonb));

    new.cvss_base_score          := r.base_score;
    new.cvss_threat_score        := r.threat_score;
    new.cvss_environmental_score := r.environmental_score;
    new.cvss_composite_score     := r.composite_score;
    new.cvss_severity            := r.severity;

    return new;
end;
$$;

drop trigger if exists before_findings_insert_compute_cvss on public.findings;

create trigger before_findings_insert_compute_cvss
    before insert or update of cvss_vector, cvss_overrides on public.findings
    for each row execute procedure public.trg_findings_compute_cvss();

comment on trigger before_findings_insert_compute_cvss on public.findings is
    'Menjamin komputasi CVSS v4.0 (termasuk penggabungan penilaian kontekstual analis) terjadi 100% di lapisan basis data, sesuai Batasan Masalah: skor tidak dihitung di klien/worker.';

-- ---------------------------------------------------------------------
-- 4. submit_cvss_assessment -- RPC bagi analis pemilik data untuk
-- mengirim penilaian Threat/Environmental Metrics. SECURITY DEFINER
-- supaya bisa menulis ke findings (yang tidak punya policy UPDATE untuk
-- authenticated), TAPI tetap memverifikasi kepemilikan baris secara
-- eksplisit di awal fungsi -- klien tidak bisa mengubah baris findings
-- milik pengguna lain.
-- ---------------------------------------------------------------------
create or replace function public.submit_cvss_assessment(p_finding_id uuid, p_overrides jsonb)
returns public.findings
language plpgsql
security definer set search_path = public
as $$
declare
    v_owner uuid;
    v_result public.findings;
begin
    select owner_id into v_owner from public.findings where id = p_finding_id;

    if v_owner is null then
        raise exception 'Finding % tidak ditemukan', p_finding_id;
    end if;

    if v_owner <> auth.uid() then
        raise exception 'Tidak diizinkan mengubah penilaian CVSS milik pengguna lain';
    end if;

    update public.findings
    set cvss_overrides = coalesce(cvss_overrides, '{}'::jsonb) || coalesce(p_overrides, '{}'::jsonb)
    where id = p_finding_id
    returning * into v_result;

    return v_result;
end;
$$;

comment on function public.submit_cvss_assessment is
    'RPC bagi analis untuk mengirim penilaian Threat Metrics (Exploit Maturity) dan Environmental Metrics (Security Requirements CR/IR/AR, Modified Base Metrics) pada satu finding miliknya. Trigger BEFORE UPDATE menghitung ulang skor secara otomatis dan atomik di database.';

revoke execute on function public.submit_cvss_assessment(uuid, jsonb) from public, anon;
grant execute on function public.submit_cvss_assessment(uuid, jsonb) to authenticated;
