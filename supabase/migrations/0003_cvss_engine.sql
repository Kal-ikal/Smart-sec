-- =====================================================================
-- SMART-SEC | 0003_cvss_engine.sql
-- Full CVSS v4.0 Stored Procedure & Automated Calculation Trigger
--
-- SHIFT-COMPUTATION PRINCIPLE:
-- Skor CVSS v4.0 (Base, Threat, Environmental, Composite, Severity)
-- TIDAK PERNAH dihitung di lapisan klien (Next.js) maupun worker (Node.js).
-- Worker hanya menyisipkan string vektor mentah (cvss_vector).
-- Trigger BEFORE INSERT pada tabel findings secara otomatis mengeksekusi
-- Stored Procedure ini untuk menghitung dan mengisi seluruh kolom skor.
--
-- ALGORITMA: ini adalah porting dari algoritma skoring RESMI CVSS v4.0
-- (spesifikasi FIRST.org) -- MacroVector 6-Equivalence-Class + tabel
-- lookup 270 baris + interpolasi jarak keparahan ("severity distance") --
-- diporting dari reference implementation resmi FIRST/Red Hat:
--   https://github.com/FIRSTdotorg/cvss-v4-calculator
--   (cvss_score.js, cvss_lookup.js, max_composed.js, max_severity.js;
--    Copyright FIRST, Red Hat, and contributors; SPDX: BSD-2-Clause)
-- Ini menggantikan pendekatan tabel datar yang disederhanakan pada versi
-- sebelumnya, yang terbukti hanya ~1.8% cocok dengan reference
-- implementation saat divalidasi terhadap 500 vektor uji acak.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. PARSER: parse_cvss_v4_vector
-- Memecah string vektor CVSS v4.0 menjadi JSONB key-value map.
-- ---------------------------------------------------------------------
create or replace function public.parse_cvss_v4_vector(p_vector text)
returns jsonb
language plpgsql
immutable
as $$
declare
    v_parts text[];
    v_part text;
    v_pair text[];
    v_result jsonb := '{}'::jsonb;
begin
    if p_vector is null or trim(p_vector) = '' then
        return v_result;
    end if;

    v_parts := string_to_array(trim(p_vector), '/');

    -- Validasi prefix CVSS:4.0
    if array_length(v_parts, 1) < 1 or upper(v_parts[1]) <> 'CVSS:4.0' then
        return v_result;
    end if;

    for i in 2..array_length(v_parts, 1) loop
        v_part := trim(v_parts[i]);
        if v_part <> '' then
            v_pair := string_to_array(v_part, ':');
            if array_length(v_pair, 1) = 2 then
                v_result := jsonb_set(v_result, array[upper(trim(v_pair[1]))], to_jsonb(upper(trim(v_pair[2]))));
            end if;
        end if;
    end loop;

    return v_result;
end;
$$;

comment on function public.parse_cvss_v4_vector is
    'Mem-parse string vektor CVSS:4.0 menjadi JSONB pasangan metric:value.';

-- Fungsi lama dari implementasi tabel datar yang disederhanakan (sebelum
-- porting spec-compliant ini) -- dihapus karena sudah digantikan sepenuhnya
-- oleh cvss_v4_compute_score() di bawah.
drop function if exists public.cvss_v4_lookup_score(int, int, int, int, int, int);

-- ---------------------------------------------------------------------
-- 2. TABEL LOOKUP MACROVECTOR RESMI CVSS v4.0 (270 baris)
-- Sumber: cvss_lookup.js pada reference implementation resmi FIRST/Red Hat.
-- Kunci adalah string 6 digit EQ1EQ2EQ3EQ4EQ5EQ6.
-- ---------------------------------------------------------------------
drop table if exists public.cvss_v4_macrovector_scores;
create table public.cvss_v4_macrovector_scores (
    macrovector char(6) primary key,
    score numeric(3,1) not null
);

comment on table public.cvss_v4_macrovector_scores is
    'Tabel skor MacroVector resmi CVSS v4.0 (270 kombinasi EQ1-EQ6), sumber github.com/FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause). Dipakai oleh cvss_v4_compute_score() untuk interpolasi skor.';

insert into public.cvss_v4_macrovector_scores (macrovector, score) values
  ('100000', 9.8),
  ('100001', 9.5),
  ('100010', 9.4),
  ('100011', 8.7),
  ('100020', 9.1),
  ('100021', 8.1),
  ('100100', 9.4),
  ('100101', 8.9),
  ('100110', 8.6),
  ('100111', 7.4),
  ('100120', 7.7),
  ('100121', 6.4),
  ('100200', 8.7),
  ('100201', 7.5),
  ('100210', 7.4),
  ('100211', 6.3),
  ('100220', 6.3),
  ('100221', 4.9),
  ('101000', 9.4),
  ('101001', 8.9),
  ('101010', 8.8),
  ('101011', 7.7),
  ('101020', 7.6),
  ('101021', 6.7),
  ('101100', 8.6),
  ('101101', 7.6),
  ('101110', 7.4),
  ('101111', 5.8),
  ('101120', 5.9),
  ('101121', 5.0),
  ('101200', 7.2),
  ('101201', 5.7),
  ('101210', 5.7),
  ('101211', 5.2),
  ('101220', 5.2),
  ('101221', 2.5),
  ('102001', 8.3),
  ('102011', 7.0),
  ('102021', 5.4),
  ('102101', 6.5),
  ('102111', 5.8),
  ('102121', 2.6),
  ('102201', 5.3),
  ('102211', 2.1),
  ('102221', 1.3),
  ('110000', 9.5),
  ('110001', 9.0),
  ('110010', 8.8),
  ('110011', 7.6),
  ('110020', 7.6),
  ('110021', 7.0),
  ('110100', 9.0),
  ('110101', 7.7),
  ('110110', 7.5),
  ('110111', 6.2),
  ('110120', 6.1),
  ('110121', 5.3),
  ('110200', 7.7),
  ('110201', 6.6),
  ('110210', 6.8),
  ('110211', 5.9),
  ('110220', 5.2),
  ('110221', 3.0),
  ('111000', 8.9),
  ('111001', 7.8),
  ('111010', 7.6),
  ('111011', 6.7),
  ('111020', 6.2),
  ('111021', 5.8),
  ('111100', 7.4),
  ('111101', 5.9),
  ('111110', 5.7),
  ('111111', 5.7),
  ('111120', 4.7),
  ('111121', 2.3),
  ('111200', 6.1),
  ('111201', 5.2),
  ('111210', 5.7),
  ('111211', 2.9),
  ('111220', 2.4),
  ('111221', 1.6),
  ('112001', 7.1),
  ('112011', 5.9),
  ('112021', 3.0),
  ('112101', 5.8),
  ('112111', 2.6),
  ('112121', 1.5),
  ('112201', 2.3),
  ('112211', 1.3),
  ('112221', 0.6),
  ('200000', 9.3),
  ('200001', 8.7),
  ('200010', 8.6),
  ('200011', 7.2),
  ('200020', 7.5),
  ('200021', 5.8),
  ('200100', 8.6),
  ('200101', 7.4),
  ('200110', 7.4),
  ('200111', 6.1),
  ('200120', 5.6),
  ('200121', 3.4),
  ('200200', 7.0),
  ('200201', 5.4),
  ('200210', 5.2),
  ('200211', 4.0),
  ('200220', 4.0),
  ('200221', 2.2),
  ('201000', 8.5),
  ('201001', 7.5),
  ('201010', 7.4),
  ('201011', 5.5),
  ('201020', 6.2),
  ('201021', 5.1),
  ('201100', 7.2),
  ('201101', 5.7),
  ('201110', 5.5),
  ('201111', 4.1),
  ('201120', 4.6),
  ('201121', 1.9),
  ('201200', 5.3),
  ('201201', 3.6),
  ('201210', 3.4),
  ('201211', 1.9),
  ('201220', 1.9),
  ('201221', 0.8),
  ('202001', 6.4),
  ('202011', 5.1),
  ('202021', 2.0),
  ('202101', 4.7),
  ('202111', 2.1),
  ('202121', 1.1),
  ('202201', 2.4),
  ('202211', 0.9),
  ('202221', 0.4),
  ('210000', 8.8),
  ('210001', 7.5),
  ('210010', 7.3),
  ('210011', 5.3),
  ('210020', 6.0),
  ('210021', 5.0),
  ('210100', 7.3),
  ('210101', 5.5),
  ('210110', 5.9),
  ('210111', 4.0),
  ('210120', 4.1),
  ('210121', 2.0),
  ('210200', 5.4),
  ('210201', 4.3),
  ('210210', 4.5),
  ('210211', 2.2),
  ('210220', 2.0),
  ('210221', 1.1),
  ('211000', 7.5),
  ('211001', 5.5),
  ('211010', 5.8),
  ('211011', 4.5),
  ('211020', 4.0),
  ('211021', 2.1),
  ('211100', 6.1),
  ('211101', 5.1),
  ('211110', 4.8),
  ('211111', 1.8),
  ('211120', 2.0),
  ('211121', 0.9),
  ('211200', 4.6),
  ('211201', 1.8),
  ('211210', 1.7),
  ('211211', 0.7),
  ('211220', 0.8),
  ('211221', 0.2),
  ('212001', 5.3),
  ('212011', 2.4),
  ('212021', 1.4),
  ('212101', 2.4),
  ('212111', 1.2),
  ('212121', 0.5),
  ('212201', 1.0),
  ('212211', 0.3),
  ('212221', 0.1),
  ('000000', 10.0),
  ('000001', 9.9),
  ('000010', 9.8),
  ('000011', 9.5),
  ('000020', 9.5),
  ('000021', 9.2),
  ('000100', 10.0),
  ('000101', 9.6),
  ('000110', 9.3),
  ('000111', 8.7),
  ('000120', 9.1),
  ('000121', 8.1),
  ('000200', 9.3),
  ('000201', 9.0),
  ('000210', 8.9),
  ('000211', 8.0),
  ('000220', 8.1),
  ('000221', 6.8),
  ('001000', 9.8),
  ('001001', 9.5),
  ('001010', 9.5),
  ('001011', 9.2),
  ('001020', 9.0),
  ('001021', 8.4),
  ('001100', 9.3),
  ('001101', 9.2),
  ('001110', 8.9),
  ('001111', 8.1),
  ('001120', 8.1),
  ('001121', 6.5),
  ('001200', 8.8),
  ('001201', 8.0),
  ('001210', 7.8),
  ('001211', 7.0),
  ('001220', 6.9),
  ('001221', 4.8),
  ('002001', 9.2),
  ('002011', 8.2),
  ('002021', 7.2),
  ('002101', 7.9),
  ('002111', 6.9),
  ('002121', 5.0),
  ('002201', 6.9),
  ('002211', 5.5),
  ('002221', 2.7),
  ('010000', 9.9),
  ('010001', 9.7),
  ('010010', 9.5),
  ('010011', 9.2),
  ('010020', 9.2),
  ('010021', 8.5),
  ('010100', 9.5),
  ('010101', 9.1),
  ('010110', 9.0),
  ('010111', 8.3),
  ('010120', 8.4),
  ('010121', 7.1),
  ('010200', 9.2),
  ('010201', 8.1),
  ('010210', 8.2),
  ('010211', 7.1),
  ('010220', 7.2),
  ('010221', 5.3),
  ('011000', 9.5),
  ('011001', 9.3),
  ('011010', 9.2),
  ('011011', 8.5),
  ('011020', 8.5),
  ('011021', 7.3),
  ('011100', 9.2),
  ('011101', 8.2),
  ('011110', 8.0),
  ('011111', 7.2),
  ('011120', 7.0),
  ('011121', 5.9),
  ('011200', 8.4),
  ('011201', 7.0),
  ('011210', 7.1),
  ('011211', 5.2),
  ('011220', 5.0),
  ('011221', 3.0),
  ('012001', 8.6),
  ('012011', 7.5),
  ('012021', 5.2),
  ('012101', 7.1),
  ('012111', 5.2),
  ('012121', 2.9),
  ('012201', 6.3),
  ('012211', 2.9),
  ('012221', 1.7);

-- ---------------------------------------------------------------------
-- 3. NILAI NUMERIK "LEVEL" PER METRIC (dipakai untuk severity distance)
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_metric_level(p_metric text, p_value text)
returns numeric
language sql
immutable
as $$
    select case p_metric
        when 'AV' then case p_value when 'N' then 0.0 when 'A' then 0.1 when 'L' then 0.2 when 'P' then 0.3 end
        when 'PR' then case p_value when 'N' then 0.0 when 'L' then 0.1 when 'H' then 0.2 end
        when 'UI' then case p_value when 'N' then 0.0 when 'P' then 0.1 when 'A' then 0.2 end
        when 'AC' then case p_value when 'L' then 0.0 when 'H' then 0.1 end
        when 'AT' then case p_value when 'N' then 0.0 when 'P' then 0.1 end
        when 'VC' then case p_value when 'H' then 0.0 when 'L' then 0.1 when 'N' then 0.2 end
        when 'VI' then case p_value when 'H' then 0.0 when 'L' then 0.1 when 'N' then 0.2 end
        when 'VA' then case p_value when 'H' then 0.0 when 'L' then 0.1 when 'N' then 0.2 end
        when 'SC' then case p_value when 'H' then 0.1 when 'L' then 0.2 when 'N' then 0.3 end
        when 'SI' then case p_value when 'S' then 0.0 when 'H' then 0.1 when 'L' then 0.2 when 'N' then 0.3 end
        when 'SA' then case p_value when 'S' then 0.0 when 'H' then 0.1 when 'L' then 0.2 when 'N' then 0.3 end
        when 'CR' then case p_value when 'H' then 0.0 when 'M' then 0.1 when 'L' then 0.2 end
        when 'IR' then case p_value when 'H' then 0.0 when 'M' then 0.1 when 'L' then 0.2 end
        when 'AR' then case p_value when 'H' then 0.0 when 'M' then 0.1 when 'L' then 0.2 end
    end;
$$;

-- ---------------------------------------------------------------------
-- 4. "HIGHEST SEVERITY VECTOR" candidates per equivalence class
-- (setara maxComposed di reference implementation resmi)
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_eq1_maxes(p_eq1 int)
returns jsonb[]
language sql
immutable
as $$
    select case p_eq1
        when 0 then array[jsonb_build_object('AV','N','PR','N','UI','N')]
        when 1 then array[
            jsonb_build_object('AV','A','PR','N','UI','N'),
            jsonb_build_object('AV','N','PR','L','UI','N'),
            jsonb_build_object('AV','N','PR','N','UI','P')]
        else array[
            jsonb_build_object('AV','P','PR','N','UI','N'),
            jsonb_build_object('AV','A','PR','L','UI','P')]
    end;
$$;

create or replace function public.cvss_v4_eq2_maxes(p_eq2 int)
returns jsonb[]
language sql
immutable
as $$
    select case p_eq2
        when 0 then array[jsonb_build_object('AC','L','AT','N')]
        else array[
            jsonb_build_object('AC','H','AT','N'),
            jsonb_build_object('AC','L','AT','P')]
    end;
$$;

create or replace function public.cvss_v4_eq3eq6_maxes(p_eq3 int, p_eq6 int)
returns jsonb[]
language sql
immutable
as $$
    select case
        when p_eq3 = 0 and p_eq6 = 0 then
            array[jsonb_build_object('VC','H','VI','H','VA','H','CR','H','IR','H','AR','H')]
        when p_eq3 = 0 and p_eq6 = 1 then array[
            jsonb_build_object('VC','H','VI','H','VA','L','CR','M','IR','M','AR','H'),
            jsonb_build_object('VC','H','VI','H','VA','H','CR','M','IR','M','AR','M')]
        when p_eq3 = 1 and p_eq6 = 0 then array[
            jsonb_build_object('VC','L','VI','H','VA','H','CR','H','IR','H','AR','H'),
            jsonb_build_object('VC','H','VI','L','VA','H','CR','H','IR','H','AR','H')]
        when p_eq3 = 1 and p_eq6 = 1 then array[
            jsonb_build_object('VC','L','VI','H','VA','L','CR','H','IR','M','AR','H'),
            jsonb_build_object('VC','L','VI','H','VA','H','CR','H','IR','M','AR','M'),
            jsonb_build_object('VC','H','VI','L','VA','H','CR','M','IR','H','AR','M'),
            jsonb_build_object('VC','H','VI','L','VA','L','CR','M','IR','H','AR','H'),
            jsonb_build_object('VC','L','VI','L','VA','H','CR','H','IR','H','AR','M')]
        when p_eq3 = 2 and p_eq6 = 1 then
            array[jsonb_build_object('VC','L','VI','L','VA','L','CR','H','IR','H','AR','H')]
        else array[]::jsonb[]
    end;
$$;

create or replace function public.cvss_v4_eq4_max(p_eq4 int)
returns jsonb
language sql
immutable
as $$
    select case p_eq4
        when 0 then jsonb_build_object('SC','H','SI','S','SA','S')
        when 1 then jsonb_build_object('SC','H','SI','H','SA','H')
        else jsonb_build_object('SC','L','SI','L','SA','L')
    end;
$$;

-- ---------------------------------------------------------------------
-- 5. NILAI EFEKTIF SATU METRIC (setara fungsi m() reference implementation)
-- Menerapkan default E:X->A, CR/IR/AR:X->H, dan overlay M<metric> untuk
-- skor environmental.
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_effective_metric(
    p_metrics jsonb,
    p_metric text,
    p_apply_threat boolean,
    p_apply_environmental boolean
) returns text
language plpgsql
immutable
as $$
declare
    v_val text;
    v_mval text;
begin
    if p_metric = 'E' then
        if not p_apply_threat then
            return 'A';
        end if;
        v_val := p_metrics ->> 'E';
        if v_val is null or v_val = 'X' then
            return 'A';
        end if;
        return v_val;
    end if;

    if p_metric in ('CR', 'IR', 'AR') then
        if not p_apply_environmental then
            return 'H';
        end if;
        v_val := p_metrics ->> p_metric;
        if v_val is null or v_val = 'X' then
            return 'H';
        end if;
        return v_val;
    end if;

    -- Base metrics: AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA
    if p_apply_environmental then
        v_mval := p_metrics ->> ('M' || p_metric);
        if v_mval is not null and v_mval <> 'X' then
            return v_mval;
        end if;
    end if;

    v_val := p_metrics ->> p_metric;
    return coalesce(v_val, case p_metric
        when 'AC' then 'L'
        else 'N'
    end);
end;
$$;

-- ---------------------------------------------------------------------
-- 6. MACROVECTOR (EQ1-EQ6) dari sekumpulan metric efektif
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_macrovector(
    p_metrics jsonb,
    p_apply_threat boolean,
    p_apply_environmental boolean
) returns char(6)
language plpgsql
immutable
as $$
declare
    v_av text; v_pr text; v_ui text; v_ac text; v_at text;
    v_vc text; v_vi text; v_va text; v_sc text; v_si text; v_sa text;
    v_e text; v_cr text; v_ir text; v_ar text;
    v_msi text; v_msa text;
    v_eq1 int; v_eq2 int; v_eq3 int; v_eq4 int; v_eq5 int; v_eq6 int;
begin
    v_av := public.cvss_v4_effective_metric(p_metrics,'AV',p_apply_threat,p_apply_environmental);
    v_pr := public.cvss_v4_effective_metric(p_metrics,'PR',p_apply_threat,p_apply_environmental);
    v_ui := public.cvss_v4_effective_metric(p_metrics,'UI',p_apply_threat,p_apply_environmental);
    v_ac := public.cvss_v4_effective_metric(p_metrics,'AC',p_apply_threat,p_apply_environmental);
    v_at := public.cvss_v4_effective_metric(p_metrics,'AT',p_apply_threat,p_apply_environmental);
    v_vc := public.cvss_v4_effective_metric(p_metrics,'VC',p_apply_threat,p_apply_environmental);
    v_vi := public.cvss_v4_effective_metric(p_metrics,'VI',p_apply_threat,p_apply_environmental);
    v_va := public.cvss_v4_effective_metric(p_metrics,'VA',p_apply_threat,p_apply_environmental);
    v_sc := public.cvss_v4_effective_metric(p_metrics,'SC',p_apply_threat,p_apply_environmental);
    v_si := public.cvss_v4_effective_metric(p_metrics,'SI',p_apply_threat,p_apply_environmental);
    v_sa := public.cvss_v4_effective_metric(p_metrics,'SA',p_apply_threat,p_apply_environmental);
    v_e  := public.cvss_v4_effective_metric(p_metrics,'E',p_apply_threat,p_apply_environmental);
    v_cr := public.cvss_v4_effective_metric(p_metrics,'CR',p_apply_threat,p_apply_environmental);
    v_ir := public.cvss_v4_effective_metric(p_metrics,'IR',p_apply_threat,p_apply_environmental);
    v_ar := public.cvss_v4_effective_metric(p_metrics,'AR',p_apply_threat,p_apply_environmental);

    if p_apply_environmental then
        v_msi := coalesce(p_metrics ->> 'MSI', 'X');
        v_msa := coalesce(p_metrics ->> 'MSA', 'X');
    else
        v_msi := 'X';
        v_msa := 'X';
    end if;

    -- EQ1: 0-(AV:N and PR:N and UI:N); 2-(AV:P or not any N); 1-lainnya
    if v_av = 'N' and v_pr = 'N' and v_ui = 'N' then
        v_eq1 := 0;
    elsif (v_av = 'N' or v_pr = 'N' or v_ui = 'N')
        and not (v_av = 'N' and v_pr = 'N' and v_ui = 'N')
        and not (v_av = 'P') then
        v_eq1 := 1;
    else
        v_eq1 := 2;
    end if;

    -- EQ2: 0-(AC:L and AT:N); 1-lainnya
    if v_ac = 'L' and v_at = 'N' then
        v_eq2 := 0;
    else
        v_eq2 := 1;
    end if;

    -- EQ3: 0-(VC:H and VI:H); 1-(salah satu VC/VI/VA:H, bukan VC&VI:H); 2-tidak ada yang H
    if v_vc = 'H' and v_vi = 'H' then
        v_eq3 := 0;
    elsif not (v_vc = 'H' and v_vi = 'H') and (v_vc = 'H' or v_vi = 'H' or v_va = 'H') then
        v_eq3 := 1;
    else
        v_eq3 := 2;
    end if;

    -- EQ4: 0-(MSI:S or MSA:S); 1-(SC/SI/SA:H); 2-lainnya
    if v_msi = 'S' or v_msa = 'S' then
        v_eq4 := 0;
    elsif (v_sc = 'H' or v_si = 'H' or v_sa = 'H') then
        v_eq4 := 1;
    else
        v_eq4 := 2;
    end if;

    -- EQ5: 0-E:A; 1-E:P; 2-E:U
    if v_e = 'A' then
        v_eq5 := 0;
    elsif v_e = 'P' then
        v_eq5 := 1;
    else
        v_eq5 := 2;
    end if;

    -- EQ6: 0-(CR:H&VC:H) or (IR:H&VI:H) or (AR:H&VA:H); 1-lainnya
    if (v_cr = 'H' and v_vc = 'H') or (v_ir = 'H' and v_vi = 'H') or (v_ar = 'H' and v_va = 'H') then
        v_eq6 := 0;
    else
        v_eq6 := 1;
    end if;

    return (v_eq1::text || v_eq2::text || v_eq3::text || v_eq4::text || v_eq5::text || v_eq6::text);
end;
$$;

-- ---------------------------------------------------------------------
-- 7. INTI ALGORITMA: skor MacroVector + interpolasi severity distance
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_compute_score(
    p_metrics jsonb,
    p_apply_threat boolean,
    p_apply_environmental boolean
) returns numeric(3,1)
language plpgsql
immutable
as $$
declare
    v_av text; v_pr text; v_ui text; v_ac text; v_at text;
    v_vc text; v_vi text; v_va text; v_sc text; v_si text; v_sa text;
    v_cr text; v_ir text; v_ar text;
    v_macro char(6);
    v_eq1 int; v_eq2 int; v_eq3 int; v_eq4 int; v_eq5 int; v_eq6 int;
    v_value numeric;
    v_score_eq1_lower numeric;
    v_score_eq2_lower numeric;
    v_score_eq3eq6_lower numeric;
    v_score_eq4_lower numeric;
    v_score_eq5_lower numeric;
    v_left numeric; v_right numeric;
    v_eq1_maxes jsonb[];
    v_eq2_maxes jsonb[];
    v_eq3eq6_maxes jsonb[];
    v_eq4_max jsonb;
    e1 jsonb; e2 jsonb; e3 jsonb;
    v_i1 int; v_i2 int; v_i3 int;
    v_dist_av numeric; v_dist_pr numeric; v_dist_ui numeric;
    v_dist_ac numeric; v_dist_at numeric;
    v_dist_vc numeric; v_dist_vi numeric; v_dist_va numeric;
    v_dist_sc numeric; v_dist_si numeric; v_dist_sa numeric;
    v_dist_cr numeric; v_dist_ir numeric; v_dist_ar numeric;
    v_all_ge_zero boolean;
    v_dist_eq1 numeric; v_dist_eq2 numeric; v_dist_eq3eq6 numeric; v_dist_eq4 numeric;
    v_maxsev_eq1 numeric; v_maxsev_eq2 numeric; v_maxsev_eq3eq6 numeric; v_maxsev_eq4 numeric;
    v_avail_eq1 numeric; v_avail_eq2 numeric; v_avail_eq3eq6 numeric; v_avail_eq4 numeric; v_avail_eq5 numeric;
    v_norm_eq1 numeric := 0; v_norm_eq2 numeric := 0; v_norm_eq3eq6 numeric := 0;
    v_norm_eq4 numeric := 0; v_norm_eq5 numeric := 0;
    v_n_existing int := 0;
    v_mean numeric;
    v_step constant numeric := 0.1;
begin
    v_vc := public.cvss_v4_effective_metric(p_metrics,'VC',p_apply_threat,p_apply_environmental);
    v_vi := public.cvss_v4_effective_metric(p_metrics,'VI',p_apply_threat,p_apply_environmental);
    v_va := public.cvss_v4_effective_metric(p_metrics,'VA',p_apply_threat,p_apply_environmental);
    v_sc := public.cvss_v4_effective_metric(p_metrics,'SC',p_apply_threat,p_apply_environmental);
    v_si := public.cvss_v4_effective_metric(p_metrics,'SI',p_apply_threat,p_apply_environmental);
    v_sa := public.cvss_v4_effective_metric(p_metrics,'SA',p_apply_threat,p_apply_environmental);

    -- Shortcut: tidak ada dampak sama sekali
    if v_vc = 'N' and v_vi = 'N' and v_va = 'N' and v_sc = 'N' and v_si = 'N' and v_sa = 'N' then
        return 0.0;
    end if;

    v_av := public.cvss_v4_effective_metric(p_metrics,'AV',p_apply_threat,p_apply_environmental);
    v_pr := public.cvss_v4_effective_metric(p_metrics,'PR',p_apply_threat,p_apply_environmental);
    v_ui := public.cvss_v4_effective_metric(p_metrics,'UI',p_apply_threat,p_apply_environmental);
    v_ac := public.cvss_v4_effective_metric(p_metrics,'AC',p_apply_threat,p_apply_environmental);
    v_at := public.cvss_v4_effective_metric(p_metrics,'AT',p_apply_threat,p_apply_environmental);
    v_cr := public.cvss_v4_effective_metric(p_metrics,'CR',p_apply_threat,p_apply_environmental);
    v_ir := public.cvss_v4_effective_metric(p_metrics,'IR',p_apply_threat,p_apply_environmental);
    v_ar := public.cvss_v4_effective_metric(p_metrics,'AR',p_apply_threat,p_apply_environmental);

    v_macro := public.cvss_v4_macrovector(p_metrics, p_apply_threat, p_apply_environmental);
    v_eq1 := substring(v_macro from 1 for 1)::int;
    v_eq2 := substring(v_macro from 2 for 1)::int;
    v_eq3 := substring(v_macro from 3 for 1)::int;
    v_eq4 := substring(v_macro from 4 for 1)::int;
    v_eq5 := substring(v_macro from 5 for 1)::int;
    v_eq6 := substring(v_macro from 6 for 1)::int;

    select score into v_value from public.cvss_v4_macrovector_scores where macrovector = v_macro;
    if v_value is null then
        -- Tidak boleh terjadi untuk macrovector yang valid; jaga-jaga saja.
        return 0.0;
    end if;

    -- Skor MacroVector satu tingkat lebih rendah per EQ (untuk interpolasi)
    select score into v_score_eq1_lower from public.cvss_v4_macrovector_scores
        where macrovector = ((v_eq1+1)::text || v_eq2::text || v_eq3::text || v_eq4::text || v_eq5::text || v_eq6::text);
    select score into v_score_eq2_lower from public.cvss_v4_macrovector_scores
        where macrovector = (v_eq1::text || (v_eq2+1)::text || v_eq3::text || v_eq4::text || v_eq5::text || v_eq6::text);
    select score into v_score_eq4_lower from public.cvss_v4_macrovector_scores
        where macrovector = (v_eq1::text || v_eq2::text || v_eq3::text || (v_eq4+1)::text || v_eq5::text || v_eq6::text);
    select score into v_score_eq5_lower from public.cvss_v4_macrovector_scores
        where macrovector = (v_eq1::text || v_eq2::text || v_eq3::text || v_eq4::text || (v_eq5+1)::text || v_eq6::text);

    -- EQ3 dan EQ6 saling terkait, ditangani sebagai satu pasangan
    if v_eq3 = 1 and v_eq6 = 1 then
        select score into v_score_eq3eq6_lower from public.cvss_v4_macrovector_scores
            where macrovector = (v_eq1::text || v_eq2::text || '2' || v_eq4::text || v_eq5::text || '1');
    elsif v_eq3 = 0 and v_eq6 = 1 then
        select score into v_score_eq3eq6_lower from public.cvss_v4_macrovector_scores
            where macrovector = (v_eq1::text || v_eq2::text || '1' || v_eq4::text || v_eq5::text || '1');
    elsif v_eq3 = 1 and v_eq6 = 0 then
        select score into v_score_eq3eq6_lower from public.cvss_v4_macrovector_scores
            where macrovector = (v_eq1::text || v_eq2::text || '1' || v_eq4::text || v_eq5::text || '1');
    elsif v_eq3 = 0 and v_eq6 = 0 then
        select score into v_left from public.cvss_v4_macrovector_scores
            where macrovector = (v_eq1::text || v_eq2::text || '0' || v_eq4::text || v_eq5::text || '1');
        select score into v_right from public.cvss_v4_macrovector_scores
            where macrovector = (v_eq1::text || v_eq2::text || '1' || v_eq4::text || v_eq5::text || '0');
        if v_left is null then
            v_score_eq3eq6_lower := v_right;
        elsif v_right is null then
            v_score_eq3eq6_lower := v_left;
        elsif v_left > v_right then
            v_score_eq3eq6_lower := v_left;
        else
            v_score_eq3eq6_lower := v_right;
        end if;
    else
        -- eq3=2, eq6=1: tidak ada macrovector yang lebih rendah lagi
        v_score_eq3eq6_lower := null;
    end if;

    -- Cari kombinasi "highest severity vector" yang berlaku untuk vektor ini
    v_eq1_maxes := public.cvss_v4_eq1_maxes(v_eq1);
    v_eq2_maxes := public.cvss_v4_eq2_maxes(v_eq2);
    v_eq3eq6_maxes := public.cvss_v4_eq3eq6_maxes(v_eq3, v_eq6);
    v_eq4_max := public.cvss_v4_eq4_max(v_eq4);

    <<search>>
    for v_i1 in 1..coalesce(array_length(v_eq1_maxes,1),0) loop
        e1 := v_eq1_maxes[v_i1];
        for v_i2 in 1..coalesce(array_length(v_eq2_maxes,1),0) loop
            e2 := v_eq2_maxes[v_i2];
            for v_i3 in 1..coalesce(array_length(v_eq3eq6_maxes,1),0) loop
                e3 := v_eq3eq6_maxes[v_i3];

                v_dist_av := public.cvss_v4_metric_level('AV', v_av) - public.cvss_v4_metric_level('AV', e1->>'AV');
                v_dist_pr := public.cvss_v4_metric_level('PR', v_pr) - public.cvss_v4_metric_level('PR', e1->>'PR');
                v_dist_ui := public.cvss_v4_metric_level('UI', v_ui) - public.cvss_v4_metric_level('UI', e1->>'UI');
                v_dist_ac := public.cvss_v4_metric_level('AC', v_ac) - public.cvss_v4_metric_level('AC', e2->>'AC');
                v_dist_at := public.cvss_v4_metric_level('AT', v_at) - public.cvss_v4_metric_level('AT', e2->>'AT');
                v_dist_vc := public.cvss_v4_metric_level('VC', v_vc) - public.cvss_v4_metric_level('VC', e3->>'VC');
                v_dist_vi := public.cvss_v4_metric_level('VI', v_vi) - public.cvss_v4_metric_level('VI', e3->>'VI');
                v_dist_va := public.cvss_v4_metric_level('VA', v_va) - public.cvss_v4_metric_level('VA', e3->>'VA');
                v_dist_cr := public.cvss_v4_metric_level('CR', v_cr) - public.cvss_v4_metric_level('CR', e3->>'CR');
                v_dist_ir := public.cvss_v4_metric_level('IR', v_ir) - public.cvss_v4_metric_level('IR', e3->>'IR');
                v_dist_ar := public.cvss_v4_metric_level('AR', v_ar) - public.cvss_v4_metric_level('AR', e3->>'AR');
                v_dist_sc := public.cvss_v4_metric_level('SC', v_sc) - public.cvss_v4_metric_level('SC', v_eq4_max->>'SC');
                v_dist_si := public.cvss_v4_metric_level('SI', v_si) - public.cvss_v4_metric_level('SI', v_eq4_max->>'SI');
                v_dist_sa := public.cvss_v4_metric_level('SA', v_sa) - public.cvss_v4_metric_level('SA', v_eq4_max->>'SA');

                v_all_ge_zero := (
                    v_dist_av >= 0 and v_dist_pr >= 0 and v_dist_ui >= 0 and
                    v_dist_ac >= 0 and v_dist_at >= 0 and
                    v_dist_vc >= 0 and v_dist_vi >= 0 and v_dist_va >= 0 and
                    v_dist_sc >= 0 and v_dist_si >= 0 and v_dist_sa >= 0 and
                    v_dist_cr >= 0 and v_dist_ir >= 0 and v_dist_ar >= 0
                );

                if v_all_ge_zero then
                    exit search;
                end if;
            end loop;
        end loop;
    end loop;

    v_dist_eq1 := v_dist_av + v_dist_pr + v_dist_ui;
    v_dist_eq2 := v_dist_ac + v_dist_at;
    v_dist_eq3eq6 := v_dist_vc + v_dist_vi + v_dist_va + v_dist_cr + v_dist_ir + v_dist_ar;
    v_dist_eq4 := v_dist_sc + v_dist_si + v_dist_sa;

    v_maxsev_eq1 := (case v_eq1 when 0 then 1 when 1 then 4 else 5 end) * v_step;
    v_maxsev_eq2 := (case v_eq2 when 0 then 1 else 2 end) * v_step;
    v_maxsev_eq3eq6 := (case
        when v_eq3 = 0 and v_eq6 = 0 then 7
        when v_eq3 = 0 and v_eq6 = 1 then 6
        when v_eq3 = 1 and v_eq6 = 0 then 8
        when v_eq3 = 1 and v_eq6 = 1 then 8
        when v_eq3 = 2 and v_eq6 = 1 then 10
        else 1
    end) * v_step;
    v_maxsev_eq4 := (case v_eq4 when 0 then 6 when 1 then 5 else 4 end) * v_step;

    v_avail_eq1 := v_value - v_score_eq1_lower;
    v_avail_eq2 := v_value - v_score_eq2_lower;
    v_avail_eq3eq6 := v_value - v_score_eq3eq6_lower;
    v_avail_eq4 := v_value - v_score_eq4_lower;
    v_avail_eq5 := v_value - v_score_eq5_lower;

    if v_avail_eq1 is not null then
        v_n_existing := v_n_existing + 1;
        v_norm_eq1 := v_avail_eq1 * (v_dist_eq1 / v_maxsev_eq1);
    end if;
    if v_avail_eq2 is not null then
        v_n_existing := v_n_existing + 1;
        v_norm_eq2 := v_avail_eq2 * (v_dist_eq2 / v_maxsev_eq2);
    end if;
    if v_avail_eq3eq6 is not null then
        v_n_existing := v_n_existing + 1;
        v_norm_eq3eq6 := v_avail_eq3eq6 * (v_dist_eq3eq6 / v_maxsev_eq3eq6);
    end if;
    if v_avail_eq4 is not null then
        v_n_existing := v_n_existing + 1;
        v_norm_eq4 := v_avail_eq4 * (v_dist_eq4 / v_maxsev_eq4);
    end if;
    if v_avail_eq5 is not null then
        -- EQ5 tidak pernah berkontribusi (persentase interpolasinya selalu 0
        -- sesuai spesifikasi resmi), tapi tetap dihitung dalam pembagi rata-rata.
        v_n_existing := v_n_existing + 1;
        v_norm_eq5 := 0;
    end if;

    if v_n_existing = 0 then
        v_mean := 0;
    else
        v_mean := (v_norm_eq1 + v_norm_eq2 + v_norm_eq3eq6 + v_norm_eq4 + v_norm_eq5) / v_n_existing;
    end if;

    v_value := v_value - v_mean;
    if v_value < 0 then v_value := 0.0; end if;
    if v_value > 10 then v_value := 10.0; end if;

    return round(v_value, 1);
end;
$$;

comment on function public.cvss_v4_compute_score is
    'Implementasi algoritma skoring resmi CVSS v4.0 (MacroVector + interpolasi severity distance), porting dari reference implementation FIRST/Red Hat.';

-- ---------------------------------------------------------------------
-- 8. CORE STORED PROCEDURE: calculate_cvss_v4
-- Nama fungsi & bentuk return TIDAK diubah -- dikonsumsi oleh trigger di
-- bawah dan dirujuk di seluruh narasi skripsi.
-- ---------------------------------------------------------------------
create or replace function public.calculate_cvss_v4(p_vector text)
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

    -- Base score: hanya 11 base metrics, E/CR/IR/AR/M* diabaikan sepenuhnya.
    v_base := public.cvss_v4_compute_score(m, false, false);
    -- Threat score: base + E (Exploit Maturity) jika ada.
    v_threat := public.cvss_v4_compute_score(m, true, false);
    -- Environmental score: base + E + CR/IR/AR + metric M* jika ada.
    v_env := public.cvss_v4_compute_score(m, true, true);

    v_has_e := (m ? 'E') and (m ->> 'E') <> 'X';
    v_has_env_inputs :=
        ((m ? 'CR') and (m ->> 'CR') <> 'X') or
        ((m ? 'IR') and (m ->> 'IR') <> 'X') or
        ((m ? 'AR') and (m ->> 'AR') <> 'X') or
        ((m ? 'MAV') and (m ->> 'MAV') <> 'X') or
        ((m ? 'MAC') and (m ->> 'MAC') <> 'X') or
        ((m ? 'MAT') and (m ->> 'MAT') <> 'X') or
        ((m ? 'MPR') and (m ->> 'MPR') <> 'X') or
        ((m ? 'MUI') and (m ->> 'MUI') <> 'X') or
        ((m ? 'MVC') and (m ->> 'MVC') <> 'X') or
        ((m ? 'MVI') and (m ->> 'MVI') <> 'X') or
        ((m ? 'MVA') and (m ->> 'MVA') <> 'X') or
        ((m ? 'MSC') and (m ->> 'MSC') <> 'X') or
        ((m ? 'MSI') and (m ->> 'MSI') <> 'X') or
        ((m ? 'MSA') and (m ->> 'MSA') <> 'X');

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
    'Stored Procedure inti CVSS v4.0: menghitung Base, Threat, Environmental, Composite score, dan Severity dari p_vector, mengikuti algoritma resmi FIRST.org CVSS v4.0.';

-- ---------------------------------------------------------------------
-- 9. AUTOMATED TRIGGER ON FINDINGS
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

    select * into r from public.calculate_cvss_v4(new.cvss_vector);

    new.cvss_base_score          := r.base_score;
    new.cvss_threat_score        := r.threat_score;
    new.cvss_environmental_score := r.environmental_score;
    new.cvss_composite_score     := r.composite_score;
    new.cvss_severity            := r.severity;

    return new;
end;
$$;

-- Drop trigger if exists to allow clean re-runs
drop trigger if exists before_findings_insert_compute_cvss on public.findings;

create trigger before_findings_insert_compute_cvss
    before insert or update of cvss_vector on public.findings
    for each row execute procedure public.trg_findings_compute_cvss();

comment on trigger before_findings_insert_compute_cvss on public.findings is
    'Menjamin komputasi CVSS v4.0 terjadi 100% di lapisan basis data (BEFORE INSERT/UPDATE), sesuai Batasan Masalah: skor tidak dihitung di klien/worker.';
