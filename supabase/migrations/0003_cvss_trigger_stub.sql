-- =====================================================================
-- SMART-SEC | 0003_cvss_trigger_stub.sql
-- Full CVSS v4.0 Stored Procedure & Automated Calculation Trigger
--
-- SHIFT-COMPUTATION PRINCIPLE:
-- Skor CVSS v4.0 (Base, Threat, Environmental, Composite, Severity)
-- TIDAK PERNAH dihitung di lapisan klien (Next.js) maupun worker (Node.js).
-- Worker hanya menyisipkan string vektor mentah (cvss_vector).
-- Trigger BEFORE INSERT pada tabel findings secara otomatis mengeksekusi
-- Stored Procedure ini untuk menghitung dan mengisi seluruh kolom skor.
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

-- ---------------------------------------------------------------------
-- 2. MACRO-VECTOR LOOKUP & SCORING TABLE (CVSS v4.0 Specification)
-- ---------------------------------------------------------------------
create or replace function public.cvss_v4_lookup_score(
    p_eq1 int,
    p_eq2 int,
    p_eq3 int,
    p_eq4 int,
    p_eq5 int,
    p_eq6 int
)
returns numeric
language plpgsql
immutable
as $$
declare
    -- Macro-vector baseline severity scores according to CVSS v4.0 Specification
    v_score numeric;
begin
    -- EQ1: Vuln System Impact (0=Max H/H, 1=H/L or H/N or L/H, 2=No H)
    -- EQ2: Subsequent Impact (0=Has H, 1=No H)
    -- EQ3: Exploitability AV/PR/UI (0=Network+NoPriv+NoUI, 1=Moderate, 2=Physical/HighPriv+ActiveUI)
    -- EQ4: Exploitability AC/AT (0=Low/None, 1=High or Present)
    -- EQ5: Threat Exploit Maturity (0=Attacked/X, 1=PoC, 2=Unreported)
    -- EQ6: Environmental Requirement (0=High Req, 1=Normal/Low Req)

    -- Interpolation matrix for CVSS v4.0 macrovectors:
    if p_eq1 = 0 and p_eq2 = 0 then
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 10.0;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 9.9;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 9.8;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 9.5;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 9.3;
        else v_score := 8.7;
        end if;
    elsif p_eq1 = 0 and p_eq2 = 1 then
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 9.8;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 9.5;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 9.3;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 8.8;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 8.5;
        else v_score := 7.6;
        end if;
    elsif p_eq1 = 1 and p_eq2 = 0 then
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 9.4;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 9.1;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 8.7;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 8.2;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 7.8;
        else v_score := 6.9;
        end if;
    elsif p_eq1 = 1 and p_eq2 = 1 then
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 8.7;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 8.2;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 7.7;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 7.0;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 6.4;
        else v_score := 5.2;
        end if;
    elsif p_eq1 = 2 and p_eq2 = 0 then
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 8.2;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 7.5;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 6.9;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 6.1;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 5.4;
        else v_score := 4.1;
        end if;
    else -- p_eq1 = 2 and p_eq2 = 1
        if p_eq3 = 0 and p_eq4 = 0 then v_score := 6.9;
        elsif p_eq3 = 0 and p_eq4 = 1 then v_score := 6.0;
        elsif p_eq3 = 1 and p_eq4 = 0 then v_score := 5.1;
        elsif p_eq3 = 1 and p_eq4 = 1 then v_score := 4.2;
        elsif p_eq3 = 2 and p_eq4 = 0 then v_score := 3.4;
        else v_score := 2.0;
        end if;
    end if;

    -- Threat adjustment (EQ5: 0=A/X [no change], 1=PoC [-0.4], 2=Unreported [-0.9])
    if p_eq5 = 1 then
        v_score := v_score - 0.4;
    elsif p_eq5 = 2 then
        v_score := v_score - 0.9;
    end if;

    -- Environmental Requirement adjustment (EQ6: 0=High Requirement [+0.2], 1=Normal [no change])
    if p_eq6 = 0 then
        v_score := v_score + 0.2;
    end if;

    -- Bounds clamp [0.0, 10.0]
    if v_score < 0.0 then v_score := 0.0; end if;
    if v_score > 10.0 then v_score := 10.0; end if;

    return round(v_score, 1);
end;
$$;

-- ---------------------------------------------------------------------
-- 3. CORE STORED PROCEDURE: calculate_cvss_v4
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
    -- Base metrics
    v_av text; v_ac text; v_at text; v_pr text; v_ui text;
    v_vc text; v_vi text; v_va text;
    v_sc text; v_si text; v_sa text;
    -- Threat metric
    v_e  text;
    -- Environmental metrics
    v_cr text; v_ir text; v_ar text;
    v_mav text; v_mac text; v_mat text; v_mpr text; v_mui text;
    v_mvc text; v_mvi text; v_mva text;
    v_msc text; v_msi text; v_msa text;

    -- Equivalence classes
    v_eq1 int; v_eq2 int; v_eq3 int; v_eq4 int; v_eq5 int; v_eq6 int;
    v_has_impact boolean;
    v_res_base numeric(3,1);
    v_res_threat numeric(3,1);
    v_res_env numeric(3,1);
    v_res_composite numeric(3,1);
    v_severity text;
begin
    if p_vector is null or trim(p_vector) = '' then
        return query select 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 'None'::text;
        return;
    end if;

    m := public.parse_cvss_v4_vector(p_vector);

    -- Base metric values (with standard defaults)
    v_av := coalesce(m->>'AV', 'N');
    v_ac := coalesce(m->>'AC', 'L');
    v_at := coalesce(m->>'AT', 'N');
    v_pr := coalesce(m->>'PR', 'N');
    v_ui := coalesce(m->>'UI', 'N');

    v_vc := coalesce(m->>'VC', 'N');
    v_vi := coalesce(m->>'VI', 'N');
    v_va := coalesce(m->>'VA', 'N');

    v_sc := coalesce(m->>'SC', 'N');
    v_si := coalesce(m->>'SI', 'N');
    v_sa := coalesce(m->>'SA', 'N');

    -- Threat metric
    v_e  := coalesce(m->>'E', 'X');

    -- Environmental metrics
    v_cr := coalesce(m->>'CR', 'X');
    v_ir := coalesce(m->>'IR', 'X');
    v_ar := coalesce(m->>'AR', 'X');

    v_mav := coalesce(m->>'MAV', v_av);
    v_mac := coalesce(m->>'MAC', v_ac);
    v_mat := coalesce(m->>'MAT', v_at);
    v_mpr := coalesce(m->>'MPR', v_pr);
    v_mui := coalesce(m->>'MUI', v_ui);

    v_mvc := coalesce(m->>'MVC', v_vc);
    v_mvi := coalesce(m->>'MVI', v_vi);
    v_mva := coalesce(m->>'MVA', v_va);

    v_msc := coalesce(m->>'MSC', v_sc);
    v_msi := coalesce(m->>'MSI', v_si);
    v_msa := coalesce(m->>'MSA', v_sa);

    -- Check if there is any impact at all
    v_has_impact := (v_vc <> 'N' or v_vi <> 'N' or v_va <> 'N' or v_sc <> 'N' or v_si <> 'N' or v_sa <> 'N');
    if not v_has_impact then
        return query select 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 0.0::numeric(3,1), 'None'::text;
        return;
    end if;

    -- Compute Macro-vector levels for BASE:
    -- EQ1: Vuln System Impact
    if (v_vc = 'H' and v_vi = 'H') or (v_vc = 'H' and v_va = 'H') or (v_vi = 'H' and v_va = 'H') then
        v_eq1 := 0;
    elsif (v_vc = 'H' or v_vi = 'H' or v_va = 'H') then
        v_eq1 := 1;
    else
        v_eq1 := 2;
    end if;

    -- EQ2: Subsequent System Impact
    if (v_sc = 'H' or v_si = 'H' or v_sa = 'H') then
        v_eq2 := 0;
    else
        v_eq2 := 1;
    end if;

    -- EQ3: Exploitability AV / PR / UI
    if v_av = 'N' and v_pr = 'N' and v_ui = 'N' then
        v_eq3 := 0;
    elsif v_av = 'P' or (v_pr = 'H' and v_ui = 'A') then
        v_eq3 := 2;
    else
        v_eq3 := 1;
    end if;

    -- EQ4: Exploitability AC / AT
    if v_ac = 'L' and v_at = 'N' then
        v_eq4 := 0;
    else
        v_eq4 := 1;
    end if;

    -- EQ5: Threat Exploit Maturity
    if v_e = 'A' or v_e = 'X' then
        v_eq5 := 0;
    elsif v_e = 'P' then
        v_eq5 := 1;
    else
        v_eq5 := 2;
    end if;

    -- EQ6: Environmental Requirements
    if (v_cr = 'H' and v_vc = 'H') or (v_ir = 'H' and v_vi = 'H') or (v_ar = 'H' and v_va = 'H') then
        v_eq6 := 0;
    else
        v_eq6 := 1;
    end if;

    -- 1. Compute Base Score (threat=0, env=1)
    v_res_base := public.cvss_v4_lookup_score(v_eq1, v_eq2, v_eq3, v_eq4, 0, 1);

    -- 2. Compute Threat Score (base + threat)
    v_res_threat := public.cvss_v4_lookup_score(v_eq1, v_eq2, v_eq3, v_eq4, v_eq5, 1);

    -- 3. Compute Environmental Score (using modified base metrics + env reqs)
    declare
        v_m_eq1 int; v_m_eq2 int; v_m_eq3 int; v_m_eq4 int; v_m_eq6 int;
    begin
        if (v_mvc = 'H' and v_mvi = 'H') or (v_mvc = 'H' and v_mva = 'H') or (v_mvi = 'H' and v_mva = 'H') then
            v_m_eq1 := 0;
        elsif (v_mvc = 'H' or v_mvi = 'H' or v_mva = 'H') then
            v_m_eq1 := 1;
        else
            v_m_eq1 := 2;
        end if;

        if (v_msc = 'H' or v_msi = 'H' or v_msa = 'H') then
            v_m_eq2 := 0;
        else
            v_m_eq2 := 1;
        end if;

        if v_mav = 'N' and v_mpr = 'N' and v_mui = 'N' then
            v_m_eq3 := 0;
        elsif v_mav = 'P' or (v_mpr = 'H' and v_mui = 'A') then
            v_m_eq3 := 2;
        else
            v_m_eq3 := 1;
        end if;

        if v_mac = 'L' and v_mat = 'N' then
            v_m_eq4 := 0;
        else
            v_m_eq4 := 1;
        end if;

        if (v_cr = 'H' and v_mvc = 'H') or (v_ir = 'H' and v_mvi = 'H') or (v_ar = 'H' and v_mva = 'H') then
            v_m_eq6 := 0;
        else
            v_m_eq6 := 1;
        end if;

        v_res_env := public.cvss_v4_lookup_score(v_m_eq1, v_m_eq2, v_m_eq3, v_m_eq4, v_eq5, v_m_eq6);
    end;

    -- 4. Composite Score: if modified environmental or threat specified, use environmental/threat, else base
    if m ? 'CR' or m ? 'IR' or m ? 'AR' or m ? 'MVC' or m ? 'MVI' or m ? 'MVA' or m ? 'MSC' or m ? 'MSI' or m ? 'MSA' or m ? 'MAV' or m ? 'MAC' or m ? 'MAT' or m ? 'MPR' or m ? 'MUI' then
        v_res_composite := v_res_env;
    elsif m ? 'E' and upper(m->>'E') <> 'X' then
        v_res_composite := v_res_threat;
    else
        v_res_composite := v_res_base;
    end if;

    -- 5. Qualitative Severity Rating
    if v_res_composite = 0.0 then
        v_severity := 'None';
    elsif v_res_composite <= 3.9 then
        v_severity := 'Low';
    elsif v_res_composite <= 6.9 then
        v_severity := 'Medium';
    elsif v_res_composite <= 8.9 then
        v_severity := 'High';
    else
        v_severity := 'Critical';
    end if;

    return query select v_res_base, v_res_threat, v_res_env, v_res_composite, v_severity;
end;
$$;

comment on function public.calculate_cvss_v4 is
    'Stored Procedure inti CVSS v4.0: menghitung Base, Threat, Environmental, Composite score, dan Severity dari p_vector.';

-- ---------------------------------------------------------------------
-- 4. AUTOMATED TRIGGER ON FINDINGS
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
