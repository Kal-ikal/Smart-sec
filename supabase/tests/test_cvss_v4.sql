-- =====================================================================
-- SMART-SEC | test_cvss_v4.sql
-- Verification script for CVSS v4.0 Stored Procedure & Trigger Logic
-- =====================================================================

-- 1. Test parsing and direct computation of standard vectors
-- Critical Vulnerability: RCE / full compromise
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H');
-- Expected: base_score = 10.0, composite_score = 10.0, severity = 'Critical'

-- High Vulnerability: Network SQL Injection without Subsequent Impact
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N');
-- Expected: base_score = 9.8, composite_score = 9.8, severity = 'Critical' / 'High'

-- Medium Vulnerability: Low impact XSS
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N');
-- Expected: base_score ~ 6.4-7.0, severity = 'Medium'

-- Low / Informational: No significant impact
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N');
-- Expected: base_score = 0.0, composite_score = 0.0, severity = 'None'

-- Threat modified: Proof-of-Concept exploit
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P');
-- Expected: threat_score and composite_score adjusted downwards

-- Environmental modified: High Confidentiality Requirement
select * from public.calculate_cvss_v4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H');
-- Expected: environmental_score adjusted upwards
