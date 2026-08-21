"use client";

import { useState, useMemo } from "react";
import type { Database } from "@/types/database";

type Target = Database["public"]["Tables"]["scan_targets"]["Row"];
type Job = Database["public"]["Tables"]["scan_jobs"]["Row"];
type Finding = Database["public"]["Tables"]["findings"]["Row"];

interface ScanReportViewProps {
  targets?: Target[];
  jobs?: Job[];
  findings?: Finding[];
}

// OWASP Top 10:2021 Standard Reference Categories
const OWASP_TOP_10_2021 = [
  { id: "A01:2021-Broken Access Control", name: "A01:2021 - Broken Access Control", desc: "Access control enforcement failures, LFI/RFI, CSRF, and path traversal." },
  { id: "A02:2021-Cryptographic Failures", name: "A02:2021 - Cryptographic Failures", desc: "Weak transport security, plaintext data exposure, or broken hashing." },
  { id: "A03:2021-Injection", name: "A03:2021 - Injection", desc: "SQL Injection, Cross-Site Scripting (XSS), Command Injection." },
  { id: "A04:2021-Insecure Design", name: "A04:2021 - Insecure Design", desc: "Architectural flaws and unvetted business logic vulnerabilities." },
  { id: "A05:2021-Security Misconfiguration", name: "A05:2021 - Security Misconfiguration", desc: "Missing security headers, default passwords, enabled debug options." },
  { id: "A06:2021-Vulnerable and Outdated Components", name: "A06:2021 - Vulnerable Components", desc: "Outdated libraries, unpatched third-party plugins or servers." },
  { id: "A07:2021-Identification and Authentication Failures", name: "A07:2021 - Identification & Auth Failures", desc: "Brute-force weakness, session fixation, unauthenticated endpoints." },
  { id: "A08:2021-Software and Data Integrity Failures", name: "A08:2021 - Software & Data Integrity Failures", desc: "Insecure deserialization, unverified auto-updates, CI/CD pipeline code flaws." },
  { id: "A09:2021-Security Logging and Monitoring Failures", name: "A09:2021 - Logging & Monitoring Failures", desc: "Insufficient audit trails, unlogged security events, undetected intrusions." },
  { id: "A10:2021-Server-Side Request Forgery", name: "A10:2021 - SSRF (Server-Side Request Forgery)", desc: "Web applications fetching remote resources without validating user URLs." }
];

export default function ScanReportView({
  targets = [],
  jobs = [],
  findings = [],
}: ScanReportViewProps) {
  const [selectedTargetId, setSelectedTargetId] = useState<string>("ALL");
  const [selectedJobId, setSelectedJobId] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedVectorId, setCopiedVectorId] = useState<string | null>(null);

  // Filter jobs based on target selection
  const filteredJobs = useMemo(() => {
    if (selectedTargetId === "ALL") return jobs;
    return jobs.filter((j) => j.target_id === selectedTargetId);
  }, [jobs, selectedTargetId]);

  // Active target details
  const activeTarget = useMemo(() => {
    if (selectedTargetId === "ALL") return null;
    return targets.find((t) => t.id === selectedTargetId) || null;
  }, [targets, selectedTargetId]);

  // Active job details
  const activeJob = useMemo(() => {
    if (selectedJobId === "ALL") return null;
    return jobs.find((j) => j.id === selectedJobId) || null;
  }, [jobs, selectedJobId]);

  // Filter findings based on selected target, job, and search query
  const relevantFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchTarget = selectedTargetId === "ALL" || f.target_id === selectedTargetId;
      const matchJob = selectedJobId === "ALL" || f.job_id === selectedJobId;
      
      const query = searchQuery.toLowerCase();
      const matchQuery =
        !searchQuery ||
        f.name.toLowerCase().includes(query) ||
        (f.owasp_category && f.owasp_category.toLowerCase().includes(query)) ||
        (f.description && f.description.toLowerCase().includes(query)) ||
        (f.cwe_id && `cwe-${f.cwe_id}`.includes(query)) ||
        (f.cvss_vector && f.cvss_vector.toLowerCase().includes(query));

      return matchTarget && matchJob && matchQuery;
    });
  }, [findings, selectedTargetId, selectedJobId, searchQuery]);

  // Severity metrics calculation
  const metrics = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let none = 0;
    let maxCompositeScore = 0;

    relevantFindings.forEach((f) => {
      const sev = (f.cvss_severity || "None").toUpperCase();
      if (sev === "CRITICAL") critical++;
      else if (sev === "HIGH") high++;
      else if (sev === "MEDIUM") medium++;
      else if (sev === "LOW") low++;
      else none++;

      if (f.cvss_composite_score && f.cvss_composite_score > maxCompositeScore) {
        maxCompositeScore = f.cvss_composite_score;
      }
    });

    const total = relevantFindings.length;
    let postureText = "BERSIH / SEHAT";
    let postureBadgeClass = "bg-emerald-950/80 text-emerald-300 border-emerald-700/80";
    let postureGlow = "glow-green";

    if (critical > 0) {
      postureText = "RISIKO KRITIS (CRITICAL)";
      postureBadgeClass = "bg-rose-950/90 text-rose-300 border-rose-700/80 animate-pulse";
      postureGlow = "glow-red";
    } else if (high > 0) {
      postureText = "RISIKO TINGGI (HIGH)";
      postureBadgeClass = "bg-red-950/90 text-red-300 border-red-700/80";
      postureGlow = "glow-red";
    } else if (medium > 0) {
      postureText = "RISIKO SEDANG (MEDIUM)";
      postureBadgeClass = "bg-amber-950/90 text-amber-300 border-amber-700/80";
      postureGlow = "";
    } else if (low > 0) {
      postureText = "RISIKO RENDAH (LOW)";
      postureBadgeClass = "bg-blue-950/90 text-blue-300 border-blue-700/80";
      postureGlow = "";
    }

    return {
      total,
      critical,
      high,
      medium,
      low,
      none,
      maxCompositeScore,
      postureText,
      postureBadgeClass,
      postureGlow,
    };
  }, [relevantFindings]);

  // Group findings by OWASP Top 10:2021
  const findingsByOwasp = useMemo(() => {
    const map = new Map<string, Finding[]>();

    // Initialize map for all OWASP Top 10 categories
    OWASP_TOP_10_2021.forEach((cat) => {
      map.set(cat.id, []);
    });
    map.set("Lainnya / Uncategorized", []);

    relevantFindings.forEach((f) => {
      const catKey = f.owasp_category || "Lainnya / Uncategorized";
      if (!map.has(catKey)) {
        map.set(catKey, []);
      }
      map.get(catKey)!.push(f);
    });

    return map;
  }, [relevantFindings]);

  // Copy CVSS Vector helper
  const copyVector = (id: string, vector: string) => {
    navigator.clipboard.writeText(vector);
    setCopiedVectorId(id);
    setTimeout(() => setCopiedVectorId(null), 2000);
  };

  // Helper for Job Status Badge
  const getJobStatusBadge = (status: string | null) => {
    switch (status) {
      case "completed":
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
            ✓ COMPLETED
          </span>
        );
      case "running":
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-950 text-blue-400 border border-blue-800 animate-pulse">
            ⚙ RUNNING
          </span>
        );
      case "claimed":
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-950 text-indigo-400 border border-indigo-800">
            🔒 CLAIMED BY WORKER
          </span>
        );
      case "failed":
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-950 text-rose-400 border border-rose-800">
            ✖ FAILED
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            ⏳ QUEUED
          </span>
        );
    }
  };

  // Download Executive Report in JSON format
  const exportToJsonReport = () => {
    const reportData = {
      meta: {
        platform: "SMART-SEC Release Edition v1.0",
        generatedAt: new Date().toISOString(),
        targetUrl: activeTarget ? activeTarget.url : "Semua Target (Agregat)",
        programName: activeTarget?.program_name ?? "General Audit",
        isAuthorized: activeTarget?.is_authorized ?? true,
        jobId: activeJob ? activeJob.id : "Semua Job",
        jobStatus: activeJob?.status ?? "Multiple Jobs",
        cvssStandard: "CVSS v4.0 (In-Database Shift-Computation PL/pgSQL)",
        owaspStandard: "OWASP Top 10:2021",
      },
      metrics: {
        totalFindings: metrics.total,
        critical: metrics.critical,
        high: metrics.high,
        medium: metrics.medium,
        low: metrics.low,
        none: metrics.none,
        maxCompositeScore: metrics.maxCompositeScore,
        overallPosture: metrics.postureText,
      },
      findings: relevantFindings.map((f) => ({
        id: f.id,
        name: f.name,
        owaspCategory: f.owasp_category,
        cweId: f.cwe_id ? `CWE-${f.cwe_id}` : null,
        cvssVector: f.cvss_vector,
        cvssScores: {
          baseScore: f.cvss_base_score,
          threatScore: f.cvss_threat_score,
          environmentalScore: f.cvss_environmental_score,
          compositeScore: f.cvss_composite_score,
          severity: f.cvss_severity,
        },
        zapRiskRating: f.risk_zap,
        description: f.description,
        evidence: f.evidence,
        solution: f.solution,
        createdAt: f.created_at,
      })),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SMART-SEC_Audit_Report_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Download Executive Summary in Markdown format
  const exportToMarkdownReport = () => {
    const targetInfo = activeTarget
      ? `Target URL: ${activeTarget.url}\nProgram: ${activeTarget.program_name || "-"}\nOtorisasi: ${activeTarget.is_authorized ? "RESMI / VDP AUTHORIZED" : "UNAUTHORIZED"}`
      : "Target: Semuanya (Laporan Rekapitulasi Agregat)";

    let markdown = `# LAPORAN AUDIT KEAMANAN VULNERABILITY ASSESSMENT (SMART-SEC)
Date: ${new Date().toLocaleString("id-ID")}
Platform: SMART-SEC Release Edition v1.0 (In-Database CVSS v4.0 Shift-Computation Engine)

## 1. RINGKASAN EKSEKUTIF (EXECUTIVE SUMMARY)
${targetInfo}
Status Posture Keamanan: ${metrics.postureText}
Skor Risiko Tertinggi Composite CVSS v4.0: ${metrics.maxCompositeScore.toFixed(1)} / 10.0

### Rekapitulasi Tingkat Kerentanan:
- Critical (Kritis) : ${metrics.critical}
- High (Tinggi)      : ${metrics.high}
- Medium (Sedang)    : ${metrics.medium}
- Low (Rendah)       : ${metrics.low}
- Total Temuan      : ${metrics.total}

---

## 2. RINCIAN TEMUAN BERDASARKAN OWASP TOP 10:2021

`;

    Array.from(findingsByOwasp.entries()).forEach(([catKey, items]) => {
      if (items.length > 0) {
        markdown += `### Category: ${catKey} (${items.length} Temuan)\n\n`;
        items.forEach((item, idx) => {
          markdown += `#### ${idx + 1}. ${item.name}\n`;
          markdown += `- **CWE ID**: ${item.cwe_id ? `CWE-${item.cwe_id}` : "-"}\n`;
          markdown += `- **Skor CVSS v4.0**: Composite ${item.cvss_composite_score ?? 0.0} (${item.cvss_severity ?? "None"})\n`;
          markdown += `- **Base / Threat / Env**: ${item.cvss_base_score ?? 0.0} / ${item.cvss_threat_score ?? 0.0} / ${item.cvss_environmental_score ?? 0.0}\n`;
          markdown += `- **Vector String**: \`${item.cvss_vector || "-"}\`\n`;
          markdown += `- **Deskripsi**: ${item.description || "-"}\n`;
          markdown += `- **Bukti (Evidence)**: ${item.evidence || "-"}\n`;
          markdown += `- **Rekomendasi Remediasi**: ${item.solution || "-"}\n\n`;
        });
      }
    });

    markdown += `---
*Laporan ini dihasilkan secara otomatis oleh SMART-SEC Platform menggunakan PostgreSQL Stored Procedure & Trigger BEFORE INSERT untuk perhitungan presisi CVSS v4.0.*
`;

    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SMART-SEC_Executive_Summary_${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="glass-panel rounded-2xl p-6 sm:p-8 border border-slate-800/80 space-y-8 shadow-2xl">
      {/* Header Panel */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 via-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-lg shadow-indigo-500/20">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2 tracking-tight">
                VirusTotal-Style Security Scan Report
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-700/80">
                  Release Edition
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Laporan rekapitulasi transparansi pemindaian massal & evaluasi skor risiko CVSS v4.0 yang dikelompokkan berdasarkan OWASP Top 10:2021.
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons / Download Exec Report */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={exportToJsonReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-slate-200 hover:text-white hover:bg-slate-800 border border-slate-700/80 transition-all shadow-sm active:scale-95"
          >
            <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Unduh JSON Report
          </button>

          <button
            onClick={exportToMarkdownReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white border border-blue-400/30 transition-all shadow-md shadow-blue-600/20 active:scale-95"
          >
            <svg className="w-4 h-4 text-cyan-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Unduh Executive Summary (.MD)
          </button>

          <button
            onClick={() => window.print()}
            className="p-2 rounded-xl text-xs bg-slate-900 text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 transition-all"
            title="Cetak Tampilan / Print PDF"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
            </svg>
          </button>
        </div>
      </div>

      {/* Target & Job Selector Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Target Selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
            <span>Pilih Target URL Audit:</span>
            <span className="text-[11px] text-slate-400 font-normal">
              {targets.length} target terdaftar
            </span>
          </label>
          <select
            value={selectedTargetId}
            onChange={(e) => {
              setSelectedTargetId(e.target.value);
              setSelectedJobId("ALL"); // Reset job selection when target changes
            }}
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="ALL">🌐 [SEMUA TARGET] - Laporan Agregat Platform</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.url} ({t.program_name || "VDP Target"})
              </option>
            ))}
          </select>
        </div>

        {/* Job Selector */}
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
            <span>Pilih Sesi / Job Scan:</span>
            <span className="text-[11px] text-slate-400 font-normal">
              {filteredJobs.length} job ditemukan
            </span>
          </label>
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-950 border border-slate-800 text-slate-100 focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="ALL">⚙ [SEMUA SESI SCAN] - Agregat Job</option>
            {filteredJobs.map((j) => (
              <option key={j.id} value={j.id}>
                Job #{j.id.substring(0, 8)} &middot; {j.status.toUpperCase()} &middot; {new Date(j.created_at).toLocaleString("id-ID")}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Target & Job Summary Card */}
      {activeTarget && (
        <div className="p-4 rounded-xl bg-slate-950/80 border border-blue-900/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-bold text-white font-mono">{activeTarget.url}</h3>
              {activeTarget.is_authorized ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  ✓ AUTHORIZED VDP TARGET
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800">
                  ⚠️ UNAUTHORIZED / PENDING
                </span>
              )}
              {activeTarget.program_name && (
                <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300">
                  {activeTarget.program_name}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Daftar target didaftarkan pada: {new Date(activeTarget.created_at).toLocaleString("id-ID")}
            </p>
          </div>

          {activeJob && (
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-400">Status Sesi Scan:</span>
              {getJobStatusBadge(activeJob.status)}
            </div>
          )}
        </div>
      )}

      {/* VirusTotal Style Security Posture Gauge & CVSS v4.0 Severity Counters */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Overall Health Score / VirusTotal Detection Gauge */}
        <div className="lg:col-span-5 rounded-2xl p-6 bg-slate-950/90 border border-slate-800 flex flex-col items-center justify-center text-center space-y-4 relative overflow-hidden">
          <div className="absolute top-0 right-0 p-3">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
              VirusTotal Style Posture
            </span>
          </div>

          {/* Security Posture Circle Gauge */}
          <div className="relative w-36 h-36 flex items-center justify-center mt-2">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                className="text-slate-800/80"
                fill="transparent"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={251.2}
                strokeDashoffset={251.2 - (251.2 * Math.min(metrics.total, 20)) / 20}
                className={
                  metrics.critical > 0
                    ? "text-rose-500"
                    : metrics.high > 0
                    ? "text-red-500"
                    : metrics.medium > 0
                    ? "text-amber-500"
                    : metrics.total > 0
                    ? "text-blue-500"
                    : "text-emerald-500"
                }
                strokeLinecap="round"
                fill="transparent"
              />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className="text-3xl font-extrabold text-white tracking-tight">
                {metrics.total}
              </span>
              <span className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">
                Temuan Alerts
              </span>
            </div>
          </div>

          <div>
            <span className={`inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-bold border shadow-lg ${metrics.postureBadgeClass} ${metrics.postureGlow}`}>
              <span className="w-2 h-2 rounded-full bg-current"></span>
              {metrics.postureText}
            </span>
            <p className="text-xs text-slate-400 mt-2">
              Skor Risiko Terburuk: <span className="font-bold text-white font-mono">{metrics.maxCompositeScore.toFixed(1)} / 10.0</span> (CVSS v4.0 Composite)
            </p>
          </div>
        </div>

        {/* Right: CVSS v4.0 Severity Distribution Cards */}
        <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-3.5">
          {/* Critical Card */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-rose-900/50 flex flex-col justify-between space-y-2 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-rose-400">Critical</span>
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
            </div>
            <div className="text-3xl font-extrabold text-rose-300 font-mono">
              {metrics.critical}
            </div>
            <div className="text-[10px] text-rose-400/70 font-mono">
              CVSS 9.0 - 10.0
            </div>
          </div>

          {/* High Card */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-red-900/50 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-red-400">High</span>
              <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
            </div>
            <div className="text-3xl font-extrabold text-red-300 font-mono">
              {metrics.high}
            </div>
            <div className="text-[10px] text-red-400/70 font-mono">
              CVSS 7.0 - 8.9
            </div>
          </div>

          {/* Medium Card */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-amber-900/50 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-amber-400">Medium</span>
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            </div>
            <div className="text-3xl font-extrabold text-amber-300 font-mono">
              {metrics.medium}
            </div>
            <div className="text-[10px] text-amber-400/70 font-mono">
              CVSS 4.0 - 6.9
            </div>
          </div>

          {/* Low Card */}
          <div className="p-4 rounded-xl bg-slate-950/80 border border-emerald-900/50 flex flex-col justify-between space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-400">Low</span>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
            </div>
            <div className="text-3xl font-extrabold text-emerald-300 font-mono">
              {metrics.low}
            </div>
            <div className="text-[10px] text-emerald-400/70 font-mono">
              CVSS 0.1 - 3.9
            </div>
          </div>
        </div>
      </div>

      {/* Search Bar for Findings */}
      <div className="relative">
        <input
          type="text"
          placeholder="Cari temuan berdasarkan judul, OWASP category, CWE-ID, atau CVSS vector string..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 text-xs rounded-xl bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-medium"
        />
        <svg className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      </div>

      {/* OWASP Top 10:2021 Grouped Findings List */}
      <div className="space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            Temuan Kerentanan Dikelompokkan Berdasarkan OWASP Top 10:2021
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            {relevantFindings.length} Total Temuan Terfilter
          </span>
        </div>

        {Array.from(findingsByOwasp.entries()).map(([catKey, items]) => {
          // If no items in this category and searchQuery is active, skip empty ones
          if (items.length === 0 && searchQuery) return null;

          const owaspRef = OWASP_TOP_10_2021.find((o) => o.id === catKey);

          return (
            <div
              key={catKey}
              className={`rounded-2xl border ${
                items.length > 0
                  ? "border-slate-800 bg-slate-950/60"
                  : "border-slate-900/60 bg-slate-950/20 opacity-60"
              } overflow-hidden transition-all`}
            >
              {/* Category Header */}
              <div className="p-4 bg-slate-900/60 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-blue-400"></span>
                    {owaspRef ? owaspRef.name : catKey}
                  </h4>
                  {owaspRef && (
                    <p className="text-[11px] text-slate-400 mt-0.5">{owaspRef.desc}</p>
                  )}
                </div>

                <div className="flex items-center gap-2 self-start sm:self-auto">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold font-mono ${
                      items.length > 0
                        ? "bg-blue-950 text-blue-300 border border-blue-800"
                        : "bg-slate-900 text-slate-500 border border-slate-800"
                    }`}
                  >
                    {items.length} Temuan
                  </span>
                </div>
              </div>

              {/* Items List */}
              {items.length > 0 ? (
                <div className="divide-y divide-slate-800/60">
                  {items.map((item) => {
                    const isExpanded = expandedFindingId === item.id;
                    const sev = (item.cvss_severity || "None").toUpperCase();

                    return (
                      <div key={item.id} className="p-4 hover:bg-slate-900/40 transition-colors">
                        <div
                          onClick={() => setExpandedFindingId(isExpanded ? null : item.id)}
                          className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer"
                        >
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-bold text-sm text-slate-100">{item.name}</span>
                              {item.cwe_id && (
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                                  CWE-{item.cwe_id}
                                </span>
                              )}
                              {item.risk_zap && (
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800">
                                  ZAP Risk: {item.risk_zap}
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-slate-400 line-clamp-1">
                              {item.description || "Tidak ada deskripsi rinci."}
                            </p>
                          </div>

                          <div className="flex items-center gap-3 self-end sm:self-auto">
                            {/* CVSS Badge */}
                            <span
                              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border font-mono ${
                                sev === "CRITICAL"
                                  ? "bg-rose-950 text-rose-300 border-rose-700 glow-red"
                                  : sev === "HIGH"
                                  ? "bg-red-950 text-red-300 border-red-700"
                                  : sev === "MEDIUM"
                                  ? "bg-amber-950 text-amber-300 border-amber-700"
                                  : sev === "LOW"
                                  ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                                  : "bg-slate-800 text-slate-400 border-slate-700"
                              }`}
                            >
                              <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
                              {sev} &middot; {item.cvss_composite_score ? item.cvss_composite_score.toFixed(1) : "0.0"}
                            </span>

                            <svg
                              className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                            </svg>
                          </div>
                        </div>

                        {/* Expanded Details */}
                        {isExpanded && (
                          <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-4 text-xs">
                            {/* CVSS v4.0 Scores Breakdown */}
                            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                              <h5 className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                                Rincian Perhitungan CVSS v4.0 In-Database (PostgreSQL Stored Procedure)
                              </h5>
                              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                                <div className="bg-slate-900/80 p-2.5 rounded-lg text-center border border-slate-800">
                                  <p className="text-[10px] text-slate-400">Base Score</p>
                                  <p className="text-base font-bold text-white font-mono mt-0.5">
                                    {item.cvss_base_score ?? "0.0"}
                                  </p>
                                </div>
                                <div className="bg-slate-900/80 p-2.5 rounded-lg text-center border border-slate-800">
                                  <p className="text-[10px] text-slate-400">Threat Score</p>
                                  <p className="text-base font-bold text-white font-mono mt-0.5">
                                    {item.cvss_threat_score ?? "0.0"}
                                  </p>
                                </div>
                                <div className="bg-slate-900/80 p-2.5 rounded-lg text-center border border-slate-800">
                                  <p className="text-[10px] text-slate-400">Environmental Score</p>
                                  <p className="text-base font-bold text-white font-mono mt-0.5">
                                    {item.cvss_environmental_score ?? "0.0"}
                                  </p>
                                </div>
                                <div className="bg-slate-900/80 p-2.5 rounded-lg text-center border border-slate-800">
                                  <p className="text-[10px] text-rose-400">Composite Score</p>
                                  <p className="text-base font-bold text-rose-400 font-mono mt-0.5">
                                    {item.cvss_composite_score ?? "0.0"}
                                  </p>
                                </div>
                              </div>
                            </div>

                            {/* Vector String */}
                            {item.cvss_vector && (
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] font-semibold text-slate-400">CVSS v4.0 Vector String:</span>
                                  <button
                                    onClick={() => copyVector(item.id, item.cvss_vector!)}
                                    className="text-[11px] text-blue-400 hover:text-blue-300 font-medium"
                                  >
                                    {copiedVectorId === item.id ? "✓ Copied!" : "Copy Vector"}
                                  </button>
                                </div>
                                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 break-all select-all">
                                  {item.cvss_vector}
                                </div>
                              </div>
                            )}

                            {/* Evidence & Solution */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              {item.evidence && (
                                <div>
                                  <span className="text-[11px] font-semibold text-slate-400 block mb-1">Bukti Kerentanan (Evidence):</span>
                                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-amber-300/90 whitespace-pre-wrap break-all max-h-36 overflow-y-auto">
                                    {item.evidence}
                                  </pre>
                                </div>
                              )}
                              {item.solution && (
                                <div>
                                  <span className="text-[11px] font-semibold text-slate-400 block mb-1">Rekomendasi Remediasi:</span>
                                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-emerald-300/90 leading-relaxed">
                                    {item.solution}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-4 text-center text-xs text-slate-500 italic">
                  Tidak ada temuan terdeteksi untuk kategori ini.
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
