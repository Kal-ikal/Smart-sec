"use client";

import type { Database } from "@/types/database";

type Finding = Database["public"]["Tables"]["findings"]["Row"];
type ScanJob = Database["public"]["Tables"]["scan_jobs"]["Row"];
type ScanTarget = Database["public"]["Tables"]["scan_targets"]["Row"];

interface StatsOverviewProps {
  targets: ScanTarget[];
  jobs: ScanJob[];
  findings: Finding[];
}

export default function StatsOverview({ targets, jobs, findings }: StatsOverviewProps) {
  const criticalCount = findings.filter((f) => f.cvss_severity === "Critical").length;
  const highCount = findings.filter((f) => f.cvss_severity === "High").length;
  const mediumCount = findings.filter((f) => f.cvss_severity === "Medium").length;
  const activeJobsCount = jobs.filter((j) => j.status === "running" || j.status === "claimed" || j.status === "queued").length;

  const validScores = findings
    .map((f) => f.cvss_composite_score)
    .filter((s): s is number => typeof s === "number");
  const avgScore = validScores.length
    ? (validScores.reduce((a, b) => a + b, 0) / validScores.length).toFixed(1)
    : "0.0";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Total Targets Card */}
      <div className="glass-panel p-5 rounded-xl flex items-center justify-between border-slate-800/80">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Target VDP Terdaftar</p>
          <p className="text-2xl font-bold text-white mt-1">{targets.length}</p>
          <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            {targets.filter((t) => t.is_authorized).length} Sah / Authorized
          </p>
        </div>
        <div className="w-11 h-11 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
        </div>
      </div>

      {/* Active Jobs Card */}
      <div className="glass-panel p-5 rounded-xl flex items-center justify-between border-slate-800/80">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Status Antrean Scan</p>
          <p className="text-2xl font-bold text-white mt-1">{activeJobsCount}</p>
          <p className="text-xs text-cyan-400 mt-1 flex items-center gap-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400 live-pulse"></span>
            {jobs.filter((j) => j.status === "running").length} Sedang Memindai
          </p>
        </div>
        <div className="w-11 h-11 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
      </div>

      {/* Critical & High Findings Card */}
      <div className="glass-panel p-5 rounded-xl flex items-center justify-between border-slate-800/80">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Critical & High Risk</p>
          <p className="text-2xl font-bold text-rose-400 mt-1">{criticalCount + highCount}</p>
          <p className="text-xs text-slate-400 mt-1">
            {criticalCount} Critical &middot; {highCount} High &middot; {mediumCount} Medium
          </p>
        </div>
        <div className="w-11 h-11 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 glow-red">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
      </div>

      {/* Mean CVSS Score Card */}
      <div className="glass-panel p-5 rounded-xl flex items-center justify-between border-slate-800/80">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Rata-rata Skor CVSS v4.0</p>
          <p className="text-2xl font-bold text-amber-400 mt-1">{avgScore}</p>
          <p className="text-xs text-slate-400 mt-1">
            Dari {findings.length} total temuan kerentanan
          </p>
        </div>
        <div className="w-11 h-11 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 glow-amber">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
        </div>
      </div>
    </div>
  );
}
