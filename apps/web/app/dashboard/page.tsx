import { createSupabaseAdminClient } from "@/lib/supabase/admin";
import StatsOverview from "./StatsOverview";
import TargetManager from "./TargetManager";
import RealtimeJobs from "./RealtimeJobs";
import RealtimeFindings from "./RealtimeFindings";
import ScanReportView from "./ScanReportView";

export const dynamic = "force-dynamic";

/**
 * Server Component Dashboard SMART-SEC Release Edition.
 * Mengambil data awal (targets, jobs, findings) secara publik (tanpa login),
 * serta menghubungkan komponen realtime WebSocket untuk pembaruan instan.
 */
export default async function DashboardPage() {
  const supabase = createSupabaseAdminClient();

  const [targetsRes, jobsRes, findingsRes] = await Promise.all([
    supabase
      .from("scan_targets")
      .select("*")
      .order("created_at", { ascending: false }),
    supabase
      .from("scan_jobs")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(30),
    supabase
      .from("findings")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(100),
  ]);

  const targets = targetsRes.data ?? [];
  const jobs = jobsRes.data ?? [];
  const findings = findingsRes.data ?? [];

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col selection:bg-blue-600 selection:text-white">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl sticky top-0 z-40 px-6 py-4 shadow-xl">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/25 ring-1 ring-white/20">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-extrabold tracking-tight text-white flex items-center gap-2">
                SMART-SEC
                <span className="text-[10px] uppercase font-bold tracking-wider px-2.5 py-0.5 rounded-full bg-gradient-to-r from-blue-950 to-indigo-950 text-blue-300 border border-blue-700/60 shadow-sm">
                  Release Edition v1.0
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Automated Mass-Vulnerability Assessment & In-Database CVSS v4.0 Shift-Computation Engine
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-end sm:self-auto">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400 live-pulse"></span>
              <span>Public Scanning Utility</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Cockpit */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-8">
        {/* Ringkasan Posture Keamanan (Executive Stats) */}
        <StatsOverview targets={targets} jobs={jobs} findings={findings} />

        {/* Manajemen Target VDP & Enqueue Scan (Input Validated) */}
        <TargetManager initialTargets={targets} />

        {/* Grid Antrean Realtime & Stream Temuan Kerentanan */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-1">
            <RealtimeJobs initialJobs={jobs} />
          </div>
          <div className="lg:col-span-2">
            <RealtimeFindings initialFindings={findings} />
          </div>
        </div>

        {/* VirusTotal-Style Security Scan Report View (Release Edition) */}
        <ScanReportView targets={targets} jobs={jobs} findings={findings} />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/60 py-5 px-6 text-center text-xs text-slate-500">
        SMART-SEC Platform &middot; Formulasi Skor Risiko CVSS v4.0 PL/pgSQL &middot; Release Edition
      </footer>
    </div>
  );
}
