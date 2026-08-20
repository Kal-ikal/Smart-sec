import { createSupabaseServerClient } from "@/lib/supabase/server";
import StatsOverview from "./StatsOverview";
import TargetManager from "./TargetManager";
import RealtimeJobs from "./RealtimeJobs";
import RealtimeFindings from "./RealtimeFindings";

export const dynamic = "force-dynamic";

/**
 * Server Component: Mengambil data awal (targets, jobs, findings)
 * lewat sesi pengguna yang login -- tunduk RLS "owner_id = auth.uid()".
 * Pembaruan data dinamis ditangani secara realtime oleh Client Components
 * melalui Supabase Realtime WebSocket channel.
 */
export default async function DashboardPage() {
  const supabase = createSupabaseServerClient();

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
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                SMART-SEC
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-blue-950 text-blue-300 border border-blue-800">
                  CVSS v4.0 Engine
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Automated Mass-Vulnerability Assessment & Shift-Computation Platform
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 live-pulse"></span>
              <span>PostgreSQL Stored Procedure Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Dashboard */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8 space-y-8">
        {/* Executive Stats Cards */}
        <StatsOverview targets={targets} jobs={jobs} findings={findings} />

        {/* Target Management & Scan Queue Trigger */}
        <TargetManager initialTargets={targets} />

        {/* Grid for Active Queue & Realtime Findings */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-1">
            <RealtimeJobs initialJobs={jobs} />
          </div>
          <div className="lg:col-span-2">
            <RealtimeFindings initialFindings={findings} />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/60 py-4 px-6 text-center text-xs text-slate-500">
        SMART-SEC &middot; In-Database CVSS v4.0 Risk Calculation &middot; Decoupled Architecture
      </footer>
    </div>
  );
}
