"use client";

import { useEffect, useState } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Database } from "@/types/database";

type ScanJob = Database["public"]["Tables"]["scan_jobs"]["Row"];

interface RealtimeJobsProps {
  initialJobs: ScanJob[];
}

export default function RealtimeJobs({ initialJobs }: RealtimeJobsProps) {
  const [jobs, setJobs] = useState<ScanJob[]>(initialJobs);

  useEffect(() => {
    const supabase = createSupabaseBrowserClient();

    const channel = supabase
      .channel("scan-jobs-live")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "scan_jobs" },
        (payload) => {
          if (payload.eventType === "INSERT") {
            setJobs((prev) => [payload.new as ScanJob, ...prev].slice(0, 30));
          } else if (payload.eventType === "UPDATE") {
            const updated = payload.new as ScanJob;
            setJobs((prev) =>
              prev.map((j) => (j.id === updated.id ? updated : j))
            );
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const getStatusBadge = (status: ScanJob["status"]) => {
    switch (status) {
      case "queued":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            Queued
          </span>
        );
      case "claimed":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-indigo-950 text-indigo-300 border border-indigo-800">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
            Claimed by Worker
          </span>
        );
      case "running":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-cyan-950 text-cyan-300 border border-cyan-800 glow-emerald">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 live-pulse"></span>
            Scanning (Running)
          </span>
        );
      case "completed":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-950 text-emerald-300 border border-emerald-800">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Completed
          </span>
        );
      case "failed":
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-rose-950 text-rose-300 border border-rose-800">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
            Failed
          </span>
        );
    }
  };

  return (
    <div className="glass-panel rounded-xl p-6 border-slate-800/80">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            Antrean Pemindaian Massal (Asynchronous Queue)
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Dikelola secara atomik lewat <code className="text-cyan-300">FOR UPDATE SKIP LOCKED</code> oleh External Worker instance.
          </p>
        </div>
        <span className="text-[11px] text-slate-400 flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400 live-pulse"></span>
          Realtime Queue
        </span>
      </div>

      <div className="divide-y divide-slate-800/60 rounded-lg border border-slate-800/80 bg-slate-950/50 overflow-hidden">
        {jobs.map((j) => (
          <div key={j.id} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/40 transition-colors">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-slate-300 font-medium">
                  {j.id.slice(0, 13)}...
                </span>
                {getStatusBadge(j.status)}
              </div>
              <p className="text-[11px] text-slate-400">
                Target ID: <span className="font-mono text-slate-300">{j.target_id.slice(0, 8)}...</span>
                {j.claimed_by && (
                  <> &middot; Diproses oleh: <span className="text-slate-300 font-mono">{j.claimed_by}</span></>
                )}
              </p>
              {j.error_message && (
                <p className="text-[11px] text-rose-400 bg-rose-950/40 p-1.5 rounded border border-rose-900/50 mt-1">
                  Error: {j.error_message}
                </p>
              )}
            </div>

            <div className="text-right text-[11px] text-slate-400">
              <p>{new Date(j.created_at).toLocaleTimeString()}</p>
              {j.finished_at && (
                <p className="text-slate-400">Selesai: {new Date(j.finished_at).toLocaleTimeString()}</p>
              )}
            </div>
          </div>
        ))}

        {!jobs.length && (
          <div className="p-6 text-center text-xs text-slate-500">
            Antrean kosong. Klik &quot;Scan Target&quot; pada tabel target untuk memulai pemindaian.
          </div>
        )}
      </div>
    </div>
  );
}
