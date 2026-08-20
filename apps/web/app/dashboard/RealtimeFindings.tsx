"use client";

import { useEffect, useState, useMemo } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Database } from "@/types/database";

type Finding = Database["public"]["Tables"]["findings"]["Row"];

interface RealtimeFindingsProps {
  initialFindings?: Finding[];
}

export default function RealtimeFindings({ initialFindings = [] }: RealtimeFindingsProps) {
  const [findings, setFindings] = useState<Finding[]>(initialFindings);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [copiedVectorId, setCopiedVectorId] = useState<string | null>(null);

  useEffect(() => {
    const supabase = createSupabaseBrowserClient();

    const channel = supabase
      .channel("findings-live-feed")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "findings" },
        (payload) => {
          const newFinding = payload.new as Finding;
          setFindings((prev) => [newFinding, ...prev]);
        }
      )
      .on(
        "postgres_changes",
        { event: "UPDATE", schema: "public", table: "findings" },
        (payload) => {
          const updated = payload.new as Finding;
          setFindings((prev) =>
            prev.map((f) => (f.id === updated.id ? updated : f))
          );
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchSeverity =
        filterSeverity === "ALL" ||
        (f.cvss_severity && f.cvss_severity.toUpperCase() === filterSeverity);

      const query = searchQuery.toLowerCase();
      const matchSearch =
        !searchQuery ||
        f.name.toLowerCase().includes(query) ||
        (f.owasp_category && f.owasp_category.toLowerCase().includes(query)) ||
        (f.description && f.description.toLowerCase().includes(query)) ||
        (f.cwe_id && `cwe-${f.cwe_id}`.includes(query));

      return matchSeverity && matchSearch;
    });
  }, [findings, filterSeverity, searchQuery]);

  const copyVector = (id: string, vector: string) => {
    navigator.clipboard.writeText(vector);
    setCopiedVectorId(id);
    setTimeout(() => setCopiedVectorId(null), 2000);
  };

  const getSeverityBadge = (severity: string | null, score: number | null) => {
    const sev = severity ?? "None";
    const scoreText = score !== null ? score.toFixed(1) : "…";

    switch (sev) {
      case "Critical":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-950/90 text-rose-300 border border-rose-700/80 glow-red">
            <span className="w-2 h-2 rounded-full bg-rose-400"></span>
            CRITICAL &middot; {scoreText}
          </span>
        );
      case "High":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-950/90 text-red-300 border border-red-700/80">
            <span className="w-2 h-2 rounded-full bg-red-400"></span>
            HIGH &middot; {scoreText}
          </span>
        );
      case "Medium":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-950/90 text-amber-300 border border-amber-700/80">
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            MEDIUM &middot; {scoreText}
          </span>
        );
      case "Low":
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950/90 text-emerald-300 border border-emerald-700/80">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            LOW &middot; {scoreText}
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <span className="w-2 h-2 rounded-full bg-slate-500"></span>
            NONE &middot; {scoreText}
          </span>
        );
    }
  };

  return (
    <div className="glass-panel rounded-xl p-6 border-slate-800/80 space-y-5">
      {/* Header & Live Subscription Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Temuan Kerentanan Realtime & Risk Scoring CVSS v4.0
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Dihitung 100% otomatis di lapisan basis data (Stored Procedure PL/pgSQL) saat worker memasukkan raw findings.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 text-xs font-medium self-start sm:self-auto">
          <span className="w-2 h-2 rounded-full bg-emerald-400 live-pulse"></span>
          Supabase Realtime Active
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 pt-1">
        <div className="flex-1 relative">
          <input
            type="text"
            placeholder="Cari kerentanan, OWASP category, CWE-ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950/80 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <svg className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterSeverity === sev
                  ? "bg-blue-600 text-white shadow-sm"
                  : "bg-slate-900/80 text-slate-400 hover:text-white hover:bg-slate-800"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.map((f) => {
          const isExpanded = expandedFindingId === f.id;

          return (
            <div
              key={f.id}
              className="rounded-xl border border-slate-800/80 bg-slate-950/60 overflow-hidden transition-all hover:border-slate-700/80"
            >
              <div
                onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-900/30 transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-sm text-white">{f.name}</span>
                    {f.owasp_category && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/80 text-blue-300 border border-blue-800/60">
                        {f.owasp_category}
                      </span>
                    )}
                    {f.cwe_id && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        CWE-{f.cwe_id}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1">
                    {f.description || "Tidak ada deskripsi rinci dari scanner."}
                  </p>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-auto">
                  {getSeverityBadge(f.cvss_severity, f.cvss_composite_score)}
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

              {/* Expanded Detail Panel */}
              {isExpanded && (
                <div className="p-4 border-t border-slate-800/80 bg-slate-900/40 space-y-4 text-xs">
                  {/* Score Breakdown Grid */}
                  <div>
                    <h4 className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 mb-2">
                      Rincian Skor CVSS v4.0 (Shift-Computation / PostgreSQL Computed)
                    </h4>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
                        <p className="text-[10px] text-slate-400">Base Score</p>
                        <p className="text-lg font-bold text-white mt-0.5">{f.cvss_base_score ?? "0.0"}</p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
                        <p className="text-[10px] text-slate-400">Threat Score</p>
                        <p className="text-lg font-bold text-white mt-0.5">{f.cvss_threat_score ?? "0.0"}</p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
                        <p className="text-[10px] text-slate-400">Environmental Score</p>
                        <p className="text-lg font-bold text-white mt-0.5">{f.cvss_environmental_score ?? "0.0"}</p>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
                        <p className="text-[10px] text-rose-400">Final Composite</p>
                        <p className="text-lg font-bold text-rose-400 mt-0.5">{f.cvss_composite_score ?? "0.0"}</p>
                      </div>
                    </div>
                  </div>

                  {/* CVSS Vector String */}
                  {f.cvss_vector && (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] font-medium text-slate-400">CVSS v4.0 Vector String:</span>
                        <button
                          onClick={() => copyVector(f.id, f.cvss_vector!)}
                          className="text-[10px] text-blue-400 hover:text-blue-300 font-medium"
                        >
                          {copiedVectorId === f.id ? "✓ Copied!" : "Copy Vector"}
                        </button>
                      </div>
                      <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 break-all select-all">
                        {f.cvss_vector}
                      </div>
                    </div>
                  )}

                  {/* Evidence & Solution */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {f.evidence && (
                      <div>
                        <span className="text-[11px] font-medium text-slate-400 block mb-1">Bukti Kerentanan (Evidence):</span>
                        <pre className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-amber-300/90 whitespace-pre-wrap break-all overflow-x-auto max-h-32">
                          {f.evidence}
                        </pre>
                      </div>
                    )}
                    {f.solution && (
                      <div>
                        <span className="text-[11px] font-medium text-slate-400 block mb-1">Rekomendasi Remediasi:</span>
                        <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-emerald-300/90 text-xs">
                          {f.solution}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {!filteredFindings.length && (
          <div className="py-12 text-center rounded-xl border border-dashed border-slate-800 bg-slate-950/30">
            <svg className="w-10 h-10 text-slate-600 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-sm font-medium text-slate-400">Belum ada temuan kerentanan</p>
            <p className="text-xs text-slate-500 mt-1">
              Saat worker selesai memindai target, temuan baru akan muncul di sini secara realtime tanpa refresh.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
