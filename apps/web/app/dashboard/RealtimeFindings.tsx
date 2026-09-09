"use client";

import { useEffect, useState, useMemo } from "react";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Database } from "@/types/database";

type Finding = Database["public"]["Tables"]["findings"]["Row"];

interface RealtimeFindingsProps {
  initialFindings?: Finding[];
}

interface FindingGroup {
  key: string;
  name: string;
  owaspCategory: string | null;
  cweId: number | null;
  items: Finding[];
  worst: Finding;
}

const PAGE_SIZE = 20;

const SEVERITY_RANK: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  None: 0,
};

function severityBadgeClasses(sev: string) {
  switch (sev) {
    case "Critical":
      return "bg-rose-950/90 text-rose-300 border-rose-700/80 glow-red";
    case "High":
      return "bg-red-950/90 text-red-300 border-red-700/80";
    case "Medium":
      return "bg-amber-950/90 text-amber-300 border-amber-700/80";
    case "Low":
      return "bg-emerald-950/90 text-emerald-300 border-emerald-700/80";
    default:
      return "bg-slate-800 text-slate-400 border-slate-700";
  }
}

function severityDotClasses(sev: string) {
  switch (sev) {
    case "Critical":
      return "bg-rose-400";
    case "High":
      return "bg-red-400";
    case "Medium":
      return "bg-amber-400";
    case "Low":
      return "bg-emerald-400";
    default:
      return "bg-slate-500";
  }
}

function SeverityBadge({ severity, score }: { severity: string | null; score: number | null }) {
  const sev = severity ?? "None";
  const scoreText = score !== null ? score.toFixed(1) : "…";
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border transition-colors ${severityBadgeClasses(sev)}`}
    >
      <span className={`w-2 h-2 rounded-full ${severityDotClasses(sev)}`}></span>
      {sev.toUpperCase()} &middot; {scoreText}
    </span>
  );
}

/** Panel detail CVSS lengkap + form penilaian kontekstual untuk satu instance finding. */
function FindingDetail({ finding }: { finding: Finding }) {
  const [assessmentE, setAssessmentE] = useState("X");
  const [assessmentCR, setAssessmentCR] = useState("X");
  const [assessmentIR, setAssessmentIR] = useState("X");
  const [assessmentAR, setAssessmentAR] = useState("X");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async () => {
    setSubmitting(true);
    setMessage(null);

    const overrides: Record<string, string> = {};
    if (assessmentE !== "X") overrides.E = assessmentE;
    if (assessmentCR !== "X") overrides.CR = assessmentCR;
    if (assessmentIR !== "X") overrides.IR = assessmentIR;
    if (assessmentAR !== "X") overrides.AR = assessmentAR;

    const supabase = createSupabaseBrowserClient();
    const { error } = await supabase.rpc("submit_cvss_assessment", {
      p_finding_id: finding.id,
      p_overrides: overrides,
    });

    setSubmitting(false);
    setMessage(error ? `Gagal: ${error.message}` : "Penilaian tersimpan, skor dihitung ulang otomatis oleh trigger database.");
  };

  const copyVector = () => {
    if (!finding.cvss_vector) return;
    navigator.clipboard.writeText(finding.cvss_vector);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-4 border-t border-slate-800/80 bg-slate-900/40 space-y-4 text-xs">
      <div>
        <h4 className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 mb-2">
          Rincian Skor CVSS v4.0 (Shift-Computation / PostgreSQL Computed)
        </h4>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
            <p className="text-[10px] text-slate-400">Base Score</p>
            <p className="text-lg font-bold text-white mt-0.5">{finding.cvss_base_score ?? "0.0"}</p>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
            <p className="text-[10px] text-slate-400">Threat Score</p>
            <p className="text-lg font-bold text-white mt-0.5">{finding.cvss_threat_score ?? "0.0"}</p>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
            <p className="text-[10px] text-slate-400">Environmental Score</p>
            <p className="text-lg font-bold text-white mt-0.5">{finding.cvss_environmental_score ?? "0.0"}</p>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
            <p className="text-[10px] text-rose-400">Final Composite</p>
            <p className="text-lg font-bold text-rose-400 mt-0.5">{finding.cvss_composite_score ?? "0.0"}</p>
          </div>
        </div>
      </div>

      <div>
        <h4 className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 mb-2">
          Penilaian Kontekstual (Threat &amp; Environmental Metrics)
        </h4>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <div>
            <label className="block text-[10px] text-slate-500 mb-1">Exploit Maturity (E)</label>
            <select
              value={assessmentE}
              onChange={(e) => setAssessmentE(e.target.value)}
              className="w-full px-2 py-1.5 text-[11px] rounded-lg bg-slate-950 border border-slate-800 text-white"
            >
              <option value="X">Tidak dinilai (X)</option>
              <option value="A">Attacked (A)</option>
              <option value="P">Proof-of-Concept (P)</option>
              <option value="U">Unreported (U)</option>
            </select>
          </div>
          {[
            { label: "Confidentiality Req. (CR)", value: assessmentCR, setValue: setAssessmentCR },
            { label: "Integrity Req. (IR)", value: assessmentIR, setValue: setAssessmentIR },
            { label: "Availability Req. (AR)", value: assessmentAR, setValue: setAssessmentAR },
          ].map((field) => (
            <div key={field.label}>
              <label className="block text-[10px] text-slate-500 mb-1">{field.label}</label>
              <select
                value={field.value}
                onChange={(e) => field.setValue(e.target.value)}
                className="w-full px-2 py-1.5 text-[11px] rounded-lg bg-slate-950 border border-slate-800 text-white"
              >
                <option value="X">Tidak dinilai (X)</option>
                <option value="H">High (H)</option>
                <option value="M">Medium (M)</option>
                <option value="L">Low (L)</option>
              </select>
            </div>
          ))}
        </div>
        <div className="flex items-center justify-between mt-2">
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="px-3 py-1.5 text-[11px] font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors active:scale-95"
          >
            {submitting ? "Menyimpan..." : "Terapkan Penilaian"}
          </button>
          {message && <span className="text-[11px] text-slate-400">{message}</span>}
        </div>
      </div>

      {finding.cvss_vector && (
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] font-medium text-slate-400">CVSS v4.0 Vector String:</span>
            <button onClick={copyVector} className="text-[10px] text-blue-400 hover:text-blue-300 font-medium">
              {copied ? "✓ Copied!" : "Copy Vector"}
            </button>
          </div>
          <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 break-all select-all">
            {finding.cvss_vector}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {finding.evidence && (
          <div>
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Bukti Kerentanan (Evidence):</span>
            <pre className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] text-amber-300/90 whitespace-pre-wrap break-all overflow-x-auto max-h-32">
              {finding.evidence}
            </pre>
          </div>
        )}
        {finding.solution && (
          <div>
            <span className="text-[11px] font-medium text-slate-400 block mb-1">Rekomendasi Remediasi:</span>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-emerald-300/90 text-xs">
              {finding.solution}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/** Satu instance di dalam grup (baris ringkas + expand ke detail penuh). */
function InstanceRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-950/40 overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full p-3 flex items-center justify-between gap-3 text-left hover:bg-slate-900/40 transition-colors"
      >
        <span className="text-[11px] text-slate-400 font-mono truncate flex-1">
          {finding.evidence || finding.description || "Tidak ada detail bukti tambahan."}
        </span>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={finding.cvss_severity} score={finding.cvss_composite_score} />
          <svg
            className={`w-3.5 h-3.5 text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      <div className={`expand-region ${open ? "is-open" : ""}`}>
        <div>{open && <FindingDetail finding={finding} />}</div>
      </div>
    </div>
  );
}

export default function RealtimeFindings({ initialFindings = [] }: RealtimeFindingsProps) {
  const [findings, setFindings] = useState<Finding[]>(initialFindings);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedGroupKey, setExpandedGroupKey] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

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
          setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const filteredFindings = useMemo(() => {
    const query = searchQuery.toLowerCase();
    return findings.filter((f) => {
      const matchSeverity =
        filterSeverity === "ALL" || (f.cvss_severity && f.cvss_severity.toUpperCase() === filterSeverity);

      const matchSearch =
        !searchQuery ||
        f.name.toLowerCase().includes(query) ||
        (f.owasp_category && f.owasp_category.toLowerCase().includes(query)) ||
        (f.description && f.description.toLowerCase().includes(query)) ||
        (f.cwe_id && `cwe-${f.cwe_id}`.includes(query));

      return matchSeverity && matchSearch;
    });
  }, [findings, filterSeverity, searchQuery]);

  // Kerentanan yang sama (nama + CWE) sering muncul berkali-kali -- satu per
  // halaman/parameter yang terdampak. Mengelompokkannya jadi satu kartu
  // dengan badge jumlah kejadian membuat daftar tetap terbaca dan ringan
  // dirender meskipun total temuan mentahnya ribuan (bukan cuma kosmetik --
  // ini juga yang membuat panel tetap cepat).
  const groups = useMemo<FindingGroup[]>(() => {
    const map = new Map<string, FindingGroup>();
    for (const f of filteredFindings) {
      const key = `${f.name}__${f.cwe_id ?? "none"}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { key, name: f.name, owaspCategory: f.owasp_category, cweId: f.cwe_id, items: [f], worst: f });
        continue;
      }
      existing.items.push(f);
      const currentRank = SEVERITY_RANK[existing.worst.cvss_severity ?? "None"] ?? 0;
      const candidateRank = SEVERITY_RANK[f.cvss_severity ?? "None"] ?? 0;
      if (
        candidateRank > currentRank ||
        (candidateRank === currentRank && (f.cvss_composite_score ?? 0) > (existing.worst.cvss_composite_score ?? 0))
      ) {
        existing.worst = f;
      }
    }
    return Array.from(map.values()).sort((a, b) => {
      const rankDiff = (SEVERITY_RANK[b.worst.cvss_severity ?? "None"] ?? 0) - (SEVERITY_RANK[a.worst.cvss_severity ?? "None"] ?? 0);
      if (rankDiff !== 0) return rankDiff;
      return (b.worst.cvss_composite_score ?? 0) - (a.worst.cvss_composite_score ?? 0);
    });
  }, [filteredFindings]);

  // Reset paginasi & grup terbuka setiap kali filter/pencarian berubah,
  // supaya tidak menampilkan halaman ke-40 dari hasil filter yang baru.
  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
    setExpandedGroupKey(null);
  }, [filterSeverity, searchQuery]);

  const visibleGroups = groups.slice(0, visibleCount);
  const remaining = groups.length - visibleGroups.length;

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
            {findings.length.toLocaleString("id-ID")} temuan mentah &middot; dikelompokkan jadi {groups.length.toLocaleString("id-ID")} jenis kerentanan unik. Dihitung 100% otomatis di lapisan basis data.
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
            className="w-full pl-9 pr-3 py-2 text-xs rounded-lg bg-slate-950/80 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
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
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all active:scale-95 ${
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

      {/* Grouped Findings List */}
      <div className="space-y-3 stagger-children">
        {visibleGroups.map((g) => {
          const isOpen = expandedGroupKey === g.key;
          return (
            <div
              key={g.key}
              className="animate-in rounded-xl border border-slate-800/80 bg-slate-950/60 overflow-hidden transition-colors hover:border-slate-700/80"
            >
              <div
                onClick={() => setExpandedGroupKey(isOpen ? null : g.key)}
                className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-900/30 transition-colors"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-sm text-white">{g.name}</span>
                    {g.items.length > 1 && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-700/60">
                        × {g.items.length} kejadian
                      </span>
                    )}
                    {g.owaspCategory && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/80 text-blue-300 border border-blue-800/60">
                        {g.owaspCategory}
                      </span>
                    )}
                    {g.cweId && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        CWE-{g.cweId}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1">
                    {g.worst.description || "Tidak ada deskripsi rinci dari scanner."}
                  </p>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-auto shrink-0">
                  <SeverityBadge severity={g.worst.cvss_severity} score={g.worst.cvss_composite_score} />
                  <svg
                    className={`w-4 h-4 text-slate-400 transition-transform ${isOpen ? "rotate-180" : ""}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              <div className={`expand-region ${isOpen ? "is-open" : ""}`}>
                <div>
                  {isOpen && (
                    g.items.length === 1 ? (
                      <FindingDetail finding={g.items[0]} />
                    ) : (
                      <div className="p-4 border-t border-slate-800/80 bg-slate-900/30 space-y-2">
                        <p className="text-[11px] text-slate-400 mb-2">
                          {g.items.length} kejadian terpisah dari kerentanan ini ditemukan. Klik salah satu untuk lihat rincian skor & terapkan penilaian kontekstual per kejadian.
                        </p>
                        <div className="space-y-2 max-h-96 overflow-y-auto pr-1 stagger-children">
                          {g.items.map((item) => (
                            <div key={item.id} className="animate-in">
                              <InstanceRow finding={item} />
                            </div>
                          ))}
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {!visibleGroups.length && (
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

        {remaining > 0 && (
          <button
            onClick={() => setVisibleCount((v) => v + PAGE_SIZE)}
            className="w-full py-2.5 rounded-lg text-xs font-semibold text-slate-300 bg-slate-900/80 border border-slate-800 hover:bg-slate-800 hover:text-white transition-colors active:scale-[0.99]"
          >
            Tampilkan {Math.min(PAGE_SIZE, remaining)} jenis kerentanan lagi ({remaining} tersisa)
          </button>
        )}
      </div>
    </div>
  );
}
