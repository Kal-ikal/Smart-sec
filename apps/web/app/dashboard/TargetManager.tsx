"use client";

import { useState } from "react";
import type { Database } from "@/types/database";

type ScanTarget = Database["public"]["Tables"]["scan_targets"]["Row"];

interface TargetManagerProps {
  initialTargets: ScanTarget[];
  onScanTriggered?: () => void;
}

export default function TargetManager({ initialTargets, onScanTriggered }: TargetManagerProps) {
  const [targets, setTargets] = useState<ScanTarget[]>(initialTargets);
  const [isAdding, setIsAdding] = useState(false);
  const [url, setUrl] = useState("");
  const [programName, setProgramName] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [loading, setLoading] = useState(false);
  const [triggeringJobId, setTriggeringJobId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setStatusMessage(null);

    try {
      const res = await fetch("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.trim(),
          program_name: programName.trim() || null,
          is_authorized: isAuthorized,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Gagal menambahkan target");
      }

      setTargets((prev) => [data.target, ...prev]);
      setUrl("");
      setProgramName("");
      setIsAdding(false);
      setStatusMessage({ text: `Target ${data.target.url} berhasil didaftarkan!`, type: "success" });
    } catch (err) {
      setStatusMessage({
        text: err instanceof Error ? err.message : "Terjadi kesalahan",
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerScan = async (targetId: string, targetUrl: string) => {
    setTriggeringJobId(targetId);
    setStatusMessage(null);

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: targetId }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Gagal memicu pemindaian");
      }

      setStatusMessage({
        text: `Pemindaian untuk ${targetUrl} berhasil dimasukkan ke antrean (Job ID: ${data.job?.id?.slice(0, 8)}...)`,
        type: "success",
      });

      if (onScanTriggered) {
        onScanTriggered();
      }
    } catch (err) {
      setStatusMessage({
        text: err instanceof Error ? err.message : "Gagal memicu scan",
        type: "error",
      });
    } finally {
      setTriggeringJobId(null);
    }
  };

  return (
    <div className="glass-panel rounded-xl p-6 border-slate-800/80">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
            Target VDP / Ruang Lingkup Audit
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Kelola URL target yang sah (Authorized VDP/Sandbox) sebelum diikutkan dalam pemindaian massal.
          </p>
        </div>

        <button
          onClick={() => setIsAdding(!isAdding)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors shadow-sm"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d={isAdding ? "M6 18L18 6M6 6l12 12" : "M12 4v16m8-8H4"} />
          </svg>
          {isAdding ? "Batal" : "Tambah Target Baru"}
        </button>
      </div>

      {statusMessage && (
        <div
          className={`p-3 rounded-lg text-xs mb-4 flex items-center justify-between ${
            statusMessage.type === "success"
              ? "bg-emerald-950/70 text-emerald-300 border border-emerald-800/80"
              : "bg-rose-950/70 text-rose-300 border border-rose-800/80"
          }`}
        >
          <span>{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-white ml-2">
            &times;
          </button>
        </div>
      )}

      {isAdding && (
        <form onSubmit={handleAddTarget} className="p-4 rounded-lg bg-slate-900/90 border border-slate-700/60 mb-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                URL Target <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                placeholder="https://vdp-target.internal"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full px-3 py-2 text-xs rounded-md bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Nama Program VDP / Platform
              </label>
              <input
                type="text"
                placeholder="Sandbox VDP 2026"
                value={programName}
                onChange={(e) => setProgramName(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-md bg-slate-950 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="is_authorized"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              className="rounded border-slate-700 bg-slate-950 text-blue-600 focus:ring-0 w-4 h-4 cursor-pointer"
            />
            <label htmlFor="is_authorized" className="text-xs text-slate-300 cursor-pointer">
              Konfirmasi Otorisasi (Target resmi mematuhi UU ITE / Scope VDP)
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setIsAdding(false)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
            >
              Batal
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors"
            >
              {loading ? "Menyimpan..." : "Daftarkan Target"}
            </button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Target URL</th>
              <th className="py-2.5 px-3">Program VDP</th>
              <th className="py-2.5 px-3">Status Kepatuhan</th>
              <th className="py-2.5 px-3 text-right">Aksi Pemindaian</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {targets.map((t) => (
              <tr key={t.id} className="hover:bg-slate-900/40 transition-colors">
                <td className="py-3 px-3 font-mono text-slate-200">{t.url}</td>
                <td className="py-3 px-3 text-slate-400">{t.program_name || "General Scope"}</td>
                <td className="py-3 px-3">
                  <span
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium ${
                      t.is_authorized
                        ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/80"
                        : "bg-amber-950/80 text-amber-400 border border-amber-800/80"
                    }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${t.is_authorized ? "bg-emerald-400" : "bg-amber-400"}`}></span>
                    {t.is_authorized ? "Authorized (Sah)" : "Menunggu Verifikasi"}
                  </span>
                </td>
                <td className="py-3 px-3 text-right">
                  <button
                    onClick={() => handleTriggerScan(t.id, t.url)}
                    disabled={!t.is_authorized || triggeringJobId === t.id}
                    title={!t.is_authorized ? "Target belum berstatus Authorized" : "Picu pemindaian massal ZAP"}
                    className={`inline-flex items-center gap-1 px-3 py-1 rounded-md text-xs font-medium transition-all ${
                      t.is_authorized
                        ? "bg-blue-600/90 text-white hover:bg-blue-500 disabled:opacity-50"
                        : "bg-slate-800 text-slate-500 cursor-not-allowed"
                    }`}
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {triggeringJobId === t.id ? "Enqueuing..." : "Scan Target"}
                  </button>
                </td>
              </tr>
            ))}
            {!targets.length && (
              <tr>
                <td colSpan={4} className="py-6 text-center text-slate-500 text-xs">
                  Belum ada target VDP yang didaftarkan. Klik tombol di atas untuk menambahkan URL target.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
