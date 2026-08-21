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
  const [urlInput, setUrlInput] = useState("");
  const [programNameInput, setProgramNameInput] = useState("");
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [loading, setLoading] = useState(false);
  const [triggeringJobId, setTriggeringJobId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ text: string; type: "success" | "error" | "info" } | null>(null);
  const [inputError, setInputError] = useState<string | null>(null);

  // Client-Side Validation URL
  const validateAndFormatUrl = (rawUrl: string): { formatted: string; isValid: boolean; error?: string } => {
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      return { formatted: "", isValid: false, error: "URL target tidak boleh kosong" };
    }

    let formatted = trimmed;
    if (!formatted.startsWith("http://") && !formatted.startsWith("https://")) {
      formatted = `https://${formatted}`;
    }

    try {
      const parsed = new URL(formatted);
      if (!parsed.hostname || !parsed.hostname.includes(".")) {
        return { formatted, isValid: false, error: "Nama domain/hostname tidak valid (contoh: target-vdp.com)" };
      }
      return { formatted, isValid: true };
    } catch {
      return { formatted, isValid: false, error: "Format sintaks URL tidak valid" };
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setInputError(null);
    setStatusMessage(null);

    const { formatted, isValid, error } = validateAndFormatUrl(urlInput);
    if (!isValid) {
      setInputError(error ?? "Format URL tidak valid");
      return;
    }

    // Cek duplikasi di state lokal terlebih dahulu
    const duplicate = targets.find((t) => t.url.toLowerCase() === formatted.toLowerCase());
    if (duplicate) {
      setStatusMessage({
        text: `Target ${formatted} sudah terdaftar sebelumnya dalam sistem.`,
        type: "info",
      });
      setIsAdding(false);
      setUrlInput("");
      return;
    }

    setLoading(true);

    try {
      const res = await fetch("/api/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: formatted,
          program_name: programNameInput.trim() || "Public Scope VDP",
          is_authorized: isAuthorized,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Gagal mendaftarkan target");
      }

      setTargets((prev) => [data.target, ...prev]);
      setUrlInput("");
      setProgramNameInput("");
      setIsAdding(false);
      setStatusMessage({
        text: `Target ${data.target.url} berhasil didaftarkan dan siap dipindai!`,
        type: "success",
      });
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
        text: `Pemindaian untuk ${targetUrl} berhasil dimasukkan ke antrean! (Job ID: ${data.job?.id?.slice(0, 8)}...)`,
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
    <div className="glass-panel rounded-xl p-6 border-slate-800/80 shadow-2xl relative overflow-hidden">
      {/* Background Decorative Accent */}
      <div className="absolute -right-16 -top-16 w-32 h-32 bg-blue-600/10 rounded-full blur-2xl pointer-events-none"></div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5 relative z-10">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
            Target VDP Terdaftar & Ruang Lingkup Audit
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Utility Publik: Daftarkan URL target aplikasi web untuk diikutkan dalam pemindaian massal otomatis.
          </p>
        </div>

        <button
          onClick={() => {
            setIsAdding(!isAdding);
            setInputError(null);
          }}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 rounded-lg transition-all shadow-md shadow-blue-500/20 active:scale-95"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d={isAdding ? "M6 18L18 6M6 6l12 12" : "M12 4v16m8-8H4"} />
          </svg>
          {isAdding ? "Batal" : "Tambah Target Baru"}
        </button>
      </div>

      {/* Alert Status Feedback */}
      {statusMessage && (
        <div
          className={`p-3 rounded-lg text-xs mb-4 flex items-center justify-between transition-all ${
            statusMessage.type === "success"
              ? "bg-emerald-950/80 text-emerald-300 border border-emerald-800"
              : statusMessage.type === "info"
              ? "bg-blue-950/80 text-blue-300 border border-blue-800"
              : "bg-rose-950/80 text-rose-300 border border-rose-800"
          }`}
        >
          <span className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${statusMessage.type === "success" ? "bg-emerald-400" : statusMessage.type === "info" ? "bg-blue-400" : "bg-rose-400"}`}></span>
            {statusMessage.text}
          </span>
          <button onClick={() => setStatusMessage(null)} className="text-slate-400 hover:text-white font-bold ml-2">
            &times;
          </button>
        </div>
      )}

      {/* Form Pendaftaran Target (Input Validated) */}
      {isAdding && (
        <form onSubmit={handleAddTarget} className="p-4 rounded-xl bg-slate-950/90 border border-slate-700/80 mb-5 space-y-4 shadow-xl">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                URL Target Aplikasi Web <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                placeholder="https://vdp-target.internal"
                value={urlInput}
                onChange={(e) => {
                  setUrlInput(e.target.value);
                  if (inputError) setInputError(null);
                }}
                required
                className={`w-full px-3.5 py-2 text-xs rounded-lg bg-slate-900 border text-white placeholder-slate-500 focus:outline-none transition-colors font-mono ${
                  inputError ? "border-rose-500 focus:border-rose-400" : "border-slate-700 focus:border-blue-500"
                }`}
              />
              {inputError && <p className="text-[11px] text-rose-400 mt-1">{inputError}</p>}
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Nama Program VDP / Scope
              </label>
              <input
                type="text"
                placeholder="Platform Sandbox VDP 2026"
                value={programNameInput}
                onChange={(e) => setProgramNameInput(e.target.value)}
                className="w-full px-3.5 py-2 text-xs rounded-lg bg-slate-900 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="is_authorized_check"
              checked={isAuthorized}
              onChange={(e) => setIsAuthorized(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0 w-4 h-4 cursor-pointer"
            />
            <label htmlFor="is_authorized_check" className="text-xs text-slate-300 cursor-pointer">
              Konfirmasi Otorisasi Scope Pemindaian Legal
            </label>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800/60">
            <button
              type="button"
              onClick={() => setIsAdding(false)}
              className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
            >
              Batal
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors shadow-sm"
            >
              {loading ? "Mendaftarkan..." : "Daftarkan Target"}
            </button>
          </div>
        </form>
      )}

      {/* Tabel Target */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-3">Target URL</th>
              <th className="py-3 px-3">Scope Program</th>
              <th className="py-3 px-3">Status Otorisasi</th>
              <th className="py-3 px-3 text-right">Aksi Pemindaian</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {targets.map((t) => (
              <tr key={t.id} className="hover:bg-slate-900/50 transition-colors">
                <td className="py-3 px-3 font-mono text-slate-200 font-medium">{t.url}</td>
                <td className="py-3 px-3 text-slate-400">{t.program_name || "Public Scope VDP"}</td>
                <td className="py-3 px-3">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-950/90 text-emerald-300 border border-emerald-800/80">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    Authorized / Public
                  </span>
                </td>
                <td className="py-3 px-3 text-right">
                  <button
                    onClick={() => handleTriggerScan(t.id, t.url)}
                    disabled={triggeringJobId === t.id}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:from-blue-500 hover:to-indigo-500 disabled:opacity-50 transition-all shadow-sm active:scale-95"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {triggeringJobId === t.id ? "Memproses..." : "Scan Target"}
                  </button>
                </td>
              </tr>
            ))}
            {!targets.length && (
              <tr>
                <td colSpan={4} className="py-8 text-center text-slate-500 text-xs">
                  Belum ada target VDP terdaftar. Klik &quot;Tambah Target Baru&quot; untuk mendaftarkan URL aplikasi web.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
