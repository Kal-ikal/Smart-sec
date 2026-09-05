"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";

/**
 * Halaman login SMART-SEC. Sesi otentikasi ini adalah dasar RLS
 * (owner_id = auth.uid()) di 0002_rls_policies.sql -- tanpa sesi ini,
 * dashboard tidak dapat membaca/menulis baris apa pun.
 *
 * Akun pengguna dibuat lewat Supabase Auth (dashboard/admin API), bukan
 * lewat pendaftaran publik -- SMART-SEC adalah alat internal komite
 * keamanan/peneliti, bukan utilitas publik seperti VirusTotal.
 */
export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const supabase = createSupabaseBrowserClient();
    const { error: signInError } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    setLoading(false);

    if (signInError) {
      setError(signInError.message);
      return;
    }

    router.push("/dashboard");
    router.refresh();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#070b14] text-slate-100 px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="w-12 h-12 mx-auto rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/25 ring-1 ring-white/20 mb-3">
            <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-lg font-extrabold tracking-tight text-white">SMART-SEC</h1>
          <p className="text-xs text-slate-400 mt-1">Masuk untuk mengakses dashboard evaluasi keamanan</p>
        </div>

        <form onSubmit={handleSubmit} className="glass-panel rounded-xl p-6 border-slate-800/80 space-y-4">
          {error && (
            <div className="p-3 rounded-lg text-xs bg-rose-950/80 text-rose-300 border border-rose-800">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2 text-xs rounded-lg bg-slate-900 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              placeholder="analis@smart-sec.local"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Kata Sandi</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3.5 py-2 text-xs rounded-lg bg-slate-900 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
              placeholder="********"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-lg transition-colors shadow-sm"
          >
            {loading ? "Memproses..." : "Masuk"}
          </button>
        </form>

        <p className="text-[11px] text-slate-500 text-center mt-4">
          Akun baru dibuat oleh administrator lewat Supabase Auth -- tidak ada pendaftaran publik.
        </p>
      </div>
    </div>
  );
}
