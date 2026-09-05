import { createClient, SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/database";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `[CONFIG] Environment variable ${name} wajib diisi (lihat .env.example). Tidak ada fallback rahasia yang di-hardcode.`
    );
  }
  return value;
}

/**
 * Server-side Admin Client (service_role, bypass RLS).
 * HANYA untuk operasi administratif tepercaya di server (mis. cron/maintenance
 * job internal) -- TIDAK dipakai oleh route handler yang melayani permintaan
 * pengguna biasa. Permintaan pengguna harus lewat createSupabaseServerClient
 * (lib/supabase/server.ts) yang tunduk pada sesi auth + RLS.
 */
export function createSupabaseAdminClient(): SupabaseClient<Database> {
  const supabaseUrl = requireEnv("NEXT_PUBLIC_SUPABASE_URL");
  const serviceRoleKey = requireEnv("SUPABASE_SERVICE_ROLE_KEY");

  return createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });
}
