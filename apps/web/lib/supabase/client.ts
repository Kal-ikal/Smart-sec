import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/database";

/**
 * Klien Supabase untuk komponen browser ("use client").
 * Hanya memakai ANON key -- semua akses tetap tunduk RLS berdasarkan
 * sesi auth pengguna yang login. Tidak pernah memuat service role key.
 */
export function createSupabaseBrowserClient(): SupabaseClient<Database> {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  ) as SupabaseClient<Database>;
}
