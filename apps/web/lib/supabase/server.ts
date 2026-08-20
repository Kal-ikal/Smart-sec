import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/database";

/**
 * Klien Supabase untuk Server Components / Route Handlers.
 * Tetap memakai ANON key + cookie sesi pengguna -- BUKAN service role.
 * Route Handler ini hanya mem-proxy insert ke scan_jobs (memicu antrean);
 * RLS di 0002_rls_policies.sql tetap berlaku, termasuk gerbang
 * is_authorized pada scan_targets.
 */
export function createSupabaseServerClient(): SupabaseClient<Database> {
  const cookieStore = cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet: { name: string; value: string; options?: any }[]) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            );
          } catch {
            // Dipanggil dari Server Component tanpa akses set-cookie;
            // aman diabaikan karena middleware menangani refresh sesi.
          }
        },
      },
    }
  ) as SupabaseClient<Database>;
}
