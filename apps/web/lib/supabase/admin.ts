import { createClient, SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/database";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || "https://ltmmjtxoetaeburbokss.supabase.co";
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";

/**
 * Server-side Public Admin Client.
 * Memungkinkan platform SMART-SEC bekerja sebagai utilitas terbuka / publik (seperti VirusTotal)
 * tanpa mewajibkan sesi login / autentikasi pengguna.
 */
export function createSupabaseAdminClient(): SupabaseClient<Database> {
  return createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });
}

/**
 * Mengambil ID profil publik default untuk pengisian owner_id pada mode anonim/public.
 * Menjamin bahwasanya ID yang dikembalikan SELALU ada pada tabel auth.users & public.profiles
 * sehingga tidak melanggar foreign key constraint (scan_targets_owner_id_fkey).
 */
export async function getPublicOwnerId(supabase: SupabaseClient<Database>): Promise<string> {
  try {
    // 1. Cek apakah sudah ada profil terdaftar di tabel public.profiles
    const { data: firstProfile } = await supabase
      .from("profiles")
      .select("id")
      .limit(1)
      .maybeSingle();

    if (firstProfile?.id) {
      return firstProfile.id;
    }

    // 2. Jika profiles kosong, cek pengguna yang terdaftar di Supabase Auth Admin
    const { data: usersData } = await supabase.auth.admin.listUsers();
    if (usersData?.users && usersData.users.length > 0) {
      const authUser = usersData.users[0];
      await supabase.from("profiles").upsert({
        id: authUser.id,
        full_name: authUser.user_metadata?.full_name || authUser.email || "Public Auditor",
        role: "admin",
      });
      return authUser.id;
    }

    // 3. Jika auth.users juga masih kosong, buat akun auditor sistem publik secara otomatis
    const { data: newAuthUser } = await supabase.auth.admin.createUser({
      email: "auditor@smart-sec.local",
      password: "SmartSecPublicAuditor123!",
      email_confirm: true,
      user_metadata: { full_name: "Public System Auditor" },
    });

    if (newAuthUser?.user?.id) {
      await supabase.from("profiles").upsert({
        id: newAuthUser.user.id,
        full_name: "Public System Auditor",
        role: "admin",
      });
      return newAuthUser.user.id;
    }
  } catch (err) {
    console.error("[SMART-SEC] Error in getPublicOwnerId:", err);
  }

  return "00000000-0000-0000-0000-000000000000";
}
