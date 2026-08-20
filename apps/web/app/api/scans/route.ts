import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/**
 * POST /api/scans
 * Body: { target_id: string }
 */
export async function POST(request: Request) {
  const supabase = createSupabaseServerClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  let userId = user?.id;

  if (!userId) {
    // Fallback untuk single-tenant / local dev profile
    const { data: firstProfile } = await supabase
      .from("profiles")
      .select("id")
      .limit(1)
      .maybeSingle();

    if (firstProfile) {
      userId = firstProfile.id;
    }
  }

  if (!userId) {
    return NextResponse.json(
      { error: "Sesi pengguna tidak ditemukan. Pastikan sudah ada profil pengguna di Supabase." },
      { status: 401 }
    );
  }

  const body = await request.json();
  const { target_id } = body as { target_id?: string };

  if (!target_id) {
    return NextResponse.json({ error: "target_id wajib diisi" }, { status: 400 });
  }

  const { data, error } = await supabase
    .from("scan_jobs")
    .insert({ owner_id: userId, target_id })
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  return NextResponse.json({ job: data }, { status: 201 });
}
