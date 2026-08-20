import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/**
 * GET /api/targets
 */
export async function GET() {
  const supabase = createSupabaseServerClient();

  const { data, error } = await supabase
    .from("scan_targets")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 400 });
  }

  return NextResponse.json({ targets: data });
}

/**
 * POST /api/targets
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
      { error: "Sesi pengguna tidak ditemukan. Pastikan ada user/profil terdaftar di Supabase." },
      { status: 401 }
    );
  }

  try {
    const body = await request.json();
    const { url, program_name, is_authorized, notes } = body;

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL target wajib diisi" }, { status: 400 });
    }

    let formattedUrl = url.trim();
    if (!formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    const { data, error } = await supabase
      .from("scan_targets")
      .insert({
        owner_id: userId,
        url: formattedUrl,
        program_name: program_name ?? null,
        is_authorized: Boolean(is_authorized),
        notes: notes ?? null,
      })
      .select()
      .single();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ target: data }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Invalid payload" },
      { status: 400 }
    );
  }
}
