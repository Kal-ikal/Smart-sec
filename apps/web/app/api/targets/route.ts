import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/**
 * GET /api/targets
 * Menggunakan klien bersesi (anon key + cookie) sehingga RLS
 * ("targets: owner full access") membatasi hasil hanya milik pengguna login.
 */
export async function GET() {
  const supabase = createSupabaseServerClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Sesi tidak ditemukan, silakan login" }, { status: 401 });
  }

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
 * is_authorized HARUS ditegaskan eksplisit oleh pengguna (checkbox
 * "Konfirmasi Otorisasi Scope Pemindaian Legal") -- default false. Ini
 * adalah gerbang kepatuhan VDP/legal (Batasan Masalah, UU ITE) yang
 * dipakai lagi oleh RLS di scan_jobs (0002_rls_policies.sql) sebelum
 * target boleh diikutkan dalam antrean pemindaian.
 */
export async function POST(request: Request) {
  const supabase = createSupabaseServerClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Sesi tidak ditemukan, silakan login" }, { status: 401 });
  }

  try {
    const body = await request.json();
    const { url, program_name, is_authorized, notes } = body;

    if (!url || typeof url !== "string" || !url.trim()) {
      return NextResponse.json({ error: "URL target wajib diisi" }, { status: 400 });
    }

    let formattedUrl = url.trim();
    if (!formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
      formattedUrl = `https://${formattedUrl}`;
    }

    try {
      new URL(formattedUrl);
    } catch {
      return NextResponse.json({ error: "Format URL target tidak valid" }, { status: 400 });
    }

    const { data: existingTarget } = await supabase
      .from("scan_targets")
      .select("*")
      .eq("url", formattedUrl)
      .maybeSingle();

    if (existingTarget) {
      return NextResponse.json(
        { target: existingTarget, message: "Target sudah terdaftar sebelumnya" },
        { status: 200 }
      );
    }

    const { data, error } = await supabase
      .from("scan_targets")
      .insert({
        owner_id: user.id,
        url: formattedUrl,
        program_name: program_name ? String(program_name).trim() : null,
        is_authorized: Boolean(is_authorized),
        notes: notes ? String(notes).trim() : null,
      })
      .select()
      .single();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ target: data }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Payload tidak valid" },
      { status: 400 }
    );
  }
}
