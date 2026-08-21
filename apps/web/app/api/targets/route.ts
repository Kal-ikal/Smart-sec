import { NextResponse } from "next/server";
import { createSupabaseAdminClient, getPublicOwnerId } from "@/lib/supabase/admin";

export const dynamic = "force-dynamic";

/**
 * GET /api/targets
 */
export async function GET() {
  const supabase = createSupabaseAdminClient();

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
  const supabase = createSupabaseAdminClient();
  const ownerId = await getPublicOwnerId(supabase);

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
        owner_id: ownerId,
        url: formattedUrl,
        program_name: program_name ? String(program_name).trim() : "Public Scope VDP",
        is_authorized: is_authorized !== undefined ? Boolean(is_authorized) : true,
        notes: notes ? String(notes).trim() : "Submitted via Public Interface",
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
