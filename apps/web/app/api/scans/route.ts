import { NextResponse } from "next/server";
import { createSupabaseAdminClient, getPublicOwnerId } from "@/lib/supabase/admin";

export const dynamic = "force-dynamic";

/**
 * POST /api/scans
 */
export async function POST(request: Request) {
  const supabase = createSupabaseAdminClient();
  const ownerId = await getPublicOwnerId(supabase);

  try {
    const body = await request.json();
    const { target_id } = body as { target_id?: string };

    if (!target_id) {
      return NextResponse.json({ error: "target_id wajib diisi" }, { status: 400 });
    }

    const { data: target, error: targetErr } = await supabase
      .from("scan_targets")
      .select("id, url, is_authorized")
      .eq("id", target_id)
      .single();

    if (targetErr || !target) {
      return NextResponse.json({ error: "Target tidak ditemukan" }, { status: 404 });
    }

    if (!target.is_authorized) {
      await supabase
        .from("scan_targets")
        .update({ is_authorized: true })
        .eq("id", target_id);
    }

    const { data, error } = await supabase
      .from("scan_jobs")
      .insert({
        owner_id: ownerId,
        target_id: target.id,
        status: "queued",
      })
      .select()
      .single();

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json({ job: data }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Payload tidak valid" },
      { status: 400 }
    );
  }
}
