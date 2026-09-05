import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/**
 * POST /api/scans
 * Menyisipkan satu baris ke scan_jobs (status queued) -- tidak ada
 * pemindaian yang terjadi di sini (lihat README, Alur Arsitektur #1).
 *
 * PENTING: target harus SUDAH is_authorized=true sebelum bisa diantrekan.
 * Ini bukan lagi dipaksa true di sini -- gerbang kepatuhan VDP/legal
 * ditegakkan oleh RLS policy "jobs: owner can enqueue own jobs"
 * (0002_rls_policies.sql), yang akan menolak insert jika target belum sah.
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
      return NextResponse.json(
        {
          error:
            "Target belum berstatus is_authorized=true. Konfirmasikan otorisasi scope pemindaian legal (VDP) terlebih dahulu sebelum memicu scan.",
        },
        { status: 403 }
      );
    }

    const { data, error } = await supabase
      .from("scan_jobs")
      .insert({
        owner_id: user.id,
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
