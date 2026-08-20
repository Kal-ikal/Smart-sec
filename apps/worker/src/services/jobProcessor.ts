import { supabaseAdmin } from "../lib/supabaseAdmin.js";
import { zapClient } from "./zapClient.js";
import { mapZapAlertToCvssVector } from "./cvssVectorMapper.js";
import { kirimNotifikasiDarurat } from "./whatsappClient.js";
import { TokenBucket } from "../lib/tokenBucket.js";
import { config } from "../config.js";

const bucket = new TokenBucket(
  config.rateLimit.bucketCapacity,
  config.rateLimit.tokensPerSecond
);

type ScanJob = {
  id: string;
  owner_id: string;
  target_id: string;
};

/**
 * Memproses satu pekerjaan pemindaian massal end-to-end:
 * 1. Ambil & verifikasi otorisasi target VDP.
 * 2. Rate-limited active scan via OWASP ZAP API (eksekusiActiveScan).
 * 3. Ekstraksi temuan & pemetaan ke draft vektor CVSS v4.0.
 * 4. Bulk-insert ke tabel findings (Skor CVSS diisi otomatis oleh database trigger BEFORE INSERT).
 * 5. Jika kerentanan Kritis/Tinggi terdeteksi, kirim peringatan via WhatsApp.
 */
export async function processJob(job: ScanJob): Promise<void> {
  console.log(`\n==================================================`);
  console.log(`[JOB-PROCESSOR] 🚀 Memulai eksekusi scan_job ID: ${job.id}`);
  console.log(`==================================================`);

  try {
    const { data: target, error: targetError } = await supabaseAdmin
      .from("scan_targets")
      .select("id, url, is_authorized")
      .eq("id", job.target_id)
      .single();

    if (targetError || !target) {
      throw new Error(`Target ${job.target_id} tidak ditemukan: ${targetError?.message}`);
    }

    if (!target.is_authorized) {
      throw new Error(`Target ${target.url} belum berstatus is_authorized=true (Otorisasi VDP Wajib)`);
    }

    console.log(`[JOB-PROCESSOR] Target sah: ${target.url}. Mengeksekusi Active Scan...`);

    // Rate Limiting Token Bucket sebelum menyentuh target
    await bucket.take();

    // Panggil OWASP ZAP API eksekusiActiveScan
    const activeScanId = await zapClient.eksekusiActiveScan(target.url);

    await supabaseAdmin
      .from("scan_jobs")
      .update({ zap_scan_id: activeScanId })
      .eq("id", job.id);

    console.log(`[JOB-PROCESSOR] Active scan ID ${activeScanId} selesai. Mengambil alerts...`);
    const alerts = await zapClient.getAlerts(target.url);
    console.log(`[JOB-PROCESSOR] Ditemukan ${alerts.length} temuan alert dari ZAP.`);

    const findingsToInsert = alerts.map((alert) => {
      const cwe = alert.cweid ? Number(alert.cweid) : null;
      const { cvss_vector, owasp_category } = mapZapAlertToCvssVector(
        alert.risk,
        cwe,
        alert.name
      );

      return {
        owner_id: job.owner_id,
        job_id: job.id,
        target_id: job.target_id,
        zap_alert_id: alert.alertRef ?? null,
        zap_plugin_id: alert.pluginId,
        name: alert.name,
        description: alert.description,
        solution: alert.solution,
        owasp_category,
        risk_zap: alert.risk,
        evidence: alert.evidence,
        cwe_id: cwe,
        // Worker menyusun cvss_vector; database trigger menghitung skor secara otomatis
        cvss_vector,
      };
    });

    if (findingsToInsert.length > 0) {
      const { data: createdFindings, error: insertError } = await supabaseAdmin
        .from("findings")
        .insert(findingsToInsert)
        .select("name, cvss_severity, cvss_composite_score, cvss_vector, owasp_category");

      if (insertError) {
        throw new Error(`Gagal bulk-insert findings: ${insertError.message}`);
      }

      console.log(`[JOB-PROCESSOR] ✅ Berhasil bulk-insert ${findingsToInsert.length} temuan (Skor CVSS dikomputasi otomatis oleh trigger DB)`);

      // Kirim Notifikasi Darurat WhatsApp jika ada temuan Kritis/Tinggi
      if (createdFindings && createdFindings.length > 0) {
        const severeFindings = createdFindings.filter(
          (f) => f.cvss_severity === "Critical" || f.cvss_severity === "High"
        );

        if (severeFindings.length > 0) {
          const criticalCount = createdFindings.filter((f) => f.cvss_severity === "Critical").length;
          const highCount = createdFindings.filter((f) => f.cvss_severity === "High").length;

          const pesanAlert = [
            `🚨 *[SMART-SEC EMERGENCY ALERT]*`,
            `Terdeteksi Kerentanan Berisiko Tinggi pada Target!`,
            `🌐 Target: ${target.url}`,
            `📊 Status: ${criticalCount} Critical | ${highCount} High`,
            "",
            "*Rincian Temuan Utama:*",
            ...severeFindings.map(
              (f, i) =>
                `${i + 1}. *[${f.cvss_severity}] ${f.name}*\n   • Skor CVSS v4.0: *${f.cvss_composite_score}*\n   • OWASP: ${f.owasp_category}\n   • Vector: \`${f.cvss_vector}\``
            ),
          ].join("\n");

          await kirimNotifikasiDarurat(config.whatsapp.targetPhone, pesanAlert);
        }
      }
    }

    await supabaseAdmin
      .from("scan_jobs")
      .update({ status: "completed", finished_at: new Date().toISOString() })
      .eq("id", job.id);

    console.log(`[JOB-PROCESSOR] ✅ scan_job ID ${job.id} SELESAI.`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[JOB-PROCESSOR] ❌ scan_job ID ${job.id} GAGAL:`, message);

    await supabaseAdmin
      .from("scan_jobs")
      .update({
        status: "failed",
        error_message: message,
        finished_at: new Date().toISOString(),
      })
      .eq("id", job.id);
  }
}
