import { supabaseAdmin } from "../lib/supabaseAdmin.js";
import { zapClient } from "./zapClient.js";
import { mapZapAlertToCvssVector } from "./cvssVectorMapper.js";
import { whatsappClient } from "./whatsappClient.js";
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
 * Memproses satu job end-to-end:
 * 1. Validasi target VDP & perizinan
 * 2. Rate-limited ZAP Spider scan
 * 3. Rate-limited ZAP Active scan
 * 4. Ambil alerts & petakan ke draft CVSS v4.0 vector
 * 5. Bulk-insert ke tabel findings (Skor CVSS dihitung otomatis oleh DB Trigger)
 * 6. Kirim Laporan Alert Notifikasi via WhatsApp API
 * 7. Update status job menjadi 'completed' atau 'failed'
 */
export async function processJob(job: ScanJob): Promise<void> {
  console.log(`[${config.workerId}] Memulai eksekusi scan_job: ${job.id}`);

  await supabaseAdmin
    .from("scan_jobs")
    .update({ status: "running", started_at: new Date().toISOString() })
    .eq("id", job.id);

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
      throw new Error(`Target ${target.url} belum berstatus is_authorized=true (Pelanggaran kebijakan VDP)`);
    }

    console.log(`[${config.workerId}] Target terverifikasi: ${target.url}. Menjalankan spider...`);

    // Rate limiting: kurangi laju request agar tidak membebani server target
    await bucket.take();
    const spiderScanId = await zapClient.startSpider(target.url);
    await zapClient.waitUntilComplete(() => zapClient.spiderStatus(spiderScanId));
    console.log(`[${config.workerId}] Spider selesai untuk scan: ${spiderScanId}`);

    console.log(`[${config.workerId}] Menjalankan active scan...`);
    await bucket.take();
    const activeScanId = await zapClient.startActiveScan(target.url);

    await supabaseAdmin
      .from("scan_jobs")
      .update({ zap_scan_id: activeScanId })
      .eq("id", job.id);

    await zapClient.waitUntilComplete(() => zapClient.activeScanStatus(activeScanId));
    console.log(`[${config.workerId}] Active scan selesai untuk scan: ${activeScanId}`);

    const alerts = await zapClient.getAlerts(target.url);
    console.log(`[${config.workerId}] Ditemukan ${alerts.length} alert(s) dari OWASP ZAP`);

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
        // SHIFT-COMPUTATION:
        // Worker hanya mengisi cvss_vector. Kolom cvss_base_score,
        // cvss_threat_score, cvss_environmental_score, cvss_composite_score,
        // dan cvss_severity diisi 100% oleh PostgreSQL trigger.
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

      console.log(`[${config.workerId}] Berhasil bulk-insert ${findingsToInsert.length} temuan (Skor CVSS dikomputasi otomatis oleh trigger DB)`);

      // Notifikasi WhatsApp Alert
      if (createdFindings && createdFindings.length > 0) {
        const criticalCount = createdFindings.filter((f) => f.cvss_severity === "Critical").length;
        const highCount = createdFindings.filter((f) => f.cvss_severity === "High").length;

        await whatsappClient.sendVulnerabilityAlert({
          targetUrl: target.url,
          jobId: job.id,
          totalFindings: createdFindings.length,
          criticalCount,
          highCount,
          findings: createdFindings.map((f) => ({
            name: f.name,
            severity: f.cvss_severity,
            score: f.cvss_composite_score,
            vector: f.cvss_vector,
            owaspCategory: f.owasp_category,
          })),
        });
      }
    }

    await supabaseAdmin
      .from("scan_jobs")
      .update({ status: "completed", finished_at: new Date().toISOString() })
      .eq("id", job.id);

    console.log(`[${config.workerId}] scan_job ${job.id} selesai dengan sukses.`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[${config.workerId}] scan_job ${job.id} gagal:`, message);

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
