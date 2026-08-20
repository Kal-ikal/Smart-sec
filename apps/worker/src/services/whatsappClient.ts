import fetch from "node-fetch";
import { config } from "../config.js";

export interface WhatsAppNotificationPayload {
  targetUrl: string;
  jobId: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  findings: Array<{
    name: string;
    severity: string | null;
    score: number | null;
    vector: string | null;
    owaspCategory: string | null;
  }>;
}

/**
 * Klien Notifikasi WhatsApp untuk SMART-SEC.
 * Mengirimkan laporan alert instan ke WhatsApp Security Team / Peneliti VDP
 * ketika pemindaian selesai dan menemukan kerentanan berisiko Tinggi (High / Critical).
 */
export const whatsappClient = {
  async sendVulnerabilityAlert(payload: WhatsAppNotificationPayload): Promise<boolean> {
    const { targetUrl, jobId, totalFindings, criticalCount, highCount, findings } = payload;

    // Format pesan WhatsApp bergaya Executive Alert
    const lines = [
      "🚨 *[SMART-SEC ALERT] Laporan Pemindaian Massal*",
      "========================================",
      `🌐 *Target VDP*: ${targetUrl}`,
      `📋 *Job ID*: \`${jobId.slice(0, 13)}\``,
      `📊 *Total Temuan*: ${totalFindings} Kerentanan`,
      `⚠️ *Ringkasan Risiko*: 🔴 ${criticalCount} Critical | 🟠 ${highCount} High`,
      "========================================",
      "",
      "*Rincian Kerentanan Utama:*",
    ];

    findings.forEach((f, idx) => {
      const icon = f.severity === "Critical" ? "🔴" : f.severity === "High" ? "🟠" : "🟡";
      lines.push(`${idx + 1}. ${icon} *[${f.severity ?? "UNKNOWN"}] ${f.name}*`);
      lines.push(`   • CVSS v4.0 Score: *${f.score ? f.score.toFixed(1) : "N/A"}* (${f.severity})`);
      if (f.owaspCategory) {
        lines.push(`   • OWASP: ${f.owaspCategory}`);
      }
      if (f.vector) {
        lines.push(`   • Vector: \`${f.vector}\``);
      }
      lines.push("");
    });

    lines.push("----------------------------------------");
    lines.push("ℹ️ *Informasi*: Skor CVSS v4.0 dihitung 100% di database PostgreSQL via Stored Procedure.");
    lines.push("🔗 Silakan cek dashboard SMART-SEC untuk analisis dan rekomendasi remediasi.");

    const messageText = lines.join("\n");

    if (!config.whatsapp.enabled) {
      console.log(`[WHATSAPP-SERVICE] (Disabled/Simulasi) Pesan Alert Notifikasi Disiapkan:`);
      console.log("----------------------------------------");
      console.log(messageText);
      console.log("----------------------------------------");
      console.log(`[WHATSAPP-SERVICE] Set WA_ENABLED=true, WA_API_TOKEN, dan WA_TARGET_PHONE di .env untuk mengirim ke WhatsApp nyata.`);
      return true;
    }

    try {
      console.log(`[WHATSAPP-SERVICE] Mengirimkan notifikasi WhatsApp ke ${config.whatsapp.targetPhone}...`);

      // Mengirim POST request ke WhatsApp Gateway API (mis. Fonnte / Wablas / Generic HTTP API)
      const response = await fetch(config.whatsapp.apiUrl, {
        method: "POST",
        headers: {
          "Authorization": config.whatsapp.apiToken,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: config.whatsapp.targetPhone,
          message: messageText,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[WHATSAPP-SERVICE] Gagal mengirim pesan (${response.status}):`, errorText);
        return false;
      }

      console.log(`[WHATSAPP-SERVICE] ✅ Notifikasi WhatsApp berhasil dikirim!`);
      return true;
    } catch (err) {
      console.error(`[WHATSAPP-SERVICE] Exception saat mengirim WhatsApp:`, err);
      return false;
    }
  },
};
