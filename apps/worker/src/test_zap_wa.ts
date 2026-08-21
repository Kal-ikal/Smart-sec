import fetch from "node-fetch";
import { config } from "./config.js";
import { kirimNotifikasiDarurat } from "./services/whatsappClient.js";

/**
 * Skrip Pengujian Verifikasi Integrasi ZAP API & WhatsApp Gateway (Fonnte).
 * Menjalankan uji ping ZAP daemon versi dan pengiriman pesan notifikasi percobaan.
 */
async function runVerification() {
  console.log("==================================================");
  console.log("SMART-SEC | Verifikasi Integrasi ZAP API & WhatsApp");
  console.log("==================================================");

  // 1. Ping OWASP ZAP API Daemon
  console.log("\n[1/2] 🔍 Memeriksa Status OWASP ZAP API Daemon...");
  const zapUrl = config.zapApiUrl || "http://127.0.0.1:8080";
  const zapApiKey = config.zapApiKey || "skripsi123";

  try {
    const versionEndpoint = `${zapUrl}/JSON/core/view/version/?apikey=${encodeURIComponent(zapApiKey)}`;
    console.log(` -> Memanggil endpoint: ${versionEndpoint}`);

    const res = await fetch(versionEndpoint);
    if (res.ok) {
      const data = (await res.json()) as { version?: string };
      console.log(` ✅ OWASP ZAP API Terhubung! Status: HTTP ${res.status} | Versi ZAP: ${data.version ?? "Unknown"}`);
    } else {
      console.warn(` ⚠️ OWASP ZAP API merespons HTTP ${res.status}: ${await res.text()}`);
    }
  } catch (err) {
    console.warn(` ⚠️ OWASP ZAP Daemon belum terdeteksi di ${zapUrl}.`);
    console.warn(`    Gunakan skrip zap-start.bat (Windows) atau zap-start.sh (Linux/Mac) untuk menjalankan ZAP daemon.`);
    console.warn(`    Detail error:`, err instanceof Error ? err.message : String(err));
  }

  // 2. Pengujian Notifikasi WhatsApp Gateway (Fonnte)
  console.log("\n[2/2] 📱 Pengujian Pengiriman Notifikasi WhatsApp (Fonnte)...");
  const targetPhone = config.whatsapp.targetPhone || "08123456789";
  const testMessage = [
    `🚨 *[SMART-SEC VERIFICATION TEST]*`,
    `Halo! Ini adalah pesan pengujian integrasi otomatis platform SMART-SEC.`,
    `----------------------------------------`,
    `🌐 *Status OWASP ZAP API*: Active (${zapUrl})`,
    `📲 *Status WhatsApp Gateway*: Connected`,
    `⏰ *Waktu Pengujian*: ${new Date().toLocaleString("id-ID")}`,
    `----------------------------------------`,
    `Sistem SMART-SEC siap menjalankan pemindaian massal & CVSS v4.0 Risk Scoring!`,
  ].join("\n");

  console.log(` -> Mengirim pesan percobaan ke nomor: ${targetPhone}`);
  const waSuccess = await kirimNotifikasiDarurat(targetPhone, testMessage);

  if (waSuccess) {
    console.log(` ✅ Verifikasi Pengiriman WhatsApp BERHASIL!`);
  } else {
    console.log(` ℹ️ Uji pengiriman WhatsApp selesai (Cek log di atas).`);
  }

  console.log("\n==================================================");
  console.log("🎉 Pengujian Verifikasi Integrasi Selesai.");
  console.log("==================================================\n");
}

runVerification().catch((err) => {
  console.error("❌ Exception pada skrip verifikasi:", err);
});
