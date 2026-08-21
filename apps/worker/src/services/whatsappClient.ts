import fetch from "node-fetch";
import { config } from "../config.js";

/**
 * Klien Integrasi WhatsApp Gateway (Fonnte API)
 * Mengirimkan notifikasi darurat/alert kerentanan berisiko Kritis atau Tinggi.
 */
export async function kirimNotifikasiDarurat(
  nomorTujuan?: string,
  pesan?: string
): Promise<boolean> {
  const targetPhone = nomorTujuan || config.whatsapp.targetPhone || process.env.WA_TARGET_PHONE || "";
  const messageText = pesan || "Pesan pengujian notifikasi darurat SMART-SEC";
  const apiToken = config.whatsapp.apiToken || process.env.WA_API_TOKEN || "";
  const apiUrl = config.whatsapp.apiUrl || process.env.WA_API_URL || "https://api.fonnte.com/send";

  if (!targetPhone) {
    console.warn("[WHATSAPP-FONNTE] ⚠️ WA_TARGET_PHONE / nomorTujuan belum diatur.");
    return false;
  }

  // Jika token Fonnte belum dikonfigurasi (placeholder), tampilkan simulasi log terminal dengan rapi
  if (!apiToken || apiToken === "your-fonnte-token-here") {
    console.log(`\n==================================================`);
    console.log(`[WHATSAPP-FONNTE SIMULASI] Log Pesan Notifikasi Darurat:`);
    console.log(`Penerima : ${targetPhone}`);
    console.log(`Endpoint : ${apiUrl}`);
    console.log("----------------------------------------");
    console.log(messageText);
    console.log("----------------------------------------");
    console.log(`ℹ️ Masukkan token Fonnte yang valid ke WA_API_TOKEN pada file .env untuk mengirim pesan ke nomor WhatsApp asli.`);
    console.log(`==================================================\n`);
    return true;
  }

  try {
    console.log(`[WHATSAPP-FONNTE] Mengirimkan notifikasi darurat POST ke ${apiUrl}...`);

    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": apiToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        target: targetPhone,
        message: messageText,
      }),
    });

    const data = (await response.json()) as { status?: boolean; reason?: string; detail?: string };

    if (response.ok && data.status !== false) {
      console.log(`[WHATSAPP-FONNTE] ✅ Notifikasi WhatsApp berhasil dikirim ke ${targetPhone}!`);
      return true;
    } else {
      console.error(`[WHATSAPP-FONNTE] ❌ Gagal mengirim pesan ke WhatsApp (${response.status}):`, data.reason || data.detail || JSON.stringify(data));
      return false;
    }
  } catch (err) {
    console.error(`[WHATSAPP-FONNTE] ❌ Exception saat mengirim pesan via Fonnte:`, err instanceof Error ? err.message : String(err));
    return false;
  }
}
