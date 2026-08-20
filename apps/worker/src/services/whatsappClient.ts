import pkg from "whatsapp-web.js";
import qrcode from "qrcode-terminal";

const { Client, LocalAuth } = pkg;

let isWaReady = false;

// Inisialisasi WhatsApp Web Client dengan LocalAuth & qrcode-terminal
export const waClient = new Client({
  authStrategy: new LocalAuth(),
  puppeteer: {
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  },
});

waClient.on("qr", (qr: string) => {
  console.log("\n==================================================");
  console.log("[WHATSAPP] 📱 Pindai QR Code berikut untuk otentikasi WhatsApp Worker:");
  console.log("==================================================");
  qrcode.generate(qr, { small: true });
});

waClient.on("ready", () => {
  isWaReady = true;
  console.log("\n[WHATSAPP] ✅ Sesi WhatsApp Web berhasil terhubung dan SIAP dikirim!");
});

waClient.on("auth_failure", (msg: string) => {
  console.error("[WHATSAPP] ❌ Otentikasi Gagal:", msg);
});

waClient.on("disconnected", (reason: string) => {
  isWaReady = false;
  console.warn("[WHATSAPP] ⚠️ WhatsApp terputus:", reason);
});

// Mulai inisialisasi background whatsapp-web.js (non-blocking)
try {
  waClient.initialize().catch((err) => {
    console.warn("[WHATSAPP] ⚠️ Gagal menginisialisasi WhatsApp Client:", err.message);
  });
} catch (err) {
  console.warn("[WHATSAPP] ⚠️ Exception inisialisasi WhatsApp:", err);
}

/**
 * Mengirimkan pesan peringatan darurat ke WhatsApp target
 * ketika temuan berstatus Kritis (Critical) atau Tinggi (High) terdeteksi.
 */
export async function kirimNotifikasiDarurat(nomorTujuan: string, pesan: string): Promise<boolean> {
  try {
    if (!nomorTujuan) {
      console.warn("[WHATSAPP] ⚠️ Nomor tujuan WhatsApp belum dikonfigurasi (WA_TARGET_PHONE / nomorTujuan).");
      return false;
    }

    // Format nomor WhatsApp: mis. 08123456789 -> 628123456789@c.us
    let formattedNumber = nomorTujuan.replace(/\D/g, "");
    if (formattedNumber.startsWith("0")) {
      formattedNumber = "62" + formattedNumber.slice(1);
    }
    const chatId = formattedNumber.endsWith("@c.us") ? formattedNumber : `${formattedNumber}@c.us`;

    if (!isWaReady) {
      console.log(`[WHATSAPP-SIMULATION] (Client belum Scan QR) Log Pesan Darurat ke ${chatId}:`);
      console.log("----------------------------------------");
      console.log(pesan);
      console.log("----------------------------------------");
      return false;
    }

    await waClient.sendMessage(chatId, pesan);
    console.log(`[WHATSAPP] 🚨 Notifikasi darurat berhasil dikirim ke ${chatId}`);
    return true;
  } catch (err) {
    console.error("[WHATSAPP] ❌ Gagal mengirim notifikasi darurat:", err instanceof Error ? err.message : String(err));
    return false;
  }
}
