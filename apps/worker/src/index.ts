import { config } from "./config.js";
import { supabaseAdmin } from "./lib/supabaseAdmin.js";
import { processJob } from "./services/jobProcessor.js";
import { zapClient } from "./services/zapClient.js";

let isShuttingDown = false;

/**
 * External Background Worker -- proses Node.js mandiri untuk mass-scanning.
 * Menggunakan claim_next_scan_job() (SECURITY DEFINER, FOR UPDATE SKIP LOCKED)
 * untuk dequeue atomik bebas race condition.
 */
async function pollLoop() {
  console.log("==================================================");
  console.log(`[${config.workerId}] SMART-SEC Background Worker Initialized`);
  console.log(`[${config.workerId}] Supabase URL: ${config.supabaseUrl}`);
  console.log(`[${config.workerId}] ZAP API URL : ${config.zapApiUrl}`);
  console.log(`[${config.workerId}] Rate Limit  : ${config.rateLimit.tokensPerSecond} req/s (Bucket: ${config.rateLimit.bucketCapacity})`);
  console.log(`[${config.workerId}] WhatsApp Alert: ${config.whatsapp.enabled ? "ACTIVE (Target: " + config.whatsapp.targetPhone + ")" : "DISABLED (Console Simulation Mode)"}`);
  console.log("==================================================");

  const zapOnline = await zapClient.checkConnection();
  if (zapOnline) {
    console.log(`[${config.workerId}] ✅ OWASP ZAP API daemon terhubung dan aktif.`);
  } else {
    console.warn(`[${config.workerId}] ⚠️ OWASP ZAP API belum terdeteksi di ${config.zapApiUrl}. Pastikan ZAP daemon/docker sudah running saat mengeksekusi scan.`);
  }

  console.log(`[${config.workerId}] Memulai polling antrean scan_jobs...`);

  while (!isShuttingDown) {
    try {
      const { data: claimedJobs, error } = await supabaseAdmin.rpc(
        "claim_next_scan_job",
        { p_worker_id: config.workerId }
      );

      if (error) {
        console.error(`[${config.workerId}] Gagal claim job:`, error.message);
        await sleep(config.pollIntervalMs);
        continue;
      }

      const job = claimedJobs?.[0];

      if (!job) {
        // Antrean kosong, tidur sejenak
        await sleep(config.pollIntervalMs);
        continue;
      }

      console.log(`[${config.workerId}] Berhasil mengklaim job ${job.id} (target: ${job.target_id})`);
      await processJob(job);
      console.log(`[${config.workerId}] Selesai memproses job ${job.id}`);
    } catch (err) {
      console.error(`[${config.workerId}] Exception dalam loop polling:`, err);
      await sleep(config.pollIntervalMs);
    }
  }

  console.log(`[${config.workerId}] Worker dihentikan dengan bersih.`);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Graceful shutdown handlers
process.on("SIGINT", () => {
  console.log(`\n[${config.workerId}] Menerima sinyal SIGINT. Menutup worker...`);
  isShuttingDown = true;
});

process.on("SIGTERM", () => {
  console.log(`\n[${config.workerId}] Menerima sinyal SIGTERM. Menutup worker...`);
  isShuttingDown = true;
});

pollLoop().catch((err) => {
  console.error(`[${config.workerId}] Worker fatal crash:`, err);
  process.exit(1);
});
