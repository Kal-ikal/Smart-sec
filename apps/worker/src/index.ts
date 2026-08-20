import { config } from "./config.js";
import { supabaseAdmin } from "./lib/supabaseAdmin.js";
import { processJob } from "./services/jobProcessor.js";
import { zapClient } from "./services/zapClient.js";

let isShuttingDown = false;

/**
 * Loop polling asinkron berkelanjutan (pollJobs)
 * Menarik pekerjaan dari antrean scan_jobs menggunakan klausa FOR UPDATE SKIP LOCKED
 * via Stored Procedure claim_next_scan_job().
 */
async function pollJobs() {
  console.log("==================================================");
  console.log(`[WORKER] 🛡️ SMART-SEC External Background Worker Started`);
  console.log(`[WORKER] Instance ID : ${config.workerId}`);
  console.log(`[WORKER] Supabase URL: ${config.supabaseUrl}`);
  console.log(`[WORKER] ZAP API URL : ${config.zapApiUrl}`);
  console.log(`[WORKER] Rate Limit  : ${config.rateLimit.tokensPerSecond} req/s (Capacity: ${config.rateLimit.bucketCapacity})`);
  console.log("==================================================");

  // Cek konektivitas awal ke OWASP ZAP API Daemon
  try {
    const zapOnline = await zapClient.checkConnection();
    if (zapOnline) {
      console.log(`[WORKER] ✅ OWASP ZAP API Daemon terhubung.`);
    } else {
      console.warn(`[WORKER] ⚠️ OWASP ZAP API tidak terdeteksi di ${config.zapApiUrl}. Gunakan Docker/ZAP atau set ZAP_MOCK=true untuk simulasi.`);
    }
  } catch (err) {
    console.warn(`[WORKER] ⚠️ Gagal memeriksa koneksi ZAP:`, err instanceof Error ? err.message : String(err));
  }

  console.log(`[WORKER] 🔄 Memulai polling antrean scan_jobs (Jeda backoff: 5 detik jika kosong)...\n`);

  while (!isShuttingDown) {
    try {
      // 1. Panggil Stored Procedure claim_next_scan_job (FOR UPDATE SKIP LOCKED)
      const { data: claimedJobs, error } = await supabaseAdmin.rpc(
        "claim_next_scan_job",
        { p_worker_id: config.workerId }
      );

      if (error) {
        console.error(`[WORKER] ❌ Gagal memanggil claim_next_scan_job:`, error.message);
        await sleep(5000);
        continue;
      }

      const job = claimedJobs?.[0];

      if (!job) {
        // Antrean kosong -- backoff 5 detik
        await sleep(5000);
        continue;
      }

      console.log(`[WORKER] 📥 Klaim Job Berhasil! Job ID: ${job.id} (Target ID: ${job.target_id})`);

      // 2. Ubah status scan_jobs menjadi 'processing'
      const { error: updateStatusError } = await supabaseAdmin
        .from("scan_jobs")
        .update({ status: "running" }) // status 'running'/'processing'
        .eq("id", job.id);

      if (updateStatusError) {
        console.warn(`[WORKER] ⚠️ Gagal memperbarui status ke processing: ${updateStatusError.message}`);
      }

      // 3. Eksekusi pemindaian & kalkulasi CVSS
      await processJob(job);

    } catch (err) {
      // Resilience check: tangkap exception agar worker tidak crash fatal
      console.error(`[WORKER] ⚠️ Terjadi kesalahan pada loop pollJobs (Unhandled exception caught):`, err instanceof Error ? err.message : String(err));
      await sleep(5000);
    }
  }

  console.log(`[WORKER] Worker dihentikan dengan aman.`);
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Graceful shutdown handlers
process.on("SIGINT", () => {
  console.log(`\n[WORKER] Menerima sinyal SIGINT. Menghentikan polling...`);
  isShuttingDown = true;
});

process.on("SIGTERM", () => {
  console.log(`\n[WORKER] Menerima sinyal SIGTERM. Menghentikan polling...`);
  isShuttingDown = true;
});

// Jalankan pollJobs
pollJobs().catch((err) => {
  console.error(`[WORKER] Fatal crash pada pollJobs:`, err);
  process.exit(1);
});
