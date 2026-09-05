import { TokenBucket } from "./lib/tokenBucket.js";

/**
 * Verifikasi ulang klaim BAB IV: 3 skenario kombinasi kapasitas/refill rate
 * Token Bucket, membandingkan laju efektif steady-state hasil pengukuran
 * nyata terhadap klaim "3,00 / 1,50 / 8,33 req/detik".
 *
 * Metodologi per skenario:
 *   1. Kuras burst awal (take() sebanyak `capacity` kali) -- ini pasti nyaris
 *      instan karena token awal penuh, JANGAN dihitung sebagai laju steady.
 *   2. Ukur laju steady-state: panggil take() berulang secara back-to-back
 *      selama `measureSeconds` detik setelah burst habis, hitung
 *      throughput = jumlah_take / waktu_terpakai.
 */
async function measureSteadyStateRate(
  capacity: number,
  refillPerSecond: number,
  measureSeconds: number
): Promise<{ measuredRate: number; takes: number; elapsedMs: number }> {
  const bucket = new TokenBucket(capacity, refillPerSecond);

  // 1. Kuras burst awal
  for (let i = 0; i < capacity; i++) {
    await bucket.take();
  }

  // 2. Ukur steady-state selama measureSeconds
  const start = Date.now();
  let takes = 0;
  while (Date.now() - start < measureSeconds * 1000) {
    await bucket.take();
    takes++;
  }
  const elapsedMs = Date.now() - start;

  return { measuredRate: takes / (elapsedMs / 1000), takes, elapsedMs };
}

async function main() {
  console.log("==========================================");
  console.log("SMART-SEC | Verifikasi Token Bucket Rate Limiter");
  console.log("==========================================\n");

  const scenarios = [
    { label: "Skenario 1", capacity: 10, refillPerSecond: 3, claimed: 3.0 },
    { label: "Skenario 2", capacity: 3, refillPerSecond: 1.5, claimed: 1.5 },
    { label: "Skenario 3", capacity: 25, refillPerSecond: 8.33, claimed: 8.33 },
  ];

  const results: { label: string; capacity: number; refillPerSecond: number; claimed: number; measuredRate: number; takes: number; elapsedMs: number }[] = [];

  for (const s of scenarios) {
    const { measuredRate, takes, elapsedMs } = await measureSteadyStateRate(s.capacity, s.refillPerSecond, 8);
    results.push({ ...s, measuredRate, takes, elapsedMs });
    console.log(
      `${s.label} (capacity=${s.capacity}, refill=${s.refillPerSecond}/s): ` +
      `klaim=${s.claimed.toFixed(2)} req/s, terukur=${measuredRate.toFixed(2)} req/s ` +
      `(${takes} take dalam ${elapsedMs}ms), selisih=${(measuredRate - s.claimed).toFixed(3)}`
    );
  }

  console.log("\n==========================================");
  console.log("RINGKASAN (JSON):");
  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error("Test gagal:", err);
  process.exit(1);
});
