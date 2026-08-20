import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Environment variable ${name} wajib diisi (lihat .env.example)`);
  }
  return value;
}

export const config = {
  supabaseUrl: required("SUPABASE_URL"),
  supabaseServiceRoleKey: required("SUPABASE_SERVICE_ROLE_KEY"),
  zapApiUrl: process.env.ZAP_API_URL ?? "http://localhost:8080",
  zapApiKey: process.env.ZAP_API_KEY ?? "",
  workerId: process.env.WORKER_ID ?? `worker-${process.pid}`,
  rateLimit: {
    tokensPerSecond: Number(process.env.RATE_LIMIT_TOKENS_PER_SECOND ?? 2),
    bucketCapacity: Number(process.env.RATE_LIMIT_BUCKET_CAPACITY ?? 10),
  },
  whatsapp: {
    enabled: process.env.WA_ENABLED === "true",
    apiUrl: process.env.WA_API_URL ?? "https://api.fonnte.com/send",
    apiToken: process.env.WA_API_TOKEN ?? "",
    targetPhone: process.env.WA_TARGET_PHONE ?? "",
  },
  // Jeda antar-poll saat antrean kosong, supaya worker tidak busy-loop.
  pollIntervalMs: 3000,
} as const;
