import dotenv from "dotenv";
import path from "path";

dotenv.config();
dotenv.config({ path: path.resolve(process.cwd(), "apps/worker/.env") });

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `[CONFIG] Environment variable ${name} wajib diisi (lihat .env.example). Worker dihentikan demi keamanan -- tidak ada fallback rahasia yang di-hardcode.`
    );
  }
  return value;
}

export const config = {
  supabaseUrl: requireEnv("SUPABASE_URL"),
  supabaseServiceRoleKey: requireEnv("SUPABASE_SERVICE_ROLE_KEY"),
  zapApiUrl: process.env.ZAP_API_URL ?? "http://127.0.0.1:8080",
  zapApiKey: process.env.ZAP_API_KEY ?? "skripsi123",
  workerId: process.env.WORKER_ID ?? `worker-${process.pid}`,
  rateLimit: {
    tokensPerSecond: Number(process.env.RATE_LIMIT_TOKENS_PER_SECOND ?? 2),
    bucketCapacity: Number(process.env.RATE_LIMIT_BUCKET_CAPACITY ?? 10),
  },
  whatsapp: {
    enabled: process.env.WA_ENABLED === "true",
    apiUrl: process.env.WA_API_URL ?? "https://api.fonnte.com/send",
    apiToken: process.env.WA_API_TOKEN ?? "",
    targetPhone: process.env.WA_TARGET_PHONE ?? "08123456789",
  },
  pollIntervalMs: 3000,
} as const;
