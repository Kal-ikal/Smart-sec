import dotenv from "dotenv";
import path from "path";

dotenv.config();
dotenv.config({ path: path.resolve(process.cwd(), "apps/worker/.env") });

export const config = {
  supabaseUrl:
    process.env.SUPABASE_URL ||
    process.env.NEXT_PUBLIC_SUPABASE_URL ||
    "https://ltmmjtxoetaeburbokss.supabase.co",
  supabaseServiceRoleKey:
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx0bW1qdHhvZXRhZWJ1cmJva3NzIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4NzEwNTAxMywiZXhwIjoyMTAyNjgxMDEzfQ.6mm7Cd5D9CIh54uZatHVK6WiUANf0Dd-SOX5j8BMmNQ",
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
