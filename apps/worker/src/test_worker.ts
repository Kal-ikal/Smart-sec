import { TokenBucket } from "./lib/tokenBucket.js";
import { mapZapAlertToCvssVector, buildDraftCvssVector } from "./services/cvssVectorMapper.js";

async function runTests() {
  console.log("==========================================");
  console.log("SMART-SEC Worker Verification Test Suite");
  console.log("==========================================");

  // 1. Test CVSS Vector Mapper & OWASP Mapping
  console.log("\n[Test 1] Testing CVSS Vector & OWASP Category Mapping...");

  const sqlInj = mapZapAlertToCvssVector("High", 89, "SQL Injection");
  console.log("-> SQL Injection (CWE-89):", sqlInj);
  if (sqlInj.owasp_category !== "A03:2021-Injection" || !sqlInj.cvss_vector.includes("VC:H/VI:H/VA:H")) {
    throw new Error("Failed SQL Injection mapping test");
  }

  const xss = mapZapAlertToCvssVector("Medium", 79, "Cross Site Scripting");
  console.log("-> XSS (CWE-79):", xss);
  if (xss.owasp_category !== "A03:2021-Injection" || !xss.cvss_vector.includes("UI:A")) {
    throw new Error("Failed XSS mapping test");
  }

  const ssrf = mapZapAlertToCvssVector("High", 918, "Server Side Request Forgery");
  console.log("-> SSRF (CWE-918):", ssrf);
  if (ssrf.owasp_category !== "A10:2021-Server-Side Request Forgery" || !ssrf.cvss_vector.includes("SC:H")) {
    throw new Error("Failed SSRF mapping test");
  }

  const genericHigh = mapZapAlertToCvssVector("High", null, "Unknown High Risk Alert");
  console.log("-> Generic High Risk:", genericHigh);
  if (!genericHigh.cvss_vector.includes("VC:H/VI:H/VA:H")) {
    throw new Error("Failed generic High risk mapping test");
  }

  console.log("✅ All CVSS Vector Mapper tests PASSED.");

  // 2. Test Token Bucket Rate Limiter
  console.log("\n[Test 2] Testing Token Bucket Rate Limiter...");
  const bucket = new TokenBucket(3, 5); // capacity 3, 5 tokens/sec
  const startTime = Date.now();

  // Burst consume 3 tokens
  await bucket.take();
  await bucket.take();
  await bucket.take();
  console.log("-> Burst consumed 3 tokens immediately.");

  // 4th take should wait for refill (~200ms)
  await bucket.take();
  const elapsed = Date.now() - startTime;
  console.log(`-> 4th token waited for refill: ${elapsed}ms`);

  if (elapsed < 150) {
    throw new Error(`Rate limiter did not throttle properly. Elapsed: ${elapsed}ms`);
  }

  console.log("✅ Token Bucket Rate Limiter test PASSED.");

  console.log("\n==========================================");
  console.log("🎉 ALL WORKER MODULE TESTS PASSED (0 ERRORS)");
  console.log("==========================================");
}

runTests().catch((err) => {
  console.error("❌ Test failed:", err);
  process.exit(1);
});
