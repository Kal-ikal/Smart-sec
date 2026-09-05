// Skrip verifikasi akurasi calculate_cvss_v4() terhadap reference
// implementation resmi CVSS v4.0 (ae-cvss-calculator, {metaeffekt}).
//
// Cara pakai:
//   npm install ae-cvss-calculator
//   PSQL_DB=<nama_database> node verify_cvss_v4_accuracy.js
//
// PSQL_DB harus sudah memuat migrasi supabase/migrations/0001-0003
// (plus stand-in skema `auth` bila diuji di luar project Supabase asli).
// Secara default memakai koneksi `psql` sebagai user OS saat ini; set
// PSQL_CMD untuk menyesuaikan (mis. "psql" saja, atau "sudo -u postgres psql").
const { Cvss4P0 } = require("ae-cvss-calculator");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");

const PSQL_DB = process.env.PSQL_DB || "smartsec_test";
const PSQL_CMD = process.env.PSQL_CMD || "psql";

// Seeded PRNG (mulberry32) for reproducibility.
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(42);
function pick(arr) {
  return arr[Math.floor(rng() * arr.length)];
}

const AV = ["N", "A", "L", "P"];
const AC = ["L", "H"];
const AT = ["N", "P"];
const PR = ["N", "L", "H"];
const UI = ["N", "P", "A"];
const CIA = ["H", "L", "N"];

const N = 500;
const vectors = [];
for (let i = 0; i < N; i++) {
  const v = [
    "CVSS:4.0",
    `AV:${pick(AV)}`,
    `AC:${pick(AC)}`,
    `AT:${pick(AT)}`,
    `PR:${pick(PR)}`,
    `UI:${pick(UI)}`,
    `VC:${pick(CIA)}`,
    `VI:${pick(CIA)}`,
    `VA:${pick(CIA)}`,
    `SC:${pick(CIA)}`,
    `SI:${pick(CIA)}`,
    `SA:${pick(CIA)}`,
  ].join("/");
  vectors.push(v);
}

// 1. Reference scores via ae-cvss-calculator (official FIRST.org CVSS v4.0 spec impl)
const referenceScores = vectors.map((v) => {
  const c = new Cvss4P0(v);
  const s = c.calculateScores();
  return s.base;
});

// 2. SMART-SEC DB scores via calculate_cvss_v4(), batched in one SQL statement.
const valuesList = vectors
  .map((v, i) => `(${i}, '${v}')`)
  .join(",\n  ");

const sql = `
create temp table cvss_test_vectors(idx int, vector text);
insert into cvss_test_vectors (idx, vector) values
  ${valuesList};

select t.idx, t.vector, r.base_score
from cvss_test_vectors t, lateral public.calculate_cvss_v4(t.vector) r
order by t.idx;
`;

const sqlFile = path.join(os.tmpdir(), "cvss_test_batch.sql");
fs.writeFileSync(sqlFile, sql, { mode: 0o644 });
const output = execSync(
  `${PSQL_CMD} -d ${PSQL_DB} -At -F',' -f ${sqlFile}`,
  { maxBuffer: 1024 * 1024 * 50 }
).toString();

const lines = output.trim().split("\n").filter((l) => l.length > 0);
const dbScores = new Array(N);
for (const line of lines) {
  const firstComma = line.indexOf(",");
  const lastComma = line.lastIndexOf(",");
  const idx = parseInt(line.slice(0, firstComma), 10);
  const baseScore = parseFloat(line.slice(lastComma + 1));
  dbScores[idx] = baseScore;
}

// 3. Compare
let exactMatches = 0;
let within01 = 0;
const mismatches = [];
for (let i = 0; i < N; i++) {
  const ref = Math.round(referenceScores[i] * 10) / 10;
  const db = Math.round(dbScores[i] * 10) / 10;
  const diff = Math.abs(ref - db);
  if (diff === 0) exactMatches++;
  if (diff <= 0.1) within01++;
  else {
    mismatches.push({ vector: vectors[i], reference: ref, smartsec: db, diff: +diff.toFixed(2) });
  }
}

console.log("==========================================");
console.log(`SMART-SEC CVSS v4.0 Base Score vs Reference (ae-cvss-calculator / FIRST.org spec)`);
console.log(`Total test vectors: ${N}`);
console.log(`Exact match (0 selisih): ${exactMatches} (${((exactMatches / N) * 100).toFixed(1)}%)`);
console.log(`Match within tolerance floating-point (<=0.1): ${within01} (${((within01 / N) * 100).toFixed(1)}%)`);
console.log(`Mismatch (>0.1, bukan sekadar floating-point rounding): ${mismatches.length} (${((mismatches.length / N) * 100).toFixed(1)}%)`);
console.log("==========================================");

// Distribution of diffs for mismatches
const diffBuckets = {};
for (const m of mismatches) {
  const bucket = m.diff.toFixed(1);
  diffBuckets[bucket] = (diffBuckets[bucket] || 0) + 1;
}
console.log("\nDistribusi besar selisih (untuk yang > 0.1):");
console.log(diffBuckets);

console.log("\nContoh 15 mismatch pertama:");
console.log(mismatches.slice(0, 15));

const mismatchFile = path.join(__dirname, "mismatches_full.json");
fs.writeFileSync(mismatchFile, JSON.stringify(mismatches, null, 2));
console.log(`\n(Semua ${mismatches.length} mismatch disimpan ke ${mismatchFile})`);
