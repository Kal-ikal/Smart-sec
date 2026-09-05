// Lihat header verify_cvss_v4_accuracy.js untuk cara pakai. Skrip ini
// menambahkan cakupan E (threat), CR/IR/AR (environmental requirements),
// dan metric M* (modified base) secara acak.
const { Cvss4P0 } = require("ae-cvss-calculator");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const PSQL_DB = process.env.PSQL_DB || "smartsec_test";
const PSQL_CMD = process.env.PSQL_CMD || "psql";

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rng = mulberry32(1337);
function pick(arr) { return arr[Math.floor(rng() * arr.length)]; }
function maybe(prob) { return rng() < prob; }

const AV = ["N", "A", "L", "P"], AC = ["L", "H"], AT = ["N", "P"], PR = ["N", "L", "H"], UI = ["N", "P", "A"];
const CIA = ["H", "L", "N"];
const E = ["X", "A", "P", "U"];
const CIAR = ["X", "H", "M", "L"];
const MCIA = ["X", "H", "L", "N"];
const MSI_SA = ["X", "S", "H", "L", "N"];

const N = 300;
const vectors = [];
for (let i = 0; i < N; i++) {
  const parts = [
    "CVSS:4.0",
    `AV:${pick(AV)}`, `AC:${pick(AC)}`, `AT:${pick(AT)}`, `PR:${pick(PR)}`, `UI:${pick(UI)}`,
    `VC:${pick(CIA)}`, `VI:${pick(CIA)}`, `VA:${pick(CIA)}`,
    `SC:${pick(CIA)}`, `SI:${pick(CIA)}`, `SA:${pick(CIA)}`,
  ];
  // 50% chance to add E
  if (maybe(0.5)) parts.push(`E:${pick(E)}`);
  // 50% chance to add environmental requirements
  if (maybe(0.5)) {
    parts.push(`CR:${pick(CIAR)}`, `IR:${pick(CIAR)}`, `AR:${pick(CIAR)}`);
  }
  // 40% chance to add some M-modified metrics
  if (maybe(0.4)) {
    if (maybe(0.5)) parts.push(`MAV:${pick(["X",...AV])}`);
    if (maybe(0.5)) parts.push(`MVC:${pick(MCIA)}`);
    if (maybe(0.5)) parts.push(`MSI:${pick(MSI_SA)}`);
    if (maybe(0.5)) parts.push(`MSA:${pick(MSI_SA)}`);
  }
  vectors.push(parts.join("/"));
}

const referenceScores = vectors.map((v) => {
  const c = new Cvss4P0(v);
  const s = c.calculateScores();
  return s.overall; // overall = fully composed score with all overlays applied
});

const valuesList = vectors.map((v, i) => `(${i}, '${v.replace(/'/g, "''")}')`).join(",\n  ");
const sql = `
create temp table cvss_full_test_vectors(idx int, vector text);
insert into cvss_full_test_vectors (idx, vector) values
  ${valuesList};

select t.idx, t.vector, r.composite_score
from cvss_full_test_vectors t, lateral public.calculate_cvss_v4(t.vector) r
order by t.idx;
`;
const os = require("os");
const sqlFile = path.join(os.tmpdir(), "cvss_full_test_batch.sql");
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
  dbScores[idx] = parseFloat(line.slice(lastComma + 1));
}

let exact = 0;
const mismatches = [];
for (let i = 0; i < N; i++) {
  const ref = Math.round(referenceScores[i] * 10) / 10;
  const db = Math.round(dbScores[i] * 10) / 10;
  if (Math.abs(ref - db) < 0.05) exact++;
  else mismatches.push({ vector: vectors[i], reference: ref, smartsec: db, diff: +(ref - db).toFixed(2) });
}

console.log(`Full vector test (with E/CR/IR/AR/M-metrics), N=${N}`);
console.log(`Match (composite_score vs overall): ${exact} (${((exact / N) * 100).toFixed(1)}%)`);
console.log(`Mismatches: ${mismatches.length}`);
console.log(mismatches.slice(0, 20));
