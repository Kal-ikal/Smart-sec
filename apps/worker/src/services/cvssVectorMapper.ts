/**
 * SMART-SEC | cvssVectorMapper.ts
 *
 * PENTING (SHIFT-COMPUTATION INVARIANT):
 * Modul ini HANYA memetakan temuan ZAP (CWE-ID, Risk rating, dan Alert Name)
 * ke dalam:
 *   1. String vektor CVSS v4.0 (mis. "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
 *   2. Kategori OWASP Top 10:2021 (mis. "A03:2021-Injection")
 *
 * Modul ini TIDAK PERNAH menghitung skor numerik (Base/Threat/Env/Composite).
 * Kalkulasi skor numerik dieksekusi 100% oleh PostgreSQL Stored Procedure & Trigger
 * di database (0003_cvss_trigger_stub.sql / calculate_cvss_v4).
 */

export interface MappedVulnerabilityMetadata {
  cvss_vector: string;
  owasp_category: string;
}

interface CweMappingRule {
  owaspCategory: string;
  av: "N" | "A" | "L" | "P";
  ac: "L" | "H";
  at: "N" | "P";
  pr: "N" | "L" | "H";
  ui: "N" | "P" | "A";
  vc: "H" | "L" | "N";
  vi: "H" | "L" | "N";
  va: "H" | "L" | "N";
  sc: "H" | "L" | "N";
  si: "H" | "L" | "N";
  sa: "H" | "L" | "N";
}

/**
 * Pemetaan representatif CWE -> CVSS v4.0 Metrics & OWASP Top 10:2021
 */
const CWE_RULES: Record<number, CweMappingRule> = {
  // SQL Injection / Command Injection
  89: {
    owaspCategory: "A03:2021-Injection",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "H", va: "H",
    sc: "N", si: "N", sa: "N",
  },
  77: {
    owaspCategory: "A03:2021-Injection",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "H", va: "H",
    sc: "H", si: "H", sa: "H",
  },
  78: {
    owaspCategory: "A03:2021-Injection",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "H", va: "H",
    sc: "H", si: "H", sa: "H",
  },
  // Cross-Site Scripting (XSS)
  79: {
    owaspCategory: "A03:2021-Injection",
    av: "N", ac: "L", at: "N", pr: "N", ui: "A",
    vc: "L", vi: "L", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Path Traversal / LFI
  22: {
    owaspCategory: "A01:2021-Broken Access Control",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Cross-Site Request Forgery (CSRF)
  352: {
    owaspCategory: "A01:2021-Broken Access Control",
    av: "N", ac: "L", at: "N", pr: "N", ui: "A",
    vc: "N", vi: "H", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Broken Authentication / Default Credentials
  287: {
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "H", va: "H",
    sc: "N", si: "N", sa: "N",
  },
  306: {
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "H", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Server-Side Request Forgery (SSRF)
  918: {
    owaspCategory: "A10:2021-Server-Side Request Forgery",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "L", va: "N",
    sc: "H", si: "N", sa: "N",
  },
  // Information Exposure
  200: {
    owaspCategory: "A01:2021-Broken Access Control",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "L", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Security Misconfiguration / Missing Headers
  16: {
    owaspCategory: "A05:2021-Security Misconfiguration",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "L", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  693: {
    owaspCategory: "A05:2021-Security Misconfiguration",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "L", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  // Cryptographic Failures / Insecure Transport
  319: {
    owaspCategory: "A02:2021-Cryptographic Failures",
    av: "N", ac: "L", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
  327: {
    owaspCategory: "A02:2021-Cryptographic Failures",
    av: "N", ac: "H", at: "N", pr: "N", ui: "N",
    vc: "H", vi: "N", va: "N",
    sc: "N", si: "N", sa: "N",
  },
};

type ZapRisk = "Informational" | "Low" | "Medium" | "High";

const IMPACT_BY_RISK: Record<ZapRisk, "N" | "L" | "H"> = {
  Informational: "N",
  Low: "L",
  Medium: "L",
  High: "H",
};

/**
 * Memetakan ZAP Alert menjadi CVSS:4.0 Vector string dan kategori OWASP
 */
export function mapZapAlertToCvssVector(
  riskZap: string,
  cweId?: number | null,
  alertName?: string
): MappedVulnerabilityMetadata {
  // 1. Jika CWE ID dikenali dalam rules, gunakan profil spesifik CWE
  if (cweId && cweId in CWE_RULES) {
    const rule = CWE_RULES[cweId];
    const vector = [
      "CVSS:4.0",
      `AV:${rule.av}`,
      `AC:${rule.ac}`,
      `AT:${rule.at}`,
      `PR:${rule.pr}`,
      `UI:${rule.ui}`,
      `VC:${rule.vc}`,
      `VI:${rule.vi}`,
      `VA:${rule.va}`,
      `SC:${rule.sc}`,
      `SI:${rule.si}`,
      `SA:${rule.sa}`,
    ].join("/");

    return {
      cvss_vector: vector,
      owasp_category: rule.owaspCategory,
    };
  }

  // 2. Fallback heuristik berbasis ZAP Risk Rating
  const validRisk: ZapRisk =
    riskZap in IMPACT_BY_RISK ? (riskZap as ZapRisk) : "Low";
  const impact = IMPACT_BY_RISK[validRisk];

  // Heuristik kategori OWASP dari nama alert
  let category = "A05:2021-Security Misconfiguration";
  const lowerName = (alertName ?? "").toLowerCase();

  if (lowerName.includes("sql") || lowerName.includes("injection") || lowerName.includes("xss")) {
    category = "A03:2021-Injection";
  } else if (lowerName.includes("auth") || lowerName.includes("password") || lowerName.includes("session")) {
    category = "A07:2021-Identification and Authentication Failures";
  } else if (lowerName.includes("ssl") || lowerName.includes("tls") || lowerName.includes("crypto") || lowerName.includes("cookie")) {
    category = "A02:2021-Cryptographic Failures";
  } else if (lowerName.includes("access") || lowerName.includes("traversal") || lowerName.includes("csrf")) {
    category = "A01:2021-Broken Access Control";
  } else if (lowerName.includes("ssrf")) {
    category = "A10:2021-Server-Side Request Forgery";
  }

  const vector = [
    "CVSS:4.0",
    "AV:N",
    "AC:L",
    "AT:N",
    "PR:N",
    "UI:N",
    `VC:${impact}`,
    `VI:${impact}`,
    `VA:${impact}`,
    "SC:N",
    "SI:N",
    "SA:N",
  ].join("/");

  return {
    cvss_vector: vector,
    owasp_category: category,
  };
}

/** Backward compatibility helper */
export function buildDraftCvssVector(zapRisk: string): string {
  return mapZapAlertToCvssVector(zapRisk).cvss_vector;
}
