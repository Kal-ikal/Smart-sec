import fetch from "node-fetch";
import { config } from "../config.js";

export interface ZapAlert {
  pluginId: string;
  alertRef?: string;
  name: string;
  description: string;
  solution: string;
  risk: string; // "Informational" | "Low" | "Medium" | "High"
  evidence: string;
  cweid: string;
  reference?: string;
}

function zapUrl(endpoint: string, params: Record<string, string> = {}) {
  const url = new URL(`${config.zapApiUrl}${endpoint}`);
  if (config.zapApiKey) {
    url.searchParams.set("apikey", config.zapApiKey);
  }
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  return url.toString();
}

/**
 * Klien untuk OWASP ZAP REST API.
 * Worker hanya memicu spider + active scan dan polling status.
 * Data mentah diteruskan ke Supabase database, di mana Stored Procedure
 * mengeksekusi kalkulasi skor CVSS v4.0.
 */
export const zapClient = {
  async checkConnection(): Promise<boolean> {
    if (process.env.ZAP_MOCK === "true") {
      return true;
    }
    try {
      const res = await fetch(zapUrl("/JSON/core/view/version/"), { signal: AbortSignal.timeout(3000) });
      return res.ok;
    } catch {
      return false;
    }
  },

  async startSpider(targetUrl: string): Promise<string> {
    if (process.env.ZAP_MOCK === "true") {
      console.log(`[ZAP-SIMULATOR] Memulai simulasi Spider untuk target: ${targetUrl}`);
      return `mock-spider-${Date.now()}`;
    }
    const res = await fetch(zapUrl("/JSON/spider/action/scan/", { url: targetUrl }));
    if (!res.ok) {
      throw new Error(`ZAP Spider API error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { scan?: string; error?: string };
    if (!json.scan) {
      throw new Error(`ZAP Spider gagal diinisiasi: ${json.error ?? JSON.stringify(json)}`);
    }
    return json.scan;
  },

  async spiderStatus(scanId: string): Promise<number> {
    if (process.env.ZAP_MOCK === "true") {
      return 100;
    }
    const res = await fetch(zapUrl("/JSON/spider/view/status/", { scanId }));
    if (!res.ok) {
      throw new Error(`ZAP Spider Status error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { status: string };
    return Number(json.status);
  },

  async startActiveScan(targetUrl: string): Promise<string> {
    if (process.env.ZAP_MOCK === "true") {
      console.log(`[ZAP-SIMULATOR] Memulai simulasi Active Scan untuk target: ${targetUrl}`);
      return `mock-ascan-${Date.now()}`;
    }
    const res = await fetch(zapUrl("/JSON/ascan/action/scan/", { url: targetUrl }));
    if (!res.ok) {
      throw new Error(`ZAP Active Scan API error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { scan?: string; error?: string };
    if (!json.scan) {
      throw new Error(`ZAP Active Scan gagal diinisiasi: ${json.error ?? JSON.stringify(json)}`);
    }
    return json.scan;
  },

  async activeScanStatus(scanId: string): Promise<number> {
    if (process.env.ZAP_MOCK === "true") {
      return 100;
    }
    const res = await fetch(zapUrl("/JSON/ascan/view/status/", { scanId }));
    if (!res.ok) {
      throw new Error(`ZAP Active Scan Status error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { status: string };
    return Number(json.status);
  },

  async getAlerts(targetUrl: string): Promise<ZapAlert[]> {
    if (process.env.ZAP_MOCK === "true") {
      console.log(`[ZAP-SIMULATOR] Menghasilkan simulasi temuan kerentanan untuk: ${targetUrl}`);
      return [
        {
          pluginId: "40018",
          alertRef: "40018-1",
          name: "SQL Injection - Blind / Time Based",
          description: "Parameter rentan terhadap injeksi SQL yang memungkinkan ekstraksi basis data.",
          solution: "Gunakan parameterized queries (Prepared Statements) dan validasi input secara ketat.",
          risk: "High",
          evidence: "1' AND SLEEP(5)--",
          cweid: "89",
        },
        {
          pluginId: "40012",
          alertRef: "40012-1",
          name: "Cross-Site Scripting (Reflected XSS)",
          description: "Input pengguna direfleksikan langsung ke dokumen HTML tanpa sanitasi memadai.",
          solution: "Lakukan kontekstual output encoding dan terapkan Content Security Policy (CSP).",
          risk: "Medium",
          evidence: "<script>alert(1)</script>",
          cweid: "79",
        },
        {
          pluginId: "90034",
          alertRef: "90034-1",
          name: "Server-Side Request Forgery (SSRF)",
          description: "Peladen memproses URL eksternal yang memungkinkan akses ke metadata cloud internal.",
          solution: "Terapkan whitelist URL dan blokir akses ke alamat IP private/internal (RFC 1918).",
          risk: "High",
          evidence: "http://169.254.169.254/latest/meta-data/",
          cweid: "918",
        },
        {
          pluginId: "10038",
          alertRef: "10038-1",
          name: "Content Security Policy (CSP) Header Not Set",
          description: "Header respons HTTP Content-Security-Policy tidak ditemukan pada server.",
          solution: "Konfigurasikan header Content-Security-Policy pada server web.",
          risk: "Low",
          evidence: "Missing Header",
          cweid: "693",
        },
      ];
    }
    const res = await fetch(zapUrl("/JSON/core/view/alerts/", { baseurl: targetUrl }));
    if (!res.ok) {
      throw new Error(`ZAP Get Alerts error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { alerts?: ZapAlert[] };
    return json.alerts ?? [];
  },

  /** Polling helper generik dengan jeda tetap sampai status = 100. */
  async waitUntilComplete(
    checkStatus: () => Promise<number>,
    intervalMs = 3000
  ): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const status = await checkStatus();
      if (status >= 100) return;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  },
};
