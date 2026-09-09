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
 * ZAP mencatat node root sebuah domain di Sites Tree dengan trailing slash
 * (mis. "http://host.com/"). Memanggil Active Scan dengan URL domain polos
 * (tanpa slash) gagal dengan "url_not_found: URL Not Found in the Scan Tree"
 * meskipun Spider pada domain yang sama berhasil -- normalisasi di sini
 * memastikan Spider dan Active Scan selalu memakai bentuk URL yang identik.
 */
function normalizeTargetUrl(targetUrl: string): string {
  const parsed = new URL(targetUrl);
  if (parsed.pathname === "") {
    parsed.pathname = "/";
  }
  return parsed.toString();
}

/**
 * Klien REST API OWASP ZAP untuk eksekusi Active Scan & Spidering.
 */
export const zapClient = {
  /**
   * Menaikkan paralelisme internal ZAP (jumlah thread spider & active
   * scan per host, delay antar-request di sisi ZAP dinolkan) -- ini
   * TIDAK mengurangi jumlah payload/kedalaman uji yang dijalankan ZAP,
   * hanya mempercepat berapa banyak yang dijalankan bersamaan. Rate
   * limiting etis terhadap target tetap sepenuhnya dijaga oleh Token
   * Bucket pada worker (lihat jobProcessor.ts), bukan oleh pengaturan
   * ini -- keduanya independen.
   */
  async optimizeForSpeed(): Promise<void> {
    if (process.env.ZAP_MOCK === "true") return;
    try {
      await fetch(zapUrl("/JSON/spider/action/setOptionThreadCount/", { Integer: "10" }));
      await fetch(zapUrl("/JSON/ascan/action/setOptionThreadPerHost/", { Integer: "10" }));
      await fetch(zapUrl("/JSON/ascan/action/setOptionDelayInMs/", { Integer: "0" }));
      // Batasi kedalaman/lebar Spider -- mencegah crawl tak terkendali ke
      // seluruh sub-halaman situs besar (mis. Firing Range punya 18+
      // kategori uji terpisah); Active Scan tetap menguji setiap URL yang
      // ditemukan secara menyeluruh, hanya jumlah URL yang dibatasi.
      await fetch(zapUrl("/JSON/spider/action/setOptionMaxDepth/", { Integer: "3" }));
      await fetch(zapUrl("/JSON/spider/action/setOptionMaxChildren/", { Integer: "10" }));
      // Batas waktu keras per Active Scan -- ZAP otomatis menghentikan diri
      // setelah durasi ini meski belum 100% tuntas, mencegah satu job
      // menyandera antrean tanpa batas waktu (praktik lazim: time-boxed
      // security scan pada pipeline CI/CD).
      await fetch(zapUrl("/JSON/ascan/action/setOptionMaxScanDurationInMins/", {
        Integer: String(config.zapMaxScanDurationMins),
      }));
      console.log(`[ZAP-CLIENT] ⚡ Paralelisme dinaikkan, spider dibatasi, durasi maksimal Active Scan ${config.zapMaxScanDurationMins} menit.`);
    } catch (err) {
      console.warn(`[ZAP-CLIENT] ⚠️ Gagal menerapkan pengaturan kecepatan ZAP (non-fatal):`, err instanceof Error ? err.message : String(err));
    }
  },

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

  /**
   * Eksekusi Active Scan pada peladen target via OWASP ZAP REST API.
   */
  async eksekusiActiveScan(targetUrl: string): Promise<string> {
    if (process.env.ZAP_MOCK === "true") {
      console.log(`[ZAP-SIMULATOR] Memulai simulasi Active Scan untuk target: ${targetUrl}`);
      return `mock-ascan-${Date.now()}`;
    }

    targetUrl = normalizeTargetUrl(targetUrl);

    // 1. Jalankan Spider terlebih dahulu
    console.log(`[ZAP-CLIENT] Memulai Spider scan untuk target: ${targetUrl}`);
    const spiderRes = await fetch(zapUrl("/JSON/spider/action/scan/", { url: targetUrl }));
    if (!spiderRes.ok) {
      throw new Error(`ZAP Spider API error (${spiderRes.status}): ${await spiderRes.text()}`);
    }
    const spiderJson = (await spiderRes.json()) as { scan?: string; error?: string };
    if (!spiderJson.scan) {
      throw new Error(`ZAP Spider gagal diinisiasi: ${spiderJson.error ?? JSON.stringify(spiderJson)}`);
    }

    await this.waitUntilComplete(async () => {
      const res = await fetch(zapUrl("/JSON/spider/view/status/", { scanId: spiderJson.scan! }));
      const json = (await res.json()) as { status: string };
      return Number(json.status);
    });

    // 2. Jalankan Active Scan
    console.log(`[ZAP-CLIENT] Memulai Active Scan untuk target: ${targetUrl}`);
    const res = await fetch(zapUrl("/JSON/ascan/action/scan/", { url: targetUrl }));
    if (!res.ok) {
      throw new Error(`ZAP Active Scan API error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { scan?: string; error?: string };
    if (!json.scan) {
      throw new Error(`ZAP Active Scan gagal diinisiasi: ${json.error ?? JSON.stringify(json)}`);
    }

    const activeScanId = json.scan;
    await this.waitUntilComplete(async () => {
      const statusRes = await fetch(zapUrl("/JSON/ascan/view/status/", { scanId: activeScanId }));
      const statusJson = (await statusRes.json()) as { status: string };
      return Number(statusJson.status);
    });

    return activeScanId;
  },

  async getAlerts(targetUrl: string): Promise<ZapAlert[]> {
    if (process.env.ZAP_MOCK === "true") {
      console.log(`[ZAP-SIMULATOR] Menghasilkan temuan simulasi untuk: ${targetUrl}`);
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
      ];
    }
    const res = await fetch(zapUrl("/JSON/core/view/alerts/", { baseurl: normalizeTargetUrl(targetUrl) }));
    if (!res.ok) {
      throw new Error(`ZAP Get Alerts error (${res.status}): ${await res.text()}`);
    }
    const json = (await res.json()) as { alerts?: ZapAlert[] };
    return json.alerts ?? [];
  },

  async waitUntilComplete(
    checkStatus: () => Promise<number>,
    intervalMs = 3000
  ): Promise<void> {
    if (process.env.ZAP_MOCK === "true") {
      return;
    }
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const status = await checkStatus();
      if (status >= 100) return;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  },
};
