import type { Page, Route } from "@playwright/test";

// Mocked API for the Overview v2 (contracts A and B): one function per scenario, used by e2e/overview-v2.spec.ts and by standalone screenshot scripts.
export type Scenario = "complete" | "slice" | "partial" | "failed" | "no_connection" | "not_synced";
const NOW = Date.now();
const HOUR = 3_600_000;

export function summary(scenario: Scenario, stress = false, value?: number) {
  const big = stress || scenario === "slice";
  const every = stress || value !== undefined; // one number everywhere, to see that any magnitude fits its box
  const total = value ?? (stress ? 16_693_578 : big ? 16_700_573 : 8_400);
  const p1 = value ?? (stress ? 16_693_578 : big ? 301_274 : 1_240);
  const state = scenario === "slice" ? "complete" : scenario;
  const noRead = scenario === "not_synced" || scenario === "no_connection";
  const asOf = scenario === "not_synced" || scenario === "no_connection" ? null : scenario === "failed" ? NOW - 8 * HOUR : NOW - 6 * 60_000;
  const held = big ? 1_085_590 : total;
  const sev = every ? { CRITICAL: total, HIGH: total, MEDIUM: total, LOW: total, NONE: total } : big ? { CRITICAL: 858_001, HIGH: 11_116_325, MEDIUM: 4_469_964, LOW: 256_147, NONE: 136 } : { CRITICAL: 120, HIGH: 4_200, MEDIUM: 3_000, LOW: 1_000, NONE: 80 };
  const facts = every ? { kev: total, exploited: total, exprtCritical: total } : big ? { kev: 115_944, exploited: 257_947, exprtCritical: 306_448 } : { kev: 140, exploited: 310, exprtCritical: 420 };
  return {
    tenant: { id: "t1", name: "Customer A" },
    completeness: {
      state, dataAsOf: asOf, lastRunAt: NOW - 5 * 60_000, reason: scenario === "failed" ? "cid_not_authorized" : null,
      coverage: { held: scenario === "partial" ? Math.round(total * 0.5) : held, falconTotal: total, priorityHeld: scenario === "partial" ? 120_000 : 1_085_590, priorityTotal: 1_085_590, priorityPass: scenario !== "partial", fullPass: !big && scenario !== "partial", scope: "all" },
      falconCounts: { total, critical: sev.CRITICAL, high: sev.HIGH, medium: sev.MEDIUM, low: sev.LOW, ...facts },
      cids: [],
    },
    hostsSync: { state: "complete", asOf: NOW - 20 * 60_000, lastRunAt: NOW - 20 * 60_000, hosts: 7_790 },
    headline: noRead ? undefined : {
      p1, p1Source: "held", p1Exact: scenario !== "partial", hostsWithP1: 4_126, hostsTotal: 7_790, hostShare: 0.5296, p1Cves: 1_412, p1Fixes: 214, internetP1Hosts: 38,
      level: { key: "high", base: "high", escalated: false, share: 0.5296, reasons: [] }, delta7: scenario === "complete" || scenario === "slice" ? { p1: -6_480, pct: -0.021, from: NOW - 7 * 24 * HOUR } : null,
    },
    hosts: { total: 7_790, source: "inventory", withFindings: 7_120, withP1: 4_126, neverSeenFindings: 670, stale7: 0, stale30: 0, duplicates: 0, staleTwins: 0, internetFacing: 311 },
    tiers: noRead ? undefined : {
      P1: { held: p1, total: p1, exact: true, source: "falcon+held", hosts: 4_126 },
      P2: { held: big ? 784_316 : 5_000, total: big ? 7_441_239 : 5_000, exact: true, source: "falcon", hosts: 6_011 },
      P3: { held: big ? 0 : 2_160, total: big ? 8_958_060 : 2_160, exact: true, source: "falcon", hosts: 0 },
      heldTotal: held, falconTotal: total, atLeast: false,
    },
    severity: noRead ? undefined : { ...sev, total, source: "falcon", endpointOnly: true, held: big ? { CRITICAL: sev.CRITICAL, HIGH: 120_000, MEDIUM: 90_000, LOW: 0, NONE: 0 } : sev },
    facts: { ...facts, internetP1: 1_200, kevOverdue: 14, source: "falcon" },
    external: { findings: 4_572, assets: 649 },
    freshness: {},
  };
}

const FIXES = ["ติดตั้งอัปเดตสะสม Windows 11 23H2 (KB5046617)", "Update Google Chrome to 131.0.6778.205", "Install Microsoft Office Security Update KB5002653", "Update Adobe Acrobat Reader DC to 24.005.20320", "Update Oracle Java SE 8 to Update 431", "Update VMware Tools to 12.4.5", "Update Mozilla Firefox to 133.0", "Update Microsoft Edge to 131.0.2903.86"];
const fixes = (stress: boolean, value?: number) => ({
  total: 214, totals: { fixes: 214, p1: 301_274, withKev: 61 },
  rows: FIXES.map((title, i) => ({
    id: String(1000 + i), title, product: title.split(" to ")[0].replace(/^(Update|Install) /, ""), noFix: false, p1: value ?? (stress ? 16_693_578 - i : 71_420 - i * 6_000), p2: 120, cves: 38 - i * 3, p1Cves: 30, kevCves: i < 3 ? 6 - i : 0,
    hosts: value ?? (stress ? 7_790 : 2_914 - i * 250), p1Hosts: 800, internetHosts: i % 2 ? 0 : 11, severity: i % 3 ? "HIGH" : "CRITICAL", exprt: "CRITICAL", impactShare: 0.12 - i * 0.01,
  })),
});
const hosts = (stress: boolean, value?: number) => ({
  total: 7_790, facets: { withP1: 4_126 },
  rows: ["BKK-DC-01", "BKK-WEB-014", "HKT-CTX-01", "เครื่องบัญชี-ฝ่ายขาย-07", "DMK-FS-02", "BKK-WS-3381"].map((h, i) => ({
    key: `a${i}`, aid: `a${i}`, hostname: h, platform: "Windows", osVersion: i % 2 ? "Windows Server 2022" : "Windows 11", productType: i % 2 ? "Server" : "Workstation", internetFacing: i === 1 || i === 2,
    p1: value ?? (stress ? 16_693_578 - i : 1_204 - i * 120), critical: value ?? 311 - i * 20, kevCves: value ?? 58 - i * 6, lastSeen: NOW - i * HOUR, stale: "fresh", worstSeverity: "CRITICAL", watched: i === 0,
  })),
});

export interface Opts { scenario: Scenario; stress?: boolean; value?: number; auth?: boolean; soc?: boolean; watchEmpty?: boolean }

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, json: body });

/** Routes every API call the Overview makes. `auth: true` also mocks the session and the organization list (standalone runs without the e2e server). */
export async function mockOverview(page: Page, o: Opts) {
  const stress = !!o.stress;
  const watched = [
    { aid: "a0", hostname: "BKK-DC-01", note: "ตัวควบคุมโดเมนหลัก รอ patch window 23 พ.ย.", addedBy: "Alice", addedAt: NOW - 86_400_000, worstSeverity: "CRITICAL", p1: stress ? 16_693_578 : 1_204, critical: 311, high: 5, newFindings24h: 14, newP1_24h: 14, newCritical24h: 14, kevCves: 5, lastSeen: NOW - HOUR, lastSynced: NOW, missing: false, external: false },
    { aid: "a2", hostname: "HKT-CTX-01", note: "vendor เข้าใช้งานจากภายนอก", worstSeverity: "CRITICAL", p1: 871, critical: 236, high: 3, newFindings24h: 0, newP1_24h: 0, newCritical24h: 0, lastSeen: NOW - 2 * HOUR, missing: false },
    { aid: "a9", hostname: "FIN-SAP-03", note: null, worstSeverity: "HIGH", p1: 212, critical: 0, high: 12, newP1_24h: 0, newCritical24h: 0, lastSeen: NOW, missing: false },
    { aid: "a8", hostname: "เครื่องเก่า-ถูกถอด", note: null, worstSeverity: null, p1: null, critical: null, high: null, newP1_24h: null, newCritical24h: null, lastSeen: null, missing: true },
  ];
  let wl = o.watchEmpty ? [] : watched;
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    const p = u.pathname;
    if (req.method() !== "GET") {
      if (p.startsWith("/api/exposure/watchlist/")) {
        const aid = decodeURIComponent(p.split("/").pop()!);
        if (req.method() === "DELETE") { wl = wl.filter((h) => h.aid !== aid); return json(route, { removed: true, count: wl.length }); }
        const body = req.postDataJSON() as { note?: string } | null;
        const host = { ...(watched.find((h) => h.aid === aid) ?? { aid, hostname: aid, worstSeverity: null, p1: null, critical: null, high: null, newP1_24h: null, newCritical24h: null, lastSeen: null, missing: false }), note: body?.note ?? null };
        wl = [...wl.filter((h) => h.aid !== aid), host];
        return json(route, { host, count: wl.length });
      }
      return route.continue();
    }
    if (o.auth) {
      if (p === "/api/auth/me") return json(route, { user: { id: "u1", email: "soc@example.com", name: "SOC", role: o.soc ? "super_admin" : "member", soc: !!o.soc, manager: true, tenants: [{ id: "t1", name: "Customer A", role: "admin" }], totpEnabled: false } });
      if (p === "/api/tenants") return json(route, { tenants: [{ id: "t1", name: "Customer A", role: o.soc ? "super_admin" : "admin" }, ...(o.soc ? [{ id: "t2", name: "Siam Retail Group", role: "super_admin" }] : [])] });
    }
    switch (p) {
      case "/api/exposure/v2/summary": return json(route, summary(o.scenario, stress, o.value));
      case "/api/exposure/v2/trend": {
        const days = Number(u.searchParams.get("days") ?? 30);
        const base = stress ? 16_700_000 : 330_000;
        const points = o.scenario === "not_synced" ? [] : Array.from({ length: days }, (_, i) => ({ day: new Date(NOW - (days - 1 - i) * 86_400_000).toISOString().slice(0, 10), p1: Math.round(base - i * (base / 400) + Math.sin(i) * base / 100) }));
        return json(route, { days, since: "", startedAt: points[0]?.day ?? null, points, week: { newP1: 18_210, closedP1: 24_690, net: -6_480 } });
      }
      case "/api/exposure/v2/fixes": return json(route, fixes(stress, o.value));
      case "/api/exposure/v2/hosts": return json(route, hosts(stress, o.value));
      case "/api/exposure/watchlist": return json(route, { tenant: { id: "t1", name: "Customer A" }, limit: 200, canEdit: true, completeness: { state: o.scenario === "failed" ? "failed" : "complete" }, hosts: wl, suggestions: wl.length ? undefined : [{ aid: "a0", hostname: "BKK-DC-01", p1: 1204 }, { aid: "a1", hostname: "BKK-WEB-014", p1: 986 }], auto: [
        { type: "kev_added", cve: "CVE-2025-6218", title: "WinRAR path traversal", devices: 312, severity: "CRITICAL", at: NOW - 2 * HOUR },
        { type: "critical_new", findings: 41, devices: 9, severity: "CRITICAL", at: NOW - 5 * HOUR },
        { type: "cve_news", cve: "CVE-2025-31324", title: "SAP NetWeaver", state: "possible", devices: 3, severity: "HIGH", at: NOW - 20 * HOUR },
      ] });
      case "/api/exposure/software": return json(route, { rows: ["Windows 11", "Google Chrome", "Microsoft Office", "Oracle Java SE 8", "Acrobat Reader DC", "VMware Tools"].map((n, i) => ({ key: `s${i}`, type: "application", vendor: ["Microsoft", "Google", "Microsoft", "Oracle", "Adobe", "VMware"][i], name: n, devices: stress ? 16_693_578 : 3_774 - i * 500, versions: 6 - (i % 4) })), total: 2_276_831, devices: 7_790, byType: [], completeness: { state: o.scenario === "failed" ? "failed" : "complete", dataAsOf: NOW - 3 * 86_400_000 } });
      case "/api/exposure/easm": return json(route, { state: "complete", asOf: NOW - 3_600_000, lastRunAt: NOW, assets: { ips: 412, rootDomains: 38, subdomains: 199 }, online: { online: 371 }, reviewIps: { reviewed: 400, notReviewed: 12 }, reviewRootDomains: { reviewed: 150, notReviewed: 75 } });
      case "/api/exposure/easm/services": return json(route, { assetsWithServices: 322, services: 759, expiredCerts: 140, expiringCerts30: 1, riskyPorts: 15, assetsWithRiskyPorts: 9, newLast7d: 14 });
      case "/api/exposure/easm/assets": return json(route, { total: 649, items: [
        { id: "e1", name: "vpn.example-airline.com", type: "dns_domain", reviewed: false, isNew: true, ports: [443, 8443], riskyPorts: [], expiredCerts: 1, findings: { count: 4, worstSeverity: "CRITICAL" } },
        { id: "e2", name: "203.0.113.40", type: "ip", reviewed: true, isNew: false, ports: [], riskyPorts: [], expiredCerts: 0, findings: { count: 1, worstSeverity: "HIGH" } },
        { id: "e3", name: "mail.example-airline.com", type: "dns_domain", reviewed: true, isNew: false, ports: [25, 443], riskyPorts: [25], expiredCerts: 0, findings: { count: 2, worstSeverity: "MEDIUM" } },
      ] });
      case "/api/exposure/news": return json(route, { total: 4, counts: { exact: 1, possible: 1, wait: 1, not_affected: 1 }, items: [
        { cve: "CVE-2025-6218", title: "WinRAR path traversal ถูกใช้โจมตีจริง", state: "exact", devices: 312, severity: "CRITICAL", kev: true, publishedAt: NOW - 2 * HOUR, lastChanged: NOW - 2 * HOUR },
        { cve: "CVE-2025-31324", title: "SAP NetWeaver unauthenticated upload", state: "possible", devices: 3, severity: null, kev: true, publishedAt: NOW - 20 * HOUR, lastChanged: NOW - 20 * HOUR },
        { cve: "CVE-2025-59287", title: "Windows Server Update Service RCE", state: "wait", devices: 0, severity: null, kev: true, publishedAt: NOW - 2 * 86_400_000, lastChanged: NOW - 2 * 86_400_000 },
        { cve: "CVE-2025-53770", title: "SharePoint Server RCE", state: "not_affected", devices: 0, severity: null, kev: true, publishedAt: NOW - 5 * 86_400_000, lastChanged: NOW - 5 * 86_400_000 },
      ] });
      case "/api/exposure/portfolio": return json(route, portfolio());
    }
    return o.auth ? json(route, {}, 404) : route.continue();
  });
}

function portfolio() {
  const run = (states: string[]) => states.map((s, i) => ({ at: NOW - (states.length - i) * HOUR, state: s, ms: 30_000 }));
  const t = (o: object) => ({ reason: null, asOf: NOW - 10 * 60_000, lastRunAt: NOW, ageHours: 0.2, stale: false, p1: 0, p1Delta7: null, p1Spark: null, hostsWithP1: 0, hosts: 0, hostShare: 0, level: "low", critical: 0, kevNew7d: 0, p1Overdue: 0, easmPendingReview: 0, mode: "full", heldShare: 1, sync24h: [], attention: [], ...o });
  return {
    generatedAt: NOW,
    summary: { tenants: 4, byState: { complete: 2, partial: 1, failed: 1 }, kevNew7d: 5, p1Overdue: 2, stale: 1 },
    tenants: [
      t({ id: "t9", name: "TENFORWARD (ภายใน)", state: "failed", reason: "cid_not_authorized", stale: true, ageHours: 8, asOf: NOW - 8 * HOUR, p1: 2_140, hostsWithP1: 0, hosts: 214, critical: 6_310, sync24h: run(Array(24).fill("failed")), attention: ["broken_connection"] }),
      t({ id: "t2", name: "Siam Retail Group", state: "complete", p1: 8_412, p1Delta7: 540, p1Spark: [7_800, 7_900, 8_100, 8_412], hostsWithP1: 612, hosts: 2_140, hostShare: 0.29, level: "medium", critical: 14_980, kevNew7d: 3, p1Overdue: 612, easmPendingReview: 12, sync24h: run(Array(24).fill("complete")), attention: ["kev_new", "p1_overdue"] }),
      t({ id: "t1", name: "Customer A", state: "complete", mode: "priority", heldShare: 0.065, p1: 301_274, p1Delta7: -6_480, p1Spark: [320_000, 310_000, 301_274], hostsWithP1: 4_126, hosts: 7_790, hostShare: 0.53, level: "high", critical: 858_001, kevNew7d: 2, p1Overdue: 38_420, easmPendingReview: 87, sync24h: run(Array(24).fill("complete")), attention: ["kev_new", "p1_overdue"] }),
      t({ id: "t3", name: "Lanna Health Network", state: "partial", p1: 1_206, hostsWithP1: 88, hosts: 460, hostShare: 0.19, level: "medium", critical: 3_455, sync24h: run(["complete", "partial", "partial"]), attention: ["partial"] }),
    ],
    attention: [
      { tenantId: "t9", name: "TENFORWARD (ภายใน)", reasons: ["broken_connection"], detail: { ageHours: 8 } },
      { tenantId: "t2", name: "Siam Retail Group", reasons: ["kev_new", "p1_overdue"], detail: { kevNew7d: 3, p1Overdue: 612 } },
      { tenantId: "t1", name: "Customer A", reasons: ["kev_new", "p1_overdue"], detail: { kevNew7d: 2, p1Overdue: 38_420 } },
      { tenantId: "t3", name: "Lanna Health Network", reasons: ["partial"], detail: {} },
    ],
    sharedCves: [
      { cveId: "CVE-2025-6218", kev: true, tenants: 2, hosts: 389, severity: "CRITICAL", exprt: "CRITICAL" },
      { cveId: "CVE-2025-31324", kev: true, tenants: 2, hosts: 9, severity: "CRITICAL", exprt: "HIGH" },
    ],
  };
}
