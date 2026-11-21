import type { Page, Route } from "@playwright/test";

// Mock of /api/exposure/graph* at the shape and scale of the real tenant (7,790 hosts, 214 fixes, 57 groups, ~420 products, 1,085,590 rows held),
// following api-v2-contract-A.md section 8. The server aggregates; this mock returns only what the contract allows (<= 20 left nodes, <= 12 hosts).
const rng = (seed: number) => () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const R = rng(20261120);

const PRODUCTS = ["Microsoft Windows 11 23H2", "Microsoft Windows Server 2022", "Google Chrome", "Microsoft Windows Server 2019", "Microsoft Windows Server 2016", "Microsoft Windows 10 22H2", "7-Zip", "Microsoft Edge", "Apache Tomcat", "Oracle Java SE 8", "OpenSSL", "Microsoft .NET Framework 4.8", "Mozilla Firefox", "Adobe Acrobat Reader DC", "Microsoft Office 2019", "VMware Tools"];
export const FIXES = Array.from({ length: 214 }, (_, i) => {
  const p = i < PRODUCTS.length ? PRODUCTS[i] : `Vendor${i} Agent ${1 + (i % 14)}`;
  const label = /Windows/.test(p) ? `Apply KB${5030000 + i * 137} (${p.replace("Microsoft ", "")})` : `Update ${p} to ${1 + (i % 24)}.${i % 9}.${i % 300} or later`;
  return { id: String(184467440000 + i), label, product: p, findings: Math.round(5900 * Math.pow(0.86, i) + 3), hosts: Math.round(1700 * Math.pow(0.88, i) + 2) };
});
export const GROUPS = ["Servers-DC-BKK", "Workstations-HQ", "Workstations-DMK", "Servers-App", "Call-Center", "Airport-Ops", "Servers-DR", "Finance", ...Array.from({ length: 32 }, (_, i) => `Branch-${String(i + 1).padStart(2, "0")}`)];
const GSIZE = GROUPS.map((_, i) => Math.round(1362 * Math.pow(0.8, i) + 60));
export const OS = ["Windows Server 2022", "Windows 11 23H2", "Windows 10 22H2", "Windows Server 2019", "RHEL 9.4", "Ubuntu 22.04"];
const CVES = Array.from({ length: 60 }, (_, i) => ({ id: `CVE-${2019 + (i % 7)}-${10000 + i * 391}`, sev: ["CRITICAL", "HIGH", "CRITICAL", "MEDIUM"][i % 4], kev: i % 3 === 0, tier: i % 5 === 4 ? "P2" : "P1" }));
const HOSTS = Array.from({ length: 80 }, (_, i) => ({ aid: `aid${String(i).padStart(30, "0")}`, name: `${i % 3 ? "PC" : "SRV"}-${GROUPS[i % 8].slice(0, 6).toUpperCase()}-${String(i).padStart(3, "0")}` }));
export const FIRST_CVE = CVES[0].id, FIRST_HOST = HOSTS[0];

const completeness = (state = "complete") => ({
  state, dataAsOf: Date.now() - 3_600_000, lastRunAt: Date.now() - 3_000_000, reason: null,
  coverage: { held: 1_085_590, falconTotal: 16_700_573, priorityHeld: 1_085_590, priorityTotal: 1_085_590, priorityPass: true, fullPass: true, scope: "all", keptTotal: 16_700_573 },
});

export interface Mode { state?: string; calls: string[]; delayMs?: number }

/** The filters a call carries, and what they do to the numbers (enough for the page to react: KEV and internet shrink the set, a group switches the right column to hosts). */
function shrink(q: URLSearchParams) {
  const two = (q.get("tier") ?? "P1").includes("P2");
  return { two, f: (q.get("kev") ? 0.4 : 1) * (q.get("internet") ? 0.2 : 1) * (two ? 1.5 : 1), value: q.get("group") ?? q.get("os") ?? q.get("site"), empty: q.get("group") === "Empty-Group" };
}

function graph(q: URLSearchParams) {
  const { two, f, value, empty } = shrink(q);
  const lens = q.get("lens");
  if (lens === "matrix") {
    const rows = FIXES.slice(0, 12).map((x) => ({ id: x.product, label: x.product, hosts: Math.round(x.hosts * f), findings: Math.round(x.findings * f), fix: { id: x.id, title: x.label }, cells: [...Array(9)].map((_, c) => Math.round(Math.max(0, x.hosts * f * Math.pow(0.55, c) * (0.6 + R() * 0.8) * (c === 8 ? 2 : 1)))) }));
    return { lens, by: q.get("by") ?? "group", totals: { hosts: Math.round(4126 * f), findings: Math.round(301274 * f), products: 420 },
      cols: GROUPS.slice(0, 8).map((g, i) => ({ id: g, label: g, hosts: Math.round(GSIZE[i] * 0.8), total: GSIZE[i] })), colOther: { count: 32, hosts: 3000, total: 4200 }, rows, rowsOther: { count: 408 }, completeness: completeness() };
  }
  if (lens === "focus") {
    const type = q.get("type")!, id = q.get("id")!;
    const hosts = Math.round(800 * f);
    const common = { lens, type, totals: { hosts }, mode: value ? "host" : "dim",
      right: value ? HOSTS.slice(0, 12).map((h, i) => ({ id: h.aid, label: h.name, sub: `${value} · ${OS[i % 6]}`, n: 40 - i * 3, inet: i % 5 === 0 })) : GROUPS.slice(0, 8).map((g, i) => ({ id: g, label: g, hosts: Math.round(300 * Math.pow(0.7, i) * f), total: GSIZE[i] })),
      rightOther: { count: value ? 700 : 32, hosts: 900, n: 5000, total: 900 }, completeness: completeness() };
    if (type === "host") {
      const h = HOSTS.find((x) => x.aid === id) ?? HOSTS[0];
      return { lens, type, totals: { hosts: 1 }, center: { id: h.aid, label: h.name, sub: `Servers-DC-BKK · ${OS[0]}`, hosts: 1, findings: Math.round(120 * f), inet: true }, left: FIXES.slice(0, 10).map((x, i) => ({ kind: "fix", id: x.id, label: x.label, sub: x.product, n: 30 - i * 2 })), leftOther: { count: 14, n: 90 }, completeness: completeness() };
    }
    if (type === "cve") {
      const c = CVES.find((x) => x.id === id) ?? CVES[0];
      return { ...common, center: { id: c.id, label: c.id, sub: FIXES[0].product, hosts, findings: hosts, cves: 1, kev: c.kev, inetHosts: 14, sev: c.sev, exprt: "CRITICAL", tier: c.tier },
        left: [{ kind: "product", id: FIXES[0].product, label: FIXES[0].product, sub: "ผลิตภัณฑ์", n: hosts }, { kind: "fix", id: FIXES[0].id, label: FIXES[0].label, sub: "วิธีแก้", n: hosts }] };
    }
    const fx = FIXES.find((x) => x.id === id || x.product === id) ?? FIXES[0];
    return { ...common, center: { id: fx.id, label: type === "product" ? fx.product : fx.label, sub: fx.product, hosts, findings: Math.round(fx.findings * f), cves: 12, kev: 9, inetHosts: 14 },
      left: CVES.slice(0, 12).map((c, i) => ({ kind: "cve", id: c.id, label: c.id, sub: fx.product, n: 700 - i * 40, sev: c.sev, kev: c.kev })), leftOther: { count: 31, n: 900 } };
  }
  // lens=fix
  const top = q.get("top") === "20" ? 20 : 10;
  const left = FIXES.slice(0, top).map((x) => { const fnd = Math.round(x.findings * f); const p1 = two ? Math.round(fnd * 0.6) : fnd; return { id: x.id, label: x.label, product: x.product, hosts: Math.round(x.hosts * f), findings: fnd, p1, p2: fnd - p1, kev: Math.round(fnd * 0.01), inet: Math.round(x.hosts * f * 0.05) }; });
  const base = { lens, by: q.get("by") ?? "group", totals: { hosts: Math.round(4126 * f), findings: Math.round(301274 * f), fixes: 178 }, left, leftOther: { count: 214 - top, findings: 120000, p1: 110000 }, completeness: completeness() };
  if (empty) return { ...base, totals: { hosts: 0, findings: 0, fixes: 0 }, left: [], leftOther: null, right: [], links: [] };
  if (value) {
    return { ...base, mode: "host", right: HOSTS.slice(0, 12).map((h, i) => ({ id: h.aid, label: h.name, sub: `${value} · ${OS[i % 6]}`, n: 60 - i * 4, inet: i % 6 === 0 })), rightOther: { count: 1350, n: 9000 },
      links: left.flatMap((_, li) => [0, 1, 2, 3].map((k) => [li, (li * 3 + k * 5) % 12, 1] as [number, number, number]).concat([[li, 12, 40]])) };
  }
  const right = GROUPS.slice(0, 8).map((g, i) => ({ id: g, label: g, hosts: Math.round(GSIZE[i] * 0.8 * f), total: GSIZE[i] }));
  return { ...base, mode: "dim", right, rightOther: { count: 32, hosts: Math.round(1802 * f), total: 2400 },
    links: left.flatMap((x, li) => [0, 1, 2].map((k) => [li, (li + k * 2) % 9, Math.max(1, Math.round(x.hosts * f * (0.5 - k * 0.15)))] as [number, number, number])) };
}

function list(q: URLSearchParams) {
  const kind = q.get("kind")!, page = Number(q.get("page") ?? 1);
  const total = { fix: 178, product: 420, host: q.get("id") || q.get("group") ? 1362 : 7790, hostCves: 61 }[kind] ?? 0;
  const rows = Array.from({ length: Math.max(0, Math.min(50, total - (page - 1) * 50)) }, (_, j) => {
    const i = (page - 1) * 50 + j;
    if (kind === "host") { const h = HOSTS[i % 80]; return { aid: h.aid + (i >= 80 ? i : ""), name: `${h.name}${i >= 80 ? `-${i}` : ""}`, group: GROUPS[i % 8], os: OS[i % 6], inet: i % 7 === 0, n: 90 - (i % 80), kev: i % 4, p1: 30 - (i % 30), sev: ["CRITICAL", "HIGH", "MEDIUM"][i % 3] }; }
    if (kind === "hostCves") { const c = CVES[i % 60]; return { id: c.id + (i >= 60 ? `-${i}` : ""), name: c.id, sub: FIXES[i % 16].product, sev: c.sev, kev: c.kev, tier: c.tier }; }
    const x = FIXES[i % 214];
    return { id: x.id, name: kind === "product" ? `${x.product} ${i}` : x.label, sub: kind === "fix" ? x.product : "", hosts: x.hosts, findings: x.findings };
  });
  return { total, page, pageSize: 50, rows };
}

const user = { id: "u1", email: "mock@e2e.test", name: "Mock SOC", role: "super_admin", soc: true, manager: true, tenants: [], totpEnabled: false };

/** Routes every API call of the page to the mock. `mode.calls` collects "path?query" of the graph calls (so a test can count them). */
export async function mockGraphApi(page: Page, mode: Mode = { calls: [] }) {
  await page.addInitScript(() => { try { localStorage.setItem("tenix.org", "t1"); } catch { /* ignore */ } });
  await page.route((u) => u.pathname.startsWith("/api/"), async (route: Route) => {
    const u = new URL(route.request().url());
    const json = (body: unknown, status = 200) => route.fulfill({ status, json: body });
    const p = u.pathname;
    if (p === "/api/auth/me") return json({ user });
    if (p === "/api/tenants") return json({ tenants: [{ id: "t1", name: "Alpha Corp", role: "super_admin", cids: [], state: mode.state ?? "complete" }] });
    if (p === "/api/exposure/watchlist") return json({ limit: 200, canEdit: true, hosts: [{ aid: HOSTS[3].aid, hostname: HOSTS[3].name, note: null, worstSeverity: "CRITICAL", p1: 12, critical: 3, high: 1, newP1_24h: 0, newCritical24h: 0, lastSeen: Date.now(), missing: false }], auto: [] });
    if (!p.startsWith("/api/exposure/graph")) return json({});
    mode.calls.push(`${p}?${u.searchParams}`);
    if (mode.delayMs) await new Promise((r) => setTimeout(r, mode.delayMs));
    if (mode.state === "error") return json({ error: "boom", code: "error" }, 500);
    if (p === "/api/exposure/graph/meta") return json({ dims: { group: true, os: true, site: true }, groups: GROUPS.slice(0, 20).map((g, i) => ({ id: g, label: g, hosts: GSIZE[i] })), os: OS.map((o) => ({ id: o, label: o, hosts: 900 })), sites: [{ id: "HQ", label: "HQ", hosts: 900 }], tiers: { P1: true, P2: true, P3: false }, held: 1_085_590, falconTotal: 16_700_573, completeness: completeness(mode.state && mode.state !== "ok" ? mode.state : "complete") });
    if (p === "/api/exposure/graph/search") { const s = (u.searchParams.get("q") ?? "").toLowerCase(); return json({ items: [...CVES.filter((c) => c.id.toLowerCase().includes(s)).slice(0, 4).map((c) => ({ kind: "cve", id: c.id, label: c.id, sub: "Microsoft Windows" })), ...FIXES.filter((x) => x.label.toLowerCase().includes(s)).slice(0, 4).map((x) => ({ kind: "fix", id: x.id, label: x.label, sub: x.product })), ...HOSTS.filter((h) => h.name.toLowerCase().includes(s)).slice(0, 4).map((h) => ({ kind: "host", id: h.aid, label: h.name, sub: "Servers-DC-BKK" }))] }); }
    if (p === "/api/exposure/graph/list") return json(list(u.searchParams));
    if (mode.state && mode.state !== "ok") {
      const c = completeness(mode.state);
      const d = graph(u.searchParams) as Record<string, unknown>;
      return json(["not_synced", "no_connection"].includes(mode.state) ? { ...d, totals: { hosts: 0 }, left: [], rows: [], completeness: c } : { ...d, completeness: c });
    }
    return json(graph(u.searchParams));
  });
}
