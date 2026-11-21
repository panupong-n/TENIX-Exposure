// Fake CrowdStrike Falcon API for development and tests. Run: npm run mock-falcon
// Credentials: client id "mock-client", secret "mock-secret". All data is invented.
import { createServer, type Server } from "node:http";

export const MOCK_CLIENT = "mock-client";
export const MOCK_SECRET = "mock-secret";
export const CID_ONE = "1".repeat(31) + "a";
export const CID_TWO = "2".repeat(31) + "b";

function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const hex = (r: () => number, n: number) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join("");

const SEVS = [["CRITICAL", 9.8, 90], ["CRITICAL", 9.1, 60], ["HIGH", 8.1, 60], ["HIGH", 7.5, 30], ["MEDIUM", 5.4, 0], ["MEDIUM", 6.1, 30], ["LOW", 3.1, 0], ["NONE", 0, 0]] as const;
const PRODUCTS = ["Microsoft Windows 11 23H2", "Google Chrome 120.0", "OpenSSL 3.0.2", "Apache Tomcat 9.0.80", "Mozilla Firefox 115", "Oracle Java 8u301", "7-Zip 22.01", "Adobe Acrobat 23.1"];
const ACTIONS = ["Update to the latest vendor release", "Apply the latest cumulative security update", "Disable the affected feature until patched", "Upgrade to a fixed version"];

const T0 = Date.parse("2026-11-01T00:00:00Z");
const iso = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
const isoNow = () => iso(Date.now());

// ---- a small FQL evaluator: what the sync asks for, and 400 for what Falcon refuses ----
class FqlError extends Error {}
/** Split at a separator that is not inside quotes, parentheses or brackets. */
function splitTop(s: string, sep: string): string[] {
  const out: string[] = []; let depth = 0, q = false, cur = "";
  for (const ch of s) {
    if (ch === "'") q = !q;
    if (!q && (ch === "(" || ch === "[")) depth++;
    if (!q && (ch === ")" || ch === "]")) depth--;
    if (!q && depth === 0 && ch === sep) { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur);
  return out;
}
const FIELDS: Record<string, (f: any) => unknown> = {
  status: (f) => f.status, cid: (f) => f.cid, aid: (f) => f.aid, "cve.severity": (f) => f.cve?.severity, "cve.exprt_rating": (f) => f.cve?.exprt_rating,
  "cve.exploit_status": (f) => f.cve?.exploit_status, "cve.is_cisa_kev": (f) => !!f.cve?.cisa_info?.is_cisa_kev,
  updated_timestamp: (f) => f.updated_timestamp, closed_timestamp: (f) => f.closed_timestamp, created_timestamp: (f) => f.created_timestamp,
  "data_providers.provider": (f) => f.data_providers?.[0]?.provider ?? "Falcon sensor", "suppression_info.is_suppressed": (f) => !!f.suppression_info?.is_suppressed,
};
function term(t: string, f: any): boolean {
  if (t.startsWith("(") && t.endsWith(")")) return splitTop(t.slice(1, -1), ",").some((x) => fql(x, f)); // parentheses with commas = OR
  const m = /^([a-z_.]+):(>=|<=|>|<|!)?(.+)$/.exec(t);
  if (!m || !FIELDS[m[1]]) throw new FqlError(`invalid filter: ${t.slice(0, 40)}`);
  const [, field, op = "", raw] = m;
  if (field === "cve.exploit_status" && op) throw new FqlError("operators are not allowed on exploit_status");
  const want = raw.startsWith("[") ? splitTop(raw.slice(1, -1), ",").map((x) => x.replace(/^'|'$/g, "")) : [raw.replace(/^'|'$/g, "")];
  const v = FIELDS[field](f);
  if (op === ">" || op === ">=" || op === "<" || op === "<=") {
    const a = Date.parse(String(v ?? "")), b = Date.parse(want[0]);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return false;
    return op === ">" ? a > b : op === ">=" ? a >= b : op === "<" ? a < b : a <= b;
  }
  const hit = want.includes(String(v));
  return op === "!" ? !hit : hit;
}
function fql(expr: string, f: any): boolean { return splitTop(expr, "+").every((t) => term(t, f)); }
const SORT_KEYS = new Set(["updated_timestamp", "closed_timestamp", "created_timestamp"]);

export interface MockData { hostGroups: { id: string; name: string }[]; external: any[]; findings: any[]; devices: Map<string, any>; remediations: Map<string, any>; software: any[]; discoverHosts: Map<string, any> }

const HOST_GROUPS = [{ id: "grp1", name: "Servers" }, { id: "grp2", name: "Laptops" }, { id: "grp3", name: "ลูกค้าสัมพันธ์" }, { id: "grp4", name: "Finance" }];
/** What the Devices API adds to a host: real check-in times, groups, serial, MAC... All a function of the index (no rng), so the findings never change. */
function inventory(cid: string, h: number) {
  return {
    first_seen: "2025-01-01T00:00:00Z", last_seen: iso(Date.now() - (h % 10 === 0 ? 40 * 86400_000 : h % 7 === 0 ? 9 * 86400_000 : 3600_000)), os_version: h % 5 === 0 ? "RHEL 8.10" : "Windows 11", os_build: h % 5 === 0 ? "" : "22631",
    agent_version: h % 3 ? "8.11.21510.0" : "8.10.21408.0", status: "normal", product_type_desc: h % 6 === 0 ? "Server" : "Workstation", criticality: h % 13 === 0 ? "critical" : "unassigned",
    groups: [HOST_GROUPS[h % 4].id, ...(h % 3 === 0 ? [HOST_GROUPS[(h + 1) % 4].id] : [])], tags: ["FalconGroupingTags/t" + (h % 3)], ou: ["Computers", `Site${h % 2}`], site_name: h % 2 ? "Bangkok" : "Chiang Mai",
    machine_domain: "corp.example.test", serial_number: `SN-${cid.slice(0, 2)}-${h}`, mac_address: `02-00-${cid.slice(0, 2)}-00-${String(h >> 8).padStart(2, "0")}-${String(h & 255).padStart(2, "0")}`.toLowerCase(),
    reduced_functionality_mode: h === 3 ? "yes" : "no",
  };
}

export function buildData(): MockData {
  const r = rng(42);
  const findings: any[] = [], devices = new Map<string, any>(), remediations = new Map<string, any>();
  ACTIONS.forEach((a, i) => remediations.set(`rem${i}`, { id: `rem${i}`, action: a, title: a, link: `https://catalog.example/kb${i}`, vendor_url: "", recommendation_type: i % 2 ? "minimum" : "recommended" }));
  const cves = Array.from({ length: 90 }, (_, i) => ({ id: `CVE-2025-${String(10000 + i * 37)}`, s: SEVS[Math.floor(r() * SEVS.length)] }));
  const plan: [string, number, number, string[]][] = [[CID_ONE, 150, 1400, ["APP", "DB", "WEB"]], [CID_TWO, 60, 500, ["APP", "FS", "DC"]]];
  for (const [cid, hosts, count, prefixes] of plan) {
    const aids: string[] = [];
    for (let h = 0; h < hosts; h++) {
      const aid = hex(r, 32);
      aids.push(aid);
      const unnamed = h % 23 === 0, ipNamed = h % 29 === 1;
      devices.set(aid, {
        device_id: aid, cid, hostname: unnamed ? "" : ipNamed ? `10.0.${h}.5` : `${prefixes[h % prefixes.length]}-${String((h % 40) + 1).padStart(2, "0")}`,
        platform_name: h % 5 === 0 ? "Linux" : "Windows", local_ip: `10.0.${h % 250}.${(h % 200) + 10}`, external_ip: "203.0.113.10",
        ...inventory(cid, h),
      });
    }
    for (let i = 0; i < count; i++) {
      const aid = aids[Math.floor(r() * aids.length)], cve = cves[Math.floor(r() * cves.length)], product = PRODUCTS[Math.floor(r() * PRODUCTS.length)];
      const id = `${aid}_${cve.id}_${i}`;
      findings.push({
        id, cid, aid, status: r() < 0.9 ? "open" : "reopen", apps: [{ product_name_version: product }], host_info: {},
        cve: { id: cve.id, severity: cve.s[0], base_score: cve.s[1], exprt_rating: cve.s[0] === "NONE" ? "UNKNOWN" : cve.s[0], exploit_status: cve.s[2], vendor_advisory: [`https://vendor.example.com/security/${cve.id}`] },
        remediation: { ids: [`rem${Math.floor(r() * ACTIONS.length)}`] },
      });
    }
  }
  // hosts that have no finding at all (the inventory lists them, the findings never do), appended last so nothing above moves
  for (const [cid, n] of [[CID_ONE, 10], [CID_TWO, 4]] as const) for (let h = 0; h < n; h++) {
    const aid = `${cid.slice(0, 4)}${String(h).padStart(4, "0")}`.padEnd(32, "e");
    devices.set(aid, { device_id: aid, cid, hostname: `QUIET-${cid.slice(0, 1)}${h}`, platform_name: "Windows", local_ip: `10.9.0.${h + 1}`, external_ip: "203.0.113.10", ...inventory(cid, 1000 + h) });
  }
  if (process.env.MOCK_RICH === "1") addRich(findings);
  // Falcon stamps every finding with the time of its last change; three findings share a second-minute so cursors meet ties
  findings.forEach((f, i) => { f.updated_timestamp = iso(T0 + Math.floor(i / 3) * 60_000); });
  const { software, discoverHosts } = buildSoftware(devices);
  // external attack surface: for each CID, IP addresses (official / unofficial, a few reviewed) and domains (root / sub)
  const external: any[] = [];
  for (const [cid, n] of [[CID_ONE, 1], [CID_TWO, 2]] as const) {
    for (let i = 0; i < 40 * n; i++) external.push({ id: `${cid.slice(0, 4)}-ip-${i}`, cid, asset_type: "ip", perimeter: i % 2 ? "official" : "unofficial", triage: { status: i % 10 === 0 ? "reviewed" : "" }, criticality: "Unassigned", status: i % 3 ? "online" : "offline", internet_exposure: "Yes", ip: { ip_address: `203.0.113.${i % 250}`, cloud_provider: i % 4 === 0 ? "AWS" : "" }, discovered_by: ["surface", "user", "aws"][i % 3], first_seen: "2026-01-01T00:00:00Z", last_seen: "2026-11-01T00:00:00Z" });
    for (let i = 0; i < 12 * n; i++) external.push({ id: `${cid.slice(0, 4)}-dns-${i}`, cid, asset_type: "dns_domain", perimeter: "official", triage: { status: "" }, dns_domain: { fqdn: `host${i}.example.test`, type: i % 4 === 0 ? "root" : "subdomain" }, internet_exposure: "Yes", discovered_by: "surface" });
  }
  return { hostGroups: HOST_GROUPS, external, findings, devices, remediations, software, discoverHosts };
}

// Falcon Discover inventory: no rng, so it never changes the findings above. The first 6 devices of each CID carry it.
function buildSoftware(devices: Map<string, any>) {
  const software: any[] = [], discoverHosts = new Map<string, any>();
  const seen: Record<string, number> = {};
  for (const d of devices.values()) {
    seen[d.cid] = (seen[d.cid] ?? 0) + 1;
    if (seen[d.cid] > 6) continue;
    const n = seen[d.cid], hostId = `${d.cid}_DISC${n}`;
    discoverHosts.set(hostId, { id: hostId, aid: d.device_id, hostname: d.hostname || null, platform_name: d.platform_name, os_version: "Windows 11" });
    const base = { cid: d.cid, host: { id: hostId }, is_suspicious: false, is_normalized: true };
    const add = (k: string, o: any) => software.push({ ...base, id: `${d.cid}_${hostId}_${k}`, name_vendor: `${o.name}-${o.vendor ?? ""}`, ...o });
    add("chrome", { name: "Google Chrome", vendor: "Google", version: n % 2 ? "120.0.1" : "121.0.2", software_type: "application", category: "Web browsers", first_seen_timestamp: "2025-01-10T00:00:00Z" });
    add("7zip", { name: "7-Zip", vendor: "Igor Pavlov", version: "22.01", software_type: "application", category: "System tools" });
    add("semver", { name: "semver", vendor: "GitHub Inc.", version: "7.5.4", software_type: "dev_package", category: "Software Packages", registry_latest_version_available: "7.8.5", store_listing: "https://www.npmjs.com/package/semver" });
    if (n === 1) add("ext", { name: "Shady Coupons", version: "1.0", software_type: "browser_extension", is_suspicious: true, host_application: "Google Chrome", browser_extension: { id: "abc", enabled: true }, store_listing: "https://chromewebstore.example/abc" });
    add("blank", { name_vendor: "-", software_type: "application" }); // Falcon sometimes returns entries with no name
  }
  return { software, discoverHosts };
}

// Opt-in (MOCK_RICH=1): CVE details on real findings plus external-asset (EASM) findings. Own rng, so the default data never changes.
function addRich(findings: any[]) {
  const r = rng(7);
  findings.forEach((f) => {
    if (!f.cve.id || f.cid !== CID_ONE && f.cid !== CID_TWO) return;
    const n = Number(f.cve.id.slice(-5));
    Object.assign(f.cve, {
      description: `${f.cve.id}: a flaw in ${f.apps[0].product_name_version} lets a remote attacker run code or read data (invented sample text).`,
      types: ["Vulnerability"], cwes: ["CWE-79"], published_date: `2025-0${(n % 9) + 1}-1${n % 9}T00:00:00Z`,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", exploitability_score: 3.9, impact_score: 5.9,
      references: [`https://example.com/advisories/${f.cve.id}`, `https://nvd.example.org/vuln/detail/${f.cve.id}`],
      vendor_advisory: [`https://vendor.example.com/security/${f.cve.id}`],
      cisa_info: { is_cisa_kev: n % 3 === 0 }, // per CVE, as Falcon does: every finding of a KEV CVE is flagged, so Falcon's tier totals are never below what we hold
    });
    Object.assign(f.apps[0], { vendor_normalized: "Example Corp", evaluation_logic: { id: `ev_${f.id}` } });
    Object.assign(f, { created_timestamp: "2026-03-01T10:00:00Z", risk_score: 40 + (n % 40), exploitability: n % 2 ? "exploitable" : "not_exploitable" });
    Object.assign(f.host_info ?? (f.host_info = {}), { os_version: "Windows 11", internet_exposure: "No" });
  });
  const sevs = [["CRITICAL", 9.1], ["HIGH", 7.8], ["MEDIUM", 5.3], ["LOW", 3.1]] as const;
  const titles = ["Exposed admin panel", "TLS certificate expires soon", "Directory listing enabled", "Weak TLS protocol offered"];
  for (const [cid, count] of [[CID_ONE, 40], [CID_TWO, 6]] as const) {
    for (let i = 0; i < count; i++) {
      const sev = sevs[Math.floor(r() * sevs.length)], t = i % titles.length;
      const aid = `cid_AS${hex(r, 20).toUpperCase()}`;
      findings.push({
        id: `${aid}_easm_${i}`, cid, aid, status: "open", apps: [], data_providers: [{ provider: "Falcon EASM" }],
        vulnerability_id: `CS-C24-A${String(123 + i).padStart(6, "0")}`,
        host_info: { hostname: `${cid === CID_ONE ? "shop" : "portal"}-${i + 1}.example.com`, platform: "" },
        cve: {
          id: "", severity: sev[0], base_score: sev[1], exprt_rating: sev[0], exploit_status: 0, types: ["Misconfiguration"], cwes: [t % 2 ? "CWE-295" : "CWE-200"],
          description: `${titles[t]} on an internet-facing asset (invented sample text).`,
        },
        remediation: { ids: ["rem0"] }, services: [{ port: 443, transport: "tcp", protocol: "https" }],
      });
    }
  }
}

export interface MockControl {
  /** Answer the next `times` requests whose path or query string contains `match` with `status` (the first `after` matching requests are served normally). */
  fail(match: string | ((pathAndQuery: string) => boolean), status: number, times?: number, after?: number): void;
  clearFailures(): void;
  requests: string[];
  data: MockData;
  /** Answer 400 to a findings request that asks for more than this many per page. */
  maxLimit: number;
  /** CIDs this API client may not read: a findings request for one gets Falcon's own 400 "not authorized to use <cid> as cid filter value". */
  deniedCids: Set<string>;
  /** Add findings as Falcon would show a new one: stamped with the current time (or keep the stamp they have). */
  add(...f: any[]): void;
  /** A finding changed now (its updated_timestamp moves); `to` also changes its status ("closed" stamps closed_timestamp). */
  touch(f: any, to?: string): void;
  /** Answer 400 "invalid cursor" to the next `times` requests that carry an `after` cursor. */
  dropCursors(times?: number): void;
  /** Largest number of findings sent in one answer so far (a page, never the whole set). */
  maxPage: number;
  /** Milliseconds every page answer (a request with a sort) waits, to exercise a time budget. */
  delayMs: number;
}

export function startMock(port = 0): Promise<{ server: Server; url: string; control: MockControl }> {
  const data = buildData();
  const failures: { match: string | ((q: string) => boolean); status: number; times: number; skip: number }[] = [];
  const requests: string[] = [];
  const control: MockControl = {
    fail: (match, status, times = 1, after = 0) => { failures.push({ match, status, times, skip: after }); },
    clearFailures: () => { failures.length = 0; },
    requests, data, maxLimit: Infinity, deniedCids: new Set<string>(), maxPage: 0, delayMs: 0,
    add: (...fs) => { for (const f of fs) { f.updated_timestamp ??= isoNow(); data.findings.push(f); } },
    touch: (f, to) => { f.updated_timestamp = isoNow(); if (to) { f.status = to; if (to === "closed") f.closed_timestamp = isoNow(); else delete f.closed_timestamp; } },
    dropCursors: (times = 1) => { cursorDrops = times; },
  };
  let cursorDrops = 0;
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const sendNow = (status: number, body: unknown) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
    const send = (status: number, body: unknown) => (control.delayMs && url.pathname.startsWith("/spotlight/combined") && url.search.includes("sort=") ? void setTimeout(() => sendNow(status, body), control.delayMs) : sendNow(status, body));
    requests.push(`${req.method} ${url.pathname}${url.search}`);
    const f = failures.find((x) => (typeof x.match === "function" ? x.match(decodeURIComponent(`${url.pathname}${url.search}`)) : `${url.pathname}${url.search}`.includes(x.match)) && x.times > 0);
    if (f) {
      if (f.skip > 0) f.skip--;
      else { f.times--; res.writeHead(f.status, f.status === 429 ? { "Retry-After": "0" } : {}); res.end("{}"); return; }
    }
    if (url.pathname === "/oauth2/token" && req.method === "POST") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        const p = new URLSearchParams(b);
        if (p.get("client_id") === MOCK_CLIENT && p.get("client_secret") === MOCK_SECRET) send(201, { access_token: "mock-token", expires_in: 1799 });
        else send(401, { errors: [{ message: "access denied, invalid credentials" }] });
      });
      return;
    }
    if (req.headers.authorization !== "Bearer mock-token") return send(401, {});
    if (url.pathname === "/spotlight/combined/vulnerabilities/v1") {
      const flt = url.searchParams.get("filter") ?? "";
      const cid = /cid:'([0-9a-f]{32})'/.exec(flt)?.[1];
      if (cid && control.deniedCids.has(cid)) return send(400, { errors: [{ code: 400, message: "invalid filter" }, { code: 400, message: `not authorized to use "${cid}" as cid filter value` }] });
      let rows: any[];
      try { rows = data.findings.filter((x) => (cid ? x.cid === cid : true) && (/status:/.test(flt) || ["open", "reopen"].includes(x.status)) && (flt ? fql(flt, x) : true)); } catch (e) {
        if (e instanceof FqlError) return send(400, { errors: [{ code: 400, message: e.message }] });
        throw e;
      }
      const asked = Number(url.searchParams.get("limit") ?? 100);
      if (asked > control.maxLimit) return send(400, { errors: [{ message: "limit too large" }] });
      const limit = Math.min(asked, 5000);
      const sort = url.searchParams.get("sort");
      const after = url.searchParams.get("after");
      if (after && cursorDrops > 0) { cursorDrops--; return send(400, { errors: [{ message: "invalid cursor" }] }); }
      let part: any[], next: string | null;
      if (sort) {
        const [key, dir = "asc"] = sort.split(/[|.]/);
        if (!SORT_KEYS.has(key) || !["asc", "desc"].includes(dir)) return send(400, { errors: [{ message: "invalid sort" }] });
        const k = (f: any): [number, string] => [Date.parse(f[key]) || 0, String(f.id)];
        const cmp = (a: any, b: any) => { const x = k(a), y = k(b); return (x[0] - y[0] || (x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0)) * (dir === "desc" ? -1 : 1); };
        rows.sort(cmp);
        let start = 0;
        if (after) { // search-after: the cursor is the sort key of the last row sent, so rows that change meanwhile do not shift the pages
          const [ts, ...id] = Buffer.from(after, "base64url").toString().split("|");
          const mark = { [key]: new Date(Number(ts)).toISOString(), id: id.join("|") };
          start = rows.findIndex((r) => cmp(r, mark) > 0);
          if (start < 0) start = rows.length;
        }
        part = rows.slice(start, start + limit);
        const last = part[part.length - 1];
        next = last && start + limit < rows.length ? Buffer.from(`${k(last)[0]}|${last.id}`).toString("base64url") : null;
      } else {
        const off = Number(after ?? 0);
        part = rows.slice(off, off + limit);
        next = off + limit < rows.length ? String(off + limit) : null;
      }
      control.maxPage = Math.max(control.maxPage, part.length);
      return send(200, { resources: part, meta: { pagination: { total: rows.length, after: next, limit } } });
    }
    if (url.pathname === "/devices/combined/devices/v1") {
      const limit = Math.min(1000, Number(url.searchParams.get("limit") ?? 100)), off = Number(url.searchParams.get("offset") ?? 0);
      const all = [...data.devices.values()];
      const part = all.slice(off, off + limit);
      return send(200, { resources: part, meta: { pagination: { total: all.length, limit, offset: "", ...(off + limit < all.length ? { next: String(off + limit) } : {}) } } });
    }
    if (url.pathname === "/devices/combined/host-groups/v1") {
      return send(200, { resources: data.hostGroups, meta: { pagination: { total: data.hostGroups.length } } });
    }
    if (url.pathname === "/devices/entities/devices/v2") {
      const ids = url.searchParams.getAll("ids");
      return send(200, { resources: ids.map((i) => data.devices.get(i)).filter(Boolean) });
    }
    if (url.pathname === "/spotlight/entities/remediations/v2") {
      return send(200, { resources: url.searchParams.getAll("ids").map((i) => data.remediations.get(i)).filter(Boolean) });
    }
    if (url.pathname === "/spotlight/entities/evaluation-logic/v1") {
      // "ev_<finding id>": the installed version is derived from the id so tests can predict it
      const ids = url.searchParams.getAll("ids");
      return send(200, { resources: ids.map((id) => ({ id, simplified_logic: [{ title: "Check if the version of Example App is less than 2.0.0", checks: "(version less than 2.0.0)", found: [`version: 1.${id.length % 10}.0`], data: ["filepath: C:\\Program Files\\Example\\app.exe"] }] })) });
    }
    if (url.pathname === "/discover/combined/applications/v1") {
      const all = data.software;
      const limit = Math.min(1000, Number(url.searchParams.get("limit") ?? 100));
      const off = Number(url.searchParams.get("after") ?? 0);
      const next = off + limit < all.length ? String(off + limit) : null;
      return send(200, { resources: all.slice(off, off + limit), meta: { pagination: { total: all.length, after: next, limit } } });
    }
    if (url.pathname === "/fem/queries/external-assets/v1") {
      const limit = Math.min(500, Number(url.searchParams.get("limit") ?? 100)), off = Number(url.searchParams.get("offset") ?? 0);
      return send(200, { resources: data.external.slice(off, off + limit).map((a) => a.id), meta: { pagination: { total: data.external.length, offset: off, limit } } });
    }
    if (url.pathname === "/fem/entities/external-assets/v1") {
      const want = new Set(url.searchParams.getAll("ids"));
      return send(200, { resources: data.external.filter((a) => want.has(a.id)) });
    }
    if (url.pathname === "/discover/entities/hosts/v1") {
      return send(200, { resources: url.searchParams.getAll("ids").map((i) => data.discoverHosts.get(i)).filter(Boolean) });
    }
    send(404, {});
  });
  return new Promise((ok) => server.listen(port, "127.0.0.1", () => {
    const addr = server.address();
    ok({ server, url: `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}`, control });
  }));
}

if (import.meta.main) {
  const port = Number(process.env.MOCK_PORT ?? 8799);
  const { url } = await startMock(port);
  console.log(`Mock Falcon on ${url}\n  client id: ${MOCK_CLIENT}\n  secret:    ${MOCK_SECRET}\n  CIDs:      ${CID_ONE}  ${CID_TWO}`);
}
