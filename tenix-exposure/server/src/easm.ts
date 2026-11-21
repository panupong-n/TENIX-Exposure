// The external attack surface in detail: the assets Falcon EASM found, where they are, how Falcon found them, which services they expose and which TLS certificates those present.
// Flags: expired certificate, certificate expiring within 30 days, risky port. Every route goes through tenantScope(); an asset of another tenant is a 404.
import { all, get, now } from "./db.ts";
import { HttpError, route } from "./http.ts";
import { inList, tenantScope } from "./scope.ts";

/** FTP, Telnet, SMTP, MS RPC, NetBIOS, SMB, RDP: services that should not face the internet. */
export const RISKY_PORTS = [21, 23, 25, 135, 139, 445, 3389];
const RISKY = `ARRAY[${RISKY_PORTS.join(",")}]`;
const DAY = 86_400_000;
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
const FIND_RANK = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
const esc = (v: string) => v.replace(/[\\%_]/g, "\\$&");

/** Counts of services, certificates and risky ports of the organization's external assets. */
export async function easmServices(cids: string[]) {
  const t = now();
  const w = `cid IN ${inList(cids)}`;
  const r = (await get<any>(
    `SELECT COUNT(DISTINCT asset_id) AS assets, COUNT(*) AS services, COUNT(*) FILTER (WHERE cert_to < ?) AS expired, COUNT(*) FILTER (WHERE cert_to >= ? AND cert_to < ?) AS expiring,
            COUNT(*) FILTER (WHERE port = ANY(${RISKY})) AS risky, COUNT(DISTINCT asset_id) FILTER (WHERE port = ANY(${RISKY})) AS risky_assets, COUNT(DISTINCT asset_id) FILTER (WHERE cert_to < ?) AS expired_assets
     FROM external_services WHERE ${w}`, t, t, t + 30 * DAY, t, ...cids))!;
  return {
    assetsWithServices: r.assets, services: r.services, expiredCerts: r.expired, expiringCerts30: r.expiring, riskyPorts: r.risky, assetsWithRiskyPorts: r.risky_assets, assetsWithExpiredCert: r.expired_assets,
    topPorts: await all<{ port: number; n: number }>(`SELECT port, COUNT(*) n FROM external_services WHERE ${w} AND port IS NOT NULL GROUP BY port ORDER BY n DESC, port LIMIT 8`, ...cids),
    riskyPortList: RISKY_PORTS,
    byCountry: await all<{ k: string; n: number }>(`SELECT country k, COUNT(*) n FROM external_assets WHERE ${w} AND country IS NOT NULL GROUP BY 1 ORDER BY n DESC, k LIMIT 8`, ...cids),
    newLast7d: (await get<{ n: number }>(`SELECT COUNT(*) n FROM external_assets WHERE ${w} AND first_seen >= ?`, ...cids, t - 7 * DAY))!.n,
  };
}
// shortcut: a separate route next to /api/exposure/easm (that route lives in exposure.ts, owned by the other backend work); fold it into buildEasm when convenient.
route("GET", "/api/exposure/easm/services", async (c) => {
  const s = await tenantScope(c, "easm-services");
  return { tenant: { id: s.tenantId, name: s.tenantName }, ...(await easmServices(s.cids)) };
});

const sums = (cids: string[], t: number) => `
  LEFT JOIN (SELECT cid, asset_id, COUNT(*) AS n, ARRAY_AGG(DISTINCT port) FILTER (WHERE port IS NOT NULL) AS ports, ARRAY_AGG(DISTINCT port) FILTER (WHERE port = ANY(${RISKY})) AS risky,
                    COUNT(*) FILTER (WHERE cert_to < ${t}) AS expired, COUNT(*) FILTER (WHERE cert_to >= ${t} AND cert_to < ${t + 30 * DAY}) AS expiring, MIN(cert_to) AS nearest
             FROM external_services WHERE cid IN ${inList(cids)} GROUP BY cid, asset_id) sv ON sv.cid = a.cid AND sv.asset_id = a.id
  LEFT JOIN (SELECT cid, aid, COUNT(*) AS n, MIN(${FIND_RANK}) AS rank FROM findings_t WHERE cid IN ${inList(cids)} AND provider ILIKE '%EASM%' GROUP BY cid, aid) fi ON fi.cid = a.cid AND fi.aid = a.id`;

const asset = (r: any, t: number) => ({
  id: r.id, type: r.asset_type, dnsType: r.dns_type, name: r.ip ?? r.fqdn ?? r.id, ip: r.ip, fqdn: r.fqdn, perimeter: r.perimeter, review: r.review, reviewed: /^reviewed$/i.test(r.review ?? ""),
  criticality: r.criticality, status: r.status, cloud: r.cloud, isp: r.isp, asn: r.asn, country: r.country, city: r.city, discoveredBy: r.discovered_by, firstSeen: r.first_seen, lastSeen: r.last_seen,
  isNew: r.first_seen !== null && r.first_seen >= t - 7 * DAY, ports: r.ports ?? [], serviceCount: r.sn ?? 0, riskyPorts: r.risky ?? [], expiredCerts: r.expired ?? 0, expiringCerts: r.expiring ?? 0, nearestCertExpiry: r.nearest ?? null,
  findings: { count: r.fn ?? 0, worstSeverity: r.frank === null || r.frank === undefined ? null : SEV[r.frank] },
});
const COLS = `a.*, sv.n AS sn, sv.ports, sv.risky, sv.expired, sv.expiring, sv.nearest, fi.n AS fn, fi.rank AS frank`;

route("GET", "/api/exposure/easm/assets", async (c) => {
  const s = await tenantScope(c, "easm-assets");
  const t = now();
  const q = c.query;
  const conds = [`a.cid IN ${inList(s.cids)}`], args: (string | number)[] = [...s.cids];
  const type = q.get("type");
  if (type) {
    if (type === "ip" || type === "dns_domain") { conds.push("a.asset_type = ?"); args.push(type); }
    else if (type === "root") conds.push("a.asset_type <> 'ip' AND a.dns_type = 'root'");
    else if (type === "sub") conds.push("a.asset_type <> 'ip' AND COALESCE(a.dns_type, '') <> 'root'");
    else throw new HttpError(400, "Invalid type");
  }
  const perimeter = q.get("perimeter");
  if (perimeter) { conds.push("a.perimeter = ?"); args.push(perimeter.slice(0, 20)); }
  const review = q.get("review");
  if (review === "reviewed") conds.push("LOWER(COALESCE(a.review, '')) = 'reviewed'");
  else if (review === "not_reviewed") conds.push("LOWER(COALESCE(a.review, '')) <> 'reviewed'");
  else if (review) throw new HttpError(400, "Invalid review");
  const status = q.get("status");
  if (status) { if (status !== "online" && status !== "offline") throw new HttpError(400, "Invalid status"); conds.push("a.status = ?"); args.push(status); }
  if (q.get("expiredCert") === "1") conds.push("COALESCE(sv.expired, 0) > 0");
  if (q.get("expiringCert") === "1") conds.push("COALESCE(sv.expiring, 0) > 0");
  if (q.get("riskyPort") === "1") conds.push("sv.risky IS NOT NULL");
  if (q.get("isNew") === "1") { conds.push("a.first_seen >= ?"); args.push(t - 7 * DAY); }
  const text = (q.get("q") ?? "").trim().slice(0, 100);
  if (text) { conds.push("(a.ip ILIKE ? ESCAPE '\\' OR a.fqdn ILIKE ? ESCAPE '\\')"); args.push(`%${esc(text)}%`, `%${esc(text)}%`); }
  // 203.0.113.2 before 203.0.113.11 (text order puts .11 first); an address that is not plain IPv4 sorts after, by text
  const IPNAT = "(CASE WHEN a.ip ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$' THEN string_to_array(a.ip, '.')::int[] END)";
  const sorts: Record<string, string> = {
    triage: `(CASE WHEN LOWER(COALESCE(a.review, '')) = 'reviewed' THEN 1 ELSE 0 END), (CASE WHEN a.first_seen >= ${t - 7 * DAY} THEN 0 ELSE 1 END), COALESCE(fi.rank, 9), a.first_seen DESC NULLS LAST, ${IPNAT}, a.id`,
    name: `(a.ip IS NULL), ${IPNAT}, COALESCE(a.ip, a.fqdn), a.id`, lastSeen: "a.last_seen DESC NULLS LAST, a.id", firstSeen: "a.first_seen DESC NULLS LAST, a.id", findings: "COALESCE(fi.n, 0) DESC, COALESCE(fi.rank, 9), a.id",
  };
  const sort = q.get("sort") ?? "triage";
  if (!sorts[sort]) throw new HttpError(400, "Invalid sort");
  const pageNo = Math.max(1, Number(q.get("page")) || 1), size = Math.min(100, Math.max(1, Number(q.get("pageSize")) || 25));
  const from = `FROM external_assets a ${sums(s.cids, t)} WHERE ${conds.join(" AND ")}`;
  // the text is: the two joins (each with the CID list), then the filters (which start with the CID list again)
  const joinArgs = [...s.cids, ...s.cids];
  const total = (await get<{ n: number }>(`SELECT COUNT(*) n ${from}`, ...joinArgs, ...args))!.n;
  const rows = await all<any>(`SELECT ${COLS} ${from} ORDER BY ${sorts[sort]} LIMIT ? OFFSET ?`, ...joinArgs, ...args, size, (pageNo - 1) * size);
  const sync = s.cids.length ? await all<{ state: string; as_of: number | null }>(`SELECT state, as_of FROM external_sync WHERE cid IN ${inList(s.cids)}`, ...s.cids) : [];
  const state = !s.cids.length ? "no_cids" : sync.length < s.cids.length ? "not_synced" : sync.some((x) => x.state === "failed") ? "failed" : sync.some((x) => x.state === "partial") ? "partial" : "complete";
  return { tenant: { id: s.tenantId, name: s.tenantName }, state, asOf: sync.length && sync.every((x) => x.as_of) ? Math.min(...sync.map((x) => x.as_of!)) : null, total, page: pageNo, pageSize: size, items: rows.map((r) => asset(r, t)) };
});

route("GET", "/api/exposure/easm/assets/:id", async (c) => {
  const s = await tenantScope(c, "easm-asset");
  const t = now();
  const id = c.params.id;
  const row = s.cids.length ? await get<any>(`SELECT ${COLS} FROM external_assets a ${sums(s.cids, t)} WHERE a.cid IN ${inList(s.cids)} AND a.id = ?`, ...s.cids, ...s.cids, ...s.cids, id) : undefined;
  if (!row) throw new HttpError(404, "Not found"); // another organization's asset looks like a missing one
  const svc = await all<any>(`SELECT * FROM external_services WHERE cid = ? AND asset_id = ? ORDER BY port, svc`, row.cid, id);
  const vulns = await all<any>(
    `SELECT cve_id, severity, base_score, exprt, product, EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = f.cve_id) AS kev FROM findings_t f WHERE cid = ? AND aid = ? AND provider ILIKE '%EASM%'
     ORDER BY ${FIND_RANK}, base_score DESC NULLS LAST, cve_id LIMIT 50`, row.cid, id);
  const json = (v: string | null) => { try { return v ? JSON.parse(v) : []; } catch { return []; } };
  return {
    ...asset(row, t), ptr: row.ptr, region: row.region, discovery: json(row.discovery_json),
    services: svc.map((v) => ({
      port: v.port, transport: v.transport, protocol: v.protocol, status: v.status, statusCode: v.status_code, os: v.os, firstSeen: v.first_seen, lastSeen: v.last_seen, risky: RISKY_PORTS.includes(v.port), applications: json(v.apps_json),
      tls: v.cert_to === null && !v.tls_version ? null : { version: v.tls_version, issuer: v.cert_issuer, subject: v.cert_subject, validFrom: v.cert_from, validTo: v.cert_to, expired: v.cert_to !== null && v.cert_to < t,
        expiresInDays: v.cert_to === null ? null : Math.floor((v.cert_to - t) / DAY), signature: v.cert_sig, fingerprint: v.cert_fingerprint },
    })),
    vulnerabilities: vulns.map((v) => ({ cve: v.cve_id, severity: v.severity, baseScore: v.base_score, exprt: v.exprt, kev: !!v.kev, product: v.product })),
  };
});
