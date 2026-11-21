// The device inventory (WP 5): every host of a CID from Falcon's Devices API, hourly after the findings. It is the truth for "how many hosts" (hosts without a finding are in it,
// Falcon EASM assets are not), and it carries what the findings do not: the real last check-in, groups, tags, OU, site, serial, MAC, agent version, containment.
// A failed or incomplete read never replaces a complete one. Duplicate hosts (same hostname / serial / MAC) are marked here, the stale age is computed when read.
import { all, insertMany, now, run, tx } from "./db.ts";
import type { FalconClient } from "./falcon.ts";
import { recordHistory, refreshDims } from "./rollup.ts";

export interface HostRow {
  cid: string; aid: string; hostname: string | null; platform: string | null; os_version: string | null; os_build: string | null; agent_version: string | null;
  first_seen: number | null; last_seen: number | null; local_ip: string | null; external_ip: string | null; mac: string | null; serial: string | null; machine_domain: string | null;
  site: string | null; ou: string[]; tags: string[]; groups: string[]; product_type: string | null; criticality: string | null; rfm: boolean; contained: boolean; status: string | null;
  dup_group: string | null; dup_role: string | null; dup_reason: string | null; dup_newer: string | null; stale_twin: boolean;
}
export interface HostsResult { state: "complete" | "partial" | "failed"; rows: HostRow[]; read: number; total: number | null; missing: string[]; notes: string[]; groupNames: boolean }

export const MAX_HOSTS = 400_000;
export const hostHooks = { pageSize: 1000 };
const FIELDS = "device_id,cid,hostname,platform_name,os_version,os_build,agent_version,first_seen,last_seen,status,reduced_functionality_mode,product_type_desc,groups,tags,ou,site_name,machine_domain,criticality,serial_number,local_ip,external_ip,mac_address";
const AID = /^[0-9a-f]{32}$/i;
const text = (v: unknown, max = 200) => { const t = typeof v === "string" ? v.replace(/\0/g, "").trim() : ""; return t ? t.slice(0, max) : null; };
const list = (v: unknown, max = 50): string[] => (Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string" && !!x.trim()).map((x) => x.replace(/\0/g, "").slice(0, 120)))].slice(0, max) : []);
const ms = (v: unknown) => { const t = typeof v === "string" ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : null; };
const why = (r: { status: number }) => `HTTP ${r.status || "network error"}${r.status === 403 ? " (the API client needs the Falcon Hosts read scope)" : ""}`;

// values that many different machines share and that say nothing about identity
const JUNK_SERIAL = /^(0+|none|n\/a|na|unknown|default string|not specified|not available|to be filled by o\.?e\.?m\.?|system serial number|serial number|\.+|-+|123456789?0?)$/i;
const JUNK_MAC = /^(0{2}([-:]?0{2}){5}|ff([-:]?ff){5})$/i;
const isIp = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(":");

/** Marks hosts that share a hostname (first label, case-insensitive), a serial number or a MAC address with another host of the CID.
 *  Chains are one group (A~B by name, B~C by serial). The newest check-in is "newest"; an older twin that last reported at least a day before it is the stale twin (a re-imaged machine counted twice).
 *  Linux "WSL" instances share the Windows host's name on purpose and are not compared by name. */
export function markDuplicates(rows: HostRow[]): void {
  const parent = new Map<string, string>();
  const find = (x: string): string => { let r = x; while (parent.get(r) !== r) r = parent.get(r)!; while (parent.get(x) !== r) { const n = parent.get(x)!; parent.set(x, r); x = n; } return r; };
  for (const h of rows) parent.set(h.aid, h.aid);
  const keysOf = (h: HostRow): [string, string][] => {
    const out: [string, string][] = [];
    const name = (h.hostname ?? "").toLowerCase().split(".")[0];
    if (name.length >= 2 && !isIp(h.hostname ?? "") && !/^wsl/i.test(h.os_version ?? "")) out.push(["hostname", name]);
    if (h.serial && h.serial.length >= 4 && !JUNK_SERIAL.test(h.serial)) out.push(["serial", h.serial.toLowerCase()]);
    if (h.mac && !JUNK_MAC.test(h.mac)) out.push(["mac", h.mac.toLowerCase().replace(/[^0-9a-f]/g, "")]);
    return out;
  };
  const owner = new Map<string, string>(); // key -> first aid seen with it
  const links = new Map<string, Set<string>>(); // aid -> key kinds shared with somebody
  for (const h of rows) {
    for (const [kind, v] of keysOf(h)) {
      const k = `${kind}|${v}`, o = owner.get(k);
      if (!o) { owner.set(k, h.aid); continue; }
      parent.set(find(h.aid), find(o));
      for (const a of [h.aid, o]) (links.get(a) ?? links.set(a, new Set()).get(a)!).add(kind);
    }
  }
  const groups = new Map<string, HostRow[]>();
  for (const h of rows) { const r = find(h.aid); (groups.get(r) ?? groups.set(r, []).get(r)!).push(h); }
  const DAY = 86400_000;
  for (const g of groups.values()) {
    if (g.length < 2) continue;
    g.sort((a, b) => (b.last_seen ?? 0) - (a.last_seen ?? 0) || (b.first_seen ?? 0) - (a.first_seen ?? 0) || (a.aid < b.aid ? -1 : 1));
    const newest = g[0], id = [...g].map((h) => h.aid).sort()[0];
    for (const h of g) {
      const kinds = links.get(h.aid) ?? new Set<string>();
      h.dup_group = id; h.dup_reason = ["hostname", "serial", "mac"].find((k) => kinds.has(k)) ?? "hostname";
      if (h === newest) { h.dup_role = "newest"; continue; }
      h.dup_role = "older"; h.dup_newer = newest.aid;
      h.stale_twin = (newest.last_seen ?? 0) - (h.last_seen ?? 0) >= DAY;
    }
  }
}

/** Every host of the API client, grouped by CID by the caller: pages of 1000 with a cursor (`meta.pagination.next` goes back as `offset`), then the group names (one call). */
export async function collectHosts(client: FalconClient, cid: string): Promise<HostsResult> {
  const missing: string[] = [], notes: string[] = [];
  const rows: HostRow[] = [];
  let offset: string | undefined, total: number | null = null, read = 0, pages = 0, foreign = 0, bad = 0;
  while (read < MAX_HOSTS) {
    const r = await client.get("/devices/combined/devices/v1", { limit: hostHooks.pageSize, fields: FIELDS, ...(offset ? { offset } : {}) });
    if (!r.ok) { missing.push(`host page ${pages + 1}: ${why(r)}`); break; }
    pages++;
    const batch: any[] = r.data?.resources ?? [];
    total = r.data?.meta?.pagination?.total ?? total;
    read += batch.length;
    for (const d of batch) {
      if (d.cid && String(d.cid).toLowerCase() !== cid) { foreign++; continue; }
      const aid = String(d.device_id ?? "");
      if (!AID.test(aid)) { bad++; continue; }
      const status = text(d.status, 40);
      rows.push({
        cid, aid, hostname: text(d.hostname, 253), platform: text(d.platform_name, 40), os_version: text(d.os_version, 80), os_build: text(d.os_build, 40), agent_version: text(d.agent_version, 40),
        first_seen: ms(d.first_seen), last_seen: ms(d.last_seen), local_ip: text(d.local_ip, 45), external_ip: text(d.external_ip, 45), mac: text(d.mac_address, 40), serial: text(d.serial_number, 80),
        machine_domain: text(d.machine_domain, 120), site: text(d.site_name, 120), ou: list(d.ou, 12), tags: list(d.tags, 30), groups: list(d.groups, 60),
        product_type: text(d.product_type_desc, 40), criticality: text(d.criticality, 30)?.toLowerCase() ?? null, rfm: String(d.reduced_functionality_mode ?? "").toLowerCase() === "yes",
        contained: status === "contained" || status === "containment_pending", status,
        dup_group: null, dup_role: null, dup_reason: null, dup_newer: null, stale_twin: false,
      });
    }
    const next = r.data?.meta?.pagination?.next || undefined;
    if (!batch.length || !next || next === offset) break;
    offset = next;
  }
  if (read >= MAX_HOSTS) missing.push(`stopped at the safety limit of ${MAX_HOSTS.toLocaleString("en-US")} hosts`);
  else if (!missing.length && total !== null && read < total) missing.push(`read ${read} of ${total} hosts`);
  if (foreign) notes.push(`${foreign} hosts of another CID were ignored`);
  if (bad) notes.push(`${bad} hosts skipped: no valid device ID`);

  // group names: the Devices API gives group ids
  let groupNames = false;
  const names = new Map<string, string>();
  if (pages) {
    for (let off = 0; ; off += 500) {
      const g = await client.get("/devices/combined/host-groups/v1", { limit: 500, offset: off });
      if (!g.ok) { notes.push(`host group names: ${why(g)}; the group names of the previous read are kept`); names.clear(); break; }
      for (const x of g.data?.resources ?? []) if (x?.id && x?.name) names.set(String(x.id), String(x.name).slice(0, 120));
      const t = g.data?.meta?.pagination?.total;
      if (!(g.data?.resources ?? []).length || typeof t !== "number" || off + 500 >= t) { groupNames = true; break; }
    }
  }
  if (groupNames) for (const h of rows) h.groups = [...new Set(h.groups.map((id) => names.get(id) ?? id))];
  markDuplicates(rows);
  return { state: !pages ? "failed" : missing.length ? "partial" : "complete", rows, read, total, missing, notes, groupNames };
}

const COLS = ["cid", "aid", "hostname", "platform", "os_version", "os_build", "agent_version", "first_seen", "last_seen", "local_ip", "external_ip", "mac", "serial", "machine_domain", "site", "ou", "tags", "groups",
  "product_type", "criticality", "rfm", "contained", "status", "dup_group", "dup_role", "dup_reason", "dup_newer", "stale_twin", "synced_at"];

/** Replaces the CID's inventory when the read is complete, or when there was nothing before; an incomplete or failed read never overwrites a complete one. Rebuilds the host dimensions of the graph rollups when it replaced. */
export async function storeHosts(cid: string, r: HostsResult): Promise<void> {
  const prev = await all<{ as_of: number | null }>("SELECT as_of FROM hosts_sync WHERE cid = ?", cid);
  const replace = r.state === "complete" || (r.state === "partial" && !prev[0]?.as_of && r.rows.length > 0);
  const t = now();
  await tx(async () => {
    if (replace) {
      // keep the group names of the last read when the names could not be read this time (the ids would be worse than old names)
      let old = new Map<string, string[]>();
      if (!r.groupNames) old = new Map((await all<{ aid: string; groups: string[] }>("SELECT aid, groups FROM hosts WHERE cid = ?", cid)).map((x) => [x.aid, x.groups]));
      await run("DELETE FROM hosts WHERE cid = ?", cid);
      await insertMany("hosts", COLS, r.rows.map((h) => [h.cid, h.aid, h.hostname, h.platform, h.os_version, h.os_build, h.agent_version, h.first_seen, h.last_seen, h.local_ip, h.external_ip, h.mac, h.serial, h.machine_domain,
        h.site, h.ou as any, h.tags as any, (r.groupNames ? h.groups : (old.get(h.aid) ?? [])) as any, h.product_type, h.criticality, h.rfm as any, h.contained as any, h.status, h.dup_group, h.dup_role, h.dup_reason, h.dup_newer, h.stale_twin as any, t]), "ON CONFLICT DO NOTHING");
    }
    await run(`INSERT INTO hosts_sync (cid, state, read, total, detail_json, as_of, last_run_at) VALUES (?,?,?,?,?,?,?)
               ON CONFLICT (cid) DO UPDATE SET state = excluded.state, read = excluded.read, total = excluded.total, detail_json = excluded.detail_json, as_of = excluded.as_of, last_run_at = excluded.last_run_at`,
      cid, r.state, r.read, r.total, JSON.stringify([...r.missing, ...r.notes]), replace ? t : (prev[0]?.as_of ?? null), t);
  });
  if (replace) { // the inventory size is part of the daily row, and the graph's host dimensions come from it
    await refreshDims(cid).catch((e) => console.error("[hosts] graph dimensions not rebuilt:", (e as Error).message));
    await recordHistory(cid).catch((e) => console.error("[history] could not write the daily row:", (e as Error).message));
  }
}
