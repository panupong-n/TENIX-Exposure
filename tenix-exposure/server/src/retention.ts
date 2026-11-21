// Which severities an organization wants stored (default: all). Unticking one stops collecting it at once; its stored rows are deleted only after a grace period
// (re-ticking inside it cancels the purge). Re-ticking brings the severity back through a catch-up cursor, so the data is honest ("partial") until it has caught up.
import { all, audit, get, now, run, tx } from "./db.ts";
import { refreshRollups } from "./rollup.ts";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const retentionHooks = { graceMs: 3 * 86400_000, purgeChunk: 50_000 };
/** severity -> when its rows may be deleted, and since when they have not been refreshed. full: the first pass was not finished then, so a catch-up must start from the beginning. */
export type Pending = Record<string, { purgeAt: number; since: number; full: boolean }>;

const valid = (v: unknown): v is Severity[] => Array.isArray(v) && v.every((x) => (SEVERITIES as readonly string[]).includes(x as string));
const ordered = (keep: Iterable<string>) => SEVERITIES.filter((s) => new Set(keep).has(s));

export async function getRetention(tenantId: string): Promise<{ keep: Severity[]; pending: Pending }> {
  const r = await get<{ keep_severities: string; pending_purge_json: string }>("SELECT keep_severities, pending_purge_json FROM tenant_settings WHERE tenant_id = ?", tenantId);
  if (!r) return { keep: [...SEVERITIES], pending: {} };
  const keep = JSON.parse(r.keep_severities);
  return { keep: valid(keep) && keep.length ? ordered(keep) : [...SEVERITIES], pending: JSON.parse(r.pending_purge_json) as Pending };
}
export async function keepForCid(cid: string): Promise<Severity[]> {
  const t = await get<{ tenant_id: string }>("SELECT tenant_id FROM tenant_cids WHERE cid = ?", cid);
  return t ? (await getRetention(t.tenant_id)).keep : [...SEVERITIES];
}

/** The FQL part that limits a read to the kept severities ("" when all are kept). Falcon names them CRITICAL, HIGH, MEDIUM, LOW; NONE is everything else, so it is expressed by leaving the others out. */
export function severityFilter(keep: readonly string[]): string {
  if (keep.length >= SEVERITIES.length) return "";
  if (keep.includes("NONE")) return `+cve.severity:![${SEVERITIES.filter((s) => s !== "NONE" && !keep.includes(s)).map((s) => `'${s}'`).join(",")}]`;
  return `+cve.severity:[${keep.map((s) => `'${s}'`).join(",")}]`;
}
/** How many findings Falcon counts in the kept severities (NONE = what is not in the other four). */
export function keptTotal(n: Record<string, number>, keep: readonly string[]): number | null {
  if (typeof n.total !== "number") return null;
  const four = ["critical", "high", "medium", "low"];
  if (keep.length >= SEVERITIES.length) return n.total;
  if (four.some((k) => typeof n[k] !== "number")) return null;
  let sum = 0;
  for (const k of four) if (keep.includes(k.toUpperCase())) sum += n[k];
  if (keep.includes("NONE")) sum += Math.max(0, n.total - four.reduce((a, k) => a + n[k], 0));
  return sum;
}

/** Saves a new selection. Returns the severities that were added (they need a catch-up) so the caller can start a sync. */
export async function setRetention(tenantId: string, next: Severity[], actor: Parameters<typeof audit>[0]["actor"], ip: string | null) {
  if (!next.length) throw new RangeError("keep_empty");
  const cur = await getRetention(tenantId);
  const t = now();
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", tenantId)).map((r) => r.cid);
  const unfinished = cids.length ? (await get<{ n: number }>(`SELECT COUNT(*) n FROM tenant_cids x LEFT JOIN cid_sync y ON y.cid = x.cid WHERE x.tenant_id = ? AND y.first_done_at IS NULL`, tenantId))!.n > 0 : false;
  const removed = cur.keep.filter((s) => !next.includes(s)), added = next.filter((s) => !cur.keep.includes(s));
  const pending: Pending = { ...cur.pending };
  for (const s of removed) pending[s] = { purgeAt: t + retentionHooks.graceMs, since: t, full: unfinished };
  await tx(async () => {
    for (const s of added) {
      const p = pending[s];
      for (const cid of cids) // catch up on what changed while it was not collected; after a purge (or if it never was collected) from the beginning
        await run("INSERT INTO cid_cursor (cid, name, wm, started, seen) VALUES (?,?,?,?,0) ON CONFLICT (cid, name) DO UPDATE SET wm = excluded.wm, started = excluded.started, seen = 0",
          cid, `add:${s}`, p && !p.full ? Math.max(0, p.since - 5 * 60_000) : 0, t);
      delete pending[s];
    }
    await run(`INSERT INTO tenant_settings (tenant_id, keep_severities, changed_at, pending_purge_json) VALUES (?,?,?,?)
               ON CONFLICT (tenant_id) DO UPDATE SET keep_severities = excluded.keep_severities, changed_at = excluded.changed_at, pending_purge_json = excluded.pending_purge_json`,
      tenantId, JSON.stringify(ordered(next)), t, JSON.stringify(pending));
  });
  for (const cid of cids) await run("UPDATE cid_sync SET scope = ? WHERE cid = ?", next.length < SEVERITIES.length ? "priority" : "all", cid);
  await audit({ actor, tenantId, action: "tenant.retention", resource: ordered(next).join(","), result: "ok", ip, detail: `removed ${removed.join(",") || "-"}; added ${added.join(",") || "-"}` });
  return { added, removed };
}

/** Deletes the rows of severities whose grace period is over, in chunks along the primary key (a 17-million-row table must not be locked or scanned over and over). Safe to run any time, any number of times. */
export async function purgeDue(): Promise<number> {
  let total = 0;
  for (const t of await all<{ tenant_id: string; pending_purge_json: string }>("SELECT tenant_id, pending_purge_json FROM tenant_settings WHERE pending_purge_json <> '{}'")) {
    const pending = JSON.parse(t.pending_purge_json) as Pending;
    const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", t.tenant_id)).map((r) => r.cid);
    let done = 0;
    for (const [sev, p] of Object.entries(pending)) {
      if (p.purgeAt > now()) continue;
      let n = 0;
      for (const cid of cids) {
        let last = "";
        for (;;) {
          const edge = await get<{ f: string }>("SELECT MAX(finding_id) f FROM (SELECT finding_id FROM findings_t WHERE cid = ? AND finding_id > ? ORDER BY finding_id LIMIT ?) w", cid, last, retentionHooks.purgeChunk);
          if (!edge?.f) break;
          n += (await get<{ n: number }>("WITH d AS (DELETE FROM findings_t WHERE cid = ? AND finding_id > ? AND finding_id <= ? AND severity = ? RETURNING 1) SELECT COUNT(*) n FROM d", cid, last, edge.f, sev))!.n;
          last = edge.f;
        }
      }
      // the setting may have changed while this ran: only forget the purge when the severity is still unticked
      await tx(async () => {
        const now_ = await getRetention(t.tenant_id);
        if (!now_.keep.includes(sev as Severity)) { delete now_.pending[sev]; await run("UPDATE tenant_settings SET pending_purge_json = ? WHERE tenant_id = ?", JSON.stringify(now_.pending), t.tenant_id); }
      });
      await audit({ actor: null, tenantId: t.tenant_id, action: "tenant.retention.purge", resource: sev, result: "ok", detail: `${n} findings deleted` });
      total += n; done++;
    }
    if (done) for (const cid of cids) { const h = await refreshRollups(cid, (await getRetention(t.tenant_id)).keep); await run("INSERT INTO cid_counts (cid, key, n, as_of) VALUES (?,?,?,?) ON CONFLICT (cid, key) DO UPDATE SET n = excluded.n, as_of = excluded.as_of", cid, "held", h.held, now()); }
  }
  return total;
}

/** For the settings dialog: what is kept, what will be deleted when, what is being re-collected, and how complete the kept scope is. */
export async function retentionView(tenantId: string) {
  const r = await getRetention(tenantId);
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", tenantId)).map((x) => x.cid);
  const rebuilding = cids.length ? (await all<{ name: string }>(`SELECT DISTINCT name FROM cid_cursor WHERE name LIKE 'add:%' AND cid IN (${cids.map(() => "?").join(",")})`, ...cids)).map((x) => x.name.slice(4)) : [];
  return {
    keep: r.keep, all: [...SEVERITIES], graceDays: Math.round(retentionHooks.graceMs / 86400_000),
    pending: Object.entries(r.pending).map(([severity, p]) => ({ severity, purgeAt: p.purgeAt })).sort((a, b) => a.purgeAt - b.purgeAt),
    rebuilding: ordered(rebuilding),
    scope: r.keep.length >= SEVERITIES.length ? ("all" as const) : r.keep,
  };
}
