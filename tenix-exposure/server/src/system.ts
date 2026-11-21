// Where the data comes from and whether it is flowing: what a super admin looks at to see that Falcon is read, stored, and served from the database.
import { all, get, now } from "./db.ts";
import { route } from "./http.ts";
import { stats } from "./cache.ts";
import { syncState } from "./falcon.ts";

const ADMIN = { roles: ["super_admin" as const] };
const count = async (sql: string) => (await get<{ n: number }>(sql))!.n;

route("GET", "/api/system/status", ADMIN, async () => {
  const cids = await all<{ tenant: string | null; state: string; data_as_of: number | null; last_run_at: number; findings: number; closed: number; duration_ms: number | null }>(
    `SELECT t.name AS tenant, s.state, s.data_as_of, s.last_run_at,
            COALESCE((SELECT n FROM cid_counts k WHERE k.cid = s.cid AND k.key = 'held'), (SELECT COUNT(*) FROM findings_t f WHERE f.cid = s.cid)) AS findings,
            (SELECT COUNT(*) FROM finding_closed c WHERE c.cid = s.cid AND c.closed_at >= ?) AS closed,
            (SELECT r.finished_at - r.started_at FROM sync_runs r WHERE r.cid = s.cid AND r.finished_at IS NOT NULL ORDER BY r.id DESC LIMIT 1) AS duration_ms
     FROM cid_status s LEFT JOIN tenant_cids x ON x.cid = s.cid LEFT JOIN tenants t ON t.id = x.tenant_id ORDER BY t.name`, now() - 7 * 86400_000);
  const cacheRows = await get<{ n: number; newest: number | null }>("SELECT COUNT(*) n, MAX(built_at) newest FROM result_cache");
  const served = stats.memoryHits + stats.databaseHits;
  return {
    // what has been read from Falcon and stored in our own database (no CID values: organizations by name)
    falcon: { running: syncState.running, lastRunAt: cids.length ? Math.max(...cids.map((c) => c.last_run_at)) : null, organizations: cids.map((c) => ({ tenant: c.tenant, state: c.state, dataAsOf: c.data_as_of, lastRunAt: c.last_run_at, findings: c.findings, closed7d: c.closed, syncMs: c.duration_ms })) },
    database: {
      findings: await count("SELECT COALESCE(SUM(n), 0) n FROM cid_counts WHERE key = 'held'"), closedFindings: await count("SELECT COUNT(*) n FROM finding_closed"), cves: await count("SELECT COUNT(*) n FROM cves"),
      publicCves: await count("SELECT COUNT(*) n FROM cve_public"), kev: await count("SELECT COUNT(*) n FROM kev"), software: await count("SELECT COUNT(*) n FROM software"), organizations: await count("SELECT COUNT(*) n FROM tenants"),
    },
    // pages are served from the database; the computed answers are cached in memory and in the database
    cache: {
      entries: cacheRows!.n, newestBuiltAt: cacheRows!.newest, memoryHits: stats.memoryHits, databaseHits: stats.databaseHits, builds: stats.builds,
      hitRate: served + stats.builds ? Math.round((served / (served + stats.builds)) * 100) : null, avgBuildMs: stats.builds ? Math.round(stats.totalBuildMs / stats.builds) : null, slowestBuildMs: stats.slowestMs, warmedAt: stats.warmedAt || null, warming: stats.warming,
    },
  };
});
