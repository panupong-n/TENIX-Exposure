import { AsyncLocalStorage } from "node:async_hooks";
import pg from "pg";
import { databaseUrl, dbSchema } from "./config.ts";

/** super_admin does everything and sees every tenant. member users only see the tenants they belong to, each as admin or operator. */
export type Role = "super_admin" | "member";
export type TenantRole = "admin" | "operator";
export const TENANT_ROLES: TenantRole[] = ["admin", "operator"];
/** "Super admin" is the only user type that sees CIDs and every tenant. (Name kept from when it meant SOC staff.) */
export const isSoc = (r: Role) => r === "super_admin";

export interface User {
  id: string; email: string; name: string; password_hash: string; role: Role;
  totp_secret: string | null; totp_enabled: number; totp_last_step: number; disabled: number;
  created_at: number; last_login_at: number | null;
}
export interface Membership { tenant_id: string; role: TenantRole }
/** The signed-in user, with the tenants they belong to. */
export type SessionUser = User & { memberships: Membership[] };
/** Tenants whose users this person may manage ("all" for a super admin). */
export const managedTenants = (u: SessionUser): "all" | Set<string> =>
  u.role === "super_admin" ? "all" : new Set(u.memberships.filter((m) => m.role === "admin").map((m) => m.tenant_id));
export const isManager = (u: SessionUser) => { const m = managedTenants(u); return m === "all" || m.size > 0; };

// BIGINT (ms timestamps, COUNT, SUM) comes back as a string by default; every value here fits in a JS number.
pg.types.setTypeParser(20, Number);
pg.types.setTypeParser(1700, Number);

if (!/^[a-z_][a-z0-9_]*$/.test(dbSchema)) throw new Error("TENIX_DB_SCHEMA must be a plain lowercase identifier");
if (dbSchema !== "public") {
  const boot = new pg.Client({ connectionString: databaseUrl });
  await boot.connect();
  await boot.query(`CREATE SCHEMA IF NOT EXISTS ${dbSchema}`);
  await boot.end();
}
// No parallel query workers: on this server they need more shared memory (/dev/shm) than it has, and a big scan then fails with "could not resize shared memory segment".
export const pool = new pg.Pool({ connectionString: databaseUrl, max: 10, options: `-c max_parallel_workers_per_gather=0${dbSchema !== "public" ? ` -c search_path=${dbSchema}` : ""}` });

// The findings table used to be called "findings" and held the remediation texts on every row. The rows now live in findings_t (the remediation texts once, in rem_sets) and
// "findings" is a view with the old columns, so every reader and every report keeps working. A database from before the change is renamed in place.
await pool.query(`DO $$ BEGIN IF to_regclass('findings') IS NOT NULL AND (SELECT relkind FROM pg_class WHERE oid = to_regclass('findings')) = 'r' THEN ALTER TABLE findings RENAME TO findings_t; END IF; END $$`);
await pool.query(`
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_cids (
  cid TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE CHECK (email = lower(email)), name TEXT NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('super_admin','member')),
  totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, last_login_at BIGINT
);
CREATE TABLE IF NOT EXISTS user_tenants (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin','operator')), PRIMARY KEY (user_id, tenant_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stage TEXT NOT NULL CHECK (stage IN ('mfa','full')), expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL,
  remember INTEGER NOT NULL DEFAULT 0, ip TEXT
);
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY, email TEXT NOT NULL CHECK (email = lower(email)), role TEXT NOT NULL, memberships_json TEXT NOT NULL DEFAULT '[]',
  kind TEXT NOT NULL CHECK (kind IN ('invite','reset')), user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE, invited_by TEXT, expires_at BIGINT NOT NULL,
  accepted_at BIGINT, revoked_at BIGINT, created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
  key TEXT PRIMARY KEY, config_json TEXT NOT NULL, secret_sealed TEXT, updated_at BIGINT NOT NULL, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS findings_t (
  cid TEXT NOT NULL, finding_id TEXT NOT NULL, aid TEXT NOT NULL, cve_id TEXT NOT NULL, severity TEXT NOT NULL,
  base_score DOUBLE PRECISION, exprt TEXT, exploit_status INTEGER, hostname TEXT, platform TEXT, local_ip TEXT, external_ip TEXT,
  product TEXT, status TEXT, synced_at BIGINT NOT NULL,
  PRIMARY KEY (cid, finding_id)
);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS line_chat TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS provider TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS kind TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS vendor TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS eval_id TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS exploitability TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS first_seen BIGINT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS os_version TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS internet_exposure TEXT;
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS port TEXT;
-- Falcon's suppression_info.is_suppressed: a suppressed finding is in no tier and no count (rollup.ts)
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS suppressed SMALLINT NOT NULL DEFAULT 0;
-- The recommended actions of a finding are the same for thousands of findings: one row per distinct set (id = first 48 bits of md5(json | text)), the finding keeps only the id.
CREATE TABLE IF NOT EXISTS rem_sets (id BIGINT PRIMARY KEY, remediation TEXT NOT NULL, remediation_json TEXT);
ALTER TABLE findings_t ADD COLUMN IF NOT EXISTS rem_set BIGINT;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'findings_t' AND column_name = 'remediation') THEN
    INSERT INTO rem_sets (id, remediation, remediation_json)
      SELECT DISTINCT ON (k) k, remediation, remediation_json FROM (SELECT ('x' || substr(md5(coalesce(remediation_json, '') || '|' || remediation), 1, 12))::bit(48)::bigint AS k, remediation, remediation_json FROM findings_t WHERE remediation IS NOT NULL) x ON CONFLICT DO NOTHING;
    UPDATE findings_t SET rem_set = ('x' || substr(md5(coalesce(remediation_json, '') || '|' || remediation), 1, 12))::bit(48)::bigint WHERE remediation IS NOT NULL;
    DROP VIEW IF EXISTS findings;
    ALTER TABLE findings_t DROP COLUMN remediation;
    ALTER TABLE findings_t DROP COLUMN remediation_json;
  END IF;
END $$;
CREATE OR REPLACE VIEW findings AS SELECT t.cid, t.finding_id, t.aid, t.cve_id, t.severity, t.base_score, t.exprt, t.exploit_status, t.hostname, t.platform, t.local_ip, t.external_ip, t.product, t.status,
  (SELECT r.remediation FROM rem_sets r WHERE r.id = t.rem_set) AS remediation, t.synced_at, t.provider, (SELECT r.remediation_json FROM rem_sets r WHERE r.id = t.rem_set) AS remediation_json,
  t.kind, t.vendor, t.eval_id, t.risk_score, t.exploitability, t.first_seen, t.os_version, t.internet_exposure, t.port, t.suppressed FROM findings_t t;
CREATE TABLE IF NOT EXISTS cves (
  id TEXT PRIMARY KEY, description TEXT, published_at TEXT, vector TEXT, exploitability_score DOUBLE PRECISION, impact_score DOUBLE PRECISION,
  cwes TEXT NOT NULL DEFAULT '[]', types TEXT NOT NULL DEFAULT '[]', references_json TEXT NOT NULL DEFAULT '[]', advisories_json TEXT NOT NULL DEFAULT '[]',
  cisa_kev INTEGER NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL
);
-- Public facts, one copy for everybody: the CVE Program records and CISA's Known Exploited Vulnerabilities list.
CREATE TABLE IF NOT EXISTS cve_public (
  id TEXT PRIMARY KEY, state TEXT NOT NULL, title TEXT, description TEXT, published_at BIGINT, modified_at BIGINT, ingested_at BIGINT NOT NULL,
  cvss_score DOUBLE PRECISION, cvss_severity TEXT, cvss_vector TEXT, cwes TEXT NOT NULL DEFAULT '[]', refs_json TEXT NOT NULL DEFAULT '[]', assigner TEXT
);
CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY, name TEXT, vendor TEXT, product TEXT, description TEXT, date_added TEXT, due_date TEXT, ransomware TEXT,
  required_action TEXT, notes TEXT, first_seen_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS feed_state (
  key TEXT PRIMARY KEY, checkpoint TEXT, etag TEXT, last_try_at BIGINT, last_ok_at BIGINT, error TEXT, info_json TEXT NOT NULL DEFAULT '{}'
);
-- Urgent items per organization. One row per (organization, CVE, reason): a repeated sync or a restart cannot make a second one.
CREATE TABLE IF NOT EXISTS alerts (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, cve_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN ('first_impact','kev_added','baseline')), created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id, cve_id, reason)
);
-- Findings that were open in one complete read and gone in the next: the history that makes "closed" visible (a failed or partial read never closes anything).
CREATE TABLE IF NOT EXISTS finding_closed (
  cid TEXT NOT NULL, finding_id TEXT NOT NULL, aid TEXT NOT NULL, cve_id TEXT NOT NULL, severity TEXT NOT NULL, hostname TEXT, provider TEXT, closed_at BIGINT NOT NULL,
  PRIMARY KEY (cid, finding_id, closed_at)
);
CREATE INDEX IF NOT EXISTS finding_closed_when ON finding_closed (cid, closed_at);
-- Computed page answers (see cache.ts), kept across restarts so the first page view after one is not a cold computation.
CREATE TABLE IF NOT EXISTS result_cache (key TEXT PRIMARY KEY, ver TEXT NOT NULL, json TEXT NOT NULL, built_at BIGINT NOT NULL, build_ms INTEGER NOT NULL DEFAULT 0);
-- One CrowdStrike connection per organization CID: where to log in (cloud, API client id and secret) and which CID it reads. A CID without a row here is read with the shared connection saved under Integrations (the way it was before).
CREATE TABLE IF NOT EXISTS falcon_connections (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, name TEXT, base_url TEXT NOT NULL, client_id TEXT NOT NULL,
  secret_sealed TEXT NOT NULL, cid TEXT NOT NULL UNIQUE, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
-- Every LINE chat the bot knows, with what it is for. role 'source': news posted there is read; role 'destination': answers are sent there.
-- tenant_id set = that organization's own chat (a source is read for that organization only; a destination receives only its data); tenant_id NULL = the SOC's.
CREATE TABLE IF NOT EXISTS line_chats (
  chat_id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('source','destination')), tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT, created_at BIGINT NOT NULL, PRIMARY KEY (chat_id, role)
);
-- Falcon EASM's internet-facing assets (IP addresses and domains), per CID: what the Exposure management > External attack surface dashboard counts.
CREATE TABLE IF NOT EXISTS external_assets (
  cid TEXT NOT NULL, id TEXT NOT NULL, asset_type TEXT NOT NULL, dns_type TEXT, perimeter TEXT, review TEXT, criticality TEXT, status TEXT, internet_exposure TEXT,
  ip TEXT, fqdn TEXT, cloud TEXT, isp TEXT, discovered_by TEXT, first_seen BIGINT, last_seen BIGINT, PRIMARY KEY (cid, id)
);
CREATE TABLE IF NOT EXISTS external_sync (
  cid TEXT PRIMARY KEY, state TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, total INTEGER, detail_json TEXT NOT NULL DEFAULT '[]', as_of BIGINT, last_run_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_cve ON findings_t (cid, cve_id);
CREATE INDEX IF NOT EXISTS findings_aid ON findings_t (cid, aid);
-- the external (EASM) findings are a few hundred among millions: the pages about them read this small index (the query must carry the same condition)
CREATE INDEX IF NOT EXISTS findings_easm ON findings_t (cid, aid) WHERE provider ILIKE '%EASM%';
CREATE TABLE IF NOT EXISTS software (
  cid TEXT NOT NULL, id TEXT NOT NULL, host_id TEXT NOT NULL, type TEXT NOT NULL, name TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
  category TEXT, first_seen BIGINT, updated_at BIGINT, suspicious INTEGER NOT NULL DEFAULT 0, threat TEXT, latest TEXT, host_app TEXT, enabled INTEGER, link TEXT,
  PRIMARY KEY (cid, id)
);
CREATE INDEX IF NOT EXISTS software_group ON software (cid, type, vendor, name);
CREATE TABLE IF NOT EXISTS software_hosts (
  cid TEXT NOT NULL, host_id TEXT NOT NULL, aid TEXT, hostname TEXT, platform TEXT, os_version TEXT, PRIMARY KEY (cid, host_id)
);
CREATE TABLE IF NOT EXISTS software_sync (
  cid TEXT PRIMARY KEY, state TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, total INTEGER, detail_json TEXT NOT NULL DEFAULT '[]', as_of BIGINT, last_run_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS cid_status (
  cid TEXT PRIMARY KEY, state TEXT NOT NULL, detail_json TEXT NOT NULL, data_as_of BIGINT, last_run_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS line_events (event_id TEXT PRIMARY KEY, received_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS news_items (
  id TEXT PRIMARY KEY, received_at BIGINT NOT NULL, kind TEXT NOT NULL, message_id TEXT, chat TEXT NOT NULL, text TEXT,
  urls_json TEXT NOT NULL DEFAULT '[]', fetch_json TEXT NOT NULL DEFAULT '[]', ocr_status TEXT, cve_result TEXT NOT NULL DEFAULT 'not_evaluated',
  matches_json TEXT NOT NULL DEFAULT '[]', reply_status TEXT, done_at BIGINT
);
CREATE TABLE IF NOT EXISTS news_cves (
  news_id TEXT NOT NULL REFERENCES news_items(id) ON DELETE CASCADE, cve_id TEXT NOT NULL, source TEXT NOT NULL, snippet TEXT, PRIMARY KEY (news_id, cve_id, source)
);
CREATE TABLE IF NOT EXISTS snapshots (
  cid TEXT NOT NULL, ts BIGINT NOT NULL, critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL,
  low INTEGER NOT NULL, "none" INTEGER NOT NULL, hosts INTEGER NOT NULL, cves INTEGER NOT NULL, PRIMARY KEY (cid, ts)
);
CREATE TABLE IF NOT EXISTS sync_runs (
  id BIGSERIAL PRIMARY KEY, cid TEXT NOT NULL, started_at BIGINT NOT NULL, finished_at BIGINT,
  state TEXT NOT NULL, pages INTEGER NOT NULL DEFAULT 0, "read" INTEGER NOT NULL DEFAULT 0, total INTEGER, detail_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS audit (
  id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL, actor_id TEXT, actor_email TEXT, role TEXT, tenant_id TEXT,
  action TEXT NOT NULL, resource TEXT, result TEXT NOT NULL, ip TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit (tenant_id, id DESC);
ALTER TABLE cid_status ADD COLUMN IF NOT EXISTS notes_json TEXT NOT NULL DEFAULT '[]';
-- why a CID is failed or partial, as a machine word: invalid_credentials | cid_not_authorized | missing_scope | unreachable | error (Falcon's own words are in detail_json)
ALTER TABLE cid_status ADD COLUMN IF NOT EXISTS reason TEXT;
-- Exact numbers Falcon counts for a CID (limit=1 calls, pagination.total), refreshed every run, plus what we hold ('held', 'priorityHeld'). They feed the Overview and the snapshots even when the rows are only a slice.
-- Per-CID rollups of findings_t that every customer page reads instead of scanning millions of rows (rollup.ts rebuilds them after a sync that changed rows).
-- src = 'endpoint' | 'external' (Falcon EASM). Counts are exactly what the same GROUP BY over findings would give.
CREATE TABLE IF NOT EXISTS roll_cve (
  cid TEXT NOT NULL, src TEXT NOT NULL, cve_id TEXT NOT NULL, rank SMALLINT NOT NULL, base_score DOUBLE PRECISION, exprt TEXT, exploit_status INTEGER, kind TEXT, product TEXT, products TEXT,
  hosts INTEGER NOT NULL, findings INTEGER NOT NULL, pri INTEGER NOT NULL, exprt_rank SMALLINT NOT NULL, inet INTEGER NOT NULL, PRIMARY KEY (cid, src, cve_id)
);
CREATE INDEX IF NOT EXISTS roll_cve_by_cve ON roll_cve (cve_id, cid);
CREATE TABLE IF NOT EXISTS roll_host (
  cid TEXT NOT NULL, src TEXT NOT NULL, aid TEXT NOT NULL, hostname TEXT, platform TEXT, local_ip TEXT, external_ip TEXT, provider TEXT,
  cves INTEGER NOT NULL, critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL, exploited INTEGER NOT NULL, rank SMALLINT NOT NULL, findings INTEGER NOT NULL, inet BOOLEAN NOT NULL,
  PRIMARY KEY (cid, src, aid)
);
CREATE TABLE IF NOT EXISTS roll_sev (cid TEXT NOT NULL, src TEXT NOT NULL, inet BOOLEAN NOT NULL, severity TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (cid, src, inet, severity));
CREATE TABLE IF NOT EXISTS roll_age (cid TEXT NOT NULL, src TEXT NOT NULL, bucket TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (cid, src, bucket));
-- Which severities an organization stores (retention.ts). keep_severities: JSON list, default all five; pending_purge_json: severity -> when its rows may be deleted.
CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, keep_severities TEXT NOT NULL DEFAULT '["CRITICAL","HIGH","MEDIUM","LOW","NONE"]', changed_at BIGINT, pending_purge_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS cid_counts (cid TEXT NOT NULL, key TEXT NOT NULL, n BIGINT NOT NULL, as_of BIGINT NOT NULL, PRIMARY KEY (cid, key));
-- Where the sync of a CID stands. Every open finding is stored in two phases: slice_done_at = phase A (the fix-first slice) is stored, first_done_at = phase B (everything) is stored; NULL until then.
CREATE TABLE IF NOT EXISTS cid_sync (
  cid TEXT PRIMARY KEY, slice_done_at BIGINT, first_done_at BIGINT, last_scan_done_at BIGINT, recon_gap BIGINT
);
-- A cursor over the findings of a CID ordered by updated_timestamp. 'slice' = phase A, 'inc' = phase B and then the incremental feed over every row, 'scan' = a reconcile pass, 'closed' = the feed of closed findings.
-- wm: everything updated before it has been stored. started: when the pass began. seen: rows read in this pass (a pass may only delete what it did not see when it saw nearly everything).
-- scope: 'all' or 'priority' (= the organization keeps only some severities, see retention.ts; the name stays because line.ts reads it to know that a complete read cannot say "not found")
ALTER TABLE cid_sync ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'all';
-- An earlier build created cid_sync without this column; CREATE TABLE IF NOT EXISTS does not add it to an existing table.
ALTER TABLE cid_sync ADD COLUMN IF NOT EXISTS slice_done_at BIGINT;
CREATE TABLE IF NOT EXISTS cid_cursor (cid TEXT NOT NULL, name TEXT NOT NULL, wm BIGINT NOT NULL DEFAULT 0, started BIGINT NOT NULL, seen BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (cid, name));
-- ---------- API v2 (hosts inventory, tiers, fixes, history, graph rollups) ----------
-- The device inventory of a CID (Falcon Devices API): the truth for "how many hosts", including hosts with no finding. groups/tags/ou are arrays of names.
-- dup_*: hostname/serial/MAC shared with another host of the CID (hosts.ts); stale_twin = the older of two such hosts.
CREATE TABLE IF NOT EXISTS hosts (
  cid TEXT NOT NULL, aid TEXT NOT NULL, hostname TEXT, platform TEXT, os_version TEXT, os_build TEXT, agent_version TEXT, first_seen BIGINT, last_seen BIGINT,
  local_ip TEXT, external_ip TEXT, mac TEXT, serial TEXT, machine_domain TEXT, site TEXT, ou TEXT[] NOT NULL DEFAULT '{}', tags TEXT[] NOT NULL DEFAULT '{}', groups TEXT[] NOT NULL DEFAULT '{}',
  product_type TEXT, criticality TEXT, rfm BOOLEAN NOT NULL DEFAULT false, contained BOOLEAN NOT NULL DEFAULT false, status TEXT,
  dup_group TEXT, dup_role TEXT, dup_reason TEXT, dup_newer TEXT, stale_twin BOOLEAN NOT NULL DEFAULT false, synced_at BIGINT NOT NULL, PRIMARY KEY (cid, aid)
);
CREATE TABLE IF NOT EXISTS hosts_sync (
  cid TEXT PRIMARY KEY, state TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, total INTEGER, detail_json TEXT NOT NULL DEFAULT '[]', as_of BIGINT, last_run_at BIGINT NOT NULL
);
-- tiers (P1/P2/P3, rollup.ts) on the older rollups; roll_cve.kev is as of the last refresh
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS tier SMALLINT NOT NULL DEFAULT 3;
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS p1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS p2 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS kev SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS first_seen BIGINT;
ALTER TABLE roll_cve ADD COLUMN IF NOT EXISTS exprt_lvl SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS p1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS p2 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS p3 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS kev_cves INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS fixes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_host ADD COLUMN IF NOT EXISTS tier SMALLINT;
CREATE INDEX IF NOT EXISTS roll_cve_tier ON roll_cve (cid, src, tier, rank);
-- one row per fix (remediation set = findings_t.rem_set, 0 = none) of a CID: endpoint findings of tier P1 and P2 only (what has to be fixed; P3 pairs would be millions of rows)
CREATE TABLE IF NOT EXISTS roll_fix (
  cid TEXT NOT NULL, fix_id BIGINT NOT NULL, product TEXT, vendor TEXT, findings INTEGER NOT NULL, p1 INTEGER NOT NULL, p2 INTEGER NOT NULL,
  cves INTEGER NOT NULL, p1_cves INTEGER NOT NULL, kev_cves INTEGER NOT NULL, hosts INTEGER NOT NULL, p1_hosts INTEGER NOT NULL, inet_hosts INTEGER NOT NULL,
  rank SMALLINT NOT NULL, exprt_lvl SMALLINT NOT NULL, first_seen BIGINT, PRIMARY KEY (cid, fix_id)
);
-- the pairs behind a fix: its hosts and its CVEs (the fix drawer and the graph read these instead of scanning findings)
CREATE TABLE IF NOT EXISTS roll_fix_host (
  cid TEXT NOT NULL, fix_id BIGINT NOT NULL, aid TEXT NOT NULL, findings INTEGER NOT NULL, p1 INTEGER NOT NULL, p2 INTEGER NOT NULL, kev INTEGER NOT NULL, inet BOOLEAN NOT NULL
);
-- The pair tables have no PRIMARY KEY on purpose: a rebuild deletes and re-inserts the same keys in one transaction, and a UNIQUE index then checks the heap for every one of the millions of rows (minutes). The pairs are unique by construction (GROUP BY).
CREATE INDEX IF NOT EXISTS roll_fix_host_key ON roll_fix_host (cid, fix_id, aid);
CREATE INDEX IF NOT EXISTS roll_fix_host_aid ON roll_fix_host (cid, aid);
CREATE TABLE IF NOT EXISTS roll_fix_cve (
  cid TEXT NOT NULL, fix_id BIGINT NOT NULL, cve_id TEXT NOT NULL, hosts INTEGER NOT NULL, findings INTEGER NOT NULL, tier SMALLINT NOT NULL, kev SMALLINT NOT NULL
);
CREATE INDEX IF NOT EXISTS roll_fix_cve_key ON roll_fix_cve (cid, fix_id, cve_id);
CREATE INDEX IF NOT EXISTS roll_fix_cve_cve ON roll_fix_cve (cid, cve_id);
-- the pairs behind a product (the 300 products with the most P1/P2 findings): what the product x group matrix reads
CREATE TABLE IF NOT EXISTS roll_prod_host (
  cid TEXT NOT NULL, product TEXT NOT NULL, aid TEXT NOT NULL, findings INTEGER NOT NULL, p1 INTEGER NOT NULL, p2 INTEGER NOT NULL, kev INTEGER NOT NULL, inet BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS roll_prod_host_key ON roll_prod_host (cid, product, aid);
CREATE INDEX IF NOT EXISTS roll_prod_host_aid ON roll_prod_host (cid, aid);
-- graph: one row per (fix | product, dimension value). Three sets: 1 = P1 findings, 12 = P1+P2, k = KEV (all KEV findings are P1). h = distinct hosts, hi = of them internet-facing, f = findings.
CREATE TABLE IF NOT EXISTS roll_fix_dim (
  cid TEXT NOT NULL, dim TEXT NOT NULL, dim_id TEXT NOT NULL, fix_id BIGINT NOT NULL,
  h1 INTEGER NOT NULL DEFAULT 0, hi1 INTEGER NOT NULL DEFAULT 0, f1 INTEGER NOT NULL DEFAULT 0, h12 INTEGER NOT NULL DEFAULT 0, hi12 INTEGER NOT NULL DEFAULT 0, f12 INTEGER NOT NULL DEFAULT 0,
  hk INTEGER NOT NULL DEFAULT 0, hik INTEGER NOT NULL DEFAULT 0, fk INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cid, dim, dim_id, fix_id)
);
CREATE INDEX IF NOT EXISTS roll_fix_dim_fix ON roll_fix_dim (cid, fix_id);
CREATE TABLE IF NOT EXISTS roll_prod_dim (
  cid TEXT NOT NULL, dim TEXT NOT NULL, dim_id TEXT NOT NULL, product TEXT NOT NULL,
  h1 INTEGER NOT NULL DEFAULT 0, hi1 INTEGER NOT NULL DEFAULT 0, f1 INTEGER NOT NULL DEFAULT 0, h12 INTEGER NOT NULL DEFAULT 0, hi12 INTEGER NOT NULL DEFAULT 0, f12 INTEGER NOT NULL DEFAULT 0,
  hk INTEGER NOT NULL DEFAULT 0, hik INTEGER NOT NULL DEFAULT 0, fk INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cid, dim, dim_id, product)
);
-- fix-level and product-level totals for the three sets (see roll_fix_dim) so the graph's default reads are one small table; fi = findings on internet-facing hosts
ALTER TABLE roll_fix_dim ADD COLUMN IF NOT EXISTS fi1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix_dim ADD COLUMN IF NOT EXISTS fi12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix_dim ADD COLUMN IF NOT EXISTS fik INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_prod_dim ADD COLUMN IF NOT EXISTS fi1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_prod_dim ADD COLUMN IF NOT EXISTS fi12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_prod_dim ADD COLUMN IF NOT EXISTS fik INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS h1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS hi1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS f1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS fi1 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS h12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS hi12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS f12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS fi12 INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS hk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS hik INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS fk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE roll_fix ADD COLUMN IF NOT EXISTS fik INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS roll_prod (
  cid TEXT NOT NULL, product TEXT NOT NULL, h1 INTEGER NOT NULL DEFAULT 0, hi1 INTEGER NOT NULL DEFAULT 0, f1 INTEGER NOT NULL DEFAULT 0, fi1 INTEGER NOT NULL DEFAULT 0, h12 INTEGER NOT NULL DEFAULT 0, hi12 INTEGER NOT NULL DEFAULT 0,
  f12 INTEGER NOT NULL DEFAULT 0, fi12 INTEGER NOT NULL DEFAULT 0, hk INTEGER NOT NULL DEFAULT 0, hik INTEGER NOT NULL DEFAULT 0, fk INTEGER NOT NULL DEFAULT 0, fik INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (cid, product)
);
-- which P1 CVEs sit on which product name (lower-cased; both the full name+version and the name without its version), and how many P1 / KEV CVEs each Discover software item has by that name (rollup.ts refreshSoftware)
CREATE TABLE IF NOT EXISTS roll_p1_prod (cid TEXT NOT NULL, key TEXT NOT NULL, cve_id TEXT NOT NULL, kev SMALLINT NOT NULL);
CREATE INDEX IF NOT EXISTS roll_p1_prod_key ON roll_p1_prod (cid, key, cve_id);
CREATE TABLE IF NOT EXISTS roll_soft (cid TEXT NOT NULL, type TEXT NOT NULL, vendor TEXT NOT NULL, name TEXT NOT NULL, p1_cves INTEGER NOT NULL, kev_cves INTEGER NOT NULL, PRIMARY KEY (cid, type, vendor, name));
-- how many hosts each dimension value has (group / os / site), for the graph columns and filters
CREATE TABLE IF NOT EXISTS roll_dim (cid TEXT NOT NULL, dim TEXT NOT NULL, dim_id TEXT NOT NULL, hosts INTEGER NOT NULL, PRIMARY KEY (cid, dim, dim_id));
-- one row per CID per UTC day (the last write of the day): what the 30/90-day trend and the portfolio sparkline draw. falcon_json = the exact Falcon counts at that time (cid_counts).
CREATE TABLE IF NOT EXISTS hist_day (
  cid TEXT NOT NULL, day TEXT NOT NULL, p1 INTEGER NOT NULL, p2 INTEGER NOT NULL, p3 INTEGER NOT NULL, held BIGINT NOT NULL, hosts_p1 INTEGER NOT NULL, hosts_total INTEGER NOT NULL,
  critical BIGINT, high BIGINT, medium BIGINT, low BIGINT, "none" BIGINT, kev BIGINT, exploited BIGINT, falcon_json TEXT NOT NULL DEFAULT '{}', written_at BIGINT NOT NULL, PRIMARY KEY (cid, day)
);
CREATE TABLE IF NOT EXISTS mail_senders (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
  security TEXT NOT NULL CHECK (security IN ('tls','starttls','none')), username TEXT, password_sealed TEXT,
  from_name TEXT, from_email TEXT NOT NULL, is_default INTEGER NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_recipients (
  id TEXT PRIMARY KEY, email TEXT NOT NULL CHECK (email = lower(email)), name TEXT,
  tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE, enabled INTEGER NOT NULL DEFAULT 1, created_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS mail_recipients_uq ON mail_recipients (email, COALESCE(tenant_id, ''));
CREATE TABLE IF NOT EXISTS mail_subscriptions (
  recipient_id TEXT NOT NULL REFERENCES mail_recipients(id) ON DELETE CASCADE, event TEXT NOT NULL, PRIMARY KEY (recipient_id, event)
);
CREATE TABLE IF NOT EXISTS mail_log (
  id BIGSERIAL PRIMARY KEY, ts BIGINT NOT NULL, event TEXT NOT NULL, recipient TEXT NOT NULL, state TEXT NOT NULL, error TEXT
);

-- Hosts an organization watches (watch.ts): shared by its users, at most 200.
CREATE TABLE IF NOT EXISTS watch_hosts (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, aid TEXT NOT NULL, cid TEXT NOT NULL, hostname TEXT, note TEXT NOT NULL DEFAULT '',
  added_by TEXT, added_by_name TEXT, added_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id, aid)
);
-- What an organization's LINE messages carry (notify.ts). No row = every severity, every device name.
CREATE TABLE IF NOT EXISTS notify_prefs (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, enabled BOOLEAN NOT NULL DEFAULT true, severities TEXT NOT NULL DEFAULT '["CRITICAL","HIGH","MEDIUM","LOW","NONE"]',
  p1_always BOOLEAN NOT NULL DEFAULT true, devices_mode TEXT NOT NULL DEFAULT 'all' CHECK (devices_mode IN ('all','watched','top')), top_n INTEGER NOT NULL DEFAULT 10, max_names INTEGER NOT NULL DEFAULT 20,
  news_possible BOOLEAN NOT NULL DEFAULT false, news_host_names BOOLEAN NOT NULL DEFAULT false, updated_by TEXT, updated_at BIGINT NOT NULL
);
-- Notify level (alertlevel.ts). matrix_on = false keeps the old behaviour (filter on the CVE severity); matrix_json NULL = the default 4x4 matrix; esc_* = escalation to CRITICAL on evidence.
ALTER TABLE notify_prefs ADD COLUMN IF NOT EXISTS matrix_on BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE notify_prefs ADD COLUMN IF NOT EXISTS matrix_json TEXT;
ALTER TABLE notify_prefs ADD COLUMN IF NOT EXISTS esc_alert BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE notify_prefs ADD COLUMN IF NOT EXISTS esc_days INTEGER NOT NULL DEFAULT 7;
ALTER TABLE notify_prefs ADD COLUMN IF NOT EXISTS esc_kev BOOLEAN NOT NULL DEFAULT false;
-- the manual level of a watched host (NULL = none set: Falcon's criticality or the host group decides)
ALTER TABLE watch_hosts ADD COLUMN IF NOT EXISTS criticality TEXT CHECK (criticality IN ('CRITICAL','HIGH','MEDIUM','LOW'));
-- host group name -> asset level, per organization
CREATE TABLE IF NOT EXISTS notify_group_levels (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, group_name TEXT NOT NULL, level TEXT NOT NULL CHECK (level IN ('CRITICAL','HIGH','MEDIUM','LOW')), PRIMARY KEY (tenant_id, group_name)
);
-- evidence cache: did Falcon raise an alert on this machine in the last esc_days days. aid '*' = the organization's alerts-API status (state 'ok' | 'forbidden'). Read-only lookups, kept 30 minutes.
CREATE TABLE IF NOT EXISTS attack_evidence (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, aid TEXT NOT NULL, state TEXT NOT NULL, days INTEGER NOT NULL DEFAULT 7, alerts INTEGER NOT NULL DEFAULT 0, alert_id TEXT, checked_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, aid)
);
-- Where a news CVE stands for one organization (news.ts): exact | possible | wait | not_affected. notified_* = what the organization was last told, so only a material change is told again.
CREATE TABLE IF NOT EXISTS news_match (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, cve TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('exact','possible','wait','not_affected')),
  devices INTEGER NOT NULL DEFAULT 0, first_seen BIGINT NOT NULL, last_changed BIGINT NOT NULL, notified_state TEXT, notified_devices INTEGER, notified_at BIGINT, PRIMARY KEY (tenant_id, cve)
);
-- Falcon EASM extras (falcon.ts storeExternal): where an asset is, how Falcon found it, and every service with its TLS certificate.
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS region TEXT;
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS asn BIGINT;
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS ptr TEXT;
ALTER TABLE external_assets ADD COLUMN IF NOT EXISTS discovery_json TEXT;
CREATE TABLE IF NOT EXISTS external_services (
  cid TEXT NOT NULL, asset_id TEXT NOT NULL, svc TEXT NOT NULL, port INTEGER, transport TEXT, protocol TEXT, status TEXT, status_code INTEGER, os TEXT, first_seen BIGINT, last_seen BIGINT, apps_json TEXT,
  tls_version TEXT, cert_issuer TEXT, cert_subject TEXT, cert_from BIGINT, cert_to BIGINT, cert_sig TEXT, cert_fingerprint TEXT, PRIMARY KEY (cid, asset_id, svc)
);
CREATE INDEX IF NOT EXISTS external_services_cert ON external_services (cid, cert_to);
-- The CVE record's affected vendor/product (feeds.ts), what a "possible" news match compares with installed software.
ALTER TABLE cve_public ADD COLUMN IF NOT EXISTS affected_json TEXT;
`);

// One-time upgrade from the first version (four fixed roles, one tenant per user) to super admin + per-tenant admin/operator.
{
  const old = await pool.query(`SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'tenant_id'`);
  if (old.rowCount) {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query(`INSERT INTO user_tenants (user_id, tenant_id, role) SELECT id, tenant_id, CASE role WHEN 'customer_admin' THEN 'admin' ELSE 'operator' END FROM users WHERE tenant_id IS NOT NULL ON CONFLICT DO NOTHING`);
      // SOC analysts used to see every tenant: keep that as operator access to the tenants that exist now
      await c.query(`INSERT INTO user_tenants (user_id, tenant_id, role) SELECT u.id, t.id, 'operator' FROM users u CROSS JOIN tenants t WHERE u.role = 'soc_analyst' ON CONFLICT DO NOTHING`);
      await c.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check`);
      await c.query(`ALTER TABLE users DROP COLUMN tenant_id`);
      await c.query(`UPDATE users SET role = CASE role WHEN 'soc_admin' THEN 'super_admin' ELSE 'member' END`);
      await c.query(`ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('super_admin','member'))`);
      await c.query(`ALTER TABLE invites ADD COLUMN IF NOT EXISTS memberships_json TEXT NOT NULL DEFAULT '[]'`);
      await c.query(`UPDATE invites SET memberships_json = CASE WHEN tenant_id IS NULL THEN '[]' ELSE '[{"tenantId":"' || tenant_id || '","role":"' || CASE WHEN role = 'customer_admin' THEN 'admin' ELSE 'operator' END || '"}]' END, role = CASE role WHEN 'soc_admin' THEN 'super_admin' ELSE 'member' END`);
      await c.query(`ALTER TABLE invites DROP COLUMN tenant_id`);
      await c.query("COMMIT");
    } catch (e) { await c.query("ROLLBACK"); throw e; } finally { c.release(); }
  }
}

export const now = () => Date.now();
/** Names in dictionary order, Thai included. The database orders by code point, which is wrong for Thai names that start with a leading vowel. */
export const byName = <T extends { name: string }>(rows: T[]): T[] => rows.sort((a, b) => nameOrder.compare(a.name, b.name));
export const nameOrder = new Intl.Collator(["th", "en"], { sensitivity: "base", numeric: true });

/** Queries inside tx() automatically use the transaction's connection. */
const txClient = new AsyncLocalStorage<pg.PoolClient>();
type Param = string | number | null;
// SQL in this code base is written with "?" placeholders; Postgres wants $1, $2, ...
const toPg = (sql: string) => { let n = 0; return sql.replace(/\?/g, () => `$${++n}`); };
const q = (sql: string, p: Param[]) => (txClient.getStore() ?? pool).query(toPg(sql), p);

export const all = async <T = Record<string, unknown>>(sql: string, ...p: Param[]) => (await q(sql, p)).rows as T[];
export const get = async <T = Record<string, unknown>>(sql: string, ...p: Param[]) => (await q(sql, p)).rows[0] as T | undefined;
export const run = async (sql: string, ...p: Param[]) => { await q(sql, p); };
export async function tx<T>(fn: () => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await txClient.run(client, fn);
    await client.query("COMMIT");
    return r;
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    throw e;
  } finally { client.release(); }
}

/** Insert many rows in a few round trips. Table and column names are code constants, never user input. */
export async function insertMany<T = never>(table: string, cols: string[], rows: Param[][], onConflict = "", returning = ""): Promise<T[]> {
  const per = Math.floor(60000 / cols.length);
  const out: T[] = [];
  for (let i = 0; i < rows.length; i += per) {
    const chunk = rows.slice(i, i + per);
    const sql = `INSERT INTO ${table} (${cols.join(",")}) VALUES ${chunk.map(() => `(${cols.map(() => "?").join(",")})`).join(",")} ${onConflict} ${returning ? `RETURNING ${returning}` : ""}`;
    if (returning) out.push(...(await all<T>(sql, ...chunk.flat()))); else await run(sql, ...chunk.flat());
  }
  return out;
}

export interface AuditInput {
  actor?: Pick<User, "id" | "email" | "role"> | null; tenantId?: string | null; action: string;
  resource?: string | null; result: "allowed" | "denied" | "ok" | "fail"; ip?: string | null; detail?: string | null;
}
export async function audit(a: AuditInput) {
  await run("INSERT INTO audit (ts, actor_id, actor_email, role, tenant_id, action, resource, result, ip, detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
    now(), a.actor?.id ?? null, a.actor?.email ?? null, a.actor?.role ?? null, a.tenantId ?? null, a.action, a.resource ?? null, a.result, a.ip ?? null, a.detail ?? null);
}
