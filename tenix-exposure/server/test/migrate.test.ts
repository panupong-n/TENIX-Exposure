// A database from before the findings table was split (remediation texts on every row) is upgraded in place when the server starts, and nothing a reader sees changes.
import { testDatabaseUrl } from "./test-db.ts";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { after, test } from "node:test";
import pg from "pg";

const url = testDatabaseUrl();
const schema = `m_${Math.random().toString(36).slice(2, 10)}`;
const admin = new pg.Client({ connectionString: url });
await admin.connect();
after(async () => { await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await admin.end(); });

const boot = () => spawnSync(process.execPath, ["--input-type=module", "-e", "await import('./src/db.ts'); const { pool } = await import('./src/db.ts'); await pool.end();"],
  { cwd: new URL("..", import.meta.url).pathname, env: { ...process.env, TENIX_DATABASE_URL: url, TENIX_DB_SCHEMA: schema, TENIX_SECRET_KEY: Buffer.alloc(32, 7).toString("base64") }, encoding: "utf8" });

test("the old findings table is renamed, its remediation texts move into rem_sets once, and the findings view answers as before", async () => {
  await admin.query(`CREATE SCHEMA ${schema}`);
  await admin.query(`SET search_path = ${schema}`);
  await admin.query(`CREATE TABLE findings (
    cid TEXT NOT NULL, finding_id TEXT NOT NULL, aid TEXT NOT NULL, cve_id TEXT NOT NULL, severity TEXT NOT NULL, base_score DOUBLE PRECISION, exprt TEXT, exploit_status INTEGER, hostname TEXT, platform TEXT,
    local_ip TEXT, external_ip TEXT, product TEXT, status TEXT, remediation TEXT, synced_at BIGINT NOT NULL, provider TEXT, remediation_json TEXT, kind TEXT, PRIMARY KEY (cid, finding_id))`);
  const text = "- Update to 2.0\n- Apply KB1", json = '[{"action":"Update to 2.0","link":"https://x.example/a","type":"recommended"}]';
  for (const [id, rem, js] of [["f1", text, json], ["f2", text, json], ["f3", null, null], ["f4", "- Other", null]] as const)
    await admin.query("INSERT INTO findings (cid, finding_id, aid, cve_id, severity, remediation, remediation_json, synced_at) VALUES ('c1', $1, 'a', 'CVE-2026-1', 'HIGH', $2, $3, 1)", [id, rem, js]);

  for (const round of [1, 2]) { // the second start finds nothing left to do
    const r = boot();
    assert.equal(r.status, 0, `start ${round}: ${r.stderr.slice(0, 400)}`);
    const rows = (await admin.query("SELECT finding_id, remediation, remediation_json FROM findings ORDER BY finding_id")).rows;
    assert.deepEqual(rows.map((x) => [x.finding_id, x.remediation, x.remediation_json]), [["f1", text, json], ["f2", text, json], ["f3", null, null], ["f4", "- Other", null]]);
    assert.equal((await admin.query("SELECT COUNT(*)::int n FROM rem_sets")).rows[0].n, 2, "two distinct sets, not four copies");
  }
  const cols = (await admin.query("SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'findings_t'", [schema])).rows.map((r) => r.column_name);
  assert.ok(cols.includes("rem_set") && !cols.includes("remediation") && !cols.includes("remediation_json"));
  const key = (await admin.query("SELECT rem_set::text k FROM findings_t WHERE finding_id = 'f1'")).rows[0].k;
  assert.equal(Number(key), parseInt(createHash("md5").update(`${json}|${text}`).digest("hex").slice(0, 12), 16), "the key the sync computes is the key the upgrade wrote");
  await admin.query("DELETE FROM findings WHERE finding_id = 'f4'"); // a delete through the view reaches the table (the tenant delete and the removal of a connection do this)
  assert.equal((await admin.query("SELECT COUNT(*)::int n FROM findings_t")).rows[0].n, 3);
});
