// The findings sync engine against the mock Falcon: exact counts, the priority slice, the watermark (resume, incremental), closures, reconcile and honest states.
import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl(); // throws unless 127.0.0.1:5433/tenix_test
process.env.TENIX_DB_SCHEMA = `s_${Math.random().toString(36).slice(2, 10)}`; // throwaway schema per run
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.TENIX_DEV_FALCON_URL_OK = "1";
import assert from "node:assert/strict";
import { after, before, beforeEach, describe, test } from "node:test";
import type { Server } from "node:http";
import { CID_ONE, CID_TWO, MOCK_CLIENT, MOCK_SECRET, startMock, type MockControl } from "./mock-falcon.ts";

const dbm = await import("../src/db.ts");
const falcon = await import("../src/falcon.ts");
const ret = await import("../src/retention.ts");

falcon.hooks.sleep = async () => {};
falcon.hooks.rollupMinMs = 0; // the tests look at the pages after every run, also an unfinished one
const hooksDefault = { ...falcon.hooks };
let mock: MockControl, server: Server, url = "";
const client = (secret = MOCK_SECRET, base = url) => new falcon.FalconClient({ baseUrl: base, clientId: MOCK_CLIENT, clientSecret: secret });
const sync = (cid = CID_ONE, onProgress?: (p: any) => void) => falcon.syncFindings(client(), cid, onProgress);
const openRows = (cid = CID_ONE) => mock.data.findings.filter((f) => f.cid === cid && ["open", "reopen"].includes(f.status));
/** The fix-first slice as the tests compute it themselves (not with the code under test). */
const inSlice = (f: any) => f.cve.severity === "CRITICAL" || f.cve.exprt_rating === "CRITICAL" || [60, 70, 80, 90].includes(f.cve.exploit_status) || !!f.cve.cisa_info?.is_cisa_kev;
const held = async (cid = CID_ONE) => (await dbm.get<{ n: number }>("SELECT COUNT(*) n FROM findings WHERE cid = ?", cid))!.n;
const counts = async (cid = CID_ONE) => Object.fromEntries((await dbm.all<{ key: string; n: number }>("SELECT key, n FROM cid_counts WHERE cid = ?", cid)).map((r) => [r.key, r.n]));
const status = (cid = CID_ONE) => dbm.get<any>("SELECT * FROM cid_status WHERE cid = ?", cid);
const syncRow = (cid = CID_ONE) => dbm.get<any>("SELECT * FROM cid_sync WHERE cid = ?", cid);
const cursor = (name: string, cid = CID_ONE) => dbm.get<any>("SELECT * FROM cid_cursor WHERE cid = ? AND name = ?", cid, name);
const findingPages = (from: number) => mock.requests.slice(from).filter((q) => q.includes("sort=updated_timestamp") && !q.includes("expired")).map((q) => decodeURIComponent(q)); // the expired feed also sorts by updated_timestamp

before(async () => {
  await dbm.run("INSERT INTO tenants (id, name, created_at) VALUES ('tt', 'Sync Co', ?)", Date.now());
  await dbm.run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?, 'tt')", CID_ONE);
});
beforeEach(async () => {
  server?.close();
  const m = await startMock();
  mock = m.control; server = m.server; url = m.url;
  Object.assign(falcon.hooks, hooksDefault, { pageSizes: [300] }); // 1,400 findings of CID_ONE = 5 pages
  // two medium CVEs are in CISA's list: every row of them is KEV, so KEV is the only reason they are in the slice
  const kev = [...new Set(mock.data.findings.filter((f) => f.cid === CID_ONE && f.cve.severity === "MEDIUM" && f.cve.exprt_rating === "MEDIUM" && f.cve.exploit_status === 0).map((f) => f.cve.id))].slice(0, 2);
  for (const f of mock.data.findings) if (kev.includes(f.cve.id)) f.cve = { ...f.cve, types: ["Vulnerability"], cisa_info: { is_cisa_kev: true } };
  await dbm.run("DELETE FROM tenant_settings");
  ret.retentionHooks.graceMs = 3 * 86400_000; ret.retentionHooks.purgeChunk = 50_000;
  for (const t of ["findings", "cid_status", "cid_sync", "cid_cursor", "cid_counts", "finding_closed", "snapshots", "alerts", "sync_runs"]) await dbm.run(t === "alerts" ? "DELETE FROM alerts" : `DELETE FROM ${t}`);
});
after(async () => {
  server.close();
  await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`);
  await dbm.pool.end();
});

describe("exact counts and the two phases", () => {
  test("Falcon's own totals are stored every run: severity, KEV, ExPRT, exploited and the slice; the snapshot uses them", async () => {
    const r = await sync();
    assert.equal(r.state, "complete");
    const rows = openRows(), c = await counts();
    const n = (p: (f: any) => boolean) => rows.filter(p).length;
    assert.deepEqual(
      [c.total, c.critical, c.high, c.medium, c.low, c.kev, c.exprtCritical, c.exprtHigh, c.exploited, c.slice],
      [rows.length, n((f) => f.cve.severity === "CRITICAL"), n((f) => f.cve.severity === "HIGH"), n((f) => f.cve.severity === "MEDIUM"), n((f) => f.cve.severity === "LOW"),
        n((f) => f.cve.cisa_info?.is_cisa_kev), n((f) => f.cve.exprt_rating === "CRITICAL"), n((f) => f.cve.exprt_rating === "HIGH"), n((f) => [60, 70, 80, 90].includes(f.cve.exploit_status)), n(inSlice)]);
    assert.ok(c.kev > 0 && c.slice < c.total, "the fixture has KEV rows and rows outside the slice");
    const snap = (await dbm.get<any>("SELECT * FROM snapshots WHERE cid = ?", CID_ONE))!;
    assert.deepEqual([snap.critical, snap.high, snap.medium, snap.low], [c.critical, c.high, c.medium, c.low], "the snapshot is Falcon's exact count");
  });

  test("every open finding of every severity is stored, for a big and a small organization alike; the coverage converges to held == Falcon's total", async () => {
    assert.equal((await sync()).state, "complete");
    assert.equal((await sync(CID_TWO)).state, "complete");
    assert.equal(await held(CID_ONE), openRows().length);
    assert.equal(await held(CID_TWO), openRows(CID_TWO).length);
    const slice = openRows().filter(inSlice);
    const cov = await falcon.loadCoverage([CID_ONE]);
    assert.deepEqual(cov.coverage, { held: openRows().length, falconTotal: openRows().length, priorityHeld: slice.length, priorityTotal: slice.length, priorityPass: true, fullPass: true, scope: "all", keptTotal: openRows().length });
    assert.equal(cov.falconCounts!.total, openRows().length);
    assert.deepEqual((await falcon.loadCoverage([CID_ONE, CID_TWO])).falconCounts!.total, openRows().length + openRows(CID_TWO).length, "counts add up across the CIDs of an organization");
    assert.deepEqual(await falcon.loadCoverage(["9".repeat(32)]), { coverage: null, falconCounts: null }, "a CID this engine never read has no coverage");
  });

  test("phase A stores the fix-first slice first and the state stays partial (held X of Y) until phase B has stored the rest; then it is complete", async () => {
    const isB = (q: string) => q.includes("sort=updated_timestamp") && !q.includes("exprt_rating") && !q.includes("expired"); // a page request of the backfill, not of the slice
    mock.fail(isB, 500, 99, 1); // the slice is fine; the backfill gets one page and then Falcon fails
    const r1 = await sync();
    assert.deepEqual([r1.state, r1.reason], ["partial", "error"]);
    const slice = openRows().filter(inSlice);
    assert.ok((await syncRow()).slice_done_at, "phase A is done");
    assert.equal((await syncRow()).first_done_at, null);
    const stored = await dbm.all<any>("SELECT finding_id, severity FROM findings WHERE cid = ?", CID_ONE);
    assert.ok(stored.length >= slice.length && stored.length < openRows().length, `${stored.length} stored of ${openRows().length}`);
    assert.ok(slice.every((f) => stored.some((x) => x.finding_id === f.id)), "every fix-first finding is already there");
    const cov = (await falcon.loadCoverage([CID_ONE])).coverage!;
    assert.deepEqual([cov.priorityPass, cov.fullPass, cov.held < cov.falconTotal!, cov.priorityHeld], [true, false, true, slice.length]);
    assert.equal((await status()).state, "partial");

    mock.clearFailures();
    const from = mock.requests.length;
    const r2 = await sync();
    assert.equal(r2.state, "complete");
    assert.ok(findingPages(from).some((q) => q.includes("exprt_rating")), "the slice keeps running during the backfill");
    assert.equal(await held(), openRows().length);
    assert.equal((await falcon.loadCoverage([CID_ONE])).coverage!.fullPass, true);
    assert.deepEqual(r2.fresh, [], "what the backfill brings is not news");
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM alerts WHERE reason = 'first_impact'"))!.n, 0, "and no urgent item for CVEs that were simply not read yet");
  });

  test("a new CRITICAL finding during the backfill is reported once (phase A keeps watching), while the backfill goes on", async () => {
    const isB = (q: string) => q.includes("sort=updated_timestamp") && !q.includes("exprt_rating") && !q.includes("expired");
    mock.fail(isB, 500, 99, 1);
    await sync();
    mock.clearFailures();
    mock.add({ cid: CID_ONE, status: "open", id: "crit-during-b", aid: "e".repeat(32), apps: [], host_info: {}, cve: { id: "CVE-2099-4321", severity: "CRITICAL", base_score: 9.8, exprt_rating: "CRITICAL", exploit_status: 0 } });
    mock.fail(isB, 500, 99, 1);
    const r = await sync();
    assert.deepEqual(r.fresh, [{ cve_id: "CVE-2099-4321", aid: "e".repeat(32) }]);
    mock.clearFailures();
    assert.deepEqual((await sync()).fresh, []);
  });
});

describe("the watermark", () => {
  test("a first pass that is interrupted keeps what it stored, shows as partial, and the next run resumes from the watermark", async () => {
    const isB = (q: string) => q.includes("sort=updated_timestamp") && !q.includes("exprt_rating") && !q.includes("expired"); // a page of the backfill (phase B)
    mock.fail(isB, 500, 99, 2); // two backfill pages are fine, then Falcon fails
    const r1 = await sync();
    assert.deepEqual([r1.state, r1.reason], ["partial", "error"]);
    const sliceN = openRows().filter(inSlice).length;
    assert.ok(await held() > sliceN && await held() <= sliceN + 600, "the slice and the first two backfill pages are stored, page by page");
    assert.ok(mock.maxPage <= 300, "never more than one page in a Falcon answer");
    const st = await status();
    assert.deepEqual([st.state, st.reason], ["partial", "error"]);
    assert.ok(st.data_as_of, "what is held is real and shown");
    assert.equal((await syncRow()).first_done_at, null);
    const wm = (await cursor("inc")).wm;
    assert.ok(wm > Date.parse("2026-11-01T00:00:00Z"), "the watermark moved with the stored pages");
    assert.ok((await cursor("slice")).wm > 0, "and phase A keeps its own");
    const cov = (await falcon.loadCoverage([CID_ONE])).coverage!;
    assert.deepEqual([cov.held, cov.falconTotal, cov.fullPass], [await held(), openRows().length, false]);

    mock.clearFailures();
    const from = mock.requests.length;
    const r2 = await sync();
    assert.equal(r2.state, "complete");
    const first = findingPages(from)[0];
    assert.match(first, /updated_timestamp:>'2026-11-01T/, "it asks for what is newer than the watermark");
    assert.ok(!first.includes("after="), "and does not depend on the old cursor");
    assert.ok(r2.read < openRows().length + sliceN - 400, `resumed, did not start over (${r2.read} read)`);
    assert.equal(await held(), openRows().length);
    assert.ok((await syncRow()).first_done_at);
    assert.equal((await falcon.loadCoverage([CID_ONE])).coverage!.fullPass, true);
  });

  test("a cursor Falcon has forgotten is not a failure: the walk restarts from the watermark", async () => {
    mock.dropCursors(1);
    const r = await sync();
    assert.equal(r.state, "complete");
    assert.equal(await held(), openRows().length);
  });

  test("the incremental run reads only what changed, and a repeated run changes nothing", async () => {
    await sync();
    const a = openRows()[10], b = openRows()[900];
    a.cve = { ...a.cve, base_score: 1.5 }; mock.touch(a);
    mock.touch(b, "reopen");
    const fresh = { cid: CID_ONE, status: "open", id: "brand-new", aid: "c".repeat(32), apps: [{ product_name_version: "X 1" }], host_info: {}, cve: { id: "CVE-2099-5", severity: "LOW", base_score: 3 } };
    mock.add(fresh);
    const from = mock.requests.length;
    const r = await sync();
    assert.equal(r.state, "complete");
    assert.equal(findingPages(from).length, 1, "one page");
    assert.ok(r.read < 60, `only the changes and the safety margin were read (${r.read})`);
    assert.equal(await held(), openRows().length);
    assert.equal((await dbm.get<any>("SELECT base_score FROM findings WHERE finding_id = ?", a.id))!.base_score, 1.5);
    assert.equal((await dbm.get<any>("SELECT status FROM findings WHERE finding_id = ?", b.id))!.status, "reopen");
    const again = await sync();
    assert.ok(again.read <= r.read && again.state === "complete");
    assert.equal(await held(), openRows().length, "an upsert twice is one row");
  });

  test("a time budget ends the run as partial without a reason, and the next run continues", async () => {
    mock.delayMs = 150; falcon.hooks.budgetMs = 700; // the budget starts after the count requests; the closed and expired feeds use 300 ms of it
    const r = await sync();
    assert.equal(r.state, "partial");
    assert.equal(r.reason, null, "slow is not an error");
    assert.ok(r.read > 0 && r.read < openRows().length, `${r.read} read, pages ${r.pages}, notes ${JSON.stringify(r.notes)}, missing ${JSON.stringify(r.missing)}`);
    assert.ok(r.notes.some((x) => /time budget reached/.test(x)));
    mock.delayMs = 0; falcon.hooks.budgetMs = 20 * 60_000;
    assert.equal((await sync()).state, "complete");
    assert.equal(await held(), openRows().length);
  });

  test("a CID whose status row is gone starts clean: a stale watermark of a removed connection is not trusted", async () => {
    await sync();
    mock.add({ cid: CID_ONE, status: "open", id: "late-1", aid: "d".repeat(32), apps: [], host_info: {}, cve: { id: "CVE-2099-9", severity: "CRITICAL", base_score: 9 } });
    await dbm.run("DELETE FROM cid_status WHERE cid = ?", CID_ONE);
    const r = await sync();
    assert.deepEqual([r.state, r.fresh], ["complete", []], "a new first pass reports no new critical");
    assert.equal(await held(), openRows().length);
  });
});

describe("closed findings", () => {
  test("closures arrive from Falcon's closed feed for every row: held rows are removed and written to the history with Falcon's time; a reopened finding stays", async () => {
    await sync();
    const rows = openRows(), inside = rows.filter(inSlice), outside = rows.filter((f) => !inSlice(f));
    const [x, y, reopened] = inside.slice(5, 8), z = outside[0], w = outside[1];
    mock.touch(x, "closed"); mock.touch(y, "closed"); mock.touch(z, "closed");
    mock.touch(reopened, "closed"); mock.touch(reopened, "reopen"); // closed and opened again
    mock.touch(w, "closed"); mock.touch(w, "reopen");
    const r = await sync();
    assert.equal(r.state, "complete");
    const gone = await dbm.all<any>("SELECT finding_id, closed_at FROM finding_closed WHERE cid = ? ORDER BY finding_id", CID_ONE);
    assert.deepEqual(gone.map((g) => g.finding_id), [x.id, y.id, z.id].sort(), "a finding outside the slice is closed too");
    assert.equal(gone.find((g) => g.finding_id === x.id).closed_at, Date.parse(x.closed_timestamp), "the history carries Falcon's closing time");
    assert.equal(await dbm.get<any>("SELECT 1 FROM findings WHERE finding_id = ?", x.id), undefined);
    assert.ok(await dbm.get<any>("SELECT 1 FROM findings WHERE finding_id = ?", reopened.id), "reopened: still here");
    assert.equal((await counts()).total, openRows().length, "the exact count follows");
    assert.equal(await held(), openRows().length);
    const again = await sync();
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM finding_closed WHERE cid = ?", CID_ONE)).n, 3, "a repeated run records nothing again");
    assert.equal(again.state, "complete");
  });
});

describe("reconcile", () => {
  const old = (days: number) => dbm.run("UPDATE cid_sync SET last_scan_done_at = ? WHERE cid = ?", Date.now() - days * 86400_000, CID_ONE);

  test("a periodic re-scan removes what Falcon no longer lists (expired) and that the incremental feed cannot see", async () => {
    await sync();
    mock.data.findings.splice(mock.data.findings.findIndex((f) => f.cid === CID_ONE), 5); // gone at Falcon without being closed
    await sync();
    assert.equal(await held(), openRows().length + 5, "the feed of changes does not notice");
    await old(8);
    const r = await sync();
    assert.ok(r.notes.some((x) => /reconcile started: periodic/.test(x)) && r.notes.some((x) => /5 findings no longer in Falcon's set were removed/.test(x)), JSON.stringify(r.notes));
    assert.equal(await held(), openRows().length);
    assert.equal(r.state, "complete");
  });

  test("a drift between what is stored and what Falcon counts starts a re-scan on its own (at most once a day)", async () => {
    await sync();
    mock.data.findings.splice(0, 80, ...mock.data.findings.slice(0, 80).filter((f) => f.cid !== CID_ONE)); // 80 findings of CID_ONE vanish: more than 1 per cent
    await old(2);
    const r = await sync();
    assert.ok(r.notes.some((x) => /reconcile started: stored and Falcon counts drifted/.test(x)), JSON.stringify(r.notes));
    assert.equal(await held(), openRows().length);
    const quiet = await sync();
    assert.ok(!quiet.notes.some((x) => /reconcile started/.test(x)), "no second re-scan right after");
  });

  test("a re-scan that cannot finish deletes nothing", async () => {
    await sync();
    mock.data.findings.splice(mock.data.findings.findIndex((f) => f.cid === CID_ONE), 5);
    await old(8);
    const before = await held();
    mock.dropCursors(99); // every cursor request fails: the scan gets a few pages at most
    const r = await sync();
    assert.equal(r.state, "partial");
    assert.equal(await held(), before, "nothing was removed");
    assert.ok(await cursor("scan"), "the scan is kept and continues in the next run");
    mock.dropCursors(0);
    const r2 = await sync();
    assert.equal(r2.state, "complete");
    assert.equal(await held(), openRows().length);
    assert.equal(await cursor("scan"), undefined);
  });
});

describe("honest states", () => {
  const withData = async () => { assert.equal((await sync()).state, "complete"); return { rows: await held(), counts: await counts(), asOf: (await status()).data_as_of }; };

  test("a run that cannot read pages never touches what is stored", async () => {
    const was = await withData();
    mock.touch(openRows()[3]);
    mock.fail("sort=updated_timestamp", 500, 99);
    const r = await sync();
    assert.deepEqual([r.state, r.reason], ["partial", "error"]);
    assert.equal(await held(), was.rows);
    assert.equal((await status()).data_as_of, was.asOf, "data as of does not move when nothing was stored");
    assert.match(r.missing.join(" "), /HTTP 500/);
  });

  test("Falcon refusing is a failed run with a reason and Falcon's words; data and counts stay", async () => {
    const was = await withData();
    mock.deniedCids.add(CID_ONE);
    const denied = await sync();
    assert.deepEqual([denied.state, denied.reason], ["failed", "cid_not_authorized"]);
    assert.match(denied.missing.join(" "), /not authorized/);
    let st = await status();
    assert.deepEqual([st.state, st.reason], ["failed", "cid_not_authorized"]);
    assert.match(st.detail_json, /not authorized/);
    assert.equal(await held(), was.rows);
    assert.deepEqual(await counts(), was.counts);
    mock.deniedCids.clear();

    assert.equal((await falcon.syncFindings(client("wrong-secret"), CID_ONE)).reason, "invalid_credentials");
    mock.fail("/spotlight/combined", 403, 99);
    assert.equal((await sync()).reason, "missing_scope");
    mock.clearFailures();
    assert.equal((await falcon.syncFindings(client(MOCK_SECRET, "http://127.0.0.1:1"), CID_ONE)).reason, "unreachable");
    assert.equal(await held(), was.rows, "none of the failures wiped anything");
    assert.equal((await sync()).state, "complete", "and the next good run is complete again");
    assert.equal((await status()).reason, null);
  });

  test("a failed first run stores nothing and says why", async () => {
    mock.deniedCids.add(CID_ONE);
    const r = await sync();
    assert.deepEqual([r.state, r.reason, await held()], ["failed", "cid_not_authorized", 0]);
    assert.equal(await syncRow(), undefined);
    assert.deepEqual(await falcon.loadCoverage([CID_ONE]), { coverage: null, falconCounts: null });
  });
});

describe("critical alerts and urgent items", () => {
  test("the first pass floods nothing; a new CRITICAL finding after it is reported once; urgent items follow the same rule", async () => {
    const first = await sync();
    assert.deepEqual(first.fresh, [], "the first pass reports nothing");
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM alerts WHERE reason = 'first_impact'"))!.n, 0);
    assert.ok((await dbm.get<any>("SELECT COUNT(*) n FROM alerts WHERE reason = 'baseline'"))!.n > 0, "what was there is the baseline");
    mock.add({ cid: CID_ONE, status: "open", id: "crit-new", aid: "e".repeat(32), apps: [], host_info: {}, cve: { id: "CVE-2099-1234", severity: "CRITICAL", base_score: 9.8, exprt_rating: "CRITICAL", exploit_status: 0 } },
      { cid: CID_ONE, status: "open", id: "low-new", aid: "e".repeat(32), apps: [], host_info: {}, cve: { id: "CVE-2099-1235", severity: "LOW", base_score: 2 } });
    const next = await sync();
    assert.deepEqual(next.fresh, [{ cve_id: "CVE-2099-1234", aid: "e".repeat(32) }], "only the new CRITICAL one");
    assert.deepEqual((await dbm.all<any>("SELECT cve_id FROM alerts WHERE reason = 'first_impact' ORDER BY cve_id")).map((x) => x.cve_id), ["CVE-2099-1234", "CVE-2099-1235"]);
    assert.deepEqual((await sync()).fresh, []);
  });

  test("an interrupted first pass is still the first pass: what arrives in the second part is baseline too", async () => {
    mock.fail((q) => q.includes("sort=updated_timestamp") && !q.includes("expired"), 500, 99, 2);
    await sync();
    mock.clearFailures();
    const r = await sync();
    assert.equal(r.state, "complete");
    assert.deepEqual(r.fresh, []);
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM alerts WHERE reason = 'first_impact'"))!.n, 0);
  });
});

describe("which severities are stored", () => {
  const sevOf = (f: any) => String(f.cve.severity);
  const heldBy = async () => Object.fromEntries((await dbm.all<{ severity: string; n: number }>("SELECT severity, COUNT(*) n FROM findings WHERE cid = ? GROUP BY 1", CID_ONE)).map((r) => [r.severity, r.n]));
  const truth = (...sev: string[]) => openRows().filter((f) => sev.includes(sevOf(f))).length;
  const keep = (...sev: string[]) => ret.setRetention("tt", sev as any, null, null);
  const pendingNow = async () => (await ret.getRetention("tt")).pending;

  test("a subset is added to every Falcon read, Falcon's counts still count everything, and the coverage is against the kept scope", async () => {
    await keep("CRITICAL", "HIGH");
    const from = mock.requests.length;
    const r = await sync();
    assert.equal(r.state, "complete", JSON.stringify(r.missing));
    assert.deepEqual(Object.keys(await heldBy()).sort(), ["CRITICAL", "HIGH"]);
    assert.equal(await held(), truth("CRITICAL", "HIGH"));
    assert.ok(findingPages(from).every((q) => q.includes("cve.severity:['CRITICAL','HIGH']")), "every page read asks for the kept severities only");
    const c = await counts();
    assert.equal(c.total, openRows().length, "the exact count is still every severity");
    assert.equal(c.keptTotal, truth("CRITICAL", "HIGH"));
    const cov = (await falcon.loadCoverage([CID_ONE])).coverage!;
    assert.deepEqual([cov.scope, cov.held, cov.keptTotal, cov.falconTotal, cov.fullPass], [["CRITICAL", "HIGH"], truth("CRITICAL", "HIGH"), truth("CRITICAL", "HIGH"), openRows().length, true]);
  });

  test("Informational/None is everything Falcon does not name: it is asked for by leaving the other severities out", async () => {
    await keep("CRITICAL", "NONE");
    const from = mock.requests.length;
    assert.equal((await sync()).state, "complete");
    assert.ok(findingPages(from).every((q) => q.includes("cve.severity:!['HIGH','MEDIUM','LOW']")));
    assert.equal(await held(), truth("CRITICAL", "NONE"));
    assert.equal(ret.keptTotal({ total: 10, critical: 1, high: 2, medium: 3, low: 1 }, ["NONE", "LOW"]), 4, "none = total - the four named severities");
    assert.equal(ret.severityFilter(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]), "");
  });

  test("unticking stops collecting at once, deletes nothing for three days, then purges in chunks, writes an audit row and is idempotent", async () => {
    assert.equal((await sync()).state, "complete");
    assert.equal(await held(), openRows().length);
    await keep("CRITICAL", "HIGH");
    const p = await pendingNow();
    assert.deepEqual(Object.keys(p).sort(), ["LOW", "MEDIUM", "NONE"]);
    assert.ok(Math.abs(p.LOW.purgeAt - Date.now() - 3 * 86400_000) < 60_000, "three days from now");
    mock.touch(openRows().find((f) => sevOf(f) === "LOW")!); // changes at Falcon after the untick are not collected
    assert.equal((await sync()).state, "complete");
    assert.equal(await held(), openRows().length, "nothing is deleted during the grace period, not even by a sync");
    assert.equal(await ret.purgeDue(), 0, "and the purge job has nothing due yet");
    // the grace period is over for LOW and MEDIUM only
    await dbm.run("UPDATE tenant_settings SET pending_purge_json = ? WHERE tenant_id = 'tt'", JSON.stringify({ ...p, LOW: { ...p.LOW, purgeAt: Date.now() - 1 }, MEDIUM: { ...p.MEDIUM, purgeAt: Date.now() - 1 } }));
    ret.retentionHooks.purgeChunk = 100; // many chunks
    const n = await ret.purgeDue();
    assert.equal(n, truth("LOW", "MEDIUM"));
    assert.deepEqual(Object.keys(await heldBy()).sort(), ["CRITICAL", "HIGH", "NONE"]);
    assert.deepEqual(Object.keys(await pendingNow()), ["NONE"], "the purged ones are forgotten, NONE still waits");
    const audit = await dbm.all<any>("SELECT resource, detail, result FROM audit WHERE action = 'tenant.retention.purge' ORDER BY resource");
    assert.deepEqual(audit.map((a) => [a.resource, a.result]), [["LOW", "ok"], ["MEDIUM", "ok"]]);
    assert.match(audit.map((a) => a.detail).join(" "), /findings deleted/);
    assert.equal((await counts()).held, truth("CRITICAL", "HIGH"), "the counts follow the purge (held is the kept scope: NONE still waits for its date)");
    assert.equal(await ret.purgeDue(), 0, "idempotent");
    assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM roll_cve WHERE cid = ? AND rank IN (2, 3)", CID_ONE)).n, 0, "and so do the rollups");
  });

  test("re-ticking inside the grace period cancels the purge and catches up on what changed while it was not collected", async () => {
    assert.equal((await sync()).state, "complete");
    await keep("CRITICAL", "HIGH", "MEDIUM", "NONE"); // LOW off
    const low = openRows().find((f) => sevOf(f) === "LOW")!;
    low.cve = { ...low.cve, base_score: 2.2 }; mock.touch(low); // changed while LOW was not collected
    await sync();
    assert.notEqual((await dbm.get<any>("SELECT base_score FROM findings WHERE finding_id = ?", low.id))!.base_score, 2.2, "not collected: the stored row is stale");
    await keep("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");
    assert.deepEqual(await pendingNow(), {}, "the purge is cancelled");
    assert.deepEqual((await ret.retentionView("tt")).rebuilding, ["LOW"]);
    const r = await sync();
    assert.equal(r.state, "complete");
    assert.equal((await dbm.get<any>("SELECT base_score FROM findings WHERE finding_id = ?", low.id))!.base_score, 2.2, "caught up");
    assert.deepEqual((await ret.retentionView("tt")).rebuilding, []);
    assert.equal(await held(), openRows().length);
  });

  test("re-ticking after the rows were purged collects the severity again from the beginning, and says partial until it has", async () => {
    assert.equal((await sync()).state, "complete");
    await keep("CRITICAL", "HIGH", "MEDIUM", "NONE");
    await dbm.run("UPDATE tenant_settings SET pending_purge_json = ? WHERE tenant_id = 'tt'", JSON.stringify({ LOW: { purgeAt: Date.now() - 1, since: Date.now() - 4 * 86400_000, full: false } }));
    assert.ok(await ret.purgeDue() > 0);
    assert.equal((await heldBy()).LOW, undefined);
    await keep("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");
    assert.equal((await cursor("add:LOW")).wm, 0, "from the beginning");
    mock.fail((q) => q.includes("sort=updated_timestamp") && q.includes("cve.severity:['LOW']"), 500, 99, 0); // Falcon fails on the catch-up
    const r1 = await sync();
    assert.deepEqual([r1.state, r1.reason], ["partial", "error"]);
    const cov = (await falcon.loadCoverage([CID_ONE])).coverage!;
    assert.ok(cov.held < cov.keptTotal!, "held X of Y against the kept scope");
    mock.clearFailures();
    assert.equal((await sync()).state, "complete");
    assert.equal(await held(), openRows().length);
    assert.equal(await cursor("add:LOW"), undefined);
  });

  test("a reconcile never deletes a severity that is only waiting for its purge date; a first pass that was unfinished at untick time restarts the catch-up from the beginning", async () => {
    await sync();
    await keep("CRITICAL", "HIGH", "MEDIUM", "NONE");
    await dbm.run("UPDATE cid_sync SET last_scan_done_at = ? WHERE cid = ?", Date.now() - 8 * 86400_000, CID_ONE);
    const r = await sync();
    assert.ok(r.notes.some((x) => /reconcile started/.test(x)));
    assert.equal((await heldBy()).LOW, truth("LOW"), "LOW rows are still there");
    // an untick while the first pass is unfinished
    for (const t of ["cid_sync", "cid_cursor"]) await dbm.run(`DELETE FROM ${t} WHERE cid = ?`, CID_ONE);
    await dbm.run("INSERT INTO cid_sync (cid) VALUES (?)", CID_ONE);
    await keep("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");
    await keep("CRITICAL", "HIGH", "MEDIUM", "NONE");
    assert.equal((await pendingNow()).LOW.full, true);
    await keep("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");
    assert.equal((await cursor("add:LOW")).wm, 0);
  });

  test("the setting needs at least one severity", async () => {
    await assert.rejects(() => keep(), /keep_empty/);
  });
});

const crypto = await import("../src/crypto.ts");
describe("rounds: a big backfill does not starve the others", () => {
  const waitIdle = async () => { for (let i = 0; i < 600 && falcon.syncState.running; i++) await new Promise((ok) => setTimeout(ok, 50)); assert.equal(falcon.syncState.running, false, "the sync finished"); };

  test("finished CIDs go first in every round, an unfinished one continues in the next round at once, and the loop ends when everything is stored", async () => {
    for (const cid of [CID_ONE, CID_TWO]) await dbm.run("INSERT INTO falcon_connections (id, tenant_id, name, base_url, client_id, secret_sealed, cid, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
      crypto.uuid(), "tt", null, url, MOCK_CLIENT, crypto.seal(MOCK_SECRET), cid, 1, 1);
    try {
      assert.equal((await sync(CID_TWO)).state, "complete"); // CID_TWO is finished, CID_ONE has not started
      mock.delayMs = 100; falcon.hooks.budgetMs = 1100; // CID_ONE needs several rounds (the counts and the slice take a good part of each)
      const from = mock.requests.length;
      assert.deepEqual(await falcon.syncCids([CID_ONE, CID_TWO]), { started: true });
      assert.deepEqual(await falcon.syncCids([CID_ONE]), { started: false, reason: "running" }, "one sync at a time");
      await waitIdle();
      const closedRequests = mock.requests.slice(from).filter((q) => q.includes("closed_timestamp")).map((q) => (decodeURIComponent(q).match(/cid:'([0-9a-f]{32})'/) ?? [])[1]);
      assert.equal(closedRequests[0], CID_TWO, "the finished CID is served first");
      assert.ok(closedRequests.filter((c) => c === CID_ONE).length >= 2, "the unfinished one got more than one round");
      assert.ok(closedRequests.filter((c) => c === CID_TWO).length >= 2, "and the finished one went on with its incremental in each round");
      assert.ok((await syncRow(CID_ONE)).first_done_at, "everything is stored in the end");
      assert.equal(await held(CID_ONE), openRows().length);
      assert.equal((await status(CID_ONE)).state, "complete");
      const runs = await dbm.all<any>("SELECT state FROM sync_runs WHERE cid = ? ORDER BY id", CID_ONE);
      assert.ok(runs.length >= 2 && runs.slice(0, -1).every((r) => r.state === "partial") && runs.at(-1).state === "complete", JSON.stringify(runs));
    } finally { mock.delayMs = 0; falcon.hooks.budgetMs = 20 * 60_000; await dbm.run("DELETE FROM falcon_connections"); }
  });

  test("a round that stored nothing (Falcon failing) ends the loop instead of hammering Falcon", async () => {
    await dbm.run("INSERT INTO falcon_connections (id, tenant_id, name, base_url, client_id, secret_sealed, cid, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)", crypto.uuid(), "tt", null, url, MOCK_CLIENT, crypto.seal(MOCK_SECRET), CID_ONE, 1, 1);
    try {
      mock.fail((q) => q.includes("sort=updated_timestamp"), 500, 999); // the counts work, every page fails
      await falcon.syncCids([CID_ONE]);
      await waitIdle();
      assert.equal((await dbm.get<any>("SELECT COUNT(*) n FROM sync_runs WHERE cid = ?", CID_ONE)).n, 1, "one run, no immediate retry");
      assert.equal((await status()).reason, "error");
    } finally { mock.clearFailures(); await dbm.run("DELETE FROM falcon_connections"); }
  });
});
