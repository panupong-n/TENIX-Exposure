import { testDatabaseUrl } from "./test-db.ts";
process.env.TENIX_DATABASE_URL = testDatabaseUrl(); // throws unless 127.0.0.1:5433/tenix_test
process.env.TENIX_DB_SCHEMA = `f_${Math.random().toString(36).slice(2, 10)}`; // throwaway schema per run
process.env.TENIX_SECRET_KEY = Buffer.alloc(32, 7).toString("base64");
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";

const dbm = await import("../src/db.ts");
const feeds = await import("../src/feeds.ts");
const falcon = await import("../src/falcon.ts");
const cache = await import("../src/cache.ts");
after(async () => { await dbm.pool.query(`DROP SCHEMA ${process.env.TENIX_DB_SCHEMA} CASCADE`); await dbm.pool.end(); }); // the throwaway schema goes with the test

// ---------------------------------------------------------------- a fake CVE Program and a fake CISA, nothing touches the network
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const H = 3600_000, D = 24 * H;
const rec = (id: string, o: { updated?: string; state?: string; description?: string; score?: number; published?: string } = {}) => ({
  cveMetadata: { cveId: id, state: o.state ?? "PUBLISHED", datePublished: o.published ?? "2026-01-01T00:00:00.000Z", dateUpdated: o.updated ?? "2026-01-01T00:00:00.000Z" },
  containers: { cna: { title: `T ${id}`, descriptions: [{ lang: "en", value: o.description ?? `D ${id}` }], metrics: o.score === undefined ? [] : [{ cvssV3_1: { baseScore: o.score, baseSeverity: "HIGH", vectorString: "CVSS:3.1/x" } }] } },
});
const src = {
  log: [] as { fetchTime: string; new: { cveId: string }[]; updated: { cveId: string }[] }[], // newest first, like deltaLog.json
  records: new Map<string, any>(),
  logDown: false, failing: new Set<string>(),
  kev: { etag: "v1", body: { catalogVersion: "1", vulnerabilities: [] as any[] }, down: false },
  calls: [] as string[],
};
const entry = (ageMs: number, news: string[], updated: string[] = []) => ({ fetchTime: iso(ageMs), new: news.map((cveId) => ({ cveId })), updated: updated.map((cveId) => ({ cveId })) });
feeds.feedHooks.fetch = async (url: string, init: RequestInit = {}) => {
  const h = (init.headers ?? {}) as Record<string, string>;
  src.calls.push(`${url.split("/").pop()}${h.Range ? ` ${h.Range}` : ""}`);
  if (url.endsWith("deltaLog.json")) {
    if (src.logDown) return new Response("", { status: 500 });
    const full = JSON.stringify(src.log, null, 2);
    const m = /bytes=0-(\d+)/.exec(h.Range ?? "");
    return m ? new Response(full.slice(0, Number(m[1]) + 1), { status: full.length > Number(m[1]) + 1 ? 206 : 200 }) : new Response(full, { status: 200 });
  }
  if (url.endsWith("known_exploited_vulnerabilities.json")) {
    if (src.kev.down) return new Response("", { status: 503 });
    if (h["If-None-Match"] === src.kev.etag) return new Response(null, { status: 304 });
    return new Response(JSON.stringify(src.kev.body), { status: 200, headers: { etag: src.kev.etag } });
  }
  const id = /CVE-\d{4}-\d+/.exec(url)![0];
  if (src.failing.has(id)) return new Response("", { status: 500 });
  const r = src.records.get(id);
  return r ? new Response(JSON.stringify(r), { status: 200 }) : new Response("", { status: 404 });
};
const state = (key: string) => dbm.get<any>("SELECT * FROM feed_state WHERE key = ?", key);
const count = async (sql: string, ...p: any[]) => (await dbm.get<{ n: number }>(sql, ...p))!.n;

describe("CVE record parsing", () => {
  test("a published record, one without a score, and a REJECTED one", () => {
    const a = feeds.parseCve(rec("CVE-2026-0001", { score: 9.8 }))!;
    assert.deepEqual([a.id, a.state, a.cvss_score, a.cvss_severity, a.title, a.description], ["CVE-2026-0001", "PUBLISHED", 9.8, "HIGH", "T CVE-2026-0001", "D CVE-2026-0001"]);
    const b = feeds.parseCve(rec("CVE-2026-0002"))!;
    assert.equal(b.cvss_score, null, "no score in the record: null, which the page shows as 'no data'");
    const c = feeds.parseCve({ cveMetadata: { cveId: "CVE-2026-0003", state: "REJECTED", dateReserved: "2026-02-01T00:00:00Z" }, containers: { cna: { rejectedReasons: [{ lang: "en", value: "duplicate" }] } } })!;
    assert.deepEqual([c.state, c.description], ["REJECTED", "duplicate"]);
    assert.equal(feeds.parseCve({ cveMetadata: { cveId: "not-a-cve" } }), null);
    const adp = feeds.parseCve({ cveMetadata: { cveId: "CVE-2026-0004", state: "PUBLISHED" }, containers: { cna: {}, adp: [{ metrics: [{ cvssV3_1: { baseScore: 7.5, baseSeverity: "HIGH" } }] }] } })!;
    assert.equal(adp.cvss_score, 7.5, "a score from the ADP container counts when the CNA gave none");
  });
  test("a log cut off in the middle yields only its complete entries", () => {
    const full = JSON.stringify([entry(1, ["CVE-2026-1"]), entry(2, ["CVE-2026-2"]), entry(3, ["CVE-2026-3"])], null, 2);
    assert.equal(feeds.topObjects(full).length, 3);
    assert.equal(feeds.topObjects(full.slice(0, full.length - 40)).length, 2);
    assert.equal(feeds.topObjects('[{"fetchTime":"x","new":[{"cveId":"a}"}]}, {"fetchTim').length, 1, "braces inside strings do not confuse it");
  });
});

describe("CVE List V5 sync", () => {
  test("first run reads only the recent window; a second run changes nothing; the checkpoint is the newest saved entry", async () => {
    const e4 = entry(10 * 60_000, ["CVE-2026-1003"]), e3 = entry(H, ["CVE-2026-1002"], ["CVE-2026-1001"]), e2 = entry(D, ["CVE-2026-1001"]), e1 = entry(3 * D, ["CVE-2026-0999"]);
    src.log = [e4, e3, e2, e1];
    for (const id of ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003", "CVE-2026-0999"]) src.records.set(id, rec(id, { score: 8.1 }));
    const r = await feeds.syncCveList();
    assert.deepEqual([r.ingested, r.error, r.gap], [4, undefined, false], "1001 is in two entries and is read twice, 0999 is older than the 2 day window and never");
    assert.equal(await count("SELECT COUNT(*) n FROM cve_public"), 3, "no duplicate rows");
    assert.equal((await state("cvelist")).checkpoint, e4.fetchTime);
    src.calls.length = 0;
    const again = await feeds.syncCveList();
    assert.equal(again.ingested, 0);
    assert.ok(src.calls.every((c) => c.startsWith("deltaLog")), "nothing but the log is read when nothing changed");
    assert.equal(await count("SELECT COUNT(*) n FROM cve_public"), 3);
  });

  test("after an outage the run catches up on everything missed, reading further back in the log when it has to", async () => {
    const before = src.log;
    const missed = [entry(210_000, ["CVE-2026-1007"]), entry(240_000, ["CVE-2026-1006"]), entry(270_000, ["CVE-2026-1005"]), entry(300_000, ["CVE-2026-1004"])]; // all newer than the checkpoint (10 minutes ago)
    for (const e of missed) src.records.set(e.new[0].cveId, rec(e.new[0].cveId));
    src.log = [...missed, ...before];
    const saved = [...feeds.feedHooks.windows]; feeds.feedHooks.windows.splice(0, feeds.feedHooks.windows.length, 400, 800, 1_000_000);
    src.calls.length = 0;
    try {
      const r = await feeds.syncCveList();
      assert.deepEqual([r.ingested, r.gap], [4, false]);
      assert.ok(src.calls.filter((c) => c.startsWith("deltaLog")).length >= 2, "the first window did not reach the checkpoint, so the next one was read");
    } finally { feeds.feedHooks.windows.splice(0, feeds.feedHooks.windows.length, ...saved); }
    for (const id of ["CVE-2026-1004", "CVE-2026-1005", "CVE-2026-1006", "CVE-2026-1007"]) assert.ok(await dbm.get("SELECT 1 FROM cve_public WHERE id = ?", id), id);
    assert.equal((await state("cvelist")).checkpoint, missed[0].fetchTime);
  });

  test("a record that fails stops the run there: the checkpoint stays behind it and the next run finishes the job", async () => {
    const ok = (await state("cvelist")).last_ok_at;
    const e = [entry(1 * 60_000, ["CVE-2026-1010"]), entry(2 * 60_000, ["CVE-2026-1009"]), entry(3 * 60_000, ["CVE-2026-1008"])];
    for (const x of e) src.records.set(x.new[0].cveId, rec(x.new[0].cveId));
    src.log = [...e, ...src.log];
    src.failing.add("CVE-2026-1009");
    const r = await feeds.syncCveList();
    assert.ok(r.error);
    const st = await state("cvelist");
    assert.equal(st.checkpoint, e[2].fetchTime, "moved past the saved entry only");
    assert.equal(st.last_ok_at, ok, "the last good time is not touched by a failed run");
    assert.ok(st.error);
    assert.ok(await dbm.get("SELECT 1 FROM cve_public WHERE id = 'CVE-2026-1008'") && !(await dbm.get("SELECT 1 FROM cve_public WHERE id = 'CVE-2026-1010'")));
    src.failing.clear();
    const healed = await feeds.syncCveList();
    assert.deepEqual([healed.ingested, healed.error], [2, undefined]);
    const after = await state("cvelist");
    assert.deepEqual([after.checkpoint, after.error, after.last_ok_at > ok], [e[0].fetchTime, null, true]);
  });

  test("when the source is down the data stays and the last good time is kept", async () => {
    const before = await state("cvelist");
    const n = await count("SELECT COUNT(*) n FROM cve_public");
    src.logDown = true;
    const r = await feeds.syncCveList();
    src.logDown = false;
    assert.ok(r.error);
    const st = await state("cvelist");
    assert.deepEqual([st.last_ok_at, st.checkpoint, await count("SELECT COUNT(*) n FROM cve_public")], [before.last_ok_at, before.checkpoint, n]);
    assert.ok(st.last_try_at >= before.last_try_at && st.error);
  });

  test("an older copy never replaces a newer one; REJECTED is recorded as such; a CVE the source does not have yet is not stored", async () => {
    src.records.set("CVE-2026-1020", rec("CVE-2026-1020", { updated: "2026-03-01T00:00:00Z", description: "new text" }));
    src.log = [entry(30_000, ["CVE-2026-1020"]), ...src.log];
    await feeds.syncCveList();
    src.records.set("CVE-2026-1020", rec("CVE-2026-1020", { updated: "2026-02-01T00:00:00Z", description: "stale text" }));
    src.log = [entry(20_000, [], ["CVE-2026-1020"]), ...src.log];
    await feeds.syncCveList();
    assert.equal((await dbm.get<any>("SELECT description FROM cve_public WHERE id = 'CVE-2026-1020'")).description, "new text");
    src.records.set("CVE-2026-1021", rec("CVE-2026-1021", { state: "REJECTED" }));
    src.log = [entry(10_000, [], ["CVE-2026-1021", "CVE-2026-1022"]), ...src.log]; // 1022 has no file
    const r = await feeds.syncCveList();
    assert.deepEqual([r.missing, r.error], [1, undefined]);
    assert.equal((await dbm.get<any>("SELECT state FROM cve_public WHERE id = 'CVE-2026-1021'")).state, "REJECTED");
    assert.equal(await dbm.get("SELECT 1 FROM cve_public WHERE id = 'CVE-2026-1022'"), undefined);
  });

  test("a run reads at most `max` records; the rest waits for the next run", async () => {
    const e = [entry(5_000, ["CVE-2026-1032"]), entry(6_000, ["CVE-2026-1031"]), entry(7_000, ["CVE-2026-1030"])];
    for (const x of e) src.records.set(x.new[0].cveId, rec(x.new[0].cveId));
    src.log = [...e, ...src.log];
    const r = await feeds.syncCveList(1);
    assert.deepEqual([r.ingested, r.remaining], [1, 2]);
    assert.equal((await feeds.syncCveList(10)).ingested, 2);
  });

  test("a CVE named before the feed has it is filled in later, into the same row", async () => {
    await feeds.ensurePublic(["CVE-2026-1040"]);
    assert.equal((await feeds.publicInfo(["CVE-2026-1040"])).get("CVE-2026-1040")!.announced, false, "not announced: the card says 'waiting for the CVE Program'");
    src.records.set("CVE-2026-1040", rec("CVE-2026-1040", { score: 9.1 }));
    src.log = [entry(2_000, ["CVE-2026-1040"]), ...src.log];
    await feeds.syncCveList();
    const v = (await feeds.publicInfo(["CVE-2026-1040"])).get("CVE-2026-1040")!;
    assert.deepEqual([v.announced, v.cvss.score, v.title], [true, 9.1, "T CVE-2026-1040"]);
  });
});

// ---------------------------------------------------------------- organizations, findings and urgent items
const CA = "a".repeat(32), CB = "b".repeat(32);
const finding = (cid: string, aid: string, cve: string, sev = "HIGH") => ({
  cid, finding_id: `${cid}:${aid}:${cve}`, aid, cve_id: cve, severity: sev, base_score: 7, exprt: null, exploit_status: null, hostname: `h-${aid}`, platform: null, local_ip: "10.0.0.1", external_ip: null,
  product: null, status: "open", remediation: null, remediation_json: null, provider: null, kind: null, vendor: null, eval_id: null, risk_score: null, exploitability: null, first_seen: null, os_version: null, internet_exposure: null, port: null,
});
/** What a finished read leaves behind (the sync engine itself is tested in falcon-sync.test.ts): a complete read replaces the rows, a partial one only when there is nothing older. */
const sync = async (cid: string, rows: ReturnType<typeof finding>[], state: "complete" | "partial" | "failed" = "complete") => {
  const prev = await dbm.get<{ data_as_of: number | null }>("SELECT data_as_of FROM cid_status WHERE cid = ?", cid);
  const replace = state === "complete" || (state === "partial" && !prev?.data_as_of);
  if (replace) {
    await dbm.run("DELETE FROM findings WHERE cid = ?", cid);
    const cols = ["cid", "finding_id", "aid", "cve_id", "severity", "base_score", "exprt", "exploit_status", "hostname", "platform", "local_ip", "external_ip", "product", "status", "synced_at", "provider", "kind", "vendor", "eval_id", "risk_score", "exploitability", "first_seen", "os_version", "internet_exposure", "port"];
    await dbm.insertMany("findings_t", cols, rows.map((r) => cols.map((c) => (c === "synced_at" ? Date.now() : (r as any)[c]))));
  }
  await dbm.run(`INSERT INTO cid_status (cid, state, detail_json, data_as_of, last_run_at) VALUES (?,?,?,?,?)
                 ON CONFLICT (cid) DO UPDATE SET state = excluded.state, detail_json = excluded.detail_json, data_as_of = excluded.data_as_of, last_run_at = excluded.last_run_at`,
    cid, state, state === "complete" ? "[]" : '["page 2"]', replace ? Date.now() : (prev?.data_as_of ?? null), Date.now());
  if (state === "complete") { await (await import("../src/rollup.ts")).refreshRollups(cid); await feeds.recordImpact(cid, !prev?.data_as_of); }
};
let ta = "", tb = "";
const urgent = async (tid: string, cid: string) => (await feeds.urgentFor(tid, [cid])).map((u) => `${u.cve}:${u.reasons.join("+")}`).sort();

describe("urgent items and CISA KEV", () => {
  test("the first read of an organization is a baseline; a CVE it has for the first time afterwards is one urgent item, however often it is synced", async () => {
    ta = "ta"; tb = "tb";
    for (const [id, name, cid] of [[ta, "Alpha", CA], [tb, "Beta", CB]]) { await dbm.run("INSERT INTO tenants (id, name, created_at) VALUES (?,?,?)", id, name, Date.now()); await dbm.run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?,?)", cid, id); }
    await sync(CA, [finding(CA, "1", "CVE-2026-2001"), finding(CA, "2", "CVE-2026-2003")]);
    await sync(CB, [finding(CB, "1", "CVE-2026-2002")]);
    assert.deepEqual([await urgent(ta, CA), await urgent(tb, CB)], [[], []], "what was already there is not news");
    await sync(CA, [finding(CA, "1", "CVE-2026-2001"), finding(CA, "2", "CVE-2026-2003"), finding(CA, "3", "CVE-2026-2004")]);
    assert.deepEqual(await urgent(ta, CA), ["CVE-2026-2004:first_impact"]);
    await sync(CA, [finding(CA, "1", "CVE-2026-2001"), finding(CA, "2", "CVE-2026-2003"), finding(CA, "3", "CVE-2026-2004")]);
    await feeds.recordImpact(CA, false);
    assert.equal(await count("SELECT COUNT(*) n FROM alerts WHERE tenant_id = ? AND reason = 'first_impact'", ta), 1, "a repeated sync makes no second item");
    assert.deepEqual(await urgent(tb, CB), [], "another organization sees nothing of it");
  });

  test("a partial or failed read creates no urgent item and removes none", async () => {
    await sync(CA, [finding(CA, "9", "CVE-2026-2009")], "partial");
    assert.deepEqual(await urgent(ta, CA), ["CVE-2026-2004:first_impact"]);
    // the previous complete data is kept, so a later complete read decides
    await sync(CA, [finding(CA, "1", "CVE-2026-2001"), finding(CA, "2", "CVE-2026-2003"), finding(CA, "3", "CVE-2026-2004")]);
    assert.deepEqual(await urgent(ta, CA), ["CVE-2026-2004:first_impact"]);
  });

  test("the first KEV import is a baseline; a CVE added later that is open in an organization is one urgent item for that organization only", async () => {
    await dbm.run("INSERT INTO cves (id, description, cisa_kev, updated_at) VALUES ('CVE-2026-2001', 'x', 0, ?) ON CONFLICT DO NOTHING", Date.now());
    const kv = (id: string, added = "2026-11-18") => ({ cveID: id, vulnerabilityName: `N ${id}`, vendorProject: "V", product: "P", shortDescription: "s", dateAdded: added, dueDate: "2026-12-09", knownRansomwareCampaignUse: "Unknown", requiredAction: "Patch", notes: "" });
    src.kev.body = { catalogVersion: "1", vulnerabilities: [kv("CVE-2020-0001")] };
    const first = await feeds.syncKev();
    assert.deepEqual([first.total, first.added, first.error], [1, [], undefined]);
    assert.equal(await count("SELECT COUNT(*) n FROM alerts WHERE reason = 'kev_added'"), 0, "the baseline raises nothing");
    src.kev.etag = "v2";
    src.kev.body = { catalogVersion: "2", vulnerabilities: [kv("CVE-2020-0001"), kv("CVE-2026-2001"), kv("CVE-2026-2002"), kv("CVE-2026-2999")] };
    const second = await feeds.syncKev();
    assert.deepEqual(second.added.sort(), ["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2999"]);
    assert.deepEqual(await urgent(ta, CA), ["CVE-2026-2001:kev_added", "CVE-2026-2004:first_impact"]);
    assert.deepEqual(await urgent(tb, CB), ["CVE-2026-2002:kev_added"], "each organization only gets its own");
    assert.equal(await count("SELECT cisa_kev n FROM cves WHERE id = 'CVE-2026-2001'"), 1, "the CVE rows used by the pages know it is in KEV");
    const u = (await feeds.urgentFor(ta, [CA])).find((x) => x.cve === "CVE-2026-2001")!;
    assert.deepEqual([u.kev, u.devices], [true, 1]);
    // the same content again, with a new tag, and a restart-like repeat, add nothing
    src.kev.etag = "v3";
    assert.deepEqual((await feeds.syncKev()).added, []);
    assert.equal(await count("SELECT COUNT(*) n FROM alerts WHERE reason = 'kev_added'"), 2, "A/2001 and B/2002; nobody has 2999");
    // not modified
    const n = await feeds.syncKev();
    assert.equal(n.notModified, true);
  });

  test("a broken or empty KEV answer never replaces the list; a source that is down keeps it too", async () => {
    const before = await count("SELECT COUNT(*) n FROM kev");
    src.kev.etag = "v4"; src.kev.body = { catalogVersion: "3", vulnerabilities: [] };
    assert.ok((await feeds.syncKev()).error);
    src.kev.down = true;
    assert.ok((await feeds.syncKev()).error);
    src.kev.down = false;
    assert.equal(await count("SELECT COUNT(*) n FROM kev"), before);
    assert.ok((await state("kev")).error);
  });

  test("an urgent item ends when the CVE is no longer open in the organization", async () => {
    await sync(CA, [finding(CA, "2", "CVE-2026-2003")]);
    assert.deepEqual(await urgent(ta, CA), []);
  });

  test("starting the feature on a database that already has findings seeds a baseline once", async () => {
    await dbm.run("DELETE FROM alerts");
    await feeds.seedAlerts();
    assert.ok(await count("SELECT COUNT(*) n FROM alerts WHERE reason = 'baseline'") > 0);
    const n = await count("SELECT COUNT(*) n FROM alerts");
    await feeds.seedAlerts();
    assert.equal(await count("SELECT COUNT(*) n FROM alerts"), n, "once");
    assert.deepEqual(await urgent(ta, CA), []);
  });
});

describe("what an organization may conclude", () => {
  const row = (state: string | null, at: number | null) => ({ state, data_as_of: at });
  const t0 = Date.now();
  test("affected, not found, waiting, partial, cannot check", () => {
    assert.equal(feeds.impactFrom([row("complete", t0)], 2, null).state, "affected");
    assert.equal(feeds.impactFrom([row("complete", t0)], 0, t0 - 1000).state, "not_found");
    assert.equal(feeds.impactFrom([row("complete", t0 - 15 * 60_000)], 0, t0 - 5 * 60_000).state, "pending", "the read is older than the announcement: still waiting");
    assert.equal(feeds.impactFrom([], 0, null).state, "pending");
    assert.equal(feeds.impactFrom([row(null, null)], 0, null).state, "pending", "never read yet");
    assert.equal(feeds.impactFrom([row("complete", t0), row("partial", t0)], 0, null).state, "partial");
    assert.equal(feeds.impactFrom([row("complete", t0), row("failed", null)], 0, null).state, "partial");
    assert.equal(feeds.impactFrom([row("failed", null)], 0, null).state, "unavailable");
    assert.equal(feeds.impactFrom([row("partial", t0)], 0, null).state, "partial", "an incomplete read never supports 'not found'");
    assert.equal(feeds.impactFrom([{ ...row("complete", t0), slice: true }], 0, null).state, "partial", "a CID that stores only the fix-first slice cannot say 'not found' either");
    assert.equal(feeds.impactFrom([{ ...row("complete", t0), slice: true }], 3, null).state, "affected", "but what it does hold is real");
  });
});

describe("the result cache", () => {
  const CC = "d".repeat(32);
  test("an answer is computed once per version of the data and again after the data changes", async () => {
    await dbm.run("INSERT INTO tenants (id, name, created_at) VALUES ('tc', 'Gamma', ?)", Date.now());
    await dbm.run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?, 'tc')", CC);
    await sync(CC, [finding(CC, "1", "CVE-2026-3001"), finding(CC, "2", "CVE-2026-3002")]);
    let built = 0;
    const get = () => cache.cached("k|tc", [CC], async () => ({ n: ++built }));
    assert.deepEqual([(await get()).n, (await get()).n], [1, 1]);
    await sync(CC, [finding(CC, "1", "CVE-2026-3001"), finding(CC, "4", "CVE-2026-3004")]);
    assert.equal((await get()).n, 2, "a new read of the organization's data invalidates it");
    await dbm.run("UPDATE cid_status SET state = 'failed', last_run_at = last_run_at + 1 WHERE cid = ?", CC);
    assert.equal((await get()).n, 3, "so does a failed read (the completeness line changes)");
    cache.forgetMemory(); // a restart
    const before = cache.stats.builds;
    assert.equal((await get()).n, 3, "served from the database after a restart, not computed again");
    assert.equal(cache.stats.builds, before);
    assert.ok(cache.stats.databaseHits >= 1);
    const [a, b] = await Promise.all([cache.cached("k2|tc", [CC], async () => ({ n: ++built })), cache.cached("k2|tc", [CC], async () => ({ n: ++built }))]);
    assert.equal(a.n, b.n, "two first reads at once share one computation");
  });
});
