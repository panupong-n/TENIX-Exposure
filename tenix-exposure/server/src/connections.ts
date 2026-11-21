// CrowdStrike connections per organization: Tenant > its CrowdStrike (cloud, API client id, secret, CID). One organization may have several (one per CID).
// A CID with no connection of its own is NOT read: there is no shared login. (Organizations created before connections existed were converted once at start,
// each CID only when the old login could really read it; see convertSharedLogin.)
import { all, audit, get, now, run, tx } from "./db.ts";
import { seal, unseal, uuid } from "./crypto.ts";
import { str } from "./auth.ts";
import { HttpError, route } from "./http.ts";
import { ROLLUP_CID_TABLES } from "./rollup.ts";
import { checkBaseUrl, convertSharedLogin, loadConfig, probeFalcon, syncCids, syncState } from "./falcon.ts";

const SUPER = { roles: ["super_admin" as const] };
const CID = /^[0-9a-f]{32}$/;
const DATA_TABLES = ["findings", "cid_status", "snapshots", "sync_runs", "software", "software_hosts", "software_sync", "finding_closed", "external_assets", "external_sync", "cid_counts", "cid_sync", "cid_cursor", ...ROLLUP_CID_TABLES]; // the rollups and the host inventory of the CID go with it

async function tenantOr404(id: string) {
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", id);
  if (!t) throw new HttpError(404, "Not found");
  return t;
}
interface Conn { id: string; tenant_id: string; name: string | null; base_url: string; client_id: string; secret_sealed: string; cid: string }

async function status(cid: string) {
  const s = await get<{ state: string; data_as_of: number | null; last_run_at: number; detail_json: string; reason: string | null }>("SELECT state, data_as_of, last_run_at, detail_json, reason FROM cid_status WHERE cid = ?", cid);
  const n = (await get<{ n: number }>("SELECT COALESCE((SELECT n FROM cid_counts WHERE cid = ? AND key = 'held'), 0) n", cid))!.n; // a count of the big table takes minutes
  return { state: s?.state ?? "not_synced", dataAsOf: s?.data_as_of ?? null, lastRunAt: s?.last_run_at ?? null, findings: n, reason: s?.reason ?? null, detail: s ? (JSON.parse(s.detail_json) as string[]) : [] };
}

async function view(tenantId: string) {
  const conns = await all<Conn>("SELECT * FROM falcon_connections WHERE tenant_id = ? ORDER BY created_at", tenantId);
  const own = new Set(conns.map((c) => c.cid));
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", tenantId)).map((r) => r.cid);
  const shared = await loadConfig();
  return {
    connections: await Promise.all(conns.map(async (c) => ({ id: c.id, name: c.name ?? "", baseUrl: c.base_url, clientId: c.client_id, hasSecret: true, cid: c.cid, shared: false, ...(await status(c.cid)) }))),
    // CIDs of this organization that have no login of their own: nothing is read for them until one is added (what is shown for them is old data)
    unconnectedCids: await Promise.all(cids.filter((c) => !own.has(c)).map(async (cid) => ({ cid, ...(await status(cid)) }))),
    legacyLogin: !!shared, // the old shared login still exists: "convert" tries it on the unconnected CIDs
    sync: { running: syncState.running },
  };
}

route("GET", "/api/tenants/:id/falcon", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  return view(t.id);
});

function input(body: Record<string, unknown>, needSecret: boolean) {
  const baseUrl = checkBaseUrl(str(body.baseUrl, 200));
  const clientId = str(body.clientId, 100).trim();
  const secret = typeof body.clientSecret === "string" ? body.clientSecret.trim() : "";
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : "";
  if (!clientId) throw new HttpError(400, "Client ID is required", "client_id_required");
  if (needSecret && !secret) throw new HttpError(400, "Client secret is required", "client_secret_required");
  if (secret.length > 200) throw new HttpError(400, "Invalid input");
  return { baseUrl, clientId, secret, name };
}

route("POST", "/api/tenants/:id/falcon/test", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  let cfg: { baseUrl: string; clientId: string; clientSecret: string };
  const cid = typeof c.body.cid === "string" && c.body.cid.trim() ? c.body.cid.trim().toLowerCase() : null;
  if (cid && !CID.test(cid)) throw new HttpError(400, "A CID is 32 hexadecimal characters", "invalid_cid");
  if (typeof c.body.connectionId === "string" && !c.body.clientSecret) {
    const saved = await get<Conn>("SELECT * FROM falcon_connections WHERE id = ? AND tenant_id = ?", c.body.connectionId, t.id);
    if (!saved) throw new HttpError(404, "Not found");
    const i = input({ ...c.body, baseUrl: c.body.baseUrl ?? saved.base_url, clientId: c.body.clientId ?? saved.client_id }, false);
    cfg = { baseUrl: i.baseUrl, clientId: i.clientId, clientSecret: unseal(saved.secret_sealed) };
  } else {
    const i = input(c.body, true);
    cfg = { baseUrl: i.baseUrl, clientId: i.clientId, clientSecret: i.secret };
  }
  const r = await probeFalcon(cfg, cid);
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.test", resource: t.name, result: r.ok ? "ok" : "fail", ip: c.ip, detail: r.ok ? null : `${r.step}: ${r.reason}` });
  return r;
});

route("POST", "/api/tenants/:id/falcon", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  const i = input(c.body, true);
  const cid = str(c.body.cid, 64).trim().toLowerCase();
  if (!CID.test(cid)) throw new HttpError(400, "A CID is 32 hexadecimal characters", "invalid_cid");
  const owner = await get<{ name: string }>("SELECT t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ? AND x.tenant_id != ?", cid, t.id);
  if (owner) throw new HttpError(409, `CID ${cid} already belongs to ${owner.name}`, "cid_taken");
  if (await get("SELECT 1 FROM falcon_connections WHERE cid = ?", cid)) throw new HttpError(409, "This CID already has a connection", "cid_has_connection");
  // nothing is saved that Falcon refuses: a wrong secret, a CID this client may not read, a missing scope are told apart here
  const p = await probeFalcon({ baseUrl: i.baseUrl, clientId: i.clientId, clientSecret: i.secret }, cid);
  if (!p.ok) { await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.add", resource: t.name, result: "fail", ip: c.ip, detail: `${p.step}: ${p.reason}` }); throw new HttpError(400, `Falcon refused the connection: ${p.reason}`, p.reason, { step: p.step, message: p.message }); }
  const id = uuid();
  await tx(async () => {
    await run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?, ?) ON CONFLICT (cid) DO NOTHING", cid, t.id);
    await run("INSERT INTO falcon_connections (id, tenant_id, name, base_url, client_id, secret_sealed, cid, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
      id, t.id, i.name || null, i.baseUrl, i.clientId, seal(i.secret), cid, now(), now());
  });
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.add", resource: `${t.name} (${i.baseUrl})`, result: "ok", ip: c.ip });
  const sync = c.body.sync === true ? await syncCids([cid]) : null; // read it right away when asked
  return { id, syncStarted: !!sync?.started, ...(sync && !sync.started ? { syncReason: sync.reason } : {}), ...(await view(t.id)) }; // "running": another organization is being read, this one follows in the next round
});

route("PUT", "/api/tenants/:id/falcon/:conn", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  const old = await get<Conn>("SELECT * FROM falcon_connections WHERE id = ? AND tenant_id = ?", c.params.conn, t.id);
  if (!old) throw new HttpError(404, "Not found");
  const i = input({ ...c.body, baseUrl: c.body.baseUrl ?? old.base_url, clientId: c.body.clientId ?? old.client_id }, false);
  if (i.clientId !== old.client_id && !i.secret) throw new HttpError(400, "A new client ID needs its client secret", "client_secret_required"); // the old secret belongs to the old id
  await run("UPDATE falcon_connections SET name = ?, base_url = ?, client_id = ?, secret_sealed = ?, updated_at = ? WHERE id = ?",
    i.name || null, i.baseUrl, i.clientId, i.secret ? seal(i.secret) : old.secret_sealed, now(), old.id); // a secret left empty is kept
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.update", resource: `${t.name} (${i.baseUrl})`, result: "ok", ip: c.ip });
  return view(t.id);
});

route("DELETE", "/api/tenants/:id/falcon/:conn", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  const old = await get<Conn>("SELECT * FROM falcon_connections WHERE id = ? AND tenant_id = ?", c.params.conn, t.id);
  if (!old) throw new HttpError(404, "Not found");
  if (c.body.confirmCid !== old.cid) throw new HttpError(400, "Type the CID to confirm", "confirm_cid"); // it also removes the data read for that CID
  await tx(async () => {
    for (const table of DATA_TABLES) await run(`DELETE FROM ${table} WHERE cid = ?`, old.cid);
    await run("DELETE FROM falcon_connections WHERE id = ?", old.id);
    await run("DELETE FROM tenant_cids WHERE cid = ?", old.cid);
  });
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.remove", resource: t.name, result: "ok", ip: c.ip });
  return view(t.id);
});

/** Try the old shared login on this organization's CIDs that have no connection. Only a CID it can really read gets a connection; the answer says which. */
route("POST", "/api/tenants/:id/falcon/convert-shared", SUPER, async (c) => {
  const t = await tenantOr404(c.params.id);
  if (!(await loadConfig())) throw new HttpError(400, "There is no old shared login to try", "no_shared");
  const results = await convertSharedLogin(t.id);
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.falcon.convert", resource: `${results.filter((r) => r.ok).length}/${results.length} CIDs`, result: "ok", ip: c.ip });
  return { results, ...(await view(t.id)) };
});
