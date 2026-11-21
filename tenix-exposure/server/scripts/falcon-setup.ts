// Saves the CrowdStrike Falcon connection and the CID to the database, so the secret never has to be typed anywhere else.
//   cd server && node scripts/falcon-setup.ts
// Uses TENIX_DATABASE_URL (required in production; otherwise defaults to port 5433) and, in production, TENIX_SECRET_KEY.
import { createInterface } from "node:readline/promises";
import { allowCustomFalconUrl } from "../src/config.ts";
import { get, now, pool, run } from "../src/db.ts";
import { seal, uuid } from "../src/crypto.ts";
import { FalconClient, loadConfig, syncCids, syncState } from "../src/falcon.ts";

const CLOUDS = [
  { name: "us-1", url: "https://api.crowdstrike.com" },
  { name: "us-2", url: "https://api.us-2.crowdstrike.com" },
  { name: "eu-1", url: "https://api.eu-1.crowdstrike.com" },
  { name: "us-gov-1", url: "https://api.laggar.gcw.crowdstrike.com" },
];
if (allowCustomFalconUrl) CLOUDS.push({ name: "mock", url: "http://127.0.0.1:8799" }); // local development only
const DEFAULT_CLOUD = 1; // us-2

if (!process.stdin.isTTY) { console.error("Run this in a terminal: it asks for the secret without echoing it."); process.exit(1); }
// One short-lived readline per question, so nothing is listening (and echoing) while the secret is typed.
const ask = async (q: string, def = "") => {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try { return (await rl.question(def ? `${q} [${def}]: ` : `${q}: `)).trim() || def; } finally { rl.close(); }
};

/** Reads a line without echoing it. */
function askHidden(q: string): Promise<string> {
  return new Promise((done) => {
    process.stdout.write(`${q}: `);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    let buf = "";
    const onData = (d: Buffer) => {
      for (const ch of d.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.off("data", onData);
          process.stdout.write("\n");
          process.stdin.pause();
          return done(buf.trim());
        }
        if (ch === "\u0003") { process.stdout.write("\n"); process.exit(130); }
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1); else buf += ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function main() {
  console.log("\nTENIX Exposure: Falcon connection\n");
  const existing = await loadConfig();
  let baseUrl = existing?.baseUrl ?? "";
  let clientId = existing?.clientId ?? "";
  let secret = existing?.clientSecret ?? "";

  if (existing && (await ask(`A connection already exists (${existing.clientId} on ${existing.baseUrl}). Keep it? y/n`, "y")).toLowerCase() !== "n") {
    console.log("Keeping the existing credentials.\n");
  } else {
    CLOUDS.forEach((c, i) => console.log(`  ${i + 1}) ${c.name.padEnd(9)} ${c.url}${i === DEFAULT_CLOUD ? "   (default)" : ""}`));
    const pick = Number(await ask("Which Falcon cloud", String(DEFAULT_CLOUD + 1)));
    const cloud = CLOUDS[pick - 1];
    if (!cloud) throw new Error("Pick a number from the list");
    baseUrl = cloud.url;
    clientId = await ask("API client ID");
    secret = await askHidden("API client secret (hidden)");
    if (!clientId || !secret) throw new Error("Client ID and secret are required");
    await run(`INSERT INTO integrations (key, config_json, secret_sealed, updated_at, updated_by) VALUES ('falcon', ?, ?, ?, 'script')
               ON CONFLICT (key) DO UPDATE SET config_json = excluded.config_json, secret_sealed = excluded.secret_sealed, updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
      JSON.stringify({ baseUrl, clientId }), seal(secret), now());
    console.log("Saved (the secret is stored encrypted).\n");
  }

  const orgName = await ask("Organization name this CID belongs to (a customer, or your own company)");
  const cid = (await ask("CID (32 hexadecimal characters)")).toLowerCase();
  if (!orgName || orgName.length > 100) throw new Error("Organization name is required (max 100 characters)");
  if (!/^[0-9a-f]{32}$/.test(cid)) throw new Error("A CID is exactly 32 hexadecimal characters");
  const owner = await get<{ name: string }>("SELECT t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ?", cid);
  if (owner && owner.name !== orgName) throw new Error(`This CID already belongs to "${owner.name}"`);
  let tenant = await get<{ id: string }>("SELECT id FROM tenants WHERE name = ?", orgName);
  if (!tenant) {
    tenant = { id: uuid() };
    await run("INSERT INTO tenants (id, name, created_at) VALUES (?,?,?)", tenant.id, orgName, now());
    console.log(`Created organization "${orgName}".`);
  }
  await run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?,?) ON CONFLICT (cid) DO NOTHING", cid, tenant.id);
  console.log(`CID mapped to "${orgName}".\n`);

  process.stdout.write("Testing the connection… ");
  const t = await new FalconClient({ baseUrl, clientId, clientSecret: secret }).testLogin();
  if (!t.ok) {
    const why: Record<number, string> = { 401: "the client ID or secret is wrong", 403: "the API client lacks permission", 0: "the Falcon cloud could not be reached" };
    console.log(`failed (HTTP ${t.status || "network"}): ${why[t.status] ?? "unexpected error"}. Run this script again to fix it.`);
    return;
  }
  console.log("ok.\n");

  if ((await ask("Run the first data sync now? y/n", "y")).toLowerCase() === "n") {
    console.log("Done. Start a sync later from Integrations in the web app.");
    return;
  }
  const res = await syncCids([cid]);
  if (!res.started) throw new Error(`Could not start the sync: ${res.reason}`);
  process.stdout.write("Syncing (this can take a few minutes for large environments)");
  while (syncState.running) { process.stdout.write("."); await new Promise((ok) => setTimeout(ok, 2000)); }
  const st = await get<{ state: string; detail_json: string }>("SELECT state, detail_json FROM cid_status WHERE cid = ?", cid);
  const n = (await get<{ findings: number; hosts: number }>("SELECT COUNT(*) findings, COUNT(DISTINCT aid) hosts FROM findings WHERE cid = ?", cid))!;
  console.log(`\nResult: ${st?.state ?? "unknown"} · ${n.findings} findings on ${n.hosts} devices.`);
  const detail: string[] = JSON.parse(st?.detail_json ?? "[]");
  if (detail.length) console.log("Notes:\n  - " + detail.join("\n  - "));
}

try { await main(); } catch (e) { console.error(`\nError: ${(e as Error).message}`); process.exitCode = 1; } finally { await pool.end(); }
