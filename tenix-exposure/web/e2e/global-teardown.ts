/* eslint-disable @typescript-eslint/no-explicit-any -- test plumbing over untyped API JSON */
import { existsSync, readFileSync, rmSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { testDatabaseUrl } from "./test-db";

const here = dirname(fileURLToPath(import.meta.url));
const AUTH = join(here, ".auth");

export default async function globalTeardown() {
  const file = join(AUTH, "env.json");
  if (!existsSync(file)) return;
  const env = JSON.parse(readFileSync(file, "utf8")) as { schema: string; pids: number[] };
  // only the PIDs recorded by global-setup, never by name
  for (const pid of env.pids) { try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ } }
  (globalThis as any).__e2eSmtp?.close();
  await new Promise((r) => setTimeout(r, 500));
  if (/^e2e_[a-z]+$/.test(env.schema)) {
    const { Client } = createRequire(join(here, "../../server/package.json"))("pg");
    const db = new Client({ connectionString: testDatabaseUrl() });
    await db.connect();
    try { await db.query(`DROP SCHEMA IF EXISTS ${env.schema} CASCADE`); } finally { await db.end(); }
  }
  for (const f of readdirSync(AUTH)) rmSync(join(AUTH, f), { force: true });
}
