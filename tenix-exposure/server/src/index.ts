import { appUrl, host, port, isProd } from "./config.ts";
import { get, now, run } from "./db.ts";
import { sha256, token, uuid } from "./crypto.ts";
import { createApp } from "./http.ts";
import { migrateSharedLogin, startScheduler } from "./falcon.ts";
import "./auth.ts";
import "./team.ts";
import "./exposure.ts";
import "./overview.ts";
import "./lists2.ts";
import "./graph2.ts";
import "./software.ts";
import "./mail.ts";
import "./line.ts";
import "./watch.ts";
import "./notify.ts";
import "./news.ts";
import "./easm.ts";
import { startFeeds } from "./feeds.ts";
import { warmAll } from "./cache.ts";
import "./system.ts";
import "./connections.ts";

/** First run: no users yet, so print a one-time link that creates the first SOC admin. */
async function bootstrap() {
  if (await get("SELECT 1 FROM users LIMIT 1")) return;
  const email = (process.env.TENIX_BOOTSTRAP_EMAIL ?? "").trim().toLowerCase();
  if (!email) {
    console.log("\nNo users exist yet. Set TENIX_BOOTSTRAP_EMAIL=you@company.com and restart to get a one-time link for the first admin.\n");
    return;
  }
  const raw = token();
  await run("UPDATE invites SET revoked_at = ? WHERE kind = 'invite' AND role = 'super_admin' AND accepted_at IS NULL AND revoked_at IS NULL", now());
  await run("INSERT INTO invites (id, email, role, memberships_json, kind, token_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)",
    uuid(), email, "super_admin", "[]", "invite", sha256(raw), now() + 24 * 3600_000, now());
  console.log(`\nFirst admin link (valid 24 h, one use):\n  ${appUrl}/accept-invite/${raw}\n`);
}

await bootstrap();
void migrateSharedLogin().catch((e) => console.error("[falcon] converting the old shared login failed:", (e as Error).message)).finally(() => startScheduler(Number(process.env.TENIX_SYNC_MINUTES ?? 60)));
startFeeds();
void warmAll().catch((e) => console.error("[cache] warm-up failed", e)); // in the background: the server answers while it fills
createApp().listen(port, host, () => console.log(`TENIX Exposure server on ${host}:${port} (${isProd ? "production" : "development"})`));
