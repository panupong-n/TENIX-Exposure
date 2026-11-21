import nodemailer from "nodemailer";
import { all, audit, get, now, run, tx } from "./db.ts";
import { seal, unseal, uuid } from "./crypto.ts";
import { str } from "./auth.ts";
import { HttpError, route } from "./http.ts";
import { composeTest, type Mail } from "./mailkit.ts";

/** Alert types a recipient can subscribe to. Add a name here and call notify() where it happens. */
export const EVENTS = ["sync_failed", "critical_new"] as const;
export type MailEvent = (typeof EVENTS)[number];

interface Sender {
  id: string; name: string; host: string; port: number; security: "tls" | "starttls" | "none"; username: string | null;
  password_sealed: string | null; from_name: string | null; from_email: string; is_default: number; created_at: number;
}
const EMAIL = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/;
const HOST = /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/;
const SECURITY = ["tls", "starttls", "none"] as const;

const transport = (s: Sender) => nodemailer.createTransport({
  host: s.host, port: s.port, secure: s.security === "tls", requireTLS: s.security === "starttls", ignoreTLS: s.security === "none",
  auth: s.username ? { user: s.username, pass: s.password_sealed ? unseal(s.password_sealed) : "" } : undefined,
  connectionTimeout: 10_000, greetingTimeout: 10_000, socketTimeout: 20_000,
});
const sendVia = (s: Sender, to: string, m: Mail) =>
  transport(s).sendMail({ from: s.from_name ? { name: s.from_name, address: s.from_email } : s.from_email, to, subject: m.subject, text: m.text, html: m.html });

/** One mail to one person through the default sender (an invitation, a reset link). "no_sender": nothing is set up yet, so the caller shows the link instead. */
export async function sendMailTo(to: string, mail: Mail, event = "account"): Promise<"sent" | "no_sender" | "failed"> {
  const sender = await get<Sender>("SELECT * FROM mail_senders ORDER BY is_default DESC, created_at LIMIT 1");
  if (!sender) return "no_sender";
  let error: string | null = null;
  try { await sendVia(sender, to, mail); } catch (e) { error = (e as Error).message.slice(0, 300); }
  await run("INSERT INTO mail_log (ts, event, recipient, state, error) VALUES (?,?,?,?,?)", now(), event, to, error ? "failed" : "sent", error);
  return error ? "failed" : "sent";
}

/**
 * Sends one mail per recipient (never a shared To list). A recipient tied to a tenant only gets that tenant's events;
 * a recipient without a tenant is SOC-wide and gets every tenant's. Failures are logged, never thrown.
 */
export async function notify(event: MailEvent, tenantId: string | null, mail: Mail): Promise<void> {
  try {
    const sender = await get<Sender>("SELECT * FROM mail_senders ORDER BY is_default DESC, created_at LIMIT 1");
    if (!sender) return;
    const rows = await all<{ email: string }>(
      `SELECT DISTINCT r.email FROM mail_recipients r JOIN mail_subscriptions s ON s.recipient_id = r.id AND s.event = ?
       WHERE r.enabled = 1 AND (r.tenant_id IS NULL OR r.tenant_id = ?)`, event, tenantId);
    for (const { email } of rows) {
      let error: string | null = null;
      try { await sendVia(sender, email, mail); } catch (e) { error = (e as Error).message.slice(0, 300); }
      await run("INSERT INTO mail_log (ts, event, recipient, state, error) VALUES (?,?,?,?,?)", now(), event, email, error ? "failed" : "sent", error);
    }
  } catch (e) { console.error("[mail] notify failed:", (e as Error).message); }
}

const ADMIN = { roles: ["super_admin" as const] };
const view = (r: Sender) => ({
  id: r.id, name: r.name, host: r.host, port: r.port, security: r.security, username: r.username, hasPassword: !!r.password_sealed,
  fromName: r.from_name, fromEmail: r.from_email, isDefault: !!r.is_default,
});

function senderInput(body: Record<string, unknown>) {
  const name = str(body.name, 60).trim();
  const host = str(body.host, 253).trim();
  const port = Number(body.port);
  const security = str(body.security, 10) as Sender["security"];
  const username = typeof body.username === "string" && body.username.trim() ? str(body.username, 200).trim() : null;
  const password = typeof body.password === "string" && body.password ? str(body.password, 200) : null;
  const fromEmail = str(body.fromEmail, 254).trim().toLowerCase();
  const fromName = typeof body.fromName === "string" && body.fromName.trim() ? str(body.fromName, 80).trim() : null;
  if (!name || !HOST.test(host) || !Number.isInteger(port) || port < 1 || port > 65535 || !SECURITY.includes(security) || !EMAIL.test(fromEmail) || /[\r\n]/.test(fromName ?? "")) {
    throw new HttpError(400, "Check the sender details", "invalid_sender");
  }
  return { name, host, port, security, username, password, fromEmail, fromName };
}

route("GET", "/api/mail", ADMIN, async () => {
  const subs = await all<{ recipient_id: string; event: string }>("SELECT recipient_id, event FROM mail_subscriptions");
  const rec = await all<{ id: string; email: string; name: string | null; tenant_id: string | null; enabled: number; tenant_name: string | null }>(
    "SELECT r.id, r.email, r.name, r.tenant_id, r.enabled, t.name AS tenant_name FROM mail_recipients r LEFT JOIN tenants t ON t.id = r.tenant_id ORDER BY r.created_at");
  return {
    events: EVENTS,
    senders: (await all<Sender>("SELECT * FROM mail_senders ORDER BY created_at")).map(view),
    recipients: rec.map((r) => ({
      id: r.id, email: r.email, name: r.name, tenantId: r.tenant_id, tenantName: r.tenant_name, enabled: !!r.enabled,
      events: subs.filter((s) => s.recipient_id === r.id).map((s) => s.event),
    })),
    log: await all("SELECT id, ts, event, recipient, state, error FROM mail_log ORDER BY id DESC LIMIT 20"),
  };
});

route("POST", "/api/mail/senders", ADMIN, async (c) => {
  const i = senderInput(c.body);
  const id = uuid();
  const first = !(await get("SELECT 1 FROM mail_senders LIMIT 1"));
  await run(`INSERT INTO mail_senders (id, name, host, port, security, username, password_sealed, from_name, from_email, is_default, created_at, updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, id, i.name, i.host, i.port, i.security, i.username, i.password ? seal(i.password) : null, i.fromName, i.fromEmail, first ? 1 : 0, now(), now());
  await audit({ actor: c.user, action: "mail.sender.create", resource: `${i.name} (${i.host})`, result: "ok", ip: c.ip });
  return { id };
});

route("PUT", "/api/mail/senders/:id", ADMIN, async (c) => {
  const old = await get<Sender>("SELECT * FROM mail_senders WHERE id = ?", c.params.id);
  if (!old) throw new HttpError(404, "Not found");
  const i = senderInput(c.body);
  await run(`UPDATE mail_senders SET name=?, host=?, port=?, security=?, username=?, password_sealed=?, from_name=?, from_email=?, updated_at=? WHERE id=?`,
    i.name, i.host, i.port, i.security, i.username, i.password ? seal(i.password) : i.username ? old.password_sealed : null, i.fromName, i.fromEmail, now(), old.id);
  await audit({ actor: c.user, action: "mail.sender.update", resource: `${i.name} (${i.host})`, result: "ok", ip: c.ip });
});

route("POST", "/api/mail/senders/:id/default", ADMIN, async (c) => {
  if (!(await get("SELECT 1 FROM mail_senders WHERE id = ?", c.params.id))) throw new HttpError(404, "Not found");
  await tx(async () => {
    await run("UPDATE mail_senders SET is_default = 0");
    await run("UPDATE mail_senders SET is_default = 1 WHERE id = ?", c.params.id);
  });
});

route("DELETE", "/api/mail/senders/:id", ADMIN, async (c) => {
  const old = await get<Sender>("SELECT * FROM mail_senders WHERE id = ?", c.params.id);
  if (!old) throw new HttpError(404, "Not found");
  await run("DELETE FROM mail_senders WHERE id = ?", old.id);
  if (old.is_default) await run("UPDATE mail_senders SET is_default = 1 WHERE id = (SELECT id FROM mail_senders ORDER BY created_at LIMIT 1)");
  await audit({ actor: c.user, action: "mail.sender.delete", resource: old.name, result: "ok", ip: c.ip });
});

route("POST", "/api/mail/senders/:id/test", ADMIN, async (c) => {
  const s = await get<Sender>("SELECT * FROM mail_senders WHERE id = ?", c.params.id);
  if (!s) throw new HttpError(404, "Not found");
  const to = str(c.body.to, 254).trim().toLowerCase();
  if (!EMAIL.test(to)) throw new HttpError(400, "Enter a valid email address");
  let error: string | null = null;
  try { await sendVia(s, to, composeTest({ sender: s.name })); } catch (e) { error = (e as Error).message.slice(0, 300); }
  await audit({ actor: c.user, action: "mail.sender.test", resource: s.name, result: error ? "fail" : "ok", ip: c.ip, detail: error });
  return error ? { ok: false, error } : { ok: true };
});

async function eventsInput(v: unknown): Promise<string[]> {
  if (!Array.isArray(v)) throw new HttpError(400, "events must be a list");
  const ev = [...new Set(v.map((x) => str(x, 40)))];
  if (ev.some((x) => !(EVENTS as readonly string[]).includes(x))) throw new HttpError(400, "Unknown alert type");
  return ev;
}
const setEvents = async (id: string, events: string[]) => {
  await run("DELETE FROM mail_subscriptions WHERE recipient_id = ?", id);
  for (const e of events) await run("INSERT INTO mail_subscriptions (recipient_id, event) VALUES (?,?)", id, e);
};

route("POST", "/api/mail/recipients", ADMIN, async (c) => {
  const email = str(c.body.email, 254).trim().toLowerCase();
  if (!EMAIL.test(email)) throw new HttpError(400, "Enter a valid email address");
  const name = typeof c.body.name === "string" && c.body.name.trim() ? str(c.body.name, 100).trim() : null;
  const tenantId = typeof c.body.tenantId === "string" && c.body.tenantId ? c.body.tenantId : null;
  if (tenantId && !(await get("SELECT 1 FROM tenants WHERE id = ?", tenantId))) throw new HttpError(400, "Unknown tenant");
  const events = await eventsInput(c.body.events ?? []);
  const id = uuid();
  await tx(async () => {
    await run("INSERT INTO mail_recipients (id, email, name, tenant_id, enabled, created_at) VALUES (?,?,?,?,1,?)", id, email, name, tenantId, now());
    await setEvents(id, events);
  });
  await audit({ actor: c.user, tenantId, action: "mail.recipient.create", resource: email, result: "ok", ip: c.ip });
  return { id };
});

route("PUT", "/api/mail/recipients/:id", ADMIN, async (c) => {
  const r = await get<{ id: string; tenant_id: string | null; email: string }>("SELECT id, tenant_id, email FROM mail_recipients WHERE id = ?", c.params.id);
  if (!r) throw new HttpError(404, "Not found");
  const events = c.body.events === undefined ? null : await eventsInput(c.body.events);
  await tx(async () => {
    if (typeof c.body.enabled === "boolean") await run("UPDATE mail_recipients SET enabled = ? WHERE id = ?", c.body.enabled ? 1 : 0, r.id);
    if (events) await setEvents(r.id, events);
  });
  await audit({ actor: c.user, tenantId: r.tenant_id, action: "mail.recipient.update", resource: r.email, result: "ok", ip: c.ip });
});

route("DELETE", "/api/mail/recipients/:id", ADMIN, async (c) => {
  const r = await get<{ id: string; tenant_id: string | null; email: string }>("SELECT id, tenant_id, email FROM mail_recipients WHERE id = ?", c.params.id);
  if (!r) throw new HttpError(404, "Not found");
  await run("DELETE FROM mail_recipients WHERE id = ?", r.id);
  await audit({ actor: c.user, tenantId: r.tenant_id, action: "mail.recipient.delete", resource: r.email, result: "ok", ip: c.ip });
});
