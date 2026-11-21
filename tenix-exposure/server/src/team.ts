import { appUrl } from "./config.ts";
import { ROLLUP_CID_TABLES } from "./rollup.ts";
import { all, audit, byName, get, isSoc, managedTenants, now, run, tx, TENANT_ROLES, type Role, type SessionUser, type TenantRole, type User } from "./db.ts";
import { hashPassword, sha256, token, uuid } from "./crypto.ts";
import { checkPassword, publicUser, revokeSessions, startSession, str } from "./auth.ts";
import { sendMailTo } from "./mail.ts";
import { composeInvite, composeReset } from "./mailkit.ts";
import { HttpError, route, type Ctx } from "./http.ts";
import { tenantStats } from "./rollup.ts";

const INVITE_TTL = 7 * 24 * 3600_000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MANAGER = { manager: true };
const SUPER = { roles: ["super_admin" as const] };

/**
 * Who may do what (the server decides; the pages only mirror it):
 * - super admin: everything, in every tenant.
 * - admin of a tenant: invite, disable, delete and reset users of that tenant, and choose which of their tenants a user sees.
 *   A user who also belongs to a tenant this admin does not manage can only be removed from the admin's tenants, never disabled or deleted.
 * - operator: read-only access to the data of their tenants; no Team page.
 */
interface Mem { tenantId: string; role: TenantRole }
const managed = (c: Ctx) => managedTenants(c.user!);
const canManage = (m: "all" | Set<string>, tenantId: string) => m === "all" || m.has(tenantId);

async function memberships(userId: string) {
  return byName(await all<{ id: string; name: string; role: TenantRole }>("SELECT t.id, t.name, m.role FROM user_tenants m JOIN tenants t ON t.id = m.tenant_id WHERE m.user_id = ?", userId));
}

/** Reads and checks a list of { tenantId, role } sent by the client. */
async function readMemberships(v: unknown, m: "all" | Set<string>): Promise<Mem[]> {
  if (!Array.isArray(v) || v.length > 200) throw new HttpError(400, "memberships must be a list");
  const out = new Map<string, Mem>();
  for (const x of v) {
    const o = (x ?? {}) as Record<string, unknown>;
    const tenantId = str(o.tenantId, 64);
    const role = str(o.role, 20) as TenantRole;
    if (!TENANT_ROLES.includes(role)) throw new HttpError(400, "Unknown role");
    if (!canManage(m, tenantId)) throw new HttpError(403, "Forbidden", "forbidden");
    if (!(await get("SELECT 1 FROM tenants WHERE id = ?", tenantId))) throw new HttpError(400, "Unknown tenant");
    out.set(tenantId, { tenantId, role });
  }
  return [...out.values()];
}

/** May the actor disable, delete or reset this user? Only when every tenant the user belongs to is one the actor manages. */
async function administers(actor: SessionUser, target: User): Promise<boolean> {
  const m = managedTenants(actor);
  if (m === "all") return true;
  if (target.role === "super_admin") return false;
  const theirs = await memberships(target.id);
  return theirs.length > 0 && theirs.every((t) => m.has(t.id));
}
/** The user must be visible to the actor at all: a super admin sees everyone, an admin sees users of their tenants. */
async function visibleTarget(c: Ctx): Promise<User> {
  const t = await get<User>("SELECT * FROM users WHERE id = ?", c.params.id);
  const m = managed(c);
  if (!t) throw new HttpError(404, "Not found");
  if (m !== "all") {
    const shared = await get("SELECT 1 FROM user_tenants WHERE user_id = ? AND tenant_id IN (" + [...m].map(() => "?").join(",") + ")", t.id, ...m);
    if (!shared || t.role === "super_admin") throw new HttpError(404, "Not found");
  }
  return t;
}
async function administered(c: Ctx): Promise<User> {
  const t = await visibleTarget(c);
  if (!(await administers(c.user!, t))) throw new HttpError(403, "This user also belongs to another organization. Remove them from yours instead.", "shared_user");
  return t;
}
/** The tenant an action on this user is filed under in the audit log (the first one the actor manages that the user belongs to). */
async function tenantOf(c: Ctx, t: User): Promise<string | null> {
  const m = managed(c);
  const mine = (await memberships(t.id)).filter((x) => m === "all" || m.has(x.id));
  return mine[0]?.id ?? null;
}
const lastSuperAdmin = async (id: string) => !(await get("SELECT 1 FROM users WHERE role = 'super_admin' AND disabled = 0 AND id != ?", id));

/** Optional: also e-mail the link (when the caller asks and a sender is set up). Never fails the request: the link is always returned, so an admin can pass it on by hand. */
async function mailLink(c: Ctx, o: { to: string; name?: string | null; kind: "invite" | "reset"; role: Role; mem: Mem[]; link: string }): Promise<"sent" | "no_sender" | "failed" | "not_asked"> {
  if (c.body.sendEmail !== true) return "not_asked";
  try {
    const names = new Map((await all<{ id: string; name: string }>("SELECT id, name FROM tenants")).map((t) => [t.id, t.name]));
    const mail = o.kind === "reset"
      ? composeReset({ name: o.name, byAdmin: true, link: o.link, ttlMs: INVITE_TTL })
      : composeInvite({ name: o.name, inviter: c.user!.name, role: o.role === "super_admin" ? "Super admin" : [...new Set(o.mem.map((x) => (x.role === "admin" ? "Organization admin" : "Operator")))].join(" / "), organizations: o.mem.map((x) => names.get(x.tenantId)).filter((x): x is string => !!x), link: o.link, ttlMs: INVITE_TTL });
    return await sendMailTo(o.to, mail, o.kind === "reset" ? "password_reset" : "invitation");
  } catch (e) { console.error("[mail] invitation mail failed:", (e as Error).message); return "failed"; }
}

async function createInvite(c: Ctx, o: { email: string; role: Role; memberships: Mem[]; kind: "invite" | "reset"; userId?: string }) {
  const raw = token();
  const id = uuid();
  await run("INSERT INTO invites (id, email, role, memberships_json, kind, user_id, token_hash, invited_by, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
    id, o.email, o.role, JSON.stringify(o.memberships), o.kind, o.userId ?? null, sha256(raw), c.user?.id ?? null, now() + INVITE_TTL, now());
  return { id, expiresAt: now() + INVITE_TTL, link: `${appUrl}/accept-invite/${raw}` };
}
const pending = "accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?";

// ---------------------------------------------------------------- users
route("GET", "/api/team/users", MANAGER, async (c) => {
  const m = managed(c);
  const rows = m === "all"
    ? await all<User>("SELECT * FROM users ORDER BY created_at")
    : await all<User>(`SELECT DISTINCT u.* FROM users u JOIN user_tenants x ON x.user_id = u.id WHERE u.role = 'member' AND x.tenant_id IN (${[...m].map(() => "?").join(",")}) ORDER BY u.created_at`, ...m);
  const users = [];
  for (const u of rows) {
    const all_ = await memberships(u.id);
    const mine = m === "all" ? all_ : all_.filter((t) => m.has(t.id));
    users.push({
      id: u.id, email: u.email, name: u.name, role: u.role, disabled: !!u.disabled, totpEnabled: !!u.totp_enabled,
      lastLoginAt: u.last_login_at, createdAt: u.created_at, tenants: mine, hiddenTenants: all_.length - mine.length,
      canAdminister: u.id !== c.user!.id && (await administers(c.user!, u)),
    });
  }
  return { users };
});

route("GET", "/api/team/invites", MANAGER, async (c) => {
  const m = managed(c);
  const rows = await all<{ id: string; email: string; role: Role; kind: string; expires_at: number; created_at: number; memberships_json: string }>(
    `SELECT id, email, role, kind, expires_at, created_at, memberships_json FROM invites WHERE ${pending} ORDER BY created_at DESC`, now());
  const names = new Map((await all<{ id: string; name: string }>("SELECT id, name FROM tenants")).map((t) => [t.id, t.name]));
  const invites = rows.map((r) => {
    const all_ = (JSON.parse(r.memberships_json) as Mem[]).filter((x) => names.has(x.tenantId));
    const mine = m === "all" ? all_ : all_.filter((x) => m.has(x.tenantId));
    return { id: r.id, email: r.email, role: r.role, kind: r.kind, expiresAt: r.expires_at, createdAt: r.created_at, tenants: mine.map((x) => ({ id: x.tenantId, name: names.get(x.tenantId)!, role: x.role })), visible: m === "all" || mine.length > 0 };
  }).filter((i) => i.visible);
  return { invites };
});

route("POST", "/api/team/invites", MANAGER, async (c) => {
  const m = managed(c);
  const email = str(c.body.email, 254).trim().toLowerCase();
  const role = (c.body.role === "super_admin" ? "super_admin" : "member") as Role;
  if (!EMAIL.test(email)) throw new HttpError(400, "Invalid email");
  if (role === "super_admin" && m !== "all") throw new HttpError(403, "Forbidden", "forbidden");
  const mem = role === "super_admin" ? [] : await readMemberships(c.body.memberships, m);
  if (role === "member" && mem.length === 0) throw new HttpError(400, "Choose at least one organization", "no_tenant");
  if (await get("SELECT 1 FROM users WHERE email = ?", email)) throw new HttpError(409, "A user with this email already exists", "exists");
  const inv = await tx(async () => {
    await run("UPDATE invites SET revoked_at = ? WHERE email = ? AND kind = 'invite' AND accepted_at IS NULL AND revoked_at IS NULL", now(), email);
    return await createInvite(c, { email, role, memberships: mem, kind: "invite" });
  });
  await audit({ actor: c.user, tenantId: mem.length === 1 ? mem[0].tenantId : null, action: "invite.create", resource: `${email} (${role === "super_admin" ? "super admin" : mem.map((x) => x.role).join("/")})`, result: "ok", ip: c.ip });
  return { invite: { id: inv.id, email, role, expiresAt: inv.expiresAt }, link: inv.link, emailed: await mailLink(c, { to: email, kind: "invite", role, mem, link: inv.link }) };
});

async function inviteForManager(c: Ctx) {
  const inv = await get<{ id: string; email: string; role: Role; kind: "invite" | "reset"; user_id: string | null; memberships_json: string }>(
    `SELECT id, email, role, kind, user_id, memberships_json FROM invites WHERE id = ? AND ${pending}`, c.params.id, now());
  if (!inv) throw new HttpError(404, "Not found");
  const m = managed(c);
  const mem = JSON.parse(inv.memberships_json) as Mem[];
  if (m !== "all" && (inv.role === "super_admin" || !mem.some((x) => m.has(x.tenantId)))) throw new HttpError(404, "Not found");
  if (m !== "all" && inv.kind === "reset" && inv.user_id) {
    const target = await get<User>("SELECT * FROM users WHERE id = ?", inv.user_id);
    if (!target || !(await administers(c.user!, target))) throw new HttpError(404, "Not found");
  }
  return { ...inv, mem };
}
route("DELETE", "/api/team/invites/:id", MANAGER, async (c) => {
  const inv = await inviteForManager(c);
  await run("UPDATE invites SET revoked_at = ? WHERE id = ?", now(), inv.id);
  await audit({ actor: c.user, tenantId: inv.mem[0]?.tenantId ?? null, action: "invite.revoke", resource: inv.email, result: "ok", ip: c.ip });
});
route("POST", "/api/team/invites/:id/regenerate", MANAGER, async (c) => {
  const inv = await inviteForManager(c);
  const next = await tx(async () => {
    await run("UPDATE invites SET revoked_at = ? WHERE id = ?", now(), inv.id);
    return await createInvite(c, { email: inv.email, role: inv.role, memberships: inv.mem, kind: inv.kind, userId: inv.user_id ?? undefined });
  });
  await audit({ actor: c.user, tenantId: inv.mem[0]?.tenantId ?? null, action: "invite.regenerate", resource: inv.email, result: "ok", ip: c.ip });
  return { link: next.link, expiresAt: next.expiresAt, emailed: await mailLink(c, { to: inv.email, kind: inv.kind, role: inv.role, mem: inv.mem, link: next.link }) };
});

// ---------------------------------------------------------------- public: accept an invite or a password-reset link
function findInvite(raw: string) {
  return get<{ id: string; email: string; role: Role; kind: "invite" | "reset"; user_id: string | null; memberships_json: string }>(
    `SELECT id, email, role, kind, user_id, memberships_json FROM invites
     WHERE token_hash = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, sha256(raw), now());
}
route("GET", "/api/invites/:token", { auth: "none" }, async (c) => {
  const inv = await findInvite(c.params.token);
  if (!inv) throw new HttpError(404, "This link is invalid or has expired", "invalid_invite");
  const names = new Map((await all<{ id: string; name: string }>("SELECT id, name FROM tenants")).map((t) => [t.id, t.name]));
  const tenants = (JSON.parse(inv.memberships_json) as Mem[]).filter((x) => names.has(x.tenantId)).map((x) => ({ name: names.get(x.tenantId)!, role: x.role }));
  return { email: inv.email, role: inv.role, tenants, kind: inv.kind };
});
route("POST", "/api/invites/:token/accept", { auth: "none" }, async (c) => {
  const inv = await findInvite(c.params.token);
  if (!inv) throw new HttpError(404, "This link is invalid or has expired", "invalid_invite");
  const password = str(c.body.password);
  checkPassword(password, inv.email);
  const hash = await hashPassword(password);
  let user: User;
  if (inv.kind === "reset") {
    await run("UPDATE users SET password_hash = ? WHERE id = ?", hash, inv.user_id);
    await revokeSessions(inv.user_id!);
    user = (await get<User>("SELECT * FROM users WHERE id = ?", inv.user_id))!;
  } else {
    const name = str(c.body.name, 100).trim();
    if (!name) throw new HttpError(400, "Name is required");
    if (await get("SELECT 1 FROM users WHERE email = ?", inv.email)) throw new HttpError(409, "A user with this email already exists", "exists");
    const id = uuid();
    await tx(async () => {
      await run("INSERT INTO users (id, email, name, password_hash, role, created_at) VALUES (?,?,?,?,?,?)", id, inv.email, name, hash, inv.role, now());
      for (const x of JSON.parse(inv.memberships_json) as Mem[]) {
        // a tenant deleted since the invite was sent is simply skipped
        await run("INSERT INTO user_tenants (user_id, tenant_id, role) SELECT ?, id, ? FROM tenants WHERE id = ?", id, x.role, x.tenantId);
      }
    });
    user = (await get<User>("SELECT * FROM users WHERE id = ?", id))!;
  }
  await run("UPDATE invites SET accepted_at = ? WHERE id = ?", now(), inv.id);
  await audit({ actor: user, action: inv.kind === "reset" ? "password.reset" : "invite.accept", result: "ok", ip: c.ip });
  // a reset never signs in: the user may have MFA, so they go through the normal login
  if (inv.kind === "invite") { await startSession(c, user, "full"); return { status: "signed_in", user: await publicUser(user) }; }
  return { status: "reset" };
});

// ---------------------------------------------------------------- user actions
route("POST", "/api/team/users/:id/disable", MANAGER, async (c) => {
  const t = await administered(c);
  if (t.id === c.user!.id) throw new HttpError(400, "You cannot disable your own account");
  if (t.role === "super_admin" && (await lastSuperAdmin(t.id))) throw new HttpError(400, "This is the last active super admin", "last_super_admin");
  await run("UPDATE users SET disabled = 1 WHERE id = ?", t.id);
  await revokeSessions(t.id);
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "user.disable", resource: t.email, result: "ok", ip: c.ip });
});
route("POST", "/api/team/users/:id/enable", MANAGER, async (c) => {
  const t = await administered(c);
  await run("UPDATE users SET disabled = 0 WHERE id = ?", t.id);
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "user.enable", resource: t.email, result: "ok", ip: c.ip });
});
route("POST", "/api/team/users/:id/reset-mfa", MANAGER, async (c) => {
  const t = await administered(c);
  await run("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = 0 WHERE id = ?", t.id);
  await revokeSessions(t.id);
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "mfa.reset", resource: t.email, result: "ok", ip: c.ip });
});
route("POST", "/api/team/users/:id/reset-password", MANAGER, async (c) => {
  const t = await administered(c);
  const inv = await tx(async () => {
    await run("UPDATE invites SET revoked_at = ? WHERE user_id = ? AND kind = 'reset' AND accepted_at IS NULL AND revoked_at IS NULL", now(), t.id);
    return await createInvite(c, { email: t.email, role: t.role, memberships: [], kind: "reset", userId: t.id });
  });
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "password.reset.issue", resource: t.email, result: "ok", ip: c.ip });
  return { link: inv.link, expiresAt: inv.expiresAt, emailed: await mailLink(c, { to: t.email, name: t.name, kind: "reset", role: t.role, mem: [], link: inv.link }) };
});
route("DELETE", "/api/team/users/:id", MANAGER, async (c) => {
  const t = await administered(c);
  if (t.id === c.user!.id) throw new HttpError(400, "You cannot delete your own account");
  if (t.role === "super_admin" && (await lastSuperAdmin(t.id))) throw new HttpError(400, "This is the last active super admin", "last_super_admin");
  await run("DELETE FROM users WHERE id = ?", t.id); // sessions, memberships and their invites go with it
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "user.delete", resource: t.email, result: "ok", ip: c.ip });
});

/**
 * Which tenants a user sees, and as what. A super admin replaces the whole list (and may change the user type);
 * a tenant admin only changes the tenants they manage and leaves the rest untouched.
 */
route("PUT", "/api/team/users/:id/access", MANAGER, async (c) => {
  const t = await visibleTarget(c);
  const m = managed(c);
  if (t.role === "super_admin" && m !== "all") throw new HttpError(404, "Not found");
  const wanted = await readMemberships(c.body.memberships ?? [], m);
  let role: Role = t.role;
  if (m === "all" && (c.body.role === "super_admin" || c.body.role === "member")) role = c.body.role;
  if (role !== t.role) {
    if (t.id === c.user!.id) throw new HttpError(400, "You cannot change your own user type");
    if (t.role === "super_admin" && (await lastSuperAdmin(t.id))) throw new HttpError(400, "This is the last active super admin", "last_super_admin");
  }
  await tx(async () => {
    await run("UPDATE users SET role = ? WHERE id = ?", role, t.id);
    const keep = m === "all" ? [] : (await memberships(t.id)).filter((x) => !m.has(x.id));
    await run("DELETE FROM user_tenants WHERE user_id = ?", t.id);
    if (role === "member") {
      for (const x of [...wanted, ...keep.map((k) => ({ tenantId: k.id, role: k.role }))]) {
        await run("INSERT INTO user_tenants (user_id, tenant_id, role) VALUES (?,?,?)", t.id, x.tenantId, x.role);
      }
    }
    if (role !== t.role) await revokeSessions(t.id);
  });
  await audit({ actor: c.user, tenantId: await tenantOf(c, t), action: "user.access", resource: `${t.email}: ${role === "super_admin" ? "super admin" : wanted.map((x) => x.role).join("/") || "no access"}`, result: "ok", ip: c.ip });
});

// ---------------------------------------------------------------- tenants and their CIDs
const CID = /^[0-9a-f]{32}$/;
route("GET", "/api/tenants", async (c) => {
  const u = c.user!;
  const mine = new Map(u.memberships.map((x) => [x.tenant_id, x.role]));
  const rows = byName(await all<{ id: string; name: string; created_at: number }>("SELECT id, name, created_at FROM tenants"));
  const visible = isSoc(u.role) ? rows : rows.filter((t) => mine.has(t.id));
  const tenants = [];
  for (const t of visible) {
    const base = { id: t.id, name: t.name, role: isSoc(u.role) ? "super_admin" : mine.get(t.id)! };
    if (!isSoc(u.role)) { tenants.push(base); continue; }
    // CIDs, user counts and sync state are for super admins only
    const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", t.id)).map((r) => r.cid);
    const states = await all<{ cid: string; state: string; data_as_of: number | null; last_run_at: number; detail_json: string }>(
      "SELECT s.cid, s.state, s.data_as_of, s.last_run_at, s.detail_json FROM cid_status s JOIN tenant_cids x ON x.cid = s.cid WHERE x.tenant_id = ?", t.id);
    // headline numbers so the super admin sees at a glance what each tenant holds
    const stats = await tenantStats(t.id); // read from the rollups: the same four numbers in milliseconds
    const users = (await get<{ n: number }>("SELECT COUNT(*) n FROM user_tenants WHERE tenant_id = ?", t.id))!.n;
    const admins = (await get<{ n: number }>("SELECT COUNT(*) n FROM user_tenants WHERE tenant_id = ? AND role = 'admin'", t.id))!.n;
    const conns0 = (await get<{ n: number }>("SELECT COUNT(*) n FROM falcon_connections WHERE tenant_id = ?", t.id))!.n;
    const state = !cids.length ? "no_cids" : conns0 === 0 ? "no_connection" : states.length < cids.length ? "not_synced" : states.some((s) => s.state === "failed") ? "failed" : states.some((s) => s.state === "partial") ? "partial" : "complete";
    const lc = await all<{ role: string; chat_id: string }>("SELECT role, chat_id FROM line_chats WHERE tenant_id = ? ORDER BY created_at, chat_id", t.id);
    const conns = (await get<{ n: number }>("SELECT COUNT(*) n FROM falcon_connections WHERE tenant_id = ?", t.id))!.n;
    tenants.push({ ...base, lineChat: lc.find((r) => r.role === "destination")?.chat_id ?? "", line: { sources: lc.filter((r) => r.role === "source").length, destinations: lc.filter((r) => r.role === "destination").length },
      falcon: { connections: conns, unconnected: cids.length - conns }, cids, users, admins, state, dataAsOf: states.length ? Math.min(...states.map((s) => s.data_as_of ?? Infinity)) : null, createdAt: t.created_at,
      stats, lastRunAt: states.length ? Math.max(...states.map((s) => s.last_run_at)) : null, detail: states.flatMap((s) => JSON.parse(s.detail_json) as string[]) });
  }
  return { tenants };
});
route("POST", "/api/tenants", SUPER, async (c) => {
  const name = str(c.body.name, 100).trim();
  if (!name) throw new HttpError(400, "Name is required");
  if (await get("SELECT 1 FROM tenants WHERE name = ?", name)) throw new HttpError(409, "A tenant with this name already exists", "exists");
  const id = uuid();
  await run("INSERT INTO tenants (id, name, created_at) VALUES (?,?,?)", id, name, now());
  await audit({ actor: c.user, tenantId: id, action: "tenant.create", resource: name, result: "ok", ip: c.ip });
  return { tenant: { id, name, cids: [] } };
});
route("PUT", "/api/tenants/:id", SUPER, async (c) => {
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  const name = str(c.body.name, 100).trim();
  if (!name) throw new HttpError(400, "Name is required");
  if (await get("SELECT 1 FROM tenants WHERE name = ? AND id != ?", name, t.id)) throw new HttpError(409, "A tenant with this name already exists", "exists");
  await run("UPDATE tenants SET name = ? WHERE id = ?", name, t.id);
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.rename", resource: `${t.name} -> ${name}`, result: "ok", ip: c.ip });
});
route("DELETE", "/api/tenants/:id", SUPER, async (c) => {
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  if (c.body.confirmName !== t.name) throw new HttpError(400, "Type the tenant name to confirm", "confirm_name");
  await tx(async () => {
    const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ?", t.id)).map((r) => r.cid);
    for (const cid of cids) for (const table of ["findings", "cid_status", "snapshots", "sync_runs", "software", "software_hosts", "software_sync", "finding_closed", "external_assets", "external_sync", "cid_counts", "cid_sync", "cid_cursor", ...ROLLUP_CID_TABLES]) await run(`DELETE FROM ${table} WHERE cid = ?`, cid);
    await run("DELETE FROM tenants WHERE id = ?", t.id); // CIDs, memberships and mail recipients cascade
  });
  await audit({ actor: c.user, action: "tenant.delete", resource: t.name, result: "ok", ip: c.ip });
});
route("PUT", "/api/tenants/:id/cids", SUPER, async (c) => {
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", c.params.id);
  if (!t) throw new HttpError(404, "Not found");
  const raw = c.body.cids;
  if (!Array.isArray(raw) || raw.length > 100) throw new HttpError(400, "cids must be a list");
  // a CID that has a CrowdStrike connection of its own stays: it is removed by removing the connection
  const own = (await all<{ cid: string }>("SELECT cid FROM falcon_connections WHERE tenant_id = ?", t.id)).map((x) => x.cid);
  const cids = [...new Set([...raw.map((x) => str(x, 64).trim().toLowerCase()), ...own])];
  if (cids.some((x) => !CID.test(x))) throw new HttpError(400, "Each CID must be 32 hexadecimal characters", "invalid_cid");
  for (const cid of cids) {
    const owner = await get<{ name: string }>("SELECT t.name FROM tenant_cids x JOIN tenants t ON t.id = x.tenant_id WHERE x.cid = ? AND x.tenant_id != ?", cid, t.id);
    if (owner) throw new HttpError(409, `CID ${cid} already belongs to ${owner.name}`, "cid_taken");
  }
  await tx(async () => {
    await run("DELETE FROM tenant_cids WHERE tenant_id = ?", t.id);
    for (const cid of cids) await run("INSERT INTO tenant_cids (cid, tenant_id) VALUES (?,?)", cid, t.id);
  });
  await audit({ actor: c.user, tenantId: t.id, action: "tenant.cids", resource: `${cids.length} CIDs`, result: "ok", ip: c.ip });
  return { cids };
});

route("GET", "/api/audit", MANAGER, async (c) => {
  const m = managed(c);
  const limit = Math.min(Number(c.query.get("limit") ?? 100) || 100, 500);
  // an admin sees what happened in their tenants and what their tenants' users did (sign-ins, password changes, ...)
  const ph = m === "all" ? "" : [...m].map(() => "?").join(",");
  const where = m === "all" ? "" : `WHERE a.tenant_id IN (${ph}) OR a.actor_id IN (SELECT user_id FROM user_tenants WHERE tenant_id IN (${ph}))`;
  const rows = await all(
    `SELECT a.id, a.ts, a.actor_email, a.role, a.action, a.resource, a.result, a.ip, t.name AS tenant_name FROM audit a LEFT JOIN tenants t ON t.id = a.tenant_id
     ${where} ORDER BY a.id DESC LIMIT ?`, ...(m === "all" ? [] : [...m, ...m]), limit);
  return { entries: rows };
});
