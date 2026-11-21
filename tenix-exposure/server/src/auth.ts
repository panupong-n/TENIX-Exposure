import { all, audit, byName, get, isSoc, now, run, type User } from "./db.ts";
import { burnPasswordCheck, hashPassword, newTotpSecret, seal, sha256, token, totpMatch, totpUri, unseal, verifyPassword } from "./crypto.ts";
import { HttpError, MFA_COOKIE, SESSION_COOKIE, route, type Ctx } from "./http.ts";

const HOUR = 3600_000;
const SESSION_TTL = 12 * HOUR;
const REMEMBER_TTL = 30 * 24 * HOUR;
const MFA_TTL = 5 * 60_000;
const MIN_PASSWORD = 12;

export const str = (v: unknown, max = 200): string => {
  if (typeof v !== "string" || v.length > max) throw new HttpError(400, "Invalid input");
  return v;
};
export const checkPassword = (pw: string, email: string) => {
  if (pw.length < MIN_PASSWORD) throw new HttpError(400, `Password must be at least ${MIN_PASSWORD} characters`, "weak_password");
  if (pw.length > 200 || pw.toLowerCase() === email.toLowerCase()) throw new HttpError(400, "Password is not acceptable", "weak_password");
};

// shortcut: in-memory counters, single process; move to the database when running more than one instance
const fails = new Map<string, { n: number; first: number; lockedUntil: number }>();
const WINDOW = 15 * 60_000;
function guard(key: string) {
  const f = fails.get(key);
  if (f && f.lockedUntil > now()) throw new HttpError(429, "Too many attempts, try again later", "rate_limited");
}
function failed(key: string) {
  const t = now();
  let f = fails.get(key);
  if (!f || t - f.first > WINDOW) f = { n: 0, first: t, lockedUntil: 0 };
  f.n++;
  if (f.n >= 5) f.lockedUntil = t + WINDOW;
  fails.set(key, f);
}
const cleared = (key: string) => fails.delete(key);

export async function startSession(c: Ctx, user: User, stage: "mfa" | "full", remember = false): Promise<void> {
  const raw = token();
  const ttl = stage === "mfa" ? MFA_TTL : remember ? REMEMBER_TTL : SESSION_TTL;
  await run("INSERT INTO sessions (id_hash, user_id, stage, expires_at, created_at, remember, ip) VALUES (?,?,?,?,?,?,?)",
    sha256(raw), user.id, stage, now() + ttl, now(), remember ? 1 : 0, c.ip);
  c.setCookie(stage === "mfa" ? MFA_COOKIE : SESSION_COOKIE, raw, Math.floor(ttl / 1000));
}
export const revokeSessions = (userId: string, exceptHash: string | null = null) =>
  run("DELETE FROM sessions WHERE user_id = ? AND id_hash IS DISTINCT FROM ?", userId, exceptHash);

export async function publicUser(u: User) {
  const tenants = byName(await all<{ id: string; name: string; role: "admin" | "operator" }>(
    "SELECT t.id, t.name, m.role FROM user_tenants m JOIN tenants t ON t.id = m.tenant_id WHERE m.user_id = ?", u.id));
  return {
    id: u.id, email: u.email, name: u.name, role: u.role, soc: isSoc(u.role),
    // may this person open the Team page? (a super admin always; otherwise only as admin of some tenant)
    manager: isSoc(u.role) || tenants.some((t) => t.role === "admin"),
    // a super admin belongs to no tenant in particular: the pages list every tenant for them
    tenants: isSoc(u.role) ? [] : tenants, totpEnabled: !!u.totp_enabled,
  };
}

route("POST", "/api/auth/login", { auth: "none" }, async (c) => {
  const email = str(c.body.email, 254).trim().toLowerCase();
  const password = str(c.body.password, 200);
  const key = `${c.ip}|${email}`;
  guard(key);
  const user = await get<User>("SELECT * FROM users WHERE email = ?", email);
  const ok = user && !user.disabled ? await verifyPassword(password, user.password_hash) : (await burnPasswordCheck(), false);
  if (!ok || !user) {
    failed(key);
    await audit({ actor: user ?? null, action: "login", resource: email, result: "fail", ip: c.ip });
    throw new HttpError(401, "Invalid email or password", "invalid_credentials");
  }
  cleared(key);
  const remember = c.body.remember === true;
  if (user.totp_enabled) {
    await startSession(c, user, "mfa", remember);
    return { status: "mfa_required" };
  }
  await startSession(c, user, "full", remember);
  await run("UPDATE users SET last_login_at = ? WHERE id = ?", now(), user.id);
  await audit({ actor: user, action: "login", result: "ok", ip: c.ip });
  return { status: "ok", user: await publicUser(user) };
});

route("POST", "/api/auth/login/mfa", { auth: "mfa" }, async (c) => {
  const user = c.user!;
  const key = `mfa|${user.id}`;
  try { guard(key); } catch (e) { await run("DELETE FROM sessions WHERE id_hash = ?", c.sessionHash!); throw e; }
  const step = user.totp_secret ? totpMatch(unseal(user.totp_secret), str(c.body.code, 10).trim()) : null;
  // each 30 s step can be used once: a replayed code is refused
  if (step === null || step <= user.totp_last_step) {
    failed(key);
    await audit({ actor: user, action: "login.mfa", result: "fail", ip: c.ip });
    throw new HttpError(401, "Invalid verification code", "invalid_code");
  }
  cleared(key);
  const remember = !!(await get<{ remember: number }>("SELECT remember FROM sessions WHERE id_hash = ?", c.sessionHash!))?.remember;
  await run("UPDATE users SET totp_last_step = ?, last_login_at = ? WHERE id = ?", step, now(), user.id);
  await run("DELETE FROM sessions WHERE id_hash = ?", c.sessionHash!);
  c.clearCookie(MFA_COOKIE);
  await startSession(c, user, "full", remember);
  await audit({ actor: user, action: "login.mfa", result: "ok", ip: c.ip });
  return { status: "ok", user: await publicUser(user) };
});

route("POST", "/api/auth/logout", async (c) => {
  await run("DELETE FROM sessions WHERE id_hash = ?", c.sessionHash!);
  c.clearCookie(SESSION_COOKIE);
  await audit({ actor: c.user, action: "logout", result: "ok", ip: c.ip });
});

route("GET", "/api/auth/me", async (c) => ({ user: await publicUser(c.user!) }));

route("POST", "/api/account/password", async (c) => {
  const u = c.user!;
  const current = str(c.body.currentPassword);
  const next = str(c.body.newPassword);
  if (!(await verifyPassword(current, u.password_hash))) throw new HttpError(400, "Current password is incorrect", "invalid_credentials");
  checkPassword(next, u.email);
  await run("UPDATE users SET password_hash = ? WHERE id = ?", await hashPassword(next), u.id);
  await revokeSessions(u.id, c.sessionHash);
  await audit({ actor: u, action: "password.change", result: "ok", ip: c.ip });
});

// MFA is optional: nothing in the app forces a user to enable it.
route("POST", "/api/account/mfa/setup", async (c) => {
  const u = c.user!;
  if (u.totp_enabled) throw new HttpError(409, "MFA is already enabled", "mfa_enabled");
  const secret = newTotpSecret();
  await run("UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ?", seal(secret), u.id);
  return { secret, uri: totpUri(secret, u.email) };
});

route("POST", "/api/account/mfa/enable", async (c) => {
  const u = c.user!;
  if (u.totp_enabled || !u.totp_secret) throw new HttpError(409, "Start MFA setup first", "mfa_not_pending");
  const step = totpMatch(unseal(u.totp_secret), str(c.body.code, 10).trim());
  if (step === null) throw new HttpError(400, "Invalid verification code", "invalid_code");
  await run("UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?", step, u.id);
  await audit({ actor: u, action: "mfa.enable", result: "ok", ip: c.ip });
});

route("POST", "/api/account/mfa/disable", async (c) => {
  const u = c.user!;
  if (!u.totp_enabled || !u.totp_secret) throw new HttpError(409, "MFA is not enabled", "mfa_not_enabled");
  const step = totpMatch(unseal(u.totp_secret), str(c.body.code, 10).trim());
  if (!(await verifyPassword(str(c.body.password), u.password_hash)) || step === null || step <= u.totp_last_step) {
    throw new HttpError(400, "Password or verification code is incorrect", "invalid_credentials");
  }
  await run("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = 0 WHERE id = ?", u.id);
  await audit({ actor: u, action: "mfa.disable", result: "ok", ip: c.ip });
});
