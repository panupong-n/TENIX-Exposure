import { all, audit, get, isSoc } from "./db.ts";
import { HttpError, type Ctx } from "./http.ts";

export interface Scope { tenantId: string; tenantName: string; cids: string[] }

/**
 * The only place that decides which CIDs a request may touch.
 * - member: only tenants they belong to (one tenant needs no choice). A foreign tenantId gets the same 404 as a missing one and is audited.
 * - super admin: must name a tenant explicitly on every request, and each read is audited.
 * - a tenant without CIDs yields an empty list, which callers must treat as "no data", never as "all".
 */
export async function tenantScope(c: Ctx, label: string): Promise<Scope> {
  const u = c.user!;
  const asked = c.query.get("tenantId");
  const mine = new Set(u.memberships.map((m) => m.tenant_id));
  let tenantId: string;
  if (asked) {
    if (!isSoc(u.role) && !mine.has(asked)) {
      await audit({ actor: u, action: `read:${label}`, resource: asked, result: "denied", ip: c.ip });
      throw new HttpError(404, "Not found");
    }
    tenantId = asked;
  } else if (!isSoc(u.role) && mine.size === 1) {
    tenantId = [...mine][0]; // a user with one tenant never has to choose
  } else if (!isSoc(u.role) && mine.size === 0) {
    throw new HttpError(403, "No organization has been assigned to this account", "no_tenant");
  } else {
    throw new HttpError(400, "tenantId is required", "tenant_required");
  }
  const t = await get<{ id: string; name: string }>("SELECT id, name FROM tenants WHERE id = ?", tenantId);
  if (!t) throw new HttpError(404, "Not found");
  if (isSoc(u.role)) await audit({ actor: u, tenantId: t.id, action: `read:${label}`, result: "allowed", ip: c.ip });
  const cids = (await all<{ cid: string }>("SELECT cid FROM tenant_cids WHERE tenant_id = ? ORDER BY cid", t.id)).map((r) => r.cid);
  return { tenantId: t.id, tenantName: t.name, cids };
}

/** SQL placeholders for an IN list. An empty list becomes a clause that matches nothing. */
export const inList = (xs: string[]) => (xs.length ? `(${xs.map(() => "?").join(",")})` : "(NULL)");
