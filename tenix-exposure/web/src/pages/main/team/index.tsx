import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { TableSkeleton } from "@/components/shared/skeletons";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { PlusIcon, VerticalDotsIcon } from "@/icons";
import { api, ApiError } from "@/lib/api";
import { formatDateTime } from "@/utils/format";
import { useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { ConfirmDialog, CreateLinkDialog, EditAccessDialog, InviteDialog, LinkDialog, type Emailed, type Membership, type SenderState, type TeamUser } from "./dialogs";

interface PendingInvite { id: string; email: string; role: "super_admin" | "member"; kind: "invite" | "reset"; expiresAt: number; createdAt: number; tenants: Membership[] }

const head = "py-1.5 pe-4 text-start text-xs font-medium whitespace-nowrap text-gray-500 dark:text-gray-400";
const cell = "py-1.5 pe-4 text-sm text-gray-500 dark:text-gray-400";
const box = "min-w-0 rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3";
const ALL = "all";

type Confirm = { kind: "disable" | "resetMfa" | "delete" | "revoke"; id: string; label: string; email: string } | null;
type Link = { link: string; email?: string; emailed?: Emailed; title: string; body: string } | null;
type Make = { path: string; email: string; kind: "reset" | "regenerate" } | null;

/** One chip per tenant ("Alpha Corp · Admin"), or a Super admin badge. */
function AccessChips({ role, tenants, hidden = 0 }: { role: "super_admin" | "member"; tenants: Membership[]; hidden?: number }) {
  const t = useTranslations("team.access");
  const tRoles = useTranslations("roles");
  if (role === "super_admin") return <Badge size="sm" color="primary" className="[text-shadow:none]">{t("superAdmin")}</Badge>;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {tenants.length === 0 && <span className="text-xs">{t("none")}</span>}
      {tenants.map((x) => (
        <Badge key={x.id} size="sm" color={x.role === "admin" ? "info" : "gray"} className="[text-shadow:none]">{t("chip", { name: x.name, role: tRoles(x.role) })}</Badge>
      ))}
      {hidden > 0 && <span className="text-xs text-gray-500 dark:text-gray-400">{t("hidden", { count: hidden })}</span>}
    </div>
  );
}

/** Users, invitations and their dialogs, without a page heading: used by the Setting Center drawer and by the page below. */
export function TeamPanel() {
  const t = useTranslations("team");
  const tc = useTranslations("common");
  const locale = useLocale();
  const { user: me } = useAuth();
  const { orgs } = useOrg();
  const [params, setParams] = useSearchParams();
  const users = useApi<{ users: TeamUser[] }>("/api/team/users");
  const invites = useApi<{ invites: PendingInvite[] }>("/api/team/invites");
  const [inviting, setInviting] = useState(false);
  const inviteRef = useRef<HTMLButtonElement>(null);
  const [editing, setEditing] = useState<TeamUser | null>(null);
  const [link, setLink] = useState<Link>(null);
  const [make, setMake] = useState<Make>(null);
  // /api/mail is for super admins; an organization admin cannot read it, so the server's "no_sender" answer tells them
  const mail = useApi<{ senders: unknown[] }>(me?.soc ? "/api/mail" : null);
  const sender: SenderState = !me?.soc ? "unknown" : mail.error ? "unknown" : !mail.data ? "loading" : mail.data.senders.length > 0 ? "yes" : "no";
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [error, setError] = useState<string | null>(null);

  const showFilter = Boolean(me?.soc) || (me?.tenants.length ?? 0) > 1;
  const wanted = params.get("tenant");
  const tenant = wanted && orgs.some((o) => o.id === wanted) ? wanted : ALL;
  const filterItems = [{ value: ALL, label: t("filter.all") }, ...orgs.map((o) => ({ value: o.id, label: o.name }))];
  const inTenant = (list: Membership[]) => tenant === ALL || list.some((x) => x.id === tenant);
  const shownUsers = users.data?.users.filter((u) => inTenant(u.tenants));
  const shownInvites = invites.data?.invites.filter((i) => inTenant(i.tenants));

  const refresh = () => {
    users.reload();
    invites.reload();
  };
  const fail = (e: unknown) => {
    const code = e instanceof ApiError ? e.code : null;
    setError(code === "shared_user" || code === "last_super_admin" ? t(`errors.${code}`) : t("errors.unknown"));
  };
  const act = async (path: string) => {
    setError(null);
    try {
      await api.post(path);
    } catch (e) {
      fail(e);
    }
    refresh();
  };
  const create = async (sendEmail: boolean) => {
    if (!make) return;
    setError(null);
    try {
      const r = await api.post<{ link: string; emailed?: Emailed }>(make.path, sendEmail ? { sendEmail: true } : undefined);
      setLink({ link: r.link, email: make.email, emailed: r.emailed, title: t("linkTitle"), body: t("linkBody") });
    } catch (e) {
      fail(e);
    }
    setMake(null);
    refresh();
  };
  const runConfirm = async () => {
    if (!confirm) return;
    setError(null);
    try {
      if (confirm.kind === "revoke") await api.del(`/api/team/invites/${confirm.id}`);
      else if (confirm.kind === "delete") await api.del(`/api/team/users/${confirm.id}`);
      else await api.post(`/api/team/users/${confirm.id}/${confirm.kind === "disable" ? "disable" : "reset-mfa"}`);
    } catch (e) {
      fail(e);
    }
    setConfirm(null);
    refresh();
  };
  const c = confirm;
  const menu = (u: TeamUser, self: boolean, locked: boolean, ref: { id: string; label: string; email: string }) => (
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={t("actions.menu", { name: u.name })} />}>
            <VerticalDotsIcon />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64 p-2">
            <DropdownMenuItem onClick={() => setEditing(u)}>{t("actions.editAccess")}</DropdownMenuItem>
            <DropdownMenuSeparator />
            {locked && <p className="px-3 py-1.5 text-xs text-gray-500 dark:text-gray-400">{self ? t("actions.isSelf") : t("actions.cannotAdminister")}</p>}
            <DropdownMenuItem disabled={locked} onClick={() => setMake({ path: `/api/team/users/${u.id}/reset-password`, email: u.email, kind: "reset" })}>{t("actions.resetPassword")}</DropdownMenuItem>
            <DropdownMenuItem disabled={locked || !u.totpEnabled} onClick={() => setConfirm({ kind: "resetMfa", ...ref })}>{t("actions.resetMfa")}</DropdownMenuItem>
            {u.disabled ? (
              <DropdownMenuItem disabled={locked} onClick={() => void act(`/api/team/users/${u.id}/enable`)}>{t("actions.enable")}</DropdownMenuItem>
            ) : (
              <DropdownMenuItem disabled={locked} onClick={() => setConfirm({ kind: "disable", ...ref })}>{t("actions.disable")}</DropdownMenuItem>
            )}
            <DropdownMenuItem variant="destructive" disabled={locked} onClick={() => setConfirm({ kind: "delete", ...ref })}>{t("actions.delete")}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
  );

  const filter = showFilter && (
    <Select value={tenant} onValueChange={(v) => {
      const next = new URLSearchParams(params);
      if (!v || v === ALL) next.delete("tenant");
      else next.set("tenant", String(v));
      setParams(next, { replace: true });
    }} items={filterItems}>
      <SelectTrigger size="sm" className="w-full sm:w-52" aria-label={t("filter.label")}><SelectValue /></SelectTrigger>
      <SelectContent>{filterItems.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}</SelectContent>
    </Select>
  );

  return (
    <div className="@container min-w-0">
      <div className="mb-3 flex flex-wrap items-center justify-end gap-2">
        {filter}
        <Button ref={inviteRef} onClick={() => setInviting(true)}><PlusIcon />{t("invite.button")}</Button>
      </div>
      {error && <Alert variant="destructive" className="mb-3" aria-live="polite"><AlertDescription>{error}</AlertDescription></Alert>}

      {shownUsers && shownInvites && (
        <ul className="mb-3 flex flex-wrap gap-2 text-xs text-gray-600 dark:text-gray-300" aria-label={t("summary.label")}>
          {[
            t("summary.users", { count: shownUsers.length }),
            t("summary.mfa", { count: shownUsers.filter((u) => u.totpEnabled).length }),
            t("summary.disabled", { count: shownUsers.filter((u) => u.disabled).length }),
            t("summary.pending", { count: shownInvites.length }),
          ].map((x) => <li key={x} className="rounded-full border border-gray-200 bg-white px-2.5 py-1 dark:border-gray-800 dark:bg-white/3">{x}</li>)}
        </ul>
      )}

      <div className={box}>
        {users.error ? <ErrorState error={users.error} onRetry={users.reload} /> : !shownUsers ? <TableSkeleton /> : shownUsers.length === 0 ? <EmptyState>{t("emptyUsers")}</EmptyState> : (
          <>
          <div className="relative hidden max-w-full overflow-x-auto @3xl:block">
            <Table>
              <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                <TableRow>
                  <TableCell isHeader className={head}>{t("columns.user")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.access")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.mfa")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.status")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.lastSignIn")}</TableCell>
                  <TableCell isHeader className={head}><span className="sr-only">{t("columns.actions")}</span></TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {shownUsers.map((u) => {
                  const self = u.id === me?.id;
                  const locked = !u.canAdminister;
                  const ref = { id: u.id, label: u.name, email: u.email };
                  return (
                    <TableRow key={u.id}>
                      <TableCell className="py-1.5 pe-4">
                        <p className="text-sm font-medium text-gray-800 dark:text-white/90">{u.name}{self && <span className="ms-2 text-xs font-normal text-gray-500">({t("you")})</span>}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">{u.email}</p>
                      </TableCell>
                      <TableCell className="py-1.5 pe-4 text-gray-500 dark:text-gray-400"><AccessChips role={u.role} tenants={u.tenants} hidden={u.hiddenTenants} /></TableCell>
                      <TableCell className="py-1.5 pe-4"><Badge size="sm" color={u.totpEnabled ? "success" : "gray"} className="[text-shadow:none]">{u.totpEnabled ? t("mfa.on") : t("mfa.off")}</Badge></TableCell>
                      <TableCell className="py-1.5 pe-4"><Badge size="sm" color={u.disabled ? "error" : "success"} className="[text-shadow:none]">{u.disabled ? t("status.disabled") : t("status.active")}</Badge></TableCell>
                      <TableCell className={`${cell} whitespace-nowrap`}>{formatDateTime(u.lastLoginAt, locale) ?? t("never")}</TableCell>
                      <TableCell className="py-1.5 text-end">
                        {menu(u, self, locked, ref)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <ul className="divide-y divide-gray-100 @3xl:hidden dark:divide-gray-800">
            {shownUsers.map((u) => {
              const self = u.id === me?.id;
              const ref = { id: u.id, label: u.name, email: u.email };
              return (
                <li key={u.id} className="flex items-start justify-between gap-2 py-2.5 first:pt-0 last:pb-0">
                  <div className="min-w-0 space-y-1">
                    <p className="text-sm font-medium text-gray-800 dark:text-white/90">{u.name}{self && <span className="ms-2 text-xs font-normal text-gray-500">({t("you")})</span>}</p>
                    <p className="truncate text-xs text-gray-500 dark:text-gray-400">{u.email}</p>
                    <AccessChips role={u.role} tenants={u.tenants} hidden={u.hiddenTenants} />
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge size="sm" color={u.disabled ? "error" : "success"} className="[text-shadow:none]">{u.disabled ? t("status.disabled") : t("status.active")}</Badge>
                      <Badge size="sm" color={u.totpEnabled ? "success" : "gray"} className="[text-shadow:none]">{t("columns.mfa")}: {u.totpEnabled ? t("mfa.on") : t("mfa.off")}</Badge>
                    </div>
                  </div>
                  {menu(u, self, !u.canAdminister, ref)}
                </li>
              );
            })}
          </ul>
          </>
        )}
      </div>

      {users.error ? null : invites.error ? (
        <div className={`mt-4 ${box}`}><ErrorState error={invites.error} onRetry={invites.reload} /></div>
      ) : shownInvites?.length === 0 ? (
        <p className="mt-3 text-sm text-gray-500 dark:text-gray-400">{t("emptyInvites")}</p>
      ) : (
        <>
        <h2 className="mt-4 mb-2 text-base font-semibold text-gray-800 dark:text-white/90">{t("invites.title")}{shownInvites?.length ? ` (${shownInvites.length})` : ""}</h2>
        <div className={box}>
        {!shownInvites ? <TableSkeleton rows={3} /> : (
          <div className="relative max-w-full overflow-x-auto">
            <Table>
              <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                <TableRow>
                  <TableCell isHeader className={head}>{t("columns.email")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.access")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.expires")}</TableCell>
                  <TableCell isHeader className={head}><span className="sr-only">{t("columns.actions")}</span></TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {shownInvites.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className={`${cell} font-medium text-gray-800 dark:text-white/90`}>
                      {i.email}
                      {i.kind === "reset" && <Badge size="sm" color="warning" className="ms-2 [text-shadow:none]">{t("invites.reset")}</Badge>}
                    </TableCell>
                    <TableCell className="py-1.5 pe-4 text-gray-500 dark:text-gray-400"><AccessChips role={i.role} tenants={i.tenants} /></TableCell>
                    <TableCell className={`${cell} whitespace-nowrap`}>{formatDateTime(i.expiresAt, locale)}</TableCell>
                    <TableCell className="py-1.5 text-end whitespace-nowrap">
                      <Button variant="ghost" size="xs" onClick={() => setMake({ path: `/api/team/invites/${i.id}/regenerate`, email: i.email, kind: "regenerate" })}>{t("actions.newLink")}</Button>
                      <Button variant="ghost" size="xs" onClick={() => setConfirm({ kind: "revoke", id: i.id, label: i.email, email: i.email })}>{t("actions.revoke")}</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
        </>
      )}

      <InviteDialog
        open={inviting}
        sender={sender}
        finalFocus={inviteRef}
        onClose={() => setInviting(false)}
        onCreated={(l, email, emailed) => {
          setInviting(false);
          setLink({ link: l, email, emailed, title: t("invite.createdTitle"), body: t("invite.createdBody", { email }) });
          refresh();
        }}
      />
      {editing && <EditAccessDialog user={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />}
      <CreateLinkDialog
        open={make !== null}
        sender={sender}
        title={make ? t(`mail.${make.kind}Title`) : ""}
        body={make ? t(`mail.${make.kind}Body`, { email: make.email }) : ""}
        onCreate={create}
        onClose={() => setMake(null)}
      />
      <LinkDialog link={link?.link ?? null} email={link?.email} emailed={link?.emailed} title={link?.title ?? ""} body={link?.body ?? ""} onClose={() => setLink(null)} />
      <ConfirmDialog
        open={c !== null}
        destructive
        title={c ? t(`confirm.${c.kind}Title`, { name: c.label, email: c.email }) : ""}
        body={c ? t(`confirm.${c.kind}Body`, { name: c.label, email: c.email }) : ""}
        action={c ? t(`confirm.${c.kind}`) : tc("confirm")}
        onConfirm={runConfirm}
        onClose={() => setConfirm(null)}
      />
    </div>
  );
}

export default function TeamPage() {
  const t = useTranslations("team");
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} />
      <TeamPanel />
    </>
  );
}
