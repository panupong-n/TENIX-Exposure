import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useTranslations } from "@/i18n";
import { api, ApiError, type TenantRole } from "@/lib/api";
import { useState } from "react";
import { Link } from "react-router";

export interface Membership { id: string; name: string; role: TenantRole }
export interface TeamUser {
  id: string; email: string; name: string; role: "super_admin" | "member"; disabled: boolean; totpEnabled: boolean;
  lastLoginAt: number | null; createdAt: number; tenants: Membership[]; hiddenTenants: number; canAdminister: boolean;
}
type Picked = Record<string, TenantRole>;
const toMemberships = (v: Picked) => Object.entries(v).map(([tenantId, role]) => ({ tenantId, role }));

/** The tenants the viewer may put users into: every tenant for a super admin, else the ones they administer. */
function useManageable() {
  const { user } = useAuth();
  const { orgs } = useOrg();
  return user?.soc ? orgs : orgs.filter((o) => o.role === "admin");
}

export type Emailed = "sent" | "no_sender" | "failed" | "not_asked";
/** "yes" a sender exists, "no" none, "unknown" the viewer may not read /api/mail (organization admins): the server then answers no_sender if there is none. */
export type SenderState = "loading" | "yes" | "no" | "unknown";

/** "Also send the link by email": ticked by default when a sender exists, disabled with a link to the e-mail setting when none exists. */
export function SendEmailOption({ sender, value, onChange }: { sender: SenderState; value: boolean | null; onChange: (v: boolean) => void }) {
  const t = useTranslations("team.mail");
  const off = sender === "no" || sender === "loading";
  const checked = !off && (value ?? sender === "yes");
  return (
    <div className="space-y-1">
      <label className="flex items-center gap-2 text-sm leading-6 text-gray-800">
        <Checkbox checked={checked} disabled={off} onCheckedChange={(c) => onChange(c === true)} />
        <span className={off ? "text-gray-500" : undefined}>{t("send")}</span>
      </label>
      {sender === "no" && (
        <p className="text-xs leading-5 text-gray-500">
          <Link to="/settings?setting=email" className="text-brand-600 hover:underline">{t("noSender")}</Link>
        </p>
      )}
    </div>
  );
}

/** Shows a one-time link with copy and "open in email" actions, and whether the server e-mailed it. The server cannot show the link again. */
export function LinkDialog({ link, email, emailed, title, body, onClose }: { link: string | null; email?: string; emailed?: Emailed; title: string; body: string; onClose: () => void }) {
  const t = useTranslations("team.invite");
  const tm = useTranslations("team.mail");
  const tc = useTranslations("common");
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(link ?? "");
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* the field below is selectable as a fallback */
    }
  };
  const mail = email && link ? `mailto:${encodeURIComponent(email)}?subject=${encodeURIComponent(t("mailSubject"))}&body=${encodeURIComponent(t("mailBody", { link }))}` : null;
  return (
    <Dialog open={link !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{body}</DialogDescription>
        </DialogHeader>
        {emailed && emailed !== "not_asked" && (
          <Alert variant={emailed === "sent" ? "success" : "warning"} aria-live="polite">
            <AlertDescription>{emailed === "sent" ? tm("sent", { email: email ?? "" }) : emailed === "no_sender" ? tm("noSenderResult") : tm("failed")}</AlertDescription>
          </Alert>
        )}
        <Input readOnly value={link ?? ""} onFocus={(e) => e.currentTarget.select()} aria-label={t("copy")} className="font-mono text-xs" />
        <DialogFooter>
          {mail && <Button variant="outline" render={<a href={mail} />}>{t("mail")}</Button>}
          <Button variant="outline" onClick={copy}>{copied ? tc("copied") : t("copy")}</Button>
          <Button onClick={onClose}>{tc("done")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Asks whether to e-mail the new link too (password reset, new invite link), then runs `onCreate`. */
export function CreateLinkDialog({ open, title, body, sender, onCreate, onClose }: { open: boolean; title: string; body: string; sender: SenderState; onCreate: (sendEmail: boolean) => void | Promise<void>; onClose: () => void }) {
  const tm = useTranslations("team.mail");
  const tc = useTranslations("common");
  const [value, setValue] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const send = sender !== "no" && sender !== "loading" && (value ?? sender === "yes");
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{body}</DialogDescription>
        </DialogHeader>
        <SendEmailOption sender={sender} value={value} onChange={setValue} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{tc("cancel")}</Button>
          <Button disabled={busy} onClick={async () => { setBusy(true); await onCreate(send); setBusy(false); setValue(null); }}>{tm("create")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Checklist of tenants with a role Select next to each ticked one. */
function AccessPicker({ tenants, value, onChange }: { tenants: { id: string; name: string }[]; value: Picked; onChange: (v: Picked) => void }) {
  const t = useTranslations("team.invite");
  const tRoles = useTranslations("roles");
  const roleItems = (["admin", "operator"] as const).map((r) => ({ value: r, label: tRoles(r) }));
  if (tenants.length === 0) return <p className="text-sm text-gray-500 dark:text-gray-400">{t("noTenants")}</p>;
  return (
    <ul className="max-h-56 divide-y divide-gray-100 overflow-y-auto rounded-lg border border-gray-200 dark:divide-gray-800 dark:border-gray-800">
      {tenants.map((x) => {
        const role = value[x.id];
        return (
          <li key={x.id} className="flex items-center justify-between gap-3 px-3 py-1.5">
            <label className="flex min-w-0 items-center gap-2 text-sm text-gray-800 dark:text-white/90">
              <Checkbox checked={role !== undefined} onCheckedChange={(c) => {
                const next = { ...value };
                if (c) next[x.id] = "operator";
                else delete next[x.id];
                onChange(next);
              }} />
              <span className="truncate">{x.name}</span>
            </label>
            {role && (
              <Select value={role} onValueChange={(v) => v && onChange({ ...value, [x.id]: v as TenantRole })} items={roleItems}>
                <SelectTrigger size="sm" className="w-32" aria-label={t("roleIn", { name: x.name })}><SelectValue /></SelectTrigger>
                <SelectContent>{roleItems.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}</SelectContent>
              </Select>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function TypeSelect({ value, onChange, disabled }: { value: "member" | "super_admin"; onChange: (v: "member" | "super_admin") => void; disabled?: boolean }) {
  const t = useTranslations("team.invite");
  const items = (["member", "super_admin"] as const).map((r) => ({ value: r, label: t(`types.${r}`) }));
  return (
    <Select value={value} onValueChange={(v) => v && onChange(v as "member" | "super_admin")} items={items} disabled={disabled}>
      <SelectTrigger aria-label={t("userType")}><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}</SelectContent>
    </Select>
  );
}

export function InviteDialog({ open, sender, onClose, onCreated, finalFocus }: { open: boolean; sender: SenderState; onClose: () => void; onCreated: (link: string, email: string, emailed: Emailed) => void; finalFocus?: React.RefObject<HTMLElement | null> }) {
  const t = useTranslations("team.invite");
  const generic = useTranslations("team.errors");
  const tTeam = useTranslations("team");
  const { user } = useAuth();
  const tenants = useManageable();
  const [email, setEmail] = useState("");
  const [type, setType] = useState<"member" | "super_admin">("member");
  const [picked, setPicked] = useState<Picked>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mailPref, setMailPref] = useState<boolean | null>(null);

  const member = type === "member";
  const sendEmail = sender !== "no" && sender !== "loading" && (mailPref ?? sender === "yes");
  const ready = /\S+@\S+\.\S+/.test(email) && (!member || Object.keys(picked).length > 0);

  const submit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ link: string; emailed?: Emailed }>("/api/team/invites", { email: email.trim(), role: type, memberships: member ? toMemberships(picked) : [], ...(sendEmail ? { sendEmail: true } : {}) });
      onCreated(r.link, email.trim(), r.emailed ?? "not_asked");
      setEmail("");
      setPicked({});
      setType("member");
    } catch (err) {
      const code = err instanceof ApiError ? err.code : null;
      setError(code === "exists" ? tTeam("errors.exists") : code === "forbidden" ? tTeam("errors.forbidden") : code === "no_tenant" ? t("errors.no_tenant") : generic("unknown"));
    }
    setBusy(false);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent finalFocus={finalFocus}>
        <form onSubmit={submit} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{t("title")}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          {error && <Alert variant="destructive" aria-live="polite"><AlertDescription>{error}</AlertDescription></Alert>}
          <Field>
            <FieldLabel className="mb-1.5 block">{t("email")}</FieldLabel>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" autoFocus required />
          </Field>
          {user?.soc && (
            <Field>
              <FieldLabel className="mb-1.5 block">{t("userType")}</FieldLabel>
              <TypeSelect value={type} onChange={setType} />
              {!member && <FieldDescription>{t("superAdminNote")}</FieldDescription>}
            </Field>
          )}
          {member && (
            <div>
              <p className="mb-1 text-sm font-medium text-gray-700 dark:text-gray-300">{t("tenants")}</p>
              <p className="mb-1.5 text-xs text-gray-500 dark:text-gray-400">{t("tenantsHelp")}</p>
              <AccessPicker tenants={tenants} value={picked} onChange={setPicked} />
            </div>
          )}
          <SendEmailOption sender={sender} value={mailPref} onChange={setMailPref} />
          <DialogFooter>
            <Button type="submit" disabled={!ready || busy}>{t("create")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Mounted only while open (the parent passes the user), so its state starts from the user's current access. */
export function EditAccessDialog({ user: target, onClose, onSaved }: { user: TeamUser; onClose: () => void; onSaved: () => void }) {
  const t = useTranslations("team.edit");
  const ti = useTranslations("team.invite");
  const tc = useTranslations("common");
  const generic = useTranslations("team.errors");
  const { user: me } = useAuth();
  const tenants = useManageable();
  const ids = new Set(tenants.map((x) => x.id));
  const [type, setType] = useState(target.role);
  const [picked, setPicked] = useState<Picked>(() => Object.fromEntries(target.tenants.filter((x) => ids.has(x.id)).map((x) => [x.id, x.role])));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const canSetType = Boolean(me?.soc) && target.id !== me?.id;
  const member = type === "member";
  const empty = Object.keys(picked).length === 0;
  const blocked = Boolean(me?.soc) && member && empty; // a super admin must leave a member with a tenant

  const submit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.put(`/api/team/users/${target.id}/access`, { memberships: member ? toMemberships(picked) : [], ...(canSetType ? { role: type } : {}) });
      onSaved();
    } catch (err) {
      const code = err instanceof ApiError ? err.code : null;
      setError(code === "no_tenant" || code === "last_super_admin" ? t(`errors.${code}`) : generic("unknown"));
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{t("title", { name: target.name })}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          {error && <Alert variant="destructive" aria-live="polite"><AlertDescription>{error}</AlertDescription></Alert>}
          {me?.soc && (
            <Field>
              <FieldLabel className="mb-1.5 block">{ti("userType")}</FieldLabel>
              <TypeSelect value={type} onChange={setType} disabled={!canSetType} />
              <FieldDescription>{canSetType ? t("typeWarning") : t("ownTypeLocked")}</FieldDescription>
            </Field>
          )}
          {member ? (
            <div>
              <p className="mb-1 text-sm font-medium text-gray-700 dark:text-gray-300">{ti("tenants")}</p>
              <p className="mb-1.5 text-xs text-gray-500 dark:text-gray-400">{ti("tenantsHelp")}</p>
              <AccessPicker tenants={tenants} value={picked} onChange={setPicked} />
              {empty && !me?.soc && <p className="mt-1.5 text-xs text-amber-600 dark:text-amber-400">{t("removeAll")}</p>}
            </div>
          ) : <p className="text-sm text-gray-500 dark:text-gray-400">{ti("superAdminNote")}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{tc("cancel")}</Button>
            <Button type="submit" disabled={blocked || busy}>{t("save")}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ConfirmDialog({ open, title, body, action, destructive, onConfirm, onClose }: { open: boolean; title: string; body: string; action: string; destructive?: boolean; onConfirm: () => void | Promise<void>; onClose: () => void }) {
  const tc = useTranslations("common");
  const [busy, setBusy] = useState(false);
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{body}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{tc("cancel")}</Button>
          <Button
            variant={destructive ? "destructive" : "default"}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              await onConfirm();
              setBusy(false);
            }}
          >
            {action}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
