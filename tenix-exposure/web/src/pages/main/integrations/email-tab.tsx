import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { FormSkeleton, TableSkeleton } from "@/components/shared/skeletons";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ScrollFade } from "@/components/shared/scroll-fade";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { api, ApiError } from "@/lib/api";
import { formatDateTime } from "@/utils/format";
import { useState } from "react";

interface Sender { id: string; name: string; host: string; port: number; security: "tls" | "starttls" | "none"; username: string | null; hasPassword: boolean; fromName: string | null; fromEmail: string; isDefault: boolean }
interface Recipient { id: string; email: string; name: string | null; tenantId: string | null; tenantName: string | null; enabled: boolean; events: string[] }
interface MailConfig { events: string[]; senders: Sender[]; recipients: Recipient[]; log: { id: number; ts: number; event: string; recipient: string; state: string; error: string | null }[] }

const card = "rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3";
const head = "py-1.5 pe-4 text-start text-xs font-medium whitespace-nowrap text-gray-500 dark:text-gray-400";
const cell = "py-1.5 pe-3 text-sm text-gray-600 dark:text-gray-300";
const PORTS = { tls: "465", starttls: "587", none: "25" } as const;

/** A delete button that asks twice, so a stray click never removes anything. */
function ConfirmButton({ label, confirm, onConfirm }: { label: string; confirm: string; onConfirm: () => void }) {
  const [armed, setArmed] = useState(false);
  return (
    <Button
      size="xs"
      variant="ghost"
      className={armed ? "text-red-500" : undefined}
      onClick={() => {
        if (!armed) { setArmed(true); window.setTimeout(() => setArmed(false), 3000); } else onConfirm();
      }}
    >
      {armed ? confirm : label}
    </Button>
  );
}

function SenderDialog({ sender, onClose, onSaved }: { sender: Sender | null; onClose: () => void; onSaved: () => void }) {
  const t = useTranslations("integrations.email.sender");
  const tc = useTranslations("common");
  const [f, setF] = useState({
    name: sender?.name ?? "", host: sender?.host ?? "", port: String(sender?.port ?? 587), security: sender?.security ?? "starttls",
    username: sender?.username ?? "", password: "", fromEmail: sender?.fromEmail ?? "", fromName: sender?.fromName ?? "",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const text = (k: "name" | "host" | "port" | "username" | "password" | "fromEmail" | "fromName") => ({
    value: f[k], onChange: (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value }),
  });
  const securityItems = (["starttls", "tls", "none"] as const).map((v) => ({ value: v, label: t(`security.${v}`) }));
  const ready = f.name.trim() && f.host.trim() && f.fromEmail.trim() && Number(f.port) > 0;

  const submit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = { ...f, port: Number(f.port) };
      if (sender) await api.put(`/api/mail/senders/${sender.id}`, body); else await api.post("/api/mail/senders", body);
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError && err.code === "invalid_sender" ? t("invalid") : tc("error"));
    }
    setBusy(false);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{sender ? t("editTitle") : t("addTitle")}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          {error && <Alert variant="destructive" aria-live="polite"><AlertDescription>{error}</AlertDescription></Alert>}
          <Field><FieldLabel className="mb-1 block">{t("name")}</FieldLabel><Input {...text("name")} maxLength={60} autoFocus /></Field>
          <div className="grid grid-cols-[1fr_6rem] gap-3">
            <Field><FieldLabel className="mb-1 block">{t("host")}</FieldLabel><Input {...text("host")} placeholder="smtp.example.com" autoComplete="off" /></Field>
            <Field><FieldLabel className="mb-1 block">{t("port")}</FieldLabel><Input {...text("port")} inputMode="numeric" /></Field>
          </div>
          <Field>
            <FieldLabel className="mb-1 block">{t("securityLabel")}</FieldLabel>
            <Select
              value={f.security}
              items={securityItems}
              onValueChange={(v) => {
                const s = String(v) as Sender["security"];
                setF({ ...f, security: s, port: Object.values(PORTS).includes(f.port as never) ? PORTS[s] : f.port });
              }}
            >
              <SelectTrigger aria-label={t("securityLabel")}><SelectValue /></SelectTrigger>
              <SelectContent>{securityItems.map((s) => <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>)}</SelectContent>
            </Select>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field><FieldLabel className="mb-1 block">{t("username")}</FieldLabel><Input {...text("username")} autoComplete="off" /></Field>
            <Field>
              <FieldLabel className="mb-1 block">{t("password")}</FieldLabel>
              <Input {...text("password")} type="password" autoComplete="new-password" placeholder={sender?.hasPassword ? t("keepPassword") : ""} />
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field><FieldLabel className="mb-1 block">{t("fromEmail")}</FieldLabel><Input {...text("fromEmail")} type="email" placeholder="alerts@example.com" /></Field>
            <Field><FieldLabel className="mb-1 block">{t("fromName")}</FieldLabel><Input {...text("fromName")} maxLength={80} /></Field>
          </div>
          <DialogFooter><Button type="submit" disabled={!ready || busy}>{tc("save")}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function TestDialog({ sender, onClose }: { sender: Sender; onClose: () => void }) {
  const t = useTranslations("integrations.email.test");
  const { user } = useAuth();
  const [to, setTo] = useState(user?.email ?? "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; error?: string } | null>(null);
  const send = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setResult(null);
    try { setResult(await api.post(`/api/mail/senders/${sender.id}/test`, { to })); } catch { setResult({ ok: false, error: t("failed") }); }
    setBusy(false);
  };
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <form onSubmit={send} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{t("title", { name: sender.name })}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          <Field><FieldLabel className="mb-1 block">{t("to")}</FieldLabel><Input type="email" value={to} onChange={(e) => setTo(e.target.value)} autoFocus /></Field>
          {result && (
            <Alert variant={result.ok ? "success" : "destructive"} aria-live="polite">
              <AlertDescription>{result.ok ? t("sent") : `${t("failed")} ${result.error ?? ""}`}</AlertDescription>
            </Alert>
          )}
          <DialogFooter><Button type="submit" disabled={busy || !/\S+@\S+\.\S+/.test(to)}>{t("send")}</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function EmailTab() {
  const t = useTranslations("integrations.email");
  const tc = useTranslations("common");
  const locale = useLocale();
  const { orgs } = useOrg();
  const { data, error, reload } = useApi<MailConfig>("/api/mail");
  const [editing, setEditing] = useState<Sender | "new" | null>(null);
  const [testing, setTesting] = useState<Sender | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [rEmail, setREmail] = useState("");
  const [rOrg, setROrg] = useState("all");

  const act = async (fn: () => Promise<unknown>) => {
    setNotice(null);
    try { await fn(); reload(); } catch (e) { setNotice(e instanceof ApiError && e.code === "exists" ? t("recipients.exists") : tc("error")); }
  };
  const addRecipient = (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    void act(async () => { await api.post("/api/mail/recipients", { email: rEmail.trim(), tenantId: rOrg === "all" ? null : rOrg, events: [] }); setREmail(""); });
  };
  const toggle = (r: Recipient, ev: string) =>
    act(() => api.put(`/api/mail/recipients/${r.id}`, { events: r.events.includes(ev) ? r.events.filter((x) => x !== ev) : [...r.events, ev] }));

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <div className="space-y-3"><FormSkeleton fields={2} /><TableSkeleton rows={3} /></div>;
  const orgItems = [{ value: "all", label: t("recipients.allOrgs") }, ...orgs.map((o) => ({ value: o.id, label: o.name }))];

  return (
    <div className="space-y-3">
      {notice && <Alert variant="destructive" aria-live="polite"><AlertDescription>{notice}</AlertDescription></Alert>}

      <section className={card}>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-semibold text-gray-800 dark:text-white/90">{t("senders.title")}</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">{t("senders.description")}</p>
          </div>
          <Button size="sm" onClick={() => setEditing("new")}>{t("senders.add")}</Button>
        </div>
        {data.senders.length === 0 ? (
          <EmptyState>{t("senders.empty")}</EmptyState>
        ) : (
          <ScrollFade>
            <Table>
              <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                <TableRow>
                  <TableCell isHeader className={head}>{t("senders.name")}</TableCell>
                  <TableCell isHeader className={head}>{t("senders.server")}</TableCell>
                  <TableCell isHeader className={head}>{t("senders.from")}</TableCell>
                  <TableCell isHeader className={`${head} text-end!`}>{t("actions")}</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {data.senders.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className={`${cell} font-medium text-gray-800 dark:text-white/90`}>
                      {s.name} {s.isDefault && <Badge size="sm" color="success" className="ms-1 [text-shadow:none]">{t("senders.default")}</Badge>}
                    </TableCell>
                    <TableCell className={`${cell} tabular-nums`}>{s.host}:{s.port} · {t(`sender.security.${s.security}`)}</TableCell>
                    <TableCell className={cell}>{s.fromName ? `${s.fromName} <${s.fromEmail}>` : s.fromEmail}</TableCell>
                    <TableCell className="py-1 text-end whitespace-nowrap">
                      <Button size="xs" variant="ghost" onClick={() => setTesting(s)}>{t("senders.test")}</Button>
                      <Button size="xs" variant="ghost" onClick={() => setEditing(s)}>{tc("edit")}</Button>
                      {!s.isDefault && <Button size="xs" variant="ghost" onClick={() => void act(() => api.post(`/api/mail/senders/${s.id}/default`))}>{t("senders.makeDefault")}</Button>}
                      <ConfirmButton label={tc("delete")} confirm={tc("confirmDelete")} onConfirm={() => void act(() => api.del(`/api/mail/senders/${s.id}`))} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollFade>
        )}
      </section>

      <section className={card}>
        <div className="mb-2 flex flex-wrap items-end justify-between gap-2">
          <div>
            <h3 className="text-base font-semibold text-gray-800 dark:text-white/90">{t("recipients.title")}</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">{t("recipients.description")}</p>
          </div>
          <form onSubmit={addRecipient} className="flex flex-wrap items-center gap-2">
            <Input type="email" value={rEmail} onChange={(e) => setREmail(e.target.value)} placeholder={t("recipients.emailPlaceholder")} aria-label={t("recipients.email")} className="w-56" />
            <Select value={rOrg} items={orgItems} onValueChange={(v) => v && setROrg(String(v))}>
              <SelectTrigger aria-label={t("recipients.organization")} className="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>{orgItems.map((o) => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}</SelectContent>
            </Select>
            <Button type="submit" size="sm" disabled={!/\S+@\S+\.\S+/.test(rEmail)}>{t("recipients.add")}</Button>
          </form>
        </div>
        {data.recipients.length === 0 ? (
          <EmptyState>{t("recipients.empty")}</EmptyState>
        ) : (
          <ScrollFade>
            <Table>
              <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                <TableRow>
                  <TableCell isHeader className={head}>{t("recipients.email")}</TableCell>
                  <TableCell isHeader className={head}>{t("recipients.organization")}</TableCell>
                  {data.events.map((ev) => <TableCell key={ev} isHeader className={`${head} text-center!`}>{t(`events.${ev}`)}</TableCell>)}
                  <TableCell isHeader className={`${head} text-center!`}>{t("recipients.active")}</TableCell>
                  <TableCell isHeader className={`${head} text-end!`}><span className="sr-only">{t("actions")}</span></TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {data.recipients.map((r) => (
                  <TableRow key={r.id} className={r.enabled ? undefined : "opacity-60"}>
                    <TableCell className={`${cell} font-medium text-gray-800 dark:text-white/90`}>{r.email}</TableCell>
                    <TableCell className={cell}>{r.tenantName ?? t("recipients.allOrgs")}</TableCell>
                    {data.events.map((ev) => (
                      <TableCell key={ev} className="py-1.5 text-center">
                        <div className="flex justify-center"><Checkbox checked={r.events.includes(ev)} onCheckedChange={() => void toggle(r, ev)} aria-label={`${r.email}: ${t(`events.${ev}`)}`} /></div>
                      </TableCell>
                    ))}
                    <TableCell className="py-1.5 text-center">
                      <div className="flex justify-center"><Switch size="sm" checked={r.enabled} onCheckedChange={(v) => void act(() => api.put(`/api/mail/recipients/${r.id}`, { enabled: v }))} aria-label={`${r.email}: ${t("recipients.active")}`} /></div>
                    </TableCell>
                    <TableCell className="py-1 text-end">
                      <ConfirmButton label={tc("delete")} confirm={tc("confirmDelete")} onConfirm={() => void act(() => api.del(`/api/mail/recipients/${r.id}`))} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollFade>
        )}
        <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">{t("recipients.scopeHelp")}</p>
      </section>

      {data.log.length > 0 && (
        <section className={card}>
          <h3 className="mb-2 text-base font-semibold text-gray-800 dark:text-white/90">{t("log.title")}</h3>
          <ScrollFade>
            <Table>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {data.log.map((l) => (
                  <TableRow key={l.id}>
                    <TableCell className={`${cell} whitespace-nowrap tabular-nums`}>{formatDateTime(l.ts, locale)}</TableCell>
                    <TableCell className={cell}>{t(`events.${l.event}`)}</TableCell>
                    <TableCell className={cell}>{l.recipient}</TableCell>
                    <TableCell className="py-1.5"><Badge size="sm" color={l.state === "sent" ? "success" : "error"} className="[text-shadow:none]">{t(`log.${l.state}`)}</Badge></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollFade>
        </section>
      )}

      {editing && <SenderDialog key={editing === "new" ? "new" : editing.id} sender={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
      {testing && <TestDialog sender={testing} onClose={() => setTesting(null)} />}
    </div>
  );
}
