import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { formatAgo } from "@/utils/format";
import { useEffect } from "react";

export type SettingKey = "feeds" | "line" | "email" | "tenants" | "team" | "audit" | "system";
export interface Chip { color: "success" | "warning" | "error" | "info" | "gray"; text: string; title?: string }
export type CardKey = SettingKey;
/** null = still loading */
export type Chips = Record<CardKey, Chip | null>;

// The parts of each endpoint's answer that the chips read (see server/src/{falcon,feeds,line,mail,team}.ts).
interface FeedsStatus { config: { enabled: boolean; cveMinutes: number }; cveList: { lastOkAt: number | null; error: string | null }; kev: { error: string | null } }
interface LineView { configured: boolean; forward: { ok: boolean } | null }
interface MailView { senders: unknown[]; recipients: { enabled: boolean }[]; log: { state: string }[] }
interface TenantsView { tenants: { state: "complete" | "partial" | "failed" | "not_synced" | "no_cids" | "no_connection"; falcon?: { connections: number; unconnected: number } }[] }
interface UsersView { users: { totpEnabled: boolean; disabled: boolean }[] }
interface InvitesView { invites: unknown[] }
interface SystemView { falcon: { running: boolean; lastRunAt: number | null; organizations: { state: "complete" | "partial" | "failed" }[] } }
interface AuditView { entries: { ts: number; result: "ok" | "allowed" | "denied" | "fail" }[] }

const DAY = 24 * 3600_000;
const nowMs = () => Date.now();

/** One GET per card, all in parallel. Each failure only turns its own chip gray. `tick` refetches them all (after a drawer closes). */
export function useSettingChips(tick: number): Chips {
  const t = useTranslations("settings.chip");
  const locale = useLocale();
  const ago = (ts: number | null | undefined) => formatAgo(ts, locale) ?? "";
  const feeds = useApi<FeedsStatus>("/api/feeds/status");
  const line = useApi<LineView>("/api/integrations/line");
  const mail = useApi<MailView>("/api/mail");
  const tenants = useApi<TenantsView>("/api/tenants");
  const users = useApi<UsersView>("/api/team/users");
  const invites = useApi<InvitesView>("/api/team/invites");
  const audit = useApi<AuditView>("/api/audit?limit=50");
  const system = useApi<SystemView>("/api/system/status");

  const reloads = [feeds.reload, line.reload, mail.reload, tenants.reload, users.reload, invites.reload, audit.reload, system.reload];
  useEffect(() => {
    if (tick > 0) for (const r of reloads) r();
  }, [tick]);
  const sysRunning = system.data?.falcon.running ?? false;
  useEffect(() => {
    if (!sysRunning) return;
    const id = window.setInterval(system.reload, 5000);
    return () => window.clearInterval(id);
  }, [sysRunning, system.reload]);

  const unavailable: Chip = { color: "gray", text: t("unavailable") };
  // first failed request wins; null while any is still loading
  const wrap = (rs: { data: unknown; error: unknown }[], make: () => Chip): Chip | null =>
    rs.some((r) => r.error) ? unavailable : rs.some((r) => !r.data) ? null : make();

  return {
    feeds: wrap([feeds], () => {
      const d = feeds.data!;
      const last = d.cveList.lastOkAt;
      if (!d.config.enabled) return { color: "gray", text: t("feedOff") };
      if (d.cveList.error || d.kev.error) return { color: "error", text: t("feedError") };
      if (!last) return { color: "warning", text: t("feedNever") };
      if (nowMs() - last > 3 * d.config.cveMinutes * 60_000) return { color: "warning", text: t("feedStale", { ago: ago(last) }) };
      return { color: "success", text: t("feedFresh", { ago: ago(last) }) };
    }),
    line: wrap([line], () => {
      const d = line.data!;
      if (!d.configured) return { color: "warning", text: t("setup") };
      if (d.forward && !d.forward.ok) return { color: "warning", text: t("lineForward") };
      return { color: "success", text: t("lineOk") };
    }),
    email: wrap([mail], () => {
      const d = mail.data!;
      const receiving = d.recipients.filter((r) => r.enabled).length;
      if (d.senders.length === 0) return { color: "warning", text: t("setup") };
      if (receiving === 0) return { color: "warning", text: t("mailNoRecipient") };
      if (d.log[0]?.state === "failed") return { color: "error", text: t("mailFailed") };
      return { color: "success", text: t("mailOk", { count: receiving }) };
    }),
    tenants: wrap([tenants], () => {
      const list = tenants.data!.tenants;
      const failed = list.filter((x) => x.state === "failed").length;
      const unlinked = list.filter((x) => x.state === "no_cids" || x.state === "no_connection").length; // no CrowdStrike login of its own
      const check = list.filter((x) => x.state === "partial" || x.state === "not_synced").length;
      if (list.length === 0) return { color: "warning", text: t("tenantsNone") };
      if (failed) return { color: "error", text: t("tenantsFailed", { count: failed }) };
      if (unlinked) return { color: "warning", text: t("tenantsUnlinked", { count: unlinked }) };
      if (check) return { color: "warning", text: t("tenantsCheck", { count: check }) };
      return { color: "success", text: t("tenantsOk", { count: list.length }) };
    }),
    team: wrap([users, invites], () => {
      const list = users.data!.users;
      const noMfa = list.filter((u) => !u.totpEnabled && !u.disabled).length;
      const pending = invites.data!.invites.length;
      if (noMfa) return { color: "warning", text: t("teamNoMfa", { count: noMfa }) };
      if (pending) return { color: "info", text: t("teamInvites", { count: pending }) };
      return { color: "gray", text: t("teamUsers", { count: list.length }) };
    }),
    system: wrap([system], () => {
      const f = system.data!.falcon;
      const failed = f.organizations.filter((o) => o.state === "failed").length;
      const partial = f.organizations.filter((o) => o.state === "partial").length;
      if (f.running) return { color: "info", text: t("syncing") };
      if (f.organizations.length === 0 || !f.lastRunAt) return { color: "gray", text: t("neverSynced") };
      if (failed) return { color: "error", text: t("sysFailed", { count: failed }) };
      if (partial) return { color: "warning", text: t("sysPartial", { count: partial }) };
      return { color: "success", text: t("syncedAgo", { ago: ago(f.lastRunAt) }) };
    }),
    audit: wrap([audit], () => {
      const list = audit.data!.entries;
      const bad = list.filter((e) => (e.result === "denied" || e.result === "fail") && nowMs() - e.ts < DAY).length;
      if (list.length === 0) return { color: "gray", text: t("auditNone") };
      if (bad) return { color: "warning", text: t("auditDenied", { count: bad }) };
      return { color: "gray", text: t("auditLast", { ago: ago(list[0]!.ts) }) };
    }),
  };
}

/** The one status chip of a card. Loading shows a skeleton the size of a chip. */
export function StatusChip({ chip }: { chip: Chip | null }) {
  if (!chip) return <Skeleton className="mt-0.5 h-5.5 w-24 rounded-lg" aria-hidden="true" />;
  return (
    <Badge size="sm" color={chip.color} className="mt-0.5 max-w-full [text-shadow:none]" title={chip.title}>
      <span className="truncate leading-5">{chip.text}</span>
    </Badge>
  );
}
