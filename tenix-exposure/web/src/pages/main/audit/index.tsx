import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { useDrawers } from "@/components/shared/drawers-context";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { intlLocale, nameOrder } from "@/utils/format";
import { useState } from "react";

interface Entry {
  id: number;
  ts: number;
  actor_email: string | null;
  action: string;
  resource: string | null;
  result: "ok" | "allowed" | "denied" | "fail";
  tenant_name: string | null;
}

const KNOWN = new Set([
  "login", "login_mfa", "logout", "password_change", "password_reset", "password_reset_issue", "mfa_enable", "mfa_disable", "mfa_reset",
  "invite_create", "invite_accept", "invite_revoke", "invite_regenerate", "user_disable", "user_enable", "tenant_create", "tenant_cids",
  "integration_falcon_update", "integration_falcon_test", "integration_falcon_sync", "integration_line_update", "integration_line_test", "route",
  "mail_recipient_create", "mail_recipient_delete", "mail_recipient_update", "mail_sender_create", "mail_sender_delete", "mail_sender_test", "mail_sender_update",
  "integration_feeds_update", "integration_feeds_run", "tenant_delete", "tenant_line_chat", "tenant_rename", "user_access", "user_delete",
]);
const RESULT_COLOR = { ok: "success", allowed: "success", denied: "error", fail: "error" } as const;
const READS = new Set(["summary", "vulnerabilities", "hosts", "host", "graph", "executive"]);
const ALL = "__all";
// a time with seconds: several entries in one minute must not look identical
const seconds = (ts: number, locale: string) => new Intl.DateTimeFormat(intlLocale(locale), { dateStyle: "medium", timeStyle: "medium" }).format(new Date(ts));
const head = "py-1.5 pe-4 text-start text-xs font-medium whitespace-nowrap text-gray-500 dark:text-gray-400";
const cell = "py-1.5 pe-4 text-sm text-gray-500 dark:text-gray-400";

/** The audit list with its filters, without a page heading: used by the Setting Center drawer, the team page and the page below. */
export function AuditPanel() {
  const t = useTranslations("audit");
  const locale = useLocale();
  const { data, error, reload } = useApi<{ entries: Entry[] }>("/api/audit?limit=200");
  const { openCve } = useDrawers();
  const [user, setUser] = useState(ALL);
  const [result, setResult] = useState(ALL);
  const [org, setOrg] = useState(ALL);
  const [views, setViews] = useState(false);

  const all = data?.entries ?? [];
  const uniq = (xs: (string | null)[]) => [...new Set(xs.filter((x): x is string => !!x))].sort(nameOrder.compare);
  const entries = all.filter((e) => (views || !e.action.startsWith("read:")) && (user === ALL || e.actor_email === user) && (result === ALL || e.result === result) && (org === ALL || e.tenant_name === org));
  const pick = (value: string, set: (v: string) => void, allLabel: string, label: string, items: { value: string; label: string }[]) => (
    <Select value={value} items={[{ value: ALL, label: allLabel }, ...items]} onValueChange={(v) => set(String(v))}>
      <SelectTrigger size="sm" className="w-44" aria-label={label}><SelectValue /></SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{allLabel}</SelectItem>
        {items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}
      </SelectContent>
    </Select>
  );
  const same = (xs: string[]) => xs.map((x) => ({ value: x, label: x }));
  // what happened and (when there is one) the thing it happened to; shared by the table and the narrow list
  const describe = (e: Entry) => {
    const key = e.action.replaceAll(".", "_");
    const [kind, ...rest] = e.action.startsWith("read:") ? e.action.slice(5).split(":") : [""];
    const cve = rest.join(":");
    return {
      what: kind ? t(`reads.${READS.has(kind) ? kind : "cve"}`) : KNOWN.has(key) ? t(`actions.${key}`) : <code className="text-xs">{e.action}</code>,
      target: kind === "cve" && cve ? (
        <button type="button" onClick={() => openCve(cve)} className="font-medium text-brand-600 hover:underline dark:text-brand-400">{cve}</button>
      ) : (
        e.resource ?? "–"
      ),
    };
  };

  return (
    <div className="@container min-w-0 rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4 dark:border-gray-800 dark:bg-white/3">
        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !data ? (
          <TableSkeleton />
        ) : data.entries.length === 0 ? (
          <EmptyState>{t("empty")}</EmptyState>
        ) : (
          <>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            {pick(user, setUser, t("filters.allUsers"), t("filters.user"), same(uniq(all.map((e) => e.actor_email))))}
            {pick(result, setResult, t("filters.allResults"), t("filters.result"), (["ok", "allowed", "denied", "fail"] as const).map((r) => ({ value: r, label: t(`results.${r}`) })))}
            {pick(org, setOrg, t("filters.allOrganizations"), t("filters.organization"), same(uniq(all.map((e) => e.tenant_name))))}
            <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
              <Checkbox checked={views} onCheckedChange={(v) => setViews(v === true)} />
              {t("filters.showViews")}
            </label>
            <span className="ms-auto text-xs text-gray-500 tabular-nums dark:text-gray-400">{t("filters.shown", { shown: entries.length, total: all.length })}</span>
          </div>
          {entries.length === 0 ? <EmptyState>{t("filters.noMatch")}</EmptyState> : (
          <>
          <div className="hidden max-w-full overflow-x-auto @4xl:block">
            <Table>
              <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                <TableRow>
                  <TableCell isHeader className={head}>{t("columns.time")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.user")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.action")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.target")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.result")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.organization")}</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                {entries.map((e) => {
                  const { what, target } = describe(e);
                  return (
                    <TableRow key={e.id}>
                      <TableCell className={`${cell} whitespace-nowrap tabular-nums`}>{seconds(e.ts, locale)}</TableCell>
                      <TableCell className={cell}>{e.actor_email ?? "–"}</TableCell>
                      <TableCell className={`${cell} text-gray-800 dark:text-white/90`}>{what}</TableCell>
                      <TableCell className={cell}>{target}</TableCell>
                      <TableCell className="py-1.5 pe-4"><Badge size="sm" color={RESULT_COLOR[e.result] ?? "gray"} className="[text-shadow:none]">{t(`results.${e.result}`)}</Badge></TableCell>
                      <TableCell className={cell}>{e.tenant_name ?? "–"}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <ul className="divide-y divide-gray-100 @4xl:hidden dark:divide-gray-800">
            {entries.map((e) => {
              const { what, target } = describe(e);
              return (
                <li key={e.id} className="py-2 first:pt-0 last:pb-0">
                  <div className="flex items-start justify-between gap-2">
                    <p className="min-w-0 text-sm leading-5 break-words text-gray-800 dark:text-white/90">{what}{target !== "–" && <span className="text-gray-500 dark:text-gray-400"> · {target}</span>}</p>
                    <Badge size="sm" color={RESULT_COLOR[e.result] ?? "gray"} className="[text-shadow:none]">{t(`results.${e.result}`)}</Badge>
                  </div>
                  <p className="mt-0.5 text-xs leading-5 break-words text-gray-500 tabular-nums dark:text-gray-400">{[seconds(e.ts, locale), e.actor_email, e.tenant_name].filter(Boolean).join(" · ")}</p>
                </li>
              );
            })}
          </ul>
          </>
          )}
          </>
        )}
    </div>
  );
}

export default function AuditPage() {
  const t = useTranslations("audit");
  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} />
      <AuditPanel />
    </>
  );
}
