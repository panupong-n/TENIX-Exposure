import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { PageStats } from "@/components/shared/page-stats";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { SearchInput } from "@/components/shared/search-input";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { useLocale, useTranslations } from "@/i18n";
import { SEVERITIES } from "@/lib/chart";
import { cn } from "@/utils";
import { formatAgo, formatDateTime, formatNumber } from "@/utils/format";
import { useState } from "react";
import { Link } from "react-router";
import { SocNews } from "./soc";
import { StateBadge, STATES, type NewsState, safeUrl, host, head, headEnd, cell } from "./common";

interface Item {
  cve: string; title: string | null; state: NewsState; devices: number; severity: string | null; cvss: number | null; kev: boolean;
  publishedAt: number | null; firstSeen: number | null; lastChanged: number | null; notifiedAt: number | null; newsCount: number; reference: string | null;
}
interface Result {
  showPossible?: boolean; showHostNames?: boolean; counts?: Partial<Record<NewsState, number>>;
  total: number; page: number; pageSize: number; items: Item[];
}

/** The hosts of one CVE for this organization, only requested when the organization allows host names. */
function HostNames({ cve }: { cve: string }) {
  const t = useTranslations("newsPage");
  const { scoped } = useOrg();
  const { data, error } = useApi<{ hostsHidden?: boolean; hosts: { aid: string; hostname: string | null; severity: string }[] | null }>(scoped(`/api/exposure/news/${encodeURIComponent(cve)}`));
  const { openDevice } = useDrawers();
  if (error) return <p className="text-xs text-gray-500">{t("hostsFailed")}</p>;
  if (!data) return <div className="h-5 w-48 animate-pulse rounded bg-gray-100" aria-hidden="true" />;
  if (!data.hosts) return <p className="text-xs text-gray-500">{t("hostsHidden")}</p>;
  return (
    <ul className="flex flex-wrap gap-1.5">
      {data.hosts.slice(0, 50).map((h) => (
        <li key={h.aid}><button type="button" onClick={() => openDevice(h.aid)} className="rounded-md border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-xs text-gray-700 hover:border-brand-300">{h.hostname || h.aid.slice(0, 8)}</button></li>
      ))}
      {data.hosts.length > 50 && <li className="py-0.5 text-xs text-gray-500">{t("moreHosts", { n: data.hosts.length - 50 })}</li>}
    </ul>
  );
}

export default function NewsPage() {
  const t = useTranslations("newsPage");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const { user } = useAuth();
  const { scoped } = useOrg();
  const { openCve } = useDrawers();
  const { values, text, onText, set, page } = useUrlFilters(["q", "state", "severity", "kev", "days", "view"], { days: "90" });
  const all = !!user?.soc && values.view === "all";
  const [open, setOpen] = useState<string | null>(null);

  const qs = new URLSearchParams({ page: String(page), pageSize: "25", days: values.days });
  if (values.q) qs.set("q", values.q);
  if (values.state) qs.set("state", values.state);
  if (values.severity) qs.set("severity", values.severity);
  if (values.kev === "1") qs.set("kev", "1");
  const mine = useApi<Result>(all ? null : scoped(`/api/exposure/news?${qs}`));
  const { data, error, loading, reload } = mine;
  const n = (v: number) => formatNumber(v, locale);
  const filtered = Boolean(values.q || values.state || values.severity || values.kev);

  const stats = data
    ? STATES.filter((s) => s !== "possible" || data.showPossible).map((s) => ({
        key: s, label: t(`state.${s}`), value: n(data.counts?.[s] ?? 0), active: values.state === s, onClick: () => set({ state: values.state === s ? null : s }),
      }))
    : error ? [] : null;

  const pick = (key: string, value: string, items: { value: string; label: string }[], label: string, onChange: (v: string) => void) => (
    <Select value={value || "all"} onValueChange={(v) => onChange(v === "all" ? "" : String(v))} items={items}>
      <SelectTrigger size="default" className="w-full sm:w-40" aria-label={label} data-testid={`news-${key}`}><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  );
  const stateItems = [{ value: "all", label: t("allStates") }, ...STATES.filter((s) => s !== "possible" || data?.showPossible || user?.soc).map((s) => ({ value: s, label: t(`state.${s}`) }))];
  const sevItems = [{ value: "all", label: t("allSeverities") }, ...SEVERITIES.map((s) => ({ value: s, label: tSev(s) }))];
  const dayItems = ["7", "30", "90"].map((d) => ({ value: d, label: t("days", { n: d }) }));

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} actions={all ? undefined : <PageStats items={stats} />} />
      {user?.soc && (
        <div className="mb-3 inline-flex rounded-lg border border-gray-200 bg-white p-0.5 text-sm" role="tablist">
          {(["org", "all"] as const).map((v) => (
            <button key={v} type="button" role="tab" aria-selected={(v === "all") === all} onClick={() => set({ view: v === "all" ? "all" : null, state: null })}
              className={cn("rounded-md px-3 py-1 font-medium", (v === "all") === all ? "bg-brand-500 text-white" : "text-gray-600 hover:bg-gray-50")}>{t(`view.${v}`)}</button>
          ))}
        </div>
      )}
      <div className="rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4">
        <div className="mb-3 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center sm:gap-3">
          <div className="col-span-2 sm:col-span-1"><SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} /></div>
          {pick("state", values.state, stateItems, t("state.label"), (v) => set({ state: v || null }))}
          {!all && pick("severity", values.severity, sevItems, t("severity"), (v) => set({ severity: v || null }))}
          {pick("days", values.days, dayItems, t("period"), (v) => set({ days: v || null }))}
          {!all && (
            <label className="col-span-2 flex items-center gap-2 text-sm text-gray-700 sm:col-span-1">
              <input type="checkbox" className="size-4 accent-brand-500" checked={values.kev === "1"} onChange={(e) => set({ kev: e.target.checked ? "1" : null })} data-testid="news-kev" />
              {t("kevOnly")}
            </label>
          )}
        </div>

        {all ? <SocNews values={values} page={page} set={set} filtered={filtered} /> : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !data ? (
          <TableSkeleton />
        ) : data.items.length === 0 ? (
          <EmptyState title={filtered ? t("empty.filteredTitle") : t("empty.title")}>{filtered ? t("empty.filtered") : t("empty.none")}</EmptyState>
        ) : (
          <div className={cn("transition-opacity duration-200", loading && "opacity-60")}>
            <ul className="divide-y divide-gray-100 sm:hidden">
              {data.items.map((r) => (
                <li key={r.cve} className="py-2">
                  <button type="button" onClick={() => openCve(r.cve)} className="flex w-full flex-col gap-1 text-start">
                    <span className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium break-all text-gray-800">{r.cve}</span>
                      <StateBadge state={r.state} devices={r.devices} />
                    </span>
                    {r.title && <span className="line-clamp-2 text-xs text-gray-600">{r.title}</span>}
                    <span className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                      {r.severity && <SeverityBadge severity={r.severity} />}
                      {r.kev && <Badge variant="light" color="error" size="sm">KEV</Badge>}
                      <span title={formatDateTime(r.lastChanged, locale) ?? undefined}>{formatAgo(r.lastChanged, locale) ?? "–"}</span>
                    </span>
                  </button>
                  {data.showHostNames && r.state === "exact" && <div className="mt-1"><HostNames cve={r.cve} /></div>}
                </li>
              ))}
            </ul>
            <div className="hidden max-w-full overflow-x-auto sm:block">
              <Table>
                <TableHeader className="border-y border-gray-100">
                  <TableRow>
                    <TableCell isHeader className={head}>{t("columns.cve")}</TableCell>
                    <TableCell isHeader className={head}>{t("columns.state")}</TableCell>
                    <TableCell isHeader className={head}>{t("severity")}</TableCell>
                    <TableCell isHeader className={headEnd}>{t("columns.cvss")}</TableCell>
                    <TableCell isHeader className={headEnd}>{t("columns.devices")}</TableCell>
                    <TableCell isHeader className={`${head} ps-6`}>{t("columns.source")}</TableCell>
                    <TableCell isHeader className={head}>{t("columns.time")}</TableCell>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y divide-gray-100">
                  {data.items.map((r) => (
                    <TableRow key={r.cve} className="align-top transition-colors hover:bg-gray-50" data-testid="news-row">
                      <TableCell className="max-w-md py-1.5 pe-4">
                        <button type="button" onClick={() => openCve(r.cve)} className="block text-start text-sm font-medium whitespace-nowrap text-gray-800 hover:text-brand-500">{r.cve}</button>
                        {r.kev && <Badge variant="light" color="error" size="sm" className="me-1">KEV</Badge>}
                        {r.title && <span className="line-clamp-2 text-xs text-gray-500" title={r.title}>{r.title}</span>}
                        {data.showHostNames && r.state === "exact" && (
                          <button type="button" onClick={() => setOpen(open === r.cve ? null : r.cve)} className="mt-0.5 text-xs font-medium text-brand-600 hover:text-brand-700" aria-expanded={open === r.cve}>
                            {open === r.cve ? t("hideHosts") : t("showHosts")}
                          </button>
                        )}
                        {open === r.cve && <div className="mt-1"><HostNames cve={r.cve} /></div>}
                      </TableCell>
                      <TableCell className="py-1.5 pe-4"><StateBadge state={r.state} devices={r.devices} /></TableCell>
                      <TableCell className="py-1.5 pe-4">{r.severity ? <SeverityBadge severity={r.severity} /> : <span className="text-sm text-gray-400">–</span>}</TableCell>
                      <TableCell className={`${cell} text-end tabular-nums`}>{r.cvss ? r.cvss.toFixed(1) : "–"}</TableCell>
                      <TableCell className={`${cell} text-end tabular-nums`}>
                        {r.state === "exact" && r.devices > 0 ? <Link to={`/devices?cve=${encodeURIComponent(r.cve)}`} className="font-medium text-brand-600 hover:text-brand-700">{n(r.devices)}</Link> : r.state === "possible" ? n(r.devices) : "–"}
                      </TableCell>
                      <TableCell className={`${cell} ps-6`}>
                        {r.reference && safeUrl(r.reference)
                          ? <a href={r.reference} target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:text-brand-700">{host(r.reference)}</a>
                          : "–"}
                        {r.newsCount > 1 && <span className="ms-1 text-xs text-gray-400">{t("newsCount", { n: r.newsCount })}</span>}
                      </TableCell>
                      <TableCell className={`${cell} whitespace-nowrap`} title={formatDateTime(r.lastChanged, locale) ?? undefined}>{formatAgo(r.lastChanged, locale) ?? "–"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
        {!all && data && data.total > 0 && <div className="mt-3"><PaginationBar page={data.page} pageSize={data.pageSize} total={data.total} onPage={(p) => set({ page: String(p) })} /></div>}
      </div>
      {!all && data && !data.showPossible && <p className="mt-2 text-xs text-gray-500">{t("possibleHidden")}</p>}
    </>
  );
}
