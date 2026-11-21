import { DataStrip, isStale, completeAsOf, type Completeness } from "@/components/shared/data-status";
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { ActiveChips, FilterBar, ExportLink, HeldNote, ListMeta, Num, PickSelect, Toggle, cell, cellEnd, head, headEnd, reasonKeys, statText, type VulnRow } from "@/components/shared/list-kit";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { PageStats } from "@/components/shared/page-stats";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { ReasonChips } from "@/components/shared/reason-chips";
import { SearchInput } from "@/components/shared/search-input";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { TierBadge } from "@/components/shared/tier-badge";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useExploitLabel } from "@/hooks/use-exploit-label";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { useLocale, useTranslations } from "@/i18n";
import { SEVERITIES } from "@/lib/chart";
import { cn } from "@/utils";
import { formatDate } from "@/utils/format";
import FixesTab from "./fixes-tab";

interface Result {
  rows: VulnRow[];
  total: number;
  page: number;
  pageSize: number;
  facets?: { P1: number; P2: number; P3: number; kev: number };
  completeness: Completeness;
}

const KEYS = ["q", "tier", "severity", "exprt", "kev", "exploited", "internet", "byfix", "sort", "tab"] as const;

export default function VulnerabilitiesPage() {
  const t = useTranslations("lists2.vulns");
  const tc = useTranslations("lists2.common");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const exploit = useExploitLabel();
  const { openCve, openFix } = useDrawers();
  const tKind = useTranslations("cve.kinds");
  const { scoped } = useOrg();
  const { values, text, onText, set, page } = useUrlFilters(KEYS, { sort: "priority", tab: "cve" });
  const byFix = values.tab === "fix";
  const exprt = (v: string | null) => (v ? (v.toUpperCase() === "UNKNOWN" ? tSev("NONE") : (SEVERITIES as readonly string[]).includes(v.toUpperCase()) ? tSev(v.toUpperCase()) : v) : "–");

  // the filters that go to the API (the same names as the CSV export)
  const f = new URLSearchParams();
  if (values.q) f.set("q", values.q);
  if (values.tier) f.set("tier", values.tier);
  if (values.severity) f.set("severity", values.severity);
  if (values.exprt) f.set("exprt", values.exprt);
  if (values.kev) f.set("kev", "1");
  if (values.exploited) f.set("exploited", "1");
  if (values.internet) f.set("internet", "1");
  if (values.byfix) f.set("fix", values.byfix);
  f.set("sort", values.sort);
  const qs = new URLSearchParams(f);
  qs.set("page", String(page));
  qs.set("pageSize", "25");
  const { data, error, loading, reload } = useApi<Result>(byFix ? null : scoped(`/api/exposure/v2/vulnerabilities?${qs}`));
  const csv = scoped(`/api/exposure/v2/vulnerabilities.csv?${f}`);
  const stale = isStale(data?.completeness);

  const filtersOn = [values.q, values.tier, values.severity, values.exprt, values.kev, values.exploited, values.internet, values.byfix].some(Boolean);
  const chips = [
    values.tier && { key: "tier", label: t("chip.tier", { v: values.tier }), remove: () => set({ tier: null }) },
    values.severity && { key: "severity", label: tSev(values.severity), remove: () => set({ severity: null }) },
    values.exprt && { key: "exprt", label: `ExPRT ${exprt(values.exprt)}`, remove: () => set({ exprt: null }) },
    values.kev && { key: "kev", label: "KEV", remove: () => set({ kev: null }) },
    values.exploited && { key: "exploited", label: t("exploited"), remove: () => set({ exploited: null }) },
    values.internet && { key: "internet", label: t("internet"), remove: () => set({ internet: null }) },
    values.byfix && { key: "byfix", label: t("chip.fix", { id: values.byfix }), remove: () => set({ byfix: null }) },
  ].filter(Boolean) as { key: string; label: string; remove: () => void }[];

  const stats = data
    ? [
        ...(["P1", "P2", "P3"] as const).map((k) => ({
          key: k, label: `${k} ${tc(`tierName.${k}`)}`, value: statText(data.facets?.[k], locale),
          active: values.tier === k, onClick: () => set({ tier: values.tier === k ? null : k }),
        })),
        { key: "kev", label: "KEV", value: statText(data.facets?.kev, locale), active: Boolean(values.kev), onClick: () => set({ kev: values.kev ? null : "1" }) },
      ]
    : error ? [] : null;

  const tabBtn = (on: boolean) => cn("rounded-md px-3 py-1 text-sm font-medium", on ? "bg-white text-gray-900 shadow-theme-xs" : "text-gray-500 hover:text-gray-800");
  const sevItems = [{ value: "all", label: t("allSeverities") }, ...SEVERITIES.map((s) => ({ value: s, label: tSev(s) }))];
  const tierItems = [{ value: "all", label: t("allTiers") }, ...(["P1", "P2", "P3"] as const).map((k) => ({ value: k, label: `${k} ${tc(`tierName.${k}`)}` }))];
  const exprtItems = [{ value: "all", label: t("allExprt") }, ...(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => ({ value: s, label: `ExPRT ${tSev(s)}` }))];
  const sortItems = (["priority", "severity", "cvss", "hosts", "age", "new"] as const).map((s) => ({ value: s, label: t(`sortOptions.${s}`) }));

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} actions={byFix ? undefined : <PageStats items={stats} />} />

      <div className="rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <nav aria-label={t("title")} className="flex w-fit items-center gap-0.5 rounded-lg bg-gray-100 p-0.5">
            <button type="button" aria-pressed={!byFix} onClick={() => set({ tab: null, sort: null })} className={tabBtn(!byFix)}>{t("tabs.cve")}</button>
            <button type="button" aria-pressed={byFix} onClick={() => set({ tab: "fix", sort: null, severity: null, exprt: null, exploited: null, byfix: null })} className={tabBtn(byFix)}>{t("tabs.fix")}</button>
          </nav>
          {!byFix && <ExportLink href={csv} label={tc("exportCsv")} />}
        </div>

        {byFix ? (
          <FixesTab values={values} set={set} text={text} onText={onText} page={page} />
        ) : (
          <>
            <div className="mb-2"><DataStrip completeness={data?.completeness} /></div>
            <FilterBar search={<SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} />} active={chips.length}>
              <PickSelect value={values.tier} onChange={(v) => set({ tier: v || null })} items={tierItems} label={t("tier")} />
              <PickSelect value={values.severity} onChange={(v) => set({ severity: v || null })} items={sevItems} label={t("severity")} />
              <PickSelect value={values.exprt} onChange={(v) => set({ exprt: v || null })} items={exprtItems} label="ExPRT" />
              <Toggle on={Boolean(values.kev)} onClick={() => set({ kev: values.kev ? null : "1" })}>KEV</Toggle>
              <Toggle on={Boolean(values.exploited)} onClick={() => set({ exploited: values.exploited ? null : "1" })}>{t("exploited")}</Toggle>
              <Toggle on={Boolean(values.internet)} onClick={() => set({ internet: values.internet ? null : "1" })}>{t("internet")}</Toggle>
              <PickSelect value={values.sort === "priority" ? "" : values.sort} onChange={(v) => set({ sort: v || null })} items={sortItems} label={t("sort")} className="sm:ms-auto sm:w-60" />
            </FilterBar>
            <ActiveChips items={chips} onClear={() => set({ tier: null, severity: null, exprt: null, kev: null, exploited: null, internet: null, byfix: null, q: null })} />

            {error ? (
              <ErrorState error={error} onRetry={reload} />
            ) : !data ? (
              <TableSkeleton />
            ) : data.rows.length === 0 ? (
              <EmptyState>{filtersOn ? t("empty.filtered") : data.completeness.state === "complete" ? t("empty.none") : t("empty.unknown")}</EmptyState>
            ) : (
              <div className={cn("transition-opacity duration-200", loading && "opacity-60")}>
                <ListMeta total={data.total} stale={stale} asOf={completeAsOf(data.completeness)} />
                <ul className="divide-y divide-gray-100 sm:hidden">
                  {data.rows.map((r) => (
                    <li key={r.cveId}>
                      <button type="button" onClick={() => openCve(r.cveId)} className="flex w-full flex-col gap-1 py-2 text-start">
                        <span className="flex items-center justify-between gap-2">
                          <span className="flex min-w-0 items-center gap-2">
                            {r.tier && <TierBadge tier={r.tier} help={false} />}
                            <span className="text-sm font-medium break-all text-gray-800">{r.cveId}</span>
                          </span>
                          <SeverityBadge severity={r.severity} />
                        </span>
                        {r.product && <span className="truncate text-xs text-gray-500">{r.product}</span>}
                        <span className="text-xs text-gray-500">{t("rowSummary", { devices: r.hosts, score: r.baseScore ? r.baseScore.toFixed(1) : "–" })}</span>
                        <ReasonChips reasons={reasonKeys(r)} max={3} />
                      </button>
                    </li>
                  ))}
                </ul>
                {/* the why-chips (KEV, exploited, ExPRT, internet) repeat the columns here, so only the phone list shows them */}
                <div className="hidden max-w-full overflow-x-auto sm:block">
                  <Table>
                    <TableHeader className="border-y border-gray-100">
                      <TableRow>
                        <TableCell isHeader className={head}>{t("columns.tier")}</TableCell>
                        <TableCell isHeader className={head}>{t("columns.cve")}</TableCell>
                        <TableCell isHeader className={head}>{t("columns.severity")}</TableCell>
                        <TableCell isHeader className={head}>ExPRT</TableCell>
                        <TableCell isHeader className={head}>{t("columns.exploit")}</TableCell>
                        <TableCell isHeader className={head}>KEV</TableCell>
                        <TableCell isHeader className={headEnd}>{t("columns.devices")}</TableCell>
                        <TableCell isHeader className={`${head} ps-6`}>{t("columns.fix")}</TableCell>
                        <TableCell isHeader className={headEnd}>{t("columns.age")}</TableCell>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="divide-y divide-gray-100">
                      {data.rows.map((r) => (
                        <TableRow key={r.cveId} onClick={() => openCve(r.cveId)} className="cursor-pointer transition-colors hover:bg-gray-50">
                          <TableCell className="py-1.5 pe-3 align-top">{r.tier ? <TierBadge tier={r.tier} help={false} /> : "–"}</TableCell>
                          <TableCell className="max-w-72 py-1.5 pe-3">
                            <button type="button" onClick={(e) => { e.stopPropagation(); openCve(r.cveId); }} className="text-start text-sm font-medium whitespace-nowrap text-gray-800 hover:text-brand-500">{r.cveId}</button>
                            {r.kind === "Misconfiguration" && <span className="ms-2 text-xs text-amber-700">{tKind("misconfiguration")}</span>}
                            {r.product && <span className="block truncate text-xs text-gray-500" title={r.product}>{r.product}</span>}
                          </TableCell>
                          <TableCell className="py-1.5 pe-3 align-top whitespace-nowrap">
                            <SeverityBadge severity={r.severity} />
                            <span className="ms-1.5 text-xs text-gray-500 tabular-nums">{r.baseScore ? r.baseScore.toFixed(1) : "–"}</span>
                          </TableCell>
                          <TableCell className={`${cell} align-top`}>{exprt(r.exprt)}</TableCell>
                          <TableCell className={`${cell} align-top`}>{exploit(r.exploitStatus)}</TableCell>
                          <TableCell className={`${cell} align-top whitespace-nowrap`}>
                            {r.kev ? (
                              <>
                                <span className="rounded bg-red-50 px-1 text-xs font-medium text-red-700" title={t("kevTitle")}>KEV</span>
                                {r.kevDueDate && <span className={cn("block text-xs tabular-nums", r.overdue ? "font-medium text-red-700" : "text-gray-500")}>{formatDate(Date.parse(r.kevDueDate), locale) ?? r.kevDueDate}</span>}
                              </>
                            ) : "–"}
                          </TableCell>
                          <TableCell className={`${cellEnd} align-top`}>
                            <Num value={r.hosts} />
                            {(r.internetHosts ?? 0) > 0 && <span className="block text-xs text-sky-700">{t("internetCount", { count: r.internetHosts ?? 0 })}</span>}
                          </TableCell>
                          <TableCell className={`${cell} max-w-64 ps-6 align-top`}>
                            {r.fix ? (
                              <button type="button" onClick={(e) => { e.stopPropagation(); openFix(r.fix!.id); }} title={r.fix.title ?? undefined} className="block max-w-full truncate text-start text-brand-600 hover:underline">
                                {r.fix.title || t("openFix")}
                              </button>
                            ) : "–"}
                          </TableCell>
                          <TableCell className={`${cellEnd} align-top whitespace-nowrap`}>{r.ageDays != null ? t("days", { count: Math.round(r.ageDays) }) : "–"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                <PaginationBar page={data.page} pageSize={data.pageSize} total={data.total} onPage={(p) => set({ page: String(p) })} />
                <HeldNote coverage={data.completeness.coverage} />
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
