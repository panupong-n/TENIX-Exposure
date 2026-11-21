import { DataStrip, isStale, completeAsOf, type Completeness } from "@/components/shared/data-status";
import type { HostV2 } from "@/components/shared/device-sheet";
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { ActiveChips, FilterBar, ExportLink, ListMeta, Num, PickSelect, Toggle, cell, cellEnd, head, headEnd, statText } from "@/components/shared/list-kit";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { PageStats } from "@/components/shared/page-stats";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { SearchInput } from "@/components/shared/search-input";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { TierBadge } from "@/components/shared/tier-badge";
import { WatchStar } from "@/components/shared/watch-star";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { useLocale, useTranslations } from "@/i18n";
import { SEVERITY_COLOR, type Severity } from "@/lib/chart";
import { cn } from "@/utils";
import type { ReactNode } from "react";
import { formatAgo, formatDate, formatDateTime } from "@/utils/format";

interface Result {
  rows: HostV2[];
  total: number;
  page: number;
  pageSize: number;
  facets?: { all: number; withFindings: number; withP1: number; internet: number; stale7: number; stale30: number; duplicates: number; staleTwins: number; noFindings: number };
  completeness: Completeness;
}

const KEYS = ["q", "tier", "seen", "duplicates", "internet", "platform", "type", "sort"] as const;
const PLATFORMS = ["Windows", "Linux", "Mac"];
const TYPES = ["Workstation", "Server", "Domain Controller"];

export default function DevicesPage({ toggle }: { toggle?: ReactNode }) {
  const t = useTranslations("lists2.devices");
  const tc = useTranslations("common");
  const tl = useTranslations("lists2.common");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { values, text, onText, set, page } = useUrlFilters(KEYS, { sort: "p1" });
  const { openDevice } = useDrawers();

  const f = new URLSearchParams();
  if (values.q) f.set("q", values.q);
  if (values.tier) f.set("tier", values.tier);
  if (values.seen) f.set("seen", values.seen);
  if (values.duplicates) f.set("duplicates", "1");
  if (values.internet) f.set("internet", "1");
  if (values.platform) f.set("platform", values.platform);
  if (values.type) f.set("type", values.type);
  f.set("sort", values.sort);
  const qs = new URLSearchParams(f);
  qs.set("page", String(page));
  qs.set("pageSize", "25");
  const { data, error, loading, reload } = useApi<Result>(scoped(`/api/exposure/v2/hosts?${qs}`));
  const csv = scoped(`/api/exposure/v2/hosts.csv?${f}`);
  const stale = isStale(data?.completeness);
  const fa = data?.facets;
  const filtersOn = [values.q, values.tier, values.seen, values.duplicates, values.internet, values.platform, values.type].some(Boolean);

  const seenItems = [{ value: "all", label: t("seen.all") }, ...(["active", "stale7", "stale30"] as const).map((k) => ({ value: k, label: t(`seen.${k}`) }))];
  const platformItems = [{ value: "all", label: t("allPlatforms") }, ...PLATFORMS.map((p) => ({ value: p, label: p }))];
  const typeItems = [{ value: "all", label: t("allTypes") }, ...TYPES.map((p) => ({ value: p, label: p }))];
  const sortItems = (["p1", "hostname", "lastSeen", "critical", "findings", "os"] as const).map((s) => ({ value: s, label: t(`sortOptions.${s}`) }));

  const chips = [
    values.tier && { key: "tier", label: t("chip.tier", { v: values.tier }), remove: () => set({ tier: null }) },
    values.seen && { key: "seen", label: t(`seen.${values.seen}`), remove: () => set({ seen: null }) },
    values.duplicates && { key: "duplicates", label: t("duplicates"), remove: () => set({ duplicates: null }) },
    values.internet && { key: "internet", label: t("internet"), remove: () => set({ internet: null }) },
    values.platform && { key: "platform", label: values.platform, remove: () => set({ platform: null }) },
    values.type && { key: "type", label: values.type, remove: () => set({ type: null }) },
  ].filter(Boolean) as { key: string; label: string; remove: () => void }[];

  // heading chips are the facets of the whole inventory; each one is also a filter
  const stats = data
    ? [
        { key: "all", label: t("stats.all"), value: statText(fa?.all ?? data.total, locale), active: !filtersOn, onClick: () => set({ tier: null, seen: null, duplicates: null, internet: null, platform: null, type: null, q: null }) },
        { key: "p1", label: t("stats.p1"), value: statText(fa?.withP1, locale), active: values.tier === "P1", onClick: () => set({ tier: values.tier === "P1" ? null : "P1" }) },
        { key: "internet", label: t("stats.internet"), value: statText(fa?.internet, locale), active: Boolean(values.internet), onClick: () => set({ internet: values.internet ? null : "1" }) },
        { key: "stale", label: t("stats.stale"), value: statText(fa?.stale7, locale), active: values.seen === "stale7", onClick: () => set({ seen: values.seen === "stale7" ? null : "stale7" }) },
      ]
    : error ? [] : null;

  const seenCell = (d: HostV2) => {
    const old = d.stale === "stale7" || d.stale === "stale30";
    return (
      <span className="inline-flex flex-wrap items-center gap-1" title={formatDateTime(d.lastSeen, locale) ?? undefined}>
        <span className={cn("tabular-nums", old && "text-gray-800")}>{d.lastSeen ? formatAgo(d.lastSeen, locale) : "–"}</span>
        {(old || stale) && <StaleStamp since={formatDate(d.lastSeen, locale)} />}
      </span>
    );
  };
  const flags = (d: HostV2) => (
    <span className="inline-flex flex-wrap items-center gap-1">
      {d.internetFacing && <span className="rounded-md bg-sky-50 px-1.5 text-xs leading-5 font-medium whitespace-nowrap text-sky-700">{t("flags.internet")}</span>}
      {d.duplicate && <span className="rounded-md bg-amber-50 px-1.5 text-xs leading-5 font-medium whitespace-nowrap text-amber-800" title={t("flags.duplicateHint", { reason: d.duplicate.reason })}>{d.duplicate.staleTwin ? t("flags.staleTwin") : t("flags.duplicate")}</span>}
      {d.inInventory === false && <span className="rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium whitespace-nowrap text-gray-700" title={t("flags.notInventoryHint")}>{t("flags.notInventory")}</span>}
    </span>
  );
  const name = (d: HostV2) => d.hostname ?? <span className="text-gray-600 italic">{tc("unnamedDevice")}</span>;
  const ts = useTranslations("severity");
  // worst severity as a coloured dot in front of the name (colour is never the only carrier: the text is in the label)
  const worstDot = (d: HostV2) => {
    if (!d.worstSeverity) return null;
    const sev = (d.worstSeverity in SEVERITY_COLOR ? d.worstSeverity : "NONE") as Severity;
    const label = t("worstDot", { severity: ts(sev) });
    return <span role="img" aria-label={label} title={label} className="me-1.5 inline-block size-2 shrink-0 rounded-full align-middle" style={{ backgroundColor: SEVERITY_COLOR[sev] }} />;
  };

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} actions={<PageStats items={stats} />} />

      <div className="rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">{toggle}<ExportLink href={csv} label={tl("exportCsv")} /></div>
        <div className="mb-2"><DataStrip completeness={data?.completeness} /></div>
        <FilterBar search={<SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} />} active={chips.length}>
          <PickSelect value={values.platform} onChange={(v) => set({ platform: v || null })} items={platformItems} label={t("platform")} />
          <PickSelect value={values.type} onChange={(v) => set({ type: v || null })} items={typeItems} label={t("type")} />
          <PickSelect value={values.seen} onChange={(v) => set({ seen: v || null })} items={seenItems} label={t("lastSeen")} className="sm:w-52" />
          <Toggle on={values.tier === "P1"} onClick={() => set({ tier: values.tier === "P1" ? null : "P1" })}>{t("hasP1")}</Toggle>
          <Toggle on={Boolean(values.internet)} onClick={() => set({ internet: values.internet ? null : "1" })}>{t("internet")}</Toggle>
          <Toggle on={Boolean(values.duplicates)} onClick={() => set({ duplicates: values.duplicates ? null : "1" })}>{t("duplicates")}</Toggle>
          <PickSelect value={values.sort === "p1" ? "" : values.sort} onChange={(v) => set({ sort: v || null })} items={sortItems} label={t("sort")} className="sm:ms-auto sm:w-56" />
        </FilterBar>
        <ActiveChips items={chips} onClear={() => set({ tier: null, seen: null, duplicates: null, internet: null, platform: null, type: null, q: null })} />

        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !data ? (
          <TableSkeleton />
        ) : data.rows.length === 0 ? (
          <EmptyState>{filtersOn ? t("empty.filtered") : data.completeness.state === "complete" ? t("empty.none") : t("empty.unknown")}</EmptyState>
        ) : (
          <div className={cn("transition-opacity duration-200", loading && "opacity-60")}>
            <ListMeta total={data.total} stale={stale} asOf={completeAsOf(data.completeness)}>
              {fa && fa.staleTwins > 0 && <span className="text-xs text-gray-500">{t("twins", { count: fa.staleTwins })}</span>}
            </ListMeta>
            <ul className="divide-y divide-gray-100 sm:hidden">
              {data.rows.map((d) => (
                <li key={d.key ?? d.aid} className="flex items-start gap-1 py-2">
                  <WatchStar aid={d.aid} hostname={d.hostname} className="mt-0.5" />
                  <button type="button" onClick={() => openDevice(d.aid)} className="flex min-w-0 flex-1 flex-col gap-1 text-start">
                    <span className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm font-medium text-gray-800">{name(d)}</span>
                      <span className="flex shrink-0 items-center gap-1.5">
                        {d.p1 > 0 ? <TierBadge tier="P1" help={false} /> : null}
                        {d.p1 > 0 && <span className="text-sm font-semibold text-gray-800 tabular-nums"><Num value={d.p1} /></span>}
                        {d.worstSeverity && <SeverityBadge severity={d.worstSeverity} />}
                      </span>
                    </span>
                    <span className="truncate text-xs text-gray-500">{[d.osVersion ?? d.platform, d.localIp].filter(Boolean).join(" · ")}</span>
                    <span className="flex flex-wrap items-center gap-1.5 text-xs text-gray-500">{seenCell(d)}{flags(d)}</span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="hidden max-w-full overflow-x-auto sm:block">
              <Table>
                <TableHeader className="border-y border-gray-100">
                  <TableRow>
                    <TableCell isHeader className={`${head} w-8`}><span className="sr-only">{t("watch")}</span></TableCell>
                    <TableCell isHeader className={head}>{t("columns.device")}</TableCell>
                    <TableCell isHeader className={head}>{t("columns.os")}</TableCell>
                    <TableCell isHeader className={headEnd}>P1</TableCell>
                    <TableCell isHeader className={headEnd}>Critical</TableCell>
                    <TableCell isHeader className={headEnd}>KEV</TableCell>
                    <TableCell isHeader className={headEnd}>{t("columns.fixes")}</TableCell>
                    <TableCell isHeader className={`${head} ps-6`}>{t("columns.lastSeen")}</TableCell>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y divide-gray-100">
                  {data.rows.map((d) => (
                    <TableRow key={d.key ?? d.aid} onClick={() => openDevice(d.aid)} className="cursor-pointer transition-colors hover:bg-gray-50">
                      <TableCell className="py-1 pe-1 align-top"><WatchStar aid={d.aid} hostname={d.hostname} /></TableCell>
                      <TableCell className="max-w-64 py-1.5 pe-3 align-top">
                        <button type="button" onClick={(e) => { e.stopPropagation(); openDevice(d.aid); }} className="block max-w-full truncate text-start text-sm font-medium text-gray-800 hover:text-brand-500">{worstDot(d)}{name(d)}</button>
                        <span className="block truncate text-xs text-gray-500 tabular-nums">{[d.productType, d.localIp].filter(Boolean).join(" · ")}</span>
                        {(d.groups?.length ?? 0) > 0 && <span className="block truncate text-xs text-gray-400" title={d.groups!.join(", ")}>{d.groups!.join(", ")}{d.groupsMore ? ` +${d.groupsMore}` : ""}</span>}
                        {(d.internetFacing || d.duplicate || d.inInventory === false) && <span className="mt-0.5 block">{flags(d)}</span>}
                      </TableCell>
                      <TableCell className={`${cell} max-w-40 truncate align-top`} title={d.osVersion ?? d.platform ?? undefined}>{d.osVersion ?? d.platform ?? "–"}</TableCell>
                      <TableCell className={`${cellEnd} align-top font-medium text-gray-800`}><Num value={d.p1} /></TableCell>
                      <TableCell className={`${cellEnd} align-top`}><Num value={d.critical} /></TableCell>
                      <TableCell className={`${cellEnd} align-top`}><Num value={d.kevCves} /></TableCell>
                      <TableCell className={`${cellEnd} align-top`}><Num value={d.fixes} /></TableCell>
                      <TableCell className={`${cell} ps-6 align-top whitespace-nowrap`}>{seenCell(d)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <PaginationBar page={data.page} pageSize={data.pageSize} total={data.total} onPage={(p) => set({ page: String(p) })} />
          </div>
        )}
      </div>
    </>
  );
}
