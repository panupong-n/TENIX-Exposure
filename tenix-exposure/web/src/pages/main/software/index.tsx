import { DataStrip, isStale, completeAsOf, type Completeness } from "@/components/shared/data-status";
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { ActiveChips, FilterBar, ListMeta, Num, PickSelect, Toggle, cell, cellEnd, head, headEnd, statText } from "@/components/shared/list-kit";
import { PageBreadcrumb } from "@/components/shared/page-breadcrumb";
import { PageMeta } from "@/components/shared/page-meta";
import { PageStats } from "@/components/shared/page-stats";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { SearchInput } from "@/components/shared/search-input";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { useLocale, useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { formatDate } from "@/utils/format";

interface Row {
  key: string;
  type: string;
  vendor: string;
  name: string;
  category: string | null;
  devices: number;
  versions: number;
  firstSeen: number | null;
  suspicious: boolean;
  latest: string | null;
  /** distinct P1 / KEV CVEs of the product: only when the backend joins findings to software; absent = unknown (shown as a dash, never 0) */
  p1Cves?: number | null;
  kevCves?: number | null;
}
interface Result {
  rows: Row[];
  total: number;
  page: number;
  pageSize: number;
  devices: number;
  byType: { type: string; items: number; devices: number }[];
  completeness: Completeness;
}

const KEYS = ["q", "type", "sort", "flagged", "p1", "kev"] as const;

export default function SoftwarePage() {
  const t = useTranslations("software");
  const tl = useTranslations("lists2.software");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { openSoftware } = useDrawers();
  const { values, text, onText, set, page } = useUrlFilters(KEYS, { sort: "risk" });

  const f = new URLSearchParams({ sort: values.sort });
  if (values.q) f.set("q", values.q);
  if (values.type) f.set("type", values.type);
  if (values.flagged) f.set("flagged", "1");
  if (values.p1) f.set("p1", "1");
  if (values.kev) f.set("kev", "1");
  const qs = new URLSearchParams(f);
  qs.set("page", String(page));
  qs.set("pageSize", "25");
  const { data, error, loading, reload } = useApi<Result>(scoped(`/api/exposure/software?${qs}`));
  const filtersOn = Boolean(values.q || values.type || values.flagged || values.p1 || values.kev);
  const stale = isStale(data?.completeness);
  const totalItems = data?.byType.reduce((a, x) => a + x.items, 0) ?? 0;
  // the risk columns and filters appear once the API returns them
  const risk = Boolean(data?.rows.some((r) => r.p1Cves != null || r.kevCves != null)) || Boolean(values.p1 || values.kev);
  const sortItems = (["risk", "devices", "name", "recent"] as const).map((s) => ({ value: s, label: tl(`sort.${s}`) }));
  const typeItems = [{ value: "all", label: t("allTypes") }, ...(data?.byType ?? []).map((x) => ({ value: x.type, label: `${t(`types.${x.type}`)} · ${x.items}` }))];

  const stats = data
    ? [
        { key: "items", label: t("stats.items"), value: statText(totalItems, locale) },
        { key: "devices", label: t("stats.devices"), value: statText(data.devices, locale) },
        { key: "types", label: t("stats.types"), value: statText(data.byType.length, locale) },
      ]
    : error ? [] : null;
  const chips = [
    values.type && { key: "type", label: t(`types.${values.type}`), remove: () => set({ type: null }) },
    values.p1 && { key: "p1", label: tl("hasP1"), remove: () => set({ p1: null }) },
    values.kev && { key: "kev", label: tl("hasKev"), remove: () => set({ kev: null }) },
    values.flagged && { key: "flagged", label: t("flagged"), remove: () => set({ flagged: null }) },
  ].filter(Boolean) as { key: string; label: string; remove: () => void }[];

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <PageBreadcrumb pageTitle={t("title")} description={t("description")} actions={<PageStats items={stats} />} />

      <div className="rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4">
        <div className="mb-2"><DataStrip completeness={data?.completeness} /></div>
        <FilterBar search={<SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} />} active={chips.length}>
          <PickSelect value={values.type} onChange={(v) => set({ type: v || null })} items={typeItems} label={t("type")} className="sm:w-48" />
          {risk && <Toggle on={Boolean(values.p1)} onClick={() => set({ p1: values.p1 ? null : "1" })}>{tl("hasP1")}</Toggle>}
          {risk && <Toggle on={Boolean(values.kev)} onClick={() => set({ kev: values.kev ? null : "1" })}>{tl("hasKev")}</Toggle>}
          <Toggle on={Boolean(values.flagged)} onClick={() => set({ flagged: values.flagged ? null : "1" })}>{t("flaggedOnly")}</Toggle>
          <PickSelect value={values.sort === "risk" ? "" : values.sort} onChange={(v) => set({ sort: v || null })} items={sortItems} label={t("sortBy")} className="sm:ms-auto sm:w-64" />
        </FilterBar>
        <ActiveChips items={chips} onClear={() => set({ type: null, p1: null, kev: null, flagged: null, q: null })} />

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
                <li key={r.key}>
                  <button type="button" onClick={() => openSoftware(r.key)} className="flex w-full flex-col gap-1 py-2 text-start">
                    <span className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium break-all text-gray-800">{r.name}</span>
                      {r.suspicious && <Badge size="sm" color="error" className="[text-shadow:none]">{t("flagged")}</Badge>}
                    </span>
                    <span className="text-xs text-gray-500">{[r.vendor, t(`types.${r.type}`)].filter(Boolean).join(" · ")}</span>
                    <span className="text-xs text-gray-500">
                      {t("rowSummary", { devices: r.devices, versions: r.versions })}
                      {r.p1Cves != null && ` · P1 ${r.p1Cves}`}{(r.kevCves ?? 0) > 0 && ` · KEV ${r.kevCves}`}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="hidden max-w-full overflow-x-auto sm:block">
              <Table>
                <TableHeader className="border-y border-gray-100">
                  <TableRow>
                    <TableCell isHeader className={head}>{t("columns.software")}</TableCell>
                    <TableCell isHeader className={head}>{t("columns.type")}</TableCell>
                    <TableCell isHeader className={headEnd}>{tl("columns.p1Cves")}</TableCell>
                    <TableCell isHeader className={headEnd}>KEV</TableCell>
                    <TableCell isHeader className={headEnd}>{t("devices")}</TableCell>
                    <TableCell isHeader className={headEnd}>{t("versions")}</TableCell>
                    <TableCell isHeader className={`${head} ps-6`}>{tl("columns.latest")}</TableCell>
                    <TableCell isHeader className={head}>{t("firstSeen")}</TableCell>
                  </TableRow>
                </TableHeader>
                <TableBody className="divide-y divide-gray-100">
                  {data.rows.map((r) => (
                    <TableRow key={r.key} onClick={() => openSoftware(r.key)} className="cursor-pointer transition-colors hover:bg-gray-50">
                      <TableCell className="max-w-96 py-1.5 pe-3">
                        <button type="button" onClick={(e) => { e.stopPropagation(); openSoftware(r.key); }} className="block max-w-full truncate text-start text-sm font-medium text-gray-800 hover:text-brand-500">{r.name}</button>
                        <span className="block truncate text-xs text-gray-500">{r.vendor || t("unknownVendor")}</span>
                      </TableCell>
                      <TableCell className={cell}>
                        {t(`types.${r.type}`)}
                        {r.suspicious && <Badge size="sm" color="error" className="ms-2 [text-shadow:none]">{t("flagged")}</Badge>}
                      </TableCell>
                      <TableCell className={`${cellEnd} font-medium text-gray-800`}><Num value={r.p1Cves} /></TableCell>
                      <TableCell className={cellEnd}><Num value={r.kevCves} /></TableCell>
                      <TableCell className={cellEnd}><Num value={r.devices} /></TableCell>
                      <TableCell className={cellEnd}><Num value={r.versions} /></TableCell>
                      <TableCell className={`${cell} ps-6 whitespace-nowrap tabular-nums`}>{r.latest ?? "–"}</TableCell>
                      <TableCell className={`${cell} whitespace-nowrap tabular-nums`}>{r.firstSeen ? formatDate(r.firstSeen, locale) : "–"}</TableCell>
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
