import { DataStrip, isStale, completeAsOf, type Completeness } from "@/components/shared/data-status";
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { ActiveChips, ExportLink, HeldNote, ListMeta, Num, PickSelect, Toggle, cell, cellEnd, head, headEnd } from "@/components/shared/list-kit";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { SearchInput } from "@/components/shared/search-input";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { formatNumber } from "@/utils/format";
import { Link } from "react-router";

export interface FixRow {
  id: string; title: string | null; action?: string | null; link?: string | null; product: string | null; vendor?: string | null; noFix?: boolean;
  p1: number; p2: number; p3: number; findings: number; cves: number; p1Cves?: number; kevCves: number; hosts: number; p1Hosts?: number; internetHosts: number;
  severity: string | null; exprt: string | null; firstSeen: number | null; ageDays: number | null; impactShare: number | null;
}
interface Result {
  rows: FixRow[]; total: number; page: number; pageSize: number;
  totals?: { fixes: number; p1: number; withKev: number };
  completeness: Completeness;
}

/** The "by fix" tab: one row is one remediation (what to do), with what it closes and where. Filters live in the same URL as the CVE tab. */
export default function FixesTab({ values, set, text, onText, page }: {
  values: Record<string, string>; set: (p: Record<string, string | null>) => void; text: string; onText: (v: string) => void; page: number;
}) {
  const t = useTranslations("lists2.fixes");
  const tv = useTranslations("lists2.vulns");
  const tc = useTranslations("lists2.common");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const { openFix } = useDrawers();
  const { scoped } = useOrg();
  const sort = ["impact", "hosts", "cves", "title", "age"].includes(values.sort) ? values.sort : "impact"; // the CVE tab's default sort is "priority"


  const f = new URLSearchParams();
  if (values.q) f.set("q", values.q);
  if (values.tier) f.set("tier", values.tier);
  if (values.kev) f.set("kev", "1");
  if (values.internet) f.set("internet", "1");
  f.set("sort", sort);
  const qs = new URLSearchParams(f);
  qs.set("page", String(page));
  qs.set("pageSize", "25");
  const { data, error, loading, reload } = useApi<Result>(scoped(`/api/exposure/v2/fixes?${qs}`));
  const csv = scoped(`/api/exposure/v2/fixes.csv?${f}`);
  const stale = isStale(data?.completeness);
  const on = [values.q, values.tier, values.kev, values.internet].some(Boolean);
  const maxShare = Math.max(0.0001, ...(data?.rows.map((r) => r.impactShare ?? 0) ?? []));
  const chips = [
    values.tier && { key: "tier", label: tv("chip.tier", { v: values.tier }), remove: () => set({ tier: null }) },
    values.kev && { key: "kev", label: "KEV", remove: () => set({ kev: null }) },
    values.internet && { key: "internet", label: tv("internet"), remove: () => set({ internet: null }) },
  ].filter(Boolean) as { key: string; label: string; remove: () => void }[];
  const tierItems = [{ value: "all", label: tv("allTiers") }, ...(["P1", "P2", "P3"] as const).map((k) => ({ value: k, label: `${k} ${tc(`tierName.${k}`)}` }))];
  const sortItems = (["impact", "hosts", "cves", "title", "age"] as const).map((s) => ({ value: s, label: t(`sortOptions.${s}`) }));

  return (
    <>
      <div className="mb-2"><DataStrip completeness={data?.completeness} /></div>
      <div className="mb-3 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center">
        <div className="col-span-2 sm:col-span-1"><SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} /></div>
        <PickSelect value={values.tier} onChange={(v) => set({ tier: v || null })} items={tierItems} label={tv("tier")} />
        <Toggle on={Boolean(values.kev)} onClick={() => set({ kev: values.kev ? null : "1" })}>KEV</Toggle>
        <Toggle on={Boolean(values.internet)} onClick={() => set({ internet: values.internet ? null : "1" })}>{tv("internet")}</Toggle>
        <PickSelect value={sort === "impact" ? "" : sort} onChange={(v) => set({ sort: v || "impact" })} items={sortItems} label={tv("sort")} className="sm:ms-auto sm:w-56" />
        <ExportLink href={csv} label={tc("exportCsv")} />
      </div>
      <ActiveChips items={chips} onClear={() => set({ tier: null, kev: null, internet: null, q: null })} />

      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data ? (
        <TableSkeleton />
      ) : data.rows.length === 0 ? (
        <EmptyState>{on ? t("empty.filtered") : data.completeness.state === "complete" ? t("empty.none") : t("empty.unknown")}</EmptyState>
      ) : (
        <div className={cn("transition-opacity duration-200", loading && "opacity-60")}>
          <ListMeta total={data.total} stale={stale} asOf={completeAsOf(data.completeness)}>
            {data.totals && <span className="text-xs text-gray-500">{t("totals", { p1: formatNumber(data.totals.p1, locale), kev: formatNumber(data.totals.withKev, locale) })}</span>}
          </ListMeta>
          <ul className="divide-y divide-gray-100 sm:hidden">
            {data.rows.map((r) => (
              <li key={r.id}>
                <button type="button" onClick={() => openFix(r.id)} className="flex w-full flex-col gap-1 py-2 text-start">
                  <span className="text-sm font-medium text-gray-800">{r.title || r.product || t("noTitle")}</span>
                  <span className="text-xs text-gray-500">{t("rowSummary", { devices: r.hosts, cves: r.cves, p1: r.p1 })}{r.kevCves > 0 ? " · KEV" : ""}</span>
                </button>
              </li>
            ))}
          </ul>
          <div className="hidden max-w-full overflow-x-auto sm:block">
            <Table>
              <TableHeader className="border-y border-gray-100">
                <TableRow>
                  <TableCell isHeader className={head}>{t("columns.fix")}</TableCell>
                  <TableCell isHeader className={headEnd}>{t("columns.cves")}</TableCell>
                  <TableCell isHeader className={headEnd}>P1</TableCell>
                  <TableCell isHeader className={headEnd}>{t("columns.devices")}</TableCell>
                  <TableCell isHeader className={`${head} ps-6`}>{t("columns.worst")}</TableCell>
                  <TableCell isHeader className={headEnd}>{t("columns.age")}</TableCell>
                  <TableCell isHeader className={headEnd}>{t("columns.impact")}</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100">
                {data.rows.map((r) => (
                  <TableRow key={r.id} onClick={() => openFix(r.id)} className="cursor-pointer transition-colors hover:bg-gray-50">
                    <TableCell className="max-w-96 py-1.5 pe-3 align-top">
                      <button type="button" onClick={(e) => { e.stopPropagation(); openFix(r.id); }} className="block max-w-full text-start text-sm font-medium text-gray-800 hover:text-brand-500" title={r.title ?? undefined}>
                        <span className="line-clamp-2">{r.title || r.product || t("noTitle")}</span>
                      </button>
                      {r.product && <span className="block truncate text-xs text-gray-500" title={r.product}>{[r.vendor, r.product].filter(Boolean).join(" · ")}</span>}
                    </TableCell>
                    <TableCell className={`${cellEnd} align-top`}>
                      <Link to={`/vulnerabilities?byfix=${encodeURIComponent(r.id)}`} onClick={(e) => e.stopPropagation()} className="text-brand-600 hover:underline"><Num value={r.cves} /></Link>
                      {r.kevCves > 0 && <span className="block text-xs text-red-700">{t("kevCves", { count: r.kevCves })}</span>}
                    </TableCell>
                    <TableCell className={`${cellEnd} align-top font-medium text-gray-800`}><Num value={r.p1} /></TableCell>
                    <TableCell className={`${cellEnd} align-top`}>
                      <Num value={r.hosts} />
                      {r.internetHosts > 0 && <span className="block text-xs text-sky-700">{tv("internetCount", { count: r.internetHosts })}</span>}
                    </TableCell>
                    <TableCell className={`${cell} ps-6 align-top whitespace-nowrap`}>
                      {r.severity ? <SeverityBadge severity={r.severity} /> : "–"}
                      {r.exprt && <span className="ms-1.5 text-xs text-gray-500">ExPRT {tSev(r.exprt.toUpperCase() === "UNKNOWN" ? "NONE" : r.exprt.toUpperCase())}</span>}
                    </TableCell>
                    <TableCell className={`${cellEnd} align-top whitespace-nowrap`}>{r.ageDays != null ? tv("days", { count: Math.round(r.ageDays) }) : "–"}</TableCell>
                    <TableCell className={`${cellEnd} align-top`}>
                      {r.impactShare != null ? (
                        <span className="inline-flex items-center gap-2" title={t("impactHint")}>
                          <span className="h-1.5 w-12 overflow-hidden rounded-full bg-gray-100"><span className="block h-full bg-brand-500" style={{ width: `${Math.max(3, (r.impactShare / maxShare) * 100)}%` }} /></span>
                          <span className="w-12 text-end">{(r.impactShare * 100).toFixed(1)}%</span>
                        </span>
                      ) : "–"}
                    </TableCell>
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
  );
}
