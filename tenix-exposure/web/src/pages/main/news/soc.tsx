import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { formatAgo, formatDateTime, formatNumber } from "@/utils/format";
import { StateBadge, cell, head, headEnd, host, safeUrl, type NewsState } from "./common";

interface SocItem {
  cve: string; title: string | null; kev: boolean; cvss: number | null; publishedAt: number | null; firstSeen: number | null; newsCount: number; sources: string[];
  exactTenants: number; possibleTenants: number; totalDevices: number;
  tenants: { tenantId: string; tenant: string; state: NewsState; devices: number; notifiedAt: number | null }[];
}
interface SocResult { counts?: Partial<Record<NewsState, number>>; total: number; page?: number; pageSize?: number; items: SocItem[] }

/** SOC only: one row per CVE with every organization it touches (customers never see this). */
export function SocNews({ values, page, set, filtered }: { values: Record<string, string>; page: number; set: (p: Record<string, string | null>) => void; filtered: boolean }) {
  const t = useTranslations("newsPage");
  const locale = useLocale();
  const { openCve } = useDrawers();
  const qs = new URLSearchParams({ page: String(page), pageSize: "25", days: values.days });
  if (values.q) qs.set("q", values.q);
  if (values.state) qs.set("state", values.state);
  const { data, error, reload } = useApi<SocResult>(`/api/exposure/news-soc?${qs}`);
  const n = (v: number) => formatNumber(v, locale);
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return <TableSkeleton />;
  if (!data.items.length) return <EmptyState title={filtered ? t("empty.filteredTitle") : t("empty.title")}>{filtered ? t("empty.filtered") : t("empty.none")}</EmptyState>;
  return (
    <>
      <p className="mb-2 text-xs text-gray-500">{t("soc.note")}</p>
      <div className="max-w-full overflow-x-auto">
        <Table>
          <TableHeader className="border-y border-gray-100">
            <TableRow>
              <TableCell isHeader className={head}>{t("columns.cve")}</TableCell>
              <TableCell isHeader className={head}>{t("soc.tenants")}</TableCell>
              <TableCell isHeader className={headEnd}>{t("columns.cvss")}</TableCell>
              <TableCell isHeader className={headEnd}>{t("soc.totalDevices")}</TableCell>
              <TableCell isHeader className={`${head} ps-6`}>{t("columns.source")}</TableCell>
              <TableCell isHeader className={head}>{t("columns.time")}</TableCell>
            </TableRow>
          </TableHeader>
          <TableBody className="divide-y divide-gray-100">
            {data.items.map((r) => (
              <TableRow key={r.cve} className="align-top hover:bg-gray-50" data-testid="news-soc-row">
                <TableCell className="max-w-sm py-1.5 pe-4">
                  <button type="button" onClick={() => openCve(r.cve)} className="block text-start text-sm font-medium whitespace-nowrap text-gray-800 hover:text-brand-500">{r.cve}</button>
                  {r.kev && <Badge variant="light" color="error" size="sm" className="me-1">KEV</Badge>}
                  {r.title && <span className="line-clamp-2 text-xs text-gray-500" title={r.title}>{r.title}</span>}
                </TableCell>
                <TableCell className="py-1.5 pe-4">
                  <ul className="flex flex-wrap gap-1">
                    {r.tenants.slice(0, 6).map((x) => (
                      <li key={x.tenantId} className="flex items-center gap-1 rounded-md border border-gray-200 py-0.5 ps-1.5 pe-0.5 text-xs text-gray-700">
                        <span className="max-w-32 truncate" title={x.tenant}>{x.tenant}</span><StateBadge state={x.state} devices={x.devices} />
                      </li>
                    ))}
                    {r.tenants.length > 6 && <li className="py-0.5 text-xs text-gray-500">{t("moreHosts", { n: r.tenants.length - 6 })}</li>}
                    {r.tenants.length === 0 && <li className="text-xs text-gray-400">{t("soc.none")}</li>}
                  </ul>
                </TableCell>
                <TableCell className={`${cell} text-end tabular-nums`}>{r.cvss ? r.cvss.toFixed(1) : "–"}</TableCell>
                <TableCell className={`${cell} text-end tabular-nums`}>{n(r.totalDevices)}</TableCell>
                <TableCell className={`${cell} ps-6`}>
                  {r.sources[0] && safeUrl(r.sources[0]) ? <a href={r.sources[0]} target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:text-brand-700">{host(r.sources[0])}</a> : "–"}
                  {r.newsCount > 1 && <span className="ms-1 text-xs text-gray-400">{t("newsCount", { n: r.newsCount })}</span>}
                </TableCell>
                <TableCell className={`${cell} whitespace-nowrap`} title={formatDateTime(r.firstSeen, locale) ?? undefined}>{formatAgo(r.firstSeen ?? r.publishedAt, locale) ?? "–"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="mt-3"><PaginationBar page={data.page ?? page} pageSize={data.pageSize ?? 25} total={data.total} onPage={(p) => set({ page: String(p) })} /></div>
    </>
  );
}
