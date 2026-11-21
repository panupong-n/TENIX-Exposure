import { DataStatus } from "@/components/shared/data-status";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/shared/empty-state";
import { PaginationBar } from "@/components/shared/pagination-bar";
import { SearchInput } from "@/components/shared/search-input";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { useLocale, useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { formatDate, formatNumber } from "@/utils/format";
import { useSearchParams } from "react-router";
import { CertExpiry, PortChips, cell, head, type AssetRow } from "./common";

interface Result { state?: "complete" | "partial" | "failed" | "not_synced" | "no_cids"; asOf?: number | null; total: number; page: number; pageSize: number; items: AssetRow[] }
interface ServicesSummary { assetsWithServices?: number; services?: number; expiredCerts?: number; expiringCerts30?: number; riskyPorts?: number; assetsWithRiskyPorts?: number; assetsWithExpiredCert?: number; newLast7d?: number }

const KEYS = ["q", "type", "perimeter", "review", "status", "sort", "expiredCert", "expiringCert", "riskyPort", "isNew"] as const;

/** The external asset list (contract B): ports, TLS expiry, risky ports, location. Filters live in the URL; a row opens the asset drawer (?asset=). */
export function AssetList() {
  const t = useTranslations("easmAssets");
  const locale = useLocale();
  const { scoped } = useOrg();
  const [, setParams] = useSearchParams();
  const { values, text, onText, set, page } = useUrlFilters(KEYS, { sort: "triage" });
  const qs = new URLSearchParams({ page: String(page), pageSize: "25", sort: values.sort });
  for (const k of KEYS) if (k !== "sort" && values[k]) qs.set(k, values[k]);
  const { data, error, loading, reload } = useApi<Result>(scoped(`/api/exposure/easm/assets?${qs}`));
  const sum = useApi<ServicesSummary>(scoped("/api/exposure/easm/services"));
  const s = sum.data;
  const n = (v: number) => formatNumber(v, locale);
  const filtered = KEYS.some((k) => k !== "sort" && values[k]);
  const open = (id: string) => setParams((p) => { const x = new URLSearchParams(p); x.set("asset", id); return x; });

  const pick = (key: string, items: { value: string; label: string }[], label: string, width = "sm:w-44") => (
    <Select value={values[key] || "all"} onValueChange={(v) => set({ [key]: v === "all" ? null : String(v) })} items={items}>
      <SelectTrigger size="default" className={`w-full ${width}`} aria-label={label} data-testid={`easm-${key}`}><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  );
  const all = (label: string) => ({ value: "all", label });
  const toggle = (key: "expiredCert" | "expiringCert" | "riskyPort" | "isNew", label: string, count?: number, tone = "red") => (
    <button key={key} type="button" aria-pressed={values[key] === "1"} data-testid={`easm-${key}`} onClick={() => set({ [key]: values[key] === "1" ? null : "1" })}
      className={cn("flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-sm transition-colors", values[key] === "1" ? "border-brand-500 bg-brand-50 text-brand-700" : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50")}>
      <span className={cn("size-2 rounded-full", tone === "red" ? "bg-red-500" : tone === "amber" ? "bg-amber-500" : "bg-brand-500")} aria-hidden="true" />
      {label}
      {typeof count === "number" && <span className="font-semibold tabular-nums">{n(count)}</span>}
    </button>
  );
  const noServiceData = s && !s.assetsWithServices && data && data.total > 0 && !filtered;

  return (
    <section className="rounded-xl border border-gray-200 bg-white px-3 pt-3 pb-3 sm:px-4" aria-labelledby="easm-assets-h">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="easm-assets-h" className="text-sm leading-6 font-semibold text-gray-800">{t("title")}</h2>
        {s && s.services !== undefined && <p className="text-xs text-gray-500">{t("servicesLine", { assets: n(s.assetsWithServices ?? 0), services: n(s.services) })}</p>}
      </div>
      {data?.state && data.state !== "complete" && <div className="mb-2"><DataStatus completeness={{ state: data.state, asOf: data.asOf ?? null, lastRunAt: null }} /></div>}
      {noServiceData && <p className="mb-2 rounded-lg bg-sky-50 px-3 py-1.5 text-sm text-sky-800">{t("noServiceData")}</p>}
      <div className="mb-2 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center sm:gap-2">
        <div className="col-span-2 sm:col-span-1"><SearchInput value={text} onChange={onText} placeholder={t("searchPlaceholder")} /></div>
        {pick("type", [all(t("allTypes")), { value: "ip", label: "IP" }, { value: "dns_domain", label: t("type.dns") }, { value: "root", label: t("type.root") }, { value: "sub", label: t("type.sub") }], t("filters.type"))}
        {pick("perimeter", [all(t("allPerimeters")), { value: "official", label: t("perimeter.official") }, { value: "unofficial", label: t("perimeter.unofficial") }], t("filters.perimeter"))}
        {pick("review", [all(t("allReviews")), { value: "not_reviewed", label: t("review.notReviewed") }, { value: "reviewed", label: t("review.reviewed") }], t("filters.review"))}
        {pick("sort", ["triage", "name", "lastSeen", "firstSeen", "findings"].map((v) => ({ value: v, label: t(`sort.${v}`) })), t("filters.sort"), "col-span-2 sm:col-span-1 sm:w-60")}
      </div>
      <div className="mb-3 flex flex-wrap gap-2">
        {toggle("expiredCert", t("filters.expiredCert"), s?.assetsWithExpiredCert)}
        {toggle("expiringCert", t("filters.expiringCert"), s?.expiringCerts30, "amber")}
        {toggle("riskyPort", t("filters.riskyPort"), s?.assetsWithRiskyPorts)}
        {toggle("isNew", t("filters.isNew"), s?.newLast7d, "brand")}
      </div>

      {error ? <ErrorState error={error} onRetry={reload} /> : !data ? <TableSkeleton /> : data.items.length === 0 ? (
        <EmptyState title={filtered ? t("empty.filteredTitle") : t("empty.title")}>{filtered ? t("empty.filtered") : data.state && data.state !== "complete" ? t("empty.unknown") : t("empty.none")}</EmptyState>
      ) : (
        <div className={cn("transition-opacity duration-200", loading && "opacity-60")}>
          <ul className="divide-y divide-gray-100 lg:hidden">
            {data.items.map((r) => (
              <li key={r.id}>
                <button type="button" onClick={() => open(r.id)} className="flex w-full flex-col gap-1 py-2 text-start" data-testid="easm-asset-row">
                  <span className="flex items-center justify-between gap-2">
                    <span className="min-w-0 truncate text-sm font-medium text-gray-800">{r.name}</span>
                    <span className="flex shrink-0 gap-1">{r.isNew && <Badge variant="light" color="primary" size="sm">{t("new")}</Badge>}{!r.reviewed && <Badge variant="light" color="warning" size="sm">{t("review.notReviewed")}</Badge>}</span>
                  </span>
                  <PortChips ports={r.ports} risky={r.riskyPorts} />
                  <span className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                    <CertExpiry validTo={r.nearestCertExpiry} />
                    {r.findings && r.findings.count > 0 && r.findings.worstSeverity && <><SeverityBadge severity={r.findings.worstSeverity} /><span>{n(r.findings.count)}</span></>}
                    {r.country && <span>{r.country}</span>}
                  </span>
                </button>
              </li>
            ))}
          </ul>
          <div className="hidden max-w-full overflow-x-auto lg:block">
            <Table>
              <TableHeader className="border-y border-gray-100">
                <TableRow>
                  <TableCell isHeader className={head}>{t("columns.asset")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.type")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.review")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.ports")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.cert")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.findings")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.location")}</TableCell>
                  <TableCell isHeader className={head}>{t("columns.firstSeen")}</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-gray-100">
                {data.items.map((r) => (
                  <TableRow key={r.id} onClick={() => open(r.id)} className="cursor-pointer align-top transition-colors hover:bg-gray-50" data-testid="easm-asset-row">
                    <TableCell className="max-w-64 py-1.5 pe-3">
                      <button type="button" onClick={(e) => { e.stopPropagation(); open(r.id); }} className="block max-w-full truncate text-start text-sm font-medium text-gray-800 hover:text-brand-500" title={r.name}>{r.name}</button>
                      <span className="flex flex-wrap items-center gap-1 text-xs text-gray-500">
                        {r.isNew && <Badge variant="light" color="primary" size="sm">{t("new")}</Badge>}
                        {r.perimeter === "official" ? t("perimeter.official") : r.perimeter === "unofficial" ? t("perimeter.unofficial") : null}
                        {r.status && <span>· {r.status === "online" ? t("online") : r.status === "offline" ? t("offline") : r.status}</span>}
                      </span>
                    </TableCell>
                    <TableCell className={cell}>{r.type === "ip" ? "IP" : r.type === "root" ? t("type.root") : r.type === "sub" ? t("type.sub") : r.type === "dns_domain" ? t("type.dns") : r.type}</TableCell>
                    <TableCell className="py-1.5 pe-3"><Badge variant="light" color={r.reviewed ? "success" : "warning"} size="sm">{r.reviewed ? t("review.reviewed") : t("review.notReviewed")}</Badge></TableCell>
                    <TableCell className="max-w-44 py-1.5 pe-3"><PortChips ports={r.ports} risky={r.riskyPorts} /></TableCell>
                    <TableCell className={cell}><CertExpiry validTo={r.nearestCertExpiry} />{(r.expiredCerts ?? 0) > 1 && <span className="ms-1 text-xs text-gray-500">{t("certCount", { n: r.expiredCerts ?? 0 })}</span>}</TableCell>
                    <TableCell className="py-1.5 pe-3">
                      {r.findings && r.findings.count > 0 ? <span className="flex items-center gap-1.5">{r.findings.worstSeverity && <SeverityBadge severity={r.findings.worstSeverity} />}<span className="text-sm text-gray-600 tabular-nums">{n(r.findings.count)}</span></span> : <span className="text-gray-400">–</span>}
                    </TableCell>
                    <TableCell className={`${cell} max-w-40`}>
                      <span className="block truncate" title={[r.city, r.country].filter(Boolean).join(", ")}>{[r.city, r.country].filter(Boolean).join(", ") || "–"}</span>
                      {r.asn != null && <span className="text-xs text-gray-400">AS{r.asn}</span>}
                    </TableCell>
                    <TableCell className={`${cell} whitespace-nowrap`}>{formatDate(r.firstSeen, locale) ?? "–"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
      {data && data.total > 0 && <div className="mt-3"><PaginationBar page={data.page} pageSize={data.pageSize} total={data.total} onPage={(p) => set({ page: String(p) })} /></div>}
    </section>
  );
}
