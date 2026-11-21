import { useDrawers } from "@/components/shared/drawers-context";
import { ErrorState } from "@/components/shared/empty-state";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { ChartCardSkeleton, FormSkeleton } from "@/components/shared/skeletons";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { formatDate, formatDateTime, formatNumber } from "@/utils/format";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { CertExpiry, type AssetRow } from "./common";

interface Service {
  port: number; transport: string | null; protocol: string | null; status: string | null; statusCode: number | null; os: string | null; firstSeen: number | null; lastSeen: number | null; risky: boolean;
  applications?: { vendor: string | null; name: string | null; category: string | null; version: string | null; cpe: string | null }[];
  tls: { version: string | null; issuer: string | null; subject: string | null; validFrom: number | null; validTo: number | null; expired: boolean; expiresInDays: number | null; signature: string | null; fingerprint: string | null } | null;
}
interface Detail extends AssetRow {
  ptr: string | null; region: string | null;
  discovery?: { entity: string; type: string | null; clue: string | null }[];
  services?: Service[];
  vulnerabilities?: { cve: string; severity: string; baseScore: number | null; exprt: string | null; kev: boolean; product: string | null }[];
}

const h4 = "mb-1.5 text-sm font-semibold text-gray-800";
const th = "py-1 pe-3 text-start text-xs font-medium whitespace-nowrap text-gray-500";
const td = "py-1.5 pe-3 align-top text-sm text-gray-600";

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg bg-gray-50 px-3 py-2">
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-medium text-gray-800 tabular-nums">{children}</dd>
    </div>
  );
}

/** One external asset (?asset=<id>): identity, discovery path, services with TLS expiry, linked CVEs. Hidden, not closed, while a CVE drawer is open on top. */
export function AssetDrawer() {
  const t = useTranslations("easmAssets");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { cve, device, software, openCve } = useDrawers();
  const [params, setParams] = useSearchParams();
  const id = params.get("asset");
  const [last, setLast] = useState<string | null>(id);
  if (id && id !== last) setLast(id);
  const { data, error, reload } = useApi<Detail>(id ? scoped(`/api/exposure/easm/assets/${encodeURIComponent(id)}`) : null);
  const close = () => setParams((p) => { const x = new URLSearchParams(p); x.delete("asset"); return x; }, { replace: true });
  const n = (v: number) => formatNumber(v, locale);
  const d = data && id && data.id === id ? data : null;
  const dash = (v: string | number | null | undefined) => (v === null || v === undefined || v === "" ? "–" : String(v));
  const place = d ? [d.city, d.region, d.country].filter(Boolean).join(", ") : "";

  return (
    <Sheet open={id !== null && !cve && !device && !software} onOpenChange={(o) => { if (!o) close(); }}>
      <SheetContent className="gap-3 overflow-y-auto p-4 data-[side=right]:w-full data-[side=right]:sm:w-[60vw] data-[side=right]:sm:max-w-none" data-testid="asset-drawer">
        <SheetHeader className="p-0 pe-8">
          <SheetTitle className="flex flex-wrap items-center gap-2">
            <span className="break-all">{d?.name ?? (last && !error ? "…" : t("drawer.title"))}</span>
            {d?.isNew && <Badge size="sm" color="primary" className="[text-shadow:none]">{t("new")}</Badge>}
            {d && <Badge size="sm" color={d.reviewed ? "success" : "warning"} className="[text-shadow:none]">{d.reviewed ? t("review.reviewed") : t("review.notReviewed")}</Badge>}
          </SheetTitle>
          <SheetDescription>{t("drawer.sub")}</SheetDescription>
        </SheetHeader>
        {error ? (error.status === 404 ? <p className="text-sm text-gray-500">{t("drawer.gone")}</p> : <ErrorState error={error} onRetry={reload} />) : !d ? (
          <div className="space-y-3"><FormSkeleton fields={3} /><ChartCardSkeleton className="h-40" /></div>
        ) : (
          <div className="flex min-w-0 flex-col gap-3">
            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              <Fact label={t("drawer.type")}>{d.type === "ip" ? "IP" : dash(d.dnsType ?? d.type)}</Fact>
              <Fact label={t("columns.perimeter")}>{d.perimeter === "official" ? t("perimeter.official") : d.perimeter === "unofficial" ? t("perimeter.unofficial") : "–"}</Fact>
              <Fact label={t("drawer.status")}>{d.status === "online" ? t("online") : d.status === "offline" ? t("offline") : dash(d.status)}</Fact>
              <Fact label={t("drawer.criticality")}>{dash(d.criticality)}</Fact>
              <Fact label={t("drawer.ip")}>{dash(d.ip)}</Fact>
              <Fact label={t("drawer.fqdn")}>{dash(d.fqdn)}</Fact>
              <Fact label={t("drawer.ptr")}>{dash(d.ptr)}</Fact>
              <Fact label={t("drawer.location")}>{place || "–"}</Fact>
              <Fact label={t("drawer.asn")}>{d.asn != null ? `AS${d.asn}${d.isp ? ` · ${d.isp}` : ""}` : dash(d.isp)}</Fact>
              <Fact label={t("drawer.cloud")}>{dash(d.cloud)}</Fact>
              <Fact label={t("columns.firstSeen")}>{formatDate(d.firstSeen, locale) ?? "–"}</Fact>
              <Fact label={t("drawer.lastSeen")}>{formatDateTime(d.lastSeen, locale) ?? "–"}</Fact>
            </dl>

            <section aria-label={t("drawer.services")}>
              <h4 className={h4}>{t("drawer.services")} <span className="font-normal text-gray-500">{d.services?.length ?? d.serviceCount ?? 0 ? `(${n(d.services?.length ?? d.serviceCount ?? 0)})` : ""}</span></h4>
              {!d.services || d.services.length === 0 ? (
                <p className="rounded-lg border border-gray-200 p-3 text-sm text-gray-500">{d.serviceCount === null || d.serviceCount === undefined ? t("drawer.noServiceData") : t("drawer.noServices")}</p>
              ) : (
                <div className="max-w-full overflow-x-auto rounded-lg border border-gray-200">
                  <table className="w-full min-w-[34rem]">
                    <thead className="border-b border-gray-100"><tr><th className={`${th} ps-3`}>{t("drawer.port")}</th><th className={th}>{t("drawer.app")}</th><th className={th}>{t("drawer.tls")}</th></tr></thead>
                    <tbody className="divide-y divide-gray-100">
                      {d.services.map((s) => (
                        <tr key={`${s.port}-${s.transport}`} data-testid="asset-service">
                          <td className={`${td} ps-3 whitespace-nowrap`}>
                            <span className={s.risky ? "rounded bg-red-50 px-1 font-medium text-red-700 tabular-nums" : "tabular-nums"}>{s.port}</span>
                            <span className="ms-1 text-xs text-gray-500">{[s.transport, s.protocol].filter(Boolean).join("/")}</span>
                            {s.risky && <span className="mt-0.5 block text-xs font-medium text-red-700">{t("riskyPort")}</span>}
                            {s.statusCode != null && <span className="block text-xs text-gray-400">HTTP {s.statusCode}</span>}
                          </td>
                          <td className={td}>
                            {(s.applications ?? []).slice(0, 3).map((a, i) => <span key={i} className="block">{[a.vendor, a.name, a.version].filter(Boolean).join(" ")}</span>)}
                            {!(s.applications ?? []).length && <span className="text-gray-400">–</span>}
                            {s.os && <span className="block text-xs text-gray-400">{s.os}</span>}
                          </td>
                          <td className={td}>
                            {s.tls ? (
                              <>
                                <CertExpiry validTo={s.tls.validTo} expired={s.tls.expired} expiresInDays={s.tls.expiresInDays} />
                                {s.tls.issuer && <span className="block max-w-56 truncate text-xs text-gray-400" title={s.tls.issuer}>{s.tls.issuer}</span>}
                              </>
                            ) : <span className="text-gray-400">–</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section aria-label={t("drawer.discovery")}>
              <h4 className={h4}>{t("drawer.discovery")}</h4>
              {!d.discovery || d.discovery.length === 0 ? <p className="text-sm text-gray-500">{t("drawer.noDiscovery")}</p> : (
                <ol className="space-y-1 rounded-lg border border-gray-200 p-3 text-sm">
                  {d.discovery.map((s, i) => (
                    <li key={i} className="flex gap-2"><span className="w-5 shrink-0 text-end text-xs text-gray-400 tabular-nums">{i + 1}</span><span className="min-w-0"><span className="font-medium break-all text-gray-800">{s.entity}</span>{s.type && <span className="ms-1 text-xs text-gray-500">({s.type})</span>}{s.clue && <span className="block text-xs text-gray-500">{s.clue}</span>}</span></li>
                  ))}
                </ol>
              )}
            </section>

            <section aria-label={t("drawer.vulns")}>
              <h4 className={h4}>{t("drawer.vulns")} {d.findings?.count ? <span className="font-normal text-gray-500">({n(d.findings.count)})</span> : null}</h4>
              {!d.vulnerabilities || d.vulnerabilities.length === 0 ? <p className="text-sm text-gray-500">{t("drawer.noVulns")}</p> : (
                <ul className="divide-y divide-gray-100 rounded-lg border border-gray-200">
                  {d.vulnerabilities.map((v) => (
                    <li key={v.cve}>
                      <button type="button" onClick={() => openCve(v.cve)} className="flex w-full flex-wrap items-center gap-2 px-3 py-1.5 text-start hover:bg-gray-50">
                        <span className="text-sm font-medium text-gray-800">{v.cve}</span>
                        <SeverityBadge severity={v.severity} />
                        {v.kev && <Badge variant="light" color="error" size="sm">KEV</Badge>}
                        <span className="text-xs text-gray-500 tabular-nums">{v.baseScore ? v.baseScore.toFixed(1) : ""}</span>
                        {v.product && <span className="ms-auto max-w-48 truncate text-xs text-gray-500" title={v.product}>{v.product}</span>}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
