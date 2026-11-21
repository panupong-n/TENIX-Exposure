import { DataStrip, isStale, type Completeness } from "@/components/shared/data-status";
import { DrawerBack } from "@/components/shared/drawer-back";
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { Num, box, cell, cellEnd, h4, head, headEnd, safeUrl } from "@/components/shared/list-kit";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { ChartCardSkeleton, FormSkeleton } from "@/components/shared/skeletons";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { TierBadge, type Tier } from "@/components/shared/tier-badge";
import { WatchStar } from "@/components/shared/watch-star";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { formatDate, formatNumber } from "@/utils/format";
import { Link } from "react-router";

interface Detail {
  id: string; title: string | null; actions?: string[]; links?: { action: string | null; link: string; type?: string | null }[];
  product: string | null; noFix?: boolean;
  versions?: { version: string; devices: number }[];
  summary: {
    p1: number; p2: number; p3: number; cves: number; p1Cves?: number; kevCves: number; hosts: number; p1Hosts?: number; internetHosts: number;
    severity: string | null; exprt: string | null; firstSeen: number | null; ageDays: number | null; impactShare: number | null;
  };
  cves: { total: number; rows: { cveId: string; tier: Tier; severity: string; baseScore: number | null; exprt: string | null; kev: boolean; kevDueDate?: string | null; overdue?: boolean; hosts: number }[] };
  hosts: { total: number; rows: { aid: string; hostname: string | null; platform: string | null; osVersion?: string | null; localIp: string | null; lastSeen: number | null; stale?: string; internetFacing?: boolean; fixP1?: number; fixFindings?: number }[] };
  completeness?: Completeness;
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg bg-gray-50 px-3 py-2">
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-medium text-gray-800 tabular-nums">{children}</dd>
    </div>
  );
}

/** One remediation (?fix=<id>): what to do, the CVEs it closes, the devices to touch. The hand-off for the IT team. */
export default function FixSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const t = useTranslations("lists2.fix");
  const tc = useTranslations("common");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { openCve, openDevice } = useDrawers();
  const path = id ? `/api/exposure/v2/fixes/${encodeURIComponent(id)}` : null;
  const { data, error, reload } = useApi<Detail>(path ? scoped(path) : null);
  const shown = id && data?.id === id ? data : null;
  const s = shown?.summary;
  const stale = isStale(shown?.completeness);
  const title = shown ? shown.title || (shown.noFix && shown.product ? t("noFixTitle", { product: shown.product }) : t("untitled")) : null;
  const links = (shown?.links ?? []).filter((l) => safeUrl(l.link));
  const csv = id ? scoped(`/api/exposure/v2/fixes/${encodeURIComponent(id)}/hosts.csv`) : null;

  return (
    <Sheet open={id !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="gap-3 overflow-y-auto p-4 data-[side=right]:w-full data-[side=right]:sm:w-[60vw] data-[side=right]:sm:max-w-none">
        <SheetHeader className="p-0 pe-8">
          <DrawerBack />
          <SheetTitle className="flex flex-wrap items-center gap-2">
            <span className="min-w-0 break-words">{shown ? title : error ? t("title") : tc("loading")}</span>
            {s?.severity && <SeverityBadge severity={s.severity} />}
            {stale && <StaleStamp since={null} />}
          </SheetTitle>
          <SheetDescription>{shown?.product ?? t("subtitle")}</SheetDescription>
        </SheetHeader>

        {shown?.completeness && <div className="min-h-5 shrink-0"><DataStrip completeness={shown.completeness} /></div>}

        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !shown || !s ? (
          <div className="space-y-3"><FormSkeleton fields={2} /><ChartCardSkeleton className="h-48" /></div>
        ) : (
          <div className="space-y-3">
            <section className={box}>
              <h4 className={h4}>{t("what")}</h4>
              {shown.noFix || (!shown.actions?.length && !links.length) ? (
                <p className="text-sm text-gray-600">{shown.product ? t("noFixBody", { product: shown.product }) : t("noFixGeneric")}</p>
              ) : (
                <ul className="list-disc space-y-1 ps-4 text-sm text-gray-700">
                  {(shown.actions ?? []).slice(0, 8).map((a) => <li key={a}>{a.replace(/^- /, "")}</li>)}
                </ul>
              )}
              {links.length > 0 && (
                <ul className="mt-2 space-y-0.5 text-xs">
                  {links.map((l) => (
                    <li key={l.link} className="truncate">
                      <a href={l.link} target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">{l.action ? `${l.action} · ` : ""}{l.link}</a>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Fact label={t("facts.p1")}><Num value={s.p1} context="tile" /></Fact>
              <Fact label={t("facts.cves")}><Num value={s.cves} context="tile" />{s.kevCves > 0 && <span className="ms-1.5 text-xs font-normal text-red-700">{t("kevCves", { count: s.kevCves })}</span>}</Fact>
              <Fact label={t("facts.hosts")}><Num value={s.hosts} context="tile" /></Fact>
              <Fact label={t("facts.internet")}><Num value={s.internetHosts} context="tile" /></Fact>
              {s.impactShare != null && <Fact label={t("facts.impact")}>{(s.impactShare * 100).toFixed(1)}%</Fact>}
              {s.firstSeen && <Fact label={t("facts.firstSeen")}>{formatDate(s.firstSeen, locale) ?? "–"}</Fact>}
              {s.exprt && <Fact label="ExPRT">{tSev(s.exprt.toUpperCase() === "UNKNOWN" ? "NONE" : s.exprt.toUpperCase())}</Fact>}
              <Fact label={t("facts.tiers")}>{`${formatNumber(s.p1, locale)} · ${formatNumber(s.p2, locale)} · ${formatNumber(s.p3 ?? 0, locale)}`}</Fact>
            </dl>

            {shown.versions && shown.versions.length > 0 && (
              <section className={box}>
                <h4 className={h4}>{t("versions")}</h4>
                <ul className="space-y-1 text-sm text-gray-700 tabular-nums">
                  {shown.versions.map((v) => <li key={v.version} className="flex justify-between gap-3"><span className="truncate">{v.version}</span><span className="text-xs text-gray-500">{t("deviceCount", { count: v.devices })}</span></li>)}
                </ul>
              </section>
            )}

            <section className={box}>
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-sm font-semibold text-gray-800">{t("cvesTitle", { count: formatNumber(shown.cves.total, locale) })}</h4>
                {shown.cves.total > shown.cves.rows.length && <Link to={`/vulnerabilities?byfix=${encodeURIComponent(shown.id)}`} className="text-xs font-medium text-brand-600 hover:underline">{t("allCves")}</Link>}
              </div>
              <div className="max-w-full overflow-x-auto">
                <Table>
                  <TableHeader className="border-y border-gray-100">
                    <TableRow>
                      <TableCell isHeader className={head}>{t("columns.tier")}</TableCell>
                      <TableCell isHeader className={head}>CVE</TableCell>
                      <TableCell isHeader className={head}>{t("columns.severity")}</TableCell>
                      <TableCell isHeader className={head}>KEV</TableCell>
                      <TableCell isHeader className={headEnd}>{t("columns.devices")}</TableCell>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="divide-y divide-gray-100">
                    {shown.cves.rows.map((c) => (
                      <TableRow key={c.cveId}>
                        <TableCell className="py-1.5 pe-3"><TierBadge tier={c.tier} help={false} /></TableCell>
                        <TableCell className={`${cell} font-medium whitespace-nowrap`}><button type="button" onClick={() => openCve(c.cveId)} className="text-gray-800 hover:text-brand-500">{c.cveId}</button></TableCell>
                        <TableCell className="py-1.5 pe-3"><SeverityBadge severity={c.severity} />{c.baseScore ? <span className="ms-1.5 text-xs text-gray-500 tabular-nums">{c.baseScore.toFixed(1)}</span> : null}</TableCell>
                        <TableCell className={cell}>{c.kev ? <span className={c.overdue ? "font-medium text-red-700" : "text-red-700"}>KEV{c.overdue ? ` · ${t("overdue")}` : ""}</span> : "–"}</TableCell>
                        <TableCell className={cellEnd}><Num value={c.hosts} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </section>

            <section className={box}>
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-sm font-semibold text-gray-800">{t("hostsTitle", { count: formatNumber(shown.hosts.total, locale) })}</h4>
                {csv && <a href={csv} download className="text-xs font-medium text-brand-600 hover:underline">{t("exportHosts")}</a>}
              </div>
              {shown.hosts.rows.length === 0 ? <EmptyState>{t("noHosts")}</EmptyState> : (
                <div className="max-w-full overflow-x-auto">
                  <Table>
                    <TableHeader className="border-y border-gray-100">
                      <TableRow>
                        <TableCell isHeader className={`${head} w-8`}><span className="sr-only">{t("watch")}</span></TableCell>
                        <TableCell isHeader className={head}>{t("columns.device")}</TableCell>
                        <TableCell isHeader className={head}>{t("columns.os")}</TableCell>
                        <TableCell isHeader className={head}>IP</TableCell>
                        <TableCell isHeader className={headEnd}>P1</TableCell>
                        <TableCell isHeader className={`${head} ps-4`}>{t("columns.lastSeen")}</TableCell>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="divide-y divide-gray-100">
                      {shown.hosts.rows.map((h) => (
                        <TableRow key={h.aid}>
                          <TableCell className="py-1 pe-1"><WatchStar aid={h.aid} hostname={h.hostname} /></TableCell>
                          <TableCell className={`${cell} font-medium whitespace-nowrap`}>
                            <button type="button" onClick={() => openDevice(h.aid)} className="text-gray-800 hover:text-brand-500">{h.hostname ?? <span className="text-gray-600 italic">{tc("unnamedDevice")}</span>}</button>
                            {h.internetFacing && <span className="ms-1.5 rounded-md bg-sky-50 px-1.5 text-xs font-medium text-sky-700">{t("internet")}</span>}
                          </TableCell>
                          <TableCell className={cell}>{h.osVersion ?? h.platform ?? "–"}</TableCell>
                          <TableCell className={`${cell} tabular-nums`}>{h.localIp ?? "–"}</TableCell>
                          <TableCell className={cellEnd}><Num value={h.fixP1} /></TableCell>
                          <TableCell className={`${cell} ps-4 whitespace-nowrap`}>
                            {formatDate(h.lastSeen, locale) ?? "–"}
                            {h.stale && h.stale !== "fresh" && h.stale !== "unknown" && <StaleStamp className="ms-1.5" since={formatDate(h.lastSeen, locale)} />}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
              {shown.hosts.total > shown.hosts.rows.length && <p className="mt-2 text-xs text-gray-500">{t("showing", { shown: formatNumber(shown.hosts.rows.length, locale), total: formatNumber(shown.hosts.total, locale) })}</p>}
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
