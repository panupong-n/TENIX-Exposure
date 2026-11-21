import { DrawerBack } from "@/components/shared/drawer-back";
import { useDrawers } from "@/components/shared/drawers-context";
import { DataStatus, type Completeness } from "@/components/shared/data-status";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { ChartCardSkeleton, FormSkeleton } from "@/components/shared/skeletons";
import { ReasonChips } from "@/components/shared/reason-chips";
import { TierBadge } from "@/components/shared/tier-badge";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { reasonKeys, type VulnRow } from "@/components/shared/list-kit";
import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { Link } from "react-router";
import { formatDate, formatNumber } from "@/utils/format";

interface Item {
  found: boolean;
  completeness: Completeness;
  type?: string;
  vendor?: string;
  name?: string;
  category?: string | null;
  suspicious?: boolean;
  threat?: string | null;
  latest?: string | null;
  link?: string | null;
  hostApp?: string | null;
  firstSeen?: number | null;
  updatedAt?: number | null;
  devices?: number;
  instances?: number;
  versions?: { version: string; devices: number }[];
  hosts?: { aid: string | null; hostname: string | null; platform: string | null; version: string; enabled: number | null; firstSeen: number | null }[];
}

const head = "py-1.5 pe-3 text-start text-xs font-medium whitespace-nowrap text-gray-500 dark:text-gray-400";
const cell = "py-1.5 pe-3 text-sm text-gray-600 dark:text-gray-300";
const box = "rounded-lg border border-gray-200 p-3 dark:border-gray-800";
const h4 = "mb-1.5 text-sm font-semibold text-gray-800 dark:text-white/90";

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg bg-gray-50 px-3 py-2 dark:bg-white/3">
      <dt className="text-xs text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-medium text-gray-800 tabular-nums dark:text-white/90">{children}</dd>
    </div>
  );
}

export default function SoftwareSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const t = useTranslations("software");
  const tc = useTranslations("common");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { openDevice, openCve, openFix, close } = useDrawers();
  const tl = useTranslations("lists2.softwareDrawer");
  const { data, error, reload } = useApi<Item>(id ? scoped(`/api/exposure/software/${encodeURIComponent(id)}`) : null);
  const shown = id && data ? data : null;
  // CVEs of this product: the v2 list searched by the product name (it matches CVE id or product), worst first; fixes come from the same rows
  const cves = useApi<{ rows: VulnRow[]; total: number }>(shown?.found && shown.name ? scoped(`/api/exposure/v2/vulnerabilities?q=${encodeURIComponent(shown.name)}&pageSize=10`) : null);
  const fixes = new Map<string, string | null>();
  for (const r of cves.data?.rows ?? []) if (r.fix) fixes.set(r.fix.id, r.fix.title);
  const link = shown?.link && /^https?:\/\//i.test(shown.link) ? shown.link : null;

  return (
    <Sheet open={id !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="gap-3 overflow-y-auto p-4 data-[side=right]:w-full data-[side=right]:sm:w-[60vw] data-[side=right]:sm:max-w-none">
        <SheetHeader className="p-0 pe-8">
          <DrawerBack />
          <SheetTitle className="flex flex-wrap items-center gap-2">
            <span className="break-all">{shown?.found ? shown.name : error ? t("sheet.title") : tc("loading")}</span>
            {shown?.found && shown.type && <Badge size="sm" color="gray" className="[text-shadow:none]">{t(`types.${shown.type}`)}</Badge>}
            {shown?.found && shown.suspicious && <Badge size="sm" color="error" className="[text-shadow:none]">{t("flagged")}</Badge>}
          </SheetTitle>
          <SheetDescription>{shown?.found ? (shown.vendor || t("unknownVendor")) : ""}</SheetDescription>
        </SheetHeader>

        <div className="min-h-5 shrink-0"><DataStatus completeness={data?.completeness} /></div>

        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !shown ? (
          <div className="space-y-3"><FormSkeleton fields={2} /><ChartCardSkeleton className="h-48" /></div>
        ) : !shown.found ? (
          <EmptyState title={t("sheet.notFound")}>{t("sheet.notFoundHelp")}</EmptyState>
        ) : (
          <div className="space-y-3">
            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Fact label={t("devices")}>{formatNumber(shown.devices ?? 0, locale)}</Fact>
              <Fact label={t("versions")}>{formatNumber(shown.versions?.length ?? 0, locale)}</Fact>
              {shown.category && <Fact label={t("category")}>{shown.category}</Fact>}
              {shown.firstSeen && <Fact label={t("firstSeen")}>{formatDate(shown.firstSeen, locale) ?? "–"}</Fact>}
              {shown.latest && <Fact label={t("latestAvailable")}>{shown.latest}</Fact>}
              {shown.threat && <Fact label={t("threat")}>{shown.threat}</Fact>}
              {shown.hostApp && <Fact label={t("hostApp")}>{shown.hostApp}</Fact>}
            </dl>
            {link && <p className="truncate text-xs"><a href={link} target="_blank" rel="noopener noreferrer" className="text-brand-600 underline dark:text-brand-400">{link}</a></p>}

            <div className="grid gap-3 lg:grid-cols-2">
              <section className={box}>
                <h4 className={h4}>{t("installedVersions")}</h4>
                <ul className="space-y-1 text-sm text-gray-700 tabular-nums dark:text-gray-300">
                  {shown.versions?.map((v) => (
                    <li key={v.version || "?"} className="flex items-baseline justify-between gap-3">
                      <span className="truncate">{v.version || t("noVersion")}</span>
                      <span className="shrink-0 text-xs text-gray-500 dark:text-gray-400">{t("deviceCount", { count: v.devices })}</span>
                    </li>
                  ))}
                </ul>
              </section>
              <section className={box}>
                <h4 className={h4}>{t("about")}</h4>
                <p className="text-sm text-gray-600 dark:text-gray-300">{t(`typeHelp.${shown.type}`)}</p>
              </section>
            </div>

            <section className={box}>
              <h4 className={h4}>{tl("cvesTitle")}</h4>
              {cves.error ? <p className="text-sm text-gray-500">{tl("cvesError")}</p> : !cves.data ? (
                <div className="h-10 animate-pulse rounded bg-gray-100" data-slot="skeleton" />
              ) : cves.data.rows.length === 0 ? <p className="text-sm text-gray-600">{tl("noCves")}</p> : (
                <ul className="divide-y divide-gray-100">
                  {cves.data.rows.map((r) => (
                    <li key={r.cveId} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 py-1.5">
                      {r.tier && <TierBadge tier={r.tier} help={false} />}
                      <button type="button" onClick={() => openCve(r.cveId)} className="text-sm font-medium text-gray-800 hover:text-brand-500">{r.cveId}</button>
                      <SeverityBadge severity={r.severity} />
                      <ReasonChips reasons={reasonKeys(r)} max={2} />
                      <span className="ms-auto text-xs text-gray-500">{tl("cveDevices", { count: r.hosts })}</span>
                    </li>
                  ))}
                </ul>
              )}
              {cves.data && cves.data.total > cves.data.rows.length && <Link to={`/vulnerabilities?q=${encodeURIComponent(shown.name ?? "")}`} onClick={() => close()} className="mt-1.5 block text-xs font-medium text-brand-600 hover:underline">{tl("allCves", { count: formatNumber(cves.data.total, locale) })}</Link>}
              {fixes.size > 0 && (
                <div className="mt-2 border-t border-gray-100 pt-2">
                  <div className="text-xs text-gray-500">{tl("fixes")}</div>
                  <ul className="space-y-0.5 text-sm">
                    {[...fixes].map(([fid, title]) => <li key={fid}><button type="button" onClick={() => openFix(fid)} className="max-w-full truncate text-start text-brand-600 hover:underline">{title || tl("openFix")}</button></li>)}
                  </ul>
                </div>
              )}
            </section>

            <section className={box}>
              <h4 className={h4}>{t("onDevices")}</h4>
              <div className="max-w-full overflow-x-auto">
                <Table>
                  <TableHeader className="border-y border-gray-100 dark:border-gray-800">
                    <TableRow>
                      <TableCell isHeader className={head}>{t("device")}</TableCell>
                      <TableCell isHeader className={head}>{t("platform")}</TableCell>
                      <TableCell isHeader className={head}>{t("version")}</TableCell>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="divide-y divide-gray-100 dark:divide-gray-800">
                    {shown.hosts?.map((h, i) => (
                      <TableRow key={`${h.aid ?? h.hostname}-${i}`}>
                        <TableCell className={cell}>
                          {h.aid ? (
                            <button type="button" onClick={() => openDevice(h.aid!)} className="text-start font-medium whitespace-nowrap text-gray-800 hover:text-brand-500 dark:text-white/90 dark:hover:text-brand-400">
                              {h.hostname ?? <span className="text-gray-600 italic dark:text-gray-400">{tc("unnamedDevice")}</span>}
                            </button>
                          ) : (
                            <span className="font-medium whitespace-nowrap text-gray-800 dark:text-white/90">{h.hostname ?? <span className="text-gray-600 italic dark:text-gray-400">{tc("unnamedDevice")}</span>}</span>
                          )}
                        </TableCell>
                        <TableCell className={cell}>{h.platform ?? "–"}</TableCell>
                        <TableCell className={`${cell} tabular-nums`}>{h.version || "–"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {(shown.devices ?? 0) > (shown.hosts?.length ?? 0) && (
                <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">{t("showing", { shown: formatNumber(shown.hosts?.length ?? 0, locale), total: formatNumber(shown.devices ?? 0, locale) })}</p>
              )}
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
