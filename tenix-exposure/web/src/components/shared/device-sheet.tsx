import { DataStrip, isStale, type Completeness } from "@/components/shared/data-status";
import { DrawerBack } from "@/components/shared/drawer-back";
import { useDrawers } from "@/components/shared/drawers-context";
import { ErrorState } from "@/components/shared/empty-state";
import { Num, box, cell, cellEnd, h4, head, headEnd, type VulnRow } from "@/components/shared/list-kit";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { ChartCardSkeleton, FormSkeleton } from "@/components/shared/skeletons";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { TierBadge, type Tier } from "@/components/shared/tier-badge";
import { WatchStar } from "@/components/shared/watch-star";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHeader, TableRow } from "@/components/ui/table";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { SEVERITIES } from "@/lib/chart";
import { formatAgo, formatDate, formatDateTime, formatNumber } from "@/utils/format";
import { useState } from "react";
import { Link } from "react-router";

export interface HostV2 {
  key?: string; aid: string; cid?: string; inInventory?: boolean; hostname: string | null; platform: string | null; osVersion: string | null; osBuild: string | null; productType: string | null; criticality: string | null;
  localIp: string | null; externalIp: string | null; agentVersion?: string | null; machineDomain?: string | null; site?: string | null; groups?: string[]; groupsMore?: number; tags?: string[];
  firstSeen: number | null; lastSeen: number | null; daysSinceSeen: number | null; stale: "fresh" | "stale7" | "stale30" | "unknown";
  duplicate: { role: "newest" | "older"; staleTwin: boolean; reason: string; newerAid?: string | null } | null;
  contained?: boolean; reducedFunctionality?: boolean; internetFacing: boolean;
  p1: number; p2: number; p3: number; findings: number; critical: number; kevCves: number; exploited: number; fixes: number; worstSeverity: string | null; tier: Tier | null; watched: boolean | null;
}
interface Detail {
  aid: string; host: HostV2;
  tiers: Record<Tier, number>; severity: Record<string, number>;
  fixes: { id: string; title: string | null; p1: number; p2: number; cves: number; kevCves: number; severity: string }[]; fixesMore: number;
  cves: (Pick<VulnRow, "cveId" | "severity" | "baseScore" | "exprt" | "exploitStatus" | "product"> & { tier: Tier; kev: boolean; fixId: string | null })[]; cvesTotal: number;
  completeness: Completeness;
}

function Fact({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-lg bg-gray-50 px-3 py-2">
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className={mono ? "mt-0.5 font-mono text-xs break-all text-gray-800" : "mt-0.5 truncate text-sm text-gray-800"}>{value ?? "–"}</dd>
    </div>
  );
}

/** The device drawer (?device=<aid>): who it is, what is wrong by tier, and the checklist of fixes to apply on it. */
export default function DeviceSheet({ aid, onClose }: { aid: string | null; onClose: () => void }) {
  const t = useTranslations("lists2.device");
  const tc = useTranslations("common");
  const tg = useTranslations("graph");
  const locale = useLocale();
  const { user } = useAuth();
  const { scoped } = useOrg();
  const { data, error, reload } = useApi<Detail>(aid ? scoped(`/api/exposure/v2/hosts/${encodeURIComponent(aid)}`) : null);
  const shown = aid && data?.aid === aid ? data : null;
  const { openCve, openFix } = useDrawers();
  const [done, setDone] = useState<Set<string>>(new Set()); // the operator's ticks; only for this session of the drawer
  const h = shown?.host;
  const stale = isStale(shown?.completeness) || h?.stale === "stale7" || h?.stale === "stale30";

  // installed software that carries findings: the products of the CVEs listed here (the list is capped, so the counts say "at least")
  const products = new Map<string, number>();
  for (const c of shown?.cves ?? []) if (c.product && c.product !== "Unknown") products.set(c.product, (products.get(c.product) ?? 0) + 1);
  const software = [...products].sort((a, b) => b[1] - a[1]);

  return (
    <Sheet open={aid !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="gap-3 overflow-y-auto p-4 data-[side=right]:w-full data-[side=right]:sm:w-[60vw] data-[side=right]:sm:max-w-none">
        <SheetHeader className="p-0 pe-8">
          <DrawerBack />
          <SheetTitle className="flex flex-wrap items-center gap-2">
            <span className="min-w-0 break-all">{h ? (h.hostname ?? tc("unnamedDevice")) : error ? t("title") : tc("loading")}</span>
            {h?.tier && <TierBadge tier={h.tier} />}
            {h && aid && <WatchStar aid={aid} hostname={h.hostname} showLabel />}
          </SheetTitle>
          <SheetDescription>{h ? [h.osVersion ?? h.platform, h.osBuild && `${t("build")} ${h.osBuild}`, h.productType].filter(Boolean).join(" · ") : ""}</SheetDescription>
          {h && <Link to={`/devices?view=graph&focus=${encodeURIComponent(`device:${h.aid}`)}`} className="text-xs leading-5 text-brand-500 hover:underline">{tg("viewInGraph")}</Link>}
        </SheetHeader>

        {shown && <div className="min-h-5 shrink-0"><DataStrip completeness={shown.completeness} /></div>}

        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !shown || !h ? (
          <div className="space-y-3"><FormSkeleton fields={2} /><ChartCardSkeleton className="h-72" /></div>
        ) : (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-1.5">
              {h.internetFacing && <span className="rounded-md bg-sky-50 px-1.5 text-xs leading-5 font-medium text-sky-700">{t("flags.internet")}</span>}
              {h.duplicate && <span className="rounded-md bg-amber-50 px-1.5 text-xs leading-5 font-medium text-amber-800" title={t("flags.duplicateHint", { reason: h.duplicate.reason })}>{h.duplicate.staleTwin ? t("flags.staleTwin") : t("flags.duplicate")}</span>}
              {h.contained && <span className="rounded-md bg-red-50 px-1.5 text-xs leading-5 font-medium text-red-700">{t("flags.contained")}</span>}
              {h.reducedFunctionality && <span className="rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-700">{t("flags.rfm")}</span>}
              {h.inInventory === false && <span className="rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-700" title={t("flags.notInventoryHint")}>{t("flags.notInventory")}</span>}
              {h.criticality && h.criticality.toLowerCase() !== "unassigned" && <span className="rounded-md bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-700">{t("flags.criticality", { v: h.criticality })}</span>}
              {stale && <StaleStamp since={formatDateTime(h.lastSeen, locale)} />}
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
              {(["P1", "P2", "P3"] as const).map((k) => (
                <span key={k} className="inline-flex items-center gap-1.5"><TierBadge tier={k} help={false} /><span className="text-sm font-medium text-gray-700 tabular-nums"><Num value={shown.tiers?.[k] ?? h[k.toLowerCase() as "p1" | "p2" | "p3"]} context="tile" /></span></span>
              ))}
              <span className="h-4 w-px bg-gray-200" aria-hidden="true" />
              {SEVERITIES.filter((s) => (shown.severity?.[s] ?? 0) > 0).map((s) => (
                <span key={s} className="inline-flex items-center gap-1.5"><SeverityBadge severity={s} /><span className="text-sm font-medium text-gray-700 tabular-nums">{formatNumber(shown.severity[s], locale)}</span></span>
              ))}
            </div>

            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
              <Fact label={t("facts.ip")} value={h.localIp} />
              <Fact label={t("facts.externalIp")} value={h.externalIp} />
              <Fact label={t("facts.lastSeen")} value={h.lastSeen ? `${formatDateTime(h.lastSeen, locale)} · ${formatAgo(h.lastSeen, locale)}` : null} />
              <Fact label={t("facts.firstSeen")} value={formatDate(h.firstSeen, locale)} />
              {h.machineDomain && <Fact label={t("facts.domain")} value={h.machineDomain} />}
              {h.site && <Fact label={t("facts.site")} value={h.site} />}
              {h.agentVersion && <Fact label={t("facts.agent")} value={h.agentVersion} />}
              {(h.groups?.length ?? 0) > 0 && <Fact label={t("facts.groups")} value={`${h.groups!.join(", ")}${h.groupsMore ? ` +${h.groupsMore}` : ""}`} />}
              {(h.tags?.length ?? 0) > 0 && <Fact label={t("facts.tags")} value={h.tags!.join(", ")} />}
              <Fact label={t("facts.deviceId")} value={h.aid} mono />
              {user?.soc && <Fact label={t("facts.cid")} value={h.cid ?? null} mono />}
            </dl>

            <section className={box}>
              <h4 className={h4}>{t("checklist")}</h4>
              {shown.fixes.length === 0 ? (
                <p className="text-sm text-gray-600">{shown.completeness.state === "complete" ? t("noFixes") : t("noFixesUnknown")}</p>
              ) : (
                <ul className="divide-y divide-gray-100">
                  {shown.fixes.map((f) => (
                    <li key={f.id} className="flex items-start gap-2.5 py-1.5">
                      <input type="checkbox" aria-label={t("tick", { title: f.title ?? f.id })} checked={done.has(f.id)} className="mt-1 size-4 shrink-0 rounded border-gray-300"
                        onChange={(e) => setDone((d) => { const n = new Set(d); if (e.target.checked) n.add(f.id); else n.delete(f.id); return n; })} />
                      <div className="min-w-0 flex-1">
                        <button type="button" onClick={() => openFix(f.id)} className={`block max-w-full text-start text-sm font-medium hover:text-brand-500 ${done.has(f.id) ? "text-gray-400 line-through" : "text-gray-800"}`}>
                          <span className="line-clamp-2">{f.title || t("untitledFix")}</span>
                        </button>
                        <span className="text-xs text-gray-500">{t("fixLine", { p1: f.p1, p2: f.p2, cves: f.cves })}{f.kevCves > 0 ? ` · KEV ${f.kevCves}` : ""}</span>
                      </div>
                      <SeverityBadge severity={f.severity} />
                    </li>
                  ))}
                </ul>
              )}
              {shown.fixesMore > 0 && <p className="mt-1 text-xs text-gray-500">{t("fixesMore", { count: shown.fixesMore })}</p>}
              <p className="mt-1.5 text-xs text-gray-400">{t("tickNote")}</p>
            </section>

            <section className={box}>
              <h4 className={h4}>{t("cvesTitle", { count: formatNumber(shown.cvesTotal, locale) })}</h4>
              <div className="max-w-full overflow-x-auto">
                <Table>
                  <TableHeader className="border-y border-gray-100">
                    <TableRow>
                      <TableCell isHeader className={head}>{t("columns.tier")}</TableCell>
                      <TableCell isHeader className={head}>CVE</TableCell>
                      <TableCell isHeader className={head}>{t("columns.severity")}</TableCell>
                      <TableCell isHeader className={head}>KEV</TableCell>
                      <TableCell isHeader className={head}>{t("columns.product")}</TableCell>
                      <TableCell isHeader className={headEnd}>{t("columns.fix")}</TableCell>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="divide-y divide-gray-100">
                    {shown.cves.map((c) => (
                      <TableRow key={c.cveId}>
                        <TableCell className="py-1.5 pe-3"><TierBadge tier={c.tier} help={false} /></TableCell>
                        <TableCell className={`${cell} font-medium whitespace-nowrap`}><button type="button" onClick={() => openCve(c.cveId)} className="text-gray-800 hover:text-brand-500">{c.cveId}</button></TableCell>
                        <TableCell className="py-1.5 pe-3"><SeverityBadge severity={c.severity} />{c.baseScore ? <span className="ms-1.5 text-xs text-gray-500 tabular-nums">{c.baseScore.toFixed(1)}</span> : null}</TableCell>
                        <TableCell className={cell}>{c.kev ? <span className="text-red-700">KEV</span> : "–"}</TableCell>
                        <TableCell className={`${cell} max-w-56 truncate`} title={c.product ?? undefined}>{c.product && c.product !== "Unknown" ? c.product : "–"}</TableCell>
                        <TableCell className={cellEnd}>{c.fixId ? <button type="button" onClick={() => openFix(c.fixId!)} className="text-brand-600 hover:underline">{t("openFix")}</button> : "–"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {shown.cvesTotal > shown.cves.length && <p className="mt-2 text-xs text-gray-500">{t("showing", { shown: formatNumber(shown.cves.length, locale), total: formatNumber(shown.cvesTotal, locale) })}</p>}
            </section>

            {software.length > 0 && (
              <section className={box}>
                <h4 className={h4}>{t("software")}</h4>
                <ul className="space-y-1 text-sm text-gray-700">
                  {software.map(([name, n]) => (
                    <li key={name} className="flex items-baseline justify-between gap-3">
                      <Link to={`/software?q=${encodeURIComponent(name)}`} className="truncate hover:text-brand-600 hover:underline">{name}</Link>
                      <span className="shrink-0 text-xs text-gray-500">{t("softwareCves", { count: n })}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
