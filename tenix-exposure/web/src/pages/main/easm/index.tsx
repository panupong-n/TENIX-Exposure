import { DataStatus } from "@/components/shared/data-status";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { Donut, type DonutSlice } from "@/components/shared/donut";
import { BarList } from "@/components/shared/bar-list";
import { NoDataArt } from "@/components/shared/illustrations";
import { MaskReveal } from "@/components/shared/mask-reveal";
import { PageMeta } from "@/components/shared/page-meta";
import { ChartCardSkeleton, StatCardsSkeleton } from "@/components/shared/skeletons";
import { AssetDrawer } from "./asset-drawer";
import { AssetList } from "./assets";
import { Tile } from "@/pages/main/dashboard/overview/tile";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { BarChartIcon, GlobeIcon, LayerIcon, SystemIcon, TelescopeIcon, type IconProps } from "@/icons";
import { SEVERITY_COLOR } from "@/lib/chart";
import { formatDateTime, formatNumber } from "@/utils/format";
import type { ComponentType, ReactNode } from "react";

type Counts = Record<string, number>;
interface Easm {
  state: "complete" | "partial" | "failed" | "not_synced" | "no_cids";
  asOf: number | null;
  lastRunAt: number | null;
  assets: { ips: number; rootDomains: number; subdomains: number };
  perimeter: Counts;
  reviewIps: { reviewed: number; notReviewed: number };
  reviewRootDomains: { reviewed: number; notReviewed: number };
  online: Counts;
  discoveredBy: Counts;
  cloud: { k: string; n: number }[];
  findings: { total: number; assets: number; byExprt: Counts; byType: Counts; bySeverity: Counts };
}

const BRAND = "#465FFF", LIGHT = "#9CB9FF", GREY = "#98A2B3";
const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const CAT_COLORS = [BRAND, LIGHT, GREY];

export default function EasmPage() {
  const t = useTranslations("easm");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { data, error, reload } = useApi<Easm>(scoped("/api/exposure/easm"));
  const n = (v: number) => formatNumber(v, locale);
  const asOf = data ? formatDateTime(data.asOf, locale) : null;
  const footer = <p className="mt-auto border-t border-gray-100 pt-2 text-xs leading-5 text-gray-500">{asOf ? t("updated", { time: asOf }) : t("notUpdated")}</p>;
  const tile = (title: string, icon: ComponentType<IconProps>, children: ReactNode, note?: string) => (
    <Tile title={title} icon={icon} note={note}>
      <div className="flex flex-1 flex-col gap-3">
        <div className="flex flex-1 flex-col justify-center">{children}</div>
        {footer}
      </div>
    </Tile>
  );
  const unknownLabel = (k: string) => (k === "unknown" || k === "" ? t("unknown") : k);

  const pair = (a: string, b: string, x: { reviewed: number; notReviewed: number }): DonutSlice[] => [
    { key: "a", label: a, value: x.reviewed, color: BRAND },
    { key: "b", label: b, value: x.notReviewed, color: LIGHT },
  ];

  let body: ReactNode;
  if (error) body = <ErrorState error={error} onRetry={reload} />;
  else if (!data) {
    body = (
      <div className="space-y-3">
        <StatCardsSkeleton />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }, (_, i) => <ChartCardSkeleton key={i} className="h-36" />)}
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {Array.from({ length: 2 }, (_, i) => <ChartCardSkeleton key={i} className="h-36" />)}
        </div>
      </div>
    );
  } else {
    const { assets, findings: f } = data;
    const empty = assets.ips + assets.rootDomains + assets.subdomains + f.total === 0;
    const kpis = [
      { key: "ips", label: t("kpi.ips"), value: assets.ips },
      { key: "roots", label: t("kpi.rootDomains"), value: assets.rootDomains },
      { key: "subs", label: t("kpi.subdomains"), value: assets.subdomains },
      { key: "findings", label: t("kpi.findings"), value: f.total, note: t("kpi.findingsNote", { assets: n(f.assets) }) },
    ];
    const exprt: DonutSlice[] = [
      ...SEV_ORDER.map((s) => ({ key: s, label: tSev(s), value: f.byExprt[s] ?? 0, color: SEVERITY_COLOR[s] })),
      ...Object.entries(f.byExprt)
        .filter(([k]) => !(SEV_ORDER as readonly string[]).includes(k) && k !== "UNKNOWN")
        .map(([k, v]) => ({ key: k, label: k, value: v, color: SEVERITY_COLOR.NONE })),
      { key: "UNKNOWN", label: t("unknown"), value: f.byExprt.UNKNOWN ?? 0, color: GREY },
    ];
    const types: DonutSlice[] = Object.entries(f.byType).sort((a, b) => b[1] - a[1]).map(([k, v], i) => ({
      key: k, label: k === "Vulnerability" ? t("type.vulnerability") : k === "Misconfiguration" ? t("type.misconfiguration") : k === "Other" ? t("type.other") : k, value: v, color: CAT_COLORS[i % 3],
    }));
    const perimeter: DonutSlice[] = Object.entries(data.perimeter).sort((a, b) => b[1] - a[1]).map(([k, v], i) => ({
      key: k, label: k === "official" ? t("perimeter.official") : k === "unofficial" ? t("perimeter.unofficial") : unknownLabel(k), value: v, color: k === "unknown" ? GREY : CAT_COLORS[i % 2],
    }));
    const online: DonutSlice[] = Object.entries(data.online).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({
      key: k, label: k === "online" ? t("online.online") : k === "offline" ? t("online.offline") : unknownLabel(k), value: v, color: k === "online" ? BRAND : k === "offline" ? LIGHT : GREY,
    }));
    const found = Object.entries(data.discoveredBy).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({
      key: k, label: k === "surface" ? t("found.surface") : k === "user" ? t("found.user") : k === "aws" ? "AWS" : unknownLabel(k), value: v, color: BRAND,
    }));
    body = (
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          {kpis.map((k) => (
            <div key={k.key} className="min-w-0 rounded-xl border border-gray-200 bg-white p-3 sm:p-4">
              <p className="text-sm leading-6 font-medium text-gray-600">{k.label}</p>
              <p className="text-3xl leading-10 font-bold text-brand-950 tabular-nums">{n(k.value)}</p>
              {k.note && <p className="text-xs leading-5 text-gray-500">{k.note}</p>}
            </div>
          ))}
        </div>
        {empty ? (
          <div className="rounded-xl border border-gray-200 bg-white">
            <EmptyState title={t("empty.title")} art={<NoDataArt className="h-24 w-32" />}>{t("empty.body")}</EmptyState>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {tile(t("tiles.exprt"), BarChartIcon, <Donut title={t("tiles.exprt")} slices={exprt} caption={t("center.findings")} />)}
              {tile(t("tiles.type"), BarChartIcon, <Donut title={t("tiles.type")} slices={types} caption={t("center.findings")} />)}
              {tile(t("tiles.perimeter"), GlobeIcon, <Donut title={t("tiles.perimeter")} slices={perimeter} caption={t("center.ips")} />)}
              {tile(t("tiles.reviewIps"), GlobeIcon, <Donut title={t("tiles.reviewIps")} slices={pair(t("review.reviewed"), t("review.notReviewed"), data.reviewIps)} caption={t("center.ips")} />)}
              {tile(t("tiles.reviewRoots"), GlobeIcon, <Donut title={t("tiles.reviewRoots")} slices={pair(t("review.reviewed"), t("review.notReviewed"), data.reviewRootDomains)} caption={t("center.domains")} />)}
              {tile(t("tiles.online"), SystemIcon, <Donut title={t("tiles.online")} slices={online} caption={t("center.ips")} />)}
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {tile(t("tiles.found"), TelescopeIcon, <BarList rows={found} emptyText={t("noData")} />, t("tiles.foundNote"))}
              {tile(t("tiles.cloud"), LayerIcon, <BarList rows={data.cloud.map((c) => ({ key: c.k, label: c.k, value: c.n, color: BRAND }))} emptyText={t("noData")} />, t("tiles.cloudNote"))}
            </div>
          </>
        )}
      </div>
    );
  }

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <div className="mb-3">
        <MaskReveal as="h1" className="text-lg font-semibold text-gray-800">{t("title")}</MaskReveal>
        <p className="text-sm leading-6 text-gray-500">{t("description")}</p>
      </div>
      <div className="mb-3 min-h-6">
        {data && (data.state === "complete" ? (
          <p className="flex items-center gap-2 text-sm leading-6 text-gray-500">
            <span className="size-2 shrink-0 rounded-full bg-green-500" aria-hidden="true" />
            {asOf ? t("asOf", { time: asOf }) : t("notUpdated")}
          </p>
        ) : (
          <DataStatus completeness={{ state: data.state, dataAsOf: data.asOf, lastRunAt: data.lastRunAt }} />
        ))}
      </div>
      {body}
      {data && !error && <div className="mt-3"><AssetList /></div>}
      <AssetDrawer />
    </>
  );
}
