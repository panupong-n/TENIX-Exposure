import { completeAsOf, DataStrip, isStale, type Completeness } from "@/components/shared/data-status";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { RetentionBanner } from "@/components/shared/retention-banner";
import { PageMeta } from "@/components/shared/page-meta";
import { ChartCardSkeleton, StatCardsSkeleton } from "@/components/shared/skeletons";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/contexts/auth-context";
import { useOrg, usePortfolioView } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { DownloadIcon } from "@/icons";
import { cn } from "@/utils";
import { useMemo } from "react";
import { useSearchParams } from "react-router";
import { Easm } from "./easm";
import FixFirst from "./fixes";
import Headline from "./headline";
import { Health } from "./health";
import { News } from "./news";
import PortfolioView from "./portfolio";
import { Severity, Tiers } from "./tiers";
import { TopDevices, TopSoftware } from "./top-lists";
import Trend from "./trend";
import type { EasmV2, SoftwareList, SummaryV2 } from "./types";
import Watchlist from "./watchlist";

/*
 * 12-column grid. xl: A 5 | B 7, then two independent columns (no row gaps when one block is short): left 8 = C, K, F, G; right 4 = D, E, H, I, J.
 * md: A, B 12; C, K 12; F 6 + G 6; D 6 + E 6; H, I, J 12. Phone: every block 12 in the order of the design (A, C, K, D, B, E, F, G, I, H, J):
 * each block carries its phone `order-N`, which `md:order-none` hands back to the DOM order.
 */
const PHONE = ["", "order-1", "order-2", "order-3", "order-4", "order-5", "order-6", "order-7", "order-8", "order-9", "order-10", "order-11"];
const B = (phone: number, cls: string) => cn(PHONE[phone], "min-w-0 md:order-none", cls);

/** Normalise Falcon's coverage so DataStrip can tell "complete for the priority slice" (blue) from "complete" (green). */
function normalise(c: Completeness): Completeness {
  const cov = c.coverage;
  if (!cov || cov.mode || c.state !== "complete" || !cov.falconTotal || cov.held >= cov.falconTotal) return c;
  return { ...c, coverage: { ...cov, mode: "priority" } };
}

function Customer() {
  const t = useTranslations("ovw");
  const { user } = useAuth();
  const { scoped } = useOrg();
  const res = useApi<SummaryV2>(scoped("/api/exposure/v2/summary"));
  const software = useApi<SoftwareList>(scoped("/api/exposure/software?sort=risk&pageSize=6"));
  const easm = useApi<EasmV2>(scoped("/api/exposure/easm"));
  const data = res.data;
  const completeness = useMemo(() => (data ? normalise(data.completeness) : undefined), [data]);

  if (res.error && !data) return <div className="rounded-xl border border-gray-200 bg-white"><ErrorState error={res.error} onRetry={res.reload} /></div>;
  if (!data || !completeness) {
    return (
      <div className="space-y-3" aria-busy="true">
        <Skeleton className="h-9 w-full rounded-lg" aria-hidden="true" />
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-12 xl:col-span-5"><ChartCardSkeleton className="h-60" /></div>
          <div className="col-span-12 xl:col-span-7"><ChartCardSkeleton className="h-60" /></div>
          <div className="col-span-12 xl:col-span-8"><ChartCardSkeleton className="h-72" /></div>
          <div className="col-span-12 xl:col-span-4"><StatCardsSkeleton count={2} /></div>
        </div>
      </div>
    );
  }

  const stale = isStale(completeness);
  const asOf = completeAsOf(completeness);
  // nothing trustworthy to show: never read, or no connection and nothing ever read. A designed empty state, never zeros.
  const noData = completeness.state === "not_synced" || completeness.state === "no_cids" || (stale && !asOf);
  const soc = !!user?.soc;
  const csv = scoped("/api/exposure/v2/fixes.csv");
  const btn = "inline-flex h-8 items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 text-xs font-medium whitespace-nowrap text-gray-700 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-gray-300/50 focus-visible:outline-none";

  return (
    <div className="grid grid-cols-12 gap-3">
      <div className="col-span-12 flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="min-w-0 flex-1 basis-80"><DataStrip completeness={completeness} whyHref="#coverage" /></div>
        {!noData && (
          <div className="flex shrink-0 flex-wrap gap-2 print:hidden">
            <button type="button" className={btn} onClick={() => window.print()}>{t("exec")}</button>
            {csv && <a className={btn} href={csv}><DownloadIcon className="size-4" aria-hidden="true" />{t("csv")}</a>}
          </div>
        )}
      </div>

      {noData ? (
        <>
          <div className="col-span-12 rounded-xl border border-gray-200 bg-white">
            <EmptyState title={t(`noData.${completeness.state === "not_synced" ? "not_synced" : "none"}`)}>{completeness.state === "not_synced" ? t("noData.afterFirst") : soc ? t("noData.steps") : t("noData.ask")}</EmptyState>
          </div>
          <div className="col-span-12 xl:col-span-8"><Watchlist stale={false} /></div>
          <div className="col-span-12 xl:col-span-4"><Health data={data} software={software.data} easm={easm.data} /></div>
        </>
      ) : (
        <>
          <div className={B(1, "col-span-12 xl:col-span-5")}><Headline data={data} stale={stale} /></div>
          <div className={B(5, "col-span-12 xl:col-span-7")}><Trend stale={stale} /></div>
          <div className="col-span-12 contents xl:col-span-8 xl:flex xl:flex-col xl:gap-3">
            <div className={B(2, "col-span-12")}><FixFirst stale={stale} /></div>
            <div className={B(3, "col-span-12")}><Watchlist stale={stale} /></div>
            <div className={B(7, "col-span-12 md:col-span-6 xl:col-span-12")}><TopDevices stale={stale} /></div>
            <div className={B(8, "col-span-12 md:col-span-6 xl:col-span-12")}><TopSoftware res={software} /></div>
          </div>
          <div className="col-span-12 contents xl:col-span-4 xl:flex xl:flex-col xl:gap-3">
            <div className={B(4, "col-span-12 md:col-span-6")}><Tiers data={data} stale={stale} /></div>
            <div className={B(6, "col-span-12 md:col-span-6")}><Severity data={data} stale={stale} /></div>
            <div className={B(10, "col-span-12 empty:hidden")}><Easm res={easm} /></div>
            <div className={B(9, "col-span-12")}><News /></div>
            <div id="coverage" className={B(11, "col-span-12")}><Health data={data} software={software.data} easm={easm.data} /></div>
          </div>
        </>
      )}
      <footer className="order-12 col-span-12 border-t border-gray-200 pt-3 text-xs leading-5 text-gray-500 md:order-none">{t("footer")} · <span className="font-medium text-gray-600">10CYBER by TENFORWARD</span></footer>
    </div>
  );
}

export default function OverviewPage() {
  const t = useTranslations("ovw");
  const th = useTranslations("header");
  const { user } = useAuth();
  const { scoped, orgs, orgId, setOrgId, loading: orgsLoading } = useOrg();
  const [params, setParams] = useSearchParams();
  const soc = !!user?.soc;
  const all = usePortfolioView(params.toString());
  const hasScope = scoped("/x") !== null;
  const view = (v: "org" | "all") => {
    if (v === "org" && orgId) setOrgId(orgId); // remembered, so "/" stays on the organization
    setParams((p) => { const n = new URLSearchParams(p); if (v === "all") n.set("view", "all"); else n.delete("view"); return n; }, { replace: true });
  };

  return (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h1 className="min-w-0 text-lg leading-8 font-semibold text-gray-800">{all ? t("titleAll") : t("title")}</h1>
        {soc && (
          <div role="group" aria-label={t("view")} className="flex overflow-hidden rounded-lg border border-gray-200 bg-white text-sm">
            {(["org", "all"] as const).map((v) => (
              <button key={v} type="button" aria-pressed={(v === "all") === all} onClick={() => view(v)} className={cn("h-8 px-3 font-medium", (v === "all") === all ? "bg-brand-50 text-brand-700" : "text-gray-600 hover:bg-gray-50")}>{t(`view_${v}`)}</button>
            ))}
          </div>
        )}
      </div>
      {!all && <div className="mb-3"><RetentionBanner /></div>}
      {all ? (
        <PortfolioView />
      ) : !hasScope && !orgsLoading ? (
        <p className="text-sm leading-6 text-gray-500">{orgs.length === 0 ? th("noOrganizations") : th("selectOrganization")}</p>
      ) : (
        <Customer />
      )}
    </>
  );
}
