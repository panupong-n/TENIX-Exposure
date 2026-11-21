// Skeleton: while the news loads, Slot (parts.tsx) renders a ChartCardSkeleton.
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState } from "@/components/shared/empty-state";
import { ReasonChips } from "@/components/shared/reason-chips";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { CheckCircleIcon, InboxIcon } from "@/icons";
import { cn } from "@/utils";
import { formatAgo } from "@/utils/format";
import { Link } from "react-router";
import { LINK, Slot, useFmt } from "./parts";
import { Tile } from "./tile";
import type { NewsItem, NewsV2 } from "./types";

const STATE: Record<NewsItem["state"], string> = { exact: "text-red-700", possible: "text-amber-700", wait: "text-gray-600", not_affected: "text-green-700" };

/** Block I: CVE news that affects me. Four cards (three on a phone): CVE, headline, state chip (กระทบ N เครื่อง / อาจกระทบ / รอ Falcon / ไม่กระทบ), age. */
export function News() {
  const t = useTranslations("ovw.i");
  const f = useFmt();
  const { scoped } = useOrg();
  const { openCve } = useDrawers();
  const res = useApi<NewsV2>(scoped("/api/exposure/news?days=7&pageSize=4"));
  return (
    <Slot res={res} h="h-44">
      {(d) => (
        <Tile title={t("title")} note={t("note")} icon={InboxIcon} className="h-full">
          {d.items.length === 0 ? (
            <EmptyState title={t("emptyTitle")} art={<CheckCircleIcon className="size-8 text-green-500" aria-hidden="true" />}>{t("emptyBody")}</EmptyState>
          ) : (
            <div className="grid gap-x-4 sm:grid-cols-2 xl:grid-cols-1">
              {d.items.slice(0, 4).map((n, i) => (
                <div key={n.cve} className={cn("border-t border-gray-100 py-1.5 first:border-t-0 sm:[&:nth-child(2)]:border-t-0 xl:[&:nth-child(2)]:border-t", i >= 3 && "max-sm:hidden")}>
                  <div className="flex items-start justify-between gap-2">
                    <button type="button" onClick={() => openCve(n.cve)} className="flex min-w-0 flex-wrap items-center gap-1.5 rounded text-start focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                      <span className="text-sm leading-5 font-semibold text-gray-900 hover:text-brand-700">{n.cve}</span>
                      {n.kev && <ReasonChips reasons={["kev"]} />}
                      {n.severity && <SeverityBadge severity={n.severity} />}
                    </button>
                    <span className={cn("shrink-0 text-end text-xs leading-5 font-medium", STATE[n.state])}>
                      {n.state === "exact" ? <Link to={`/devices?cve=${encodeURIComponent(n.cve)}`} className="hover:underline">{t("state.exact", { n: f.n(n.devices) })}</Link> : t(`state.${n.state}`)}
                    </span>
                  </div>
                  <p className="truncate text-xs leading-5 text-gray-500" title={n.title ?? undefined}>{n.title ?? "—"}{(n.lastChanged ?? n.publishedAt) && ` · ${formatAgo(n.lastChanged ?? n.publishedAt, f.locale)}`}</p>
                </div>
              ))}
            </div>
          )}
          <div className="mt-auto pt-2 text-end text-xs leading-5"><Link to="/news" className={LINK}>{t("all", { n: f.n(d.total) })}</Link></div>
        </Tile>
      )}
    </Slot>
  );
}
