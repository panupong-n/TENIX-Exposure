// Skeleton: while the hosts load, Slot (parts.tsx) renders a ChartCardSkeleton.
import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState } from "@/components/shared/empty-state";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { WatchStar } from "@/components/shared/watch-star";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { CheckCircleIcon, LayoutGridIcon, SystemIcon } from "@/icons";
import { cn } from "@/utils";
import { formatAgo } from "@/utils/format";
import { Link } from "react-router";
import { LINK, NUM, ROW, Slot, useDeviceName, useFmt } from "./parts";
import { Tile } from "./tile";
import type { HostsV2, SoftwareList } from "./types";

/** Block F: the six hosts with the most P1 (P1, Critical, KEV), a star to watch each, the row opens the device drawer. */
export function TopDevices({ stale }: { stale: boolean }) {
  const t = useTranslations("ovw.f");
  const f = useFmt();
  const name = useDeviceName();
  const { scoped } = useOrg();
  const { openDevice } = useDrawers();
  const res = useApi<HostsV2>(scoped("/api/exposure/v2/hosts?sort=p1&pageSize=6"));
  return (
    <Slot res={res} h="h-56">
      {(d) => {
        const rows = d.rows.filter((r) => r.p1 > 0 || r.critical > 0);
        const withP1 = d.facets?.withP1;
        return (
          <Tile title={t("title")} note={t("note")} icon={SystemIcon} actions={stale ? <StaleStamp /> : undefined} className="h-full">
            {rows.length === 0 ? (
              <EmptyState title={t("emptyTitle")} art={<CheckCircleIcon className="size-8 text-green-500" aria-hidden="true" />}>{t("emptyBody")}</EmptyState>
            ) : (
              <>
                <div className="grid grid-cols-[1.5rem_minmax(0,1fr)_3.5rem] items-center gap-x-1 pb-1 text-xs leading-4 text-gray-500 sm:grid-cols-[1.5rem_minmax(0,1fr)_3.5rem_3.5rem_3.5rem]" aria-hidden="true">
                  <span /><span>{t("col.host")}</span><span className={NUM}>P1</span><span className={cn(NUM, "max-sm:hidden")}>Critical</span><span className={cn(NUM, "max-sm:hidden")}>KEV</span>
                </div>
                {rows.map((r) => (
                  <div key={r.key} className={cn(ROW, "grid grid-cols-[1.5rem_minmax(0,1fr)_3.5rem] items-center gap-x-1 py-1 sm:grid-cols-[1.5rem_minmax(0,1fr)_3.5rem_3.5rem_3.5rem]")}>
                    <WatchStar aid={r.aid} hostname={r.hostname} />
                    <button type="button" onClick={() => openDevice(r.aid)} className="min-w-0 rounded text-start hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="truncate text-sm leading-5 font-medium text-gray-900" title={r.hostname ?? r.aid}>{name(r.hostname, r.aid)}</span>
                        {r.internetFacing && <span className="shrink-0 rounded bg-sky-50 px-1.5 text-xs leading-5 font-medium text-sky-700">{t("internet")}</span>}
                      </span>
                      <span className="block truncate text-xs leading-4 text-gray-500">{[r.productType, r.osVersion ?? r.platform].filter(Boolean).join(" · ")}{r.lastSeen && <span className="max-sm:hidden"> · {formatAgo(r.lastSeen, f.locale)}</span>}</span>
                    </button>
                    <span className={cn(NUM, "text-sm font-semibold")}>{f.cell(r.p1)}</span>
                    <span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.critical)}</span>
                    <span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.kevCves)}</span>
                  </div>
                ))}
                <div className="mt-auto pt-2 text-end text-xs leading-5"><Link to="/devices?tier=P1" className={LINK}>{withP1 != null ? t("all", { n: f.n(withP1) }) : t("allNo")}</Link></div>
              </>
            )}
          </Tile>
        );
      }}
    </Slot>
  );
}

/** Block G: the products with the most devices. P1 / KEV columns appear when the server sends them; its own stale stamp when the software read failed. */
export function TopSoftware({ res }: { res: { data: SoftwareList | null; error: import("@/lib/api").ApiError | null; reload: () => void } }) {
  const t = useTranslations("ovw.g");
  const f = useFmt();
  const { openSoftware } = useDrawers();
  return (
    <Slot res={res} h="h-56">
      {(d) => {
        const rows = d.rows.slice(0, 6);
        const hasCve = rows.some((r) => r.p1Cves != null);
        const old = d.completeness?.state === "failed";
        const cols = hasCve ? "grid-cols-[minmax(0,1fr)_3rem_3.5rem] sm:grid-cols-[minmax(0,1fr)_3.5rem_3.5rem_3.5rem_3.5rem]" : "grid-cols-[minmax(0,1fr)_3.5rem_3.5rem]";
        return (
          <Tile title={t("title")} note={hasCve ? t("note") : t("noteDevices")} icon={LayoutGridIcon} actions={old ? <StaleStamp /> : undefined} className="h-full">
            {rows.length === 0 ? (
              <EmptyState title={t("emptyTitle")}>{t("emptyBody")}</EmptyState>
            ) : (
              <>
                <div className={cn("grid items-center gap-x-1 pb-1 text-xs leading-4 text-gray-500", cols)} aria-hidden="true">
                  <span>{t("col.product")}</span><span className={cn(NUM, "max-sm:hidden")}>{t("col.versions")}</span><span className={NUM}>{t("col.devices")}</span>
                  {hasCve && <><span className={NUM}>{t("col.p1")}</span><span className={cn(NUM, "max-sm:hidden")}>KEV</span></>}
                </div>
                {rows.map((r) => (
                  <button key={r.key} type="button" onClick={() => openSoftware(r.key)} className={cn(ROW, "grid items-center gap-x-1 py-1 text-start hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", cols)}>
                    <span className="min-w-0"><span className="block truncate text-sm leading-5 font-medium text-gray-900" title={r.name}>{r.name}</span><span className="block truncate text-xs leading-4 text-gray-500">{r.vendor}</span></span>
                    <span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.versions)}</span>
                    <span className={cn(NUM, "text-sm")}>{f.cell(r.devices)}</span>
                    {hasCve && <><span className={cn(NUM, "text-sm font-semibold")}>{f.cell(r.p1Cves)}</span><span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.kevCves)}</span></>}
                  </button>
                ))}
                <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2 text-xs leading-5 text-gray-500">
                  <span className="tabular-nums">{t("total", { n: f.n(d.total), devices: f.n(d.devices) })}</span>
                  <Link to="/software" className={LINK}>{t("all")}</Link>
                </div>
              </>
            )}
          </Tile>
        );
      }}
    </Slot>
  );
}
