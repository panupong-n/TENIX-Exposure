// Skeleton: while the fixes load, Slot (parts.tsx) renders a ChartCardSkeleton.
import { EmptyState } from "@/components/shared/empty-state";
import { ReasonChips } from "@/components/shared/reason-chips";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { CheckCircleIcon, DownloadIcon, TaskIcon } from "@/icons";
import { cn } from "@/utils";
import { Link } from "react-router";
import { LINK, NUM, ROW, Slot, useFmt } from "./parts";
import { Tile } from "./tile";
import type { FixesV2 } from "./types";

const COLS = "grid grid-cols-[1.5rem_minmax(0,1fr)] items-center gap-x-2 sm:grid-cols-[1.5rem_minmax(0,1fr)_5.5rem_5rem_5rem_5.5rem]";

/** Block C: fix first. One row = one remediation; the row opens the fix drawer (?fix=). Top 8 on desktop, 5 on a phone. */
export default function FixFirst({ stale }: { stale: boolean }) {
  const t = useTranslations("ovw.c");
  const f = useFmt();
  const { scoped } = useOrg();
  const res = useApi<FixesV2>(scoped("/api/exposure/v2/fixes?pageSize=8"));
  const csv = scoped("/api/exposure/v2/fixes.csv");
  return (
    <Slot res={res} h="h-72">
      {(d) => {
        const rows = d.rows;
        const noP1 = (d.totals?.p1 ?? rows[0]?.p1 ?? 0) === 0;
        const shareTop = rows.reduce((a, r) => a + (r.impactShare ?? 0), 0);
        return (
          <Tile
            title={t("title")}
            note={rows.length ? (shareTop > 0 && !noP1 ? t("note", { n: rows.length, share: f.pct(shareTop, 0), total: f.n(d.total) }) : t("noteShort", { total: f.n(d.total) })) : t("noteEmpty")}
            icon={TaskIcon}
            actions={<>{stale && <StaleStamp />}{csv && rows.length > 0 && <a href={csv} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-gray-300 px-3 text-xs font-medium text-gray-700 hover:bg-gray-50"><DownloadIcon className="size-4" aria-hidden="true" />{t("csv")}</a>}</>}
            className="h-full"
          >
            {rows.length === 0 ? (
              <EmptyState title={t("emptyTitle")} art={<CheckCircleIcon className="size-8 text-green-500" aria-hidden="true" />}>{t("emptyBody")}</EmptyState>
            ) : (
              <>
                {noP1 && <p className="mb-1 rounded-lg bg-gray-50 px-2 py-1 text-xs leading-5 text-gray-600">{t("noP1")}</p>}
                <div className={cn(COLS, "pb-1 text-xs leading-4 text-gray-500 max-sm:hidden")} aria-hidden="true">
                  <span /><span>{t("col.fix")}</span><span className={cn(NUM, "max-sm:hidden")}>{t("col.cves")}</span><span className={cn(NUM, "max-sm:hidden")}>{t("col.p1")}</span><span className={cn(NUM, "max-sm:hidden")}>{t("col.hosts")}</span><span className="max-sm:hidden ps-2">{t("col.severity")}</span>
                </div>
                {rows.map((r, i) => (
                  <Link key={r.id} to={`?fix=${encodeURIComponent(r.id)}`} className={cn(COLS, ROW, "py-1.5 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", i >= 5 && "max-sm:hidden")}>
                    <span className="flex size-5 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-700">{i + 1}</span>
                    <span className="min-w-0">
                      <span className="block truncate text-sm leading-5 font-medium text-gray-900" title={r.title}>{r.title}</span>
                      <span className="block truncate text-xs leading-4 text-gray-500">{r.product ?? ""}<span className="sm:hidden"> · {t("short", { hosts: f.n(r.hosts), cves: f.n(r.cves) })}</span></span>
                      <ReasonChips className="sm:hidden" reasons={r.kevCves ? ["kev"] : []} />
                    </span>
                    <span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.cves)} {r.kevCves > 0 && <span className="ms-0.5 rounded bg-red-50 px-1 text-xs font-medium text-red-700">KEV {f.cell(r.kevCves)}</span>}</span>
                    <span className={cn(NUM, "text-sm font-medium max-sm:hidden")}>{f.cell(r.p1)}</span>
                    <span className={cn(NUM, "text-sm max-sm:hidden")}>{f.cell(r.hosts)}{r.internetHosts > 0 && <span className="block text-xs leading-4 text-sky-700">{t("internet", { n: f.cell(r.internetHosts) })}</span>}</span>
                    <span className="ps-2 max-sm:hidden"><SeverityBadge severity={r.severity} /></span>
                  </Link>
                ))}
                <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-2 text-xs leading-5 text-gray-500">
                  <span>{t("order")}</span>
                  <Link to="/vulnerabilities?tab=fix" className={LINK}>{t("all", { n: f.n(d.total) })}</Link>
                </div>
              </>
            )}
          </Tile>
        );
      }}
    </Slot>
  );
}
