import { ErrorState } from "@/components/shared/empty-state";
import { StatCardsSkeleton, TableSkeleton } from "@/components/shared/skeletons";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { formatAgo, formatDateTime, formatNumber } from "@/utils/format";
import { useEffect } from "react";

type State = "complete" | "partial" | "failed";
interface Org { tenant: string | null; state: State; dataAsOf: number | null; lastRunAt: number; findings: number; closed7d: number; syncMs: number | null }
interface SystemStatus {
  falcon: { running: boolean; lastRunAt: number | null; organizations: Org[] };
  database: { findings: number; closedFindings: number; cves: number; publicCves: number; kev: number; software: number; organizations: number };
  cache: { entries: number; newestBuiltAt: number | null; memoryHits: number; databaseHits: number; builds: number; hitRate: number | null; avgBuildMs: number | null; slowestBuildMs: number; warmedAt: number | null; warming: boolean };
}

const STATE_COLOR = { complete: "success", partial: "warning", failed: "error" } as const;
const DB_KEYS = ["findings", "closedFindings", "cves", "publicCves", "kev", "software", "organizations"] as const;
const block = "rounded-xl border border-gray-200 bg-white p-3";
const head = "py-1.5 pe-3 text-start text-xs leading-5 font-medium whitespace-nowrap text-gray-500";
const cell = "py-1.5 pe-3 text-sm leading-6 text-gray-600 tabular-nums";

function Tile({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-gray-100 bg-gray-50 px-3 py-2">
      <div className="text-xs leading-5 text-gray-500">{label}</div>
      <div className="truncate text-lg leading-6 font-semibold text-gray-800 tabular-nums">{value}</div>
    </div>
  );
}

/** Setting Center: is data really pulled from Falcon, stored in our database and served from a cache? (super admin, GET /api/system/status) */
export function SystemPanel() {
  const t = useTranslations("settings.system");
  const locale = useLocale();
  const { data, error, reload } = useApi<SystemStatus>("/api/system/status");
  useEffect(() => {
    const id = window.setInterval(reload, 15_000);
    return () => window.clearInterval(id);
  }, [reload]);

  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return (
    <div className="space-y-3">
      <TableSkeleton rows={4} />
      <StatCardsSkeleton count={4} />
      <StatCardsSkeleton count={4} />
    </div>
  );
  const { falcon, database, cache } = data;
  const num = (n: number) => formatNumber(n, locale);
  const dur = (ms: number | null) => {
    if (ms === null) return "-";
    if (ms < 1000) return t("ms", { n: num(ms) });
    if (ms < 60_000) return t("sec", { n: num(Math.round(ms / 100) / 10) });
    return t("min", { n: num(Math.round(ms / 6000) / 10) });
  };
  const when = (ts: number | null) => formatDateTime(ts, locale) ?? "-";

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="min-w-0 text-xs leading-5 text-gray-500">{t("auto")}</p>
        <Button type="button" size="xs" variant="outline" onClick={reload}>{t("refresh")}</Button>
      </div>

      <section className={block}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="text-sm leading-6 font-semibold text-gray-800">{t("falconTitle")}</h3>
            <p className="text-xs leading-5 text-gray-500">{t("falconNote")}</p>
          </div>
          <Badge size="sm" color={falcon.running ? "info" : "gray"}>
            <span className="leading-5">{falcon.running ? t("running") : falcon.lastRunAt ? t("lastRun", { ago: formatAgo(falcon.lastRunAt, locale) ?? "" }) : t("noRun")}</span>
          </Badge>
        </div>
        {falcon.organizations.length === 0 ? (
          <p className="mt-2 text-sm leading-6 text-gray-500">{t("empty")}</p>
        ) : (
          <>
            <div className="mt-2 hidden overflow-x-auto sm:block">
              <table className="w-full min-w-[34rem] border-collapse">
                <thead className="border-y border-gray-100">
                  <tr>
                    {(["org", "state", "asOf", "lastRun", "findings", "closed", "took"] as const).map((c) => <th key={c} className={`${head} ${c === "findings" || c === "closed" || c === "took" ? "text-end" : ""}`}>{t(`cols.${c}`)}</th>)}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {falcon.organizations.map((o, i) => (
                    <tr key={`${o.tenant}-${i}`}>
                      <td className={`${cell} max-w-48 truncate font-medium text-gray-800`}>{o.tenant ?? t("noTenant")}</td>
                      <td className={cell}><Badge size="sm" color={STATE_COLOR[o.state]}>{t(`states.${o.state}`)}</Badge></td>
                      <td className={`${cell} whitespace-nowrap`}>{when(o.dataAsOf)}</td>
                      <td className={`${cell} whitespace-nowrap`}>{when(o.lastRunAt)}</td>
                      <td className={`${cell} text-end`}>{num(o.findings)}</td>
                      <td className={`${cell} text-end`}>{num(o.closed7d)}</td>
                      <td className={`${cell} text-end whitespace-nowrap`}>{dur(o.syncMs)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ul className="mt-2 space-y-2 sm:hidden">
              {falcon.organizations.map((o, i) => (
                <li key={`${o.tenant}-${i}`} className="rounded-lg border border-gray-100 p-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="min-w-0 flex-1 truncate text-sm leading-6 font-medium text-gray-800">{o.tenant ?? t("noTenant")}</span>
                    <Badge size="sm" color={STATE_COLOR[o.state]}>{t(`states.${o.state}`)}</Badge>
                  </div>
                  <dl className="mt-1 grid grid-cols-2 gap-x-3 text-xs leading-5 text-gray-500">
                    <div><dt>{t("cols.asOf")}</dt><dd className="text-gray-700">{when(o.dataAsOf)}</dd></div>
                    <div><dt>{t("cols.lastRun")}</dt><dd className="text-gray-700">{when(o.lastRunAt)}</dd></div>
                    <div><dt>{t("cols.findings")}</dt><dd className="text-gray-700 tabular-nums">{num(o.findings)}</dd></div>
                    <div><dt>{t("cols.closed")}</dt><dd className="text-gray-700 tabular-nums">{num(o.closed7d)}</dd></div>
                    <div><dt>{t("cols.took")}</dt><dd className="text-gray-700 tabular-nums">{dur(o.syncMs)}</dd></div>
                  </dl>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section className={block}>
        <h3 className="text-sm leading-6 font-semibold text-gray-800">{t("dbTitle")}</h3>
        <p className="text-xs leading-5 text-gray-500">{t("dbNote")}</p>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-4">
          {DB_KEYS.map((k) => <Tile key={k} label={t(`db.${k}`)} value={num(database[k])} />)}
        </div>
      </section>

      <section className={block}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h3 className="min-w-0 text-sm leading-6 font-semibold text-gray-800">{t("cacheTitle")}</h3>
          <Badge size="sm" color={cache.warming ? "info" : cache.warmedAt ? "success" : "gray"}>
            <span className="leading-5">{cache.warming ? t("cache.warming") : cache.warmedAt ? t("cache.warmed", { ago: formatAgo(cache.warmedAt, locale) ?? "" }) : t("cache.notWarmed")}</span>
          </Badge>
        </div>
        <p className="text-xs leading-5 text-gray-500">{t("cacheNote")}</p>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Tile label={t("cache.hitRate")} value={cache.hitRate === null ? t("cache.none") : `${num(cache.hitRate)}%`} />
          <Tile label={t("cache.entries")} value={num(cache.entries)} />
          <Tile label={t("cache.avg")} value={dur(cache.avgBuildMs)} />
          <Tile label={t("cache.slowest")} value={dur(cache.builds ? cache.slowestBuildMs : null)} />
        </div>
        <p className="mt-2 text-xs leading-5 text-gray-500 tabular-nums">{t("cache.hits", { memory: num(cache.memoryHits), db: num(cache.databaseHits), builds: num(cache.builds) })}</p>
      </section>
    </div>
  );
}
