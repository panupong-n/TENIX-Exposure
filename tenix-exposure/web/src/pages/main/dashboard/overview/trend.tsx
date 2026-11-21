// Skeleton: while the trend loads, Slot (parts.tsx) renders a ChartCardSkeleton.
import { StaleStamp } from "@/components/shared/stale-stamp";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { BarChartIcon } from "@/icons";
import { cn } from "@/utils";
import { formatDate, formatCompact } from "@/utils/format";
import { useState } from "react";
import { Slot, useFmt } from "./parts";
import { Tile } from "./tile";
import type { TrendV2 } from "./types";

const DAYS = [7, 30, 90] as const;
const W = 600, H = 150;

/** Block B: P1 findings open per day, one line (never two scales on one chart). Hover reads a day; a screen-reader table holds every point. */
export default function Trend({ stale }: { stale: boolean }) {
  const t = useTranslations("ovw.b");
  const locale = useLocale();
  const f = useFmt();
  const { scoped } = useOrg();
  const [days, setDays] = useState<(typeof DAYS)[number]>(30);
  const [hover, setHover] = useState<number | null>(null);
  const res = useApi<TrendV2>(scoped(`/api/exposure/v2/trend?days=${days}`));

  const picker = (
    <div role="group" aria-label={t("range")} className="flex overflow-hidden rounded-lg border border-gray-200 text-xs">
      {DAYS.map((d) => (
        <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(d)} className={cn("h-7 px-2.5 font-medium", days === d ? "bg-brand-50 text-brand-700" : "text-gray-600 hover:bg-gray-50")}>{t("days", { n: d })}</button>
      ))}
    </div>
  );
  return (
    <Slot res={res} h="h-44">
      {(d) => {
        const pts = d.points;
        const week = d.week;
        const closed = week?.closedP1 ?? (week as { closed?: number | null } | undefined)?.closed ?? null;
        const max = Math.max(1, ...pts.map((p) => p.p1)), min = Math.min(...pts.map((p) => p.p1));
        const lo = pts.length > 1 ? Math.max(0, min - (max - min) * 0.1) : 0, hi = max + (max - min) * 0.1 || max;
        const x = (i: number) => (pts.length < 2 ? W : (i / (pts.length - 1)) * W);
        const y = (v: number) => H - ((v - lo) / (hi - lo || 1)) * (H - 8) - 4;
        const line = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)} ${y(p.p1).toFixed(1)}`).join("");
        const last = pts[pts.length - 1];
        const at = hover != null ? pts[hover] : last;
        const prev = hover != null && hover > 0 ? pts[hover - 1] : null;
        return (
          <Tile title={t("title")} note={d.startedAt ? t("since", { date: formatDate(Date.parse(d.startedAt), locale) ?? d.startedAt }) : t("noteNone")} icon={BarChartIcon} actions={<>{stale && <StaleStamp />}{picker}</>} className="h-full">
            {pts.length < 2 ? (
              <div className="relative mt-1 flex min-h-36 flex-1 items-center">
                <span className="absolute inset-x-0 top-1/2 border-t-2 border-dashed border-gray-200" aria-hidden="true" />
                {last && <span className="absolute end-0 top-1/2 size-2.5 -translate-y-1/2 rounded-full border-2 border-white bg-brand-700" aria-hidden="true" />}
                <p className="relative bg-white pe-3 text-sm leading-5 text-gray-600">{last ? t("onePoint", { value: f.n(last.p1) }) : t("needTwo")}</p>
              </div>
            ) : (
              <>
                <p className="min-h-5 text-xs leading-5 text-gray-600 tabular-nums" aria-live="polite">
                  {at && <>{formatDate(Date.parse(at.day), locale)} · <span className="font-semibold text-gray-900">P1 {f.n(at.p1)}</span>{prev && <> · {at.p1 - prev.p1 >= 0 ? "+" : "−"}{f.n(Math.abs(at.p1 - prev.p1))}</>}</>}
                </p>
                <div className="relative mt-1 flex flex-1 gap-2">
                  <div className="flex shrink-0 flex-col justify-between py-0.5 text-xs leading-4 text-gray-500 tabular-nums" aria-hidden="true"><span>{formatCompact(Math.round(hi))}</span><span>{formatCompact(Math.round(lo))}</span></div>
                  <div className="relative min-h-36 min-w-0 flex-1" onMouseLeave={() => setHover(null)} onMouseMove={(e) => { const r = e.currentTarget.getBoundingClientRect(); setHover(Math.round(((e.clientX - r.left) / r.width) * (pts.length - 1))); }}>
                    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="absolute inset-0 size-full" role="img" aria-label={t("chartLabel", { from: f.n(pts[0].p1), to: f.n(last.p1) })}>
                      <path d={`${line}L${W} ${H}L0 ${H}Z`} fill="var(--color-brand-500)" opacity="0.08" />
                      <path d={line} fill="none" stroke="var(--color-brand-700)" strokeWidth="2" vectorEffect="non-scaling-stroke" strokeDasharray={stale ? "5 4" : undefined} />
                    </svg>
                    {hover != null && <span className="pointer-events-none absolute inset-y-0 w-px bg-gray-300" style={{ left: `${(hover / (pts.length - 1)) * 100}%` }} aria-hidden="true" />}
                    <span className="pointer-events-none absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-white bg-brand-700" style={{ left: `${((hover ?? pts.length - 1) / (pts.length - 1)) * 100}%`, top: `${(y((hover != null ? pts[hover] : last).p1) / H) * 100}%` }} aria-hidden="true" />
                  </div>
                </div>
                <table className="sr-only"><caption>{t("title")}</caption><tbody>{pts.map((p) => <tr key={p.day}><td>{p.day}</td><td>{p.p1}</td></tr>)}</tbody></table>
              </>
            )}
            {stale && <p className="text-xs leading-4 text-gray-500">{t("noNew")}</p>}
            {!stale && week && (week.newP1 != null || closed != null || week.net != null) && (
              <p className="mt-1 flex flex-wrap gap-x-3 text-xs leading-5 text-gray-600 tabular-nums">
                <span className="text-gray-500">{t("thisWeek")}</span>
                {week.newP1 != null && <span>{t("new")} <b className="text-red-700">+{f.n(week.newP1)}</b></span>}
                {closed != null && <span>{t("closed")} <b className="text-green-700">{closed > 0 ? "−" : ""}{f.n(closed)}</b></span>}
                {week.net != null && <span>{t("net")} <b className={week.net <= 0 ? "text-green-700" : "text-red-700"}>{week.net > 0 ? "+" : week.net < 0 ? "−" : ""}{f.n(Math.abs(week.net))}</b></span>}
              </p>
            )}
          </Tile>
        );
      }}
    </Slot>
  );
}

