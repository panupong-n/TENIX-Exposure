import { Metric } from "@/components/shared/metric";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { Popover, PopoverBody, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useTranslations } from "@/i18n";
import { AlertIcon, InfoCircleIcon } from "@/icons";
import { cn } from "@/utils";
import { Link } from "react-router";
import { LINK, useFmt } from "./parts";
import { Tile } from "./tile";
import type { LevelKey, SummaryV2 } from "./types";

const LEVELS: LevelKey[] = ["low", "medium", "high", "critical"];
const LEVEL_COLOR: Record<LevelKey, string> = { low: "bg-green-500", medium: "bg-yellow-500", high: "bg-orange-500", critical: "bg-red-500" };
const LEVEL_TEXT: Record<LevelKey, string> = { low: "text-green-700", medium: "text-yellow-700", high: "text-orange-700", critical: "text-red-700" };

/** The level meter: four steps, the current one lit, the words always beside it, and a popover that prints the rule and the inputs (spec 4.2). */
function Level({ s }: { s: NonNullable<SummaryV2["headline"]> }) {
  const t = useTranslations("ovw.a");
  const f = useFmt();
  const lv = s.level;
  if (!lv) return null;
  const at = LEVELS.indexOf(lv.key);
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm leading-5">
      <span className="text-gray-500">{t("level")}</span>
      <span className="flex gap-0.5" aria-hidden="true">
        {LEVELS.map((k, i) => <span key={k} className={cn("h-2 w-6 rounded-sm", i <= at ? LEVEL_COLOR[lv.key] : "bg-gray-200")} />)}
      </span>
      <span className={cn("font-semibold", LEVEL_TEXT[lv.key])}>{t(`levels.${lv.key}`)}</span>
      {lv.escalated && <span className="text-xs text-gray-500">{t("escalated")}</span>}
      <Popover>
        <PopoverTrigger className={cn(LINK, "text-xs")}>{t("how")}</PopoverTrigger>
        <PopoverContent align="start" sideOffset={6} className="w-80 max-w-[calc(100vw-1.5rem)] ring-1 ring-gray-200">
          <PopoverBody className="space-y-2 p-3 text-xs leading-5 text-gray-700">
            <p className="font-medium text-gray-900">{t("howTitle")}</p>
            <ul className="space-y-0.5">
              {LEVELS.map((k) => (
                <li key={k} className={cn("flex justify-between rounded px-1.5", k === lv.base && "bg-gray-100 font-medium")}>
                  <span>{t(`rule.${k}`)}</span><span className={LEVEL_TEXT[k]}>{t(`levels.${k}`)}</span>
                </li>
              ))}
            </ul>
            <p>{t("inputs", { hosts: f.n(s.hostsWithP1), total: f.n(s.hostsTotal), share: f.pct(s.hostShare, 0) })}</p>
            <p className="text-gray-500">{t("escalationRule")}</p>
            <p className="text-gray-500">{t("standard")}</p>
          </PopoverBody>
        </PopoverContent>
      </Popover>
    </div>
  );
}

/** Block A (headline P1 + level + the sentence for the boss) with the four fact cells (block E of the spec: KEV, Exploited, ExPRT, internet P1). */
export default function Headline({ data, stale }: { data: SummaryV2; stale: boolean }) {
  const t = useTranslations("ovw.a");
  const f = useFmt();
  const h = data.headline;
  const facts = data.facts;
  if (!h) return null;
  const down = h.delta7 && h.delta7.p1 < 0;
  const say = h.p1 === 0 ? t("sayNone")
    : h.delta7 && h.delta7.pct != null && h.delta7.p1 !== 0 && !stale
      ? t(down ? "sayDown" : "sayUp", { hosts: f.n(h.hostsWithP1), share: f.pct(h.hostShare, 0), change: f.pct(Math.abs(h.delta7.pct)), fixes: f.n(Math.min(8, h.p1Fixes)) })
      : t("sayFlat", { hosts: f.n(h.hostsWithP1), share: f.pct(h.hostShare, 0), fixes: f.n(Math.min(8, h.p1Fixes)) });
  const cell = [
    { k: "kev", v: facts?.kev, to: "/vulnerabilities?kev=1" },
    { k: "exploited", v: facts?.exploited, to: "/vulnerabilities?exploited=1" },
    { k: "exprt", v: facts?.exprtCritical, to: "/vulnerabilities?exprt=CRITICAL" },
    { k: "internet", v: h.internetP1Hosts, to: "/devices?tier=P1&internet=1", unit: true },
  ];
  return (
    <Tile title={t("title")} note={t("note")} icon={AlertIcon} className="h-full">
      <div className="flex flex-wrap items-end justify-between gap-x-3 gap-y-1">
        <div className={cn("min-w-0 flex-1 basis-40 text-gray-900", stale && "text-gray-500")} data-testid="p1-number">
          <Metric value={h.p1} size="hero" reveal={!stale} />
        </div>
        <div className="shrink-0 pb-1 text-sm leading-5">
          {stale ? <StaleStamp /> : h.delta7 && h.delta7.pct != null && (
            <span className={cn("font-medium", down ? "text-green-700" : h.delta7.p1 > 0 ? "text-red-700" : "text-gray-600")}>
              {down ? "▼" : h.delta7.p1 > 0 ? "▲" : "="} {f.pct(Math.abs(h.delta7.pct))} ({h.delta7.p1 > 0 ? "+" : "−"}{f.n(Math.abs(h.delta7.p1))}) <span className="font-normal text-gray-500">{t("vs7")}</span>
            </span>
          )}
        </div>
      </div>
      <p className="mt-1 text-sm leading-5 text-gray-700">
        {t("onHosts", { hosts: f.n(h.hostsWithP1), pct: f.pct(h.hostShare, 0), total: f.n(h.hostsTotal), cves: f.n(h.p1Cves) })}
        {h.p1Exact !== undefined && <span className="text-gray-500"> · {t(h.p1Exact ? "exact" : "atLeast")}</span>}
      </p>
      <Level s={h} />
      <p className={cn("mt-2 rounded-lg px-2.5 py-1.5 text-sm leading-5", h.p1 === 0 ? "bg-green-50 text-green-800" : "bg-brand-50 text-brand-950")}>{say}</p>
      <div className="mt-2 grid grid-cols-2 gap-2">
        {cell.map((c) => (
          <Link key={c.k} to={c.to} className="min-w-0 rounded-lg border border-gray-200 p-2 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
            {c.v == null ? <span className="text-lg font-semibold text-gray-400">–</span> : <Metric value={c.v} size="sm" valueClassName={stale ? "text-gray-500" : "text-gray-900"} />}
            <span className="block text-xs leading-4 text-gray-500">{t(`facts.${c.k}`)}{c.unit && <> · {t("facts.hosts")}</>}</span>
          </Link>
        ))}
      </div>
      <p className="mt-auto flex items-start gap-1 pt-2 text-xs leading-4 text-gray-500">{stale && <StaleStamp className="shrink-0" />}<InfoCircleIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />{t("factsNote")}</p>
    </Tile>
  );
}
