import { sevColor } from "@/components/shared/graph";
import { TierBadge, type Tier } from "@/components/shared/tier-badge";
import { WatchStar } from "@/components/shared/watch-star";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { ChevronRightIcon } from "@/icons";
import { formatNumber } from "@/utils/format";
import { useState, type RefObject } from "react";
import type { EntityType } from "./state";
import type { ListData, ListRow } from "./types";

export type ListKind = "fix" | "product" | "host" | "hostCves";
export interface RowActions {
  drill: (kind: EntityType, id: string, label: string) => void;
  open: (kind: EntityType, id: string) => void;
}

const chip = "inline-flex h-[18px] shrink-0 items-center rounded-md bg-gray-100 px-1.5 text-[11.5px] font-medium whitespace-nowrap text-gray-700";
const SIZE = 50;

function Row({ kind, r, rank, a }: { kind: ListKind; r: ListRow; rank: number; a: RowActions }) {
  const t = useTranslations("graphView.panel");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  const id = String((kind === "host" ? r.aid ?? r.id : r.id) ?? "");
  const name = r.name ?? r.label ?? id;
  const type: EntityType = kind === "hostCves" ? "cve" : kind;
  const main = "min-w-0 rounded text-start focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none";
  const open = (
    <button type="button" onClick={() => a.open(type, id)} aria-label={t("openAria", { name })} title={t("open")} className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-gray-400 hover:bg-gray-100 hover:text-brand-600 focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none">
      <ChevronRightIcon className="size-4 rtl:rotate-180" aria-hidden="true" />
    </button>
  );
  if (kind === "host") {
    return (
      <li className="flex items-center gap-1.5 rounded-lg px-1.5 py-1 hover:bg-gray-50">
        <WatchStar aid={id} hostname={name} />
        <button type="button" onClick={() => a.drill("host", id, name)} className={`${main} flex-1`}>
          <span className="block truncate text-[13px] leading-snug text-gray-800">{name}</span>
          <span className="flex items-center gap-1.5 text-[11.5px] text-gray-500">
            {r.sev && <span className="size-2 shrink-0 rounded-full" style={{ background: sevColor(r.sev) }} aria-hidden="true" />}
            <span className="truncate">{[r.group, r.os].filter(Boolean).join(" · ")}</span>
            {r.inet && <span className={chip}>{t("inet")}</span>}
          </span>
        </button>
        <span className="shrink-0 text-end text-[12.5px] font-medium tabular-nums">
          {n(r.n ?? 0)}
          <small className="block text-[11px] font-normal text-gray-500">{[r.p1 ? t("p1", { count: n(r.p1) }) : null, r.kev ? t("kev", { count: n(Number(r.kev)) }) : null].filter(Boolean).join(" · ")}</small>
        </span>
        {open}
      </li>
    );
  }
  if (kind === "hostCves") {
    return (
      <li className="flex items-center gap-1.5 rounded-lg px-1.5 py-1 hover:bg-gray-50">
        <span className="ms-1 size-2.5 shrink-0 rounded-full" style={{ background: sevColor(r.sev ?? "") }} role="img" aria-label={r.sev ?? ""} />
        <button type="button" onClick={() => a.drill("cve", id, name)} className={`${main} flex-1`}>
          <span className="block truncate text-[13px] leading-snug text-gray-800">{name}</span>
          {r.sub && <span className="block truncate text-[11.5px] text-gray-500">{r.sub}</span>}
        </button>
        {r.kev ? <span className={`${chip} !bg-gray-700 !text-white`}>KEV</span> : null}
        {r.tier && <TierBadge tier={r.tier as Tier} help={false} />}
        {open}
      </li>
    );
  }
  return (
    <li className="flex items-center gap-1.5 rounded-lg px-1.5 py-1 hover:bg-gray-50">
      <span className="grid size-[22px] shrink-0 place-items-center rounded-md bg-brand-50 text-xs font-semibold text-brand-700">{rank}</span>
      <button type="button" onClick={() => a.drill(type, id, name)} className={`${main} flex-1`}>
        <span className="block text-[13px] leading-snug break-words text-gray-800">{name}</span>
        {r.sub && <span className="block truncate text-[11.5px] text-gray-500">{r.sub}</span>}
      </button>
      <span className="shrink-0 text-end text-[12.5px] font-medium tabular-nums">
        {r.findings != null ? n(r.findings) : n(r.hosts ?? 0)}
        {r.findings != null && <small className="block text-[11px] font-normal text-gray-500">{t("hostsN", { count: n(r.hosts ?? 0) })}</small>}
      </span>
      {open}
    </li>
  );
}

function Rows({ path, kind, from, a }: { path: string; kind: ListKind; from: number; a: RowActions }) {
  const { data, error, reload } = useApi<ListData>(path);
  const tc = useTranslations("common");
  if (error) return <li className="px-2 py-2"><Button size="sm" variant="outline" onClick={reload}>{tc("retry")}</Button></li>;
  if (!data) return Array.from({ length: 8 }, (_, i) => <li key={i} className="px-1.5 py-1"><Skeleton className="h-8 w-full" /></li>);
  return data.rows.map((r, i) => <Row key={`${from + i}`} kind={kind} r={r} rank={from + i + 1} a={a} />);
}

/** The panel beside the graph: every row behind it (all fixes, all products, all hosts of the entity or group, a host's CVEs), 50 per page. It is also the table alternative of the graph. */
export function SideList({ kind, base, a, scroller }: { kind: ListKind; /** the query without `page`, tenant included */ base: string; a: RowActions; scroller: RefObject<HTMLDivElement | null> }) {
  const t = useTranslations("graphView.panel");
  const tc = useTranslations("common");
  const locale = useLocale();
  const { scoped } = useOrg();
  const [pages, setPages] = useState(1);
  const path = (p: number) => scoped(`/api/exposure/graph/list?${base}&page=${p}`);
  const first = useApi<ListData>(path(1));
  const total = first.data?.total ?? 0;
  const shown = Math.min(total, pages * SIZE);
  const n = (v: number) => formatNumber(v, locale);
  return (
    <div ref={scroller} className="min-h-30 flex-1 overflow-y-auto px-1.5 pt-1 pb-2" aria-label={t("label")}>
      {first.data && (
        <div className="flex justify-between gap-2 px-1.5 pt-1 pb-0.5 text-xs text-gray-500">
          <span>{t(`total.${kind}`, { count: n(total) })}</span><span>{t("showing", { count: n(shown) })}</span>
        </div>
      )}
      {first.data && total === 0 && <p className="px-2 py-3 text-sm text-gray-500">{t("empty")}</p>}
      <ul>
        {first.error && <li className="px-2 py-2"><Button size="sm" variant="outline" onClick={first.reload}>{tc("retry")}</Button></li>}
        {!first.error && !first.data && Array.from({ length: 8 }, (_, i) => <li key={i} className="px-1.5 py-1"><Skeleton className="h-8 w-full" /></li>)}
        {first.data?.rows.map((r, i) => <Row key={i} kind={kind} r={r} rank={i + 1} a={a} />)}
        {Array.from({ length: pages - 1 }, (_, i) => <Rows key={i + 2} path={path(i + 2)!} kind={kind} from={(i + 1) * SIZE} a={a} />)}
      </ul>
      {first.data && shown < total && (
        <Button size="sm" variant="outline" className="mt-1.5 w-full" onClick={() => setPages(pages + 1)}>{t("more", { count: n(Math.min(SIZE, total - shown)), rest: n(total - shown) })}</Button>
      )}
    </div>
  );
}
