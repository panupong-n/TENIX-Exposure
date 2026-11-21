import { useDrawers } from "@/components/shared/drawers-context";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { ReasonChips } from "@/components/shared/reason-chips";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { ChartCardSkeleton, StatCardsSkeleton } from "@/components/shared/skeletons";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { Metric } from "@/components/shared/metric";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { AlertIcon, ClockIcon, DownloadIcon, LinkIcon, TableIcon } from "@/icons";
import { cn } from "@/utils";
import { formatAgo, formatDateTime, nameOrder } from "@/utils/format";
import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { clock, DOT, LINK, NUM, ROW, TILE_FILTER, useFmt } from "./parts";
import { Tile, TILE } from "./tile";
import type { AttentionReason, Portfolio, PortfolioTenant } from "./types";

/** The state a row shows: a complete read of a big organization is "priority" (blue), not a warning. */
const stateOf = (r: PortfolioTenant) => (r.state === "complete" && r.mode === "priority" ? "priority" : r.state);
const BROKEN = ["failed", "no_connection", "no_cids"];
/** A summary tile and its filter: "broken" = could not read (the attention queue lists these); "partial" = first read, incomplete or not set up yet (no CID). */
const inGroup = (r: PortfolioTenant, k: string) => (k === "broken" ? ["failed", "no_connection"].includes(r.state) : k === "partial" ? ["partial", "not_synced", "no_cids"].includes(r.state) : stateOf(r) === k);
const REASON_STYLE: Record<AttentionReason, string> = { broken_connection: "bg-red-50 text-red-700", kev_new: "bg-red-50 text-red-700", p1_overdue: "bg-red-50 text-red-700", partial: "bg-yellow-50 text-yellow-800", stale: "bg-gray-100 text-gray-700" };
const REASONS_TEXT = ["invalid_credentials", "cid_not_authorized", "missing_scope", "unreachable", "error"];
type SortKey = "attention" | "p1" | "share" | "delta" | "asOf" | "name";

function Spark({ values }: { values: number[] }) {
  if (values.length < 2) return <span className="text-xs text-gray-400">–</span>;
  const lo = Math.min(...values), hi = Math.max(...values);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * 56},${14 - ((v - lo) / (hi - lo || 1)) * 12}`).join(" ");
  return <svg width="56" height="16" viewBox="0 0 56 16" aria-hidden="true"><polyline points={pts} fill="none" stroke="var(--color-brand-700)" strokeWidth="1.5" /></svg>;
}

function StateChip({ r }: { r: PortfolioTenant }) {
  const t = useTranslations("ovw.p");
  const s = stateOf(r);
  return <span className="inline-flex items-center gap-1.5 text-xs leading-5 font-medium text-gray-800"><span className={cn("size-2 rounded-full", DOT[s] ?? "bg-gray-400")} aria-hidden="true" />{t(`state.${s}`)}</span>;
}

const csvCell = (v: string | number | null) => (v === null ? "" : typeof v === "number" ? String(v) : `"${(/^[=+\-@\t\r]/.test(v) ? `'${v}` : v).replace(/"/g, '""')}"`);

/** The SOC portfolio (org switcher = ทุกองค์กร): summary strip, attention queue, cross-tenant CVEs, the tenant table and the 24 h sync strip. */
export default function PortfolioView() {
  const t = useTranslations("ovw.p");
  const ts = useTranslations("states.reason");
  const f = useFmt();
  const locale = useLocale();
  const nav = useNavigate();
  const [, setParams] = useSearchParams();
  const { setOrgId } = useOrg();
  const { openCve } = useDrawers();
  const res = useApi<Portfolio>("/api/exposure/portfolio");
  const [filter, setFilter] = useState<string>("");
  const [text, setText] = useState("");
  const [sort, setSort] = useState<SortKey>("attention");

  const rows = useMemo(() => {
    const all = res.data?.tenants ?? [];
    const q = text.trim().toLowerCase();
    const list = all.filter((r) => (!filter || (filter === "kev" ? r.kevNew7d > 0 : filter === "overdue" ? r.p1Overdue > 0 : inGroup(r, filter))) && (!q || r.name.toLowerCase().includes(q)));
    const order = new Map(all.map((r, i) => [r.id, i]));
    const by: Record<SortKey, (a: PortfolioTenant, b: PortfolioTenant) => number> = {
      attention: (a, b) => order.get(a.id)! - order.get(b.id)!,
      p1: (a, b) => (b.p1 ?? -1) - (a.p1 ?? -1),
      share: (a, b) => (b.hostShare ?? -1) - (a.hostShare ?? -1),
      delta: (a, b) => (b.p1Delta7 ?? -Infinity) - (a.p1Delta7 ?? -Infinity),
      asOf: (a, b) => (a.asOf ?? 0) - (b.asOf ?? 0),
      name: (a, b) => nameOrder.compare(a.name, b.name),
    };
    return [...list].sort((a, b) => by[sort](a, b) || nameOrder.compare(a.name, b.name));
  }, [res.data, filter, text, sort]);

  if (res.error && !res.data) return <div className={TILE}><ErrorState error={res.error} onRetry={res.reload} /></div>;
  if (!res.data) return <div className="space-y-3" aria-busy="true"><StatCardsSkeleton count={6} /><ChartCardSkeleton className="h-48" /><ChartCardSkeleton className="h-56" /></div>;
  const d = res.data;
  const open = (id: string) => { setOrgId(id); setParams((p) => { const n = new URLSearchParams(p); n.delete("view"); return n; }, { replace: true }); void nav("/"); };
  const count = (k: string) => d.tenants.filter((r) => inGroup(r, k)).length;
  const tiles: { k: string; v: number; dot?: string }[] = [
    { k: "", v: d.summary.tenants }, { k: "complete", v: count("complete"), dot: "bg-green-500" }, { k: "priority", v: count("priority"), dot: "bg-sky-500" },
    { k: "partial", v: count("partial"), dot: "bg-yellow-500" }, { k: "broken", v: count("broken"), dot: "bg-red-500" }, { k: "kev", v: d.summary.kevNew7d }, { k: "overdue", v: d.summary.p1Overdue },
  ];
  const fresh = d.tenants.filter((r) => !r.stale && r.p1 != null);
  const staleN = d.tenants.length - fresh.length;
  const exportCsv = () => {
    const head = ["organization", "state", "p1", "p1_delta_7d", "hosts_with_p1", "hosts", "critical", "kev_new_7d", "p1_overdue", "easm_pending_review", "data_as_of"];
    const lines = [head.join(","), ...rows.map((r) => [r.name, stateOf(r), r.p1, r.p1Delta7, r.hostsWithP1, r.hosts, r.critical, r.kevNew7d, r.p1Overdue, r.easmPendingReview, r.asOf ? new Date(r.asOf).toISOString() : null].map((v) => csvCell(v as string | number | null)).join(","))];
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" }));
    a.download = `portfolio-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const reasonLabel = (r: Portfolio["attention"][number], k: AttentionReason) => k === "kev_new" ? t("reason.kev_new", { n: f.n(r.detail.kevNew7d ?? 0) }) : k === "p1_overdue" ? t("reason.p1_overdue", { n: f.n(r.detail.p1Overdue ?? 0) }) : k === "stale" && r.detail.ageHours != null ? t("reason.staleHours", { h: Math.round(r.detail.ageHours) }) : t(`reason.${k}`);

  return (
    <div className="grid grid-cols-12 gap-3">
      <div className="col-span-12 grid gap-2 [grid-template-columns:repeat(auto-fit,minmax(min(100%,8.5rem),1fr))]">
        {tiles.map((x) => (
          <button key={x.k || "all"} type="button" aria-pressed={filter === x.k && x.k !== ""} onClick={() => setFilter(filter === x.k ? "" : x.k)} className={cn(TILE_FILTER, filter === x.k && x.k !== "" && "border-brand-500 bg-brand-50")}>
            <span className="flex items-center gap-1.5">{x.dot && <span className={cn("size-2 rounded-full", x.dot)} aria-hidden="true" />}<Metric value={x.v} size="sm" showFull={false} className="flex-1" /></span>
            <span className="block text-xs leading-4 text-gray-500">{t(`tile.${x.k || "all"}`)}</span>
          </button>
        ))}
      </div>

      <div className="col-span-12 xl:col-span-8">
        <Tile title={t("attention")} note={t("attentionNote")} icon={AlertIcon} className="h-full">
          {d.attention.length === 0 ? (
            <EmptyState title={t("attentionNone")} />
          ) : (
            d.attention.slice(0, 8).map((a) => {
              const tn = d.tenants.find((x) => x.id === a.tenantId);
              const broken = a.reasons.includes("broken_connection");
              const why = broken && tn?.reason && REASONS_TEXT.includes(tn.reason) ? ts(tn.reason) : null;
              return (
                <div key={a.tenantId} className={cn(ROW, "flex flex-wrap items-center justify-between gap-2 border-s-4 ps-2 py-1.5", broken ? "border-s-red-500" : a.reasons[0] === "partial" || a.reasons[0] === "stale" ? "border-s-yellow-500" : "border-s-red-500")}>
                  <div className="min-w-0 flex-1 basis-60">
                    <span className="text-sm leading-5 font-semibold text-gray-900">{a.name}</span>{" "}
                    <span className="inline-flex flex-wrap gap-1 align-middle">{a.reasons.map((k) => <span key={k} className={cn("rounded px-1.5 text-xs leading-5 font-medium", REASON_STYLE[k])}>{reasonLabel(a, k)}</span>)}</span>
                    {why && <span className="block text-xs leading-4 text-gray-500">{why}</span>}
                  </div>
                  <button type="button" onClick={() => open(a.tenantId)} className="h-8 shrink-0 rounded-lg border border-gray-300 px-3 text-xs font-medium text-gray-700 hover:bg-gray-50">{t(broken ? "openConnection" : "openOverview")}</button>
                </div>
              );
            })
          )}
        </Tile>
      </div>
      <div className="col-span-12 xl:col-span-4">
        <Tile title={t("shared")} note={t("sharedNote")} icon={LinkIcon} className="h-full">
          {d.sharedCves.length === 0 ? <EmptyState title={t("sharedNone")} /> : d.sharedCves.slice(0, 5).map((c) => (
            <button key={c.cveId} type="button" onClick={() => openCve(c.cveId)} className={cn(ROW, "flex w-full items-center justify-between gap-2 py-1 text-start hover:bg-gray-50")}>
              <span className="flex min-w-0 flex-wrap items-center gap-1.5"><span className="text-sm leading-5 font-semibold text-gray-900">{c.cveId}</span>{c.kev && <ReasonChips reasons={["kev"]} />}<SeverityBadge severity={c.severity} /></span>
              <span className="shrink-0 text-end text-xs leading-4 text-gray-600 tabular-nums"><b className="text-sm text-gray-900">{t("orgs", { n: f.n(c.tenants) })}</b><br />{t("hosts", { n: f.n(c.hosts) })}</span>
            </button>
          ))}
        </Tile>
      </div>

      <div className="col-span-12">
        <Tile title={t("table")} note={t("tableNote")} icon={TableIcon} actions={<button type="button" onClick={exportCsv} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-gray-300 px-3 text-xs font-medium text-gray-700 hover:bg-gray-50"><DownloadIcon className="size-4" aria-hidden="true" />{t("csv")}</button>}>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder={t("search")} aria-label={t("search")} className="h-8 min-w-0 flex-1 basis-44 rounded-lg border border-gray-300 px-2.5 text-sm outline-none focus:border-brand-300 focus:ring-3 focus:ring-brand-500/10" />
            <label className="flex items-center gap-1.5 text-xs text-gray-500">{t("sortBy")}
              <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)} className="h-9 rounded-lg border border-gray-300 bg-white px-2 text-sm leading-5 text-gray-800">
                {(["attention", "p1", "share", "delta", "asOf", "name"] as SortKey[]).map((k) => <option key={k} value={k}>{t(`sort.${k}`)}</option>)}
              </select>
            </label>
            {filter && <button type="button" onClick={() => setFilter("")} className={cn(LINK, "text-xs")}>{t("clearFilter")}</button>}
          </div>
          {rows.length === 0 ? (
            <EmptyState title={d.tenants.length === 0 ? t("noOrgs") : t("noMatch")}>{d.tenants.length === 0 && <Link to="/settings?setting=tenants" className={LINK}>{t("noOrgsLink")}</Link>}</EmptyState>
          ) : (
            <>
              <div className="hidden md:block">
                <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1.3fr)_7rem_4rem_6.5rem_5rem_4.5rem_4.5rem_4.5rem_4rem] items-end gap-x-2 border-b border-gray-200 pb-1 text-xs leading-4 text-gray-500">
                  <span>{t("col.org")}</span><span>{t("col.state")}</span><span className={NUM}>P1</span><span>{t("col.trend")}</span><span className={NUM}>{t("col.hostsP1")}</span><span className={NUM}>Critical</span><span className={NUM}>{t("col.kevNew")}</span><span className={NUM}>{t("col.overdue")}</span><span className={NUM}>EASM</span><span />
                </div>
                {rows.map((r) => {
                  const none = r.asOf == null; // nothing was ever read (no CID, never synced): not "old data", just no data
                  const old = (r.stale || BROKEN.includes(r.state)) && !none;
                  return (
                    <div key={r.id} className={cn(ROW, "grid grid-cols-[minmax(0,1.6fr)_minmax(0,1.3fr)_7rem_4rem_6.5rem_5rem_4.5rem_4.5rem_4.5rem_4rem] items-center gap-x-2 py-1.5 text-sm", old && "text-gray-500")}>
                      <span className="truncate font-medium text-gray-900" title={r.name}>{r.name}</span>
                      <span className="min-w-0"><StateChip r={r} /><span className="block truncate text-xs leading-4 text-gray-500">{old ? `${t("asOfOld", { ago: formatAgo(r.asOf, locale) ?? "–" })}` : r.asOf ? clock(r.asOf, locale) : "–"}</span></span>
                      <span className={NUM}>{none ? "–" : <>{r.mode !== "full" && r.state === "partial" ? "≥ " : ""}{f.cell(r.p1)}</>}{old && <> <StaleStamp /></>}{!old && r.p1Delta7 != null && r.p1Delta7 !== 0 && <span className={cn("block text-xs leading-4", r.p1Delta7 < 0 ? "text-green-700" : "text-red-700")}>{r.p1Delta7 < 0 ? "▼" : "▲"} {f.cell(Math.abs(r.p1Delta7))}</span>}</span>
                      <span>{!old && r.p1Spark ? <Spark values={r.p1Spark} /> : <span className="text-xs text-gray-400">–</span>}</span>
                      <span className={NUM}>{r.hostsWithP1 != null && r.hosts ? <>{f.cell(r.hostsWithP1)} / {f.cell(r.hosts)}<span className="block text-xs leading-4 text-gray-500">{f.pct(r.hostShare, 0)}</span></> : "–"}</span>
                      <span className={NUM}>{none ? "–" : f.cell(r.critical)}</span>
                      <span className={cn(NUM, r.kevNew7d > 0 && "font-semibold text-red-700")}>{old || none ? "–" : f.cell(r.kevNew7d)}</span>
                      <span className={NUM}>{old || none ? "–" : f.cell(r.p1Overdue)}</span>
                      <span className={NUM}>{none ? "–" : f.cell(r.easmPendingReview)}</span>
                      <span className="text-end"><button type="button" onClick={() => open(r.id)} className="h-7 rounded-lg border border-gray-300 px-2.5 text-xs font-medium text-gray-700 hover:bg-gray-50">{t(BROKEN.includes(r.state) ? "fix" : "open")}</button></span>
                    </div>
                  );
                })}
              </div>
              <div className="md:hidden">
                {rows.map((r) => {
                  const none = r.asOf == null;
                  const old = (r.stale || BROKEN.includes(r.state)) && !none;
                  return (
                    <button key={r.id} type="button" onClick={() => open(r.id)} className={cn(ROW, "flex w-full items-center justify-between gap-2 py-2 text-start", old && "text-gray-500")}>
                      <span className="min-w-0"><span className="block truncate text-sm font-medium text-gray-900">{r.name}</span><StateChip r={r} /></span>
                      <span className="shrink-0 text-end text-sm tabular-nums"><b>{none ? "–" : f.cell(r.p1)}</b>{old ? <> <StaleStamp /></> : r.p1Delta7 != null && r.p1Delta7 !== 0 && <span className={cn("block text-xs", r.p1Delta7 < 0 ? "text-green-700" : "text-red-700")}>{r.p1Delta7 < 0 ? "▼" : "▲"} {f.cell(Math.abs(r.p1Delta7))}</span>}</span>
                    </button>
                  );
                })}
              </div>
              <p className="mt-2 border-t border-gray-100 pt-2 text-xs leading-5 text-gray-600 tabular-nums">
                {staleN > 0 ? t("totalStale", { n: staleN }) : t("total")}: <b className="text-gray-900">{f.n(fresh.reduce((a, r) => a + (r.p1 ?? 0), 0))}</b>
              </p>
            </>
          )}
        </Tile>
      </div>

      <div className="col-span-12">
        <Tile title={t("sync")} note={t("syncNote")} icon={ClockIcon}>
          {d.tenants.map((r) => (
            <div key={r.id} className={cn(ROW, "grid grid-cols-[8rem_minmax(0,1fr)] items-center gap-2 py-1 sm:grid-cols-[12rem_minmax(0,1fr)]")}>
              <span className="truncate text-sm text-gray-800" title={r.name}>{r.name}</span>
              <span className="flex flex-wrap gap-0.5" role="img" aria-label={t("syncLabel", { n: r.sync24h.length })}>
                {r.sync24h.length === 0 ? <span className="text-xs text-gray-400">{t("noRuns")}</span> : r.sync24h.map((x) => (
                  <span key={x.at} title={`${formatDateTime(x.at, locale) ?? ""} · ${x.state}`} className={cn("h-4 w-2 rounded-sm", x.state === "complete" ? "bg-green-500" : x.state === "failed" ? "bg-red-500" : x.state === "partial" ? "bg-yellow-500" : "bg-gray-300")} />
                ))}
              </span>
            </div>
          ))}
        </Tile>
      </div>
    </div>
  );
}
