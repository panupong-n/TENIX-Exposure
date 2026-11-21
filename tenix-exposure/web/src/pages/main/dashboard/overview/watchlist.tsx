// Skeleton: the host search below loads with useApi and shows a SearchSkeleton row; the list itself loads through the shared cache (WatchlistSkeleton).
import { useDrawers } from "@/components/shared/drawers-context";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { ChartCardSkeleton } from "@/components/shared/skeletons";
import { useWatchlist, type WatchAuto, type WatchHost } from "@/components/shared/watch-star";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { CheckCircleIcon, EyeIcon, GearIcon, PencilIcon, PlusIcon, XIcon } from "@/icons";
import { ErrorState } from "@/components/shared/empty-state";
import { cn } from "@/utils";
import { formatAgo, nameOrder } from "@/utils/format";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { LINK, NUM, ROW, useDeviceName, useFmt } from "./parts";
import { Tile, TILE } from "./tile";
import type { HostsV2 } from "./types";

function SearchSkeleton() { return <Skeleton className="h-8 w-full" aria-hidden="true" />; }

/** The "add a host" box: 2+ letters, up to 8 hosts (Thai dictionary order), a + button adds one. */
function AddHost({ canEdit, add, watched }: { canEdit: boolean; add: (aid: string, name: string | null) => Promise<boolean>; watched: (aid: string) => boolean }) {
  const t = useTranslations("ovw.k");
  const name = useDeviceName();
  const { scoped } = useOrg();
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  useEffect(() => { const id = window.setTimeout(() => setQ(text.trim()), 300); return () => window.clearTimeout(id); }, [text]);
  const res = useApi<HostsV2>(q.length >= 2 ? scoped(`/api/exposure/v2/hosts?q=${encodeURIComponent(q)}&sort=hostname&pageSize=8`) : null);
  const found = (res.data?.rows ?? []).filter((r) => !watched(r.aid)).sort((a, b) => nameOrder.compare(a.hostname ?? "", b.hostname ?? ""));
  return (
    <div className="relative min-w-0 flex-1 basis-48">
      <Input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder={t("addPlaceholder")} aria-label={t("addPlaceholder")} disabled={!canEdit} className="h-8 text-sm" />
      {q.length >= 2 && (
        <ul className="absolute inset-x-0 top-9 z-20 max-h-64 overflow-y-auto rounded-lg border border-gray-200 bg-white p-1 shadow-theme-lg">
          {res.loading && !res.data && <li className="p-1"><SearchSkeleton /></li>}
          {res.data && found.length === 0 && <li className="px-2 py-1.5 text-xs text-gray-500">{t("noMatch")}</li>}
          {found.map((r) => (
            <li key={r.aid}>
              <button type="button" onClick={() => { void add(r.aid, r.hostname).then(() => { setText(""); setQ(""); }); }} className="flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-start text-sm hover:bg-gray-50">
                <span className="min-w-0 truncate">{name(r.hostname, r.aid)}<span className="text-xs text-gray-500"> {[r.productType, r.platform].filter(Boolean).join(" · ")}</span></span>
                <PlusIcon className="size-4 shrink-0 text-brand-600" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Note({ h, canEdit, save }: { h: WatchHost; canEdit: boolean; save: (note: string | null) => void }) {
  const t = useTranslations("ovw.k");
  const [edit, setEdit] = useState(false);
  const [v, setV] = useState(h.note ?? "");
  if (edit) {
    return (
      <Input autoFocus value={v} maxLength={200} aria-label={t("note")} onChange={(e) => setV(e.target.value)} className="h-7 text-xs"
        onBlur={() => { setEdit(false); if ((h.note ?? "") !== v.trim()) save(v.trim() || null); }}
        onKeyDown={(e) => { if (e.key === "Enter") e.currentTarget.blur(); if (e.key === "Escape") { setV(h.note ?? ""); setEdit(false); } }} />
    );
  }
  return (
    <button type="button" disabled={!canEdit} onClick={() => { setV(h.note ?? ""); setEdit(true); }} className="flex max-w-full items-center gap-1 rounded text-start text-xs leading-4 text-gray-500 italic hover:text-gray-700 disabled:hover:text-gray-500" title={h.note ?? t("addNote")}>
      <span className="truncate">{h.note || t("addNote")}</span>{canEdit && <PencilIcon className="size-3 shrink-0" aria-hidden="true" />}
    </button>
  );
}

/** The manual asset level of a watched host: it feeds the notification level. Empty = automatic (Falcon's criticality, then the host group). */
function LevelPick({ h, canEdit, save }: { h: WatchHost; canEdit: boolean; save: (level: string | null) => void }) {
  const t = useTranslations("ovw.k");
  const tSev = useTranslations("severity");
  return (
    <select value={h.criticality ?? ""} disabled={!canEdit} onChange={(e) => save(e.target.value || null)} aria-label={`${t("assetLevel")}: ${h.hostname ?? h.aid}`} title={t("assetLevelHint")}
      className="h-7 shrink-0 rounded border border-gray-200 bg-white py-0 ps-1.5 pe-6 text-xs leading-none text-gray-600 disabled:opacity-60" data-testid={`watch-level-${h.aid}`}>
      <option value="">{t("assetLevelAuto")}</option>
      {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((l) => <option key={l} value={l}>{tSev(l)}</option>)}
    </select>
  );
}

const AUTO_STYLE: Record<WatchAuto["type"], string> = { kev_added: "bg-red-50 text-red-700", critical_new: "bg-red-50 text-red-700", cve_news: "bg-sky-50 text-sky-700", first_impact: "bg-gray-100 text-gray-700" };

/** Block K, รายการเฝ้าระวัง: the hosts the team watches (note, worst severity, P1, new in 24 h, remove) and the automatic urgent items. Same cache as every star in the app. */
export default function Watchlist({ stale }: { stale: boolean }) {
  const t = useTranslations("ovw.k");
  const name = useDeviceName();
  const f = useFmt();
  const locale = useLocale();
  const { openDevice, openCve } = useDrawers();
  const w = useWatchlist();
  if (w.error && !w.data) return <div className={TILE}><ErrorState error={w.error} onRetry={w.reload} /></div>;
  if (!w.data) return <ChartCardSkeleton className="h-48" />;
  const d = w.data;
  const canEdit = d.canEdit !== false;
  const hosts = [...d.hosts].sort((a, b) => ((b.newP1_24h ?? 0) + (b.newCritical24h ?? 0)) - ((a.newP1_24h ?? 0) + (a.newCritical24h ?? 0)) || (b.p1 ?? -1) - (a.p1 ?? -1) || nameOrder.compare(a.hostname ?? "", b.hostname ?? ""));
  const old = stale || d.completeness?.state === "failed";
  return (
    <Tile
      title={t("title")} note={t("count", { hosts: f.n(hosts.length), auto: f.n(d.auto.length) })} icon={EyeIcon} className="h-full"
      actions={<>{old && <StaleStamp />}<Link to="?settings=notify" className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-gray-300 px-3 text-xs font-medium text-gray-700 hover:bg-gray-50"><GearIcon className="size-4" aria-hidden="true" />{t("notify")}</Link></>}
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <AddHost canEdit={canEdit} add={(aid, name) => w.add(aid, name)} watched={w.isWatched} />
        <span className="text-xs text-gray-500 tabular-nums">{t("limit", { n: f.n(hosts.length), max: f.n(d.limit) })}</span>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-x-4 gap-y-3 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <section aria-label={t("mine")}>
          <h4 className="text-xs leading-5 font-semibold text-gray-700">{t("mine")}</h4>
          {hosts.length === 0 ? (
            <div className="py-2 text-sm leading-5 text-gray-600">
              <p>{t("noneTitle")}</p>
              {d.suggestions && d.suggestions.length > 0 && (
                <ul className="mt-1 space-y-0.5">
                  {d.suggestions.map((s) => (
                    <li key={s.aid}><button type="button" disabled={!canEdit} onClick={() => void w.add(s.aid, s.hostname)} className="flex w-full items-center justify-between gap-2 rounded px-1 text-start hover:bg-gray-50"><span className="min-w-0 truncate">{name(s.hostname, s.aid)}{s.p1 != null && <span className="text-xs text-gray-500"> · P1 {f.n(s.p1)}</span>}</span><span className="inline-flex shrink-0 items-center gap-1 text-xs text-brand-600"><PlusIcon className="size-3.5" aria-hidden="true" />{t("watch")}</span></button></li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            hosts.map((h) => (
              <div key={h.aid} className={cn(ROW, "grid grid-cols-[minmax(0,1fr)_auto_3rem_1.5rem] items-center gap-x-2 py-1 sm:grid-cols-[minmax(0,1fr)_5.5rem_3.5rem_4.5rem_1.5rem]")}>
                <div className="min-w-0">
                  <button type="button" onClick={() => openDevice(h.aid)} className="flex max-w-full items-center gap-1.5 rounded text-start text-sm leading-5 font-medium text-gray-900 hover:text-brand-700 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                    <span className="truncate" title={h.hostname ?? h.aid}>{name(h.hostname, h.aid)}</span>
                    {h.missing && <span className="shrink-0 rounded bg-gray-100 px-1.5 text-xs text-gray-600">{t("missing")}</span>}
                  </button>
                  <span className="flex min-w-0 items-center gap-2"><LevelPick h={h} canEdit={canEdit} save={(level) => void w.setLevel(h.aid, h.hostname, level)} /><span className="min-w-0 max-sm:hidden"><Note h={h} canEdit={canEdit} save={(note) => void w.setNote(h.aid, h.hostname, note)} /></span></span>
                </div>
                <span>{h.worstSeverity && !h.missing ? <SeverityBadge severity={h.worstSeverity} /> : <span className="text-xs text-gray-400">{t("noDetail")}</span>}</span>
                <span className={cn(NUM, "text-sm font-medium")}>{h.missing ? "–" : f.cell(h.p1)}</span>
                <span className="text-xs max-sm:hidden">
                  {!old && ((h.newP1_24h ?? 0) > 0 || (h.newCritical24h ?? 0) > 0) ? <span className="rounded bg-sky-50 px-1.5 py-0.5 font-medium whitespace-nowrap text-sky-700">{(h.newP1_24h ?? 0) > 0 ? `+${f.cell(h.newP1_24h)} P1` : `+${f.cell(h.newCritical24h)} Critical`}</span> : <span className="text-gray-400">–</span>}
                </span>
                <button type="button" disabled={!canEdit} aria-label={t("remove", { name: h.hostname ?? h.aid })} title={t("remove", { name: h.hostname ?? h.aid })} onClick={() => void w.remove(h.aid, h.hostname)} className="inline-flex size-6 items-center justify-center rounded text-gray-400 hover:bg-gray-100 hover:text-gray-700 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none disabled:opacity-40"><XIcon className="size-4" aria-hidden="true" /></button>
              </div>
            ))
          )}
        </section>
        <section aria-label={t("auto")}>
          <h4 className="text-xs leading-5 font-semibold text-gray-700">{t("auto")}</h4>
          {d.auto.length === 0 ? (
            <p className="flex items-center gap-2 py-2 text-sm leading-5 text-gray-600"><CheckCircleIcon className="size-5 shrink-0 text-green-500" aria-hidden="true" />{t("autoNone")}</p>
          ) : (
            d.auto.slice(0, 5).map((a, i) => {
              const body = (
                <>
                  <span className="flex items-center justify-between gap-2">
                    <span className="flex min-w-0 items-center gap-1.5"><span className={cn("shrink-0 rounded px-1.5 text-xs leading-5 font-medium", AUTO_STYLE[a.type])}>{t(`type.${a.type}`)}</span><span className="truncate text-sm leading-5 font-medium text-gray-900">{a.cve ?? t("criticalNew", { findings: f.n(a.findings ?? 0), devices: f.n(a.devices) })}</span></span>
                    <span className="shrink-0 text-xs text-gray-500">{formatAgo(a.at, locale)}</span>
                  </span>
                  <span className="block truncate text-xs leading-4 text-gray-500">{a.cve ? `${a.title ? `${a.title} · ` : ""}${t("devices", { n: f.n(a.devices) })}` : ""}</span>
                </>
              );
              return a.cve
                ? <button key={`${a.type}${a.cve}${i}`} type="button" onClick={() => openCve(a.cve!)} className={cn(ROW, "block w-full py-1 text-start hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none")}>{body}</button>
                : <div key={`${a.type}${i}`} className={cn(ROW, "py-1")}>{body}</div>;
            })
          )}
        </section>
      </div>
      <p className="mt-auto pt-2 text-xs leading-5 text-gray-500">{t("hint")} <Link to="?settings=notify" className={LINK}>{t("notify")}</Link></p>
    </Tile>
  );
}
