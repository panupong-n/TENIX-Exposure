import { DataStatus, isStale, type Completeness } from "@/components/shared/data-status";
import { EmptyState, ErrorState } from "@/components/shared/empty-state";
import { useDrawers } from "@/components/shared/drawers-context";
import { useWidth } from "@/components/shared/graph";
import { PageMeta } from "@/components/shared/page-meta";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { GraphSkeleton } from "@/components/shared/skeletons";
import { StaleStamp } from "@/components/shared/stale-stamp";
import { TierBadge, type Tier } from "@/components/shared/tier-badge";
import { useWatchlist, WatchStar } from "@/components/shared/watch-star";
import { Button } from "@/components/ui/button";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { SEVERITY_COLOR } from "@/lib/chart";
import { cn } from "@/utils";
import { formatNumber } from "@/utils/format";
import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { Cards, FixTable } from "./cards";
import { Diagram } from "./diagram";
import { Matrix } from "./matrix";
import { fixModel, focusModel, HOSTS, P1, P2, type Model } from "./models";
import { GraphSearch } from "./search";
import { SideList, type ListKind, type RowActions } from "./side-list";
import { CLEAR_DIM, filterParams, focusParam, useGraphState, type Dim, type EntityType, type Lens, type Meta } from "./state";
import { Crumbs, Filters, LensTabs } from "./toolbar";
import { fillLabels, shapeOf, type FixData, type FocusData, type GraphData, type MatrixData, type SearchItem } from "./types";

const card = "rounded-xl border border-gray-200 bg-white";
const NO_DATA = ["not_synced", "no_connection", "no_cids"];
const phone = () => window.matchMedia("(max-width: 759px)");
const subscribe = (cb: () => void) => { const m = phone(); m.addEventListener("change", cb); return () => m.removeEventListener("change", cb); };

/** Falcon holds more than we keep in detail: say so as "held X of Y" even when the server did not label the slice. */
function normalise(c: Completeness | undefined): Completeness | undefined {
  const cov = c?.coverage;
  return c && cov && !cov.mode && cov.falconTotal && cov.held < cov.falconTotal ? { ...c, coverage: { ...cov, mode: "priority" } } : c;
}

export default function GraphPage() {
  const t = useTranslations("graphView");
  const locale = useLocale();
  const { scoped } = useOrg();
  const { state, go } = useGraphState();
  const drawers = useDrawers() as ReturnType<typeof useDrawers> & { openFix?: (id: string) => void };
  const isPhone = useSyncExternalStore((cb) => subscribe(cb), () => phone().matches, () => false);
  const [view, setView] = useState<"graph" | "table">("graph");
  const [notice, setNotice] = useState("");
  const scroller = useRef<HTMLDivElement>(null);
  const n = (v: number) => formatNumber(v, locale);
  const num = (v?: number) => (v == null ? "–" : n(v));

  const lens: Lens = state.focus ? "focus" : state.lens;
  const pick = lens === "focus" && !state.focus;
  const meta = useApi<Meta>(scoped("/api/exposure/graph/meta"));
  const q = filterParams(state, lens === "fix");
  q.set("lens", lens);
  if (state.focus) { q.set("type", state.focus.type); q.set("id", state.focus.id); }
  const res = useApi<GraphData>(pick ? null : scoped(`/api/exposure/graph?${q}`));
  const d = res.data && shapeOf(res.data) === lens ? fillLabels(res.data) : null;

  const by: Dim = state.by || (d && "by" in d ? d.by : undefined) || (meta.data?.dims?.group === false ? "os" : "group");
  const dim = t(`filters.dim.${by}`);
  const unit = t(state.tiers.length === 1 && state.tiers[0] === "P1" ? "unit.p1" : "unit.all");
  const comp = normalise(d?.completeness ?? meta.data?.completeness);
  const stale = isStale(comp) || comp?.state === "failed";

  const flash = (msg: string) => { setNotice(msg); window.setTimeout(() => setNotice(""), 4000); };
  const open = (type: EntityType, id: string) => {
    if (type === "host") drawers.openDevice(id);
    else if (type === "cve") drawers.openCve(id);
    else if (type === "product") drawers.openSoftware(id);
    else if (drawers.openFix) drawers.openFix(id);
    else go({ fix: id }, true); // the ?fix= drawer reads this param
  };
  const drill = (kind: EntityType | "dim", id: string, _label?: string) => {
    if (kind === "dim") go({ ...CLEAR_DIM, by, [by]: id }, true);
    else go({ focus: focusParam(kind, id) }, true);
  };
  const clearAll = () => go({ tier: null, kev: null, internet: null, ...CLEAR_DIM });
  const model: Model = {
    t, n, unit, dim, go: drill,
    other: () => { scroller.current?.scrollTo({ top: 540, behavior: "smooth" }); flash(t("node.otherToast")); },
    noFix: () => flash(t("node.noFixToast")),
    center: () => state.focus && d && "center" in d && open(d.type, d.center.id),
  };
  const rowActions: RowActions = { drill: (kind, id) => drill(kind, id), open };

  const focused = d && "center" in d ? d : null;
  const steps: { label: string; go?: () => void }[] = [{ label: t(lens === "focus" && !state.focus ? "lens.focus" : "crumb.root"), go: () => go({ focus: null, ...CLEAR_DIM }) }];
  if (state.focus) steps.push({ label: t(`crumb.${state.focus.type}`, { name: focused?.center.label ?? state.focus.id }), go: () => go({ ...CLEAR_DIM }) });
  if (state.value) steps.push({ label: t(`crumb.${state.value.dim}`, { name: state.value.name }) });
  const back = () => { if (state.value) go({ ...CLEAR_DIM }); else if (state.focus) go({ focus: null }); };

  // Esc goes up one level, unless a field, the search list or a drawer has it
  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented || document.querySelector("[role=dialog]")) return;
      if ((e.target as HTMLElement | null)?.closest("input,select,textarea,[role=combobox],[role=listbox]")) return;
      back();
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  });

  const lensCall = (l: Lens) => go({ lens: l, focus: null, ...CLEAR_DIM });
  const picked = (it: SearchItem) => go({ lens: "focus", focus: focusParam(it.kind, it.id), ...CLEAR_DIM }, true);

  const head = (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <h1 className="text-lg font-semibold text-gray-800">{t("title")}</h1>
      <div className="min-w-0 flex-1 basis-80"><DataStatus completeness={comp} /></div>
    </div>
  );
  const tools = (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <LensTabs lens={lens} onPick={lensCall} />
        <GraphSearch onPick={picked} />
      </div>
      <Filters state={state} by={by} meta={meta.data} showTop={lens === "fix"} go={(p) => go(p)} />
      <Crumbs steps={steps} onBack={back} />
    </>
  );
  // `bare`: nothing to filter yet (no data), so only the strip and the message
  const frame = (body: ReactNode, bare = false) => (
    <>
      <PageMeta title={`${t("title")} | 10CYBER Exposure`} description={t("description")} />
      <div className="flex flex-col gap-2.5">{head}{!bare && tools}{body}</div>
    </>
  );
  const message = (title: string, body: string, action?: ReactNode, bare = false) =>
    frame(<div className={card}><EmptyState title={title}>{body}</EmptyState>{action && <div className="flex justify-center pb-6">{action}</div>}</div>, bare);

  if (res.error?.code === "tenant_required") return message(t("state.orgTitle"), t("state.orgBody"));
  if (res.error?.status === 404) return message(t("focus.unknown"), "", <Button size="sm" variant="outline" onClick={back}>← {t("crumb.back")}</Button>);
  if (res.error) return frame(<div className={card}><ErrorState error={res.error} onRetry={res.reload} /></div>);
  if (pick) return frame(<Pick onHost={(aid) => drill("host", aid)} />);
  if (!d && comp && NO_DATA.includes(comp.state)) return message(t("state.noneTitle"), t("state.noneBody"), undefined, true);
  if (!d) return frame(<GraphSkeleton />);

  const empty = "cols" in d ? d.rows.length === 0 : "center" in d ? (d.center.hosts ?? d.totals?.hosts ?? 1) === 0 || d.center.findings === 0 : d.left.length === 0 || d.totals?.hosts === 0;
  if (comp && (NO_DATA.includes(comp.state) || comp.state === "failed") && empty) return message(t("state.noneTitle"), t("state.noneBody"), undefined, true);
  if (empty) return message(t("state.emptyTitle"), t("state.emptyBody"), <Button size="sm" onClick={clearAll}>{t("state.clear")}</Button>);

  const hostsMode = lens === "fix" ? !!state.value : false;
  const listKind: ListKind = state.focus ? (state.focus.type === "host" ? "hostCves" : "host") : lens === "matrix" ? "product" : hostsMode ? "host" : "fix";
  const lq = filterParams(state);
  lq.set("kind", listKind);
  if (state.focus) { if (listKind === "host") lq.set("type", state.focus.type); lq.set("id", state.focus.id); }

  const title = t(`canvas.${lens}`, { dim });
  const sub = "cols" in d ? t("sub.matrix", { hosts: num(d.totals?.hosts), products: num(d.totals?.products ?? d.rows.length) })
    : "center" in d ? t("sub.focus", { hosts: num(d.totals?.hosts ?? d.center.hosts), findings: num(d.totals?.findings ?? d.center.findings), unit })
      : t("sub.fix", { fixes: num(d.totals?.fixes), hosts: num(d.totals?.hosts), findings: num(d.totals?.findings), unit });
  const cov = comp?.coverage;
  const share = cov?.priorityTotal ? cov.priorityHeld / cov.priorityTotal : cov?.falconTotal ? cov.held / cov.falconTotal : null;
  const partial = comp?.state === "partial";

  return frame(
    <div className={cn("grid items-start gap-3", !isPhone && "lg:grid-cols-[minmax(0,1fr)_340px]")}>
      <section className={cn(card, "min-w-0 p-3 transition-opacity", res.loading && "opacity-60")} aria-label={title} aria-busy={res.loading}>
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 pb-1.5">
          <div className="min-w-0">
            <h2 className="inline text-sm font-semibold text-gray-800">{title}</h2>
            {stale && <StaleStamp className="ms-1.5 align-middle" />}
            {partial && <span className="ms-1.5 inline-flex items-center rounded bg-gray-100 px-1.5 text-xs leading-5 font-medium text-gray-600 align-middle">{share == null ? t("stamp.partialNoPct") : t("stamp.partial", { percent: Math.round(share * 100) })}</span>}
            <p className="text-[12.5px] text-gray-500">{sub}</p>
          </div>
          {lens === "fix" && !isPhone && (
            <div role="group" aria-label={t("view.label")} className="inline-flex rounded-lg border border-gray-200 p-0.5">
              {(["graph", "table"] as const).map((v) => (
                <button key={v} type="button" aria-pressed={view === v} onClick={() => setView(v)} className={cn("rounded-md px-2.5 py-0.5 text-[13px] font-medium", view === v ? "bg-brand-50 text-brand-700" : "text-gray-500")}>{t(`view.${v}`)}</button>
              ))}
            </div>
          )}
        </div>
        {notice && <p role="status" className="mb-1.5 rounded-md bg-gray-100 px-2 py-1 text-xs text-gray-700">{notice}</p>}
        <Measured className={cn(stale && "opacity-55 grayscale-[.4]")}>
          {(width) => isPhone && lens !== "matrix" ? <Cards data={d} m={model} />
            : "cols" in d ? <Matrix data={d as MatrixData} dim={dim} onProduct={(id, l) => model.go("product", id, l)} onDim={(id, l) => model.go("dim", id, l)} onCell={(row, col) => go({ focus: focusParam("product", row), by, ...CLEAR_DIM, [by]: col }, true)} />
              : "center" in d ? <FocusView d={d} m={model} width={width} />
                : view === "table" ? <FixTable data={d as FixData} m={model} />
                  : <FixView d={d as FixData} m={model} width={width} />}
        </Measured>
        {lens !== "matrix" && !isPhone && view === "graph" && <Legend lens={lens} dots={"center" in d && d.type !== "host" && d.type !== "cve"} />}
        {lens === "matrix" && <MatrixNote d={d as MatrixData} />}
      </section>
      <aside className={cn(card, "flex max-h-[640px] min-w-0 flex-col lg:sticky lg:top-2")} aria-label={t("panel.label")}>
        <PanelHead d={d} lens={lens} kind={listKind} dim={dim} unit={unit} open={open} />
        <SideList key={`${listKind}?${lq}`} kind={listKind} base={lq.toString()} a={rowActions} scroller={scroller} />
      </aside>
    </div>,
  );
}

/** Measures its own width (the drawn graph fits the card; there is no zoom or pan). */
function Measured({ children, className }: { children: (width: number) => ReactNode; className?: string }) {
  const [ref, width] = useWidth();
  return <div ref={ref} className={className} data-testid="graph-canvas">{children(width)}</div>;
}

function FixView({ d, m, width }: { d: FixData; m: Model; width: number }) {
  const t = m.t;
  if (width === 0) return null;
  const W = Math.max(300, width), { cols, links, label } = fixModel(d, W, m);
  return (
    <>
      <div className="flex justify-between px-0.5 text-xs font-medium text-gray-500" aria-hidden="true"><span>{t("col.fix")}</span><span>{d.mode === "host" ? t("col.hostsMax") : m.dim}</span></div>
      {d.mode === "host" && <p className="px-0.5 pb-1 text-xs text-gray-500">{t("hostsHint")}</p>}
      <Diagram cols={cols} links={links} width={W} label={label} />
    </>
  );
}

function FocusView({ d, m, width }: { d: FocusData; m: Model; width: number }) {
  const t = m.t;
  if (width === 0) return null;
  const W = Math.max(300, width), { cols, links, label } = focusModel(d, W, m);
  const left = d.type === "host" ? t("col.partsHost") : d.type === "cve" ? t("col.partsCveOf") : t("col.partsCve");
  return (
    <>
      <div className="flex justify-between px-0.5 text-xs font-medium text-gray-500" aria-hidden="true"><span>{left}</span><span>{d.type === "host" ? "" : d.mode === "host" ? t("col.hostsMax") : m.dim}</span></div>
      <Diagram cols={cols} links={links} width={W} label={label} />
    </>
  );
}

function Legend({ lens, dots }: { lens: Lens; dots: boolean }) {
  const t = useTranslations("graphView.legend");
  const sw = (c: string) => <i className="me-1 inline-block h-[7px] w-3.5 rounded-sm align-middle" style={{ background: c }} />;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-3.5 gap-y-1 text-xs text-gray-500">
      {lens === "fix" && <><span>{sw(P1)}{t("p1")}</span><span>{sw(P2)}{t("p2")}</span></>}
      <span>{sw(HOSTS)}{t("hosts")}</span><span>{t("width")}</span>
      {dots && <span>{t("dots")}: {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => <span key={s} className="ms-1.5"><i className="me-1 inline-block size-2 rounded-full align-middle" style={{ background: SEVERITY_COLOR[s] }} />{s.charAt(0) + s.slice(1).toLowerCase()}</span>)}</span>}
    </div>
  );
}

function MatrixNote({ d }: { d: MatrixData }) {
  const t = useTranslations("graphView");
  const locale = useLocale();
  return (
    <div className="mt-2 flex flex-wrap gap-x-3.5 gap-y-1 text-xs text-gray-500">
      <span><i className="me-1 inline-block h-[7px] w-[60px] rounded-sm align-middle" style={{ background: "linear-gradient(90deg,#F2F6FF,#2A31D8)" }} />{t("legend.shade")}</span>
      <span>{t("legend.cell")}</span><span>{t("legend.rows")}</span>
      {d.rowsOther && <span>{t("matrix.shown", { shown: formatNumber(d.rows.length, locale), total: formatNumber(d.totals?.products ?? d.rows.length + d.rowsOther.count, locale) })}</span>}
    </div>
  );
}

/** Blast radius with nothing chosen yet: search, or one of the watched hosts. */
function Pick({ onHost }: { onHost: (aid: string) => void }) {
  const t = useTranslations("graphView.focus");
  const w = useWatchlist();
  const hosts = w.data?.hosts ?? [];
  return (
    <div className={cn(card, "flex flex-col gap-2 p-4")}>
      <h2 className="text-[15px] font-semibold text-gray-800">{t("pickTitle")}</h2>
      <p className="text-[13px] text-gray-500">{t("pickHint")}</p>
      {hosts.length > 0 && (
        <div>
          <p className="mb-1 text-xs text-gray-500">{t("pickWatched")} ({hosts.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {hosts.map((h) => <button key={h.aid} type="button" onClick={() => onHost(h.aid)} className="rounded-lg border border-gray-200 bg-white px-2.5 py-0.5 text-[13px] hover:border-brand-300 hover:bg-brand-50">★ {h.hostname ?? h.aid}</button>)}
          </div>
        </div>
      )}
    </div>
  );
}

function PanelHead({ d, lens, kind, dim, unit, open }: { d: GraphData; lens: Lens; kind: ListKind; dim: string; unit: string; open: (type: EntityType, id: string) => void }) {
  const t = useTranslations("graphView");
  const locale = useLocale();
  const n = (v: number) => formatNumber(v, locale);
  if ("center" in d) {
    const c = d.center;
    const kev = typeof c.kev === "number" ? c.kev : 0;
    return (
      <div className="border-b border-gray-100 px-3 pt-2.5 pb-2">
        <h3 className="text-sm leading-snug font-semibold break-words text-gray-800">{c.label}</h3>
        <p className="text-[12.5px] text-gray-500">{t("panel.metaFocus", { sub: c.sub ?? "", hosts: n(c.hosts ?? 0), findings: n(c.findings ?? 0), unit })}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1">
          {c.sev && <SeverityBadge severity={c.sev} />}
          {(c.kev === true || kev > 0) && <span className="inline-flex h-5 items-center rounded-md bg-gray-700 px-1.5 text-xs font-medium text-white">{kev ? t("focus.kevN", { count: n(kev) }) : t("focus.kev")}</span>}
          {(c.inet || !!c.inetHosts) && <span className="inline-flex h-5 items-center rounded-md bg-gray-100 px-1.5 text-xs font-medium text-gray-700">{c.inetHosts ? t("focus.internetN", { count: n(c.inetHosts) }) : t("focus.internet")}</span>}
          {c.tier && <TierBadge tier={c.tier as Tier} help={false} />}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Button size="sm" onClick={() => open(d.type, c.id)}>{t("focus.open")}</Button>
          {d.type === "host" && <WatchStar aid={c.id} hostname={c.label} showLabel />}
        </div>
      </div>
    );
  }
  const [title, meta] = lens === "matrix" ? [t("panel.products"), t("panel.productsMeta")] : kind === "host" ? [t("panel.hostsIn", { dim }), t("panel.hostsMeta")] : [t("panel.fixes"), t("panel.fixesMeta")];
  return (
    <div className="border-b border-gray-100 px-3 pt-2.5 pb-2">
      <h3 className="text-sm font-semibold text-gray-800">{title}</h3>
      <p className="text-[12.5px] text-gray-500">{meta}</p>
    </div>
  );
}
