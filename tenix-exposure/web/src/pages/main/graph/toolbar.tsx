import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { CLEAR_DIM, type Dim, type GraphState, type Lens, type Meta } from "./state";

const toggle = "inline-flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-[13px] font-medium whitespace-nowrap focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none";
const on = "border-brand-300 bg-brand-50 text-brand-700";
const off = "border-gray-200 bg-white text-gray-700 hover:bg-gray-50";

export function LensTabs({ lens, onPick }: { lens: Lens; onPick: (l: Lens) => void }) {
  const t = useTranslations("graphView");
  return (
    <div role="tablist" aria-label={t("lensLabel")} className="inline-flex shrink-0 rounded-lg border border-gray-200 bg-white p-0.5">
      {(["fix", "matrix", "focus"] as const).map((l) => (
        <button key={l} type="button" role="tab" aria-selected={lens === l} onClick={() => onPick(l)}
          className={cn("rounded-md px-3 py-1 text-start text-sm leading-tight font-medium focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none", lens === l ? "bg-brand-50 text-brand-700" : "text-gray-500 hover:text-gray-800")}>
          {t(`lens.${l}`)}
          <small className="hidden text-[11px] font-normal text-gray-500 sm:block">{t(`lens.${l}Hint`)}</small>
        </button>
      ))}
    </div>
  );
}

/** Filters that apply on every lens: tier, KEV, internet-facing, group-by + value (group / OS / site), and the left-column size on the fix lens. */
export function Filters({ state, by, meta, showTop, go }: {
  state: GraphState; by: Dim; meta: Meta | null; showTop: boolean; go: (patch: Record<string, string | null>) => void;
}) {
  const f = useTranslations("graphView.filters");
  const tiers = (tier: "P1" | "P2" | "P3") => {
    const next = state.tiers.includes(tier) ? state.tiers.filter((x) => x !== tier) : [...state.tiers, tier].sort();
    if (next.length) go({ tier: next.join(",") });
  };
  const dims = (["group", "os", "site"] as const).filter((d) => meta?.dims?.[d] !== false);
  const dimItems = dims.map((d) => ({ value: d, label: f(`dim.${d}`) }));
  const list = (by === "group" ? meta?.groups : by === "os" ? meta?.os : meta?.sites) ?? [];
  const valueItems = [{ value: "all", label: f("all") }, ...list.map((i) => ({ value: i.id, label: `${i.label} (${i.hosts})` }))];
  const current = state.value?.dim === by ? state.value.name : "all";
  const topItems = ["10", "20"].map((v) => ({ value: v, label: f("topN", { count: v }) }));
  const p3 = meta?.tiers?.P3 === true;
  return (
    <div role="group" aria-label={f("label")} className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
      <span className="text-xs text-gray-500">{f("tier")}</span>
      <button type="button" aria-pressed={state.tiers.includes("P1")} onClick={() => tiers("P1")} className={cn(toggle, state.tiers.includes("P1") ? on : off)}>{f("p1")}</button>
      <button type="button" aria-pressed={state.tiers.includes("P2")} onClick={() => tiers("P2")} className={cn(toggle, state.tiers.includes("P2") ? on : off)}>{f("p2")}</button>
      <button type="button" aria-pressed={state.tiers.includes("P3")} disabled={!p3} onClick={() => tiers("P3")} title={p3 ? undefined : f("p3None")}
        className={cn(toggle, p3 ? (state.tiers.includes("P3") ? on : off) : "cursor-not-allowed border-dashed border-gray-200 bg-white text-gray-400")}>
        {f("p3")}{!p3 && <span className="text-[11.5px] font-normal">{f("p3None")}</span>}
      </button>
      <span className="ms-1.5 text-xs text-gray-500">{f("only")}</span>
      <button type="button" aria-pressed={state.kev} onClick={() => go({ kev: state.kev ? null : "1" })} className={cn(toggle, state.kev ? on : off)}>{f("kev")}</button>
      <button type="button" aria-pressed={state.internet} onClick={() => go({ internet: state.internet ? null : "1" })} className={cn(toggle, state.internet ? on : off)}>{f("internet")}</button>
      {/* the label stays with its select when the row wraps on a phone */}
      <span className="ms-1.5 flex items-center gap-2">
        <span className="text-xs text-gray-500">{f("by")}</span>
        <Select value={by} items={dimItems} onValueChange={(v) => go({ by: String(v), ...CLEAR_DIM })}>
          <SelectTrigger size="sm" className="w-40" aria-label={f("by")}><SelectValue /></SelectTrigger>
          <SelectContent>{dimItems.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
        </Select>
      </span>
      {list.length > 0 && (
        <Select value={current} items={valueItems} onValueChange={(v) => go({ ...CLEAR_DIM, by, [by]: v === "all" ? null : String(v) })}>
          <SelectTrigger size="sm" className="w-44" aria-label={`${f("value")} ${f(`dim.${by}`)}`}><SelectValue /></SelectTrigger>
          <SelectContent>{valueItems.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
        </Select>
      )}
      {showTop && (
        <Select value={state.top} items={topItems} onValueChange={(v) => go({ top: String(v) })}>
          <SelectTrigger size="sm" className="w-32" aria-label={f("top")}><SelectValue /></SelectTrigger>
          <SelectContent>{topItems.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
        </Select>
      )}
    </div>
  );
}

/** Where we are: whole organization > entity > group. Each item goes back to that level; "Back" (and Esc) goes up one. */
export function Crumbs({ steps, onBack }: { steps: { label: string; go?: () => void }[]; onBack: () => void }) {
  const t = useTranslations("graphView.crumb");
  if (steps.length < 2) return null;
  return (
    <nav aria-label={t("label")} className="flex flex-wrap items-center gap-x-1 gap-y-0.5 text-[13.5px]">
      <button type="button" onClick={onBack} className="me-1.5 rounded-md border border-gray-200 bg-white px-2 text-gray-700 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">← {t("back")}</button>
      {steps.map((s, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <span className="text-gray-400" aria-hidden="true">›</span>}
          {i < steps.length - 1
            ? <button type="button" onClick={s.go} className="rounded px-1 font-medium text-brand-600 hover:bg-brand-50 focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:outline-none">{s.label}</button>
            : <span aria-current="location" className="px-1 font-semibold text-gray-900">{s.label}</span>}
        </span>
      ))}
    </nav>
  );
}
