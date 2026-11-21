// Skeleton: this is a section of notify-panel.tsx, which loads its data with useApi and shows a FormSkeleton.
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useTranslations } from "@/i18n";
import { SEVERITY_COLOR } from "@/lib/chart";
import { cn } from "@/utils";

export const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type Level = (typeof LEVELS)[number];
export type Matrix = Record<Level, Record<Level, Level>>;
export interface LevelPrefs { matrixOn: boolean; matrix: Matrix; escAlert: boolean; escDays: number; escKev: boolean; groupLevels: { group: string; level: Level }[] }
export interface LevelView { defaultMatrix: Matrix; evidence?: { state: "unknown" | "ok" | "forbidden" }; knownGroups?: string[] }

// py-0 + leading-none: the theme's select padding made a 28 px box clip the text
const sel = "h-8 rounded-md border border-gray-300 bg-white py-0 ps-2 pe-6 text-xs leading-none text-gray-800 disabled:opacity-60";
const chip = (l: Level) => <span className="inline-block rounded-full px-2 text-xs font-semibold text-white" style={{ backgroundColor: SEVERITY_COLOR[l] }}>{l[0] + l.slice(1).toLowerCase()}</span>;

/** The notify-level section of the LINE settings: the 4x4 matrix, the escalation toggles and the host-group to level mapping. The server holds the default; this only edits a draft. */
export function NotifyLevels({ p, patch, dis, view }: { p: LevelPrefs; patch: (x: Partial<LevelPrefs>) => void; dis: boolean; view: LevelView }) {
  const t = useTranslations("notifyPrefs.lv");
  const tSev = useTranslations("severity");
  const setCell = (c: Level, a: Level, v: Level) => patch({ matrix: { ...p.matrix, [c]: { ...p.matrix[c], [a]: v } } });
  const isDefault = JSON.stringify(p.matrix) === JSON.stringify(view.defaultMatrix);
  const setGroup = (i: number, x: Partial<{ group: string; level: Level }>) => patch({ groupLevels: p.groupLevels.map((g, j) => (j === i ? { ...g, ...x } : g)) });
  const ev = view.evidence?.state ?? "unknown";
  const examples: [Level, Level][] = [["CRITICAL", "LOW"], ["MEDIUM", "CRITICAL"]];
  return (
    <fieldset className="flex min-w-0 flex-col gap-2 rounded-xl border border-gray-200 p-3" data-testid="notify-levels">
      <legend className="px-1 text-sm font-semibold text-gray-800">{t("title")}</legend>
      <label className="flex items-start gap-2 text-sm text-gray-800">
        <Switch checked={p.matrixOn} disabled={dis} onCheckedChange={(v) => patch({ matrixOn: v })} aria-label={t("on")} data-testid="notify-matrix-on" />
        <span className="min-w-0">{t("on")}<span className="block text-xs text-gray-500">{p.matrixOn ? t("hint") : t("off")}</span></span>
      </label>
      <div className={cn("flex min-w-0 flex-col gap-2", !p.matrixOn && "opacity-60")}>
        <div role="group" aria-label={t("gridLabel")} className="grid grid-cols-[3.5rem_repeat(4,minmax(0,1fr))] items-center gap-1 text-xs sm:grid-cols-5" data-testid="notify-matrix">
          <span className="text-gray-500">{t("corner")}</span>
          {LEVELS.map((a) => <span key={a} className="text-center font-semibold" style={{ color: SEVERITY_COLOR[a] }}>{tSev(a)}</span>)}
          {LEVELS.map((c) => (
            <div key={c} className="contents">
              <span className="font-semibold" style={{ color: SEVERITY_COLOR[c] }}>{tSev(c)}</span>
              {LEVELS.map((a) => (
                <select key={a} value={p.matrix[c][a]} disabled={dis} onChange={(e) => setCell(c, a, e.target.value as Level)} className={cn(sel, "w-full min-w-0 font-semibold max-sm:ps-0.5 max-sm:pe-5 max-sm:text-[11px]")} style={{ color: SEVERITY_COLOR[p.matrix[c][a]] }}
                  aria-label={t("cell", { cve: c, asset: a })} data-testid={`notify-cell-${c}-${a}`}>
                  {LEVELS.map((l) => <option key={l} value={l}>{tSev(l)}</option>)}
                </select>
              ))}
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-700">
          <span className="font-semibold">{t("exTitle")}</span>
          {examples.map(([c, a]) => <span key={c + a} className="flex items-center gap-1" data-testid={`notify-example-${c}-${a}`}>{t("exCve", { cve: c[0] + c.slice(1).toLowerCase(), asset: a[0] + a.slice(1).toLowerCase() })} → {chip(p.matrix[c][a])}</span>)}
          {!dis && <Button size="sm" variant="outline" className="ms-auto h-7 px-2 text-xs" disabled={isDefault} onClick={() => patch({ matrix: view.defaultMatrix })} data-testid="notify-matrix-reset">{t("reset")}</Button>}
        </div>

        <div className="flex flex-col gap-1.5 border-t border-gray-100 pt-2">
          <h4 className="text-xs font-semibold text-gray-800">{t("escTitle")}</h4>
          <div className="flex flex-wrap items-center gap-2 text-sm text-gray-800">
            <Switch checked={p.escAlert} disabled={dis} onCheckedChange={(v) => patch({ escAlert: v })} aria-label={t("escAlert")} data-testid="notify-esc-alert" />
            {t("escAlert")}
            <Input type="number" inputMode="numeric" min={1} max={30} value={p.escDays} disabled={dis} aria-label={t("escDays")} className="h-8 w-16 px-2 text-center tabular-nums" data-testid="notify-esc-days"
              onChange={(e) => patch({ escDays: Math.min(30, Math.max(1, Math.round(Number(e.target.value)) || 1)) })} />
            {t("escDays")}
          </div>
          <p role="status" className={cn("text-xs", ev === "forbidden" ? "font-medium text-amber-800" : "text-gray-500")} data-testid="notify-esc-status">{t(`ev.${ev}`)}</p>
          <label className="flex items-start gap-2 text-sm text-gray-800">
            <input type="checkbox" className="mt-1 size-4 accent-brand-500" checked={p.escKev} disabled={dis} onChange={(e) => patch({ escKev: e.target.checked })} data-testid="notify-esc-kev" />
            <span className="min-w-0">{t("escKev")}<span className="block text-xs text-gray-500">{t("escKevHint")}</span></span>
          </label>
        </div>

        <div className="flex flex-col gap-1.5 border-t border-gray-100 pt-2" data-testid="notify-groups">
          <h4 className="text-xs font-semibold text-gray-800">{t("groupsTitle")}</h4>
          <p className="text-xs text-gray-500">{t("groupsHint")} {t("sources")}</p>
          <datalist id="notify-known-groups">{(view.knownGroups ?? []).map((g) => <option key={g} value={g} />)}</datalist>
          {p.groupLevels.map((g, i) => (
            <div key={i} className="flex items-center gap-1.5">
              <Input list="notify-known-groups" value={g.group} maxLength={120} disabled={dis} aria-label={t("groupPlaceholder")} placeholder={t("groupPlaceholder")} className="h-8 min-w-0 flex-1 px-2 text-sm" data-testid="notify-group-name" onChange={(e) => setGroup(i, { group: e.target.value })} />
              <select value={g.level} disabled={dis} onChange={(e) => setGroup(i, { level: e.target.value as Level })} className={sel} data-testid="notify-group-level" aria-label={t("groupLevel", { name: g.group })}>
                {LEVELS.map((l) => <option key={l} value={l}>{tSev(l)}</option>)}
              </select>
              {!dis && <button type="button" onClick={() => patch({ groupLevels: p.groupLevels.filter((_, j) => j !== i) })} aria-label={t("groupRemove", { name: g.group })} className="inline-flex size-7 items-center justify-center rounded text-gray-400 hover:text-red-600">×</button>}
            </div>
          ))}
          {!dis && p.groupLevels.length < 100 && <Button size="sm" variant="outline" className="h-7 w-fit px-2 text-xs" onClick={() => patch({ groupLevels: [...p.groupLevels, { group: "", level: "HIGH" }] })} data-testid="notify-group-add">{t("groupAdd")}</Button>}
        </div>
      </div>
    </fieldset>
  );
}
