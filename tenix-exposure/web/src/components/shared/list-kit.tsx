import { StaleStamp } from "@/components/shared/stale-stamp";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useLocale, useTranslations } from "@/i18n";
import { FilterIcon, XIcon } from "@/icons";
import { cn } from "@/utils";
import { formatDateTime, formatMetric, formatNumber, type NumberContext } from "@/utils/format";
import { useState, type ReactNode } from "react";

/** Table cell classes shared by the list pages and drawers. */
export const head = "py-1.5 pe-3 text-start text-xs font-medium whitespace-nowrap text-gray-500";
export const headEnd = "py-1.5 ps-3 text-end text-xs font-medium whitespace-nowrap text-gray-500";
export const cell = "py-1.5 pe-3 text-sm text-gray-600";
export const cellEnd = "py-1.5 ps-3 text-end text-sm text-gray-600 tabular-nums";
export const box = "rounded-lg border border-gray-200 p-3";
export const h4 = "mb-1.5 text-sm font-semibold text-gray-800";
export const safeUrl = (u: string) => /^https?:\/\//i.test(u);

/** A count in a table cell or chip: full with separators up to its context's limit, short (16.7M) above it; the full value is always in the tooltip. */
export function Num({ value, context = "cell", className }: { value: number | null | undefined; context?: NumberContext; className?: string }) {
  const locale = useLocale();
  if (value === null || value === undefined) return <span className={cn("text-gray-400", className)} title="–">–</span>; // unknown is a dash, never 0
  const m = formatMetric(value, locale, context);
  return <span className={cn("tabular-nums", className)} title={m.compact ? formatNumber(value, locale) : undefined}>{m.text}</span>;
}

/** Text for a heading chip (PageStats): the same rule as Num, as a string. */
export const statText = (v: number | null | undefined, locale: string) => (v === null || v === undefined ? "–" : formatMetric(v, locale, "tile").text);

/** One dropdown filter. "" is the first item (all). */
export function PickSelect({ value, onChange, items, label, className }: { value: string; onChange: (v: string) => void; items: { value: string; label: string }[]; label: string; className?: string }) {
  const cur = value || items[0].value;
  return (
    <Select value={cur} items={items} onValueChange={(v) => onChange(String(v) === items[0].value ? "" : String(v))}>
      <SelectTrigger size="default" className={cn("w-full sm:w-40", className)} aria-label={label}><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  );
}

/** A yes/no filter as a pill button (aria-pressed). */
export function Toggle({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} aria-pressed={on}
      className={cn("inline-flex h-9 items-center rounded-[10px] border px-3 text-sm font-medium whitespace-nowrap transition-colors focus-visible:ring-3 focus-visible:ring-brand-500/20 focus-visible:outline-none",
        on ? "border-brand-500 bg-brand-50 text-brand-700" : "border-gray-300 bg-white text-gray-600 hover:bg-gray-50")}>
      {children}
    </button>
  );
}

/** The row of list filters: on a phone only the search box and a "Filters (n)" button show, the rest opens on demand; from sm up everything is in view. */
export function FilterBar({ search, active, children }: { search: ReactNode; active: number; children: ReactNode }) {
  const t = useTranslations("lists2.common");
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-3 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap sm:items-center">
      <div className="col-span-2 flex items-center gap-2 sm:col-span-1 sm:block">
        <div className="min-w-0 flex-1">{search}</div>
        <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} aria-controls="list-filters" className={cn("inline-flex h-9 shrink-0 items-center gap-1.5 rounded-[10px] border px-3 text-sm font-medium focus-visible:ring-3 focus-visible:ring-brand-500/20 focus-visible:outline-none sm:hidden", active > 0 ? "border-brand-500 bg-brand-50 text-brand-700" : "border-gray-300 bg-white text-gray-600")}>
          <FilterIcon className="size-4" aria-hidden="true" />{active > 0 ? t("filtersCount", { count: active }) : t("filters")}
        </button>
      </div>
      <div id="list-filters" className={cn("col-span-2 gap-2 sm:contents", open ? "grid grid-cols-2" : "hidden")}>{children}</div>
    </div>
  );
}

/** The filters that are on, each with an x, so a pre-filtered link (from the Overview) shows what it filtered and the person can remove it. */
export function ActiveChips({ items, onClear }: { items: { key: string; label: string; remove: () => void }[]; onClear?: () => void }) {
  const t = useTranslations("lists2.common");
  if (items.length === 0) return null;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-1.5" aria-label={t("activeFilters")}>
      {items.map((i) => (
        <button key={i.key} type="button" onClick={i.remove} title={t("removeFilter")}
          className="inline-flex h-6 items-center gap-1 rounded-full bg-brand-50 ps-2.5 pe-1.5 text-xs font-medium text-brand-700 hover:bg-brand-100">
          {i.label}<XIcon className="size-3.5" aria-hidden="true" />
        </button>
      ))}
      {onClear && items.length > 1 && <button type="button" onClick={onClear} className="px-1 text-xs font-medium text-gray-500 hover:text-gray-800">{t("clearAll")}</button>}
    </div>
  );
}

/** CSV download of the current filters: a plain link, the server streams the file with the session cookie. */
export function ExportLink({ href, label }: { href: string | null; label: string }) {
  if (!href) return null;
  return (
    <a href={href} download className="inline-flex h-9 items-center gap-1.5 rounded-[10px] border border-gray-300 bg-white px-3 text-sm font-medium whitespace-nowrap text-gray-700 hover:bg-gray-50 focus-visible:ring-3 focus-visible:ring-brand-500/20 focus-visible:outline-none">
      {label}
    </a>
  );
}

/** Line above a table: how many rows, with the grey old-data stamp when the last read failed. */
export function ListMeta({ total, stale, asOf, children }: { total: number; stale: boolean; asOf: number | null; children?: ReactNode }) {
  const t = useTranslations("lists2.common");
  const locale = useLocale();
  return (
    <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-gray-600">
      <span className="tabular-nums">{t("rows", { count: total })}</span>
      {stale && <StaleStamp since={formatDateTime(asOf, locale)} />}
      {children}
    </div>
  );
}

/** Footer of a list of a sliced tenant: how much of Falcon's total we hold in detail. */
export function HeldNote({ coverage }: { coverage: { held: number; falconTotal: number | null; mode?: string } | null | undefined }) {
  const t = useTranslations("lists2.common");
  const locale = useLocale();
  if (!coverage || coverage.mode !== "priority" || !coverage.falconTotal) return null;
  return <p className="mt-3 text-xs text-gray-500">{t("heldNote", { held: formatNumber(Math.min(coverage.held, coverage.falconTotal), locale), total: formatNumber(coverage.falconTotal, locale) })}</p>;
}

/** Row of a v2 list of CVEs (contract A 5.1). Every field after `cveId` may be missing while the backend is still being built. */
export interface VulnRow {
  cveId: string; tier?: "P1" | "P2" | "P3" | null; severity: string; baseScore: number | null; exprt: string | null; exploitStatus: number | null;
  kev?: boolean; kevDueDate?: string | null; overdue?: boolean; whyTier?: string[]; hosts: number; internetHosts?: number; findings: number; p1Findings?: number;
  kind?: string | null; product?: string | null; firstSeen?: number | null; ageDays?: number | null; fix?: { id: string; title: string | null; fixes?: number } | null; published?: string | null;
}

/** Why-tier rules of the API as the ReasonChips keys (rules that are not a chip, like "exploit code", are written out in the CVE drawer). */
export function reasonKeys(r: Pick<VulnRow, "whyTier" | "kev" | "overdue" | "internetHosts" | "exploitStatus">): ("kev" | "exprt" | "exploited" | "internet" | "overdue")[] {
  const w = r.whyTier ?? [];
  const out: ("kev" | "exprt" | "exploited" | "internet" | "overdue")[] = [];
  if (r.kev || w.includes("kev")) out.push("kev");
  if (r.overdue) out.push("overdue");
  if (w.includes("exploited") || (r.exploitStatus ?? 0) >= 60) out.push("exploited");
  if (w.includes("critical_exprt") || w.includes("exprt_high")) out.push("exprt");
  if ((r.internetHosts ?? 0) > 0) out.push("internet");
  return out;
}
