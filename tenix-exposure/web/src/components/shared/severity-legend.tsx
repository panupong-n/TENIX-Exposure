// HTML legend for severity colours (use instead of the Apex legend, which can overlap dot and label).
// <SeverityLegend />                                  all five severities
// <SeverityLegend items={["CRITICAL", { severity: "NONE", label: "Other" }]} className="mt-2" />
import { useTranslations } from "@/i18n";
import { SEVERITIES, SEVERITY_COLOR, type Severity } from "@/lib/chart";
import { cn } from "@/utils";

export type SeverityLegendItem = Severity | { severity: Severity; label: string };

export function SeverityLegend({ items, className }: { items?: SeverityLegendItem[]; className?: string }) {
  const t = useTranslations("severity");
  const list = items ?? [...SEVERITIES];
  return (
    <ul className={cn("flex flex-wrap items-center gap-x-3 gap-y-1", className)}>
      {list.map((it) => {
        const sev = typeof it === "string" ? it : it.severity;
        const label = typeof it === "string" ? t(it) : it.label;
        return (
          <li key={sev} className="flex items-center gap-1.5">
            <span aria-hidden="true" className="size-2 shrink-0 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[sev] }} />
            <span className="text-xs leading-5 text-gray-600">{label}</span>
          </li>
        );
      })}
    </ul>
  );
}
