import { Badge } from "@/components/ui/badge";
import { useTranslations } from "@/i18n";
import { SEVERITIES, type Severity } from "@/lib/chart";
import { cn } from "@/utils";

const STYLE: Record<Severity, string> = {
  CRITICAL: "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-400",
  HIGH: "bg-orange-50 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400",
  MEDIUM: "bg-yellow-50 text-yellow-800 dark:bg-yellow-500/15 dark:text-yellow-400",
  LOW: "bg-green-50 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  NONE: "bg-sky-50 text-sky-700 dark:bg-sky-500/15 dark:text-sky-400",
};

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const t = useTranslations("severity");
  const key = (SEVERITIES as readonly string[]).includes(severity) ? (severity as Severity) : "NONE";
  return (
    <Badge variant="light" color="gray" size="sm" className={cn("[text-shadow:none]", STYLE[key], className)}>
      {t(key)}
    </Badge>
  );
}
