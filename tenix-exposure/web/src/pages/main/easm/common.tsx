import { Badge } from "@/components/ui/badge";
import { useLocale, useTranslations } from "@/i18n";
import { formatDate } from "@/utils/format";

export interface AssetRow {
  id: string; type: string; dnsType: string | null; name: string; ip: string | null; fqdn: string | null; perimeter: string | null; review: string | null; reviewed: boolean;
  criticality: string | null; status: string | null; cloud: string | null; isp: string | null; asn: number | null; country: string | null; city: string | null;
  discoveredBy: string | null; firstSeen: number | null; lastSeen: number | null; isNew: boolean;
  ports: number[] | null; serviceCount: number | null; riskyPorts: number[] | null; expiredCerts: number | null; expiringCerts: number | null; nearestCertExpiry: number | null;
  findings: { count: number; worstSeverity: string | null } | null;
}

export const head = "py-1.5 pe-3 text-start text-xs font-medium whitespace-nowrap text-gray-500";
export const cell = "py-1.5 pe-3 text-sm text-gray-600";

/** Whole days from now to a certificate's end (negative = already expired). */
export const daysTo = (ms: number) => Math.floor((ms - Date.now()) / 86_400_000);

/** Certificate expiry in words and colour: expired (red), within 30 days (amber), later (plain date). null = no certificate data. */
export function CertExpiry({ validTo, expired, expiresInDays }: { validTo: number | null | undefined; expired?: boolean; expiresInDays?: number | null }) {
  const t = useTranslations("easmAssets.cert");
  const locale = useLocale();
  if (!validTo) return <span className="text-gray-400" title={t("none")}>–</span>;
  const d = expiresInDays ?? daysTo(validTo);
  const isExpired = expired ?? d < 0;
  const date = formatDate(validTo, locale);
  if (isExpired) return <span className="inline-flex flex-wrap items-center gap-1 whitespace-nowrap"><Badge variant="light" color="error" size="sm">{t("expired")}</Badge><span className="text-xs text-gray-500">{date}</span></span>;
  if (d <= 30) return <span className="inline-flex flex-wrap items-center gap-1 whitespace-nowrap"><Badge variant="light" color="warning" size="sm">{t("expiring", { days: d })}</Badge><span className="text-xs text-gray-500">{date}</span></span>;
  return <span className="whitespace-nowrap tabular-nums">{date}</span>;
}

export function PortChips({ ports, risky, max = 5 }: { ports: number[] | null; risky: number[] | null; max?: number }) {
  const t = useTranslations("easmAssets");
  if (!ports || !ports.length) return <span className="text-gray-400" title={t("noServices")}>–</span>;
  const r = new Set(risky ?? []);
  const sorted = [...ports].sort((a, b) => Number(r.has(b)) - Number(r.has(a)) || a - b); // risky ports first, they must not fall in "+N"
  return (
    <span className="flex flex-wrap gap-1">
      {sorted.slice(0, max).map((p) => (
        <span key={p} title={r.has(p) ? t("riskyPort") : undefined} className={r.has(p) ? "rounded bg-red-50 px-1 text-xs font-medium text-red-700 tabular-nums" : "rounded bg-gray-100 px-1 text-xs text-gray-700 tabular-nums"}>
          {p}{r.has(p) && <span className="sr-only"> {t("riskyPort")}</span>}
        </span>
      ))}
      {sorted.length > max && <span className="text-xs text-gray-500">+{sorted.length - max}</span>}
    </span>
  );
}
