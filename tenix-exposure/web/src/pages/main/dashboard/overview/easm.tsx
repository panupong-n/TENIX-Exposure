// Skeleton: while the EASM numbers load, Slot (parts.tsx) renders a ChartCardSkeleton.
import { StaleStamp } from "@/components/shared/stale-stamp";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { GlobeIcon } from "@/icons";
import type { ApiError } from "@/lib/api";
import { Link } from "react-router";
import { LINK, Slot, useFmt } from "./parts";
import { Tile } from "./tile";
import type { EasmAssets, EasmServices, EasmV2 } from "./types";

/** Block H: the external attack surface. Counts are exact aggregates; the block is hidden when the organization has no EASM data at all (not licensed), never "0". */
export function Easm({ res }: { res: { data: EasmV2 | null; error: ApiError | null; reload: () => void } }) {
  const t = useTranslations("ovw.h");
  const f = useFmt();
  const { scoped } = useOrg();
  const sv = useApi<EasmServices>(scoped("/api/exposure/easm/services"));
  const top = useApi<EasmAssets>(scoped("/api/exposure/easm/assets?pageSize=3"));
  return (
    <Slot res={res} h="h-56">
      {(d) => {
        const total = d.assets.ips + d.assets.rootDomains + d.assets.subdomains;
        if (total === 0 && d.state !== "failed") return null;
        const pending = (d.reviewIps?.notReviewed ?? 0) + (d.reviewRootDomains?.notReviewed ?? 0);
        const old = d.state === "failed";
        const stats: [string, number | null | undefined][] = [
          ["ips", d.assets.ips], ["domains", d.assets.rootDomains + d.assets.subdomains], ["pending", pending], ["new", sv.data?.newLast7d],
        ];
        return (
          <Tile title={t("title")} note={t("note", { n: f.n(total) })} icon={GlobeIcon} actions={old ? <StaleStamp /> : undefined} className="h-full">
            <div className="grid grid-cols-2 gap-2">
              {stats.map(([k, v]) => (
                <Link key={k} to={k === "pending" ? "/external?review=pending" : k === "new" ? "/external?new=1" : "/external"} className="min-w-0 rounded-lg border border-gray-200 px-2 py-1 hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                  <span className="block text-lg leading-6 font-semibold text-gray-900 tabular-nums">{f.cell(v)}</span>
                  <span className="block text-xs leading-4 text-gray-500">{t(`stat.${k}`)}</span>
                </Link>
              ))}
            </div>
            {sv.data && (sv.data.expiredCerts > 0 || sv.data.assetsWithRiskyPorts > 0) && (
              <p className="mt-2 text-xs leading-5 text-gray-600">{t("risks", { certs: f.n(sv.data.expiredCerts), ports: f.n(sv.data.assetsWithRiskyPorts) })}</p>
            )}
            <ul className="mt-1">
              {(top.data?.items ?? []).map((a) => (
                <li key={a.id} className="border-t border-gray-100 py-1 first:border-t-0">
                  <Link to={`/external?asset=${encodeURIComponent(a.id)}`} className="flex items-start justify-between gap-2 rounded hover:bg-gray-50 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
                    <span className="min-w-0"><span className="block truncate text-sm leading-5 font-medium text-gray-900" title={a.name}>{a.name}</span>
                      <span className="block truncate text-xs leading-4 text-gray-500">{a.ports.length ? t("ports", { ports: a.ports.slice(0, 4).join(", ") }) : t("noPorts")}{!a.reviewed && ` · ${t("pendingOne")}`}</span></span>
                    {a.findings.worstSeverity && <SeverityBadge severity={a.findings.worstSeverity} />}
                  </Link>
                </li>
              ))}
            </ul>
            <div className="mt-auto pt-2 text-end text-xs leading-5"><Link to="/external" className={LINK}>{t("all")}</Link></div>
          </Tile>
        );
      }}
    </Slot>
  );
}
