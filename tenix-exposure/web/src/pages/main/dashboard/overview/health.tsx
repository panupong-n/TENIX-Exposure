import { useAuth } from "@/contexts/auth-context";
import { completeAsOf } from "@/components/shared/data-status";
import { useOrg } from "@/contexts/org-context";
import { useLocale, useTranslations } from "@/i18n";
import { ClockIcon } from "@/icons";
import { cn } from "@/utils";
import { formatAgo, formatDateTime } from "@/utils/format";
import { Link } from "react-router";
import { clock, DOT, LINK, useFmt } from "./parts";
import { Tile } from "./tile";
import type { EasmV2, SoftwareList, SummaryV2 } from "./types";

const REASONS = ["invalid_credentials", "cid_not_authorized", "missing_scope", "unreachable", "error"];

/** Block J: one line per feed (findings, devices, software, EASM) with a dot, the state in words and the time. A customer sees no CID or connection; SOC also sees the last run, Falcon's reason and the link to the connection. */
export function Health({ data, software, easm }: { data: SummaryV2; software: SoftwareList | null; easm: EasmV2 | null }) {
  const t = useTranslations("ovw.j");
  const ts = useTranslations("states.reason");
  const locale = useLocale();
  const f = useFmt();
  const { user } = useAuth();
  const { orgId } = useOrg();
  const c = data.completeness;
  const lines: { k: string; state: string; at: number | null | undefined; extra?: string }[] = [
    { k: "findings", state: c.state, at: completeAsOf(c) },
    { k: "hosts", state: data.hostsSync?.state ?? "not_synced", at: data.hostsSync?.asOf, extra: data.hostsSync?.hosts ? t("hostsN", { n: f.n(data.hostsSync.hosts) }) : undefined },
    { k: "software", state: software?.completeness?.state ?? "not_synced", at: software?.completeness ? completeAsOf(software.completeness) : null },
    ...(easm ? [{ k: "easm", state: easm.state, at: easm.asOf }] : []),
  ];
  const cov = c.coverage;
  const soc = !!user?.soc;
  return (
    <Tile title={t("title")} note={t("note")} icon={ClockIcon} className="h-full">
      <ul className="space-y-1">
        {lines.map((l) => {
          const bad = l.state === "failed" || l.state === "no_connection";
          const ago = formatAgo(l.at ?? null, locale);
          return (
            <li key={l.k} className="flex items-center justify-between gap-2 text-sm leading-5">
              <span className="flex min-w-0 items-center gap-2"><span className={cn("size-2 shrink-0 rounded-full", DOT[l.state] ?? "bg-gray-400")} aria-hidden="true" /><span className="truncate text-gray-800">{t(`line.${l.k}`)}{l.extra && <span className="text-gray-500"> · {l.extra}</span>}</span></span>
              <span className={cn("shrink-0 text-end text-xs", bad ? "font-medium text-red-700" : "text-gray-500")}>
                {t(`state.${l.state}`)}{l.at ? ` · ${clock(l.at, locale)}` : ""}{bad && ago ? ` · ${ago}` : ""}
              </span>
            </li>
          );
        })}
      </ul>
      {cov?.falconTotal != null && cov.held < cov.falconTotal && (
        <p className="mt-2 text-xs leading-5 text-gray-600 tabular-nums">{t("coverage", { held: f.n(cov.held), total: f.n(cov.falconTotal), pct: f.pct(cov.held / cov.falconTotal) })}</p>
      )}
      {soc && (
        <p className="mt-1 text-xs leading-5 text-gray-500">
          {c.lastRunAt ? t("lastRun", { time: formatDateTime(c.lastRunAt, locale) ?? "" }) : ""}
          {c.reason && c.state === "failed" && ` · ${REASONS.includes(c.reason) ? ts(c.reason) : c.reason}`}
        </p>
      )}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-x-3 gap-y-1 pt-2 text-xs leading-5">
        <Link to="?settings=retention" className={LINK}>{t("retention")}</Link>
        {soc && orgId && <Link to={`/settings?setting=tenants&tenant=${encodeURIComponent(orgId)}&section=falcon`} className={LINK}>{t("connection")}</Link>}
      </div>
    </Tile>
  );
}
