// skeleton-ok: renders nothing until a purge is pending (an empty strip must not flash a skeleton on every page)
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/contexts/auth-context";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useLocale, useTranslations } from "@/i18n";
import { ClockIcon } from "@/icons";
import { api } from "@/lib/api";
import { useRemaining, type Retention } from "@/lib/retention";
import { formatDateTime } from "@/utils/format";
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";

/**
 * Yellow strip "ข้อมูลระดับ Low จะถูกลบใน 2 วัน 18 ชม.": one line per severity whose purge is pending, with the deadline,
 * "ยกเลิกการลบ" (ticks it again) and a link to the settings. Only tenant admins and super admins get the answer (others get 404 and see nothing).
 */
export function RetentionBanner() {
  const t = useTranslations("retention");
  const tSev = useTranslations("severity");
  const locale = useLocale();
  const remaining = useRemaining();
  const { user } = useAuth();
  const { orgId, orgs } = useOrg();
  const { pathname, search } = useLocation();
  const allowed = !!user && !!orgId && (user.soc || orgs.find((o) => o.id === orgId)?.role === "admin");
  const { data, reload } = useApi<Retention>(allowed ? `/api/tenants/${encodeURIComponent(orgId!)}/retention` : null);
  const [now, setNow] = useState(() => Date.now());
  const [busy, setBusy] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const pending = data?.pending ?? [];
  useEffect(() => { // the settings drawer saved: refresh at once
    const on = () => reload();
    window.addEventListener("tenix:retention-changed", on);
    return () => window.removeEventListener("tenix:retention-changed", on);
  }, [reload]);
  useEffect(() => {
    if (!pending.length) return;
    const id = window.setInterval(() => setNow(Date.now()), 60_000); // the countdown moves each minute
    return () => window.clearInterval(id);
  }, [pending.length]);
  if (!allowed || !pending.length || !data) return null;

  const undo = async (severity: string) => {
    setBusy(severity);
    setFailed(false);
    try {
      await api.put(`/api/tenants/${encodeURIComponent(orgId!)}/retention`, { keep: [...new Set([...data.keep, severity])] });
      reload();
    } catch {
      setFailed(true);
    }
    setBusy(null);
  };
  const to = new URLSearchParams(search);
  to.set("settings", "retention");
  return (
    <Alert variant="warning" className="mb-3 gap-1 p-3" data-testid="retention-banner">
      <ClockIcon className="size-5" />
      <div className="flex min-w-0 flex-col gap-1.5">
        {pending.map((p) => (
          <div key={p.severity} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <p className="min-w-0 flex-1 text-sm leading-5 text-amber-900">
              <span className="font-semibold">{t("banner.title", { levels: tSev(p.severity), time: remaining(p.purgeAt, now) })}</span>{" "}
              <span className="text-xs text-amber-800">({formatDateTime(p.purgeAt, locale)})</span>
            </p>
            <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => void undo(p.severity)}>{t("banner.undo")}</Button>
          </div>
        ))}
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <Link to={`${pathname}?${to}`} className="font-medium text-brand-600 hover:text-brand-700">{t("banner.view")}</Link>
          {failed && <span role="status" className="text-xs text-red-700">{t("banner.undoFailed")}</span>}
        </div>
      </div>
    </Alert>
  );
}
