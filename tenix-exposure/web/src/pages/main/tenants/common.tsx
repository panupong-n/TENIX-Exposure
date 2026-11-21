import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useLocale, useTranslations } from "@/i18n";
import { formatDateTime } from "@/utils/format";
import { ApiError } from "@/lib/api";
import { useState, type ReactNode } from "react";

/** `extra` is secondary small text (Falcon's own message for a refused connection). */
export type Notice = { kind: "success" | "destructive" | "warning" | "info"; text: string; extra?: string } | null;

export const STATE_COLOR = { complete: "success", partial: "warning", failed: "error", not_synced: "gray", no_cids: "warning", no_connection: "warning" } as const;
export type SyncState = keyof typeof STATE_COLOR;

export const CLOUDS = [
  { key: "us1", url: "https://api.crowdstrike.com" },
  { key: "us2", url: "https://api.us-2.crowdstrike.com" },
  { key: "eu1", url: "https://api.eu-1.crowdstrike.com" },
  { key: "gov", url: "https://api.laggar.gcw.crowdstrike.com" },
] as const;

export const CID_RE = /^[0-9a-f]{32}$/;
export const CHAT_RE = /^[A-Za-z0-9_-]{5,64}$/;
export const cidShort = (cid: string) => `${cid.slice(0, 6)}…${cid.slice(-4)}`;

/** DELETE with a JSON body: api.del cannot send one (src/lib/api.ts is shared), so call fetch directly. */
export async function delWithBody<T>(path: string, body: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { method: "DELETE", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "network", "network");
  }
  const d = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, d?.error ?? "error", d?.code ?? null, d?.detail && typeof d.detail === "object" ? d.detail : null);
  return d as T;
}

const CODES = [
  "exists", "name_exists", "cid_taken", "cid_has_connection", "invalid_cid", "invalid_base_url", "client_id_required", "client_secret_required", "confirm_cid", "confirm_name",
  "chat_taken", "invalid_chat", "no_cids", "running", "not_configured", "no_shared",
];
/** Why Falcon refused a connection (the server's `reason` / error code); each has its own explanation under tenants2.test. */
export const REASONS = ["invalid_credentials", "cid_not_authorized", "missing_scope", "unreachable", "error"] as const;
export type Reason = (typeof REASONS)[number];
export const isReason = (v: unknown): v is Reason => REASONS.includes(v as Reason);

/** Maps a server error code to a message (tenants2.errors, or the Falcon explanations of tenants2.test), falling back to "unknown". */
export function useErrorText() {
  const t = useTranslations("tenants2");
  return (e: unknown) => {
    const code = e instanceof ApiError ? e.code : null;
    if (isReason(code)) return t(`test.${code}`);
    return code && CODES.includes(code) ? t(`errors.${code}`) : t("errors.unknown");
  };
}
/** The same as a Notice: a refused connection also carries Falcon's own message as small text. */
export function useErrorNotice() {
  const text = useErrorText();
  return (e: unknown): Notice => ({ kind: "destructive", text: text(e), extra: e instanceof ApiError && isReason(e.code) ? e.detail?.message : undefined });
}

export function NoticeBar({ notice, className = "" }: { notice: Notice; className?: string }) {
  if (!notice) return null;
  return (
    <Alert variant={notice.kind} className={className} aria-live="polite">
      <AlertDescription className="leading-6">
        {notice.text}
        {notice.extra && <span className="mt-0.5 block text-xs leading-5 break-words opacity-80">{notice.extra}</span>}
      </AlertDescription>
    </Alert>
  );
}

export function StateChip({ state }: { state: SyncState }) {
  const t = useTranslations("tenants.states");
  return <Badge size="sm" color={STATE_COLOR[state]} className="[text-shadow:none]">{t(state)}</Badge>;
}

/** One honest sentence about what the numbers of a CID / organization are: old, partial, not read at all. Never says "no data" about a failed read that left old data. */
export function StateNote({ state, dataAsOf, reason, className = "" }: { state: SyncState; dataAsOf: number | null; reason?: string | null; className?: string }) {
  const t = useTranslations("tenants2.status");
  const tt = useTranslations("tenants2.test");
  const tc = useTranslations("common");
  const locale = useLocale();
  const time = formatDateTime(dataAsOf, locale);
  const why = isReason(reason) ? tt(reason) : null;
  const text = state === "failed" ? (time ? t("failedOld", { time }) : t("failedNone"))
    : state === "partial" ? t("partial", { time: time ?? tc("never") })
    : state === "complete" ? t("complete", { time: time ?? tc("never") })
    : t(state);
  const tone = state === "failed" ? "text-red-600" : state === "complete" ? "text-gray-600" : state === "not_synced" ? "text-gray-500" : "text-amber-700";
  return (
    <p className={`text-sm leading-6 ${tone} ${className}`}>
      {text}
      {state === "failed" && why && <span className="block text-xs leading-5">{why}</span>}
    </p>
  );
}

/** A value in mono with a copy button; never overlaps (wraps on narrow widths). */
export function CopyText({ value, shown, label }: { value: string; shown?: string; label: string }) {
  const tc = useTranslations("common");
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* the text is selectable as a fallback */
    }
  };
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-1">
      <span className="min-w-0 rounded-md bg-gray-100 px-1.5 py-0.5 font-mono text-[11px] leading-5 break-all text-gray-700 dark:bg-white/5 dark:text-gray-300">{shown ?? value}</span>
      <Button type="button" variant="ghost" size="xs" onClick={copy} aria-label={label}>{copied ? tc("copied") : tc("copy")}</Button>
    </span>
  );
}

/** A section with a big heading and a one-line help; the three parts of an organization never share a card. */
export function Section({ title, help, action, children, step, id }: { title: string; help?: string; action?: ReactNode; children: ReactNode; step?: string; id?: string }) {
  return (
    <section id={id} className="min-w-0 rounded-xl border border-gray-200 bg-white p-3 sm:p-4 dark:border-gray-800 dark:bg-white/3">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <div className="min-w-0 flex-1 basis-56">
          <h3 className="flex flex-wrap items-center gap-2 text-base leading-6 font-semibold text-gray-800 dark:text-white/90">
            {step && <span className="inline-flex size-6 items-center justify-center rounded-full bg-brand-50 text-xs font-semibold text-brand-500">{step}</span>}
            <span>{title}</span>
          </h3>
          {help && <p className="mt-0.5 text-sm leading-6 text-gray-500 dark:text-gray-400">{help}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
