import { useOrg } from "@/contexts/org-context";
import { getTranslations } from "@/i18n";
import { useTranslations } from "@/i18n";
import { StarFilledIcon, StarIcon } from "@/icons";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/utils";
import { useCallback, useEffect, useSyncExternalStore } from "react";
import { createRoot, type Root } from "react-dom/client";

/** One row of GET /api/exposure/watchlist (contract B, section 1). Every count is null when we hold nothing for the host. */
export interface WatchHost {
  aid: string;
  hostname: string | null;
  note: string | null;
  /** manual asset level (CRITICAL, HIGH, MEDIUM, LOW); null = none, Falcon's criticality or the host group decides */
  criticality?: string | null;
  addedBy?: string | null;
  addedAt?: number | null;
  worstSeverity: string | null;
  p1: number | null;
  critical: number | null;
  high: number | null;
  newFindings24h?: number | null;
  newP1_24h: number | null;
  newCritical24h: number | null;
  kevCves?: number | null;
  lastSeen: number | null;
  missing: boolean;
  external?: boolean;
}
export interface WatchAuto {
  type: "kev_added" | "first_impact" | "critical_new" | "cve_news";
  cve?: string;
  title?: string;
  state?: "exact" | "possible";
  findings?: number;
  devices: number;
  severity: string;
  at: number;
}
export interface WatchlistData {
  tenant?: { id: string; name: string };
  limit: number;
  canEdit: boolean;
  completeness?: { state: string; dataAsOf?: number | null };
  hosts: WatchHost[];
  suggestions?: { aid: string; hostname: string | null; p1: number | null }[];
  auto: WatchAuto[];
}

interface Entry { data: WatchlistData | null; error: ApiError | null; loading: boolean }
const EMPTY: Entry = { data: null, error: null, loading: false };

// One cache for the whole app, keyed by the scoped path (it carries the tenant id), so every star and the Overview block agree.
const entries = new Map<string, Entry>();
const listeners = new Set<() => void>();
const set = (key: string, e: Entry) => { entries.set(key, e); listeners.forEach((l) => l()); };
const subscribe = (l: () => void) => { listeners.add(l); return () => { listeners.delete(l); }; };

function load(key: string) {
  const cur = entries.get(key) ?? EMPTY;
  if (cur.loading) return;
  set(key, { ...cur, loading: true });
  api.get<WatchlistData>(key)
    .then((data) => set(key, { data, error: null, loading: false }))
    .catch((e: unknown) => set(key, { data: entries.get(key)?.data ?? null, error: e instanceof ApiError ? e : new ApiError(0, "error", null), loading: false }));
}

const withTenant = (key: string, path: string) => { const q = key.split("?")[1]; return q ? `${path}?${q}` : path; };
const blank = (aid: string, hostname: string | null, note: string | null): WatchHost => ({ aid, hostname, note, worstSeverity: null, p1: null, critical: null, high: null, newP1_24h: null, newCritical24h: null, lastSeen: null, missing: false });

/** Optimistic PUT: the star flips at once; a refusal puts it back and reload() shows the server's truth. */
async function put(key: string, aid: string, hostname: string | null, note: string | null, level?: string | null): Promise<boolean> {
  const before = entries.get(key) ?? EMPTY;
  if (before.data) {
    const known = before.data.hosts.some((h) => h.aid === aid);
    const hosts = known ? before.data.hosts.map((h) => (h.aid === aid ? { ...h, note, ...(level !== undefined ? { criticality: level } : {}) } : h)) : [...before.data.hosts, blank(aid, hostname, note)];
    set(key, { ...before, data: { ...before.data, hosts } });
  }
  try {
    const r = await api.put<{ host: WatchHost }>(withTenant(key, `/api/exposure/watchlist/${encodeURIComponent(aid)}`), { ...(note ? { note } : {}), ...(level !== undefined ? { criticality: level ?? "" } : {}) });
    const cur = entries.get(key) ?? EMPTY;
    if (cur.data) set(key, { ...cur, data: { ...cur.data, hosts: cur.data.hosts.map((h) => (h.aid === aid ? { ...h, ...r.host } : h)) } });
    return true;
  } catch {
    set(key, before);
    return false;
  }
}

async function remove(key: string, aid: string): Promise<boolean> {
  const before = entries.get(key) ?? EMPTY;
  if (before.data) set(key, { ...before, data: { ...before.data, hosts: before.data.hosts.filter((h) => h.aid !== aid) } });
  try {
    await api.del(withTenant(key, `/api/exposure/watchlist/${encodeURIComponent(aid)}`));
    return true;
  } catch {
    set(key, before);
    return false;
  }
}

// ---- undo toast: one at a time, 5 s, rendered into its own root so no provider is needed
let toastRoot: Root | null = null;
let toastTimer: number | undefined;
function showUndo(message: string, action: string, onUndo: () => void) {
  if (typeof document === "undefined") return;
  let el = document.getElementById("watch-toast");
  if (!el) { el = document.createElement("div"); el.id = "watch-toast"; document.body.appendChild(el); }
  toastRoot ??= createRoot(el);
  const hide = () => { window.clearTimeout(toastTimer); toastRoot?.render(null); };
  toastRoot.render(
    <div role="status" className="fixed bottom-4 start-1/2 z-[100000] flex max-w-[calc(100vw-2rem)] -translate-x-1/2 items-center gap-3 rounded-lg bg-gray-900 px-3 py-2 text-sm leading-5 text-white shadow-theme-lg">
      <span className="min-w-0 truncate">{message}</span>
      <button type="button" onClick={() => { hide(); onUndo(); }} className="shrink-0 font-medium text-brand-200 hover:text-white">{action}</button>
    </div>,
  );
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(hide, 5000);
}

/** The shared watchlist: `data` (hosts, auto items), `isWatched`, add / remove / note. Every caller reads the same cache. */
export function useWatchlist() {
  const { scoped } = useOrg();
  const key = scoped("/api/exposure/watchlist");
  const snap = useSyncExternalStore(subscribe, () => (key ? entries.get(key) ?? EMPTY : EMPTY));
  useEffect(() => { if (key && !entries.has(key)) load(key); }, [key]);
  const reload = useCallback(() => { if (key) load(key); }, [key]);
  const isWatched = useCallback((aid: string) => !!snap.data?.hosts.some((h) => h.aid === aid), [snap.data]);
  const add = useCallback((aid: string, hostname: string | null = null, note: string | null = null) => (key ? put(key, aid, hostname, note) : Promise.resolve(false)), [key]);
  const setNote = add;
  const setLevel = useCallback((aid: string, hostname: string | null, level: string | null) => (key ? put(key, aid, hostname, entries.get(key)?.data?.hosts.find((h) => h.aid === aid)?.note ?? null, level) : Promise.resolve(false)), [key]);
  const drop = useCallback(async (aid: string, hostname?: string | null) => {
    if (!key) return false;
    const note = entries.get(key)?.data?.hosts.find((h) => h.aid === aid)?.note ?? null;
    const t = getTranslations("watch");
    const ok = await remove(key, aid);
    if (ok) showUndo(t("removed", { name: hostname ?? aid }), t("undo"), () => void put(key, aid, hostname ?? null, note).then(() => load(key)));
    else load(key);
    return ok;
  }, [key]);
  return { ...snap, key, reload, isWatched, add, setNote, setLevel, remove: drop };
}

/** The star toggle used in every list and drawer: aria-pressed, optimistic, undo toast on remove. Hidden for a viewer who cannot edit. */
export function WatchStar({ aid, hostname, className, showLabel = false }: { aid: string; hostname?: string | null; className?: string; /** write "เฝ้าระวัง" beside the star (drawer header) */ showLabel?: boolean }) {
  const t = useTranslations("watch");
  const w = useWatchlist();
  if (!w.key) return null;
  const on = w.isWatched(aid);
  const Icon = on ? StarFilledIcon : StarIcon;
  const label = on ? t("unwatch", { name: hostname ?? aid }) : t("watch", { name: hostname ?? aid });
  return (
    <button
      type="button"
      aria-pressed={on}
      aria-label={label}
      title={label}
      disabled={w.data?.canEdit === false}
      onClick={(e) => { e.stopPropagation(); void (on ? w.remove(aid, hostname) : w.add(aid, hostname ?? null)); }}
      className={cn("inline-flex size-6 shrink-0 items-center justify-center gap-1 rounded-md focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none disabled:opacity-50", on ? "text-amber-500 hover:text-amber-600" : "text-gray-400 hover:text-amber-500", showLabel && "w-auto px-1.5 text-xs font-medium", className)}
    >
      <Icon className="size-4" aria-hidden="true" />
      {showLabel && <span>{t("label")}</span>}
    </button>
  );
}
