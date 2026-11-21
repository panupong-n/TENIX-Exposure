import { Skeleton } from "@/components/ui/skeleton";
import { useOrg } from "@/contexts/org-context";
import { useApi } from "@/hooks/use-api";
import { useTranslations } from "@/i18n";
import { SearchIcon } from "@/icons";
import { useId, useRef, useState, type KeyboardEvent } from "react";
import type { SearchItem } from "./types";

/** Search-to-focus: 2+ characters, up to 4 each of CVE, fix, product, host; Enter picks the highlighted one (the first by default). */
export function GraphSearch({ onPick }: { onPick: (item: SearchItem) => void }) {
  const t = useTranslations("graphView");
  const { scoped } = useOrg();
  const id = useId();
  const timer = useRef<number | undefined>(undefined);
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState(0);
  const live = q.length >= 2;
  const { data, loading } = useApi<{ items: SearchItem[] }>(live ? scoped(`/api/exposure/graph/search?q=${encodeURIComponent(q)}`) : null);
  const items = live ? (data?.items ?? []) : [];

  const change = (v: string) => {
    setText(v); setOpen(true); setSel(0);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setQ(v.trim()), 150);
  };
  const pick = (it: SearchItem) => { setOpen(false); setText(""); setQ(""); onPick(it); };
  const key = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel(Math.min(items.length - 1, sel + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel(Math.max(0, sel - 1)); }
    else if (e.key === "Enter" && open && items[sel]) { e.preventDefault(); pick(items[sel]); }
    else if (e.key === "Escape" && open) { e.stopPropagation(); setOpen(false); }
  };
  const show = open && live;

  return (
    <div className="relative min-w-0 flex-1 basis-64 sm:max-w-md">
      <SearchIcon className="pointer-events-none absolute start-2.5 top-1/2 size-4.5 -translate-y-1/2 text-gray-400" aria-hidden="true" />
      <input
        type="search" role="combobox" aria-expanded={show} aria-controls={`${id}-list`} aria-autocomplete="list" aria-label={t("search.label")}
        aria-activedescendant={show && items[sel] ? `${id}-${sel}` : undefined} placeholder={t("search.placeholder")} value={text}
        onChange={(e) => change(e.target.value)} onKeyDown={key} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}
        className="h-9 w-full rounded-lg border border-gray-200 bg-white ps-9 pe-2 text-[13.5px] text-gray-800 placeholder:text-gray-400 focus:border-brand-300 focus:ring-3 focus:ring-brand-500/10 focus:outline-hidden"
      />
      {show && (
        <ul id={`${id}-list`} role="listbox" aria-label={t("search.label")} onMouseDown={(e) => e.preventDefault()}
          className="absolute inset-x-0 top-10 z-30 max-h-80 overflow-auto rounded-xl border border-gray-200 bg-white p-1 shadow-theme-lg">
          {items.length === 0 && (loading
            ? [0, 1, 2].map((i) => <li key={i} className="p-1.5"><Skeleton className="h-4 w-full" /></li>)
            : <li className="px-2 py-1.5 text-xs text-gray-500">{t("search.none")}</li>)}
          {items.map((it, i) => (
            <li key={`${it.kind}:${it.id}`} id={`${id}-${i}`} role="option" aria-selected={i === sel} onClick={() => pick(it)}
              className={`flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-[13px] ${i === sel ? "bg-brand-50" : "hover:bg-gray-50"}`}>
              <span className="w-16 shrink-0 text-[11px] text-gray-500">{t(`kind.${it.kind}`)}</span>
              <span className="min-w-0 flex-1 truncate">{it.label}</span>
              {it.sub && <span className="max-w-[40%] shrink-0 truncate text-xs text-gray-500">{it.sub}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
