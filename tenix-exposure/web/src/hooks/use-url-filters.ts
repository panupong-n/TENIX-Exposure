import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";

/**
 * Filters that live in the URL (shareable, survive reload, and the header search can set `q`).
 * The text box edits a local copy and writes it to the URL 300 ms after typing stops.
 */
export function useUrlFilters(keys: readonly string[], defaults: Record<string, string> = {}) {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? defaults[k] ?? "";
  const q = get("q");

  const [text, setText] = useState(q);
  const [seenQ, setSeenQ] = useState(q);
  if (q !== seenQ) {
    // the URL changed from outside (header search, back button): follow it
    setSeenQ(q);
    setText(q);
  }

  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  // Reads the URL as it is now, not the `params` of the render that created this function: the debounced text write below is called 300 ms later and would
  // otherwise put back the URL of the moment the person typed, dropping a filter chosen in between.
  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(window.location.search);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "" || v === defaults[k]) next.delete(k);
      else next.set(k, v);
    }
    if (!("page" in patch)) next.delete("page");
    setParams(next, { replace: true });
  };

  const onText = (value: string) => {
    setText(value);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => set({ q: value.trim() }), 300);
  };

  const values = Object.fromEntries(keys.map((k) => [k, get(k)])) as Record<string, string>;
  return { values, text, onText, set, page: Math.max(1, Number(params.get("page")) || 1) };
}
