import { api, ApiError } from "@/lib/api";
import { useCallback, useEffect, useState } from "react";

interface Settled<T> {
  key: string;
  data?: T;
  error?: ApiError;
}

/**
 * GET `path` (null = do nothing). Keeps the previous data on screen while a new path loads,
 * so filters and pages change without a flash of empty content.
 */
export function useApi<T>(path: string | null) {
  const [tick, setTick] = useState(0);
  const [res, setRes] = useState<Settled<T> | null>(null);
  const key = path === null ? null : `${path}#${tick}`;

  useEffect(() => {
    if (key === null || path === null) return;
    const ctl = new AbortController();
    api
      .get<T>(path, ctl.signal)
      .then((data) => setRes({ key, data }))
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return;
        setRes({ key, error: e instanceof ApiError ? e : new ApiError(0, "error", null) });
      });
    return () => ctl.abort();
  }, [key, path]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  const settled = res !== null && res.key === key;
  return {
    data: res?.data ?? null,
    error: settled ? (res.error ?? null) : null,
    loading: key !== null && !settled,
    reload,
  };
}
