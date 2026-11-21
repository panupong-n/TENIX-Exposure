import { api, UNAUTHENTICATED_EVENT, type SessionUser } from "@/lib/api";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

interface AuthValue {
  user: SessionUser | null;
  /** false until the first /me answer arrives */
  ready: boolean;
  setUser: (u: SessionUser | null) => void;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setUser((await api.get<{ user: SessionUser }>("/api/auth/me")).user);
    } catch {
      setUser(null);
    }
    setReady(true);
  }, []);

  useEffect(() => {
    let alive = true;
    api
      .get<{ user: SessionUser }>("/api/auth/me")
      .then((r) => alive && setUser(r.user))
      .catch(() => alive && setUser(null))
      .finally(() => alive && setReady(true));
    const onLost = () => setUser(null);
    window.addEventListener(UNAUTHENTICATED_EVENT, onLost);
    return () => {
      alive = false;
      window.removeEventListener(UNAUTHENTICATED_EVENT, onLost);
    };
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      setUser(null);
    }
  }, []);

  const value = useMemo(() => ({ user, ready, setUser, refresh, signOut }), [user, ready, refresh, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth must be used inside AuthProvider");
  return v;
}
