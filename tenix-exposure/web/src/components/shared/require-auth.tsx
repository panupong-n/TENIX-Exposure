import { PageSkeleton } from "@/components/shared/skeletons";
import { useAuth } from "@/contexts/auth-context";
import { OrgProvider } from "@/contexts/org-context";
import type { SessionUser } from "@/lib/api";
import { Navigate, Outlet, useLocation } from "react-router";

const Splash = () => (
  <div className="mx-auto max-w-(--breakpoint-2xl) p-3 md:p-4">
    <PageSkeleton />
  </div>
);

/** Everything inside needs a signed-in user. */
export function RequireAuth() {
  const { user, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <Splash />;
  if (!user) return <Navigate to="/signin" replace state={{ from: location.pathname + location.search }} />;
  return (
    <OrgProvider>
      <Outlet />
    </OrgProvider>
  );
}

/** Signed-in users do not need the sign-in pages. */
export function RedirectIfAuthed() {
  const { user, ready } = useAuth();
  if (!ready) return <Splash />;
  return user ? <Navigate to="/" replace /> : <Outlet />;
}

type Gate = "super" | "manager";
/** Route-level role gate. The server enforces the same rule; this only keeps people off empty pages. */
export function RequireRole({ gate }: { gate: Gate }) {
  const { user } = useAuth();
  const ok = (u: SessionUser) => (gate === "super" ? u.soc : u.manager);
  return user && ok(user) ? <Outlet /> : <Navigate to="/" replace />;
}
