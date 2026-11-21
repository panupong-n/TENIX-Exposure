import OrgSwitcher from "@/components/shared/header/org-switcher";
import UserDropdown from "@/components/shared/header/user-dropdown";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { cn } from "@/utils";
import { Link, NavLink, useLocation } from "react-router";
import { navItems, othersItems } from "../sidebar/data";
import type { NavItem } from "../sidebar/types";

/** One row: brand, the menu, then organization / theme / account. On a phone the menu becomes a second row that wraps, so every item is visible. */
export default function AppHeader() {
  const t = useTranslations("sidebar.items");
  const tHeader = useTranslations("header");
  const { user } = useAuth();
  const { pathname } = useLocation();
  const allowed = (g: NonNullable<NavItem["gate"]>) => (g === "super" ? user?.soc : g === "tenantAdmin" ? user?.manager && !user.soc : user?.manager);
  const items = [...navItems, ...othersItems].filter((i) => i.path && (!i.gate || allowed(i.gate)));

  const links = (
    <>
      {items.map((i) => (
        <NavLink
          key={i.key}
          to={i.path!}
          end={i.path === "/"}
          className={({ isActive }) => {
            const on = i.match ? i.match.some((m) => pathname === m || pathname.startsWith(`${m}/`)) : isActive;
            return cn(
              "relative flex h-full max-lg:h-9 shrink-0 items-center px-2 text-sm sm:px-3 font-medium whitespace-nowrap transition-colors",
              "after:absolute after:inset-x-2 sm:after:inset-x-3 after:bottom-0 after:h-0.5 after:origin-center after:scale-x-0 after:rounded-full after:bg-brand-500 after:transition-transform after:duration-300 dark:after:bg-brand-400",
              on
                ? "text-gray-900 after:scale-x-100 dark:text-white"
                : "text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200",
            );
          }}
        >
          {t(i.key)}
        </NavLink>
      ))}
    </>
  );

  return (
    <header className="sticky top-0 z-50 border-b border-gray-200 bg-white/95 backdrop-blur dark:border-gray-800 dark:bg-gray-900/95">
      <div className="mx-auto grid h-12 w-full max-w-(--breakpoint-2xl) grid-cols-[1fr_auto] items-center gap-3 px-3 lg:grid-cols-[1fr_auto_1fr] md:px-4">
        <Link to="/" className="flex shrink-0 items-center gap-2.5 justify-self-start" aria-label="10CYBER by TENFORWARD · Exposure">
          {/* the team (10CYBER) under the company (TENFORWARD) */}
          <span className="flex flex-col leading-none">
            <span className="text-[17px] font-extrabold tracking-tight text-brand-600">10CYBER</span>
            <span className="mt-1 text-[8.5px] font-semibold tracking-[0.24em] text-gray-500">TENFORWARD</span>
          </span>
          <span className="hidden h-6 w-px bg-gray-200 sm:block dark:bg-gray-700" />
          <span className="hidden text-sm font-semibold tracking-tight text-gray-800 sm:block dark:text-white/90">Exposure</span>
        </Link>

        <nav className="hidden h-full items-stretch justify-self-center lg:flex" aria-label={tHeader("menu")}>{links}</nav>

        <div className="flex items-center gap-2 justify-self-end">
          <OrgSwitcher />
          <UserDropdown />
        </div>
      </div>
      <nav className="flex flex-wrap items-stretch justify-center border-t border-gray-100 px-1 lg:hidden dark:border-gray-800" aria-label={tHeader("menu")}>{links}</nav>
    </header>
  );
}
