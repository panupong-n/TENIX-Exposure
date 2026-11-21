import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown";
import { useAuth } from "@/contexts/auth-context";
import { useTranslations } from "@/i18n";
import { ChevronDownIcon, GearIcon, LogOutIcon, UserCircleIcon } from "@/icons";
import { cn, getInitials } from "@/utils";
import { useState } from "react";
import { Link, useNavigate } from "react-router";

export default function UserDropdown() {
  const t = useTranslations("userDropdown");
  const tRoles = useTranslations("roles");
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  if (!user) return null;

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger className="dropdown-toggle flex items-center text-gray-700 dark:text-gray-400">
        <span
          aria-hidden="true"
          className="me-2 flex size-8 items-center justify-center rounded-lg bg-brand-50 text-xs font-semibold text-brand-600 dark:bg-brand-500/15 dark:text-brand-400"
        >
          {getInitials(user.name)}
        </span>
        <span className="me-1 hidden max-w-40 truncate text-sm font-medium sm:block">{user.name}</span>
        <ChevronDownIcon className={cn("hidden size-4 text-gray-500 sm:block duration-200 dark:text-gray-400", isOpen ? "rotate-180" : "rotate-0")} />
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" sideOffset={8} className="w-64 p-2">
        <div className="px-3 py-2">
          <span className="block truncate text-sm font-medium text-gray-700 dark:text-gray-300">{user.name}</span>
          <span className="mt-0.5 block truncate text-xs text-gray-500 dark:text-gray-400">{user.email}</span>
          <span className="mt-0.5 block truncate text-xs text-gray-500 dark:text-gray-400">
            {user.soc ? tRoles("super_admin") : user.tenants.map((x) => `${x.name} (${tRoles(x.role)})`).join(", ")}
          </span>
        </div>

        <DropdownMenuSeparator />

        <DropdownMenuItem render={<Link to="/account" />}>
          <UserCircleIcon className="size-5" />
          {t("account")}
        </DropdownMenuItem>
        <DropdownMenuItem render={<Link to="/account#security" />}>
          <GearIcon className="size-5" />
          {t("security")}
        </DropdownMenuItem>


        <DropdownMenuSeparator />

        <DropdownMenuItem
          onClick={() => {
            void signOut().then(() => navigate("/signin", { replace: true }));
          }}
        >
          <LogOutIcon className="size-5" />
          {t("signOut")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
