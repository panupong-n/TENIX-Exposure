import { SidebarHeader } from "@/components/ui/sidebar";
import { cn } from "@/utils";
import { Link } from "react-router";

interface AppSidebarHeaderProps {
  showContent: boolean;
}

export default function AppSidebarHeader({
  showContent,
}: AppSidebarHeaderProps) {
  return (
    <SidebarHeader className="px-5 pt-5 pb-8">
      <Link
        to="/"
        className={cn(
          "flex items-center",
          !showContent ? "justify-center" : "justify-start",
        )}
      >
        {showContent ? (
          <>
            <img className="h-8 w-auto dark:hidden" src="/images/brand/tenixmark.png" alt="TENIX Exposure" />
            <img className="hidden h-8 w-auto dark:block" src="/images/brand/tenixlogo.png" alt="TENIX Exposure" />
          </>
        ) : (
          <span aria-label="TENIX Exposure" className="flex size-9 items-center justify-center rounded-lg bg-brand-500 text-lg font-semibold text-white">
            T
          </span>
        )}
      </Link>
    </SidebarHeader>
  );
}
