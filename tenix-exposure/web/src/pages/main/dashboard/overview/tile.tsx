import { Badge } from "@/components/ui/badge";
import { useTranslations } from "@/i18n";
import type { IconProps } from "@/icons";
import { cn } from "@/utils";
import type { ComponentType, ReactNode } from "react";

/** One bento tile: white card, small icon chip, title and note. Two accents only: organization data (brand chip) and public data (gray chip + badge). */
export const TILE = "flex h-full min-w-0 flex-col rounded-xl border border-gray-200 bg-white p-3 sm:p-4";

export function Tile({ title, note, icon: Icon, accent = "org", actions, className, children }: {
  title: string;
  note?: ReactNode;
  icon: ComponentType<IconProps>;
  accent?: "org" | "public";
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const t = useTranslations("overview");
  return (
    <section className={cn(TILE, className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-start gap-2">
          <span className={cn("flex size-7 shrink-0 items-center justify-center rounded-lg", accent === "org" ? "bg-brand-50 text-brand-600" : "bg-gray-100 text-gray-600")}>
            <Icon className="size-4" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h3 className="text-sm leading-7 font-semibold text-gray-800">{title}</h3>
            {note && <p className="text-xs leading-5 text-gray-500">{note}</p>}
          </div>
        </div>
        {(actions || accent === "public") && (
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
            {accent === "public" && <Badge size="sm" color="gray" className="[text-shadow:none]">{t("public")}</Badge>}
            {actions}
          </div>
        )}
      </div>
      <div className="mt-2 flex min-w-0 flex-1 flex-col">{children}</div>
    </section>
  );
}
