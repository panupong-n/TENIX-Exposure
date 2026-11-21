import { Popover, PopoverBody, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useTranslations } from "@/i18n";
import { InfoCircleIcon } from "@/icons";
import { cn } from "@/utils";

export type Tier = "P1" | "P2" | "P3";

/** Tier colours are steps of the brand blue (P1 #2A31D8, P2 #7592FF, P3 #C2D6FF), so red/orange/yellow/green stay reserved for severity. The text is always there. */
const STYLE: Record<Tier, string> = {
  P1: "bg-brand-700 text-white",
  P2: "bg-brand-400 text-brand-950",
  P3: "bg-brand-200 text-brand-950",
};

/** The definitions every tier chip points to (spec 4.1): one sentence each. */
function TierHelp() {
  const t = useTranslations("foundation.tier");
  return (
    <Popover>
      <PopoverTrigger aria-label={t("help")} className="inline-flex size-5 items-center justify-center rounded-full text-gray-400 hover:text-brand-600 focus-visible:ring-4 focus-visible:ring-brand-500/20 focus-visible:outline-none">
        <InfoCircleIcon aria-hidden="true" className="size-4" />
      </PopoverTrigger>
      <PopoverContent align="start" sideOffset={6} className="w-80 max-w-[calc(100vw-1.5rem)] ring-1 ring-gray-200">
        <PopoverBody className="space-y-2 p-3 text-xs leading-5 text-gray-700">
          <p className="font-medium text-gray-900">{t("help")}</p>
          {(["P1", "P2", "P3"] as const).map((k) => (
            <p key={k} className="flex gap-2"><TierChip tier={k} /><span>{t(`${k}.definition`)}</span></p>
          ))}
          <p className="text-gray-500">{t("suppressed")}</p>
        </PopoverBody>
      </PopoverContent>
    </Popover>
  );
}

function TierChip({ tier, label }: { tier: Tier; label?: boolean }) {
  const t = useTranslations("foundation.tier");
  return (
    <span className={cn("inline-flex h-5 shrink-0 items-center gap-1 rounded-md px-1.5 text-xs leading-5 font-semibold whitespace-nowrap", STYLE[tier])}>
      {tier}{label && <span className="font-medium">{t(`${tier}.name`)}</span>}
    </span>
  );
}

/** P1 / P2 / P3 chip. `label` adds the short name (แก้ทันที / แก้ตามรอบ / วางแผนแก้); `help` (default) adds the "what is P1/P2/P3" popover next to it, turn it off in dense table rows. */
export function TierBadge({ tier, label = false, help = true, className }: { tier: Tier; label?: boolean; help?: boolean; className?: string }) {
  return <span className={cn("inline-flex items-center gap-1", className)}><TierChip tier={tier} label={label} />{help && <TierHelp />}</span>;
}
