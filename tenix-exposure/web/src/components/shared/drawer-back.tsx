import { useDrawers } from "@/components/shared/drawers-context";
import { useTranslations } from "@/i18n";
import { ArrowLeftIcon } from "@/icons";

/** Shown at the top of a drawer that was opened from another drawer, so the person can step back instead of closing everything. */
export function DrawerBack() {
  const { back, backKind } = useDrawers();
  const t = useTranslations("drawer");
  if (!back || !backKind) return null;
  return (
    <button type="button" onClick={back} className="mb-1 inline-flex items-center gap-1 self-start rounded text-sm font-medium text-brand-600 hover:underline dark:text-brand-400">
      <ArrowLeftIcon className="size-4" aria-hidden />
      {backKind === "cve" ? t("backToCve") : backKind === "software" ? t("backToSoftware") : backKind === "fix" ? t("backToFix") : t("backToDevice")}
    </button>
  );
}
