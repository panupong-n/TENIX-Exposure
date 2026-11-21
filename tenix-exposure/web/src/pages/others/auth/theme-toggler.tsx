import { Button } from "@/components/ui/button";
import { useTheme } from "@/contexts";
import { useTranslations } from "@/i18n";
import { MoonIcon, SunIcon } from "@/icons";

export default function ThemeToggler() {
  const { toggleTheme } = useTheme();
  const t = useTranslations("header");

  return (
    <Button onClick={toggleTheme} aria-label={t("toggleTheme")} className="size-14 rounded-full">
      <MoonIcon className="block dark:hidden" />
      <SunIcon className="hidden dark:block" />
    </Button>
  );
}
