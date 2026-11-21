import { Button } from "@/components/ui/button";
import { useTheme } from "@/contexts/theme-context";
import { useTranslations } from "@/i18n";
import { MoonIcon, SunIcon } from "@/icons";

export default function ThemeToggleButton() {
  const { toggleTheme, theme } = useTheme();
  const t = useTranslations("header");

  return (
    <Button variant="outline" size="icon-lg" className="relative" aria-label={t("toggleTheme")} onClick={toggleTheme}>
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
    </Button>
  );
}
