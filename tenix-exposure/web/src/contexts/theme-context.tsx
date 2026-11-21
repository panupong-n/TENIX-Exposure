import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

type ThemeMode = "light" | "dark" | "auto";
type ResolvedTheme = "light" | "dark";

type ThemeContextType = {
  theme: ResolvedTheme; // Resolved theme actually active ("light" or "dark")
  themeMode: ThemeMode; // The configured preference ("light", "dark", or "auto")
  setThemeMode: (mode: ThemeMode) => void;
  toggleTheme: () => void;
};

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

/**
 * TENIX Exposure is light only. Dark mode is switched off, not deleted: the toggles are not rendered (see header and auth layout)
 * and this provider ignores any saved or system preference. To bring dark mode back, remove the early return below and render the toggles again.
 */
const LIGHT_ONLY = true;

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [themeMode, setThemeModeState] = useState<ThemeMode>("light");
  const [theme, setTheme] = useState<ResolvedTheme>("light");
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    const savedMode = localStorage.getItem("theme-mode") as ThemeMode | null;
    const legacySavedTheme = localStorage.getItem(
      "theme",
    ) as ResolvedTheme | null;
    const initialMode = LIGHT_ONLY ? "light" : savedMode || (legacySavedTheme as ThemeMode) || "light";

    setThemeModeState(initialMode);
    setIsInitialized(true);
  }, []);

  useEffect(() => {
    if (!isInitialized) return;

    localStorage.setItem("theme-mode", themeMode);

    if (themeMode === "auto") {
      const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

      const handleChange = () => {
        const resolved = mediaQuery.matches ? "dark" : "light";
        setTheme(resolved);
      };

      handleChange();

      mediaQuery.addEventListener("change", handleChange);
      return () => {
        mediaQuery.removeEventListener("change", handleChange);
      };
    } else {
      setTheme(themeMode as ResolvedTheme);
    }
  }, [themeMode, isInitialized]);

  useEffect(() => {
    if (isInitialized) {
      localStorage.setItem("theme", theme);
      if (theme === "dark") {
        document.documentElement.classList.add("dark");
        document.documentElement.setAttribute("data-color-scheme", "dark");
      } else {
        document.documentElement.classList.remove("dark");
        document.documentElement.setAttribute("data-color-scheme", "light");
      }
    }
  }, [theme, isInitialized]);

  const setThemeMode = (mode: ThemeMode) => {
    setThemeModeState(LIGHT_ONLY ? "light" : mode);
  };

  const toggleTheme = () => {
    if (LIGHT_ONLY) return;
    setThemeModeState(() => {
      const currentResolved = theme;
      return currentResolved === "light" ? "dark" : "light";
    });
  };

  return (
    <ThemeContext.Provider
      value={{ theme, themeMode, setThemeMode, toggleTheme }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
};
