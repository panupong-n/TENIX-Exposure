export const CHART_FONT = "Outfit, 'Noto Sans Thai', sans-serif";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Fixed meaning everywhere: Critical red, High orange, Medium yellow, Low green, Informational / other blue. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#F04438",
  HIGH: "#FB6514",
  MEDIUM: "#EAB308",
  LOW: "#12B76A",
  NONE: "#0BA5EC",
};

export const axisColor = (theme: string) => (theme === "dark" ? "#94A3B8" : "#364153");
export const gridColor = (theme: string) => (theme === "dark" ? "#1E2640" : "#F3F4F6");
