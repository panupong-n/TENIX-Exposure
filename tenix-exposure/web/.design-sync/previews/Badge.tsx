import { Badge } from "tenix-exposure-ui";

const row = { display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" } as const;
const colors = ["primary", "success", "warning", "error", "info", "gray"] as const;

export const Light = () => (
  <div style={row}>
    {colors.map((c) => <Badge key={c} color={c}>{c === "error" ? "Failed" : c === "warning" ? "Partial" : c === "success" ? "Complete" : c === "info" ? "Syncing" : c === "gray" ? "Not synced" : "Active"}</Badge>)}
  </div>
);

export const Solid = () => (
  <div style={row}>
    {colors.map((c) => <Badge key={c} variant="solid" color={c}>{c}</Badge>)}
  </div>
);

export const Sizes = () => (
  <div style={row}>
    <Badge size="sm" color="success">Small</Badge>
    <Badge color="success">Default</Badge>
    <Badge size="lg" color="success">Large</Badge>
  </div>
);
