import { SeverityBadge } from "tenix-exposure-ui";

export const All = () => (
  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
    {["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].map((s) => <SeverityBadge key={s} severity={s} />)}
  </div>
);
