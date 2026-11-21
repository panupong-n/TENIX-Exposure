import { Checkbox, Label } from "tenix-exposure-ui";

const row = { display: "flex", alignItems: "center", gap: 8 } as const;
export const States = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
    <div style={row}><Checkbox id="c1" defaultChecked /><Label htmlFor="c1">Notify on new Critical findings</Label></div>
    <div style={row}><Checkbox id="c2" /><Label htmlFor="c2">Notify when a sync fails</Label></div>
    <div style={row}><Checkbox id="c3" disabled /><Label htmlFor="c3">Weekly summary (not available)</Label></div>
  </div>
);
