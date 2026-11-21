import { Label, Switch } from "tenix-exposure-ui";

const row = { display: "flex", alignItems: "center", gap: 10 } as const;
export const States = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
    <div style={row}><Switch defaultChecked id="s1" /><Label htmlFor="s1">Scheduled sync every 60 minutes</Label></div>
    <div style={row}><Switch id="s2" /><Label htmlFor="s2">Require MFA</Label></div>
    <div style={row}><Switch disabled id="s3" /><Label htmlFor="s3">Locked by administrator</Label></div>
    <div style={{ ...row, gap: 16 }}><Switch size="sm" defaultChecked /><Switch defaultChecked /><span style={{ fontSize: 12, color: "#667085" }}>small and default size</span></div>
  </div>
);
