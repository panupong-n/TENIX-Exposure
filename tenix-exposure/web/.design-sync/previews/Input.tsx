import { Input, Label } from "tenix-exposure-ui";

const col = { display: "flex", flexDirection: "column", gap: 12, maxWidth: 360 } as const;
export const States = () => (
  <div style={col}>
    <Input placeholder="Search by CVE or device" />
    <Input defaultValue="alpha-admin@alphacorp.example" />
    <Input defaultValue="not-an-email" aria-invalid />
    <Input defaultValue="Read only value" disabled />
  </div>
);
export const WithLabel = () => (
  <div style={{ ...col, gap: 6 }}>
    <Label htmlFor="cid">Falcon CID</Label>
    <Input id="cid" placeholder="32 character CID" />
  </div>
);
