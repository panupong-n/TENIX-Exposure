import { RadioGroup, RadioGroupItem, Label } from "tenix-exposure-ui";

const row = { display: "flex", alignItems: "center", gap: 8 } as const;
export const Role = () => (
  <RadioGroup defaultValue="operator">
    <div style={row}><RadioGroupItem value="admin" id="r1" /><Label htmlFor="r1">Admin: can invite and remove users</Label></div>
    <div style={row}><RadioGroupItem value="operator" id="r2" /><Label htmlFor="r2">System Operator: view only</Label></div>
  </RadioGroup>
);
