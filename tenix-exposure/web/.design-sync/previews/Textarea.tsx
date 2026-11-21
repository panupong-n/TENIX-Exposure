import { Textarea, Label } from "tenix-exposure-ui";

export const Default = () => (
  <div style={{ display: "flex", flexDirection: "column", gap: 6, maxWidth: 420 }}>
    <Label htmlFor="note">Note for the customer</Label>
    <Textarea id="note" defaultValue="Patch window agreed for Saturday 02:00. WS-FIN-014 needs a reboot after the update." />
  </div>
);
export const Invalid = () => (<div style={{ maxWidth: 420 }}><Textarea aria-invalid defaultValue="" placeholder="A note is required" /></div>);
