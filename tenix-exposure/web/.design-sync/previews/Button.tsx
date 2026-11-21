import { Button } from "tenix-exposure-ui";

const row = { display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" } as const;

export const Variants = () => (
  <div style={row}>
    <Button>Run sync</Button>
    <Button variant="outline">Export CSV</Button>
    <Button variant="ghost">Cancel</Button>
    <Button variant="destructive">Delete tenant</Button>
    <Button variant="link">View audit log</Button>
  </div>
);

export const Sizes = () => (
  <div style={row}>
    <Button size="xs">Extra small</Button>
    <Button size="sm">Small</Button>
    <Button>Default</Button>
    <Button size="lg">Large</Button>
  </div>
);

export const Disabled = () => (
  <div style={row}>
    <Button disabled>Sync in progress</Button>
    <Button variant="outline" disabled>Export CSV</Button>
  </div>
);
