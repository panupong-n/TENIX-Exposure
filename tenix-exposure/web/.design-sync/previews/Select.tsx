import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "tenix-exposure-ui";

const items = [{ value: "all", label: "All sources" }, { value: "endpoint", label: "Endpoints" }, { value: "external", label: "External assets" }];
export const Open = () => (
  <div style={{ width: 220 }}>
    <Select defaultValue="all" items={items} defaultOpen>
      <SelectTrigger><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  </div>
);
export const Closed = () => (
  <div style={{ width: 220 }}>
    <Select defaultValue="endpoint" items={items}>
      <SelectTrigger><SelectValue /></SelectTrigger>
      <SelectContent>{items.map((i) => <SelectItem key={i.value} value={i.value}>{i.label}</SelectItem>)}</SelectContent>
    </Select>
  </div>
);
