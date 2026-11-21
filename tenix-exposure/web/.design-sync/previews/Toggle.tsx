import { Toggle } from "tenix-exposure-ui";

export const States = () => (<div style={{ display: "flex", gap: 10 }}><Toggle>Compact</Toggle><Toggle defaultPressed>Group by device</Toggle><Toggle disabled>Locked</Toggle></div>);
