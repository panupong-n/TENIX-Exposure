import { Button, Spinner } from "tenix-exposure-ui";

export const Sizes = () => (
  <div style={{ display: "flex", gap: 16, alignItems: "center", color: "#465fff" }}>
    <Spinner />
    <Spinner className="size-6" />
    <Spinner className="size-10" />
  </div>
);
export const InButton = () => (<Button disabled><Spinner /> Syncing</Button>);
