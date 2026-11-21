import { EmptyState } from "tenix-exposure-ui";

export const Default = () => (<div style={{ maxWidth: 420 }}><EmptyState title="No findings match" >Try removing a filter or choosing All sources.</EmptyState></div>);
export const TitleOnly = () => (<div style={{ maxWidth: 420 }}><EmptyState title="Nothing synced yet" /></div>);
