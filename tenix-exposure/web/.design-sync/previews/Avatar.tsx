import { Avatar, AvatarBadge, AvatarFallback, AvatarGroup, AvatarGroupCount } from "tenix-exposure-ui";

export const Sizes = () => (
  <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
    {(["xs", "sm", "default", "lg", "xl"] as const).map((s) => <Avatar key={s} size={s}><AvatarFallback>PN</AvatarFallback></Avatar>)}
  </div>
);
export const Group = () => (
  <AvatarGroup>
    <Avatar><AvatarFallback>PN</AvatarFallback></Avatar>
    <Avatar><AvatarFallback>SA</AvatarFallback></Avatar>
    <Avatar><AvatarFallback>KT</AvatarFallback></Avatar>
    <AvatarGroupCount>+4</AvatarGroupCount>
  </AvatarGroup>
);
export const WithBadge = () => (<Avatar size="lg"><AvatarFallback>PN</AvatarFallback><AvatarBadge /></Avatar>);
