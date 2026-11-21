import { Field, FieldGroup, FieldLabel, FieldSeparator, Input } from "tenix-exposure-ui";

export const Form = () => (<div style={{ maxWidth: 360 }}><FieldGroup><Field><FieldLabel>Email</FieldLabel><Input placeholder="you@company.com" /></Field><FieldSeparator>or</FieldSeparator><Field><FieldLabel>Invite code</FieldLabel><Input placeholder="XXXX-XXXX" /></Field></FieldGroup></div>);
