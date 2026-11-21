import { Button, Card, CardContent, CardFooter } from "tenix-exposure-ui";

export const Actions = () => (<div style={{ maxWidth: 360 }}><Card><CardContent><p style={{ margin: 0, fontSize: 14 }}>Invite expires in 7 days.</p></CardContent><CardFooter style={{ gap: 8 }}><Button size="sm">Copy link</Button><Button size="sm" variant="outline">Revoke</Button></CardFooter></Card></div>);
