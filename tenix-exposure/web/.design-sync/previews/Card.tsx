import { Badge, Button, Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "tenix-exposure-ui";

export const Basic = () => (
  <div style={{ maxWidth: 420 }}>
    <Card>
      <CardHeader>
        <CardTitle>Alpha Corp</CardTitle>
        <CardDescription>2 CIDs connected. Last full sync 36 minutes ago.</CardDescription>
      </CardHeader>
      <CardContent>
        <div style={{ marginBottom: 8 }}><Badge color="success">Complete</Badge></div>
        <p style={{ margin: 0, fontSize: 14 }}>12,481 open findings on 842 devices. 37 are Critical and 4 are on the CISA KEV list.</p>
      </CardContent>
      <CardFooter style={{ gap: 8 }}>
        <Button size="sm">Open overview</Button>
        <Button size="sm" variant="outline">Sync now</Button>
      </CardFooter>
    </Card>
  </div>
);

export const Simple = () => (
  <div style={{ maxWidth: 420 }}>
    <Card>
      <CardHeader>
        <CardTitle>Top vulnerable devices</CardTitle>
        <CardDescription>Ranked by Critical and High findings.</CardDescription>
      </CardHeader>
      <CardContent>
        <p style={{ margin: 0, fontSize: 14 }}>WS-FIN-014 has 212 findings. SRV-ERP-02 has 187.</p>
      </CardContent>
    </Card>
  </div>
);
