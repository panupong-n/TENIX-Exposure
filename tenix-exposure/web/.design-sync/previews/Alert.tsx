import { Alert, AlertDescription, AlertTitle } from "tenix-exposure-ui";

const stack = { display: "flex", flexDirection: "column", gap: 12, maxWidth: 520 } as const;

export const Variants = () => (
  <div style={stack}>
    <Alert variant="info">
      <AlertTitle>Sync started</AlertTitle>
      <AlertDescription>Reading vulnerabilities from Falcon. This usually takes 2 to 3 minutes per CID.</AlertDescription>
    </Alert>
    <Alert variant="success">
      <AlertTitle>Sync complete</AlertTitle>
      <AlertDescription>118,204 findings across 2 CIDs were read in full.</AlertDescription>
    </Alert>
    <Alert variant="warning">
      <AlertTitle>Incomplete data</AlertTitle>
      <AlertDescription>The last sync stopped at 400,000 findings. Numbers on this page come from the previous complete run.</AlertDescription>
    </Alert>
    <Alert variant="destructive">
      <AlertTitle>Sync failed</AlertTitle>
      <AlertDescription>Falcon rejected the request (HTTP 403). Check that the API client has the Spotlight: Read scope.</AlertDescription>
    </Alert>
  </div>
);

export const Default = () => (
  <div style={stack}>
    <Alert>
      <AlertTitle>Read only</AlertTitle>
      <AlertDescription>System operators can view data but cannot invite or remove users.</AlertDescription>
    </Alert>
  </div>
);
