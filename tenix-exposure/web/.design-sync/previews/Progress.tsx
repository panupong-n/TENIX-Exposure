import { Progress, ProgressIndicator, ProgressLabel, ProgressTrack, ProgressValue } from "tenix-exposure-ui";

export const Sync = () => (
  <div style={{ maxWidth: 360, display: "flex", flexDirection: "column", gap: 16 }}>
    <Progress value={62}>
      <ProgressLabel>Reading vulnerabilities</ProgressLabel>
      <ProgressValue />
      <ProgressTrack><ProgressIndicator /></ProgressTrack>
    </Progress>
    <Progress value={100}><ProgressTrack><ProgressIndicator /></ProgressTrack></Progress>
  </div>
);
