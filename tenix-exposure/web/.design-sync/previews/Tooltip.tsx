import { Button, Tooltip, TooltipContent, TooltipTrigger } from "tenix-exposure-ui";

export const Top = () => (
  <div style={{ paddingTop: 48, paddingLeft: 40 }}>
    <Tooltip open>
      <TooltipTrigger render={<Button variant="outline">Sync all</Button>} />
      <TooltipContent>Reads every CID. Takes 2 to 3 minutes each.</TooltipContent>
    </Tooltip>
  </div>
);
