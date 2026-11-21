import { Button, Popover, PopoverBody, PopoverContent, PopoverDescription, PopoverFooter, PopoverHeader, PopoverTitle, PopoverTrigger } from "tenix-exposure-ui";

export const Filter = () => (
  <div style={{ paddingLeft: 24 }}>
    <Popover open>
      <PopoverTrigger render={<Button variant="outline">Filter</Button>} />
      <PopoverContent>
        <PopoverHeader><PopoverTitle>Filter findings</PopoverTitle><PopoverDescription>Show only what needs action.</PopoverDescription></PopoverHeader>
        <PopoverBody>
          <p style={{ margin: 0, fontSize: 14 }}>Critical and High, on the CISA KEV list.</p>
          <PopoverFooter><Button size="sm" variant="outline">Reset</Button><Button size="sm">Apply</Button></PopoverFooter>
        </PopoverBody>
      </PopoverContent>
    </Popover>
  </div>
);
