import { Button, Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "tenix-exposure-ui";

export const Drawer = () => (
  <Sheet open>
    <SheetContent side="right">
      <SheetHeader>
        <SheetTitle>CVE-2024-3400</SheetTitle>
        <SheetDescription>Command injection in PAN-OS GlobalProtect. Exploited in the wild. Affects 12 devices in this tenant.</SheetDescription>
      </SheetHeader>
      <SheetFooter><Button variant="outline">Close</Button><Button>Export devices</Button></SheetFooter>
    </SheetContent>
  </Sheet>
);
