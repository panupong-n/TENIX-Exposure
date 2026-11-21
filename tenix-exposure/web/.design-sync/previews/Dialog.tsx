import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "tenix-exposure-ui";

export const ConfirmDelete = () => (
  <Dialog open>
    <DialogContent>
      <DialogHeader>
        <DialogTitle>Delete tenant Beta Ltd?</DialogTitle>
        <DialogDescription>This removes its vulnerability data, CID status, snapshots and sync history. Users keep their accounts but lose access to this tenant. This cannot be undone.</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button variant="outline">Cancel</Button>
        <Button variant="destructive">Delete tenant</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
);
