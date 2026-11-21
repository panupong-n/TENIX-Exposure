import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "tenix-exposure-ui";

export const Footer = () => (<Dialog open><DialogContent><DialogHeader><DialogTitle>Reset MFA?</DialogTitle><DialogDescription>The user must set up an authenticator again at next sign in.</DialogDescription></DialogHeader><DialogFooter showCloseButton><Button>Reset MFA</Button></DialogFooter></DialogContent></Dialog>);
