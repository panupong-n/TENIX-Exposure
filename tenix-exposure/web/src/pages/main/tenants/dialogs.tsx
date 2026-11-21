import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslations } from "@/i18n";
import { api } from "@/lib/api";
import { useState } from "react";
import { delWithBody, useErrorText, type Notice, type SyncState } from "./common";

export type { Notice };
export interface Tenant {
  id: string; name: string; cids: string[]; users: number; admins: number;
  state: SyncState; dataAsOf: number | null;
  stats: { findings: number; critical: number; devices: number; kev: number }; lastRunAt: number | null; detail: string[];
  line: { sources: number; destinations: number }; falcon: { connections: number; unconnected: number };
}

function Shell({ title, description, error, onClose, onSubmit, children, footer }: {
  title: string; description: string; error: string | null; onClose: () => void;
  onSubmit: (e: React.SyntheticEvent<HTMLFormElement>) => void; children: React.ReactNode; footer: React.ReactNode;
}) {
  const tc = useTranslations("common");
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <form onSubmit={onSubmit} className="grid gap-3">
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          {error && <Alert variant="destructive" aria-live="polite"><AlertDescription>{error}</AlertDescription></Alert>}
          {children}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>{tc("cancel")}</Button>
            {footer}
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Rename an organization (creating one is the wizard). Parents mount it only while open, so state starts fresh. */
export function RenameDialog({ tenant, onClose, onDone }: { tenant: Tenant; onClose: () => void; onDone: (n: Notice) => void }) {
  const t = useTranslations("tenants");
  const errText = useErrorText();
  const [name, setName] = useState(tenant.name);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.put(`/api/tenants/${tenant.id}`, { name: name.trim() });
      onDone({ kind: "success", text: t("notices.renamed") });
    } catch (err) {
      setError(errText(err));
      setBusy(false);
    }
  };

  return (
    <Shell onClose={onClose} onSubmit={submit} error={error} title={t("rename.title")} description={t("rename.description")}
      footer={<Button type="submit" disabled={!name.trim() || name.trim() === tenant.name || busy}>{t("rename.title")}</Button>}>
      <Field>
        <FieldLabel className="mb-1.5 block">{t("rename.name")}</FieldLabel>
        <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} autoFocus required />
      </Field>
    </Shell>
  );
}

export function DeleteDialog({ tenant, onClose, onDone }: { tenant: Tenant; onClose: () => void; onDone: (n: Notice) => void }) {
  const t = useTranslations("tenants");
  const errText = useErrorText();
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.SyntheticEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await delWithBody(`/api/tenants/${tenant.id}`, { confirmName: typed });
      onDone({ kind: "success", text: t("notices.deleted") });
    } catch (err) {
      setError(errText(err));
      setBusy(false);
    }
  };

  return (
    <Shell onClose={onClose} onSubmit={submit} error={error} title={t("delete.title", { name: tenant.name })} description={t("delete.body")}
      footer={<Button type="submit" variant="destructive" disabled={typed !== tenant.name || busy}>{t("delete.action")}</Button>}>
      <Field>
        <FieldLabel className="mb-1.5 block">{t("delete.confirmLabel", { name: tenant.name })}</FieldLabel>
        <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} autoFocus />
      </Field>
    </Shell>
  );
}
