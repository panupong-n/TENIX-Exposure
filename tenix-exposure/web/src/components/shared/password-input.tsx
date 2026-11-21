import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { useTranslations } from "@/i18n";
import { EyeCloseIcon, EyeIcon } from "@/icons";
import { forwardRef, useState, type ComponentProps } from "react";

/** Password input with a show/hide toggle. Works with react-hook-form's register(). */
export const PasswordInput = forwardRef<HTMLInputElement, Omit<ComponentProps<"input">, "type"> & { groupClassName?: string }>(function PasswordInput({ groupClassName, ...props }, ref) {
  const t = useTranslations("auth.signIn");
  const [shown, setShown] = useState(false);
  return (
    <InputGroup className={groupClassName}>
      <InputGroupInput ref={ref} type={shown ? "text" : "password"} {...props} />
      <InputGroupAddon align="inline-end">
        <InputGroupButton
          size="icon-xs"
          onClick={() => setShown((v) => !v)}
          aria-label={shown ? t("hidePassword") : t("showPassword")}
          aria-pressed={shown}
          className="text-gray-500 dark:text-gray-400"
        >
          {shown ? <EyeIcon className="text-current" /> : <EyeCloseIcon className="text-current" />}
        </InputGroupButton>
      </InputGroupAddon>
    </InputGroup>
  );
});
