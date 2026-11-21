import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { SearchIcon } from "@/icons";

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <InputGroup className="w-full sm:w-80">
      <InputGroupAddon align="inline-start">
        <SearchIcon className="size-5 text-gray-500 dark:text-gray-400" />
      </InputGroupAddon>
      <InputGroupInput type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} />
    </InputGroup>
  );
}
