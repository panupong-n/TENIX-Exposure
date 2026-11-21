import { MaskReveal } from "@/components/shared/mask-reveal";
import { cn } from "@/utils";

export interface SignInHeaderProps {
  title: string;
  description: string;
  className?: string;
}

export default function SignInHeader({ title, description, className }: SignInHeaderProps) {
  return (
    <div className={cn("mb-8", className)}>
      <MaskReveal as="h1" className="mb-3 block text-4xl font-bold text-brand-950 sm:text-5xl">
        {title}
      </MaskReveal>
      <MaskReveal as="p" className="block text-base text-gray-500">
        {description}
      </MaskReveal>
    </div>
  );
}
