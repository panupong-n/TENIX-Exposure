import { z } from "zod";

export const makeSignInSchema = (t: (key: string) => string) =>
  z.object({
    email: z.string().trim().email(t("email")),
    password: z.string().min(1, t("password")),
    keepLoggedIn: z.boolean(),
  });

export type SignInFormData = z.infer<ReturnType<typeof makeSignInSchema>>;
