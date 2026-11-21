import { defineConfig } from "@playwright/test";

// Runs the self-contained list specs without the e2e stack (no global setup): E2E_DIST=dist-fe2 npx playwright test -c playwright.lists.config.ts
export default defineConfig({
  testDir: "./e2e",
  testMatch: /lists-v2\.spec\.ts/,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  projects: [{ name: "desktop", use: { viewport: { width: 1440, height: 900 } } }],
});
