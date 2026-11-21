import { defineConfig } from "@playwright/test";

// Standalone run (no e2e stack, no database): the spec mocks every /api call. Build first: VITE_LOCALE=en vite build --outDir dist-fe3, then
//   npx playwright test -c e2e/misc-v2.config.ts
export default defineConfig({
  testDir: ".",
  testMatch: /misc-v2\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  webServer: { command: "npx vite preview --outDir dist-fe3 --port 4179 --strictPort", port: 4179, reuseExistingServer: true },
  use: { baseURL: "http://127.0.0.1:4179" },
  projects: [{ name: "desktop", use: { viewport: { width: 1280, height: 900 } } }],
});
