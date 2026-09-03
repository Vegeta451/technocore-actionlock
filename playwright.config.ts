import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  workers: 2,
  retries: 0,
  use: { baseURL: "http://127.0.0.1:4327", screenshot: "only-on-failure" },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 900 } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: {
    command: `"${process.execPath}" node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 4327`,
    url: "http://127.0.0.1:4327",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
