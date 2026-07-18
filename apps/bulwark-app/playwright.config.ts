import { defineConfig, devices } from "@playwright/test";

// Frontend UI tests run against the real React app with every @tauri-apps/api/*
// import swapped for a fixture-backed mock (VITE_MOCK_TAURI=true — see
// src/mocks/tauri/ and vite.config.ts), served on port 4173. No Tauri/webkit
// runtime or display is needed, so this runs anywhere Chromium runs, including CI.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["github"], ["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: "http://localhost:4173",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev",
    env: { VITE_MOCK_TAURI: "true" },
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
