import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// Tauri expects a fixed dev-server port (matches tauri.conf.json's devUrl) and needs
// HMR to reach the webview correctly rather than the host's own address.
//
// VITE_MOCK_TAURI=true swaps every @tauri-apps/api/* import for a fixture-backed mock (see
// src/mocks/tauri/) so the real UI can be opened and screenshotted in a plain browser — this
// project's sandboxed dev environment has no working screen-capture tool for the actual Tauri
// window itself. Never set by cargo tauri dev/build or CI; opt-in only.
const mockTauri = process.env.VITE_MOCK_TAURI === "true";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      ...(mockTauri
        ? {
            "@tauri-apps/api/core": path.resolve(__dirname, "./src/mocks/tauri/core.ts"),
            "@tauri-apps/api/event": path.resolve(__dirname, "./src/mocks/tauri/event.ts"),
            "@tauri-apps/api/app": path.resolve(__dirname, "./src/mocks/tauri/app.ts"),
            "@tauri-apps/api/window": path.resolve(__dirname, "./src/mocks/tauri/window.ts"),
          }
        : {}),
    },
  },
  clearScreen: false,
  server: {
    port: mockTauri ? 4173 : 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
});
