import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
  },
  // Ensure Tauri v2 exports resolve correctly
  resolve: {
    conditions: ["tauri", "browser"],
  },
  optimizeDeps: {
    include: [
      "@tauri-apps/api/core",
      "@tauri-apps/plugin-dialog",
    ],
  },
  build: {
    target: ["es2021", "chrome100", "safari13"],
  },
}));
