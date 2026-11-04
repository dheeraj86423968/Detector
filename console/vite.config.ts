import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: { proxy: { "/api": { target: "https://localhost:8443", secure: false, changeOrigin: true } } },
});
