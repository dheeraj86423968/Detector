import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// dev server: proxy the API to a running PDP stack (override with PDP_API=https://host:port)
const api = process.env.PDP_API || "https://127.0.0.1";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 700 },
  server: { proxy: { "/api": { target: api, secure: false, changeOrigin: true } } },
});
