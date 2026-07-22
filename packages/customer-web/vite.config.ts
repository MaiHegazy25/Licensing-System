import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Separate port from the admin portal; proxies API calls to the backend.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
