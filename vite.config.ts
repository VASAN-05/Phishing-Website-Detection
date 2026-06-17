import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
    // Kill whatever is already on 8080 so port never shifts
    strictPort: true,
    hmr: {
      // Disable red overlay — errors show in terminal instead
      overlay: false,
    },
    fs: {
      allow: ["./client", "./shared", "index.html"],
      deny: [".env", ".env.*", "*.{crt,pem}", "**/.git/**"],
    },
    // Proxy /api/* to standalone Express server — bypasses Vite body size limits
    proxy: {
      "/api": {
        target:       "http://localhost:3001",
        changeOrigin: true,
        // No timeout — needed for large file uploads that take minutes
        proxyTimeout:  0,
        timeout:       0,
        configure: (proxy) => {
          proxy.on("error", (err) => {
            console.error("[proxy error]", err.message);
          });
        },
      },
    },
  },
  build: {
    outDir: "dist/spa",
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@":       path.resolve(__dirname, "./client"),
      "@shared": path.resolve(__dirname, "./shared"),
    },
  },
}));
