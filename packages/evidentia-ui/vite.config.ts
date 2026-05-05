/// <reference types="vitest" />
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

/**
 * Vite config for the Evidentia web UI.
 *
 * Build output goes to dist/ by default. At release time, the GitHub
 * Actions release workflow copies dist/* into packages/evidentia-api/
 * src/evidentia_api/static/ so the FastAPI server can serve the SPA
 * from inside its wheel.
 *
 * Dev mode: Vite serves at :5173; the backend FastAPI (started via
 * `evidentia serve --dev`) runs at :8000 with permissive CORS so
 * fetch("/api/...") from :5173 reaches the backend via the proxy below.
 *
 * v0.7.15: tailwindcss v4 first-class vite plugin replaces the v3
 * PostCSS chain (postcss.config.js + tailwind.config.ts both removed).
 * All theme config lives in src/index.css `@theme {}` blocks per the
 * v4 CSS-first design.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // Dev-only: proxy /api/* to the FastAPI server. In production the
      // FastAPI server serves the SPA directly so no proxy is needed.
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    target: "es2022",
    rollupOptions: {
      output: {
        // Predictable asset hashing for Python-side static mount.
        assetFileNames: "assets/[name]-[hash][extname]",
        chunkFileNames: "assets/[name]-[hash].js",
        entryFileNames: "assets/[name]-[hash].js",
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      exclude: ["src/main.tsx", "**/*.d.ts", "tests/e2e/**"],
    },
  },
});
