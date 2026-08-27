import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Same-origin proxy: the deployed stack serves the UI and API from one
      // host and CORS is disabled, so the dev server has to match that shape.
      // Override the target to point at a locally-run API (e.g. on another
      // port) without disturbing a container already bound to 8000.
      "/api": {
        target: process.env.VITE_API_PROXY_TARGET || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // Pull the large, rarely-changing libraries into their own long-lived
        // chunks so they cache across deploys and don't re-download when app
        // code changes. d3 (~250kB) and react-markdown are further isolated
        // because only a few routes use them — with route-level lazy loading
        // they load only when those pages are opened.
        manualChunks: {
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-query": ["@tanstack/react-query"],
          "vendor-d3": ["d3"],
          "vendor-markdown": ["react-markdown", "remark-gfm"],
        },
      },
    },
  },
});

