import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
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

