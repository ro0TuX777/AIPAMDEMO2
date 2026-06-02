import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import { App } from "./App";
import { setApiToken } from "./api";

// Set API auth token.  Priority (highest first):
//   1. localStorage["aipam_token"]   — per-browser override for ad-hoc rotation:
//        localStorage.setItem("aipam_token", "<new-token>"); location.reload();
//   2. window.__AIPAM_CONFIG__.apiToken — written by the frontend container
//      entrypoint at start-up from $AIPAM_API_TOKEN (server-side rotation).
//   3. VITE_API_TOKEN — baked into the bundle at build time (legacy fallback).
const buildToken = (import.meta as any).env?.VITE_API_TOKEN as string | undefined;
const runtimeConfigToken =
  typeof window !== "undefined"
    ? (window as any).__AIPAM_CONFIG__?.apiToken
    : undefined;
const localStorageToken =
  typeof window !== "undefined" ? window.localStorage.getItem("aipam_token") : null;
const token = localStorageToken || runtimeConfigToken || buildToken;
if (token) {
  setApiToken(token);
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,        // 30 s before a query is considered stale
      retry: 1,                 // single retry on failure
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);

