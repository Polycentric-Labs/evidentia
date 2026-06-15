import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, HashRouter } from "react-router-dom";

import { App } from "@/App";
import { IS_DEMO } from "@/lib/demo";
import "@/index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Compliance data is moderate-churn; 30s staleTime is a sensible default.
      staleTime: 30_000,
      // Network errors on a localhost backend almost always indicate the
      // server is restarting — retrying once is enough.
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const root = document.getElementById("root");
if (!root) {
  throw new Error("Root element #root not found");
}

// The demo bundle is served from a static subpath (e.g. a Vercel project root
// or a folder under the site repo) with no server-side rewrite, so `HashRouter`
// keeps every route reachable on a hard refresh. The real console runs under a
// backend that rewrites unknown paths to index.html, so it uses `BrowserRouter`.
const Router = IS_DEMO ? HashRouter : BrowserRouter;

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Router>
        <App />
      </Router>
    </QueryClientProvider>
  </StrictMode>,
);
