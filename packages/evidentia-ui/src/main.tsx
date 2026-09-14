import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { App } from "@/App";
import { AppRouter } from "@/app-router";
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

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AppRouter>
        <App />
      </AppRouter>
    </QueryClientProvider>
  </StrictMode>,
);
