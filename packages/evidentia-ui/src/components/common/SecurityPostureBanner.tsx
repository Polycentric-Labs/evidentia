import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";

import { api } from "@/lib/api";

/**
 * Unsecured-deployment notice — v0.10.12 threat-model §4(c).
 *
 * The Evidentia API ships anonymous + RBAC-permissive by default. When no
 * AuthProvider is configured, anything that can reach the local API can drive
 * the console's mutating + credentialed actions. This strip surfaces that
 * posture honestly. The HIGH-risk credentialed / network-egress consoles
 * (collect, integrations) additionally gate their run buttons on
 * `auth_configured` per §4(c) — this banner is the soft, always-visible half.
 *
 * Renders nothing once an AuthProvider is configured (`auth_configured = true`),
 * so a secured deployment (and the static demo bundle) shows no banner. Shares
 * the `["health"]` query with AppLayout (TanStack dedupes), so it adds no extra
 * request.
 */
export function SecurityPostureBanner() {
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
    refetchInterval: 30_000,
  });

  // Show only when we know auth is OFF; while loading (undefined) stay quiet.
  if (!health || health.auth_configured) {
    return null;
  }

  return (
    <div
      role="status"
      className="flex items-start gap-2 border-b border-[hsl(var(--primary)/0.45)] bg-[hsl(var(--primary)/0.1)] px-8 py-2 text-[0.78rem] leading-snug text-foreground"
    >
      <ShieldAlert
        className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]"
        aria-hidden
      />
      <span>
        <span className="font-semibold">Unsecured deployment.</span> The API has
        no authentication configured — anyone who can reach it can read and
        modify local compliance data, and credentialed actions (collect,
        integrations) are disabled. Set{" "}
        <code className="kbd">EVIDENTIA_API_AUTH_TOKEN_FILE</code> before exposing
        this console beyond localhost.
      </span>
    </div>
  );
}
