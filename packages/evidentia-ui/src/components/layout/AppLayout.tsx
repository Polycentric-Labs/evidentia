import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useLocation } from "react-router-dom";

import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Sidebar navigation entries. Kept colocated with the layout so adding a new
 *  route is a one-place edit. */
const NAV_ITEMS: { to: string; label: string; description: string }[] = [
  { to: "/", label: "Home", description: "Welcome + onboarding" },
  { to: "/dashboard", label: "Dashboard", description: "Saved gap reports" },
  { to: "/frameworks", label: "Frameworks", description: "82 bundled catalogs" },
  { to: "/gap/analyze", label: "Gap Analyze", description: "Run a gap analysis" },
  { to: "/gap/diff", label: "Gap Diff", description: "Compare two reports" },
  { to: "/risk/generate", label: "Risk Generate", description: "AI risk statements" },
  { to: "/settings", label: "Settings", description: "Config + LLM + air-gap" },
];

export function AppLayout() {
  const location = useLocation();

  const { data: health, isError: healthError } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
    refetchInterval: 15_000,
  });

  const { data: airGap } = useQuery({
    queryKey: ["air-gap"],
    queryFn: () => api.doctorCheckAirGap(),
    staleTime: 60_000,
  });

  const connected = health?.status === "ok" && !healthError;
  const offline = Boolean(airGap?.air_gapped);

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b">
        <div className="container flex h-14 items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <span className="text-xl font-semibold text-primary">Evidentia</span>
            {health?.version && (
              <span className="text-xs text-muted-foreground" aria-label="version">
                v{health.version}
              </span>
            )}
          </Link>
          <nav className="flex items-center gap-4 text-sm" aria-label="Connection status">
            {offline && (
              <span
                className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs"
                title="All subsystems are air-gap ready."
              >
                air-gapped
              </span>
            )}
            <span
              className={cn(
                "inline-flex items-center gap-1",
                connected ? "text-primary" : "text-destructive",
              )}
              aria-live="polite"
            >
              <span
                className={cn(
                  "h-2 w-2 rounded-full",
                  connected ? "bg-primary" : "bg-destructive",
                )}
                aria-hidden
              />
              {connected ? "connected" : "disconnected"}
            </span>
          </nav>
        </div>
      </header>

      <div className="container flex flex-1 gap-8 py-8">
        <aside className="w-56 shrink-0" aria-label="Primary navigation">
          <nav className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              const active =
                item.to === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(item.to);
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "rounded-md px-3 py-2 text-sm transition-colors",
                    active
                      ? "bg-accent text-accent-foreground font-medium"
                      : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                  )}
                  aria-current={active ? "page" : undefined}
                >
                  <div>{item.label}</div>
                  <div className="text-xs text-muted-foreground">
                    {item.description}
                  </div>
                </Link>
              );
            })}
          </nav>
          <Separator className="my-6" />
          <div className="space-y-1 px-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">v0.7.6 (alpha.2 wired)</p>
            <p>Interactive onboarding wizard</p>
            <p>Gap Analyze + Diff forms</p>
            <p>Risk Generate (SSE streamed)</p>
            <p>Settings edit form</p>
          </div>
        </aside>

        <main className="flex-1 min-w-0">
          <Outlet />
        </main>
      </div>

      <footer className="border-t py-4 text-center text-xs text-muted-foreground">
        Evidentia is open source. &nbsp;
        <a
          href="https://github.com/polycentric-labs/evidentia"
          className="underline-offset-4 hover:underline"
          target="_blank"
          rel="noreferrer"
        >
          Source on GitHub
        </a>
      </footer>
    </div>
  );
}
