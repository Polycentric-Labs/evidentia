import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  ApiError,
  type ConmonCadence,
  type ConmonCheckResponse,
  type ConmonMarkCompletedResponse,
  type ConmonNextResponse,
} from "@/lib/api";

/**
 * Render a null/empty cell as a muted em-dash so an absent citation reads as
 * "intentionally blank" rather than a broken value.
 */
const EMPTY = "—"; // —

/**
 * Keys that, when present, double as a chip/badge in the card header. Rendering
 * them again in the definition list would be redundant, so they are excluded
 * from the `<dl>` body. The map itself is untyped (a flat string→string|null),
 * so these are best-effort: any key not in this set still renders in the body.
 */
const HEADER_KEYS = new Set(["slug", "description", "frequency", "framework"]);

/**
 * Candidate keys, in priority order, for a human-readable card title. The
 * bundled cadences expose `description` (a sentence) and `slug` (the stable
 * id); we prefer the sentence, then any name/title/label/id-like key, then
 * fall back to the first value, then a generic label. Defensive because the
 * API hands back an arbitrary flat map, not a typed model.
 */
const TITLE_KEYS = [
  "description",
  "name",
  "title",
  "label",
  "activity",
  "slug",
  "id",
];

function deriveTitle(cadence: ConmonCadence): string {
  for (const key of TITLE_KEYS) {
    const value = cadence[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  // Last resort: first non-empty value, else a generic label.
  for (const value of Object.values(cadence)) {
    if (typeof value === "string" && value.trim()) return value;
  }
  return "Cadence";
}

/**
 * Prefer a stable id-like key for the React list key. Falls back to the index
 * (handled by the caller) when no id-like key is present.
 */
function cadenceKey(cadence: ConmonCadence): string | undefined {
  const candidate = cadence.slug ?? cadence.id ?? cadence.name;
  return typeof candidate === "string" && candidate.trim()
    ? candidate
    : undefined;
}

/** Title-case a kebab/snake key into a definition-list label. */
function humanizeKey(key: string): string {
  const spaced = key.replace(/[_-]+/g, " ").trim();
  return spaced.replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Shared destructive-alert body for a failed mutation. Surfaces the structured
 * `ApiError` payload when present, otherwise the stringified error — never a
 * raw-HTML prop.
 */
function MutationError({ title, error }: { title: string; error: unknown }) {
  return (
    <Alert variant="destructive">
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        {error instanceof ApiError && error.payload
          ? JSON.stringify(error.payload)
          : String(error)}
      </AlertDescription>
    </Alert>
  );
}

function CadenceCard({ cadence }: { cadence: ConmonCadence }) {
  const title = deriveTitle(cadence);
  const slug = cadence.slug;
  const frequency = cadence.frequency;
  const framework = cadence.framework;

  // Everything not surfaced in the header, rendered as a definition list.
  // Defensive: iterate whatever keys the map actually carries.
  const detailEntries = Object.entries(cadence).filter(
    ([key]) => !HEADER_KEYS.has(key),
  );

  return (
    <Card style={{ height: "100%" }}>
      <CardHeader className="stack-2">
        <div className="row gap-2 wrap">
          {typeof frequency === "string" && frequency.trim() && (
            <Badge variant="outline">{frequency}</Badge>
          )}
          {typeof framework === "string" && framework.trim() && (
            <Badge variant="secondary">{framework}</Badge>
          )}
        </div>
        <CardTitle className="base">{title}</CardTitle>
        {typeof slug === "string" && slug.trim() && (
          <code className="kbd">{slug}</code>
        )}
      </CardHeader>
      {detailEntries.length > 0 && (
        <CardContent className="pt-0">
          <dl className="reset stack-2 text-sm">
            {detailEntries.map(([key, value]) => (
              <div key={key}>
                <dt className="text-xs muted">{humanizeKey(key)}</dt>
                <dd className="reset" style={{ marginTop: "0.125rem" }}>
                  {value == null || value === "" ? (
                    <span className="muted">{EMPTY}</span>
                  ) : (
                    value
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </CardContent>
      )}
    </Card>
  );
}

/**
 * Next-due action — `POST /api/conmon/next` (CLI parity: `evidentia conmon
 * next`). Given a cadence slug + its last-completed date, the server resolves
 * the cadence's frequency and returns the computed next-due date. A read-only
 * computation; no state file is mutated.
 */
function NextDuePanel() {
  const [slug, setSlug] = useState("");
  const [lastCompleted, setLastCompleted] = useState("");

  const next = useMutation<ConmonNextResponse, unknown, void>({
    mutationFn: () =>
      api.conmonNext({ slug: slug.trim(), last_completed: lastCompleted }),
  });

  const canSubmit = Boolean(slug.trim() && lastCompleted) && !next.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Next due</CardTitle>
        <CardDescription>
          Compute the next-due date for a cadence from its last-completed date.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        <form
          className="row gap-2 wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) next.mutate();
          }}
        >
          <div className="stack-2">
            <Label htmlFor="conmon-next-slug">Cadence slug</Label>
            <Input
              id="conmon-next-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="nist-800-53-rev5-ca7"
              style={{ minWidth: "16rem" }}
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="conmon-next-last">Last completed</Label>
            <Input
              id="conmon-next-last"
              type="date"
              value={lastCompleted}
              onChange={(e) => setLastCompleted(e.target.value)}
              style={{ maxWidth: "16rem" }}
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={!canSubmit}
            style={{ alignSelf: "flex-end" }}
          >
            {next.isPending ? "Computing..." : "Compute next due"}
          </Button>
        </form>

        {next.isError && (
          <MutationError title="Could not compute next-due date" error={next.error} />
        )}

        {next.isSuccess && (
          <dl
            className="grid grid-2 text-sm"
            aria-label="Next-due result"
          >
            <div className="stack-2">
              <dt className="text-xs faint">Next due</dt>
              <dd className="mono tnum">{next.data.next_due}</dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Frequency</dt>
              <dd>{next.data.frequency}</dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Framework</dt>
              <dd>{next.data.framework}</dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Last completed</dt>
              <dd className="mono tnum">{next.data.last_completed}</dd>
            </div>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Check action — `POST /api/conmon/check` (CLI parity: `evidentia conmon
 * check`). Given one or more `{slug, last_completed}` entries and a due-soon
 * window, the server buckets each into current / due-soon / overdue and flags
 * any unknown slugs. Read-only.
 */
function CheckPanel() {
  const [slug, setSlug] = useState("");
  const [lastCompleted, setLastCompleted] = useState("");

  const check = useMutation<ConmonCheckResponse, unknown, void>({
    mutationFn: () =>
      api.conmonCheck({
        entries: [{ slug: slug.trim(), last_completed: lastCompleted }],
        window_days: 14,
      }),
  });

  const canSubmit = Boolean(slug.trim() && lastCompleted) && !check.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Check status</CardTitle>
        <CardDescription>
          Bucket a cadence into current / due-soon / overdue against today.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        <form
          className="row gap-2 wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) check.mutate();
          }}
        >
          <div className="stack-2">
            <Label htmlFor="conmon-check-slug">Cadence slug</Label>
            <Input
              id="conmon-check-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="nist-800-53-rev5-ca7"
              style={{ minWidth: "16rem" }}
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="conmon-check-last">Last completed</Label>
            <Input
              id="conmon-check-last"
              type="date"
              value={lastCompleted}
              onChange={(e) => setLastCompleted(e.target.value)}
              style={{ maxWidth: "16rem" }}
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={!canSubmit}
            style={{ alignSelf: "flex-end" }}
          >
            {check.isPending ? "Checking..." : "Check status"}
          </Button>
        </form>

        {check.isError && (
          <MutationError title="Could not check cadence status" error={check.error} />
        )}

        {check.isSuccess && (
          <div className="stack-3" aria-label="Check result">
            <div className="row gap-2 wrap">
              <Badge variant="low">Current {check.data.current.length}</Badge>
              <Badge variant="medium">
                Due soon {check.data.due_soon.length}
              </Badge>
              <Badge variant="critical">
                Overdue {check.data.overdue.length}
              </Badge>
              <span className="text-xs faint">
                as of {check.data.today} ({check.data.window_days}-day window)
              </span>
            </div>
            {check.data.unknown_slugs.length > 0 && (
              <p className="text-xs muted">
                Unknown slugs: {check.data.unknown_slugs.join(", ")}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Health action — `POST /api/conmon/health` (CLI parity: `evidentia conmon
 * health`). Aggregates a `{slug: last_completed}` state mapping into a
 * framework-health report. The response is a free-form summary map, so it is
 * rendered as preformatted JSON (never a raw-HTML prop). Read-only.
 */
function HealthPanel() {
  const [slug, setSlug] = useState("");
  const [lastCompleted, setLastCompleted] = useState("");

  const health = useMutation<Record<string, unknown>, unknown, void>({
    mutationFn: () =>
      api.conmonHealth({
        state: slug.trim() ? { [slug.trim()]: lastCompleted } : {},
        window_days: 14,
      }),
  });

  const canSubmit = Boolean(slug.trim() && lastCompleted) && !health.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Health summary</CardTitle>
        <CardDescription>
          Aggregate framework health from a slug → last-completed state mapping.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        <form
          className="row gap-2 wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) health.mutate();
          }}
        >
          <div className="stack-2">
            <Label htmlFor="conmon-health-slug">Cadence slug</Label>
            <Input
              id="conmon-health-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="nist-800-53-rev5-ca7"
              style={{ minWidth: "16rem" }}
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="conmon-health-last">Last completed</Label>
            <Input
              id="conmon-health-last"
              type="date"
              value={lastCompleted}
              onChange={(e) => setLastCompleted(e.target.value)}
              style={{ maxWidth: "16rem" }}
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={!canSubmit}
            style={{ alignSelf: "flex-end" }}
          >
            {health.isPending ? "Summarizing..." : "Summarize health"}
          </Button>
        </form>

        {health.isError && (
          <MutationError title="Could not summarize health" error={health.error} />
        )}

        {health.isSuccess && (
          <pre
            className="mono text-xs"
            style={{
              whiteSpace: "pre-wrap",
              overflowX: "auto",
              margin: 0,
              maxHeight: "24rem",
            }}
            aria-label="Health summary"
          >
            {JSON.stringify(health.data, null, 2)}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Mark-completed action — `POST /api/conmon/mark-completed` (CLI parity:
 * `evidentia conmon mark-completed`). The ONLY mutation on this screen: it
 * records a cycle completion in the server's state file and returns the
 * previous + new last-completed dates. Invalidates the cadences query on
 * success so any derived display refreshes.
 */
function MarkCompletedPanel() {
  const queryClient = useQueryClient();
  const [slug, setSlug] = useState("");
  const [when, setWhen] = useState("");

  const mark = useMutation<ConmonMarkCompletedResponse, unknown, void>({
    mutationFn: () =>
      api.conmonMarkCompleted({ slug: slug.trim(), when }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["conmon-cadences"] });
    },
  });

  const canSubmit = Boolean(slug.trim() && when) && !mark.isPending;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Mark completed</CardTitle>
        <CardDescription>
          Record a cadence cycle completion in the server's state file.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        <form
          className="row gap-2 wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) mark.mutate();
          }}
        >
          <div className="stack-2">
            <Label htmlFor="conmon-mark-slug">Cadence slug</Label>
            <Input
              id="conmon-mark-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="nist-800-53-rev5-ca7"
              style={{ minWidth: "16rem" }}
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="conmon-mark-when">Completed on</Label>
            <Input
              id="conmon-mark-when"
              type="date"
              value={when}
              onChange={(e) => setWhen(e.target.value)}
              style={{ maxWidth: "16rem" }}
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={!canSubmit}
            style={{ alignSelf: "flex-end" }}
          >
            {mark.isPending ? "Recording..." : "Mark completed"}
          </Button>
        </form>

        {mark.isError && (
          <MutationError
            title="Could not mark cadence completed"
            error={mark.error}
          />
        )}

        {mark.isSuccess && (
          <dl
            className="grid grid-2 text-sm"
            aria-label="Mark-completed result"
          >
            <div className="stack-2">
              <dt className="text-xs faint">Slug</dt>
              <dd>
                <code className="kbd">{mark.data.slug}</code>
              </dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Framework</dt>
              <dd>{mark.data.framework}</dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Previous last-completed</dt>
              <dd className="mono tnum">
                {mark.data.previous_last_completed ?? (
                  <span className="muted">{EMPTY}</span>
                )}
              </dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">New last-completed</dt>
              <dd className="mono tnum">{mark.data.new_last_completed}</dd>
            </div>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Dedup-list section — `GET /api/conmon/dedup-list` (CLI parity: `evidentia
 * conmon dedup-list`). Reads the `conmon watch` daemon's alert-dedup state and
 * lists the deduplicated alert entries (newest-dispatched first), optionally
 * scoped by slug + suppression-window. Read-only; the request is fired on
 * demand via the load button so it doesn't error on page mount when the daemon
 * state file is unconfigured.
 */
type DedupEntry = Record<string, string | number | null>;

function DedupListPanel() {
  const [slug, setSlug] = useState("");
  const [suppressionHours, setSuppressionHours] = useState("");

  const dedup = useMutation<Record<string, unknown>, unknown, void>({
    mutationFn: () => {
      const hours = suppressionHours.trim();
      return api.conmonDedupList({
        slug: slug.trim() || undefined,
        suppression_hours: hours ? Number(hours) : undefined,
      });
    },
  });

  const entries = useMemo<DedupEntry[]>(() => {
    const raw = dedup.data?.entries;
    return Array.isArray(raw) ? (raw as DedupEntry[]) : [];
  }, [dedup.data]);

  const loading = dedup.isPending;

  return (
    <Card>
      <CardHeader className="row-between gap-4 wrap pb-3">
        <div className="stack-2">
          <CardTitle className="base">Dedup list</CardTitle>
          <CardDescription>
            Deduplicated alert entries from the `conmon watch` daemon's state.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="stack-4">
        <form
          className="row gap-2 wrap"
          onSubmit={(e) => {
            e.preventDefault();
            if (!loading) dedup.mutate();
          }}
        >
          <div className="stack-2">
            <Label htmlFor="conmon-dedup-slug">Cadence slug (optional)</Label>
            <Input
              id="conmon-dedup-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="all cadences"
              style={{ minWidth: "16rem" }}
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="conmon-dedup-hours">
              Suppression hours (optional)
            </Label>
            <Input
              id="conmon-dedup-hours"
              type="number"
              min={0}
              value={suppressionHours}
              onChange={(e) => setSuppressionHours(e.target.value)}
              placeholder="default"
              style={{ maxWidth: "12rem" }}
            />
          </div>
          <Button
            type="submit"
            size="sm"
            variant="outline"
            disabled={loading}
            style={{ alignSelf: "flex-end" }}
          >
            {loading ? "Loading..." : "Load dedup entries"}
          </Button>
        </form>

        {dedup.isError && (
          <MutationError
            title="Could not load dedup entries"
            error={dedup.error}
          />
        )}

        {dedup.isSuccess && entries.length === 0 && (
          <div className="empty-state">No deduplicated alert entries.</div>
        )}

        {entries.length > 0 && (
          <ul className="reset stack-3" aria-label="Dedup entries">
            {entries.map((entry, i) => {
              const key =
                typeof entry.cadence_slug === "string"
                  ? entry.cadence_slug
                  : i;
              return (
                <li key={key} className="reset">
                  <Card style={{ height: "100%" }}>
                    <CardContent className="card-body stack-2 text-sm">
                      <dl className="reset stack-2">
                        {Object.entries(entry).map(([k, v]) => (
                          <div key={k}>
                            <dt className="text-xs muted">{humanizeKey(k)}</dt>
                            <dd
                              className="reset"
                              style={{ marginTop: "0.125rem" }}
                            >
                              {v == null || v === "" ? (
                                <span className="muted">{EMPTY}</span>
                              ) : (
                                String(v)
                              )}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    </CardContent>
                  </Card>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Continuous-Monitoring screen — a browser over the bundled + runtime-
 * registered CONMON cadences (`GET /api/conmon/cadences`), plus the ConMon
 * action surface that reaches REST parity with the `evidentia conmon` CLI
 * verbs: next-due / check / health (read-only computations), mark-completed
 * (the one mutation), and dedup-list (the daemon's alert-dedup state).
 *
 * Each cadence is a flat string→(string|null) map, so the list renders
 * defensively: it derives a human title from whatever description/id-like key
 * is present and lists the remaining entries as a definition list, surfacing
 * null values as a muted em-dash.
 */
export function ConmonPage() {
  const [framework, setFramework] = useState("");

  // The endpoint accepts an exact `framework` filter; only send it once the
  // operator has typed a value. Kept simple (no debounce): the trimmed value
  // participates in the query key, so React Query refetches as it changes.
  const frameworkFilter = framework.trim();

  const query = useQuery({
    queryKey: ["conmon-cadences", frameworkFilter],
    queryFn: () =>
      api.listConmonCadences(
        frameworkFilter ? { framework: frameworkFilter } : undefined,
      ),
  });

  const cadences = query.data ?? [];

  const subtitle = useMemo(() => {
    if (query.isLoading) return "Loading cadences...";
    if (query.isError) return "Bundled monitoring cadences.";
    const count = cadences.length;
    return `${count} ${count === 1 ? "cadence" : "cadences"}`;
  }, [query.isLoading, query.isError, cadences.length]);

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Continuous Monitoring</h1>
        <p className="page-sub">{subtitle}</p>
      </header>

      <section className="stack-4" aria-label="ConMon actions">
        <h2 className="section-num">Actions</h2>
        <div
          className="grid"
          style={{
            gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))",
            gap: "1rem",
          }}
        >
          <NextDuePanel />
          <CheckPanel />
          <HealthPanel />
          <MarkCompletedPanel />
        </div>
        <DedupListPanel />
      </section>

      <section className="stack-3" aria-label="Cadences">
        <h2 className="section-num">Cadences</h2>

        <div className="row wrap gap-3" aria-label="Filters">
          <input
            type="search"
            className="input grow"
            style={{ minWidth: "16rem", width: "auto" }}
            placeholder="Filter by framework (e.g. fedramp-rev5-mod)..."
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            aria-label="Filter cadences by framework"
          />
        </div>

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch continuous-monitoring cadences. Is the backend
                running?
              </span>
            </CardContent>
          </Card>
        )}

        {query.isLoading && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            }}
          >
            {Array.from({ length: 6 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "9rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && cadences.length === 0 && (
          <div className="empty-state">
            {frameworkFilter
              ? `No cadences registered for framework "${frameworkFilter}".`
              : "No continuous-monitoring cadences are registered."}
          </div>
        )}

        {cadences.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            }}
          >
            {cadences.map((cadence, i) => (
              <li key={cadenceKey(cadence) ?? i} className="reset">
                <CadenceCard cadence={cadence} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
