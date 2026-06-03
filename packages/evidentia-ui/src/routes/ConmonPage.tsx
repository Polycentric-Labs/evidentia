import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api, type ConmonCadence } from "@/lib/api";

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
 * Continuous-Monitoring screen — a read-only browser over the bundled +
 * runtime-registered CONMON cadences (`GET /api/conmon/cadences`). These are
 * the assessment cycles (NIST 800-53 CA-7, FedRAMP ConMon, CMMC L2, DoD RMF,
 * OCC, …); the live `conmon watch` daemon is GUI-exempt, so there is no
 * mutation here — pure read/display.
 *
 * Each cadence is a flat string→(string|null) map, so the screen renders
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
    return `${count} ${count === 1 ? "cadence" : "cadences"} (read-only)`;
  }, [query.isLoading, query.isError, cadences.length]);

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Continuous Monitoring</h1>
        <p className="page-sub">{subtitle}</p>
      </header>

      <section className="row wrap gap-3" aria-label="Filters">
        <input
          type="search"
          className="input grow"
          style={{ minWidth: "16rem", width: "auto" }}
          placeholder="Filter by framework (e.g. fedramp-rev5-mod)..."
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          aria-label="Filter cadences by framework"
        />
      </section>

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
          style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}
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
          style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}
        >
          {cadences.map((cadence, i) => (
            <li key={cadenceKey(cadence) ?? i} className="reset">
              <CadenceCard cadence={cadence} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
