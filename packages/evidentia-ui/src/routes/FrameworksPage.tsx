import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

const TIER_OPTIONS: [string | null, string][] = [
  [null, "All tiers"],
  ["A", "Tier A (public)"],
  ["B", "Tier B (free-restricted)"],
  ["C", "Tier C (licensed)"],
  ["D", "Tier D (regulation)"],
];

const CATEGORY_OPTIONS: [string | null, string][] = [
  [null, "All types"],
  ["control", "Control"],
  ["technique", "Technique"],
  ["vulnerability", "Vulnerability"],
  ["obligation", "Obligation"],
];

/**
 * Frameworks browser — lists all bundled catalogs (count rendered live
 * from the API's `total`), filterable by tier + category + free-text search.
 */
export function FrameworksPage() {
  const [tierFilter, setTierFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const query = useQuery({
    queryKey: ["frameworks", tierFilter, categoryFilter],
    queryFn: () =>
      api.listFrameworks({
        tier: tierFilter ?? undefined,
        category: categoryFilter ?? undefined,
      }),
  });

  const filtered = useMemo(() => {
    if (!query.data) return [];
    const needle = search.trim().toLowerCase();
    if (!needle) return query.data.frameworks;
    return query.data.frameworks.filter(
      (fw) =>
        fw.id.toLowerCase().includes(needle) ||
        fw.name.toLowerCase().includes(needle),
    );
  }, [query.data, search]);

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Frameworks</h1>
        <p className="page-sub">
          {query.data
            ? `${filtered.length} of ${query.data.total} catalogs`
            : "Loading catalogs..."}
        </p>
      </header>

      <section className="row wrap gap-3" aria-label="Filters">
        <input
          type="search"
          className="input grow"
          style={{ minWidth: "16rem", width: "auto" }}
          placeholder="Search by ID or name..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search frameworks"
        />
        <div
          className="row gap-2"
          role="radiogroup"
          aria-label="Filter by tier"
        >
          {TIER_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all"}
              type="button"
              role="radio"
              aria-checked={tierFilter === value}
              onClick={() => setTierFilter(value)}
              className={cn("chip", tierFilter === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
        <div
          className="row gap-2"
          role="radiogroup"
          aria-label="Filter by category"
        >
          {CATEGORY_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all"}
              type="button"
              role="radio"
              aria-checked={categoryFilter === value}
              onClick={() => setCategoryFilter(value)}
              className={cn("chip", categoryFilter === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
      </section>

      {query.isError && (
        <Card className="border-dest">
          <CardContent className="card-body" style={{ padding: "1.5rem" }}>
            <span className="text-sm text-destructive">
              Could not fetch frameworks. Is the backend running?
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
              <div className="skel" style={{ height: "7rem" }} />
            </li>
          ))}
        </ul>
      )}

      {query.isSuccess && filtered.length === 0 && (
        <div className="empty-state">No frameworks match your filters.</div>
      )}

      <ul
        className="reset grid"
        style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}
      >
        {filtered.map((fw) => (
          <li key={fw.id} className="reset">
            <Link
              to={`/frameworks/${encodeURIComponent(fw.id)}`}
              style={{
                display: "block",
                height: "100%",
                textDecoration: "none",
              }}
            >
              <Card className="card-hover" style={{ height: "100%" }}>
                <CardHeader className="stack-2">
                  <div className="row gap-2 wrap">
                    <Badge variant="outline">Tier {fw.tier}</Badge>
                    <Badge variant="secondary">{fw.category}</Badge>
                    <Badge
                      variant={
                        fw.status === "retired" ? "destructive" : "outline"
                      }
                    >
                      {fw.status || "status unknown"}
                    </Badge>
                    {fw.placeholder === "true" && (
                      <Badge variant="destructive">placeholder</Badge>
                    )}
                  </div>
                  <CardTitle className="base">{fw.name}</CardTitle>
                </CardHeader>
                <CardContent className="pt-0 text-xs muted stack-2">
                  <p>
                    <code className="kbd">{fw.id}</code> &middot; {fw.version}
                  </p>
                  {fw.notes && <p>{fw.notes}</p>}
                  {fw.verified_on && <p>Source checked: {fw.verified_on}</p>}
                  {fw.superseded_by && <p>Successor: {fw.superseded_by}</p>}
                </CardContent>
              </Card>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
