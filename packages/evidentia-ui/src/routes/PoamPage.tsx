import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

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
import { api, ApiError, type PoamState } from "@/lib/api";
import { cn } from "@/lib/utils";
import { severityBadge } from "@/lib/severity";
import type { ControlGap } from "@/types/api";
import type { components } from "@/types/openapi";

/**
 * POA&M screen (Wave-2).
 *
 * Lists Plan-of-Action-and-Milestones items — each item IS a `ControlGap`
 * carrying a `poam_milestones` timeline — filterable by gap severity +
 * underlying gap status (mirroring the `evidentia poam list` CLI filters).
 * Selecting an item opens an in-page detail panel showing its milestone
 * timeline; each milestone can be advanced through the forward-only
 * `POAMState` lifecycle via a PATCH that invalidates the list query on
 * success.
 *
 * The state machine lives on the MILESTONE, not the gap. It is
 * forward-only: `planned -> in_progress -> completed -> verified`, with
 * `overdue` as an off-axis attention state. Backward transitions are
 * blocked server-side; the UI only ever offers legal successor states
 * (mirroring `evidentia_core.poam.state.valid_next_states`).
 */

type Milestone = components["schemas"]["Milestone"];

/**
 * The list/detail endpoints return the full `ControlGap-Output`, which
 * carries `poam_milestones`. The hand-authored `ControlGap` mirror does
 * not yet model that field, so widen it locally rather than editing the
 * seam-owned `@/types/api`.
 */
type PoamGap = ControlGap & { poam_milestones?: Milestone[] };

const SEVERITY_OPTIONS: [string | null, string][] = [
  [null, "All severities"],
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["informational", "Informational"],
];

// Underlying gap status (GapStatus) — the same axis `poam list` filters on.
const STATUS_OPTIONS: [string | null, string][] = [
  [null, "All statuses"],
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["remediated", "Remediated"],
  ["accepted", "Accepted"],
  ["not_applicable", "Not applicable"],
];

const POAM_STATE_LABEL: Record<PoamState, string> = {
  planned: "Planned",
  in_progress: "In progress",
  overdue: "Overdue",
  completed: "Completed",
  verified: "Verified",
};

/**
 * Forward-only successor map — a presentation mirror of the server's
 * `_VALID_TRANSITIONS` table (`evidentia_core.poam.state`). The UI offers
 * only these so it never surfaces a transition the PATCH would reject.
 */
const VALID_NEXT_STATES: Record<PoamState, PoamState[]> = {
  planned: ["in_progress", "overdue", "completed"],
  in_progress: ["overdue", "completed"],
  overdue: ["in_progress", "completed"],
  completed: ["verified"],
  verified: [],
};

/** Badge tint for a milestone state — reuses the severity palette. */
function stateBadgeVariant(state: PoamState) {
  switch (state) {
    case "verified":
      return "informational" as const;
    case "completed":
      return "low" as const;
    case "overdue":
      return "critical" as const;
    case "in_progress":
      return "medium" as const;
    case "planned":
    default:
      return "secondary" as const;
  }
}

export function PoamPage() {
  const [severity, setSeverity] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["poam", severity, status],
    queryFn: () =>
      api.listPoamItems({
        severity: severity ?? undefined,
        status: status ?? undefined,
      }),
  });

  const items = (query.data?.items ?? []) as PoamGap[];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">POA&amp;M</h1>
        <p className="page-sub">
          {query.data
            ? `${items.length} of ${query.data.total} plan-of-action items`
            : "Plan of Action & Milestones."}
        </p>
      </header>

      <section className="row wrap gap-3" aria-label="Filters">
        <div
          className="row gap-2 wrap"
          role="radiogroup"
          aria-label="Filter by severity"
        >
          {SEVERITY_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all-sev"}
              type="button"
              role="radio"
              aria-checked={severity === value}
              onClick={() => setSeverity(value)}
              className={cn("chip", severity === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>
        <div
          className="row gap-2 wrap"
          role="radiogroup"
          aria-label="Filter by status"
        >
          {STATUS_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all-status"}
              type="button"
              role="radio"
              aria-checked={status === value}
              onClick={() => setStatus(value)}
              className={cn("chip", status === value && "on")}
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
              Could not fetch POA&amp;M items. Is the backend running?
            </span>
          </CardContent>
        </Card>
      )}

      {query.isLoading && (
        <ul
          className="reset grid"
          style={{ gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))" }}
        >
          {Array.from({ length: 6 }).map((_, i) => (
            <li key={i} className="reset">
              <div className="skel" style={{ height: "8rem" }} />
            </li>
          ))}
        </ul>
      )}

      {query.isSuccess && items.length === 0 && (
        <div className="empty-state">
          No POA&amp;M items yet. Create them from a gap report with{" "}
          <code className="kbd">evidentia poam create</code>, then refresh.
        </div>
      )}

      {items.length > 0 && (
        <ul
          className="reset grid"
          style={{ gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))" }}
        >
          {items.map((item) => {
            const milestones = item.poam_milestones ?? [];
            const isSelected = item.id === selectedId;
            return (
              <li key={item.id} className="reset">
                <button
                  type="button"
                  className="reset"
                  style={{
                    display: "block",
                    width: "100%",
                    textAlign: "left",
                    cursor: "pointer",
                  }}
                  aria-pressed={isSelected}
                  onClick={() =>
                    setSelectedId(isSelected ? null : (item.id ?? null))
                  }
                >
                  <Card
                    className={cn("card-hover", isSelected && "border-dest")}
                    style={{ height: "100%" }}
                  >
                    <CardHeader className="stack-2">
                      <div className="row gap-2 wrap">
                        <Badge variant={severityBadge(item.gap_severity)}>
                          {item.gap_severity}
                        </Badge>
                        <Badge variant="outline">
                          {milestones.length} milestone
                          {milestones.length === 1 ? "" : "s"}
                        </Badge>
                      </div>
                      <CardTitle className="base">
                        <span className="mono text-xs">{item.control_id}</span>{" "}
                        {item.control_title}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-0 text-xs muted">
                      <code className="kbd">{item.framework}</code> &middot;{" "}
                      <span className="cap">
                        {item.status.replace(/_/g, " ")}
                      </span>
                    </CardContent>
                  </Card>
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {selected && (
        <PoamDetail
          item={selected}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

/**
 * In-page detail panel for a single POA&M item: header context + the
 * milestone timeline, each with its forward-transition controls.
 */
function PoamDetail({
  item,
  onClose,
}: {
  item: PoamGap;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const milestones = item.poam_milestones ?? [];

  const mutation = useMutation({
    mutationFn: ({
      milestoneId,
      next,
    }: {
      milestoneId: string;
      next: PoamState;
    }) => api.updatePoamMilestone(item.id ?? "", milestoneId, { status: next }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
    },
  });

  return (
    <section
      className="stack-4"
      aria-labelledby="poam-detail-heading"
      aria-busy={mutation.isPending}
    >
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="poam-detail-heading" className="base">
                <span className="mono text-xs">{item.control_id}</span>{" "}
                {item.control_title}
              </CardTitle>
              <CardDescription>
                <code className="kbd">{item.framework}</code> &middot;{" "}
                <Badge variant={severityBadge(item.gap_severity)}>
                  {item.gap_severity}
                </Badge>
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          {item.gap_description && (
            <p className="text-sm muted">{item.gap_description}</p>
          )}

          {mutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not advance milestone</AlertTitle>
              <AlertDescription>
                {mutation.error instanceof ApiError && mutation.error.payload
                  ? JSON.stringify(mutation.error.payload)
                  : String(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          <div className="stack-3">
            <h2 className="section-num">Milestones</h2>
            {milestones.length === 0 ? (
              <div className="empty-state">
                No milestones on this item yet. Add one with{" "}
                <code className="kbd">evidentia poam milestone add</code>.
              </div>
            ) : (
              <ul className="reset stack-2">
                {milestones.map((ms, idx) => (
                  <MilestoneRow
                    key={ms.id ?? `${item.id}-ms-${idx}`}
                    milestone={ms}
                    pending={mutation.isPending}
                    onAdvance={(next) => {
                      if (ms.id) {
                        mutation.mutate({ milestoneId: ms.id, next });
                      }
                    }}
                  />
                ))}
              </ul>
            )}
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

function MilestoneRow({
  milestone,
  pending,
  onAdvance,
}: {
  milestone: Milestone;
  pending: boolean;
  onAdvance: (next: PoamState) => void;
}) {
  const state = milestone.status as PoamState;
  const nextStates = VALID_NEXT_STATES[state] ?? [];

  return (
    <li className="reset">
      <Card>
        <CardContent className="stack-3" style={{ padding: "1rem" }}>
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <span className="text-sm">{milestone.description}</span>
              <span className="text-xs muted">
                Target{" "}
                <span className="mono tnum">{milestone.target_date}</span>
                {milestone.owner ? ` · owner ${milestone.owner}` : ""}
                {milestone.reviewer ? ` · reviewer ${milestone.reviewer}` : ""}
              </span>
              {milestone.evidence_ref && (
                <span className="text-xs faint">
                  Evidence:{" "}
                  <code className="kbd">{milestone.evidence_ref}</code>
                </span>
              )}
            </div>
            <Badge variant={stateBadgeVariant(state)}>
              {POAM_STATE_LABEL[state] ?? state}
            </Badge>
          </div>

          {nextStates.length === 0 ? (
            <span className="text-xs faint">
              {state === "verified"
                ? "Verified — terminal. File a new milestone to re-open scope."
                : "No further transitions available."}
            </span>
          ) : (
            <div className="row gap-2 wrap" aria-label="Advance milestone">
              <span className="text-xs faint">Advance to:</span>
              {nextStates.map((next) => (
                <Button
                  key={next}
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={pending}
                  onClick={() => onAdvance(next)}
                >
                  {POAM_STATE_LABEL[next]}
                </Button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </li>
  );
}
