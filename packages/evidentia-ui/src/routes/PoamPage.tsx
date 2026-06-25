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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type MilestoneCreatePayload,
  type PoamItemInput,
  type PoamState,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { severityBadge } from "@/lib/severity";
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
 * The list/detail endpoints return the full generated `ControlGap-Output`,
 * which models `poam_milestones` directly.
 */
type PoamGap = components["schemas"]["ControlGap"];

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

type GapSeverity = components["schemas"]["GapSeverity"];
type GapStatus = components["schemas"]["GapStatus"];
type ImplementationEffort = components["schemas"]["ImplementationEffort"];

// Create-form pickers — mirror the OpenAPI GapSeverity / GapStatus enums
// (the same axes `poam list` filters on, minus the "All" sentinel).
const SEVERITY_PICKER_OPTIONS: [GapSeverity, string][] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["informational", "Informational"],
];

const STATUS_PICKER_OPTIONS: [GapStatus, string][] = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["remediated", "Remediated"],
  ["accepted", "Accepted"],
  ["not_applicable", "Not applicable"],
];

/**
 * One row of the read-only calendar attention surface. The
 * `GET /api/poam/calendar` response is an untyped server-side dict, so the
 * shape is mirrored here from `evidentia_api.routers.poam.get_calendar`.
 */
interface CalendarEntry {
  milestone_id: string;
  poam_id: string;
  control_id: string;
  target_date: string;
  status: string;
  description: string;
}

interface PoamCalendarResponse {
  today: string;
  overdue: CalendarEntry[];
  due_soon: CalendarEntry[];
}

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

      <CreatePoamForm />

      <PoamCalendar />

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
        <Card className="border-dest" role="alert">
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
  const poamId = item.id ?? "";
  const milestones = item.poam_milestones ?? [];
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const mutation = useMutation({
    mutationFn: ({
      milestoneId,
      next,
    }: {
      milestoneId: string;
      next: PoamState;
    }) => api.updatePoamMilestone(poamId, milestoneId, { status: next }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
    },
  });

  // Delete the whole POA&M item (DELETE /api/poam/items/{id} → CLI
  // `evidentia poam delete`). On success the list refetches and the
  // now-orphaned detail panel closes.
  const deleteMutation = useMutation({
    mutationFn: () => api.deletePoamItem(poamId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
      onClose();
    },
  });

  return (
    <section
      className="stack-4"
      aria-labelledby="poam-detail-heading"
      aria-busy={mutation.isPending || deleteMutation.isPending}
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
                No milestones on this item yet. Add one below or with{" "}
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

          <AddMilestoneForm poamId={poamId} />

          <EditPoamForm item={item} />

          {/* ── Delete item ───────────────────────────────────────────── */}
          <div className="row-between border-t pt-4 wrap gap-3">
            {confirmingDelete ? (
              <div className="row gap-2 wrap" aria-label="Confirm delete">
                <span className="text-sm">Delete this POA&amp;M item?</span>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  disabled={deleteMutation.isPending}
                  onClick={() => deleteMutation.mutate()}
                >
                  {deleteMutation.isPending ? "Deleting..." : "Confirm delete"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={deleteMutation.isPending}
                  onClick={() => setConfirmingDelete(false)}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setConfirmingDelete(true)}
              >
                Delete item
              </Button>
            )}
          </div>
          {deleteMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not delete item</AlertTitle>
              <AlertDescription>
                {deleteMutation.error instanceof ApiError &&
                deleteMutation.error.payload
                  ? JSON.stringify(deleteMutation.error.payload)
                  : String(deleteMutation.error)}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

/**
 * Add-milestone form inside the detail panel.
 *
 * Wired to `POST /api/poam/items/{id}/milestones` (CLI
 * `evidentia poam milestone add`). Sends the `MilestoneCreatePayload`
 * required fields (description + target_date) plus the optional initial
 * status / evidence_ref; invalidates the list on success.
 */
function AddMilestoneForm({ poamId }: { poamId: string }) {
  const queryClient = useQueryClient();
  const [description, setDescription] = useState("");
  const [targetDate, setTargetDate] = useState("");
  const [status, setStatus] = useState<PoamState>("planned");
  const [evidenceRef, setEvidenceRef] = useState("");

  const mutation = useMutation({
    mutationFn: (body: MilestoneCreatePayload) =>
      api.addPoamMilestone(poamId, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
      setDescription("");
      setTargetDate("");
      setStatus("planned");
      setEvidenceRef("");
    },
  });

  const canSubmit =
    description.trim().length > 0 &&
    targetDate.length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    const evidence = evidenceRef.trim();
    mutation.mutate({
      description: description.trim(),
      target_date: targetDate,
      status,
      ...(evidence ? { evidence_ref: evidence } : {}),
    });
  };

  // `planned` and `in_progress` are the sensible initial states for a new
  // milestone; the forward-only lifecycle drives it onward from there.
  const INITIAL_STATE_OPTIONS: [PoamState, string][] = [
    ["planned", "Planned"],
    ["in_progress", "In progress"],
  ];

  return (
    <div className="stack-3 border-t pt-4">
      <h2 className="section-num">Add milestone</h2>
      <form
        className="stack-4"
        aria-label="Add milestone"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="stack-2">
          <Label htmlFor="milestone-description">Description</Label>
          <Textarea
            id="milestone-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What the operator is committing to deliver."
            required
          />
        </div>
        <div className="grid grid-2">
          <div className="stack-2">
            <Label htmlFor="milestone-target-date">Target date</Label>
            <Input
              id="milestone-target-date"
              type="date"
              value={targetDate}
              onChange={(e) => setTargetDate(e.target.value)}
              required
            />
          </div>
          <div className="stack-2">
            <Label htmlFor="milestone-evidence-ref">
              Evidence ref (optional)
            </Label>
            <Input
              id="milestone-evidence-ref"
              value={evidenceRef}
              onChange={(e) => setEvidenceRef(e.target.value)}
              placeholder="Jira key, OSCAL UUID, S3 URI…"
            />
          </div>
        </div>
        <div className="stack-2">
          <span className="text-sm font-medium leading-none">
            Initial status
          </span>
          <div
            className="row wrap gap-2"
            role="radiogroup"
            aria-label="Initial milestone status"
          >
            {INITIAL_STATE_OPTIONS.map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={status === value}
                onClick={() => setStatus(value)}
                className={cn("pill", status === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="row-end">
          <Button type="submit" disabled={!canSubmit}>
            {mutation.isPending ? "Adding..." : "Add milestone"}
          </Button>
        </div>
      </form>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not add milestone</AlertTitle>
          <AlertDescription>
            {mutation.error instanceof ApiError && mutation.error.payload
              ? JSON.stringify(mutation.error.payload)
              : String(mutation.error)}
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

/**
 * Edit (full-replace) form for the POA&M item's editable gap fields.
 *
 * Wired to `PUT /api/poam/items/{id}` (CLI `evidentia poam edit`). PUT is a
 * full replace, so the body re-sends the whole `ControlGap-Input` — the
 * existing milestones + all unedited fields are preserved verbatim, with
 * only the form-bound fields overridden. Invalidates the list on success.
 */
function EditPoamForm({ item }: { item: PoamGap }) {
  const queryClient = useQueryClient();
  const poamId = item.id ?? "";
  const [open, setOpen] = useState(false);
  const [controlTitle, setControlTitle] = useState(item.control_title);
  const [gapDescription, setGapDescription] = useState(item.gap_description);
  const [gapSeverity, setGapSeverity] = useState<GapSeverity>(
    item.gap_severity,
  );
  const [status, setStatus] = useState<GapStatus>(item.status);

  const mutation = useMutation({
    mutationFn: (body: PoamItemInput) => api.replacePoamItem(poamId, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
      setOpen(false);
    },
  });

  const canSubmit =
    controlTitle.trim().length > 0 &&
    gapDescription.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    // PUT is a full replace: re-send the existing item, overriding only the
    // edited fields. `additionalProperties: false` server-side, so spread the
    // full ControlGap-Output (it is a structural superset of the Input shape).
    mutation.mutate({
      ...(item as PoamItemInput),
      control_title: controlTitle.trim(),
      gap_description: gapDescription.trim(),
      gap_severity: gapSeverity,
      status,
    });
  };

  if (!open) {
    return (
      <div className="row-end border-t pt-4">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setOpen(true)}
        >
          Edit item
        </Button>
      </div>
    );
  }

  return (
    <div className="stack-3 border-t pt-4">
      <h2 className="section-num">Edit item</h2>
      <form
        className="stack-4"
        aria-label="Edit item"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="stack-2">
          <Label htmlFor="edit-control-title">Control title</Label>
          <Input
            id="edit-control-title"
            value={controlTitle}
            onChange={(e) => setControlTitle(e.target.value)}
            required
          />
        </div>
        <div className="stack-2">
          <Label htmlFor="edit-gap-description">Gap description</Label>
          <Textarea
            id="edit-gap-description"
            value={gapDescription}
            onChange={(e) => setGapDescription(e.target.value)}
            required
          />
        </div>
        <div className="stack-2">
          <span className="text-sm font-medium leading-none">Severity</span>
          <div
            className="row wrap gap-2"
            role="radiogroup"
            aria-label="Edit gap severity"
          >
            {SEVERITY_PICKER_OPTIONS.map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={gapSeverity === value}
                onClick={() => setGapSeverity(value)}
                className={cn("pill", gapSeverity === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="stack-2">
          <span className="text-sm font-medium leading-none">Status</span>
          <div
            className="row wrap gap-2"
            role="radiogroup"
            aria-label="Edit gap status"
          >
            {STATUS_PICKER_OPTIONS.map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={status === value}
                onClick={() => setStatus(value)}
                className={cn("pill", status === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="row gap-2 row-end">
          <Button
            type="button"
            variant="outline"
            disabled={mutation.isPending}
            onClick={() => setOpen(false)}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={!canSubmit}>
            {mutation.isPending ? "Saving..." : "Save changes"}
          </Button>
        </div>
      </form>

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not save item</AlertTitle>
          <AlertDescription>
            {mutation.error instanceof ApiError && mutation.error.payload
              ? JSON.stringify(mutation.error.payload)
              : String(mutation.error)}
          </AlertDescription>
        </Alert>
      )}
    </div>
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

const EMPTY_CREATE_FORM = {
  framework: "",
  control_id: "",
  control_title: "",
  gap_description: "",
  gap_severity: "high" as GapSeverity,
  status: "open" as GapStatus,
};

/**
 * Create-POA&M-item form.
 *
 * A POA&M item IS a `ControlGap`, so this is wired to
 * `POST /api/poam/items` (CLI `evidentia poam create`). It sends the
 * required `ControlGap-Input` fields the operator must author — framework,
 * control_id, control_title, gap_severity, status, gap_description — plus
 * the small set of schema-required fields the server has no default for
 * (`control_description`, `implementation_status`, `remediation_guidance`,
 * `implementation_effort`). The new item lands in the list on success.
 */
function CreatePoamForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_CREATE_FORM });

  const mutation = useMutation({
    mutationFn: (body: PoamItemInput) => api.createPoamItem(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["poam"] });
      setForm({ ...EMPTY_CREATE_FORM });
    },
  });

  const canSubmit =
    form.framework.trim().length > 0 &&
    form.control_id.trim().length > 0 &&
    form.control_title.trim().length > 0 &&
    form.gap_description.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    // The required ControlGap-Input fields. `control_description`,
    // `remediation_guidance`, and `implementation_effort` are schema-required
    // with no server default; seed them from the operator-authored fields so
    // the create round-trips. Operators refine them later via Edit / the CLI.
    const description = form.gap_description.trim();
    mutation.mutate({
      framework: form.framework.trim(),
      control_id: form.control_id.trim(),
      control_title: form.control_title.trim(),
      control_description: form.control_title.trim(),
      gap_description: description,
      gap_severity: form.gap_severity,
      status: form.status,
      implementation_status: "missing",
      remediation_guidance: description,
      implementation_effort: "medium" as ImplementationEffort,
      // Required by the schema (`@default 0` in OSCAL terms, but non-optional
      // in the generated Input type). The server recomputes the real priority.
      priority_score: 0,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">New POA&amp;M item</CardTitle>
        <CardDescription>
          Open a plan-of-action item from a control gap. Add its remediation
          milestones once it lands in the list below.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="stack-5"
          aria-label="New POA&M item"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="poam-framework">Framework</Label>
              <Input
                id="poam-framework"
                value={form.framework}
                onChange={(e) =>
                  setForm({ ...form, framework: e.target.value })
                }
                placeholder="soc2-tsc"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="poam-control-id">Control ID</Label>
              <Input
                id="poam-control-id"
                value={form.control_id}
                onChange={(e) =>
                  setForm({ ...form, control_id: e.target.value })
                }
                placeholder="CC6.1"
                required
              />
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="poam-control-title">Control title</Label>
            <Input
              id="poam-control-title"
              value={form.control_title}
              onChange={(e) =>
                setForm({ ...form, control_title: e.target.value })
              }
              placeholder="Logical access controls"
              required
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="poam-gap-description">Gap description</Label>
            <Textarea
              id="poam-gap-description"
              value={form.gap_description}
              onChange={(e) =>
                setForm({ ...form, gap_description: e.target.value })
              }
              placeholder="What is missing or incomplete."
              required
            />
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">
              Gap severity
            </span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Gap severity"
            >
              {SEVERITY_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.gap_severity === value}
                  onClick={() => setForm({ ...form, gap_severity: value })}
                  className={cn("pill", form.gap_severity === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Status</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Gap status"
            >
              {STATUS_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.status === value}
                  onClick={() => setForm({ ...form, status: value })}
                  className={cn("pill", form.status === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              The item lands in the list below; add milestones from its detail
              panel.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Creating..." : "Create item"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not create POA&amp;M item</AlertTitle>
            <AlertDescription>
              {mutation.error instanceof ApiError && mutation.error.payload
                ? JSON.stringify(mutation.error.payload)
                : String(mutation.error)}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Read-only calendar / attention surface.
 *
 * Wired to `GET /api/poam/calendar` (CLI `evidentia poam calendar`),
 * bucketing milestones into overdue + due-soon. Pure attention view — no
 * mutations — so it owns its own `["poam", "calendar"]` query.
 */
function PoamCalendar() {
  const query = useQuery({
    queryKey: ["poam", "calendar"],
    // `poamCalendar` is typed `Record<string, unknown>` server-side; narrow to
    // the known attention-surface shape (mirrored from the router) via unknown.
    queryFn: () =>
      api.poamCalendar() as unknown as Promise<PoamCalendarResponse>,
  });

  const overdue = query.data?.overdue ?? [];
  const dueSoon = query.data?.due_soon ?? [];
  const isEmpty =
    query.isSuccess && overdue.length === 0 && dueSoon.length === 0;

  return (
    <section className="stack-3" aria-label="Calendar attention surface">
      <h2 className="section-num">Calendar / attention</h2>

      {query.isError && (
        <Card className="border-dest" role="alert">
          <CardContent className="card-body" style={{ padding: "1.5rem" }}>
            <span className="text-sm text-destructive">
              Could not fetch the POA&amp;M calendar. Is the backend running?
            </span>
          </CardContent>
        </Card>
      )}

      {query.isLoading && <div className="skel" style={{ height: "6rem" }} />}

      {isEmpty && (
        <div className="empty-state">
          Nothing overdue or due soon. Milestones surface here as their target
          dates approach.
        </div>
      )}

      {query.isSuccess && !isEmpty && (
        <div className="grid grid-2">
          <CalendarBucket
            title="Overdue"
            tone="critical"
            entries={overdue}
            emptyLabel="No overdue milestones."
          />
          <CalendarBucket
            title="Due soon"
            tone="medium"
            entries={dueSoon}
            emptyLabel="No milestones due soon."
          />
        </div>
      )}
    </section>
  );
}

function CalendarBucket({
  title,
  tone,
  entries,
  emptyLabel,
}: {
  title: string;
  tone: "critical" | "medium";
  entries: CalendarEntry[];
  emptyLabel: string;
}) {
  return (
    <Card style={{ height: "100%" }}>
      <CardHeader className="pb-3">
        <CardTitle className="base">
          <Badge variant={tone}>{title}</Badge>{" "}
          <span className="text-xs muted">
            {entries.length} milestone{entries.length === 1 ? "" : "s"}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        {entries.length === 0 ? (
          <span className="text-xs faint">{emptyLabel}</span>
        ) : (
          <ul className="reset stack-2">
            {entries.map((entry) => (
              <li key={entry.milestone_id} className="reset text-sm">
                <div className="row gap-2 wrap" style={{ alignItems: "baseline" }}>
                  <span className="mono text-xs">{entry.control_id}</span>
                  <span className="text-xs muted">
                    due <span className="mono tnum">{entry.target_date}</span>
                  </span>
                </div>
                <span className="text-xs">{entry.description}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
