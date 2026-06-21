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
import {
  api,
  ApiError,
  type RetentionCreatePayload,
  type RetentionMetadata,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * Retention screen (Wave-2).
 *
 * Lists per-record retention metadata — each record carries a
 * regulator-aligned `classification`, a `lifecycle_stage`, a `lock_until`
 * mandatory-retention date, and an optional `legal_hold` — filterable by
 * classification + lifecycle stage (mirroring the `evidentia retention list`
 * CLI filters). Selecting a record opens an in-page detail panel exposing the
 * three lifecycle actions: extend the lock-until, transition the lifecycle
 * stage (only legal next stages offered), and delete. A "New retention record"
 * form sits above the list, and a "Report" affordance renders the server's
 * markdown summary as preformatted text.
 *
 * The lifecycle state machine is enforced server-side; the UI mirrors the
 * legal-transition table so it never offers an illegal next stage:
 *   active    -> preserved | expired
 *   preserved -> active | expired
 *   expired   -> purged
 *   purged    -> (terminal)
 */

type RetentionClassification =
  components["schemas"]["RetentionClassification"];
type RetentionLifecycleStage =
  components["schemas"]["RetentionLifecycleStage"];

// ── Enum option tables (mirror the OpenAPI enums) ──────────────────────────

const CLASSIFICATION_FILTER_OPTIONS: [RetentionClassification | null, string][] =
  [
    [null, "All classifications"],
    ["sec-17a-4", "SEC 17a-4"],
    ["finra-3110", "FINRA 3110"],
    ["irs-tax", "IRS tax"],
    ["sox-404", "SOX 404"],
    ["hipaa", "HIPAA"],
    ["glba", "GLBA"],
    ["pci-dss", "PCI DSS"],
    ["model-risk", "Model risk"],
    ["gdpr", "GDPR"],
    ["generic", "Generic"],
  ];

const CLASSIFICATION_PICKER_OPTIONS: [RetentionClassification, string][] = [
  ["sec-17a-4", "SEC 17a-4"],
  ["finra-3110", "FINRA 3110"],
  ["irs-tax", "IRS tax"],
  ["sox-404", "SOX 404"],
  ["hipaa", "HIPAA"],
  ["glba", "GLBA"],
  ["pci-dss", "PCI DSS"],
  ["model-risk", "Model risk"],
  ["gdpr", "GDPR"],
  ["generic", "Generic"],
];

const CLASSIFICATION_LABELS: Record<RetentionClassification, string> = {
  "sec-17a-4": "SEC 17a-4",
  "finra-3110": "FINRA 3110",
  "irs-tax": "IRS tax",
  "sox-404": "SOX 404",
  hipaa: "HIPAA",
  glba: "GLBA",
  "pci-dss": "PCI DSS",
  "model-risk": "Model risk",
  gdpr: "GDPR",
  generic: "Generic",
};

const LIFECYCLE_FILTER_OPTIONS: [RetentionLifecycleStage | null, string][] = [
  [null, "All stages"],
  ["active", "Active"],
  ["preserved", "Preserved"],
  ["expired", "Expired"],
  ["purged", "Purged"],
];

const LIFECYCLE_LABELS: Record<RetentionLifecycleStage, string> = {
  active: "Active",
  preserved: "Preserved",
  expired: "Expired",
  purged: "Purged",
};

/**
 * Legal forward/back transitions — a presentation mirror of the server's
 * lifecycle state machine (`evidentia_core.retention`). The UI offers only
 * these so it never surfaces a transition the POST would reject. Legal hold
 * blocks expiry/purge server-side regardless; the UI surfaces that too.
 */
const VALID_NEXT_STAGES: Record<
  RetentionLifecycleStage,
  RetentionLifecycleStage[]
> = {
  active: ["preserved", "expired"],
  preserved: ["active", "expired"],
  expired: ["purged"],
  purged: [],
};

/** Badge tint for a lifecycle stage — reuses the severity palette. */
function stageBadgeVariant(stage: RetentionLifecycleStage) {
  switch (stage) {
    case "purged":
      return "critical" as const;
    case "expired":
      return "medium" as const;
    case "preserved":
      return "informational" as const;
    case "active":
    default:
      return "low" as const;
  }
}

export function RetentionPage() {
  const [classification, setClassification] =
    useState<RetentionClassification | null>(null);
  const [lifecycle, setLifecycle] = useState<RetentionLifecycleStage | null>(
    null,
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["retention", classification, lifecycle],
    queryFn: () =>
      api.listRetention({
        classification: classification ?? undefined,
        lifecycle: lifecycle ?? undefined,
      }),
  });

  const items = query.data?.items ?? [];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Retention</h1>
        <p className="page-sub">
          {query.data
            ? `${items.length} of ${query.data.total} retention records`
            : "Regulator-aligned record retention."}
        </p>
      </header>

      <NewRetentionForm />

      <RetentionReport />

      <section className="stack-3" aria-label="Retention records">
        <h2 className="section-num">Retention records</h2>

        <div className="row wrap gap-3" aria-label="Filters">
          <div
            className="row gap-2 wrap"
            role="radiogroup"
            aria-label="Filter by classification"
          >
            {CLASSIFICATION_FILTER_OPTIONS.map(([value, label]) => (
              <button
                key={value ?? "all-class"}
                type="button"
                role="radio"
                aria-checked={classification === value}
                onClick={() => setClassification(value)}
                className={cn("chip", classification === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
          <div
            className="row gap-2 wrap"
            role="radiogroup"
            aria-label="Filter by lifecycle stage"
          >
            {LIFECYCLE_FILTER_OPTIONS.map(([value, label]) => (
              <button
                key={value ?? "all-stage"}
                type="button"
                role="radio"
                aria-checked={lifecycle === value}
                onClick={() => setLifecycle(value)}
                className={cn("chip", lifecycle === value && "on")}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch retention records. Is the backend running?
              </span>
            </CardContent>
          </Card>
        )}

        {query.isLoading && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
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
            {classification || lifecycle
              ? "No retention records match your filters."
              : "No retention records yet. Add your first record above."}
          </div>
        )}

        {items.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
          >
            {items.map((item) => {
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
                          <Badge variant="outline">
                            {CLASSIFICATION_LABELS[item.classification]}
                          </Badge>
                          <Badge
                            variant={stageBadgeVariant(item.lifecycle_stage)}
                          >
                            {LIFECYCLE_LABELS[item.lifecycle_stage]}
                          </Badge>
                          {item.legal_hold && (
                            <Badge variant="critical">Legal hold</Badge>
                          )}
                        </div>
                        <CardTitle className="base">
                          {item.record_pointer || (
                            <span className="muted">(no record pointer)</span>
                          )}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="pt-0 text-xs muted stack-2">
                        <div>
                          Lock until:{" "}
                          {item.lock_until ? (
                            <code className="kbd mono tnum">
                              {item.lock_until}
                            </code>
                          ) : (
                            <span className="dim">&mdash;</span>
                          )}
                        </div>
                        <div>
                          {item.retention_period_days}-day retention &middot;{" "}
                          <span>{item.lock_until ? "locked" : "unlocked"}</span>
                        </div>
                      </CardContent>
                    </Card>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {selected && (
        <RetentionDetail
          item={selected}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

/**
 * In-page detail panel for a single retention record: full fields plus the
 * three lifecycle actions (extend lock-until, transition stage, delete).
 * Every mutation invalidates the list query on success.
 */
function RetentionDetail({
  item,
  onClose,
}: {
  item: RetentionMetadata;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [newLockUntil, setNewLockUntil] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["retention"] });

  const extend = useMutation({
    mutationFn: (lock: string) =>
      api.extendRetention(item.id ?? "", { new_lock_until: lock }),
    onSuccess: () => {
      invalidate();
      setNewLockUntil("");
    },
  });

  const transition = useMutation({
    mutationFn: (next: RetentionLifecycleStage) =>
      api.transitionRetention(item.id ?? "", { new_stage: next }),
    onSuccess: invalidate,
  });

  const remove = useMutation({
    mutationFn: () => api.deleteRetention(item.id ?? ""),
    onSuccess: () => {
      invalidate();
      onClose();
    },
  });

  const nextStages = VALID_NEXT_STAGES[item.lifecycle_stage] ?? [];
  const pending = extend.isPending || transition.isPending || remove.isPending;

  return (
    <section
      className="stack-4"
      aria-labelledby="retention-detail-heading"
      aria-busy={pending}
    >
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="retention-detail-heading" className="base">
                {item.record_pointer || "(no record pointer)"}
              </CardTitle>
              <CardDescription>
                <Badge variant="outline">
                  {CLASSIFICATION_LABELS[item.classification]}
                </Badge>{" "}
                <Badge variant={stageBadgeVariant(item.lifecycle_stage)}>
                  {LIFECYCLE_LABELS[item.lifecycle_stage]}
                </Badge>
                {item.legal_hold && (
                  <>
                    {" "}
                    <Badge variant="critical">Legal hold</Badge>
                  </>
                )}
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          <dl className="grid grid-2 text-sm">
            <div className="stack-2">
              <dt className="text-xs faint">Retention period</dt>
              <dd className="mono tnum">{item.retention_period_days} days</dd>
            </div>
            <div className="stack-2">
              <dt className="text-xs faint">Lock until</dt>
              <dd>
                {item.lock_until ? (
                  <code className="kbd mono tnum">{item.lock_until}</code>
                ) : (
                  <span className="dim">&mdash;</span>
                )}
              </dd>
            </div>
            {item.policy_name && (
              <div className="stack-2">
                <dt className="text-xs faint">Policy</dt>
                <dd>{item.policy_name}</dd>
              </div>
            )}
            {item.created_at && (
              <div className="stack-2">
                <dt className="text-xs faint">Created</dt>
                <dd className="mono tnum text-xs">{item.created_at}</dd>
              </div>
            )}
            {item.updated_at && (
              <div className="stack-2">
                <dt className="text-xs faint">Updated</dt>
                <dd className="mono tnum text-xs">{item.updated_at}</dd>
              </div>
            )}
          </dl>

          {item.notes && (
            <p className="text-sm muted">{item.notes}</p>
          )}

          {/* ── Extend lock-until ─────────────────────────────────────── */}
          <div className="stack-3">
            <h2 className="section-num">Extend lock-until</h2>
            <form
              className="row gap-2 wrap"
              onSubmit={(e) => {
                e.preventDefault();
                if (newLockUntil) extend.mutate(newLockUntil);
              }}
            >
              <div className="stack-2">
                <Label htmlFor="retention-new-lock">New lock-until date</Label>
                <Input
                  id="retention-new-lock"
                  type="date"
                  value={newLockUntil}
                  onChange={(e) => setNewLockUntil(e.target.value)}
                  style={{ maxWidth: "16rem" }}
                />
              </div>
              <Button
                type="submit"
                size="sm"
                disabled={!newLockUntil || extend.isPending}
                style={{ alignSelf: "flex-end" }}
              >
                {extend.isPending ? "Extending..." : "Extend"}
              </Button>
            </form>
            {extend.isError && (
              <Alert variant="destructive">
                <AlertTitle>Could not extend lock-until</AlertTitle>
                <AlertDescription>
                  {extend.error instanceof ApiError && extend.error.payload
                    ? JSON.stringify(extend.error.payload)
                    : String(extend.error)}
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* ── Transition lifecycle stage ────────────────────────────── */}
          <div className="stack-3">
            <h2 className="section-num">Transition stage</h2>
            {nextStages.length === 0 ? (
              <span className="text-xs faint">
                {item.lifecycle_stage === "purged"
                  ? "Purged — terminal. No further transitions available."
                  : "No further transitions available."}
              </span>
            ) : (
              <div className="row gap-2 wrap" aria-label="Transition stage">
                <span className="text-xs faint">Transition to:</span>
                {nextStages.map((next) => (
                  <Button
                    key={next}
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={pending}
                    onClick={() => transition.mutate(next)}
                  >
                    {LIFECYCLE_LABELS[next]}
                  </Button>
                ))}
              </div>
            )}
            {transition.isError && (
              <Alert variant="destructive">
                <AlertTitle>Could not transition stage</AlertTitle>
                <AlertDescription>
                  {transition.error instanceof ApiError &&
                  transition.error.payload
                    ? JSON.stringify(transition.error.payload)
                    : String(transition.error)}
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* ── Delete ────────────────────────────────────────────────── */}
          <div className="row-between border-t pt-4 wrap gap-3">
            {confirmingDelete ? (
              <div className="row gap-2 wrap" aria-label="Confirm delete">
                <span className="text-sm">Delete this retention record?</span>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate()}
                >
                  {remove.isPending ? "Deleting..." : "Confirm delete"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={remove.isPending}
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
                Delete record
              </Button>
            )}
          </div>
          {remove.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not delete record</AlertTitle>
              <AlertDescription>
                {remove.error instanceof ApiError && remove.error.payload
                  ? JSON.stringify(remove.error.payload)
                  : String(remove.error)}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

const EMPTY_FORM = {
  classification: "sec-17a-4" as RetentionClassification,
  retention_period_days: "",
  record_pointer: "",
  legal_hold: false,
  policy_name: "",
  notes: "",
};

function NewRetentionForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_FORM });

  const mutation = useMutation({
    mutationFn: (body: RetentionCreatePayload) => api.createRetention(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["retention"] });
      setForm({ ...EMPTY_FORM });
    },
  });

  const submit = () => {
    if (mutation.isPending) return;
    // classification is the only required field; the server defaults the
    // retention period from the per-classification regulator minimum when
    // `retention_period_days` is omitted. Optional text fields are sent only
    // when non-empty (null/undefined collapse to the server default).
    const days = form.retention_period_days.trim();
    const pointer = form.record_pointer.trim();
    const policy = form.policy_name.trim();
    const notes = form.notes.trim();
    mutation.mutate({
      classification: form.classification,
      legal_hold: form.legal_hold,
      retention_period_days: days ? Number(days) : null,
      record_pointer: pointer || null,
      policy_name: policy || null,
      notes: notes || null,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">New retention record</CardTitle>
        <CardDescription>
          Track a record's retention. Only the classification is required — the
          server defaults the retention period to the regulator-stated minimum.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="stack-5"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="stack-2">
            <span className="text-sm font-medium leading-none">
              Classification
            </span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Classification"
            >
              {CLASSIFICATION_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.classification === value}
                  onClick={() => setForm({ ...form, classification: value })}
                  className={cn(
                    "pill",
                    form.classification === value && "on",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="retention-period-days">
                Retention period (days)
              </Label>
              <Input
                id="retention-period-days"
                type="number"
                min={0}
                value={form.retention_period_days}
                onChange={(e) =>
                  setForm({ ...form, retention_period_days: e.target.value })
                }
                placeholder="regulator default"
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="retention-pointer">Record pointer</Label>
              <Input
                id="retention-pointer"
                value={form.record_pointer}
                onChange={(e) =>
                  setForm({ ...form, record_pointer: e.target.value })
                }
                placeholder="s3://bucket/key or /path/to/record"
              />
            </div>
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="retention-policy">Policy name</Label>
              <Input
                id="retention-policy"
                value={form.policy_name}
                onChange={(e) =>
                  setForm({ ...form, policy_name: e.target.value })
                }
                placeholder="optional cross-reference"
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="retention-notes">Notes</Label>
              <Input
                id="retention-notes"
                value={form.notes}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                placeholder="optional operator notes"
              />
            </div>
          </div>

          <div className="row gap-2" style={{ alignItems: "center" }}>
            <input
              id="retention-legal-hold"
              type="checkbox"
              checked={form.legal_hold}
              onChange={(e) =>
                setForm({ ...form, legal_hold: e.target.checked })
              }
            />
            <Label htmlFor="retention-legal-hold">
              Place under legal hold
            </Label>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              The record lands in the inventory below.
            </p>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Adding..." : "Add record"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not add retention record</AlertTitle>
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
 * On-demand retention report: a button fetches the server's markdown summary
 * (`GET /api/retention/report`, served as text/markdown) and renders it as
 * preformatted text. The raw markdown is shown verbatim in a `<pre>` — never
 * via a raw-HTML prop.
 */
function RetentionReport() {
  const report = useMutation({
    mutationFn: () => api.retentionReport(),
  });

  return (
    <Card>
      <CardHeader className="row-between gap-4 wrap pb-3">
        <div className="stack-2">
          <CardTitle className="base">Retention report</CardTitle>
          <CardDescription>
            A regulator-aligned summary of the retention store, rendered as
            markdown.
          </CardDescription>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={report.isPending}
          onClick={() => report.mutate()}
        >
          {report.isPending ? "Generating..." : "Generate report"}
        </Button>
      </CardHeader>
      {(report.isSuccess || report.isError) && (
        <CardContent className="pt-0">
          {report.isError ? (
            <Alert variant="destructive">
              <AlertTitle>Could not generate report</AlertTitle>
              <AlertDescription>
                {report.error instanceof ApiError && report.error.payload
                  ? JSON.stringify(report.error.payload)
                  : String(report.error)}
              </AlertDescription>
            </Alert>
          ) : (
            <pre
              className="mono text-xs"
              style={{
                whiteSpace: "pre-wrap",
                overflowX: "auto",
                margin: 0,
                maxHeight: "32rem",
              }}
              aria-label="Retention report"
            >
              {report.data}
            </pre>
          )}
        </CardContent>
      )}
    </Card>
  );
}
