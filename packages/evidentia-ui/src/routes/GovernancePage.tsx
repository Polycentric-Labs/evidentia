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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  type EffectiveChallenge,
  type Metric,
  type MetricWithStatus,
  type Owner,
  type Workflow,
  type WorkflowInput,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import type { components } from "@/types/openapi";

/**
 * Governance console (Wave-3) — the largest UI surface, a four-tab cockpit
 * over the `evidentia governance` family:
 *
 *   - Challenges   — SR 11-7 §III.D effective-challenge log (list + create).
 *   - Metrics      — KRI/KPI/KGI register with thresholds + observations.
 *   - Workflows    — stepwise governance workflows (run + advance + log).
 *   - Lines        — IIA Three-Lines-of-Defense owner roster + report.
 *
 * Each tab mirrors the PoamPage list+detail+mutation rhythm: a filtered card
 * list, an in-page detail panel for the selected record, and mutations that
 * invalidate the relevant query on success. Markdown reports
 * (`metricsReport`, `workflowLog`, `linesReport`) are rendered as PLAIN
 * preformatted text — React auto-escaping only, never raw HTML.
 */

// ── Shared enum option tables (mirror the OpenAPI governance schemas) ─────

type ChallengeOutcome = components["schemas"]["ChallengeOutcome"];
type MetricKind = components["schemas"]["MetricKind"];
type MetricDirection = components["schemas"]["MetricDirection"];
type LineOfDefense = components["schemas"]["LineOfDefense"];
type WorkflowStepStatus = components["schemas"]["WorkflowStepStatus"];

const OUTCOME_FILTER_OPTIONS: [ChallengeOutcome | null, string][] = [
  [null, "All outcomes"],
  ["accepted", "Accepted"],
  ["rejected", "Rejected"],
  ["modify", "Modify"],
  ["pending", "Pending"],
];

const OUTCOME_PICKER_OPTIONS: [ChallengeOutcome, string][] = [
  ["pending", "Pending"],
  ["accepted", "Accepted"],
  ["rejected", "Rejected"],
  ["modify", "Modify"],
];

const OUTCOME_BADGE_VARIANT: Record<
  ChallengeOutcome,
  "critical" | "low" | "medium" | "secondary"
> = {
  accepted: "low",
  rejected: "critical",
  modify: "medium",
  pending: "secondary",
};

const KIND_FILTER_OPTIONS: [MetricKind | null, string][] = [
  [null, "All kinds"],
  ["kri", "KRI"],
  ["kpi", "KPI"],
  ["kgi", "KGI"],
];

const KIND_PICKER_OPTIONS: [MetricKind, string][] = [
  ["kri", "KRI"],
  ["kpi", "KPI"],
  ["kgi", "KGI"],
];

const DIRECTION_PICKER_OPTIONS: [MetricDirection, string][] = [
  ["higher_is_worse", "Higher is worse"],
  ["higher_is_better", "Higher is better"],
];

const KIND_LABELS: Record<MetricKind, string> = {
  kri: "KRI",
  kpi: "KPI",
  kgi: "KGI",
};

/** Derived `status` -> Badge variant for a metric. */
function metricStatusVariant(
  status: string,
): "critical" | "medium" | "low" | "secondary" {
  switch (status) {
    case "breach":
      return "critical";
    case "watch":
      return "medium";
    case "comfortable":
      return "low";
    case "no_data":
    default:
      return "secondary";
  }
}

const LOD_PICKER_OPTIONS: [LineOfDefense, string][] = [
  ["first", "First line"],
  ["second", "Second line"],
  ["third", "Third line"],
];

const LOD_LABELS: Record<LineOfDefense, string> = {
  first: "First line",
  second: "Second line",
  third: "Third line",
};

const WORKFLOW_STATUS_VARIANT: Record<
  string,
  "critical" | "medium" | "low" | "secondary"
> = {
  draft: "secondary",
  in_progress: "medium",
  approved: "low",
  rejected: "critical",
  canceled: "secondary",
};

const STEP_STATUS_VARIANT: Record<
  WorkflowStepStatus,
  "critical" | "medium" | "low" | "secondary"
> = {
  pending: "secondary",
  in_progress: "medium",
  approved: "low",
  rejected: "critical",
  skipped: "secondary",
};

const STEP_STATUS_LABEL: Record<WorkflowStepStatus, string> = {
  pending: "Pending",
  in_progress: "In progress",
  approved: "Approved",
  rejected: "Rejected",
  skipped: "Skipped",
};

/**
 * Legal next states a `pending` / `in_progress` step can be advanced to. The
 * engine accepts any of these as a `new_status`; the UI offers them so the
 * advance control never surfaces a no-op. A 400 on an illegal transition is
 * still surfaced from the server response.
 */
const STEP_ADVANCE_OPTIONS: WorkflowStepStatus[] = [
  "in_progress",
  "approved",
  "rejected",
  "skipped",
];

export function GovernancePage() {
  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Governance</h1>
        <p className="page-sub">
          Effective challenges, risk/performance metrics, stepwise workflows,
          and the three-lines-of-defense roster.
        </p>
      </header>

      <Tabs defaultValue="challenges">
        <TabsList>
          <TabsTrigger value="challenges">Challenges</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
          <TabsTrigger value="lines">Lines of Defense</TabsTrigger>
        </TabsList>

        <TabsContent value="challenges">
          <ChallengesTab />
        </TabsContent>
        <TabsContent value="metrics">
          <MetricsTab />
        </TabsContent>
        <TabsContent value="workflows">
          <WorkflowsTab />
        </TabsContent>
        <TabsContent value="lines">
          <LinesTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════
// Challenges
// ════════════════════════════════════════════════════════════════════════

function ChallengesTab() {
  const [outcome, setOutcome] = useState<ChallengeOutcome | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["gov-challenges", outcome],
    queryFn: () =>
      api.listChallenges({ outcome: outcome ?? undefined }),
  });

  const items = query.data?.items ?? [];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <NewChallengeForm />

      <section className="stack-3" aria-label="Effective challenges">
        <h2 className="section-num">Effective challenges</h2>

        <div
          className="row gap-2 wrap"
          role="radiogroup"
          aria-label="Filter by outcome"
        >
          {OUTCOME_FILTER_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all-outcome"}
              type="button"
              role="radio"
              aria-checked={outcome === value}
              onClick={() => setOutcome(value)}
              className={cn("chip", outcome === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch challenges. Is the backend running?
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
            {Array.from({ length: 4 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && items.length === 0 && (
          <div className="empty-state">
            {outcome
              ? "No challenges match this outcome."
              : "No effective challenges logged yet. Record your first above."}
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
                <li key={item.id ?? item.challenge_topic} className="reset">
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
                          <Badge variant={OUTCOME_BADGE_VARIANT[item.outcome]}>
                            {item.outcome}
                          </Badge>
                          <Badge variant="outline">
                            <span className="mono tnum">
                              {item.challenge_date}
                            </span>
                          </Badge>
                        </div>
                        <CardTitle className="base">
                          {item.challenge_topic}
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="pt-0 text-xs muted">
                        Subject:{" "}
                        <code className="kbd mono">{item.subject_model_id}</code>
                      </CardContent>
                    </Card>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        {selected && (
          <ChallengeDetail
            challenge={selected}
            onClose={() => setSelectedId(null)}
          />
        )}
      </section>
    </div>
  );
}

function ChallengeDetail({
  challenge,
  onClose,
}: {
  challenge: EffectiveChallenge;
  onClose: () => void;
}) {
  return (
    <section className="stack-4" aria-labelledby="challenge-detail-heading">
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="challenge-detail-heading" className="base">
                {challenge.challenge_topic}
              </CardTitle>
              <CardDescription>
                {challenge.challenger_role} &middot;{" "}
                <code className="kbd">{challenge.challenger_email}</code>{" "}
                &middot;{" "}
                <Badge variant={OUTCOME_BADGE_VARIANT[challenge.outcome]}>
                  {challenge.outcome}
                </Badge>
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          <div className="stack-2">
            <h3 className="section-num">Substance</h3>
            <p className="text-sm">{challenge.challenge_substance}</p>
          </div>

          <div className="stack-2">
            <h3 className="section-num">Response</h3>
            <p className="text-sm muted">
              {challenge.response ?? "No response logged yet."}
            </p>
          </div>

          <div className="stack-2">
            <h3 className="section-num">Outcome rationale</h3>
            <p className="text-sm muted">
              {challenge.outcome_rationale ?? "No rationale recorded."}
            </p>
          </div>

          {challenge.resolved_at && (
            <p className="text-xs faint">
              Resolved{" "}
              <span className="mono tnum">{challenge.resolved_at}</span>
            </p>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

const EMPTY_CHALLENGE = {
  subject_model_id: "",
  challenger_email: "",
  challenger_role: "",
  challenge_date: "",
  challenge_topic: "",
  challenge_substance: "",
  outcome: "pending" as ChallengeOutcome,
};

function NewChallengeForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_CHALLENGE });

  const mutation = useMutation({
    mutationFn: (body: EffectiveChallenge) => api.createChallenge(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gov-challenges"] });
      setForm({ ...EMPTY_CHALLENGE });
    },
  });

  const canSubmit =
    form.subject_model_id.trim().length > 0 &&
    form.challenger_email.trim().length > 0 &&
    form.challenger_role.trim().length > 0 &&
    form.challenge_date.length > 0 &&
    form.challenge_topic.trim().length > 0 &&
    form.challenge_substance.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate({
      subject_model_id: form.subject_model_id.trim(),
      challenger_email: form.challenger_email.trim(),
      challenger_role: form.challenger_role.trim(),
      challenge_date: form.challenge_date,
      challenge_topic: form.challenge_topic.trim(),
      challenge_substance: form.challenge_substance.trim(),
      outcome: form.outcome,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Record a challenge</CardTitle>
        <CardDescription>
          Log an independent effective challenge against a model (SR 11-7
          §III.D). The server fills id / timestamps.
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
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="challenge-subject">Subject model id</Label>
              <Input
                id="challenge-subject"
                value={form.subject_model_id}
                onChange={(e) =>
                  setForm({ ...form, subject_model_id: e.target.value })
                }
                placeholder="model UUID"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="challenge-date">Challenge date</Label>
              <Input
                id="challenge-date"
                type="date"
                value={form.challenge_date}
                onChange={(e) =>
                  setForm({ ...form, challenge_date: e.target.value })
                }
                required
              />
            </div>
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="challenge-email">Challenger email</Label>
              <Input
                id="challenge-email"
                value={form.challenger_email}
                onChange={(e) =>
                  setForm({ ...form, challenger_email: e.target.value })
                }
                placeholder="mrm-director@example.com"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="challenge-role">Challenger role</Label>
              <Input
                id="challenge-role"
                value={form.challenger_role}
                onChange={(e) =>
                  setForm({ ...form, challenger_role: e.target.value })
                }
                placeholder="MRM Director"
                required
              />
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="challenge-topic">Topic</Label>
            <Input
              id="challenge-topic"
              value={form.challenge_topic}
              onChange={(e) =>
                setForm({ ...form, challenge_topic: e.target.value })
              }
              placeholder="Methodology — feature selection rationale"
              required
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="challenge-substance">Substance</Label>
            <Textarea
              id="challenge-substance"
              value={form.challenge_substance}
              onChange={(e) =>
                setForm({ ...form, challenge_substance: e.target.value })
              }
              placeholder="What was questioned and on what grounds."
              required
            />
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Outcome</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Challenge outcome"
            >
              {OUTCOME_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.outcome === value}
                  onClick={() => setForm({ ...form, outcome: value })}
                  className={cn("pill", form.outcome === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Six required fields. The challenge lands in the log below.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Recording..." : "Record challenge"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not record challenge</AlertTitle>
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

// ════════════════════════════════════════════════════════════════════════
// Metrics
// ════════════════════════════════════════════════════════════════════════

function latestObservation(metric: Metric) {
  const obs = metric.observations ?? [];
  return obs.length > 0 ? obs[obs.length - 1] : null;
}

function MetricsTab() {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<MetricKind | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["gov-metrics", kind],
    queryFn: () => api.listMetrics({ kind: kind ?? undefined }),
  });

  const reportMutation = useMutation({
    mutationFn: () => api.metricsReport(),
    onSuccess: (md) => setReport(md),
  });

  const items = query.data?.items ?? [];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <NewMetricForm />

      <section className="stack-3" aria-label="Metric register">
        <div className="row-between gap-4 wrap">
          <h2 className="section-num">Metric register</h2>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={reportMutation.isPending}
            onClick={() => reportMutation.mutate()}
          >
            {reportMutation.isPending ? "Generating..." : "Report"}
          </Button>
        </div>

        <div
          className="row gap-2 wrap"
          role="radiogroup"
          aria-label="Filter by metric kind"
        >
          {KIND_FILTER_OPTIONS.map(([value, label]) => (
            <button
              key={value ?? "all-kind"}
              type="button"
              role="radio"
              aria-checked={kind === value}
              onClick={() => setKind(value)}
              className={cn("chip", kind === value && "on")}
            >
              {label}
            </button>
          ))}
        </div>

        {report !== null && (
          <Card>
            <CardHeader className="pb-3">
              <div className="row-between gap-4 wrap">
                <CardTitle className="base">Metrics report</CardTitle>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setReport(null)}
                >
                  Dismiss
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <pre
                className="mono text-xs box"
                style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
              >
                {report}
              </pre>
            </CardContent>
          </Card>
        )}

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch metrics. Is the backend running?
              </span>
            </CardContent>
          </Card>
        )}

        {query.isLoading && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
            }}
          >
            {Array.from({ length: 4 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && items.length === 0 && (
          <div className="empty-state">
            {kind
              ? "No metrics of this kind yet."
              : "No metrics defined yet. Add your first above."}
          </div>
        )}

        {items.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
            }}
          >
            {items.map((metric) => {
              const isSelected = metric.id === selectedId;
              const latest = latestObservation(metric);
              return (
                <li key={metric.id ?? metric.name} className="reset">
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
                      setSelectedId(isSelected ? null : (metric.id ?? null))
                    }
                  >
                    <Card
                      className={cn("card-hover", isSelected && "border-dest")}
                      style={{ height: "100%" }}
                    >
                      <CardHeader className="stack-2">
                        <div className="row gap-2 wrap">
                          <Badge variant="outline">
                            {KIND_LABELS[metric.kind]}
                          </Badge>
                          <Badge variant={metricStatusVariant(metric.status)}>
                            {metric.status.replace(/_/g, " ")}
                          </Badge>
                        </div>
                        <CardTitle className="base">{metric.name}</CardTitle>
                      </CardHeader>
                      <CardContent className="pt-0 text-xs muted stack-2">
                        <div>
                          Unit: <code className="kbd">{metric.unit}</code>
                        </div>
                        <div>
                          Latest:{" "}
                          {latest ? (
                            <span className="mono tnum">{latest.value}</span>
                          ) : (
                            <span className="muted">no data</span>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        {selected && (
          <MetricDetail
            metric={selected}
            onClose={() => setSelectedId(null)}
            onMutated={() =>
              queryClient.invalidateQueries({ queryKey: ["gov-metrics"] })
            }
            onDeleted={() => {
              setSelectedId(null);
              queryClient.invalidateQueries({ queryKey: ["gov-metrics"] });
            }}
          />
        )}
      </section>
    </div>
  );
}

function MetricDetail({
  metric,
  onClose,
  onMutated,
  onDeleted,
}: {
  metric: MetricWithStatus;
  onClose: () => void;
  onMutated: () => void;
  onDeleted: () => void;
}) {
  const observations = metric.observations ?? [];

  const observeMutation = useMutation({
    mutationFn: (payload: {
      value: number;
      observed_at: string;
      note?: string;
    }) => api.observeMetric(metric.id ?? "", payload),
    onSuccess: () => onMutated(),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteMetric(metric.id ?? ""),
    onSuccess: () => onDeleted(),
  });

  const [obsValue, setObsValue] = useState("");
  const [obsDate, setObsDate] = useState("");
  const [obsNote, setObsNote] = useState("");

  const canObserve =
    obsValue.trim().length > 0 &&
    !Number.isNaN(Number(obsValue)) &&
    obsDate.length > 0 &&
    !observeMutation.isPending;

  const submitObservation = () => {
    if (!canObserve) return;
    observeMutation.mutate(
      {
        value: Number(obsValue),
        observed_at: obsDate,
        note: obsNote.trim() ? obsNote.trim() : undefined,
      },
      {
        onSuccess: () => {
          setObsValue("");
          setObsDate("");
          setObsNote("");
        },
      },
    );
  };

  const confirmDelete = () => {
    if (
      window.confirm(
        `Delete metric "${metric.name}"? This cannot be undone.`,
      )
    ) {
      deleteMutation.mutate();
    }
  };

  return (
    <section
      className="stack-4"
      aria-labelledby="metric-detail-heading"
      aria-busy={observeMutation.isPending || deleteMutation.isPending}
    >
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="metric-detail-heading" className="base">
                {metric.name}
              </CardTitle>
              <CardDescription>
                <Badge variant="outline">{KIND_LABELS[metric.kind]}</Badge>{" "}
                <Badge variant={metricStatusVariant(metric.status)}>
                  {metric.status.replace(/_/g, " ")}
                </Badge>
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          <p className="text-sm muted">{metric.description}</p>

          <div className="text-xs muted stack-2">
            <div>
              Warning threshold:{" "}
              {metric.warning_threshold != null ? (
                <span className="mono tnum">{metric.warning_threshold}</span>
              ) : (
                <span className="muted">none</span>
              )}
            </div>
            <div>
              Critical threshold:{" "}
              {metric.critical_threshold != null ? (
                <span className="mono tnum">{metric.critical_threshold}</span>
              ) : (
                <span className="muted">none</span>
              )}
            </div>
          </div>

          <div className="stack-3">
            <h3 className="section-num">Observations</h3>
            {observations.length === 0 ? (
              <div className="empty-state">No observations recorded yet.</div>
            ) : (
              <ul className="reset stack-2">
                {observations.map((obs, idx) => (
                  <li key={`${metric.id}-obs-${idx}`} className="reset">
                    <div className="row gap-3 wrap text-xs">
                      <span className="mono tnum">{obs.value}</span>
                      <span className="muted mono tnum">{obs.observed_at}</span>
                      {obs.note && <span className="faint">{obs.note}</span>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <form
            className="stack-3 border-t pt-4"
            aria-label="Record observation"
            onSubmit={(e) => {
              e.preventDefault();
              submitObservation();
            }}
          >
            <h3 className="section-num">Record observation</h3>
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="obs-value">Value</Label>
                <Input
                  id="obs-value"
                  type="number"
                  step="any"
                  value={obsValue}
                  onChange={(e) => setObsValue(e.target.value)}
                  required
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="obs-date">Observed at</Label>
                <Input
                  id="obs-date"
                  type="date"
                  value={obsDate}
                  onChange={(e) => setObsDate(e.target.value)}
                  required
                />
              </div>
            </div>
            <div className="stack-2">
              <Label htmlFor="obs-note">Note (optional)</Label>
              <Input
                id="obs-note"
                value={obsNote}
                onChange={(e) => setObsNote(e.target.value)}
                placeholder="Q3 backlog spike"
              />
            </div>
            <div className="row-end">
              <Button type="submit" disabled={!canObserve}>
                {observeMutation.isPending ? "Observing..." : "Observe"}
              </Button>
            </div>
          </form>

          {observeMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not record observation</AlertTitle>
              <AlertDescription>
                {observeMutation.error instanceof ApiError &&
                observeMutation.error.payload
                  ? JSON.stringify(observeMutation.error.payload)
                  : String(observeMutation.error)}
              </AlertDescription>
            </Alert>
          )}

          <div className="row-between border-t pt-4">
            <p className="text-xs faint">
              Deleting removes the metric and its observation history.
            </p>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              disabled={deleteMutation.isPending}
              onClick={confirmDelete}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete metric"}
            </Button>
          </div>

          {deleteMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not delete metric</AlertTitle>
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

const EMPTY_METRIC = {
  name: "",
  description: "",
  kind: "kri" as MetricKind,
  direction: "higher_is_worse" as MetricDirection,
  unit: "",
  owner_email: "",
  warning_threshold: "",
  critical_threshold: "",
};

function NewMetricForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_METRIC });

  const mutation = useMutation({
    mutationFn: (body: Metric) => api.createMetric(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gov-metrics"] });
      setForm({ ...EMPTY_METRIC });
    },
  });

  const canSubmit =
    form.name.trim().length > 0 &&
    form.description.trim().length > 0 &&
    form.unit.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    const warning =
      form.warning_threshold.trim() && !Number.isNaN(Number(form.warning_threshold))
        ? Number(form.warning_threshold)
        : null;
    const critical =
      form.critical_threshold.trim() &&
      !Number.isNaN(Number(form.critical_threshold))
        ? Number(form.critical_threshold)
        : null;
    mutation.mutate({
      name: form.name.trim(),
      description: form.description.trim(),
      kind: form.kind,
      direction: form.direction,
      unit: form.unit.trim(),
      owner_email: form.owner_email.trim() ? form.owner_email.trim() : null,
      warning_threshold: warning,
      critical_threshold: critical,
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">New metric</CardTitle>
        <CardDescription>
          Define a KRI / KPI / KGI. Thresholds drive the derived status
          (comfortable / watch / breach).
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
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="metric-name">Name</Label>
              <Input
                id="metric-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Failed-login rate"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="metric-unit">Unit</Label>
              <Input
                id="metric-unit"
                value={form.unit}
                onChange={(e) => setForm({ ...form, unit: e.target.value })}
                placeholder="per 1,000 logins"
                required
              />
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="metric-description">Description</Label>
            <Textarea
              id="metric-description"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              placeholder="What this metric measures and why it's tracked."
              required
            />
          </div>

          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="metric-owner">Owner email (optional)</Label>
              <Input
                id="metric-owner"
                value={form.owner_email}
                onChange={(e) =>
                  setForm({ ...form, owner_email: e.target.value })
                }
                placeholder="owner@example.com"
              />
            </div>
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="metric-warning">Warning threshold</Label>
                <Input
                  id="metric-warning"
                  type="number"
                  step="any"
                  value={form.warning_threshold}
                  onChange={(e) =>
                    setForm({ ...form, warning_threshold: e.target.value })
                  }
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="metric-critical">Critical threshold</Label>
                <Input
                  id="metric-critical"
                  type="number"
                  step="any"
                  value={form.critical_threshold}
                  onChange={(e) =>
                    setForm({ ...form, critical_threshold: e.target.value })
                  }
                />
              </div>
            </div>
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Kind</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Metric kind"
            >
              {KIND_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.kind === value}
                  onClick={() => setForm({ ...form, kind: value })}
                  className={cn("pill", form.kind === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="stack-2">
            <span className="text-sm font-medium leading-none">Direction</span>
            <div
              className="row wrap gap-2"
              role="radiogroup"
              aria-label="Metric direction"
            >
              {DIRECTION_PICKER_OPTIONS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={form.direction === value}
                  onClick={() => setForm({ ...form, direction: value })}
                  className={cn("pill", form.direction === value && "on")}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              Name, description, and unit are required.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Adding..." : "Add metric"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not add metric</AlertTitle>
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

// ════════════════════════════════════════════════════════════════════════
// Workflows
// ════════════════════════════════════════════════════════════════════════

function WorkflowsTab() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["gov-workflows"],
    queryFn: () => api.listWorkflows(),
  });

  const items = query.data?.items ?? [];
  const selected = items.find((it) => it.id === selectedId) ?? null;

  return (
    <div className="stack-6">
      <NewWorkflowForm />

      <section className="stack-3" aria-label="Workflows">
        <h2 className="section-num">Workflows</h2>

        {query.isError && (
          <Card className="border-dest">
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <span className="text-sm text-destructive">
                Could not fetch workflows. Is the backend running?
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
            {Array.from({ length: 4 }).map((_, i) => (
              <li key={i} className="reset">
                <div className="skel" style={{ height: "8rem" }} />
              </li>
            ))}
          </ul>
        )}

        {query.isSuccess && items.length === 0 && (
          <div className="empty-state">
            No workflows yet. Run your first above.
          </div>
        )}

        {items.length > 0 && (
          <ul
            className="reset grid"
            style={{
              gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            }}
          >
            {items.map((wf) => {
              const isSelected = wf.id === selectedId;
              const steps = wf.steps ?? [];
              return (
                <li key={wf.id ?? wf.name} className="reset">
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
                      setSelectedId(isSelected ? null : (wf.id ?? null))
                    }
                  >
                    <Card
                      className={cn("card-hover", isSelected && "border-dest")}
                      style={{ height: "100%" }}
                    >
                      <CardHeader className="stack-2">
                        <div className="row gap-2 wrap">
                          <Badge
                            variant={
                              WORKFLOW_STATUS_VARIANT[wf.status] ?? "secondary"
                            }
                          >
                            {wf.status.replace(/_/g, " ")}
                          </Badge>
                          <Badge variant="outline">
                            {steps.length} step{steps.length === 1 ? "" : "s"}
                          </Badge>
                        </div>
                        <CardTitle className="base">{wf.name}</CardTitle>
                      </CardHeader>
                      <CardContent className="pt-0 text-xs muted">
                        Initiator:{" "}
                        <code className="kbd">{wf.initiator}</code>
                      </CardContent>
                    </Card>
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        {selected && (
          <WorkflowDetail
            workflow={selected}
            onClose={() => setSelectedId(null)}
            onMutated={() =>
              queryClient.invalidateQueries({ queryKey: ["gov-workflows"] })
            }
            onDeleted={() => {
              setSelectedId(null);
              queryClient.invalidateQueries({ queryKey: ["gov-workflows"] });
            }}
          />
        )}
      </section>
    </div>
  );
}

function WorkflowDetail({
  workflow,
  onClose,
  onMutated,
  onDeleted,
}: {
  workflow: Workflow;
  onClose: () => void;
  onMutated: () => void;
  onDeleted: () => void;
}) {
  const steps = workflow.steps ?? [];
  const [actor, setActor] = useState("");
  const [log, setLog] = useState<string | null>(null);

  const advanceMutation = useMutation({
    mutationFn: (payload: {
      step_index: number;
      new_status: WorkflowStepStatus;
    }) =>
      api.advanceWorkflow(workflow.id ?? "", {
        step_index: payload.step_index,
        new_status: payload.new_status,
        actor: actor.trim() || "operator@example.com",
      }),
    onSuccess: () => onMutated(),
  });

  const logMutation = useMutation({
    mutationFn: () => api.workflowLog(workflow.id ?? ""),
    onSuccess: (md) => setLog(md),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteWorkflow(workflow.id ?? ""),
    onSuccess: () => onDeleted(),
  });

  const confirmDelete = () => {
    if (
      window.confirm(
        `Delete workflow "${workflow.name}"? This cannot be undone.`,
      )
    ) {
      deleteMutation.mutate();
    }
  };

  return (
    <section
      className="stack-4"
      aria-labelledby="workflow-detail-heading"
      aria-busy={advanceMutation.isPending || deleteMutation.isPending}
    >
      <Card>
        <CardHeader className="stack-2">
          <div
            className="row-between gap-4 wrap"
            style={{ alignItems: "flex-start" }}
          >
            <div className="stack-2">
              <CardTitle id="workflow-detail-heading" className="base">
                {workflow.name}
              </CardTitle>
              <CardDescription>
                <Badge
                  variant={
                    WORKFLOW_STATUS_VARIANT[workflow.status] ?? "secondary"
                  }
                >
                  {workflow.status.replace(/_/g, " ")}
                </Badge>{" "}
                &middot; initiator{" "}
                <code className="kbd">{workflow.initiator}</code>
                {workflow.subject ? (
                  <>
                    {" "}
                    &middot; subject{" "}
                    <span className="muted">{workflow.subject}</span>
                  </>
                ) : null}
              </CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </CardHeader>
        <CardContent className="stack-4 pt-0">
          <p className="text-sm muted">{workflow.description}</p>

          <div className="stack-2">
            <Label htmlFor="workflow-actor">Actor (for advancing steps)</Label>
            <Input
              id="workflow-actor"
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="approver@example.com"
              style={{ maxWidth: "20rem" }}
            />
          </div>

          {advanceMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not advance step</AlertTitle>
              <AlertDescription>
                {advanceMutation.error instanceof ApiError &&
                advanceMutation.error.payload
                  ? JSON.stringify(advanceMutation.error.payload)
                  : String(advanceMutation.error)}
              </AlertDescription>
            </Alert>
          )}

          <div className="stack-3">
            <h3 className="section-num">Steps</h3>
            {steps.length === 0 ? (
              <div className="empty-state">This workflow has no steps.</div>
            ) : (
              <ul className="reset stack-2">
                {steps.map((step, idx) => (
                  <li key={`${workflow.id}-step-${idx}`} className="reset">
                    <Card>
                      <CardContent
                        className="stack-3"
                        style={{ padding: "1rem" }}
                      >
                        <div
                          className="row-between gap-4 wrap"
                          style={{ alignItems: "flex-start" }}
                        >
                          <div className="stack-2">
                            <span className="text-sm">
                              <span className="mono text-xs">#{idx}</span>{" "}
                              {step.name}
                            </span>
                            <span className="text-xs muted">
                              Required role:{" "}
                              <code className="kbd">{step.required_role}</code>
                              {step.sla_days != null
                                ? ` · SLA ${step.sla_days}d`
                                : ""}
                            </span>
                            {step.description && (
                              <span className="text-xs faint">
                                {step.description}
                              </span>
                            )}
                          </div>
                          <Badge variant={STEP_STATUS_VARIANT[step.status]}>
                            {STEP_STATUS_LABEL[step.status]}
                          </Badge>
                        </div>

                        <div
                          className="row gap-2 wrap"
                          aria-label="Advance step"
                        >
                          <span className="text-xs faint">Advance to:</span>
                          {STEP_ADVANCE_OPTIONS.filter(
                            (next) => next !== step.status,
                          ).map((next) => (
                            <Button
                              key={next}
                              type="button"
                              variant="outline"
                              size="sm"
                              disabled={advanceMutation.isPending}
                              onClick={() =>
                                advanceMutation.mutate({
                                  step_index: idx,
                                  new_status: next,
                                })
                              }
                            >
                              {STEP_STATUS_LABEL[next]}
                            </Button>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="row gap-2 wrap border-t pt-4">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={logMutation.isPending}
              onClick={() => logMutation.mutate()}
            >
              {logMutation.isPending ? "Loading..." : "Log"}
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="sm"
              disabled={deleteMutation.isPending}
              onClick={confirmDelete}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete workflow"}
            </Button>
          </div>

          {log !== null && (
            <div className="stack-2">
              <div className="row-between gap-4 wrap">
                <h3 className="section-num">Workflow log</h3>
                <Button variant="outline" size="sm" onClick={() => setLog(null)}>
                  Dismiss
                </Button>
              </div>
              <pre
                className="mono text-xs box"
                style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
              >
                {log}
              </pre>
            </div>
          )}

          {deleteMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not delete workflow</AlertTitle>
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

type StepDraft = { name: string; required_role: string };

const EMPTY_WORKFLOW = {
  name: "",
  description: "",
  initiator: "",
  subject: "",
};

function NewWorkflowForm() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_WORKFLOW });
  const [steps, setSteps] = useState<StepDraft[]>([
    { name: "", required_role: "" },
  ]);

  const mutation = useMutation({
    mutationFn: (body: WorkflowInput) => api.runWorkflow(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["gov-workflows"] });
      setForm({ ...EMPTY_WORKFLOW });
      setSteps([{ name: "", required_role: "" }]);
    },
  });

  const validSteps = steps.filter(
    (s) => s.name.trim().length > 0 && s.required_role.trim().length > 0,
  );

  const canSubmit =
    form.name.trim().length > 0 &&
    form.description.trim().length > 0 &&
    form.initiator.trim().length > 0 &&
    validSteps.length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate({
      name: form.name.trim(),
      description: form.description.trim(),
      initiator: form.initiator.trim(),
      subject: form.subject.trim() ? form.subject.trim() : null,
      status: "draft",
      steps: validSteps.map((s) => ({
        name: s.name.trim(),
        required_role: s.required_role.trim(),
        status: "pending",
      })),
    });
  };

  const updateStep = (idx: number, patch: Partial<StepDraft>) =>
    setSteps((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)),
    );

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="base">Run a workflow</CardTitle>
        <CardDescription>
          Create a stepwise governance workflow. Each step carries a name and a
          required role; steps start in <code className="kbd">pending</code>.
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
          <div className="grid grid-2">
            <div className="stack-2">
              <Label htmlFor="workflow-name">Name</Label>
              <Input
                id="workflow-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Credit-model-v3 quarterly review"
                required
              />
            </div>
            <div className="stack-2">
              <Label htmlFor="workflow-initiator">Initiator</Label>
              <Input
                id="workflow-initiator"
                value={form.initiator}
                onChange={(e) =>
                  setForm({ ...form, initiator: e.target.value })
                }
                placeholder="initiator@example.com"
                required
              />
            </div>
          </div>

          <div className="stack-2">
            <Label htmlFor="workflow-subject">Subject (optional)</Label>
            <Input
              id="workflow-subject"
              value={form.subject}
              onChange={(e) => setForm({ ...form, subject: e.target.value })}
              placeholder="Model X"
            />
          </div>

          <div className="stack-2">
            <Label htmlFor="workflow-description">Description</Label>
            <Textarea
              id="workflow-description"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              placeholder="Workflow purpose narrative."
              required
            />
          </div>

          <div className="stack-3">
            <span className="text-sm font-medium leading-none">Steps</span>
            <ul className="reset stack-2">
              {steps.map((step, idx) => (
                <li key={idx} className="reset">
                  <div className="row gap-2 wrap" aria-label={`Step ${idx + 1}`}>
                    <Input
                      aria-label={`Step ${idx + 1} name`}
                      value={step.name}
                      onChange={(e) => updateStep(idx, { name: e.target.value })}
                      placeholder="Step name (e.g. MRM 2nd-line review)"
                      style={{ flex: "1 1 14rem" }}
                    />
                    <Input
                      aria-label={`Step ${idx + 1} required role`}
                      value={step.required_role}
                      onChange={(e) =>
                        updateStep(idx, { required_role: e.target.value })
                      }
                      placeholder="Required role"
                      style={{ flex: "1 1 10rem" }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={steps.length === 1}
                      onClick={() =>
                        setSteps((prev) => prev.filter((_, i) => i !== idx))
                      }
                    >
                      Remove
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
            <div className="row-end">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  setSteps((prev) => [...prev, { name: "", required_role: "" }])
                }
              >
                Add step
              </Button>
            </div>
          </div>

          <div className="row-between border-t pt-4">
            <p className="text-xs muted">
              At least one fully-filled step is required.
            </p>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Running..." : "Run workflow"}
            </Button>
          </div>
        </form>

        {mutation.isError && (
          <Alert variant="destructive" className="mt-4">
            <AlertTitle>Could not run workflow</AlertTitle>
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

// ════════════════════════════════════════════════════════════════════════
// Lines of Defense
// ════════════════════════════════════════════════════════════════════════

type OwnerDraft = {
  email: string;
  line_of_defense: LineOfDefense;
  team: string;
  title: string;
};

const EMPTY_OWNER: OwnerDraft = {
  email: "",
  line_of_defense: "first",
  team: "",
  title: "",
};

function LinesTab() {
  const [owners, setOwners] = useState<OwnerDraft[]>([{ ...EMPTY_OWNER }]);
  const [report, setReport] = useState<string | null>(null);

  const reportMutation = useMutation({
    mutationFn: (payload: Owner[]) => api.linesReport(payload),
    onSuccess: (md) => setReport(md),
  });

  const validOwners = owners.filter((o) => o.email.trim().length > 0);
  const canGenerate = validOwners.length > 0 && !reportMutation.isPending;

  const updateOwner = (idx: number, patch: Partial<OwnerDraft>) =>
    setOwners((prev) =>
      prev.map((o, i) => (i === idx ? { ...o, ...patch } : o)),
    );

  const generate = () => {
    if (!canGenerate) return;
    reportMutation.mutate(
      validOwners.map((o) => ({
        email: o.email.trim(),
        line_of_defense: o.line_of_defense,
        team: o.team.trim() ? o.team.trim() : null,
        title: o.title.trim() ? o.title.trim() : null,
      })),
    );
  };

  return (
    <div className="stack-6">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Three lines of defense</CardTitle>
          <CardDescription>
            Build an owner roster across the IIA three lines, then generate the
            coverage report (rendered as plain text).
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-5">
          <ul className="reset stack-3" aria-label="Owner roster">
            {owners.map((owner, idx) => (
              <li key={idx} className="reset">
                <div className="stack-3 box">
                  <div className="row gap-2 wrap">
                    <Input
                      aria-label={`Owner ${idx + 1} email`}
                      value={owner.email}
                      onChange={(e) =>
                        updateOwner(idx, { email: e.target.value })
                      }
                      placeholder="owner@example.com"
                      style={{ flex: "1 1 14rem" }}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={owners.length === 1}
                      onClick={() =>
                        setOwners((prev) => prev.filter((_, i) => i !== idx))
                      }
                    >
                      Remove
                    </Button>
                  </div>

                  <div className="row gap-2 wrap">
                    <Input
                      aria-label={`Owner ${idx + 1} team`}
                      value={owner.team}
                      onChange={(e) =>
                        updateOwner(idx, { team: e.target.value })
                      }
                      placeholder="Team (optional, e.g. MRM)"
                      style={{ flex: "1 1 10rem" }}
                    />
                    <Input
                      aria-label={`Owner ${idx + 1} title`}
                      value={owner.title}
                      onChange={(e) =>
                        updateOwner(idx, { title: e.target.value })
                      }
                      placeholder="Title (optional)"
                      style={{ flex: "1 1 10rem" }}
                    />
                  </div>

                  <div
                    className="row wrap gap-2"
                    role="radiogroup"
                    aria-label={`Owner ${idx + 1} line of defense`}
                  >
                    {LOD_PICKER_OPTIONS.map(([value, label]) => (
                      <button
                        key={value}
                        type="button"
                        role="radio"
                        aria-checked={owner.line_of_defense === value}
                        onClick={() =>
                          updateOwner(idx, { line_of_defense: value })
                        }
                        className={cn(
                          "pill",
                          owner.line_of_defense === value && "on",
                        )}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              </li>
            ))}
          </ul>

          <div className="row-between gap-2 wrap">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setOwners((prev) => [...prev, { ...EMPTY_OWNER }])}
            >
              Add owner
            </Button>
            <Button type="button" disabled={!canGenerate} onClick={generate}>
              {reportMutation.isPending
                ? "Generating..."
                : "Generate report"}
            </Button>
          </div>

          {reportMutation.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not generate report</AlertTitle>
              <AlertDescription>
                {reportMutation.error instanceof ApiError &&
                reportMutation.error.payload
                  ? JSON.stringify(reportMutation.error.payload)
                  : String(reportMutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {report !== null && (
            <div className="stack-2">
              <div className="row-between gap-4 wrap">
                <h3 className="section-num">Lines-of-defense report</h3>
                <span className="text-xs faint">
                  {LOD_LABELS[validOwners[0]?.line_of_defense ?? "first"]}{" "}
                  &amp; more
                </span>
              </div>
              <pre
                className="mono text-xs box"
                style={{ whiteSpace: "pre-wrap", overflowX: "auto" }}
              >
                {report}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
