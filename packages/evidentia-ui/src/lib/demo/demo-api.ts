/**
 * Fixtures-backed implementation of the `api` client (Task B2).
 *
 * In a `VITE_DEMO=true` build, `api.ts` swaps the real fetch-based client for
 * this object so the static demo GUI runs with **zero network**: every method
 * resolves straight from `fixtures.ts` (the Meridian v2 hero dataset). Method
 * names and signatures mirror the real `api` object one-for-one so the routes /
 * hooks are none the wiser. The two SSE routes (Explain, RiskGenerate) drive
 * `simulateSse` to replay a baked stream instead of opening an EventSource.
 *
 * Mutating verbs (`putConfig`, `createVendor`, `replacePoamItem`, …) echo their
 * input back (or return the relevant fixture) so the UI's optimistic flows
 * resolve without a backend; nothing is persisted across a reload.
 */

import type {
  ConmonCadence,
  FrameworkListResponse,
  GapReportListResponse,
  GapReportMeta,
  PoamListResponse,
  VendorListResponse,
  Vendor,
  VendorInput,
  PoamItemInput,
  MilestoneUpdatePayload,
  GapExportResult,
  GapExportFormat,
  ChallengeListResponse,
  EffectiveChallenge,
  Metric,
  MetricWithStatus,
  MetricObservationPayload,
  MetricListResponse,
  Workflow,
  WorkflowInput,
  WorkflowAdvancePayload,
  WorkflowListResponse,
  Owner,
  RetentionCreatePayload,
  RetentionMetadata,
  RetentionExtendPayload,
  RetentionTransitionPayload,
  RetentionListResponse,
  EvidenceArtifact,
  EvidenceArtifactInput,
  EvidenceSaveSummary,
  EvidenceHistoryResponse,
} from "@/lib/api";
import type {
  AirGapCheckResponse,
  ControlGap,
  GapAnalysisReport,
  GapDiff,
  HealthResponse,
  InitWizardRequest,
  InitWizardResponse,
  LlmStatusResponse,
  VersionResponse,
} from "@/types/api";
import type { CatalogControl, ControlCatalog } from "@/types/catalog";
import type { EvidentiaConfig } from "@/types/config";

import {
  DEMO_AIRGAP,
  DEMO_CONFIG,
  DEMO_CONMON,
  DEMO_FRAMEWORKS,
  DEMO_GAP_DIFF,
  DEMO_GAP_REPORT,
  DEMO_GAP_REPORT_PR,
  DEMO_GAPS,
  DEMO_HEALTH,
  DEMO_LLM_STATUS,
  DEMO_POAM,
  DEMO_REPORT_LIST,
  DEMO_VENDORS,
  DEMO_VERSION,
} from "./fixtures";

/** Clone helper so callers can never mutate the shared fixture objects. */
function clone<T>(value: T): T {
  return structuredClone(value);
}

/** Resolve a gap report by its store key (baseline or pr-branch). */
function reportForKey(key: string): GapAnalysisReport {
  return key.endsWith(":pr-branch")
    ? clone(DEMO_GAP_REPORT_PR)
    : clone(DEMO_GAP_REPORT);
}

/**
 * Replay a baked SSE stream. Awaits a short delay between events (so progress
 * bars actually animate) then invokes `onEvent` for each frame — the same
 * callback contract the real pages' `readSse` loop uses, minus the network.
 *
 * `signal` mirrors how the real reader honors a Cancel button: once the
 * caller's `AbortController` fires we stop emitting immediately and do NOT
 * deliver any remaining frames — crucially including the terminal `done`
 * frame, which would otherwise re-set the page's streaming state and undo
 * the cancel. Aborting is silent (no throw): a cancelled demo stream simply
 * stops, matching the caller's `AbortError`-swallowing try/catch.
 */
export async function simulateSse<T>(
  events: T[],
  onEvent: (event: T) => void,
  gapMs = 25,
  signal?: AbortSignal,
): Promise<void> {
  for (const event of events) {
    if (signal?.aborted) return;
    await new Promise((resolve) => setTimeout(resolve, gapMs));
    if (signal?.aborted) return;
    onEvent(event);
  }
}

/**
 * A single bundled framework rendered as a (minimal) `ControlCatalog` from the
 * demo gap rows — enough for the catalog routes to render without a backend.
 */
function catalogForFramework(frameworkId: string): ControlCatalog {
  const entry = DEMO_FRAMEWORKS.frameworks.find((f) => f.id === frameworkId);
  const controls = DEMO_GAPS.filter((g) => g.framework === frameworkId).map(
    controlFromGap,
  );
  return {
    framework_id: frameworkId,
    framework_name: entry?.name ?? frameworkId,
    version: entry?.version ?? "n/a",
    source: "bundled",
    controls,
    families: [
      ...new Set(controls.map((c) => c.family).filter((f): f is string => !!f)),
    ],
    family_hierarchy: null,
    category: "control",
    tier: entry?.tier ?? null,
    license_required: entry?.license_required === "true",
    license_terms: null,
    license_url: null,
    placeholder: entry?.placeholder === "true",
  };
}

/** Project a demo `ControlGap` row into a (minimal) `CatalogControl`. */
function controlFromGap(gap: ControlGap): CatalogControl {
  return {
    id: gap.control_id,
    title: gap.control_title,
    description: gap.control_description,
    family: gap.control_family,
    baseline_impact: [],
    enhancements: [],
    related_controls: gap.cross_framework_value,
    assessment_objectives: [],
    examples: [],
    parameters: {},
    license_required: false,
    placeholder: false,
  };
}

// ── Demo fixtures for the governance / retention / evidence surfaces ──────
//
// Small inline hero datasets (a couple of rows each) so the demo GUI renders
// these screens with zero network. Mutating verbs echo their input; deletes
// resolve void; the four report verbs return a short baked markdown string.

const DEMO_CHALLENGES: EffectiveChallenge[] = [
  {
    id: "demo-chal-1",
    subject_model_id: "demo-model-credit-v3",
    challenger_email: "mrm.director@meridian.example",
    challenger_role: "MRM Director",
    challenge_date: "2026-03-12",
    challenge_topic: "Methodology — feature selection rationale",
    challenge_substance:
      "Questioned whether the income-proxy feature introduces fair-lending risk absent a documented disparate-impact test.",
    outcome: "modify",
    outcome_rationale:
      "Owner agreed to add a quarterly disparate-impact monitor before next validation.",
    response: "Disparate-impact monitor scheduled for Q2; tracked in POA&M.",
    resolved_at: null,
  },
  {
    id: "demo-chal-2",
    subject_model_id: "demo-model-fraud-v1",
    challenger_email: "audit.senior@meridian.example",
    challenger_role: "Internal Audit Senior",
    challenge_date: "2026-04-02",
    challenge_topic: "Data quality — training-set drift",
    challenge_substance:
      "Raised that the training set predates the 2026 product launch and may not represent current transaction patterns.",
    outcome: "accepted",
    outcome_rationale: "Retraining cadence accelerated to monthly.",
    response: "Retraining job re-pointed at the rolling 90-day window.",
    resolved_at: "2026-04-20",
  },
];

const DEMO_METRICS: MetricWithStatus[] = [
  {
    id: "demo-metric-1",
    name: "Failed-login rate",
    description:
      "Failed-login attempts per 1,000 successful logins (account-takeover KRI).",
    kind: "kri",
    direction: "higher_is_worse",
    unit: "per 1,000 logins",
    warning_threshold: 5,
    critical_threshold: 12,
    observations: [
      { observed_at: "2026-04-01", value: 3.1, note: null },
      { observed_at: "2026-05-01", value: 6.4, note: "Q2 backlog spike" },
    ],
    status: "watch",
  },
  {
    id: "demo-metric-2",
    name: "Control-coverage ratio",
    description: "Fraction of in-scope controls with passing evidence (KPI).",
    kind: "kpi",
    direction: "higher_is_better",
    unit: "%",
    warning_threshold: 90,
    critical_threshold: 80,
    observations: [{ observed_at: "2026-05-01", value: 94, note: null }],
    status: "ok",
  },
];

const DEMO_WORKFLOWS: Workflow[] = [
  {
    id: "demo-wf-1",
    name: "Credit-model-v3 quarterly review 2026-Q2",
    description: "SR 11-7 quarterly review for the credit decisioning model.",
    initiator: "mrm.lead@meridian.example",
    subject: "demo-model-credit-v3",
    template: "sr-11-7-quarterly",
    status: "in_progress",
    steps: [
      {
        name: "1st-line self-attestation",
        required_role: "first",
        status: "approved",
        sla_days: 5,
        history: [],
      },
      {
        name: "2nd-line MRM review",
        required_role: "second",
        status: "in_progress",
        sla_days: 10,
        history: [],
      },
    ],
  },
];

const DEMO_RETENTION: RetentionMetadata[] = [
  {
    id: "demo-ret-1",
    classification: "sec-17a-4",
    retention_period_days: 2555,
    legal_hold: false,
    lifecycle_stage: "active",
    lock_until: "2033-01-01",
    record_pointer: "s3://meridian-evidence/2026/audit-log.jsonl",
    policy_name: "broker-dealer-books-and-records",
    notes: "WORM-mirrored to the compliance bucket.",
  },
  {
    id: "demo-ret-2",
    classification: "model-risk",
    retention_period_days: 1825,
    legal_hold: true,
    lifecycle_stage: "preserved",
    lock_until: "2031-04-20",
    record_pointer: "file:///evidence/model-validation-credit-v3.pdf",
    policy_name: null,
    notes: "Under legal hold pending regulatory inquiry.",
  },
];

const DEMO_EVIDENCE: EvidenceArtifact[] = [
  {
    id: "demo-ev-v1",
    lineage_id: "demo-lineage-1",
    version: 1,
    predecessor_id: null,
    title: "S3 bucket encryption snapshot",
    collected_by: "aws-collector",
    content_format: "json",
    content_hash:
      "0000000000000000000000000000000000000000000000000000000000000000",
  } as EvidenceArtifact,
  {
    id: "demo-ev-v2",
    lineage_id: "demo-lineage-1",
    version: 2,
    predecessor_id: "demo-ev-v1",
    title: "S3 bucket encryption snapshot (re-collected)",
    collected_by: "aws-collector",
    content_format: "json",
    content_hash:
      "1111111111111111111111111111111111111111111111111111111111111111",
  } as EvidenceArtifact,
];

const DEMO_REPORT_MARKDOWN =
  "# Demo Report\n\nThis is baked demo markdown — the live build streams a real " +
  "report from the API. No backend is contacted in the demo GUI.\n";

export const demoApi = {
  // ── Probe / identity ──────────────────────────────────────────────────
  health: (): Promise<HealthResponse> => Promise.resolve(clone(DEMO_HEALTH)),
  version: (): Promise<VersionResponse> => Promise.resolve(clone(DEMO_VERSION)),
  llmStatus: (): Promise<LlmStatusResponse> =>
    Promise.resolve(clone(DEMO_LLM_STATUS)),

  // ── Doctor / air-gap ──────────────────────────────────────────────────
  doctor: (): Promise<{
    subsystems: Array<{ name: string; status: string; detail: string }>;
  }> =>
    Promise.resolve({
      subsystems: DEMO_AIRGAP.checks.map((c) => ({
        name: c.subsystem,
        status: c.status === "ok" ? "ok" : "warn",
        detail: c.detail,
      })),
    }),
  doctorCheckAirGap: (): Promise<AirGapCheckResponse> =>
    Promise.resolve(clone(DEMO_AIRGAP)),

  // ── Config ────────────────────────────────────────────────────────────
  getConfig: (): Promise<EvidentiaConfig> =>
    Promise.resolve(clone(DEMO_CONFIG)),
  putConfig: (cfg: EvidentiaConfig): Promise<EvidentiaConfig> =>
    Promise.resolve(clone(cfg)),

  // ── Frameworks ────────────────────────────────────────────────────────
  listFrameworks: (params?: {
    tier?: string;
    category?: string;
  }): Promise<FrameworkListResponse> => {
    let frameworks = DEMO_FRAMEWORKS.frameworks;
    if (params?.tier)
      frameworks = frameworks.filter((f) => f.tier === params.tier);
    if (params?.category)
      frameworks = frameworks.filter((f) => f.category === params.category);
    return Promise.resolve({
      total: frameworks.length,
      frameworks: clone(frameworks),
    });
  },
  getFramework: (id: string): Promise<ControlCatalog> =>
    Promise.resolve(catalogForFramework(id)),
  getControl: (
    frameworkId: string,
    controlId: string,
  ): Promise<CatalogControl> => {
    const gap = DEMO_GAPS.find(
      (g) => g.framework === frameworkId && g.control_id === controlId,
    );
    return Promise.resolve(
      gap
        ? controlFromGap(gap)
        : {
            id: controlId,
            title: controlId,
            description:
              "[Licensed content — see license_url for authoritative text.]",
            family: null,
            baseline_impact: [],
            enhancements: [],
            related_controls: [],
            assessment_objectives: [],
            examples: [],
            parameters: {},
            license_required: false,
            placeholder: false,
          },
    );
  },

  // ── Gaps ──────────────────────────────────────────────────────────────
  listGapReports: (): Promise<GapReportListResponse> =>
    Promise.resolve(clone(DEMO_REPORT_LIST)),
  getGapReport: (key: string): Promise<GapAnalysisReport> =>
    Promise.resolve(reportForKey(key)),
  gapDiff: (_baseKey: string, _headKey: string): Promise<GapDiff> =>
    Promise.resolve(clone(DEMO_GAP_DIFF)),

  // ── Init wizard ───────────────────────────────────────────────────────
  initWizard: (payload: InitWizardRequest): Promise<InitWizardResponse> =>
    Promise.resolve({
      evidentia_yaml: `organization: ${payload.organization}\nframeworks:\n  - nist-800-53-rev5-moderate\n  - soc2-tsc\n`,
      my_controls_yaml: "controls: []\n",
      system_context_yaml: `system_name: ${payload.system_name ?? payload.organization}\n`,
      recommended_frameworks: ["nist-800-53-rev5-moderate", "soc2-tsc"],
    }),

  // ── POA&M ─────────────────────────────────────────────────────────────
  listPoamItems: (params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    status?: string;
    owner?: string;
    reviewer?: string;
  }): Promise<PoamListResponse> => {
    let items = DEMO_POAM.items;
    if (params?.severity)
      items = items.filter((i) => i.gap_severity === params.severity);
    if (params?.status) items = items.filter((i) => i.status === params.status);
    if (params?.owner)
      items = items.filter((i) => i.assigned_to === params.owner);
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit;
    const page =
      limit != null ? items.slice(skip, skip + limit) : items.slice(skip);
    return Promise.resolve({ total, items: clone(page) });
  },
  getPoamItem: (poamId: string): Promise<ControlGap> => {
    const item =
      DEMO_POAM.items.find((i) => i.id === poamId) ?? DEMO_POAM.items[0];
    return Promise.resolve(clone(item));
  },
  replacePoamItem: (poamId: string, item: PoamItemInput): Promise<ControlGap> =>
    Promise.resolve({
      ...clone(DEMO_POAM.items[0]),
      ...clone(item),
      id: poamId,
    }),
  updatePoamMilestone: (
    poamId: string,
    _milestoneId: string,
    _payload: MilestoneUpdatePayload,
  ): Promise<ControlGap> => {
    const item =
      DEMO_POAM.items.find((i) => i.id === poamId) ?? DEMO_POAM.items[0];
    return Promise.resolve(clone(item));
  },

  // ── TPRM ──────────────────────────────────────────────────────────────
  listVendors: (params?: {
    skip?: number;
    limit?: number;
    criticality_tier?: string;
    type?: string;
  }): Promise<VendorListResponse> => {
    let vendors = DEMO_VENDORS.vendors;
    if (params?.criticality_tier)
      vendors = vendors.filter(
        (v) => v.criticality_tier === params.criticality_tier,
      );
    if (params?.type) vendors = vendors.filter((v) => v.type === params.type);
    const total = vendors.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit;
    const page =
      limit != null ? vendors.slice(skip, skip + limit) : vendors.slice(skip);
    return Promise.resolve({ total, vendors: clone(page) });
  },
  createVendor: (vendor: VendorInput): Promise<Vendor> =>
    Promise.resolve({
      ...clone(DEMO_VENDORS.vendors[0]),
      ...clone(vendor),
      id: `demo-vendor-${Date.now()}`,
    } as Vendor),

  // ── ConMon ────────────────────────────────────────────────────────────
  listConmonCadences: (params?: {
    framework?: string;
  }): Promise<ConmonCadence[]> => {
    let cadences = DEMO_CONMON;
    if (params?.framework)
      cadences = cadences.filter((c) => c.framework === params.framework);
    return Promise.resolve(clone(cadences));
  },

  // ── Governance: challenges ────────────────────────────────────────────
  listChallenges: (params?: {
    skip?: number;
    limit?: number;
    subject_model_id?: string;
    outcome?: string;
  }): Promise<ChallengeListResponse> => {
    let items = DEMO_CHALLENGES;
    if (params?.subject_model_id)
      items = items.filter(
        (c) => c.subject_model_id === params.subject_model_id,
      );
    if (params?.outcome)
      items = items.filter((c) => c.outcome === params.outcome);
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit ?? total;
    const page = items.slice(skip, skip + limit);
    return Promise.resolve({ total, skip, limit, items: clone(page) });
  },
  createChallenge: (challenge: EffectiveChallenge): Promise<EffectiveChallenge> =>
    Promise.resolve({
      ...clone(challenge),
      id: `demo-chal-${Date.now()}`,
    }),
  getChallenge: (challengeId: string): Promise<EffectiveChallenge> => {
    const item =
      DEMO_CHALLENGES.find((c) => c.id === challengeId) ?? DEMO_CHALLENGES[0];
    return Promise.resolve(clone(item));
  },

  // ── Governance: metrics ───────────────────────────────────────────────
  listMetrics: (params?: {
    skip?: number;
    limit?: number;
    kind?: string;
  }): Promise<MetricListResponse> => {
    let items = DEMO_METRICS;
    if (params?.kind) items = items.filter((m) => m.kind === params.kind);
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit ?? total;
    const page = items.slice(skip, skip + limit);
    return Promise.resolve({ total, skip, limit, items: clone(page) });
  },
  createMetric: (metric: Metric): Promise<MetricWithStatus> =>
    Promise.resolve({
      ...clone(metric),
      id: `demo-metric-${Date.now()}`,
      status: "ok",
    }),
  observeMetric: (
    metricId: string,
    payload: MetricObservationPayload,
  ): Promise<MetricWithStatus> => {
    const base = DEMO_METRICS.find((m) => m.id === metricId) ?? DEMO_METRICS[0];
    const item = clone(base);
    item.observations = [
      ...(item.observations ?? []),
      {
        observed_at: payload.observed_at,
        value: payload.value,
        note: payload.note ?? null,
      },
    ];
    return Promise.resolve(item);
  },
  getMetric: (metricId: string): Promise<MetricWithStatus> => {
    const item = DEMO_METRICS.find((m) => m.id === metricId) ?? DEMO_METRICS[0];
    return Promise.resolve(clone(item));
  },
  deleteMetric: (_metricId: string): Promise<void> => Promise.resolve(),
  metricsReport: (): Promise<string> => Promise.resolve(DEMO_REPORT_MARKDOWN),

  // ── Governance: workflows ─────────────────────────────────────────────
  listWorkflows: (params?: {
    skip?: number;
    limit?: number;
  }): Promise<WorkflowListResponse> => {
    const items = DEMO_WORKFLOWS;
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit ?? total;
    const page = items.slice(skip, skip + limit);
    return Promise.resolve({ total, skip, limit, items: clone(page) });
  },
  runWorkflow: (workflow: WorkflowInput): Promise<Workflow> =>
    Promise.resolve({
      ...clone(DEMO_WORKFLOWS[0]),
      ...clone(workflow),
      id: `demo-wf-${Date.now()}`,
    } as Workflow),
  advanceWorkflow: (
    workflowId: string,
    _payload: WorkflowAdvancePayload,
  ): Promise<Workflow> => {
    const item =
      DEMO_WORKFLOWS.find((w) => w.id === workflowId) ?? DEMO_WORKFLOWS[0];
    return Promise.resolve(clone(item));
  },
  getWorkflow: (workflowId: string): Promise<Workflow> => {
    const item =
      DEMO_WORKFLOWS.find((w) => w.id === workflowId) ?? DEMO_WORKFLOWS[0];
    return Promise.resolve(clone(item));
  },
  workflowLog: (_workflowId: string): Promise<string> =>
    Promise.resolve(DEMO_REPORT_MARKDOWN),
  deleteWorkflow: (_workflowId: string): Promise<void> => Promise.resolve(),

  // ── Governance: three-lines report ────────────────────────────────────
  linesReport: (_owners: Owner[]): Promise<string> =>
    Promise.resolve(DEMO_REPORT_MARKDOWN),

  // ── Retention ─────────────────────────────────────────────────────────
  listRetention: (params?: {
    skip?: number;
    limit?: number;
    classification?: string;
    lifecycle?: string;
  }): Promise<RetentionListResponse> => {
    let items = DEMO_RETENTION;
    if (params?.classification)
      items = items.filter((r) => r.classification === params.classification);
    if (params?.lifecycle)
      items = items.filter((r) => r.lifecycle_stage === params.lifecycle);
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit ?? total;
    const page = items.slice(skip, skip + limit);
    return Promise.resolve({ total, skip, limit, items: clone(page) });
  },
  createRetention: (payload: RetentionCreatePayload): Promise<RetentionMetadata> =>
    Promise.resolve({
      ...clone(DEMO_RETENTION[0]),
      ...clone(payload),
      retention_period_days: payload.retention_period_days ?? 2555,
      id: `demo-ret-${Date.now()}`,
    } as RetentionMetadata),
  getRetention: (retentionId: string): Promise<RetentionMetadata> => {
    const item =
      DEMO_RETENTION.find((r) => r.id === retentionId) ?? DEMO_RETENTION[0];
    return Promise.resolve(clone(item));
  },
  extendRetention: (
    retentionId: string,
    payload: RetentionExtendPayload,
  ): Promise<RetentionMetadata> => {
    const base =
      DEMO_RETENTION.find((r) => r.id === retentionId) ?? DEMO_RETENTION[0];
    return Promise.resolve({
      ...clone(base),
      lock_until: payload.new_lock_until,
    });
  },
  transitionRetention: (
    retentionId: string,
    payload: RetentionTransitionPayload,
  ): Promise<RetentionMetadata> => {
    const base =
      DEMO_RETENTION.find((r) => r.id === retentionId) ?? DEMO_RETENTION[0];
    return Promise.resolve({
      ...clone(base),
      lifecycle_stage: payload.new_stage,
    });
  },
  deleteRetention: (_retentionId: string): Promise<void> => Promise.resolve(),
  retentionReport: (): Promise<string> => Promise.resolve(DEMO_REPORT_MARKDOWN),

  // ── Evidence (lineage / versions) ─────────────────────────────────────
  saveEvidence: (
    artifact: EvidenceArtifactInput,
  ): Promise<EvidenceSaveSummary> =>
    Promise.resolve({
      artifact_id: `demo-ev-${Date.now()}`,
      // Lineage continues the demo chain when the input names it; otherwise
      // a fresh synthetic lineage. (artifact.lineage_id is echoed when set.)
      lineage_id: artifact.lineage_id ?? "demo-lineage-1",
      version: DEMO_EVIDENCE.length + 1,
      predecessor_id: DEMO_EVIDENCE[DEMO_EVIDENCE.length - 1]?.id ?? null,
    }),
  evidenceHistory: (lineageId: string): Promise<EvidenceHistoryResponse> => {
    const items = DEMO_EVIDENCE.filter((e) => e.lineage_id === lineageId);
    const chain = items.length > 0 ? items : DEMO_EVIDENCE;
    return Promise.resolve({ total: chain.length, items: clone(chain) });
  },
  evidenceVersion: (
    lineageId: string,
    version: number,
  ): Promise<EvidenceArtifact> => {
    const item =
      DEMO_EVIDENCE.find(
        (e) => e.lineage_id === lineageId && e.version === version,
      ) ?? DEMO_EVIDENCE[0];
    return Promise.resolve(clone(item));
  },

  // ── Explain ───────────────────────────────────────────────────────────
  // Mirrors the real client: only builds the canonical URL. The SSE branch
  // lives in `ExplainPage` (Task B3), where `IS_DEMO` routes to `simulateSse`.
  explainControlUrl: (
    framework: string,
    controlId: string,
    params?: { refresh?: boolean; model?: string },
  ): string => {
    const search = new URLSearchParams();
    if (params?.refresh) search.set("refresh", "true");
    if (params?.model) search.set("model", params.model);
    const qs = search.toString();
    return `/api/explain/${encodeURIComponent(framework)}/${encodeURIComponent(
      controlId,
    )}${qs ? `?${qs}` : ""}`;
  },
};

/**
 * Demo replacement for `exportGapReport` — serializes the report to a JSON
 * `Blob` in-browser (no `/api/gap/export` round-trip). Only the `json` format
 * is materialized; other formats fall back to the JSON body so the download
 * still succeeds offline.
 */
export function demoExportGapReport(
  report: GapAnalysisReport,
  format: GapExportFormat,
): Promise<GapExportResult> {
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const ext = format === "json" ? "json" : "txt";
  return Promise.resolve({ blob, filename: `gap-report.${ext}` });
}

/** Minimal report-meta accessor kept for symmetry with the real list shape. */
export const DEMO_REPORT_KEYS: ReadonlyArray<GapReportMeta["key"]> =
  DEMO_REPORT_LIST.reports.map((r) => r.key);
