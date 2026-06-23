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
  ModelInventory,
  ModelInventoryInput,
  ModelListResponse,
  CatalogImportPayload,
  CatalogCrosswalkResponse,
  ConcentrationReport,
  Questionnaire,
  DDQuestionnaireIngestResult,
  MilestoneCreatePayload,
  RiskQuantifyRequest,
  RiskQuantifyResponse,
  ConmonNextRequest,
  ConmonNextResponse,
  ConmonCheckRequest,
  ConmonCheckResponse,
  ConmonHealthRequest,
  ConmonMarkCompletedRequest,
  ConmonMarkCompletedResponse,
  AISystemDescriptor,
  AISystemClassification,
  AISystemRegisterRequest,
  AISystemUpdateRequest,
  AISystemEntry,
  FIPS199CategorizeRequest,
  OMBImpactRequest,
  HighImpactRequest,
  OscalVerifyRequest,
  TraceabilityMatrix,
  SecurityFinding,
  OcsfCollectRequest,
} from "@/lib/api";
import type {
  AirGapCheckResponse,
  ControlGap,
  GapAnalysisReport,
  GapDiff,
  HealthResponse,
  InitWizardCommitRequest,
  InitWizardCommitResponse,
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

// Model-risk inventory: a couple of SR 11-7-style rows so the model-risk
// screens render with zero network. Cast through `unknown` because the demo
// rows carry only the required fields, not the full optional surface.
const DEMO_MODELS: ModelInventory[] = [
  {
    id: "demo-model-credit-v3",
    name: "Credit decisioning model v3",
    owner: "mrm.lead@meridian.example",
    purpose: "Consumer-credit underwriting score.",
    methodology: "ml",
    tier: "tier_1",
    vendor_or_internal: "internal",
  } as unknown as ModelInventory,
  {
    id: "demo-model-fraud-v1",
    name: "Transaction-fraud model v1",
    owner: "fraud.ds@meridian.example",
    purpose: "Real-time card-fraud detection.",
    methodology: "hybrid",
    tier: "tier_2",
    vendor_or_internal: "vendor",
  } as unknown as ModelInventory,
];

const DEMO_REPORT_MARKDOWN =
  "# Demo Report\n\nThis is baked demo markdown — the live build streams a real " +
  "report from the API. No backend is contacted in the demo GUI.\n";

// Baked markdown for the model-risk documentation / validation-report verbs.
const DEMO_MODEL_DOC_MARKDOWN =
  "# Model documentation (demo)\n\nBaked demo markdown — the live build renders " +
  "the model's real documentation card. No backend is contacted in the demo GUI.\n";

// Minimal baked crosswalk so the catalog crosswalk screen renders offline.
const DEMO_CROSSWALK: CatalogCrosswalkResponse = {
  source: "nist-800-53-rev5-moderate",
  target: "soc2-tsc",
  control: "AC-2",
  total: 1,
  mappings: [
    {
      source_control: "AC-2",
      target_control: "CC6.1",
      relationship: "equivalent",
    },
  ],
};

// Baked vendor-concentration report (cast: demo carries only the required field).
const DEMO_CONCENTRATION: ConcentrationReport = {
  total_vendors: 3,
} as unknown as ConcentrationReport;

// Baked due-diligence questionnaire (cast: demo carries the required fields only).
const DEMO_QUESTIONNAIRE: Questionnaire = {
  title: "Vendor due-diligence questionnaire (demo)",
  format: "json",
  vendor: { name: "Demo Vendor" },
} as unknown as Questionnaire;

// ── AI-governance demo fixtures ──────────────────────────────────────────
//
// A couple of registered AI systems (free-form `AISystemEntry` objects, the
// same loose shape the registry endpoints return) so the ai-gov screens render
// with zero network. `eu_ai_act_tier` lets the `tier` filter exercise.
const DEMO_AI_SYSTEMS: AISystemEntry[] = [
  {
    id: "demo-ai-credit-adjudicator",
    name: "Credit adjudication assistant",
    purpose: "Recommends consumer-credit decisions for human review.",
    owner: "ai.gov.lead@meridian.example",
    provider: "Meridian (internal)",
    deployment_status: "production",
    eu_ai_act_tier: "high",
    omb_high_impact: {
      determination: "high_impact",
      bases: ["civil_rights_liberties_privacy", "essential_services_access"],
      rationale:
        "Adjudicates access to an essential service (consumer credit).",
    },
  },
  {
    id: "demo-ai-chat-helpdesk",
    name: "Internal IT helpdesk chatbot",
    purpose: "Answers employee IT questions from a knowledge base.",
    owner: "it.ops@meridian.example",
    provider: "acme-llm-vendor",
    deployment_status: "pilot",
    eu_ai_act_tier: "minimal",
  },
];

// Baked classification verdict for the one-shot classify verb.
const DEMO_AI_CLASSIFICATION: AISystemClassification = {
  descriptor_name: "Credit adjudication assistant",
  eu_ai_act_tier: "high",
  applicable_nist_ai_rmf_functions: ["govern", "measure", "manage"],
  rationale: [
    "Influences access to an essential private service (credit) — Annex III high-risk use case.",
    "Affects natural persons' significant interests — SME review recommended before deployment.",
  ],
  disclaimer:
    "This classification is an informational starting point produced by a rule-based classifier. It is NOT a legal compliance determination.",
};

// Baked OSCAL-verify verdict (free-form object; a real verify returns a richer
// structured verdict). Demo always reports a clean PASS on the digest leg.
const DEMO_OSCAL_VERIFY: Record<string, unknown> = {
  verified: true,
  digest_check: "passed",
  signature_check: "not checked",
  sigstore_check: "skipped (offline)",
  summary: "Demo verdict — the live build runs the real chain-of-custody check.",
};

// Baked UNSIGNED OSCAL profile returned by the traceability emit verb.
const DEMO_TRACEABILITY_PROFILE: Record<string, unknown> = {
  profile: {
    uuid: "00000000-0000-0000-0000-000000000000",
    metadata: {
      title: "Control↔Threat Traceability Matrix (demo)",
      version: "0.0.0-demo",
    },
    imports: [],
  },
  metadata: {
    title: "Control↔Threat Traceability Matrix (demo)",
    signed: false,
  },
};

// ── Collector demo fixtures ──────────────────────────────────────────────
//
// A tiny baked `SecurityFinding[]` so the collect verbs resolve offline. NO
// secrets anywhere (the demo build never opens a connection); these are static
// observations mirroring what a real collector run would surface.
const DEMO_FINDINGS: SecurityFinding[] = [
  {
    title: "S3 bucket without default encryption",
    description:
      "Bucket meridian-evidence has no default server-side encryption configured.",
    severity: "high",
    source_system: "aws-config",
    status: "active",
    compliance_status: "fail",
    resource_type: "AWS::S3::Bucket",
    resource_id: "meridian-evidence",
  },
  {
    title: "MFA enforced on all admin accounts",
    description:
      "All accounts in the Administrators group require multi-factor authentication.",
    severity: "informational",
    source_system: "aws-iam",
    status: "active",
    compliance_status: "pass",
    resource_type: "AWS::IAM::Group",
    resource_id: "Administrators",
  },
];

// Baked OCSF-convert output (loose object list; the demo never runs the mapper).
const DEMO_CONVERT_OUTPUT: Record<string, unknown>[] = [
  {
    activity_id: 1,
    category_uid: 2,
    class_uid: 2003,
    metadata: { product: { name: "Evidentia (demo)" } },
    compliance: { status: "Fail" },
    finding_info: { title: "S3 bucket without default encryption" },
  },
];

// Baked collectors-status map (demo: nothing configured — no live credentials).
const DEMO_COLLECTORS_STATUS: Record<string, unknown> = {
  aws: { configured: false },
  github: { configured: false },
  okta: { configured: false },
  vanta: { configured: false },
};

// Baked integration status (demo: not configured — no server-side credentials).
const DEMO_INTEGRATION_STATUS: Record<string, unknown> = { configured: false };

// Baked push / publish / sync result for the demo integration verbs.
const DEMO_INTEGRATION_RESULT: Record<string, unknown> = {
  ok: true,
  configured: false,
  detail:
    "Demo result — the live build pushes to the configured integration. No external system is contacted in the demo GUI.",
  pushed: 0,
};

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
  initCommit: (
    _payload: InitWizardCommitRequest,
  ): Promise<InitWizardCommitResponse> =>
    // The static demo has no server filesystem; report a no-op "success" so
    // the wizard flow completes without claiming real files were written.
    Promise.resolve({
      created: ["evidentia.yaml", "my-controls.yaml", "system-context.yaml"],
      skipped: [],
      directory: "(demo — files are not written to disk)",
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
  createPoamItem: (item: PoamItemInput): Promise<ControlGap> =>
    Promise.resolve({
      ...clone(DEMO_POAM.items[0]),
      ...clone(item),
      id: `demo-poam-${Date.now()}`,
    }),
  deletePoamItem: (_poamId: string): Promise<void> => Promise.resolve(),
  poamCalendar: (_params?: {
    today?: string;
  }): Promise<Record<string, unknown>> =>
    Promise.resolve({ today: "2026-06-21", upcoming: [], overdue: [] }),
  addPoamMilestone: (
    poamId: string,
    _payload: MilestoneCreatePayload,
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
  getVendor: (vendorId: string): Promise<Vendor> => {
    const vendor =
      DEMO_VENDORS.vendors.find((v) => v.id === vendorId) ??
      DEMO_VENDORS.vendors[0];
    return Promise.resolve(clone(vendor));
  },
  updateVendor: (vendorId: string, vendor: VendorInput): Promise<Vendor> => {
    const base =
      DEMO_VENDORS.vendors.find((v) => v.id === vendorId) ??
      DEMO_VENDORS.vendors[0];
    return Promise.resolve({
      ...clone(base),
      ...clone(vendor),
      id: vendorId,
    } as Vendor);
  },
  deleteVendor: (_vendorId: string): Promise<void> => Promise.resolve(),
  tprmConcentration: (_params?: {
    by?: string;
    threshold?: number;
  }): Promise<ConcentrationReport> => Promise.resolve(clone(DEMO_CONCENTRATION)),
  ddQuestionnaireGenerate: (
    _vendorId: string,
    _params?: { format?: string },
  ): Promise<Questionnaire> => Promise.resolve(clone(DEMO_QUESTIONNAIRE)),
  ddQuestionnaireIngest: (
    vendorId: string,
    document: Questionnaire,
  ): Promise<DDQuestionnaireIngestResult> => {
    const vendor =
      DEMO_VENDORS.vendors.find((v) => v.id === vendorId) ??
      DEMO_VENDORS.vendors[0];
    // PARSE-ONLY: correlate each posted question's `vendor_response` by its
    // `id` (no mutation, mirroring the real endpoint). The demo fixture
    // questionnaire carries no `questions`, so an empty/partial doc yields
    // an empty `responses` map — exactly what the server would return.
    const questions =
      (document as { questions?: Array<{ id?: string; vendor_response?: string }> })
        .questions ?? [];
    const responses: Record<string, string> = {};
    for (const q of questions) {
      if (q?.id) responses[q.id] = q.vendor_response ?? "";
    }
    return Promise.resolve({
      vendor: { id: vendor.id ?? vendorId, name: vendor.name },
      questionnaire_id:
        (document as { id?: string | null }).id ?? null,
      format: (document as { format?: string | null }).format ?? null,
      responses,
      ingested_at: "2026-06-21T00:00:00Z",
    });
  },

  // ── ConMon ────────────────────────────────────────────────────────────
  listConmonCadences: (params?: {
    framework?: string;
  }): Promise<ConmonCadence[]> => {
    let cadences = DEMO_CONMON;
    if (params?.framework)
      cadences = cadences.filter((c) => c.framework === params.framework);
    return Promise.resolve(clone(cadences));
  },
  conmonNext: (body: ConmonNextRequest): Promise<ConmonNextResponse> =>
    Promise.resolve({
      slug: body.slug,
      framework: "soc2-tsc",
      activity: "Quarterly access review",
      frequency: "quarterly",
      last_completed: body.last_completed,
      next_due: "2026-09-30",
    }),
  conmonCheck: (body: ConmonCheckRequest): Promise<ConmonCheckResponse> =>
    Promise.resolve({
      today: "2026-06-21",
      window_days: body.window_days ?? 30,
      current: [],
      due_soon: [],
      overdue: [],
      unknown_slugs: [],
    }),
  conmonHealth: (
    _body: ConmonHealthRequest,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve({ status: "ok", overdue: 0, due_soon: 0 }),
  conmonMarkCompleted: (
    body: ConmonMarkCompletedRequest,
  ): Promise<ConmonMarkCompletedResponse> =>
    Promise.resolve({
      slug: body.slug,
      framework: "soc2-tsc",
      activity: "Quarterly access review",
      previous_last_completed: null,
      new_last_completed: body.when,
    }),
  conmonDedupList: (_params?: {
    slug?: string;
    suppression_hours?: number;
  }): Promise<Record<string, unknown>> =>
    Promise.resolve({ entries: [], suppressed: [] }),

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

  // ── Model-risk (inventory) ────────────────────────────────────────────
  listModels: (params?: {
    skip?: number;
    limit?: number;
  }): Promise<ModelListResponse> => {
    const items = DEMO_MODELS;
    const total = items.length;
    const skip = params?.skip ?? 0;
    const limit = params?.limit ?? total;
    const page = items.slice(skip, skip + limit);
    return Promise.resolve({ total, skip, limit, items: clone(page) });
  },
  createModel: (model: ModelInventoryInput): Promise<ModelInventory> =>
    Promise.resolve({
      ...clone(DEMO_MODELS[0]),
      ...clone(model),
      id: `demo-model-${Date.now()}`,
    } as ModelInventory),
  getModel: (modelId: string): Promise<ModelInventory> => {
    const item = DEMO_MODELS.find((m) => m.id === modelId) ?? DEMO_MODELS[0];
    return Promise.resolve(clone(item));
  },
  updateModel: (
    modelId: string,
    model: ModelInventoryInput,
  ): Promise<ModelInventory> => {
    const base = DEMO_MODELS.find((m) => m.id === modelId) ?? DEMO_MODELS[0];
    return Promise.resolve({
      ...clone(base),
      ...clone(model),
      id: modelId,
    } as ModelInventory);
  },
  deleteModel: (_modelId: string): Promise<void> => Promise.resolve(),
  modelDocumentation: (_modelId: string): Promise<string> =>
    Promise.resolve(DEMO_MODEL_DOC_MARKDOWN),
  modelValidationReport: (_modelId: string): Promise<string> =>
    Promise.resolve(DEMO_MODEL_DOC_MARKDOWN),

  // ── Catalog (crosswalk / where / license / import / remove) ───────────
  catalogCrosswalk: (params: {
    source: string;
    target: string;
    control: string;
  }): Promise<CatalogCrosswalkResponse> =>
    Promise.resolve({
      ...clone(DEMO_CROSSWALK),
      source: params.source,
      target: params.target,
      control: params.control,
    }),
  catalogWhere: (frameworkId: string): Promise<Record<string, unknown>> =>
    Promise.resolve({
      framework_id: frameworkId,
      source: "bundled",
      path: `bundled://${frameworkId}.yaml`,
    }),
  catalogLicenseInfo: (
    frameworkId: string,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve({
      framework_id: frameworkId,
      license_required: false,
      license_terms: null,
    }),
  catalogImport: (
    payload: CatalogImportPayload,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve({
      framework_id: payload.framework_id,
      imported: true,
      controls: 0,
    }),
  catalogRemove: (_frameworkId: string): Promise<void> => Promise.resolve(),

  // ── Risk quantification (FAIR / OpenFAIR) ─────────────────────────────
  riskQuantify: (
    _body: RiskQuantifyRequest,
  ): Promise<RiskQuantifyResponse> =>
    Promise.resolve({
      method: "open-fair",
      scenario_count: 0,
      scenarios: [],
      total_ale: 0,
    }),

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

  // ── AI governance (EU AI Act / FIPS 199 / OMB M-24-10) ────────────────
  listAiSystems: (params?: {
    skip?: number;
    limit?: number;
    tier?: string;
  }): Promise<AISystemEntry[]> => {
    let items = DEMO_AI_SYSTEMS;
    if (params?.tier)
      items = items.filter((s) => s.eu_ai_act_tier === params.tier);
    const skip = params?.skip ?? 0;
    const page =
      params?.limit != null
        ? items.slice(skip, skip + params.limit)
        : items.slice(skip);
    return Promise.resolve(clone(page));
  },
  classifyAiSystem: (
    _descriptor: AISystemDescriptor,
  ): Promise<AISystemClassification> =>
    Promise.resolve(clone(DEMO_AI_CLASSIFICATION)),
  registerAiSystem: (
    body: AISystemRegisterRequest,
  ): Promise<AISystemEntry> =>
    Promise.resolve({
      ...clone(DEMO_AI_SYSTEMS[0]),
      owner: body.owner,
      provider: body.provider,
      deployment_status: body.deployment_status,
      id: `demo-ai-${Date.now()}`,
    }),
  getAiSystem: (systemId: string): Promise<AISystemEntry> => {
    const item =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve(clone(item));
  },
  updateAiSystem: (
    systemId: string,
    body: AISystemUpdateRequest,
  ): Promise<AISystemEntry> => {
    const base =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve({ ...clone(base), ...clone(body), id: systemId });
  },
  deleteAiSystem: (_systemId: string): Promise<void> => Promise.resolve(),
  retireAiSystem: (systemId: string): Promise<AISystemEntry> => {
    const base =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve({
      ...clone(base),
      id: systemId,
      deployment_status: "retired",
    });
  },
  categorizeFipsAiSystem: (
    systemId: string,
    body: FIPS199CategorizeRequest,
  ): Promise<AISystemEntry> => {
    const base =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve({
      ...clone(base),
      id: systemId,
      fips199: clone(body),
    });
  },
  setOmbImpactAiSystem: (
    systemId: string,
    body: OMBImpactRequest,
  ): Promise<AISystemEntry> => {
    const base =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve({
      ...clone(base),
      id: systemId,
      omb_impact: clone(body),
    });
  },
  setHighImpactAiSystem: (
    systemId: string,
    body: HighImpactRequest,
  ): Promise<AISystemEntry> => {
    const base =
      DEMO_AI_SYSTEMS.find((s) => s.id === systemId) ?? DEMO_AI_SYSTEMS[0];
    return Promise.resolve({
      ...clone(base),
      id: systemId,
      omb_high_impact: clone(body),
    });
  },

  // ── OSCAL (verify) ────────────────────────────────────────────────────
  oscalVerify: (
    _body: OscalVerifyRequest,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_OSCAL_VERIFY)),

  // ── Traceability (Control↔Threat matrix → OSCAL profile) ──────────────
  traceabilityEmit: (
    matrix: TraceabilityMatrix,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve({
      ...clone(DEMO_TRACEABILITY_PROFILE),
      // Echo the supplied title into the emitted profile's metadata so the
      // demo response visibly reflects the posted matrix.
      metadata: {
        ...(DEMO_TRACEABILITY_PROFILE.metadata as Record<string, unknown>),
        title: matrix.title,
      },
    }),

  // ── Collectors (evidence collection) ──────────────────────────────────
  // Every collect verb resolves the baked `DEMO_FINDINGS` array — zero network,
  // no credentials. Signatures mirror the real client one-for-one.
  collectAws: (_body?: Record<string, unknown>): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectGithub: (_body: Record<string, unknown>): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectOkta: (_body?: Record<string, unknown>): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectSql: (
    _dialect: string,
    _body: Record<string, unknown>,
  ): Promise<SecurityFinding[]> => Promise.resolve(clone(DEMO_FINDINGS)),
  collectDatabricks: (
    _body?: Record<string, unknown>,
  ): Promise<SecurityFinding[]> => Promise.resolve(clone(DEMO_FINDINGS)),
  collectSnowflake: (
    _body?: Record<string, unknown>,
  ): Promise<SecurityFinding[]> => Promise.resolve(clone(DEMO_FINDINGS)),
  collectVanta: (_body?: Record<string, unknown>): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectDrata: (_body?: Record<string, unknown>): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectBitsight: (
    _body?: Record<string, unknown>,
  ): Promise<SecurityFinding[]> => Promise.resolve(clone(DEMO_FINDINGS)),
  collectSecurityscorecard: (
    _body?: Record<string, unknown>,
  ): Promise<SecurityFinding[]> => Promise.resolve(clone(DEMO_FINDINGS)),
  collectOcsf: (_body: OcsfCollectRequest): Promise<SecurityFinding[]> =>
    Promise.resolve(clone(DEMO_FINDINGS)),
  collectConvert: (
    _body: Record<string, unknown>,
  ): Promise<Record<string, unknown>[]> =>
    Promise.resolve(clone(DEMO_CONVERT_OUTPUT)),
  collectorsStatus: (): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_COLLECTORS_STATUS)),

  // ── Integrations (push / publish to external systems) ─────────────────
  // Status verbs return a baked {configured:false}; push / publish / sync verbs
  // return a baked result — no external system is contacted in the demo GUI.
  jiraStatus: (): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_STATUS)),
  jiraPush: (
    _reportKey: string,
    _body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_RESULT)),
  jiraSync: (
    _reportKey: string,
    _body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_RESULT)),
  jiraStatusMap: (): Promise<Record<string, Record<string, string>>> =>
    Promise.resolve({}),
  tableauPublish: (
    _reportKey: string,
    _body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_RESULT)),
  powerbiPublish: (
    _reportKey: string,
    _body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_RESULT)),
  servicenowStatus: (): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_STATUS)),
  servicenowPush: (
    _reportKey: string,
    _body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> =>
    Promise.resolve(clone(DEMO_INTEGRATION_RESULT)),
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
