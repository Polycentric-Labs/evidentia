/**
 * Typed API client for the Evidentia REST backend.
 *
 * Thin fetch wrapper returning typed data or throwing `ApiError`. All hooks
 * in @/hooks/*.ts wrap these calls with TanStack Query for caching,
 * retries, and mutation state.
 *
 * Runtime base URL: always same-origin (production ships frontend + API
 * from one uvicorn instance). Dev mode: Vite's proxy forwards /api to :8000.
 */

import { demoApi, demoExportGapReport } from "@/lib/demo/demo-api";
import { IS_DEMO } from "@/lib/demo";
import { parseContentDispositionFilename } from "@/lib/download";
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
import type { ControlCatalog, CatalogControl } from "@/types/catalog";
import type { EvidentiaConfig } from "@/types/config";
import type { components } from "@/types/openapi";

export class ApiError extends Error {
  public readonly status: number;
  public readonly payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

/**
 * Pull the human-readable message out of an API error body.
 *
 * Deliberate 4xx/5xx responses carry the structured
 * `{detail: {error, ..., message}}` shape (2026-07-06 error-shape
 * convergence — see `evidentia_api.errors`); the legacy
 * `{detail: string}` shape is still accepted for robustness. Returns
 * `undefined` for anything else (e.g. Pydantic 422 array details) so
 * callers keep their own fallback.
 */
export function extractApiErrorMessage(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object" || !("detail" in payload)) {
    return undefined;
  }
  const detail = (payload as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (
    detail &&
    typeof detail === "object" &&
    "message" in detail &&
    typeof (detail as { message: unknown }).message === "string"
  ) {
    return (detail as { message: string }).message;
  }
  return undefined;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      /* empty body is fine */
    }
    throw new ApiError(
      `API ${init?.method ?? "GET"} ${path} failed (${response.status})`,
      response.status,
      payload,
    );
  }

  if (response.status === 204) {
    return undefined as unknown as T;
  }

  return (await response.json()) as T;
}

/**
 * Like `request<T>` but for `text/markdown` (and other plain-text) endpoints —
 * returns the raw `response.text()` instead of parsing JSON. Same
 * `ApiError`-on-`!ok` handling. Used by the governance + retention report
 * endpoints (`metricsReport`, `workflowLog`, `linesReport`, `retentionReport`),
 * which the backend serves as `text/markdown`, not a JSON envelope.
 */
async function requestText(path: string, init?: RequestInit): Promise<string> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Accept: "text/markdown, text/plain, */*",
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      /* empty body is fine */
    }
    throw new ApiError(
      `API ${init?.method ?? "GET"} ${path} failed (${response.status})`,
      response.status,
      payload,
    );
  }

  return await response.text();
}

export interface FrameworkListEntry {
  id: string;
  name: string;
  version: string;
  tier: string;
  category: string;
  placeholder: string;
  license_required: string;
}

export interface FrameworkListResponse {
  total: number;
  frameworks: FrameworkListEntry[];
}

export interface GapReportMeta {
  key: string;
  mtime_iso: string;
  size_bytes: number;
  organization: string;
  frameworks_analyzed: string[];
  total_gaps: number;
  critical_gaps: number;
  coverage_percentage: number | null;
}

export interface GapReportListResponse {
  total: number;
  reports: GapReportMeta[];
  store_dir: string;
}

/**
 * Gap-report export formats supported by `POST /api/gap/export`.
 *
 * Mirrors `evidentia_core.gap_analyzer.reporter.OutputFormat` (the same
 * set the CLI's `evidentia gap analyze --format` honors). Kept in sync
 * with `GAP_EXPORT_FORMATS` in the API's `schemas.py`.
 */
export const GAP_EXPORT_FORMATS = [
  { id: "json", label: "JSON", hint: "Full report (native Evidentia schema)" },
  { id: "oscal-ar", label: "OSCAL AR", hint: "OSCAL Assessment Results" },
  { id: "sarif", label: "SARIF", hint: "SARIF 2.1.0 (code-scanning)" },
  {
    id: "ocsf",
    label: "OCSF Compliance",
    hint: "OCSF Compliance Finding (2003)",
  },
  {
    id: "ocsf-detection",
    label: "OCSF Detection",
    hint: "OCSF Detection Finding (2004, SIEM)",
  },
  { id: "cyclonedx-vex", label: "CycloneDX VEX", hint: "CycloneDX 1.6 VEX" },
  { id: "csv", label: "CSV", hint: "One row per gap" },
  { id: "markdown", label: "Markdown", hint: "Human-readable report" },
] as const;

export type GapExportFormat = (typeof GAP_EXPORT_FORMATS)[number]["id"];

export interface GapExportResult {
  blob: Blob;
  filename: string;
}

// ── POA&M types (mirrored from evidentia_core.poam) ────────────────────
//
// A POA&M item IS a `ControlGap` (see types/api.ts). The list endpoint
// returns a paginated envelope of them; detail / create / replace operate
// on the full ControlGap. Milestone state-transitions use POAMState
// ("planned" | "in_progress" | "overdue" | "completed" | "verified").

/** POA&M item — full-replace body shape (server fills id / created_at). */
export type PoamItemInput = components["schemas"]["ControlGap"];
/** Milestone PATCH body (state-transition). Backward transitions blocked. */
export type MilestoneUpdatePayload =
  components["schemas"]["MilestoneUpdatePayload"];
/** Milestone forward-only state machine. */
export type PoamState = components["schemas"]["POAMState"];

/** Paginated POA&M list envelope (response is an untyped object server-side). */
export interface PoamListResponse {
  total: number;
  items: ControlGap[];
}

// ── TPRM types (mirrored from evidentia_core.vendor_store) ──────────────

/** Vendor create body. Required: name, type, criticality_tier,
 *  relationship_owner, contract_start_date. */
export type VendorInput = components["schemas"]["Vendor"];
/** Vendor record as returned by the API. */
export type Vendor = components["schemas"]["Vendor"];
export type VendorType = components["schemas"]["VendorType"];
export type CriticalityTier = components["schemas"]["CriticalityTier"];

/** Paginated vendor list envelope (response is an untyped object server-side). */
export interface VendorListResponse {
  total: number;
  vendors: Vendor[];
}

// ── ConMon types (mirrored from evidentia_core.conmon) ──────────────────

/**
 * A bundled / registered continuous-monitoring cadence. The API returns a
 * flat list of string→(string|null) maps (read-only; no live daemon state).
 */
export type ConmonCadence = Record<string, string | null>;

// ── Governance types (mirrored from evidentia_core.governance / metrics /
//    workflows / effective_challenge_store) ──────────────────────────────

/** Effective-challenge record — body shape AND response shape (single schema). */
export type EffectiveChallenge = components["schemas"]["EffectiveChallenge"];
/** Metric create body. The server returns the Metric augmented with a derived
 *  `status` field (untyped server-side); see `MetricWithStatus`. */
export type Metric = components["schemas"]["Metric"];
/** Observation PATCH/POST body ({value, observed_at(date), note?}). */
export type MetricObservationPayload =
  components["schemas"]["MetricObservationPayload"];
/** Governance workflow — create body shape (server fills id / step state). */
export type WorkflowInput = components["schemas"]["Workflow"];
/** Governance workflow as returned by the API. */
export type Workflow = components["schemas"]["Workflow"];
/** Workflow step-advance body ({step_index, new_status, actor, note?}). */
export type WorkflowAdvancePayload =
  components["schemas"]["WorkflowAdvancePayload"];
/** Three-lines-of-defense owner row (body of POST /governance/lines-report). */
export type Owner = components["schemas"]["Owner"];

/**
 * A metric as returned by the create / get / observe endpoints: the stored
 * `Metric` plus a server-derived `status` label (ok / watch / breach). The
 * server response is an untyped dict, so this is a loose intersection.
 */
export type MetricWithStatus = Metric & { status: string };

/** Paginated challenge list envelope (response is an untyped object server-side). */
export interface ChallengeListResponse {
  total: number;
  skip: number;
  limit: number;
  items: EffectiveChallenge[];
}

/** Paginated metric list envelope. `items` carry the derived `status`. */
export interface MetricListResponse {
  total: number;
  skip: number;
  limit: number;
  items: MetricWithStatus[];
}

/** Paginated workflow list envelope (response is an untyped object server-side). */
export interface WorkflowListResponse {
  total: number;
  skip: number;
  limit: number;
  items: Workflow[];
}

// ── Retention types (mirrored from evidentia_core.retention) ─────────────

/** Retention create body ({classification, retention_period_days?, …}). */
export type RetentionCreatePayload =
  components["schemas"]["RetentionCreatePayload"];
/** Per-record retention metadata as returned by the API. */
export type RetentionMetadata = components["schemas"]["RetentionMetadata"];
/** Lock-until extension body ({new_lock_until: date}). */
export type RetentionExtendPayload =
  components["schemas"]["RetentionExtendPayload"];
/** Lifecycle-stage transition body ({new_stage}). */
export type RetentionTransitionPayload =
  components["schemas"]["RetentionTransitionPayload"];

/** Paginated retention list envelope (response is an untyped object server-side). */
export interface RetentionListResponse {
  total: number;
  skip: number;
  limit: number;
  items: RetentionMetadata[];
}

// ── Evidence types (mirrored from evidentia_core.models.evidence) ────────

/** Evidence artifact — save body shape (caller constructs new lineage/version). */
export type EvidenceArtifactInput = components["schemas"]["EvidenceArtifact"];
/** Evidence artifact as returned by the version endpoint. */
export type EvidenceArtifact = components["schemas"]["EvidenceArtifact"];

/** Summary returned by `POST /api/evidence` after persisting an artifact. */
export interface EvidenceSaveSummary {
  artifact_id: string;
  lineage_id: string;
  version: number;
  predecessor_id: string | null;
}

/** Evidence lineage history envelope (no skip/limit — full chain). */
export interface EvidenceHistoryResponse {
  total: number;
  items: EvidenceArtifact[];
}

// ── Model-risk types (mirrored from evidentia_core.model_risk) ───────────

/** Model-inventory create / update body shape (server fills id / timestamps). */
export type ModelInventoryInput = components["schemas"]["ModelInventory"];
/** Model-inventory record as returned by the API. */
export type ModelInventory = components["schemas"]["ModelInventory"];

/** Paginated model-inventory list envelope (response is an untyped object
 *  server-side; hand-typed here like the other list envelopes). */
export interface ModelListResponse {
  total: number;
  skip: number;
  limit: number;
  items: ModelInventory[];
}

// ── AI-governance types (mirrored from evidentia_core.ai_governance) ─────

/** AI-system descriptor — body of `POST /api/ai-gov/classify` and the
 *  `descriptor` leg of a register request. */
export type AISystemDescriptor = components["schemas"]["AISystemDescriptor"];
/** Classification verdict returned by `POST /api/ai-gov/classify`. */
export type AISystemClassification =
  components["schemas"]["AISystemClassification"];
/** Register body ({descriptor, owner, provider, deployment_status}). */
export type AISystemRegisterRequest = components["schemas"]["RegisterRequest"];
/** Partial-update body for `PUT /api/ai-gov/systems/{system_id}`. */
export type AISystemUpdateRequest =
  components["schemas"]["UpdateSystemRequest"];
/** FIPS 199 categorization body ({confidentiality, integrity, availability, overall?}). */
export type FIPS199CategorizeRequest =
  components["schemas"]["FIPS199CategorizeRequest"];
/** OMB M-24-10 impact body ({category}). DEPRECATED (v0.10.12): M-24-10
 *  rescinded 2025-04-03 by M-25-21; use HighImpactRequest. */
export type OMBImpactRequest = components["schemas"]["OMBImpactRequest"];
/** OMB M-25-21 high-impact body ({determination, bases?, rationale?}). */
export type HighImpactRequest = components["schemas"]["HighImpactRequest"];
/** M-25-21 high-impact determination (high_impact / not_high_impact / not_assessed). */
export type HighImpactDetermination =
  components["schemas"]["HighImpactDetermination"];
/** M-25-21 high-impact consequence basis. */
export type HighImpactBasis = components["schemas"]["HighImpactBasis"];

// ── M-25-21 minimum practices + M-25-22 acquisitions (v0.12 GUI parity) ──
// Unlike the older ai-gov verbs above, these carry real response models
// server-side (v0.12 WU-3), so the generated types have actual fields —
// the console is typed against them rather than Record<string, unknown>.

/** M-25-21 §4(b) minimum-practice body ({practice, status, notes?, ...}). */
export type SetPracticeRequest = components["schemas"]["SetPracticeRequest"];
/** `{system_id, entry, practice_compliance}` after a practice update. */
export type SetPracticeResponse = components["schemas"]["SetPracticeResponse"];
/** One of the M-25-21 minimum practices. */
export type MinimumPractice = components["schemas"]["MinimumPractice"];
/** Practice status (implemented / in_progress / not_started / waived). */
export type PracticeStatus = components["schemas"]["PracticeStatus"];
/** Per-practice compliance roll-up over an M-25-21 assessment. */
export type PracticeComplianceSummary =
  components["schemas"]["PracticeComplianceSummary"];

/** M-25-22 acquisition-registration body. */
export type RegisterAcquisitionRequest =
  components["schemas"]["RegisterAcquisitionRequest"];
/** `{acquisition_id, acquisition}` after registration. */
export type RegisterAcquisitionResponse =
  components["schemas"]["RegisterAcquisitionResponse"];
/** `{count, acquisitions}` list envelope. */
export type ListAcquisitionsResponse =
  components["schemas"]["ListAcquisitionsResponse"];
/** `{acquisition, progress}` — shared by show and set-phase. */
export type AcquisitionDetailResponse =
  components["schemas"]["AcquisitionDetailResponse"];
/** M-25-22 §4 lifecycle-phase body ({phase, status, notes?, ...}). */
export type SetAcquisitionPhaseRequest =
  components["schemas"]["SetAcquisitionPhaseRequest"];
/** A tracked M-25-22 acquisition lifecycle record. */
export type AIAcquisition = components["schemas"]["AIAcquisition"];
/** M-25-22 §4 phase. */
export type AcquisitionPhase = components["schemas"]["AcquisitionPhase"];
/** M-25-22 §4 phase status. */
export type AcquisitionPhaseStatus =
  components["schemas"]["AcquisitionPhaseStatus"];
/** §4 phase-completion roll-up derived from an acquisition record. */
export type AcquisitionProgressSummary =
  components["schemas"]["AcquisitionProgressSummary"];

/**
 * A registered AI system as returned by the registry endpoints. The server
 * serializes the stored entry as a free-form object (no dedicated response
 * schema in OpenAPI), so this is the loose object shape — callers narrow on
 * the fields they read. Matches the `{[key:string]:unknown}` the generated
 * `operations` types carry for these responses.
 */
export type AISystemEntry = Record<string, unknown>;

// ── OSCAL verify types (mirrored from evidentia_core.oscal) ──────────────

/** Inline OSCAL Assessment-Result verify body
 *  ({content, expected_sigstore_identity?, expected_sigstore_issuer?}). */
export type OscalVerifyRequest = components["schemas"]["VerifyRequest"];

// ── Traceability types (mirrored from evidentia_core.traceability) ───────

/** Control↔Threat Traceability Matrix — body of `POST /api/traceability/emit`. */
export type TraceabilityMatrix = components["schemas"]["TraceabilityMatrix"];

// ── Collector types (mirrored from evidentia_collectors) ─────────────────

/**
 * A single collector observation. Every `POST …/collect` endpoint returns a
 * bare `SecurityFinding[]`. Collectors take NO secrets in the body — server-
 * side credentials drive the connection; the body carries only non-secret
 * params (region / repo / host / options).
 */
export type SecurityFinding = components["schemas"]["SecurityFinding"];

/** SQL collector dialects accepted by `POST /api/collectors/sql/{dialect}/collect`. */
export type SqlDialect = "postgres" | "mysql" | "mssql" | "oracle" | "sqlite";

/**
 * Concrete per-dialect SQL collect endpoints. Spelled out (not interpolated)
 * so each path is a literal the CLI<->GUI parity gate sees as wired, and so an
 * unknown dialect can't build an off-contract URL.
 */
const SQL_COLLECT_PATHS: Record<SqlDialect, string> = {
  postgres: "/api/collectors/sql/postgres/collect",
  mysql: "/api/collectors/sql/mysql/collect",
  mssql: "/api/collectors/sql/mssql/collect",
  oracle: "/api/collectors/sql/oracle/collect",
  sqlite: "/api/collectors/sql/sqlite/collect",
};

/**
 * OCSF ingest body for `POST /api/collectors/ocsf/collect`. Supply EITHER
 * inline `content` OR a `url` to fetch; `block_private_ips` (default True
 * server-side) rejects RFC1918 / loopback / link-local targets on the URL leg.
 */
export interface OcsfCollectRequest {
  content?: unknown;
  url?: string;
  block_private_ips?: boolean;
}

/**
 * Nessus scan-export ingest body for `POST /api/collectors/nessus/collect`.
 * `content` is the `<NessusClientData_v2>` XML text — no path, no URL; the
 * server never reads a client-named file. `cadence_slug` defaults server-side
 * to `fedramp-conmon-scans`; `save_evidence` defaults server-side to `true`.
 */
export interface NessusCollectRequest {
  content: string;
  cadence_slug?: string;
  save_evidence?: boolean;
  plugin_output_max_chars?: number;
}

/** Response of `POST /api/collectors/nessus/collect` — findings + manifest + the saved evidence artifact's lineage. */
export type NessusCollectResponse =
  components["schemas"]["NessusCollectResponse"];

// ── Catalog types (mirrored from evidentia_core catalog tooling) ─────────

/** Catalog import body ({framework_id, content, format?, name?, …}). */
export type CatalogImportPayload =
  components["schemas"]["CatalogImportPayload"];

/**
 * Catalog crosswalk envelope. The server returns the requested mapping
 * coordinates echoed back plus the resolved `mappings` (an untyped list
 * of mapping rows server-side), so `mappings` is loosely typed.
 */
export interface CatalogCrosswalkResponse {
  source: string;
  target: string;
  control: string;
  total: number;
  mappings: unknown[];
}

// ── Risk-quantification types (mirrored from evidentia_core.risk) ────────

/** Risk-quantify body ({scenarios, method?, iterations?, seed?}). */
export type RiskQuantifyRequest = components["schemas"]["RiskQuantifyRequest"];
/**
 * Risk-quantify response — a discriminated union of the OpenFAIR (analytic)
 * and FAIR-Monte-Carlo result shapes. The backend picks one based on the
 * requested `method`; callers narrow on the present fields.
 */
export type RiskQuantifyResponse =
  | components["schemas"]["OpenFairQuantifyResponse"]
  | components["schemas"]["FairMcQuantifyResponse"];

// ── TPRM (completion) types (mirrored from evidentia_core.vendor_store) ──

/** Due-diligence questionnaire as generated by the API. ALSO the ingest body
 *  shape: the same `Questionnaire` document with each `questions[]` entry's
 *  `vendor_response` filled in (plus the optional carry-forward `id`/`format`).
 *  The ingest endpoint is PARSE-ONLY — it does not mutate the vendor. */
export type Questionnaire = components["schemas"]["Questionnaire"];
/**
 * Correlation result from `POST …/dd-questionnaire/ingest` (PARSE-ONLY; no
 * vendor mutation). Carries the resolved vendor `{id, name}`, the carry-forward
 * `questionnaire_id` / `format`, the per-question `responses` (keyed by
 * `question.id`), and the `ingested_at` timestamp.
 */
export type DDQuestionnaireIngestResult =
  components["schemas"]["DDQuestionnaireIngestResult"];
/** Vendor-concentration report as returned by the API. */
export type ConcentrationReport = components["schemas"]["ConcentrationReport"];

// ── POA&M (completion) types (mirrored from evidentia_core.poam) ─────────

/** Milestone create body ({description, target_date, status?, evidence_ref?}). */
export type MilestoneCreatePayload =
  components["schemas"]["MilestoneCreatePayload"];

// ── ConMon (completion) types (mirrored from evidentia_core.conmon) ──────

/** `POST /api/conmon/next` body ({slug, last_completed}). */
export type ConmonNextRequest = components["schemas"]["NextDueRequest"];
/** `POST /api/conmon/next` response. */
export type ConmonNextResponse = components["schemas"]["NextDueResponse"];
/** `POST /api/conmon/check` body ({entries, today?, window_days?}). */
export type ConmonCheckRequest = components["schemas"]["CheckRequest"];
/** `POST /api/conmon/check` response. */
export type ConmonCheckResponse = components["schemas"]["CheckResponse"];
/** `POST /api/conmon/health` body ({state, framework?, today?, window_days?}). */
export type ConmonHealthRequest = components["schemas"]["HealthRequest"];
/** `POST /api/conmon/mark-completed` body ({slug, when}). */
export type ConmonMarkCompletedRequest =
  components["schemas"]["MarkCompletedRequest"];
/** `POST /api/conmon/mark-completed` response. */
export type ConmonMarkCompletedResponse =
  components["schemas"]["MarkCompletedResponse"];
/** `POST /api/conmon/series` body ({slug, since?, until?, lookback_days, tolerance_days?}). */
export type ConmonSeriesRequest = components["schemas"]["SeriesRequest"];
/** `POST /api/conmon/series` response ({description, series}). */
export type ConmonSeriesResponse = components["schemas"]["SeriesResponse"];

/**
 * Request a gap-report export and return the artifact blob + the
 * server-suggested filename (parsed from `Content-Disposition`).
 *
 * Does NOT go through the JSON `request()` helper because the response
 * body is an arbitrary artifact (JSON / CSV / SARIF / …), not a typed
 * JSON envelope. On a non-2xx response the JSON `{detail}` error body is
 * read and thrown as an `ApiError`.
 */
async function realExportGapReport(
  report: GapAnalysisReport,
  format: GapExportFormat,
): Promise<GapExportResult> {
  const response = await fetch("/api/gap/export", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ format, report }),
  });

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      /* empty body is fine */
    }
    const detail =
      extractApiErrorMessage(payload) ?? `Export failed (${response.status})`;
    throw new ApiError(detail, response.status, payload);
  }

  const blob = await response.blob();
  const filename = parseContentDispositionFilename(
    response.headers.get("content-disposition"),
    `gap-report.${format === "json" ? "json" : "txt"}`,
  );
  return { blob, filename };
}

/**
 * Request a gap-report export. In a `VITE_DEMO` build this serializes the
 * report client-side (no `/api/gap/export` call); otherwise it round-trips to
 * the backend exporter.
 */
export const exportGapReport = IS_DEMO
  ? demoExportGapReport
  : realExportGapReport;

const realApi = {
  // ── Probe / identity ──────────────────────────────────────────────────
  health: () => request<HealthResponse>("/api/health"),
  version: () => request<VersionResponse>("/api/version"),
  llmStatus: () => request<LlmStatusResponse>("/api/llm-status"),

  // ── Doctor / air-gap ──────────────────────────────────────────────────
  doctor: () =>
    request<{
      subsystems: Array<{ name: string; status: string; detail: string }>;
    }>("/api/doctor"),
  doctorCheckAirGap: () =>
    request<AirGapCheckResponse>("/api/doctor/check-air-gap", {
      method: "POST",
    }),

  // ── Config ────────────────────────────────────────────────────────────
  getConfig: () => request<EvidentiaConfig>("/api/config"),
  putConfig: (cfg: EvidentiaConfig) =>
    request<EvidentiaConfig>("/api/config", {
      method: "PUT",
      body: JSON.stringify(cfg),
    }),

  // ── Frameworks ────────────────────────────────────────────────────────
  listFrameworks: (params?: { tier?: string; category?: string }) => {
    const search = new URLSearchParams();
    if (params?.tier) search.set("tier", params.tier);
    if (params?.category) search.set("category", params.category);
    const qs = search.toString();
    return request<FrameworkListResponse>(
      `/api/frameworks${qs ? `?${qs}` : ""}`,
    );
  },
  getFramework: (id: string) =>
    request<ControlCatalog>(`/api/frameworks/${encodeURIComponent(id)}`),
  getControl: (frameworkId: string, controlId: string) =>
    request<CatalogControl>(
      `/api/frameworks/${encodeURIComponent(frameworkId)}/controls/${encodeURIComponent(
        controlId,
      )}`,
    ),

  // ── Gaps ──────────────────────────────────────────────────────────────
  listGapReports: () => request<GapReportListResponse>("/api/gap/reports"),
  getGapReport: (key: string) =>
    request<GapAnalysisReport>(`/api/gap/reports/${key}`),
  gapDiff: (baseKey: string, headKey: string) =>
    request<GapDiff>("/api/gap/diff", {
      method: "POST",
      body: JSON.stringify({ base_key: baseKey, head_key: headKey }),
    }),

  // ── Init wizard ───────────────────────────────────────────────────────
  initWizard: (payload: InitWizardRequest) =>
    request<InitWizardResponse>("/api/init/wizard", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  initCommit: (payload: InitWizardCommitRequest) =>
    request<InitWizardCommitResponse>("/api/init/commit", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // ── POA&M ─────────────────────────────────────────────────────────────
  listPoamItems: (params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    status?: string;
    owner?: string;
    reviewer?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    if (params?.severity) search.set("severity", params.severity);
    if (params?.status) search.set("status", params.status);
    if (params?.owner) search.set("owner", params.owner);
    if (params?.reviewer) search.set("reviewer", params.reviewer);
    const qs = search.toString();
    return request<PoamListResponse>(`/api/poam/items${qs ? `?${qs}` : ""}`);
  },
  getPoamItem: (poamId: string) =>
    request<ControlGap>(`/api/poam/items/${encodeURIComponent(poamId)}`),
  replacePoamItem: (poamId: string, item: PoamItemInput) =>
    request<ControlGap>(`/api/poam/items/${encodeURIComponent(poamId)}`, {
      method: "PUT",
      body: JSON.stringify(item),
    }),
  updatePoamMilestone: (
    poamId: string,
    milestoneId: string,
    payload: MilestoneUpdatePayload,
  ) =>
    request<ControlGap>(
      `/api/poam/items/${encodeURIComponent(poamId)}/milestones/${encodeURIComponent(
        milestoneId,
      )}`,
      { method: "PATCH", body: JSON.stringify(payload) },
    ),
  createPoamItem: (item: PoamItemInput) =>
    request<ControlGap>("/api/poam/items", {
      method: "POST",
      body: JSON.stringify(item),
    }),
  deletePoamItem: (poamId: string) =>
    request<void>(`/api/poam/items/${encodeURIComponent(poamId)}`, {
      method: "DELETE",
    }),
  poamCalendar: (params?: { today?: string }) => {
    const search = new URLSearchParams();
    if (params?.today) search.set("today", params.today);
    const qs = search.toString();
    return request<Record<string, unknown>>(
      `/api/poam/calendar${qs ? `?${qs}` : ""}`,
    );
  },
  addPoamMilestone: (poamId: string, payload: MilestoneCreatePayload) =>
    request<ControlGap>(
      `/api/poam/items/${encodeURIComponent(poamId)}/milestones`,
      { method: "POST", body: JSON.stringify(payload) },
    ),

  // ── TPRM ──────────────────────────────────────────────────────────────
  listVendors: (params?: {
    skip?: number;
    limit?: number;
    criticality_tier?: string;
    type?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    if (params?.criticality_tier)
      search.set("criticality_tier", params.criticality_tier);
    if (params?.type) search.set("type", params.type);
    const qs = search.toString();
    return request<VendorListResponse>(
      `/api/tprm/vendors${qs ? `?${qs}` : ""}`,
    );
  },
  createVendor: (vendor: VendorInput) =>
    request<Vendor>("/api/tprm/vendors", {
      method: "POST",
      body: JSON.stringify(vendor),
    }),
  getVendor: (vendorId: string) =>
    request<Vendor>(`/api/tprm/vendors/${encodeURIComponent(vendorId)}`),
  updateVendor: (vendorId: string, vendor: VendorInput) =>
    request<Vendor>(`/api/tprm/vendors/${encodeURIComponent(vendorId)}`, {
      method: "PUT",
      body: JSON.stringify(vendor),
    }),
  deleteVendor: (vendorId: string) =>
    request<void>(`/api/tprm/vendors/${encodeURIComponent(vendorId)}`, {
      method: "DELETE",
    }),
  tprmConcentration: (params?: { by?: string; threshold?: number }) => {
    const search = new URLSearchParams();
    if (params?.by) search.set("by", params.by);
    if (params?.threshold != null)
      search.set("threshold", String(params.threshold));
    const qs = search.toString();
    return request<ConcentrationReport>(
      `/api/tprm/concentration${qs ? `?${qs}` : ""}`,
    );
  },
  ddQuestionnaireGenerate: (vendorId: string, params?: { format?: string }) => {
    const search = new URLSearchParams();
    if (params?.format) search.set("format", params.format);
    const qs = search.toString();
    return request<Questionnaire>(
      `/api/tprm/vendors/${encodeURIComponent(vendorId)}/dd-questionnaire${
        qs ? `?${qs}` : ""
      }`,
      { method: "POST" },
    );
  },
  ddQuestionnaireIngest: (vendorId: string, document: Questionnaire) =>
    request<DDQuestionnaireIngestResult>(
      `/api/tprm/vendors/${encodeURIComponent(vendorId)}/dd-questionnaire/ingest`,
      { method: "POST", body: JSON.stringify(document) },
    ),

  // ── ConMon ────────────────────────────────────────────────────────────
  listConmonCadences: (params?: { framework?: string }) => {
    const search = new URLSearchParams();
    if (params?.framework) search.set("framework", params.framework);
    const qs = search.toString();
    return request<ConmonCadence[]>(
      `/api/conmon/cadences${qs ? `?${qs}` : ""}`,
    );
  },
  conmonNext: (body: ConmonNextRequest) =>
    request<ConmonNextResponse>("/api/conmon/next", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  conmonCheck: (body: ConmonCheckRequest) =>
    request<ConmonCheckResponse>("/api/conmon/check", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  conmonHealth: (body: ConmonHealthRequest) =>
    request<Record<string, unknown>>("/api/conmon/health", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  conmonSeries: (body: ConmonSeriesRequest) =>
    request<ConmonSeriesResponse>("/api/conmon/series", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  conmonMarkCompleted: (body: ConmonMarkCompletedRequest) =>
    request<ConmonMarkCompletedResponse>("/api/conmon/mark-completed", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  conmonDedupList: (params?: { slug?: string; suppression_hours?: number }) => {
    const search = new URLSearchParams();
    if (params?.slug) search.set("slug", params.slug);
    if (params?.suppression_hours != null)
      search.set("suppression_hours", String(params.suppression_hours));
    const qs = search.toString();
    return request<Record<string, unknown>>(
      `/api/conmon/dedup-list${qs ? `?${qs}` : ""}`,
    );
  },

  // ── Governance: challenges ────────────────────────────────────────────
  listChallenges: (params?: {
    skip?: number;
    limit?: number;
    subject_model_id?: string;
    outcome?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    if (params?.subject_model_id)
      search.set("subject_model_id", params.subject_model_id);
    if (params?.outcome) search.set("outcome", params.outcome);
    const qs = search.toString();
    return request<ChallengeListResponse>(
      `/api/governance/challenges${qs ? `?${qs}` : ""}`,
    );
  },
  createChallenge: (challenge: EffectiveChallenge) =>
    request<EffectiveChallenge>("/api/governance/challenges", {
      method: "POST",
      body: JSON.stringify(challenge),
    }),
  getChallenge: (challengeId: string) =>
    request<EffectiveChallenge>(
      `/api/governance/challenges/${encodeURIComponent(challengeId)}`,
    ),

  // ── Governance: metrics ───────────────────────────────────────────────
  listMetrics: (params?: { skip?: number; limit?: number; kind?: string }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    if (params?.kind) search.set("kind", params.kind);
    const qs = search.toString();
    return request<MetricListResponse>(
      `/api/governance/metrics${qs ? `?${qs}` : ""}`,
    );
  },
  createMetric: (metric: Metric) =>
    request<MetricWithStatus>("/api/governance/metrics", {
      method: "POST",
      body: JSON.stringify(metric),
    }),
  observeMetric: (metricId: string, payload: MetricObservationPayload) =>
    request<MetricWithStatus>(
      `/api/governance/metrics/${encodeURIComponent(metricId)}/observations`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  getMetric: (metricId: string) =>
    request<MetricWithStatus>(
      `/api/governance/metrics/${encodeURIComponent(metricId)}`,
    ),
  deleteMetric: (metricId: string) =>
    request<void>(`/api/governance/metrics/${encodeURIComponent(metricId)}`, {
      method: "DELETE",
    }),
  metricsReport: () => requestText("/api/governance/metrics/report"),

  // ── Governance: workflows ─────────────────────────────────────────────
  listWorkflows: (params?: { skip?: number; limit?: number }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    const qs = search.toString();
    return request<WorkflowListResponse>(
      `/api/governance/workflows${qs ? `?${qs}` : ""}`,
    );
  },
  runWorkflow: (workflow: WorkflowInput) =>
    request<Workflow>("/api/governance/workflows", {
      method: "POST",
      body: JSON.stringify(workflow),
    }),
  advanceWorkflow: (workflowId: string, payload: WorkflowAdvancePayload) =>
    request<Workflow>(
      `/api/governance/workflows/${encodeURIComponent(workflowId)}/advance`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  getWorkflow: (workflowId: string) =>
    request<Workflow>(
      `/api/governance/workflows/${encodeURIComponent(workflowId)}`,
    ),
  workflowLog: (workflowId: string) =>
    requestText(
      `/api/governance/workflows/${encodeURIComponent(workflowId)}/log`,
    ),
  deleteWorkflow: (workflowId: string) =>
    request<void>(
      `/api/governance/workflows/${encodeURIComponent(workflowId)}`,
      { method: "DELETE" },
    ),

  // ── Governance: three-lines report ────────────────────────────────────
  linesReport: (owners: Owner[]) =>
    requestText("/api/governance/lines-report", {
      method: "POST",
      body: JSON.stringify(owners),
    }),

  // ── Retention ─────────────────────────────────────────────────────────
  listRetention: (params?: {
    skip?: number;
    limit?: number;
    classification?: string;
    lifecycle?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    if (params?.classification)
      search.set("classification", params.classification);
    if (params?.lifecycle) search.set("lifecycle", params.lifecycle);
    const qs = search.toString();
    return request<RetentionListResponse>(
      `/api/retention${qs ? `?${qs}` : ""}`,
    );
  },
  createRetention: (payload: RetentionCreatePayload) =>
    request<RetentionMetadata>("/api/retention", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getRetention: (retentionId: string) =>
    request<RetentionMetadata>(
      `/api/retention/${encodeURIComponent(retentionId)}`,
    ),
  extendRetention: (retentionId: string, payload: RetentionExtendPayload) =>
    request<RetentionMetadata>(
      `/api/retention/${encodeURIComponent(retentionId)}/extend`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  transitionRetention: (
    retentionId: string,
    payload: RetentionTransitionPayload,
  ) =>
    request<RetentionMetadata>(
      `/api/retention/${encodeURIComponent(retentionId)}/transition`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  deleteRetention: (retentionId: string) =>
    request<void>(`/api/retention/${encodeURIComponent(retentionId)}`, {
      method: "DELETE",
    }),
  retentionReport: () => requestText("/api/retention/report"),

  // ── Evidence (lineage / versions) ─────────────────────────────────────
  saveEvidence: (artifact: EvidenceArtifactInput) =>
    request<EvidenceSaveSummary>("/api/evidence", {
      method: "POST",
      body: JSON.stringify(artifact),
    }),
  evidenceHistory: (lineageId: string) =>
    request<EvidenceHistoryResponse>(
      `/api/evidence/${encodeURIComponent(lineageId)}/history`,
    ),
  evidenceVersion: (lineageId: string, version: number) =>
    request<EvidenceArtifact>(
      `/api/evidence/${encodeURIComponent(lineageId)}/versions/${encodeURIComponent(
        String(version),
      )}`,
    ),

  // ── Model-risk (inventory) ────────────────────────────────────────────
  listModels: (params?: { skip?: number; limit?: number }) => {
    const search = new URLSearchParams();
    if (params?.skip != null) search.set("skip", String(params.skip));
    if (params?.limit != null) search.set("limit", String(params.limit));
    const qs = search.toString();
    return request<ModelListResponse>(
      `/api/model-risk/models${qs ? `?${qs}` : ""}`,
    );
  },
  createModel: (model: ModelInventoryInput) =>
    request<ModelInventory>("/api/model-risk/models", {
      method: "POST",
      body: JSON.stringify(model),
    }),
  getModel: (modelId: string) =>
    request<ModelInventory>(
      `/api/model-risk/models/${encodeURIComponent(modelId)}`,
    ),
  updateModel: (modelId: string, model: ModelInventoryInput) =>
    request<ModelInventory>(
      `/api/model-risk/models/${encodeURIComponent(modelId)}`,
      { method: "PUT", body: JSON.stringify(model) },
    ),
  deleteModel: (modelId: string) =>
    request<void>(`/api/model-risk/models/${encodeURIComponent(modelId)}`, {
      method: "DELETE",
    }),
  // `documentation` + `validation-report` are served as text/plain (markdown),
  // not a JSON envelope — so they route through requestText (see metricsReport).
  modelDocumentation: (modelId: string) =>
    requestText(
      `/api/model-risk/models/${encodeURIComponent(modelId)}/documentation`,
    ),
  modelValidationReport: (modelId: string) =>
    requestText(
      `/api/model-risk/models/${encodeURIComponent(modelId)}/validation-report`,
    ),

  // ── Catalog (crosswalk / where / license / import / remove) ───────────
  catalogCrosswalk: (params: {
    source: string;
    target: string;
    control: string;
  }) => {
    const search = new URLSearchParams();
    search.set("source", params.source);
    search.set("target", params.target);
    search.set("control", params.control);
    return request<CatalogCrosswalkResponse>(
      `/api/catalog/crosswalk?${search.toString()}`,
    );
  },
  catalogWhere: (frameworkId: string) => {
    const search = new URLSearchParams();
    search.set("framework_id", frameworkId);
    return request<Record<string, unknown>>(
      `/api/catalog/where?${search.toString()}`,
    );
  },
  catalogLicenseInfo: (frameworkId: string) =>
    request<Record<string, unknown>>(
      `/api/catalog/license-info/${encodeURIComponent(frameworkId)}`,
    ),
  catalogImport: (payload: CatalogImportPayload) =>
    request<Record<string, unknown>>("/api/catalog/import", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  catalogRemove: (frameworkId: string) =>
    request<void>(`/api/catalog/${encodeURIComponent(frameworkId)}`, {
      method: "DELETE",
    }),

  // ── Risk quantification (FAIR / OpenFAIR) ─────────────────────────────
  riskQuantify: (body: RiskQuantifyRequest) =>
    request<RiskQuantifyResponse>("/api/risk/quantify", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ── Explain ───────────────────────────────────────────────────────────
  // NOTE: POST /api/explain/{framework}/{control_id} streams the explanation
  // via Server-Sent Events (text/event-stream), NOT a JSON body — so it is
  // intentionally NOT a request()-based method. The Explain screen consumes
  // it with fetch + ReadableStream.getReader() (see RiskGeneratePage.tsx's
  // readSse pattern). This helper just builds the canonical URL.
  explainControlUrl: (
    framework: string,
    controlId: string,
    params?: { refresh?: boolean; model?: string },
  ) => {
    const search = new URLSearchParams();
    if (params?.refresh) search.set("refresh", "true");
    if (params?.model) search.set("model", params.model);
    const qs = search.toString();
    return `/api/explain/${encodeURIComponent(framework)}/${encodeURIComponent(
      controlId,
    )}${qs ? `?${qs}` : ""}`;
  },

  // ── AI governance (EU AI Act / FIPS 199 / OMB M-25-21 high-impact) ────
  // The list endpoint takes a `tier` filter (NOT skip/limit) and returns a
  // bare array of registry entries — there is no paginated envelope server-
  // side. The `skip`/`limit` params are accepted for call-site symmetry with
  // the other list verbs and applied client-side.
  listAiSystems: (params?: {
    skip?: number;
    limit?: number;
    tier?: string;
  }) => {
    const search = new URLSearchParams();
    if (params?.tier) search.set("tier", params.tier);
    const qs = search.toString();
    return request<AISystemEntry[]>(`/api/ai-gov/systems${qs ? `?${qs}` : ""}`);
  },
  classifyAiSystem: (descriptor: AISystemDescriptor) =>
    request<AISystemClassification>("/api/ai-gov/classify", {
      method: "POST",
      body: JSON.stringify(descriptor),
    }),
  registerAiSystem: (body: AISystemRegisterRequest) =>
    request<AISystemEntry>("/api/ai-gov/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getAiSystem: (systemId: string) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}`,
    ),
  updateAiSystem: (systemId: string, body: AISystemUpdateRequest) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}`,
      { method: "PUT", body: JSON.stringify(body) },
    ),
  deleteAiSystem: (systemId: string) =>
    request<void>(`/api/ai-gov/systems/${encodeURIComponent(systemId)}`, {
      method: "DELETE",
    }),
  retireAiSystem: (systemId: string) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}/retire`,
      { method: "POST" },
    ),
  categorizeFipsAiSystem: (systemId: string, body: FIPS199CategorizeRequest) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}/categorize-fips`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  setOmbImpactAiSystem: (systemId: string, body: OMBImpactRequest) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}/set-omb-impact`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  setHighImpactAiSystem: (systemId: string, body: HighImpactRequest) =>
    request<AISystemEntry>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}/set-high-impact`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  // M-25-21 §4(b) minimum practices. The API 400s unless the system
  // already carries an M-25-21 assessment, so the console gates the form
  // on `omb_high_impact` being present rather than surfacing that error.
  setPracticeAiSystem: (systemId: string, body: SetPracticeRequest) =>
    request<SetPracticeResponse>(
      `/api/ai-gov/systems/${encodeURIComponent(systemId)}/set-practice`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  // ── AI acquisitions (OMB M-25-22 lifecycle) ───────────────────────────
  listAcquisitions: () =>
    request<ListAcquisitionsResponse>("/api/ai-gov/acquisitions"),
  getAcquisition: (acquisitionId: string) =>
    request<AcquisitionDetailResponse>(
      `/api/ai-gov/acquisitions/${encodeURIComponent(acquisitionId)}`,
    ),
  registerAcquisition: (body: RegisterAcquisitionRequest) =>
    request<RegisterAcquisitionResponse>("/api/ai-gov/acquisitions", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  setAcquisitionPhase: (
    acquisitionId: string,
    body: SetAcquisitionPhaseRequest,
  ) =>
    request<AcquisitionDetailResponse>(
      `/api/ai-gov/acquisitions/${encodeURIComponent(acquisitionId)}/set-phase`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  // ── OSCAL (verify) ────────────────────────────────────────────────────
  // Returns a free-form structured verdict object (no dedicated response
  // schema server-side); a tampered/invalid AR is still a 200 with a
  // NEGATIVE verdict, not an error.
  oscalVerify: (body: OscalVerifyRequest) =>
    request<Record<string, unknown>>("/api/oscal/verify", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ── Traceability (Control↔Threat matrix → OSCAL profile) ──────────────
  // Returns the bare UNSIGNED OSCAL profile dict (no dedicated response
  // schema server-side); signing is CLI-only and never performed here.
  traceabilityEmit: (matrix: TraceabilityMatrix) =>
    request<Record<string, unknown>>("/api/traceability/emit", {
      method: "POST",
      body: JSON.stringify(matrix),
    }),

  // ── Collectors (evidence collection) ──────────────────────────────────
  // Every collect verb returns a bare `SecurityFinding[]`. NO secrets in the
  // body — credentials are server-side; the body carries only non-secret
  // params (region / repo / host / options). `aws`/`okta`/the vendor-risk
  // collectors accept an optional body; `github`/`sql` require one.
  collectAws: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/aws/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectGithub: (body: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/github/collect", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  collectOkta: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/okta/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectSql: (dialect: string, body: Record<string, unknown>) =>
    request<SecurityFinding[]>(
      SQL_COLLECT_PATHS[dialect as SqlDialect] ??
        `/api/collectors/sql/${encodeURIComponent(dialect)}/collect`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  collectDatabricks: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/databricks/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectSnowflake: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/snowflake/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectVanta: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/vanta/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectDrata: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/drata/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectBitsight: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/bitsight/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectSecurityscorecard: (body?: Record<string, unknown>) =>
    request<SecurityFinding[]>("/api/collectors/securityscorecard/collect", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  collectOcsf: (body: OcsfCollectRequest) =>
    request<SecurityFinding[]>("/api/collectors/ocsf/collect", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Nessus ingest is LOCAL-ONLY (text upload, no path/URL, no credentials) —
  // mirrors OCSF's inline-`content` mode's trust posture.
  collectNessus: (body: NessusCollectRequest) =>
    request<NessusCollectResponse>("/api/collectors/nessus/collect", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // `convert` is LOCAL-ONLY (no collection); it round-trips findings through the
  // OCSF mapping layer and returns a loose object list (no named schema).
  collectConvert: (body: Record<string, unknown>) =>
    request<Record<string, unknown>[]>("/api/collectors/convert", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  collectorsStatus: () =>
    request<Record<string, unknown>>("/api/collectors/status"),

  // ── Integrations (push / publish to external systems) ─────────────────
  // Status verbs report configuration / connectivity; push / publish / sync
  // verbs round-trip a gap report (keyed by `report_key` in the PATH) to the
  // target. NO secrets in the body — integration credentials are server-side;
  // the body carries only non-secret options. Responses are free-form objects
  // (no named schema server-side) → `Record<string, unknown>`.
  jiraStatus: () =>
    request<Record<string, unknown>>("/api/integrations/jira/status"),
  jiraPush: (reportKey: string, body?: Record<string, unknown>) =>
    request<Record<string, unknown>>(
      `/api/integrations/jira/push/${encodeURIComponent(reportKey)}`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
  jiraSync: (reportKey: string, body?: Record<string, unknown>) =>
    request<Record<string, unknown>>(
      `/api/integrations/jira/sync/${encodeURIComponent(reportKey)}`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
  // status-map is a nested map of {report_key: {gap_id: jira_status}}.
  jiraStatusMap: () =>
    request<Record<string, Record<string, string>>>(
      "/api/integrations/jira/status-map",
    ),
  tableauPublish: (reportKey: string, body?: Record<string, unknown>) =>
    request<Record<string, unknown>>(
      `/api/integrations/tableau/publish/${encodeURIComponent(reportKey)}`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
  powerbiPublish: (reportKey: string, body?: Record<string, unknown>) =>
    request<Record<string, unknown>>(
      `/api/integrations/powerbi/publish/${encodeURIComponent(reportKey)}`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
  servicenowStatus: () =>
    request<Record<string, unknown>>("/api/integrations/servicenow/status"),
  servicenowPush: (reportKey: string, body?: Record<string, unknown>) =>
    request<Record<string, unknown>>(
      `/api/integrations/servicenow/push/${encodeURIComponent(reportKey)}`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
};

/**
 * The API client the app actually imports. In a `VITE_DEMO` build this is the
 * fixtures-backed `demoApi` (zero network, baked Meridian v2 data); in every
 * normal build it is the real fetch-based `realApi`. The swap happens once, at
 * module load, so no call site needs to know which it is talking to.
 */
export const api = IS_DEMO ? demoApi : realApi;
