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
export type PoamItemInput = components["schemas"]["ControlGap-Input"];
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
export type VendorInput = components["schemas"]["Vendor-Input"];
/** Vendor record as returned by the API. */
export type Vendor = components["schemas"]["Vendor-Output"];
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
      payload &&
      typeof payload === "object" &&
      "detail" in payload &&
      typeof (payload as { detail: unknown }).detail === "string"
        ? (payload as { detail: string }).detail
        : `Export failed (${response.status})`;
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

  // ── ConMon ────────────────────────────────────────────────────────────
  listConmonCadences: (params?: { framework?: string }) => {
    const search = new URLSearchParams();
    if (params?.framework) search.set("framework", params.framework);
    const qs = search.toString();
    return request<ConmonCadence[]>(
      `/api/conmon/cadences${qs ? `?${qs}` : ""}`,
    );
  },

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
};

/**
 * The API client the app actually imports. In a `VITE_DEMO` build this is the
 * fixtures-backed `demoApi` (zero network, baked Meridian v2 data); in every
 * normal build it is the real fetch-based `realApi`. The swap happens once, at
 * module load, so no call site needs to know which it is talking to.
 */
export const api = IS_DEMO ? demoApi : realApi;
