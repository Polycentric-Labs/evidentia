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
