/**
 * Baked demo dataset — the Meridian v2 "hero" story rendered with zero backend.
 *
 * Every export here mirrors a response shape the real `api` client returns, so
 * `demo-api.ts` (Task B2) can resolve each `api` method straight from a fixture.
 * The numbers, organization, and framework set are seeded from
 * `examples/meridian-fintech-v2/snapshots/baseline.json` so the static demo GUI
 * tells the same story as the Tier-0 asciinema cast: Meridian Financial, 311
 * gaps (297 critical / 13 high / 1 medium) across NIST 800-53 Rev 5 Moderate +
 * SOC 2 TSC.
 *
 * The dataset is intentionally small — `GapTable` paginates, so ~12 gap rows
 * across the severities tell the story without shipping all 311. Types are
 * pinned to the same sources the production client uses (`@/types/api`,
 * `@/lib/api`, `@/types/config`, `@/types/openapi`) so the fixtures can never
 * drift from the rendered components.
 */

import type {
  EntraM365CollectResult,
  FrameworkListResponse,
  GapReportListResponse,
  PoamListResponse,
  VendorListResponse,
  Vendor,
  ConmonCadence,
} from "@/lib/api";
import type {
  AirGapCheckResponse,
  ControlGap,
  EfficiencyOpportunity,
  GapAnalysisReport,
  GapDiff,
  HealthResponse,
  LlmStatusResponse,
  VersionResponse,
} from "@/types/api";
import type { EvidentiaConfig } from "@/types/config";
import type { components } from "@/types/openapi";

/**
 * The plain-English explanation payload the `done` SSE event carries. Mirrors
 * the (non-exported) `Explanation` interface in `routes/ExplainPage.tsx`, which
 * mirrors `evidentia_ai.explain.models.PlainEnglishExplanation`. Kept structural
 * so `DEMO_EXPLANATION` is assignable where `ExplainPage` expects it.
 */
export interface Explanation {
  framework_id: string;
  control_id: string;
  control_title: string;
  plain_english: string;
  why_it_matters: string;
  what_to_do: string[];
  effort_estimate: string;
  common_misconceptions?: string | null;
  generation_context?: { model?: string | null } | null;
}

/**
 * A POA&M list item is the generated `ControlGap-Output`, which models
 * `poam_milestones` directly — but `PoamListResponse.items` is typed against the
 * hand-authored `ControlGap` mirror, which does not. Widen locally so a fixture
 * can carry milestones, exactly as `PoamPage`/`PoamPage.test.tsx` do at that
 * seam. (A `PoamGap[]` is still assignable to `ControlGap[]`.)
 */
type Milestone = components["schemas"]["Milestone"];
type PoamGap = ControlGap & { poam_milestones?: Milestone[] };

const ANALYZED_AT = "2026-04-19T14:47:33.594669Z";
const CREATED_AT = "2026-04-19T14:47:33.586669Z";
const EVIDENTIA_VERSION = "0.10.10";

const REMEDIATION = (controlId: string, title: string): string =>
  `Implement ${controlId} (${title}) to meet the following requirement:\n` +
  "[Licensed content — see license_url for authoritative text.]\n\n" +
  "Consider: existing tools, processes, or compensating controls that may " +
  "partially address this requirement.";

/**
 * ~12 representative `ControlGap` rows seeded from the Meridian v2 baseline —
 * 9 critical + 2 high + 1 medium, mirroring the report header's 1-medium count.
 * Real control ids / titles / families / cross-framework values where the
 * baseline carries them; schema-complete realistic rows for the NIST controls
 * the demo story calls out (IA-2, SC-7, RA-5, AT-2).
 */
export const DEMO_GAPS: ControlGap[] = [
  {
    id: "demo-gap-cc7-1",
    framework: "soc2-tsc",
    control_id: "CC7.1",
    control_title: "Common Criteria 7.1",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Common Criteria",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control CC7.1 (Common Criteria 7.1) is required by soc2-tsc but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: [
      "nist-800-53-mod:CM-6",
      "nist-800-53-mod:RA-5",
      "nist-800-53-mod:SI-2",
    ],
    remediation_guidance: REMEDIATION("CC7.1", "Common Criteria 7.1"),
    implementation_effort: "low",
    priority_score: 6.4,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-cc7-2",
    framework: "soc2-tsc",
    control_id: "CC7.2",
    control_title: "Common Criteria 7.2",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Common Criteria",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control CC7.2 (Common Criteria 7.2) is required by soc2-tsc but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: [
      "nist-800-53-mod:AU-2",
      "nist-800-53-mod:AU-6",
      "nist-800-53-mod:SI-4",
    ],
    remediation_guidance: REMEDIATION("CC7.2", "Common Criteria 7.2"),
    implementation_effort: "low",
    priority_score: 6.4,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-cc6-1",
    framework: "soc2-tsc",
    control_id: "CC6.1",
    control_title: "Common Criteria 6.1",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Common Criteria",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control CC6.1 (Common Criteria 6.1) is required by soc2-tsc but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["nist-800-53-mod:AC-2", "nist-800-53-mod:IA-5"],
    remediation_guidance: REMEDIATION("CC6.1", "Common Criteria 6.1"),
    implementation_effort: "low",
    priority_score: 5.6,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-cc6-6",
    framework: "soc2-tsc",
    control_id: "CC6.6",
    control_title: "Common Criteria 6.6",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Common Criteria",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control CC6.6 (Common Criteria 6.6) is required by soc2-tsc but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["nist-800-53-mod:SC-7"],
    remediation_guidance: REMEDIATION("CC6.6", "Common Criteria 6.6"),
    implementation_effort: "low",
    priority_score: 4.8,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-cc8-1",
    framework: "soc2-tsc",
    control_id: "CC8.1",
    control_title: "Common Criteria 8.1",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Common Criteria",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control CC8.1 (Common Criteria 8.1) is required by soc2-tsc but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["nist-800-53-mod:CM-2"],
    remediation_guidance: REMEDIATION("CC8.1", "Common Criteria 8.1"),
    implementation_effort: "low",
    priority_score: 4.8,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-au-2",
    framework: "nist-800-53-rev5-moderate",
    control_id: "AU-2",
    control_title: "Event Logging",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Audit and Accountability",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control AU-2 (Event Logging) is required by nist-800-53-rev5-moderate but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["soc2-tsc:CC7.2"],
    remediation_guidance: REMEDIATION("AU-2", "Event Logging"),
    implementation_effort: "low",
    priority_score: 6.0,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-si-4",
    framework: "nist-800-53-rev5-moderate",
    control_id: "SI-4",
    control_title: "System Monitoring",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "System and Information Integrity",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control SI-4 (System Monitoring) is required by nist-800-53-rev5-moderate but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["soc2-tsc:CC7.2"],
    remediation_guidance: REMEDIATION("SI-4", "System Monitoring"),
    implementation_effort: "medium",
    priority_score: 5.4,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-ia-2",
    framework: "nist-800-53-rev5-moderate",
    control_id: "IA-2",
    control_title: "Identification and Authentication (Organizational Users)",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Identification and Authentication",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control IA-2 (Identification and Authentication (Organizational Users)) is required by nist-800-53-rev5-moderate but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["soc2-tsc:CC6.1"],
    remediation_guidance: REMEDIATION(
      "IA-2",
      "Identification and Authentication (Organizational Users)",
    ),
    implementation_effort: "medium",
    priority_score: 5.2,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-sc-7",
    framework: "nist-800-53-rev5-moderate",
    control_id: "SC-7",
    control_title: "Boundary Protection",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "System and Communications Protection",
    gap_severity: "critical",
    implementation_status: "missing",
    gap_description:
      "Control SC-7 (Boundary Protection) is required by nist-800-53-rev5-moderate but is not present in the organization's control inventory.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: ["soc2-tsc:CC6.6"],
    remediation_guidance: REMEDIATION("SC-7", "Boundary Protection"),
    implementation_effort: "high",
    priority_score: 5.0,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-cm-6",
    framework: "nist-800-53-rev5-moderate",
    control_id: "CM-6",
    control_title: "Configuration Settings",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Configuration Management",
    gap_severity: "high",
    implementation_status: "partial",
    gap_description:
      "Control CM-6 (Configuration Settings) is partially implemented for nist-800-53-rev5-moderate; remaining configuration baselines are not enforced.",
    status: "open",
    equivalent_controls_in_inventory: ["CM-6"],
    cross_framework_value: ["soc2-tsc:CC7.1"],
    remediation_guidance:
      "Complete the implementation of CM-6 (Configuration Settings). Review the partial coverage already in the inventory and close the remaining configuration-baseline enforcement gap.",
    implementation_effort: "medium",
    priority_score: 1.5,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-ra-5",
    framework: "nist-800-53-rev5-moderate",
    control_id: "RA-5",
    control_title: "Vulnerability Monitoring and Scanning",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Risk Assessment",
    gap_severity: "high",
    implementation_status: "partial",
    gap_description:
      "Control RA-5 (Vulnerability Monitoring and Scanning) is partially implemented for nist-800-53-rev5-moderate; authenticated scanning coverage is incomplete.",
    status: "open",
    equivalent_controls_in_inventory: ["RA-5"],
    cross_framework_value: ["soc2-tsc:CC7.1"],
    remediation_guidance:
      "Complete the implementation of RA-5 (Vulnerability Monitoring and Scanning). Extend authenticated scan coverage to the remaining assets and wire results into the remediation workflow.",
    implementation_effort: "medium",
    priority_score: 1.4,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
  {
    id: "demo-gap-at-2",
    framework: "nist-800-53-rev5-moderate",
    control_id: "AT-2",
    control_title: "Literacy Training and Awareness",
    control_description:
      "[Licensed content — see license_url for authoritative text.]",
    control_family: "Awareness and Training",
    gap_severity: "medium",
    implementation_status: "planned",
    gap_description:
      "Control AT-2 (Literacy Training and Awareness) is planned for nist-800-53-rev5-moderate; the awareness program has not yet been rolled out org-wide.",
    status: "open",
    equivalent_controls_in_inventory: ["AT-2"],
    cross_framework_value: [],
    remediation_guidance:
      "Execute the planned implementation for AT-2 (Literacy Training and Awareness). Roll out the security-awareness curriculum to all staff and track completion.",
    implementation_effort: "low",
    priority_score: 2.0,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: CREATED_AT,
    remediated_at: null,
    assigned_to: null,
    tags: [],
  },
];

/** The three "many frameworks, one control" efficiency wins from the story. */
export const DEMO_EFFICIENCY_OPPORTUNITIES: EfficiencyOpportunity[] = [
  {
    control_id: "AC-2",
    control_title: "Account Management",
    frameworks_satisfied: ["nist-800-53-rev5-moderate", "soc2-tsc", "eu-gdpr"],
    framework_count: 3,
    total_gaps_closed: 47,
    implementation_effort: "medium",
    value_score: 8.9,
  },
  {
    control_id: "AU-2",
    control_title: "Event Logging",
    frameworks_satisfied: ["nist-800-53-rev5-moderate", "soc2-tsc"],
    framework_count: 2,
    total_gaps_closed: 31,
    implementation_effort: "low",
    value_score: 7.4,
  },
  {
    control_id: "IA-5",
    control_title: "Authenticator Management",
    frameworks_satisfied: ["nist-800-53-rev5-moderate", "soc2-tsc"],
    framework_count: 2,
    total_gaps_closed: 22,
    implementation_effort: "medium",
    value_score: 6.8,
  },
];

/**
 * The hero gap report. Counts mirror the Meridian v2 baseline header
 * (311 / 297 / 13 / 1 / 0 / 0); 49 of 348 controls implemented => 10.6%
 * coverage — the exact figures the Meridian v2 baseline.json carries, so
 * the GUI and the Tier-0 cast (which runs the real CLI) quote the same story.
 */
export const DEMO_GAP_REPORT: GapAnalysisReport = {
  id: "meridian-fintech-v2-baseline",
  organization: "Meridian Financial",
  frameworks_analyzed: ["nist-800-53-rev5-moderate", "soc2-tsc"],
  analyzed_at: ANALYZED_AT,
  total_controls_required: 348,
  total_controls_in_inventory: 49,
  total_gaps: 311,
  critical_gaps: 297,
  high_gaps: 13,
  medium_gaps: 1,
  low_gaps: 0,
  informational_gaps: 0,
  coverage_percentage: 10.6,
  gaps: DEMO_GAPS,
  efficiency_opportunities: DEMO_EFFICIENCY_OPPORTUNITIES,
  prioritized_roadmap: DEMO_GAPS.map((g) => g.id),
  inventory_source: "my-controls.yaml",
  evidentia_version: EVIDENTIA_VERSION,
  notes: null,
};

/**
 * The post-remediation report (the `pr-branch` snapshot) — one control added
 * (49 -> 50 in inventory), closing one critical + the one medium gap, so the
 * diff shows real progress. Counts mirror pr-branch.json: 309 gaps / 296
 * critical / 0 medium, coverage 11.2%.
 */
export const DEMO_GAP_REPORT_PR: GapAnalysisReport = {
  ...DEMO_GAP_REPORT,
  id: "meridian-fintech-v2-pr-branch",
  analyzed_at: "2026-04-26T09:12:05.114200Z",
  total_controls_in_inventory: 50,
  total_gaps: 309,
  critical_gaps: 296,
  medium_gaps: 0,
  coverage_percentage: 11.2,
  gaps: DEMO_GAPS.filter((g) => !["AU-2", "AT-2"].includes(g.control_id)),
  inventory_source: "my-controls.yaml",
};

/** Report-list envelope — two snapshots: the baseline + the PR branch. */
export const DEMO_REPORT_LIST: GapReportListResponse = {
  total: 2,
  store_dir: "/demo/reports",
  reports: [
    {
      key: "meridian-fintech-v2:baseline",
      mtime_iso: ANALYZED_AT,
      size_bytes: 517_419,
      organization: DEMO_GAP_REPORT.organization,
      frameworks_analyzed: DEMO_GAP_REPORT.frameworks_analyzed,
      total_gaps: DEMO_GAP_REPORT.total_gaps,
      critical_gaps: DEMO_GAP_REPORT.critical_gaps,
      coverage_percentage: DEMO_GAP_REPORT.coverage_percentage,
    },
    {
      key: "meridian-fintech-v2:pr-branch",
      mtime_iso: DEMO_GAP_REPORT_PR.analyzed_at,
      size_bytes: 511_038,
      organization: DEMO_GAP_REPORT_PR.organization,
      frameworks_analyzed: DEMO_GAP_REPORT_PR.frameworks_analyzed,
      total_gaps: DEMO_GAP_REPORT_PR.total_gaps,
      critical_gaps: DEMO_GAP_REPORT_PR.critical_gaps,
      coverage_percentage: DEMO_GAP_REPORT_PR.coverage_percentage,
    },
  ],
};

/** baseline → pr-branch diff: one critical + one medium gap closed, none opened. */
export const DEMO_GAP_DIFF: GapDiff = {
  id: "meridian-fintech-v2-diff",
  generated_at: "2026-04-26T09:13:40.000000Z",
  base_organization: "Meridian Financial",
  base_inventory_source: "my-controls.yaml",
  head_organization: "Meridian Financial",
  head_inventory_source: "my-controls.yaml",
  frameworks_analyzed: ["nist-800-53-rev5-moderate", "soc2-tsc"],
  summary: {
    closed: 2,
    opened: 0,
    severity_increased: 0,
    severity_decreased: 0,
    unchanged: 309,
  },
  entries: [
    {
      framework: "nist-800-53-rev5-moderate",
      control_id: "AU-2",
      control_title: "Event Logging",
      status: "closed",
      base_severity: "critical",
      head_severity: null,
      base_priority: 6.0,
      head_priority: null,
      gap_description: null,
      remediation_guidance: null,
    },
    {
      framework: "nist-800-53-rev5-moderate",
      control_id: "AT-2",
      control_title: "Literacy Training and Awareness",
      status: "closed",
      base_severity: "medium",
      head_severity: null,
      base_priority: 2.1,
      head_priority: null,
      gap_description: null,
      remediation_guidance: null,
    },
  ],
};

const MILESTONE = (
  id: string,
  description: string,
  target_date: string,
  status: components["schemas"]["POAMState"],
): Milestone => ({
  id,
  description,
  target_date,
  status,
  owner: "grc@meridian.example",
  reviewer: null,
  evidence_ref: null,
});

/**
 * POA&M list — the critical gaps as remediation items, each carrying a
 * milestone timeline. Items are the same `ControlGap` rows, widened with
 * `poam_milestones` (the seam `PoamPage` reads).
 */
const DEMO_POAM_ITEMS: PoamGap[] = DEMO_GAPS.filter(
  (g) => g.gap_severity === "critical",
).map((g, i) => ({
  ...g,
  poam_milestones: [
    MILESTONE(
      `${g.id}-ms-1`,
      `Scope and assign an owner for ${g.control_id} (${g.control_title}).`,
      "2026-07-15",
      i % 2 === 0 ? "in_progress" : "planned",
    ),
    MILESTONE(
      `${g.id}-ms-2`,
      `Implement and collect evidence for ${g.control_id}.`,
      "2026-09-30",
      "planned",
    ),
  ],
}));

export const DEMO_POAM: PoamListResponse = {
  total: DEMO_POAM_ITEMS.length,
  items: DEMO_POAM_ITEMS,
};

/** TPRM vendor register — a cloud platform, a data processor, and an auditor. */
export const DEMO_VENDORS: VendorListResponse = {
  total: 3,
  vendors: [
    {
      id: "demo-vendor-okta",
      name: "Okta, Inc.",
      type: "cloud_provider",
      criticality_tier: "critical",
      relationship_owner: "iam-lead@meridian.example",
      contract_start_date: "2024-01-01",
      contract_end_date: "2026-12-31",
      region: "us-east-1",
      residual_risk_score: 6,
      last_due_diligence_review: "2026-01-15",
      next_review_due: "2027-01-15",
      notes: "Primary workforce identity provider (SSO + MFA).",
      evidentia_version: EVIDENTIA_VERSION,
    } satisfies Vendor,
    {
      id: "demo-vendor-snowflake",
      name: "Snowflake Inc.",
      type: "data_processor",
      criticality_tier: "high",
      relationship_owner: "data-platform@meridian.example",
      contract_start_date: "2024-03-01",
      contract_end_date: null,
      region: "us-west-2",
      residual_risk_score: 9,
      last_due_diligence_review: "2025-11-01",
      next_review_due: "2026-11-01",
      notes: "Cloud data warehouse holding customer transaction data.",
      evidentia_version: EVIDENTIA_VERSION,
    } satisfies Vendor,
    {
      id: "demo-vendor-auditor",
      name: "Harborline Assurance LLP",
      type: "contractor",
      criticality_tier: "low",
      relationship_owner: "compliance@meridian.example",
      contract_start_date: "2025-06-01",
      contract_end_date: "2026-06-01",
      region: "US",
      residual_risk_score: 2,
      last_due_diligence_review: "2025-06-01",
      next_review_due: "2028-06-01",
      notes: "Independent SOC 2 / financial-statement auditor.",
      evidentia_version: EVIDENTIA_VERSION,
    } satisfies Vendor,
  ],
};

/**
 * Continuous-monitoring cadences — the read-only flat string maps the API
 * returns. Six representative cadences across the two analyzed frameworks.
 */
export const DEMO_CONMON: ConmonCadence[] = [
  {
    framework: "nist-800-53-rev5-moderate",
    control_id: "AU-6",
    cadence: "monthly",
    activity: "Audit-log review",
    last_completed: "2026-04-01",
    next_due: "2026-05-01",
  },
  {
    framework: "nist-800-53-rev5-moderate",
    control_id: "RA-5",
    cadence: "weekly",
    activity: "Vulnerability scan",
    last_completed: "2026-04-12",
    next_due: "2026-04-19",
  },
  {
    framework: "nist-800-53-rev5-moderate",
    control_id: "AC-2",
    cadence: "quarterly",
    activity: "Access recertification",
    last_completed: "2026-01-31",
    next_due: "2026-04-30",
  },
  {
    framework: "nist-800-53-rev5-moderate",
    control_id: "CA-2",
    cadence: "annual",
    activity: "Control assessment",
    last_completed: "2025-09-15",
    next_due: "2026-09-15",
  },
  {
    framework: "soc2-tsc",
    control_id: "CC7.2",
    cadence: "monthly",
    activity: "Security-monitoring review",
    last_completed: "2026-04-01",
    next_due: "2026-05-01",
  },
  {
    framework: "soc2-tsc",
    control_id: "CC4.1",
    cadence: "annual",
    activity: "Type II readiness review",
    last_completed: "2025-10-01",
    next_due: "2026-10-01",
  },
];

/** The Meridian config the Settings screen renders. */
export const DEMO_CONFIG: EvidentiaConfig = {
  organization: "Meridian Financial",
  system_name: "Meridian Core Banking Platform",
  frameworks: ["nist-800-53-rev5-moderate", "soc2-tsc", "eu-gdpr"],
  llm: { model: null, temperature: null },
  source_path: "evidentia.yaml",
};

/** Probe / identity fixtures. */
export const DEMO_HEALTH: HealthResponse = {
  status: "ok",
  version: EVIDENTIA_VERSION,
  auth_configured: true,
};

export const DEMO_VERSION: VersionResponse = {
  api_version: EVIDENTIA_VERSION,
  core_version: EVIDENTIA_VERSION,
  ai_version: EVIDENTIA_VERSION,
  python_version: "3.13.5",
};

/**
 * No LLM provider configured — air-gap-honest. The demo runs with zero
 * credentials, so the Explain/Settings screens correctly show "not configured".
 */
export const DEMO_LLM_STATUS: LlmStatusResponse = {
  providers: {
    anthropic: { configured: false, source: null },
    openai: { configured: false, source: null },
    ollama: { configured: false, source: null },
  },
  configured_model: "claude-3-5-sonnet-latest",
};

/** A baked AC-2 explanation — the `done` SSE frame the demo Explain route emits. */
export const DEMO_EXPLANATION: Explanation = {
  framework_id: "nist-800-53-rev5-moderate",
  control_id: "AC-2",
  control_title: "Account Management",
  plain_english:
    "AC-2 is about knowing who has accounts on your systems and making sure each account is supposed to exist. You define who can request accounts, who approves them, and the rules for creating, enabling, disabling, and removing them — then you actually follow those rules and review the accounts on a schedule.",
  why_it_matters:
    "Stale and orphaned accounts are one of the most common ways attackers get a foothold — a former contractor's login, a shared service account nobody owns, an admin account that should have been removed months ago. Tight account management shrinks that attack surface and is foundational to almost every other access control.",
  what_to_do: [
    "Write down the account types you allow and who owns the approval for each.",
    "Automate account creation/disable/removal off your HR or identity source so departures are handled the same day.",
    "Recertify accounts at least quarterly — every account should map to a current, authorized person or system.",
    "Alert on dormant and never-logged-in accounts and disable them automatically.",
  ],
  effort_estimate:
    "Medium. The policy is quick to draft; the work is wiring account lifecycle to an authoritative identity source and standing up the recurring recertification.",
  common_misconceptions:
    "AC-2 is not just 'turn on SSO'. SSO helps authentication, but AC-2 is about the full lifecycle and periodic review of every account — including service and break-glass accounts that often sit outside SSO.",
  generation_context: { model: null },
};

/** Air-gap check — fully air-gapped: every subsystem reports no outbound leak. */
export const DEMO_AIRGAP: AirGapCheckResponse = {
  air_gapped: true,
  checks: [
    {
      subsystem: "llm",
      status: "ok",
      detail: "No LLM provider configured; no outbound model calls possible.",
    },
    {
      subsystem: "collectors",
      status: "ok",
      detail: "No collectors enabled; no outbound integration traffic.",
    },
    {
      subsystem: "catalogs",
      status: "ok",
      detail: "All framework catalogs are bundled locally; no network fetch.",
    },
    {
      subsystem: "telemetry",
      status: "ok",
      detail: "Telemetry is disabled; nothing is reported externally.",
    },
  ],
};

/**
 * The bundled framework catalog the demo references — 10 real entries from the
 * manifest, including the two the hero report analyzes. `placeholder` /
 * `license_required` are lowercase strings, exactly as the API serializes them.
 */
export const DEMO_FRAMEWORKS: FrameworkListResponse = {
  total: 10,
  frameworks: [
    {
      id: "nist-800-53-rev5-moderate",
      name: "NIST SP 800-53 Rev 5 Moderate Baseline",
      version: "5.2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "nist-800-53-rev5-high",
      name: "NIST SP 800-53 Rev 5 High Baseline",
      version: "5.2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "nist-800-53-rev5-low",
      name: "NIST SP 800-53 Rev 5 Low Baseline",
      version: "5.2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "nist-csf-2.0",
      name: "NIST Cybersecurity Framework 2.0",
      version: "2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "fedramp-rev5-moderate",
      name: "FedRAMP Rev 5 Moderate Baseline",
      version: "Rev 5 (profiles published 2024-09-24)",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "cmmc-2-l2",
      name: "CMMC 2.0 Level 2 (Advanced)",
      version: "2.0 (2024 Final Rule)",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
      text_depth: "headings",
    },
    {
      id: "eu-gdpr",
      name: "EU General Data Protection Regulation (GDPR)",
      version: "Regulation (EU) 2016/679",
      tier: "D",
      category: "obligation",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "mitre-attack-enterprise",
      name: "MITRE ATT&CK Enterprise",
      version: "v15.1 (2024)",
      tier: "B",
      category: "technique",
      placeholder: "false",
      license_required: "false",
      text_depth: "full",
    },
    {
      id: "soc2-tsc",
      name: "SOC 2 Trust Services Criteria (stub)",
      version: "2017 (with 2022 Points of Focus revisions)",
      tier: "C",
      category: "control",
      placeholder: "true",
      license_required: "true",
      text_depth: "headings",
    },
    {
      id: "iso-27001-2022",
      name: "ISO/IEC 27001:2022 (Annex A controls)",
      version: "2022",
      tier: "C",
      category: "control",
      placeholder: "true",
      license_required: "true",
      text_depth: "headings",
    },
  ],
};

/** Authored synthetic example; no tenant observation or live validation. */
export const DEMO_ENTRA_M365_PARTIAL: EntraM365CollectResult = {
  schema_version: "entra-m365-collection/v1",
  status: "partial",
  requested_capabilities: [
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
  ],
  full_surface_complete: false,
  provenance: {
    tenant_label: "synthetic-demo",
    identity_basis: "operator-declared",
    authenticated_identity_verified: false,
    graph_cloud: "commercial",
  },
  capabilities: [
    {
      name: "conditional-access",
      state: "complete",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 1,
      matched_filter: 1,
      collected: 1,
      duplicate_records: 0,
      pages_completed: 1,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {
        id: {
          absent: 0,
          null: 0,
          known: 1,
          unknown: 0,
        },
        state: {
          absent: 0,
          null: 0,
          known: 1,
          unknown: 0,
        },
        conditions: {
          absent: 1,
          null: 0,
          known: 0,
          unknown: 0,
        },
        grantControls: {
          absent: 1,
          null: 0,
          known: 0,
          unknown: 0,
        },
        sessionControls: {
          absent: 1,
          null: 0,
          known: 0,
          unknown: 0,
        },
      },
      diagnostics: [],
    },
    {
      name: "authentication-registration",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "sign-ins",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "directory-roles",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "managed-devices",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "retention-labels",
      state: "unavailable",
      credential_basis: "unverified:retention-token",
      declared_auth_mode: "delegated",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "dlp-export",
      state: "unavailable",
      credential_basis: "unverified:dlp-export",
      declared_auth_mode: null,
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 0,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "input_missing",
          count: 1,
          http_status: null,
        },
      ],
    },
    {
      name: "defender-alerts",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "defender-incidents",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
  ],
  findings: [
    {
      id: "ed2baf50-814e-5830-b343-e996715c2ab6",
      title: "Conditional Access policy configuration",
      description:
        "Observed access-policy configuration. Effective identity and application coverage is not established.",
      severity: "informational",
      status: "active",
      compliance_status: "unknown",
      remediation: null,
      source_system: "entra-m365",
      source_finding_id: "synthetic-demo:conditional-access:synthetic-policy",
      resource_type: "MicrosoftEntra::ConditionalAccessPolicy",
      resource_id: "synthetic-policy",
      resource_region: null,
      resource_account: "synthetic-demo",
      control_mappings: [
        {
          framework: "nist-800-53-rev5",
          control_id: "AC-3",
          control_title: null,
          relationship: "intersects-with",
          justification:
            "observed access-policy configuration does not establish effective identity/application coverage.",
        },
        {
          framework: "nist-800-53-rev5",
          control_id: "IA-2",
          control_title: null,
          relationship: "intersects-with",
          justification:
            "observed access-policy configuration does not establish effective identity/application coverage.",
        },
      ],
      collection_context: {
        collector_id: "entra-m365-scan",
        collector_version: "0.12.1",
        run_id: "synthetic-demo-partial",
        collected_at: "2026-09-10T00:00:00Z",
        credential_identity: "unverified:primary-token",
        source_system_id: "entra-m365:operator-label:synthetic-demo",
        filter_applied: {
          tenant_label: "synthetic-demo",
          identity_basis: "operator-declared",
          authenticated_identity_verified: false,
          graph_cloud: "commercial",
          capabilities: [
            "conditional-access",
            "authentication-registration",
            "sign-ins",
            "directory-roles",
            "managed-devices",
            "retention-labels",
            "dlp-export",
            "defender-alerts",
            "defender-incidents",
          ],
          lookback_days: 30,
          max_items: 10000,
          max_pages: 100,
          capability: "conditional-access",
          requested_window_start: null,
          requested_window_end: null,
        },
        pagination_context: {
          page_size: null,
          page_number: null,
          total_pages: 1,
          continuation_token: null,
          is_complete: true,
        },
        evidentia_version: "0.12.1",
      },
      raw_data: {
        observation: {
          configuration_state: "report_only",
        },
        source: {
          id: "synthetic-policy",
          state: "enabledForReportingButNotEnforced",
        },
      },
      first_observed: "2026-09-10T00:00:00.000000Z",
      last_observed: "2026-09-10T00:00:00.000000Z",
      resolved_at: null,
    },
  ],
  manifest: {
    run_id: "synthetic-demo-partial",
    collector_id: "entra-m365-scan",
    collector_version: "0.12.1",
    collection_started_at: "2026-09-10T00:00:00Z",
    collection_finished_at: "2026-09-10T00:00:00Z",
    source_system_ids: ["entra-m365:operator-label:synthetic-demo"],
    filters_applied: {
      tenant_label: "synthetic-demo",
      identity_basis: "operator-declared",
      authenticated_identity_verified: false,
      graph_cloud: "commercial",
      capabilities: [
        "conditional-access",
        "authentication-registration",
        "sign-ins",
        "directory-roles",
        "managed-devices",
        "retention-labels",
        "dlp-export",
        "defender-alerts",
        "defender-incidents",
      ],
      lookback_days: 30,
      max_items: 10000,
      max_pages: 100,
    },
    coverage_counts: [
      {
        resource_type: "conditional-access",
        scanned: 1,
        matched_filter: 1,
        collected: 1,
      },
      {
        resource_type: "authentication-registration",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "sign-ins",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "directory-roles",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "managed-devices",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "retention-labels",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "dlp-export",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "defender-alerts",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "defender-incidents",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
    ],
    total_findings: 1,
    is_complete: false,
    incomplete_reason:
      "authentication-registration:permission_denied:403; sign-ins:permission_denied:403; directory-roles:permission_denied:403; managed-devices:permission_denied:403; retention-labels:permission_denied:403; dlp-export:input_missing; defender-alerts:permission_denied:403; defender-incidents:permission_denied:403",
    empty_categories: [],
    warnings: [
      "conditional-access: unknown source values retained",
      "sign-ins: source scope and retention limit the observation",
      "defender-alerts: source scope and retention limit the observation",
      "defender-incidents: source scope and retention limit the observation",
    ],
    errors: [
      "authentication-registration:permission_denied:403",
      "sign-ins:permission_denied:403",
      "directory-roles:permission_denied:403",
      "managed-devices:permission_denied:403",
      "retention-labels:permission_denied:403",
      "dlp-export:input_missing",
      "defender-alerts:permission_denied:403",
      "defender-incidents:permission_denied:403",
    ],
    evidentia_version: "0.12.1",
  },
};

/** Authored synthetic example; no tenant observation or live validation. */
export const DEMO_ENTRA_M365_UNAVAILABLE: EntraM365CollectResult = {
  schema_version: "entra-m365-collection/v1",
  status: "unavailable",
  requested_capabilities: [
    "conditional-access",
    "authentication-registration",
    "sign-ins",
    "directory-roles",
    "managed-devices",
    "retention-labels",
    "dlp-export",
    "defender-alerts",
    "defender-incidents",
  ],
  full_surface_complete: false,
  provenance: {
    tenant_label: "synthetic-demo",
    identity_basis: "operator-declared",
    authenticated_identity_verified: false,
    graph_cloud: "commercial",
  },
  capabilities: [
    {
      name: "conditional-access",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "authentication-registration",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "sign-ins",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "directory-roles",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "managed-devices",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "retention-labels",
      state: "unavailable",
      credential_basis: "unverified:retention-token",
      declared_auth_mode: "delegated",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "dlp-export",
      state: "unavailable",
      credential_basis: "unverified:dlp-export",
      declared_auth_mode: null,
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 0,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: null,
      requested_window_end: null,
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "input_missing",
          count: 1,
          http_status: null,
        },
      ],
    },
    {
      name: "defender-alerts",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
    {
      name: "defender-incidents",
      state: "unavailable",
      credential_basis: "unverified:primary-token",
      declared_auth_mode: "application",
      scanned: 0,
      matched_filter: 0,
      collected: 0,
      duplicate_records: 0,
      pages_completed: 0,
      requests_attempted: 1,
      started_at: "2026-09-10T00:00:00.000000Z",
      finished_at: "2026-09-10T00:00:00.000000Z",
      requested_window_start: "2026-08-11T00:00:00.000000Z",
      requested_window_end: "2026-09-10T00:00:00.000000Z",
      observed_first: null,
      observed_last: null,
      field_coverage: {},
      diagnostics: [
        {
          code: "permission_denied",
          count: 1,
          http_status: 403,
        },
      ],
    },
  ],
  findings: [],
  manifest: {
    run_id: "synthetic-demo-unavailable",
    collector_id: "entra-m365-scan",
    collector_version: "0.12.1",
    collection_started_at: "2026-09-10T00:00:00Z",
    collection_finished_at: "2026-09-10T00:00:00Z",
    source_system_ids: ["entra-m365:operator-label:synthetic-demo"],
    filters_applied: {
      tenant_label: "synthetic-demo",
      identity_basis: "operator-declared",
      authenticated_identity_verified: false,
      graph_cloud: "commercial",
      capabilities: [
        "conditional-access",
        "authentication-registration",
        "sign-ins",
        "directory-roles",
        "managed-devices",
        "retention-labels",
        "dlp-export",
        "defender-alerts",
        "defender-incidents",
      ],
      lookback_days: 30,
      max_items: 10000,
      max_pages: 100,
    },
    coverage_counts: [
      {
        resource_type: "conditional-access",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "authentication-registration",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "sign-ins",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "directory-roles",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "managed-devices",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "retention-labels",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "dlp-export",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "defender-alerts",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
      {
        resource_type: "defender-incidents",
        scanned: 0,
        matched_filter: 0,
        collected: 0,
      },
    ],
    total_findings: 0,
    is_complete: false,
    incomplete_reason:
      "conditional-access:permission_denied:403; authentication-registration:permission_denied:403; sign-ins:permission_denied:403; directory-roles:permission_denied:403; managed-devices:permission_denied:403; retention-labels:permission_denied:403; dlp-export:input_missing; defender-alerts:permission_denied:403; defender-incidents:permission_denied:403",
    empty_categories: [],
    warnings: [
      "sign-ins: source scope and retention limit the observation",
      "defender-alerts: source scope and retention limit the observation",
      "defender-incidents: source scope and retention limit the observation",
    ],
    errors: [
      "conditional-access:permission_denied:403",
      "authentication-registration:permission_denied:403",
      "sign-ins:permission_denied:403",
      "directory-roles:permission_denied:403",
      "managed-devices:permission_denied:403",
      "retention-labels:permission_denied:403",
      "dlp-export:input_missing",
      "defender-alerts:permission_denied:403",
      "defender-incidents:permission_denied:403",
    ],
    evidentia_version: "0.12.1",
  },
};

/** Synthetic session results; no provider was contacted. Native tokens stay in wire text. */
export const ENTERPRISE_RETENTION_DEMO = {
  "google-vault": {
    "complete": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "google-vault",
        "targets": [
          {
            "matter_id": "matter-0"
          },
          {
            "matter_id": "matter-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"scope_label\":\"synthetic\",\"target\":{\"matter_id\":\"matter-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":100,\"total_pages\":2},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/google-vault/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected matter and hold configuration; retention rules and held-record coverage are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"8d16caa8-50f2-5766-aca1-5f290a07aa7d\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"2a0447828d71d2cb0fc1643a03b8d2d9b519934694ba551f4462b493cbb50556\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"3a1a06f9f955e3a25c1e2ce071df9b00c99ae89e22f05d212aad0143186a6f1e\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"resource_region\":null,\"resource_type\":\"GoogleVault::Matter\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Google Vault matter and hold configuration\"},{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"scope_label\":\"synthetic\",\"target\":{\"matter_id\":\"matter-1\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":100,\"total_pages\":2},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/google-vault/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected matter and hold configuration; retention rules and held-record coverage are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"62640d90-e015-5f17-836c-8fe76362bc5b\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"0dd7a328cb2dfe830c3a865608319fed0acf58678705616ae52d1ae52cac3375\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"5097a6f9158dd478292e68123f0e81a68b257545d551678854db57d21db07b48\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-1\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-1\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-1\",\"resource_region\":null,\"resource_type\":\"GoogleVault::Matter\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/google-vault/selected/matter/matter-1\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Google Vault matter and hold configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":4,\"canonical_observation_bytes\":2354,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":596,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":2,\"pages_admitted\":4,\"pages_received\":4,\"raw_bytes\":596,\"reads_attempted\":4,\"reads_completed\":4,\"reads_planned\":4,\"records_admitted\":4,\"records_received\":4,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":4,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"complete\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"enterprise-retention/google-vault/selected/vault-holds/matter-0\"],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-0\"}},{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"enterprise-retention/google-vault/selected/vault-holds/matter-1\"],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-1\"}}],\"retention_rules_assessed\":false,\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":41,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"05ba5de56f66af8ff663d99c4bee1fc18994f55919592be4f02a9926e09c4876\",\"diagnostics\":[],\"field_coverage\":{\"matterId\":\"known\",\"state\":\"known\"},\"fields\":{\"matterId\":\"matter-0\",\"state\":\"OPEN\"},\"interpretation_status\":\"known\",\"native_scope\":\"matter\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"matter-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":41,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":257,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"bc9a24fe8f0ff632957ae220014a0dff5d88c8c269cc5f12b69459240fac0ddd\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"safe_http_status\":200}],\"field_coverage\":{\"accounts\":\"known\",\"corpus\":\"known\",\"holdId\":\"known\",\"name\":\"absent\",\"orgUnit\":\"absent\",\"query\":\"known\",\"updateTime\":\"absent\"},\"fields\":{\"accounts\":[{\"accountId\":\"synthetic-account\",\"holdTime\":\"2026-01-01T00:00:00.123456789Z\"}],\"corpus\":\"MAIL\",\"holdId\":\"hold-matter-0\",\"query\":{\"mailQuery\":{\"startTime\":\"2026-01-01T00:00:00.123456789Z\",\"terms\":\"<synthetic-query>\"}}},\"interpretation_status\":\"limited\",\"native_scope\":\"hold\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"hold-matter-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":257,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":41,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"5e77848faf3e3bf8e8c26747c8dd97cdb902984ae6cb9677c382f93df73eef84\",\"diagnostics\":[],\"field_coverage\":{\"matterId\":\"known\",\"state\":\"known\"},\"fields\":{\"matterId\":\"matter-1\",\"state\":\"OPEN\"},\"interpretation_status\":\"known\",\"native_scope\":\"matter\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"matter-1\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":41,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":257,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"9fb13b01799c51942fac162bbd59f80eca75b7c69d34a69f77cdab6ad2e9d361\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-1\",\"safe_http_status\":200}],\"field_coverage\":{\"accounts\":\"known\",\"corpus\":\"known\",\"holdId\":\"known\",\"name\":\"absent\",\"orgUnit\":\"absent\",\"query\":\"known\",\"updateTime\":\"absent\"},\"fields\":{\"accounts\":[{\"accountId\":\"synthetic-account\",\"holdTime\":\"2026-01-01T00:00:00.123456789Z\"}],\"corpus\":\"MAIL\",\"holdId\":\"hold-matter-1\",\"query\":{\"mailQuery\":{\"startTime\":\"2026-01-01T00:00:00.123456789Z\",\"terms\":\"<synthetic-query>\"}}},\"interpretation_status\":\"limited\",\"native_scope\":\"hold\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"hold-matter-1\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":257,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-1\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"unassessed_surfaces\":[\"default_retention_rules\",\"custom_retention_rules\",\"held_record_coverage\"]}"
    },
    "partial": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "google-vault",
        "targets": [
          {
            "matter_id": "matter-0"
          },
          {
            "matter_id": "matter-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"scope_label\":\"synthetic\",\"target\":{\"matter_id\":\"matter-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":100,\"total_pages\":2},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/google-vault/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected matter and hold configuration; retention rules and held-record coverage are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"8d16caa8-50f2-5766-aca1-5f290a07aa7d\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"2a0447828d71d2cb0fc1643a03b8d2d9b519934694ba551f4462b493cbb50556\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"3a1a06f9f955e3a25c1e2ce071df9b00c99ae89e22f05d212aad0143186a6f1e\",\"observations\":1,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"resource_region\":null,\"resource_type\":\"GoogleVault::Matter\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Google Vault matter and hold configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":3,\"canonical_observation_bytes\":1177,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":298,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":1,\"pages_admitted\":2,\"pages_received\":2,\"raw_bytes\":298,\"reads_attempted\":3,\"reads_completed\":2,\"reads_planned\":4,\"records_admitted\":2,\"records_received\":2,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":3,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"partial\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"enterprise-retention/google-vault/selected/vault-holds/matter-0\"],\"status\":\"complete\",\"target\":{\"matter_id\":\"matter-0\"}},{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"enterprise-retention/google-vault/selected/vault-holds/matter-1\"],\"status\":\"unavailable\",\"target\":{\"matter_id\":\"matter-1\"}}],\"retention_rules_assessed\":false,\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":41,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"05ba5de56f66af8ff663d99c4bee1fc18994f55919592be4f02a9926e09c4876\",\"diagnostics\":[],\"field_coverage\":{\"matterId\":\"known\",\"state\":\"known\"},\"fields\":{\"matterId\":\"matter-0\",\"state\":\"OPEN\"},\"interpretation_status\":\"known\",\"native_scope\":\"matter\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"matter-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":41,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":257,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[{\"api_version\":\"v1\",\"canonical_projection_sha256\":\"bc9a24fe8f0ff632957ae220014a0dff5d88c8c269cc5f12b69459240fac0ddd\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"safe_http_status\":200}],\"field_coverage\":{\"accounts\":\"known\",\"corpus\":\"known\",\"holdId\":\"known\",\"name\":\"absent\",\"orgUnit\":\"absent\",\"query\":\"known\",\"updateTime\":\"absent\"},\"fields\":{\"accounts\":[{\"accountId\":\"synthetic-account\",\"holdTime\":\"2026-01-01T00:00:00.123456789Z\"}],\"corpus\":\"MAIL\",\"holdId\":\"hold-matter-0\",\"query\":{\"mailQuery\":{\"startTime\":\"2026-01-01T00:00:00.123456789Z\",\"terms\":\"<synthetic-query>\"}}},\"interpretation_status\":\"limited\",\"native_scope\":\"hold\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"hold-matter-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":257,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"matter-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"matter-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":0,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":null,\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":0,\"safe_http_status\":null,\"source_id\":\"matter-1\",\"started_at\":null,\"status\":\"unavailable\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"partial\",\"unassessed_surfaces\":[\"default_retention_rules\",\"custom_retention_rules\",\"held_record_coverage\"]}"
    },
    "unavailable": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "google-vault",
        "targets": [
          {
            "matter_id": "matter-0"
          },
          {
            "matter_id": "matter-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"vault-holds/accounts\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/corpus\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/holdId\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/name\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/orgUnit\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/query\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-holds/updateTime\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/matterId\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"vault-matter/state\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0}},\"findings\":[],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":2,\"canonical_observation_bytes\":0,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":0,\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"reads_attempted\":2,\"reads_completed\":0,\"reads_planned\":4,\"records_admitted\":0,\"records_received\":0,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":2,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"unavailable\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"google-vault\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"enterprise-retention/google-vault/selected/vault-holds/matter-0\"],\"status\":\"unavailable\",\"target\":{\"matter_id\":\"matter-0\"}},{\"canonical_resource_id\":\"enterprise-retention/google-vault/selected/matter/matter-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"enterprise-retention/google-vault/selected/vault-holds/matter-1\"],\"status\":\"unavailable\",\"target\":{\"matter_id\":\"matter-1\"}}],\"retention_rules_assessed\":false,\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-0\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"matter-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":0,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":null,\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-0\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":0,\"safe_http_status\":null,\"source_id\":\"matter-0\",\"started_at\":null,\"status\":\"unavailable\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"vault-matter\",\"method_id\":\"vault.matters.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-matter/matter-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"matter-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":0,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":null,\"kind\":\"vault-holds\",\"method_id\":\"vault.matters.holds.list\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/google-vault/selected/vault-holds/matter-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":0,\"safe_http_status\":null,\"source_id\":\"matter-1\",\"started_at\":null,\"status\":\"unavailable\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"unassessed_surfaces\":[\"default_retention_rules\",\"custom_retention_rules\",\"held_record_coverage\"]}"
    }
  },
  "splunk-enterprise": {
    "complete": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "splunk-enterprise",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":1},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/splunk-enterprise/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index configuration; event coverage and archival execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"d22294d3-922b-50ef-a7d1-19c66dbad48a\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"e312ab85dc044664aed377e5d748a89d56935b49e8688376dd893a846691bf8c\",\"observations\":1,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"resource_region\":null,\"resource_type\":\"SplunkEnterprise::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Splunk Enterprise index retention configuration\"},{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-1\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":1},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/splunk-enterprise/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index configuration; event coverage and archival execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"69bc0e96-1c6b-55e2-8e40-f2853d770ce4\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"5cd34b981b4f4d30f8b33307e79e9bb42fde1bd5552f27234add6a23f9fa8b50\",\"observations\":1,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-1\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-1\",\"resource_region\":null,\"resource_type\":\"SplunkEnterprise::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-1\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Splunk Enterprise index retention configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":2,\"canonical_observation_bytes\":1372,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":420,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":2,\"pages_admitted\":2,\"pages_received\":2,\"raw_bytes\":420,\"reads_attempted\":2,\"reads_completed\":2,\"reads_planned\":2,\"records_admitted\":2,\"records_received\":2,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":2,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"complete\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\"],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\"],\"status\":\"complete\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":210,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[{\"api_version\":\"splunk-enterprise-10.4\",\"canonical_projection_sha256\":\"d45da27e58f8cbab04bad0d2f06378504552a31d8370bc6d8a596f616c0f0cd0\",\"diagnostics\":[],\"field_coverage\":{\"coldToFrozenDir\":\"known\",\"coldToFrozenScript\":\"known\",\"datatype\":\"known\",\"disabled\":\"known\",\"frozenTimePeriodInSecs\":\"known\",\"maxTotalDataSizeMB\":\"known\",\"name\":\"known\"},\"fields\":{\"coldToFrozenDirState\":\"empty\",\"coldToFrozenScriptState\":\"empty\",\"datatype\":\"event\",\"disabled\":false,\"frozenTimePeriodInSecs\":9007199254740993,\"maxTotalDataSizeMB\":\"00042\",\"name\":\"events-0\"},\"interpretation_status\":\"known\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":210,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":210,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[{\"api_version\":\"splunk-enterprise-10.4\",\"canonical_projection_sha256\":\"4c501f1c62a988180f11ee9c30956d2fd6634423973006fea1419b277e0f7c8f\",\"diagnostics\":[],\"field_coverage\":{\"coldToFrozenDir\":\"known\",\"coldToFrozenScript\":\"known\",\"datatype\":\"known\",\"disabled\":\"known\",\"frozenTimePeriodInSecs\":\"known\",\"maxTotalDataSizeMB\":\"known\",\"name\":\"known\"},\"fields\":{\"coldToFrozenDirState\":\"empty\",\"coldToFrozenScriptState\":\"empty\",\"datatype\":\"event\",\"disabled\":false,\"frozenTimePeriodInSecs\":9007199254740993,\"maxTotalDataSizeMB\":\"00042\",\"name\":\"events-1\"},\"interpretation_status\":\"known\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-1\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":210,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"unassessed_surfaces\":[\"event_coverage\",\"archive_execution_and_durability\",\"smartstore_and_volume_configuration\",\"cluster_wide_configuration\"]}"
    },
    "partial": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "splunk-enterprise",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":1},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/splunk-enterprise/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index configuration; event coverage and archival execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"d22294d3-922b-50ef-a7d1-19c66dbad48a\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"not_applicable\",\"reads\":[{\"observation_digests_sha256\":\"e312ab85dc044664aed377e5d748a89d56935b49e8688376dd893a846691bf8c\",\"observations\":1,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"resource_region\":null,\"resource_type\":\"SplunkEnterprise::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Splunk Enterprise index retention configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":2,\"canonical_observation_bytes\":686,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":210,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":1,\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":210,\"reads_attempted\":2,\"reads_completed\":1,\"reads_planned\":2,\"records_admitted\":1,\"records_received\":1,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":2,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"partial\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\"],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\"],\"status\":\"unavailable\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":210,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[{\"api_version\":\"splunk-enterprise-10.4\",\"canonical_projection_sha256\":\"d45da27e58f8cbab04bad0d2f06378504552a31d8370bc6d8a596f616c0f0cd0\",\"diagnostics\":[],\"field_coverage\":{\"coldToFrozenDir\":\"known\",\"coldToFrozenScript\":\"known\",\"datatype\":\"known\",\"disabled\":\"known\",\"frozenTimePeriodInSecs\":\"known\",\"maxTotalDataSizeMB\":\"known\",\"name\":\"known\"},\"fields\":{\"coldToFrozenDirState\":\"empty\",\"coldToFrozenScriptState\":\"empty\",\"datatype\":\"event\",\"disabled\":false,\"frozenTimePeriodInSecs\":9007199254740993,\"maxTotalDataSizeMB\":\"00042\",\"name\":\"events-0\"},\"interpretation_status\":\"known\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":210,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"partial\",\"unassessed_surfaces\":[\"event_coverage\",\"archive_execution_and_durability\",\"smartstore_and_volume_configuration\",\"cluster_wide_configuration\"]}"
    },
    "unavailable": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "splunk-enterprise",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"splunk-index/coldToFrozenDir\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/coldToFrozenScript\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/datatype\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/disabled\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/frozenTimePeriodInSecs\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/maxTotalDataSizeMB\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"splunk-index/name\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0}},\"findings\":[],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":2,\"canonical_observation_bytes\":0,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":0,\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"reads_attempted\":2,\"reads_completed\":0,\"reads_planned\":2,\"records_admitted\":0,\"records_received\":0,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":2,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"unavailable\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"splunk-enterprise\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\"],\"status\":\"unavailable\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/splunk-enterprise/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"not_applicable\",\"read_ids\":[\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\"],\"status\":\"unavailable\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-0\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"splunk-index\",\"method_id\":\"splunk.data.indexes.get\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/splunk-enterprise/selected/splunk-index/events-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"unassessed_surfaces\":[\"event_coverage\",\"archive_execution_and_durability\",\"smartstore_and_volume_configuration\",\"cluster_wide_configuration\"]}"
    }
  },
  "elastic-ilm": {
    "complete": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "elastic-ilm",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":2,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":2,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":3},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/elastic-ilm/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index, service and current policy configuration; document coverage and lifecycle execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"a1e5e603-62bc-593b-9df1-5a1c8abf0570\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"resolved\",\"reads\":[{\"observation_digests_sha256\":\"f7ecbc1aef2244787c24cc4e4072c0f6dddaf7784a134d47b1a92ea23247e2dd\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"fad959608b4a163ca42f759b7531cef17bf95911a03cf1224a78a284051872b0\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"40a6931e9e577e5f9e249dc1db9e9853eacdb4a099939e3763aabe510376f1c6\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"resource_region\":null,\"resource_type\":\"ElasticsearchILM::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Elasticsearch ILM configuration\"},{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-1\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":3},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/elastic-ilm/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index, service and current policy configuration; document coverage and lifecycle execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"719ad45d-60dc-54b2-a090-405566a7dcdc\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"resolved\",\"reads\":[{\"observation_digests_sha256\":\"8646227da49096773e154a14c441dd426f5c1fb38de56dd2518270ed5c385d46\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"fad959608b4a163ca42f759b7531cef17bf95911a03cf1224a78a284051872b0\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"40a6931e9e577e5f9e249dc1db9e9853eacdb4a099939e3763aabe510376f1c6\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-1\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-1\",\"resource_region\":null,\"resource_type\":\"ElasticsearchILM::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/elastic-ilm/selected/index/events-1\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Elasticsearch ILM configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":4,\"canonical_observation_bytes\":3074,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":843,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":2,\"pages_admitted\":4,\"pages_received\":4,\"raw_bytes\":843,\"reads_attempted\":4,\"reads_completed\":4,\"reads_planned\":4,\"records_admitted\":4,\"records_received\":4,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":4,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"complete\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"resolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"resolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"complete\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":29,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-status\",\"method_id\":\"elastic.ilm.get_status\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"07a4d016ce77a10dbd9b5adc64194668e37a18f204c8c4fbe090fbce649e88ee\",\"diagnostics\":[],\"field_coverage\":{\"operation_mode\":\"known\"},\"fields\":{\"operation_mode\":\"RUNNING\"},\"interpretation_status\":\"known\",\"native_scope\":\"service\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"service\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":29,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"service\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":314,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"d70d47111514814bafae7620855ab21c07a244c33c47d16a635b44b128abda1c\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"safe_http_status\":200}],\"field_coverage\":{\"action\":\"known\",\"action_time_millis\":\"absent\",\"failed_step\":\"absent\",\"index\":\"known\",\"index_creation_date_millis\":\"absent\",\"lifecycle_date_millis\":\"known\",\"managed\":\"known\",\"phase\":\"known\",\"phase_execution\":\"known\",\"phase_time_millis\":\"absent\",\"policy\":\"known\",\"step\":\"known\",\"step_time_millis\":\"absent\"},\"fields\":{\"action\":\"synthetic-action\",\"index\":\"events-0\",\"lifecycle_date_millis\":1767225600000,\"managed\":true,\"phase\":\"hot\",\"phase_execution\":{\"modified_date_in_millis\":1767225600000,\"policy\":\"synthetic-policy\",\"version\":1},\"policy\":\"synthetic-policy\",\"step\":\"synthetic-step\"},\"interpretation_status\":\"limited\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":314,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":314,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"dfb7752c276795ab38b9000c9da2c777ba063c8fd045878bfdf58bb032cb8a65\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"safe_http_status\":200}],\"field_coverage\":{\"action\":\"known\",\"action_time_millis\":\"absent\",\"failed_step\":\"absent\",\"index\":\"known\",\"index_creation_date_millis\":\"absent\",\"lifecycle_date_millis\":\"known\",\"managed\":\"known\",\"phase\":\"known\",\"phase_execution\":\"known\",\"phase_time_millis\":\"absent\",\"policy\":\"known\",\"step\":\"known\",\"step_time_millis\":\"absent\"},\"fields\":{\"action\":\"synthetic-action\",\"index\":\"events-1\",\"lifecycle_date_millis\":1767225600000,\"managed\":true,\"phase\":\"hot\",\"phase_execution\":{\"modified_date_in_millis\":1767225600000,\"policy\":\"synthetic-policy\",\"version\":1},\"policy\":\"synthetic-policy\",\"step\":\"synthetic-step\"},\"interpretation_status\":\"limited\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-1\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":314,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":186,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-policy\",\"method_id\":\"elastic.ilm.get_lifecycle\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"4af3deb74e2f7b2e7ad988b95dfd8fd1e7d99b26a1db2822df65429f7577229c\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"safe_http_status\":200}],\"field_coverage\":{\"modified_date\":\"absent\",\"policy\":\"known\",\"version\":\"known\"},\"fields\":{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_docs\":9007199254740993}},\"min_age\":\"0ms\"}}},\"version\":1},\"interpretation_status\":\"limited\",\"native_scope\":\"policy\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"synthetic-policy\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":186,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"synthetic-policy\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"unassessed_surfaces\":[\"document_coverage\",\"lifecycle_execution_guarantees\",\"templates_and_unselected_indices\",\"atomic_provider_snapshot\"]}"
    },
    "partial": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "elastic-ilm",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"findings\":[{\"collection_context\":{\"collected_at\":\"2026-01-01T00:00:00.000000Z\",\"collector_id\":\"enterprise-retention\",\"collector_version\":\"0.12.1\",\"credential_identity\":\"operator-configured:identity-unverified\",\"evidentia_version\":\"0.12.1\",\"filter_applied\":{\"coverage_scope\":\"selected_resources\",\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"scope_label\":\"synthetic\",\"target\":{\"index\":\"events-0\"}},\"pagination_context\":{\"continuation_token\":null,\"is_complete\":true,\"page_number\":null,\"page_size\":null,\"total_pages\":3},\"run_id\":\"01K00000000000000000000000\",\"source_system_id\":\"enterprise-retention/elastic-ilm/selected\"},\"compliance_status\":\"unknown\",\"control_mappings\":[],\"description\":\"Selected index, service and current policy configuration; document coverage and lifecycle execution are unassessed.\",\"first_observed\":\"2026-01-01T00:00:00.000000Z\",\"id\":\"a1e5e603-62bc-593b-9df1-5a1c8abf0570\",\"last_observed\":\"2026-01-01T00:00:00.000000Z\",\"raw_data\":{\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":1,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":1,\"null\":0,\"unknown\":0}},\"policy_resolution\":\"resolved\",\"reads\":[{\"observation_digests_sha256\":\"f7ecbc1aef2244787c24cc4e4072c0f6dddaf7784a134d47b1a92ea23247e2dd\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"fad959608b4a163ca42f759b7531cef17bf95911a03cf1224a78a284051872b0\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"status\":\"complete\"},{\"observation_digests_sha256\":\"40a6931e9e577e5f9e249dc1db9e9853eacdb4a099939e3763aabe510376f1c6\",\"observations\":1,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"status\":\"complete\"}],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},\"remediation\":null,\"resolved_at\":null,\"resource_account\":null,\"resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"resource_region\":null,\"resource_type\":\"ElasticsearchILM::Index\",\"severity\":\"informational\",\"source_finding_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"source_system\":\"enterprise-retention\",\"status\":\"active\",\"title\":\"Elasticsearch ILM configuration\"}],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":4,\"canonical_observation_bytes\":2046,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":529,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":1,\"pages_admitted\":3,\"pages_received\":3,\"raw_bytes\":529,\"reads_attempted\":4,\"reads_completed\":3,\"reads_planned\":4,\"records_admitted\":3,\"records_received\":3,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":4,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"partial\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"resolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"complete\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"unresolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"partial\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":29,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-status\",\"method_id\":\"elastic.ilm.get_status\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"07a4d016ce77a10dbd9b5adc64194668e37a18f204c8c4fbe090fbce649e88ee\",\"diagnostics\":[],\"field_coverage\":{\"operation_mode\":\"known\"},\"fields\":{\"operation_mode\":\"RUNNING\"},\"interpretation_status\":\"known\",\"native_scope\":\"service\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"service\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":29,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"service\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":314,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"d70d47111514814bafae7620855ab21c07a244c33c47d16a635b44b128abda1c\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"safe_http_status\":200}],\"field_coverage\":{\"action\":\"known\",\"action_time_millis\":\"absent\",\"failed_step\":\"absent\",\"index\":\"known\",\"index_creation_date_millis\":\"absent\",\"lifecycle_date_millis\":\"known\",\"managed\":\"known\",\"phase\":\"known\",\"phase_execution\":\"known\",\"phase_time_millis\":\"absent\",\"policy\":\"known\",\"step\":\"known\",\"step_time_millis\":\"absent\"},\"fields\":{\"action\":\"synthetic-action\",\"index\":\"events-0\",\"lifecycle_date_millis\":1767225600000,\"managed\":true,\"phase\":\"hot\",\"phase_execution\":{\"modified_date_in_millis\":1767225600000,\"policy\":\"synthetic-policy\",\"version\":1},\"policy\":\"synthetic-policy\",\"step\":\"synthetic-step\"},\"interpretation_status\":\"limited\",\"native_scope\":\"index\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"events-0\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":314,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":186,\"diagnostics\":[],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-policy\",\"method_id\":\"elastic.ilm.get_lifecycle\",\"observations\":[{\"api_version\":\"elastic-stack-ilm\",\"canonical_projection_sha256\":\"4af3deb74e2f7b2e7ad988b95dfd8fd1e7d99b26a1db2822df65429f7577229c\",\"diagnostics\":[{\"code\":\"missing_source_detail\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"safe_http_status\":200}],\"field_coverage\":{\"modified_date\":\"absent\",\"policy\":\"known\",\"version\":\"known\"},\"fields\":{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_docs\":9007199254740993}},\"min_age\":\"0ms\"}}},\"version\":1},\"interpretation_status\":\"limited\",\"native_scope\":\"policy\",\"projection_version\":\"enterprise-retention-projection/v1\",\"source_identity\":\"synthetic-policy\"}],\"pages_admitted\":1,\"pages_received\":1,\"raw_bytes\":186,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-policy/synthetic-policy\",\"records_admitted\":1,\"records_received\":1,\"responses_received\":1,\"safe_http_status\":200,\"source_id\":\"synthetic-policy\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"complete\",\"terminal_reason\":null}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"partial\",\"unassessed_surfaces\":[\"document_coverage\",\"lifecycle_execution_guarantees\",\"templates_and_unselected_indices\",\"atomic_provider_snapshot\"]}"
    },
    "unavailable": {
      "request": {
        "profile_alias": "selected",
        "scope_label": "synthetic",
        "provider": "elastic-ilm",
        "targets": [
          {
            "index": "events-0"
          },
          {
            "index": "events-1"
          }
        ]
      },
      "rawJson": "{\"authenticated_identity_verified\":false,\"coverage_scope\":\"selected_resources\",\"diagnostics\":[],\"field_coverage\":{\"elastic-explain/action\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/action_time_millis\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/failed_step\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/index_creation_date_millis\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/lifecycle_date_millis\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/managed\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/phase\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/phase_execution\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/phase_time_millis\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/policy\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/step\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-explain/step_time_millis\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/modified_date\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/policy\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-policy/version\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0},\"elastic-status/operation_mode\":{\"absent\":0,\"known\":0,\"null\":0,\"unknown\":0}},\"findings\":[],\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"identity_basis\":\"operator-declared\",\"manifest\":{\"attempts\":3,\"canonical_observation_bytes\":0,\"collector_version\":\"0.12.1\",\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"duplicates_coalesced\":0,\"evidentia_version\":\"0.12.1\",\"findings\":0,\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"reads_attempted\":3,\"reads_completed\":0,\"reads_planned\":3,\"records_admitted\":0,\"records_received\":0,\"resources_attempted\":2,\"resources_requested\":2,\"responses_received\":3,\"run_id\":\"01K00000000000000000000000\",\"schema_version\":\"enterprise-retention-manifest/v1\",\"status\":\"unavailable\"},\"object_enforcement_assessed\":false,\"observation_scope\":\"configuration\",\"profile_alias\":\"selected\",\"provider\":\"elastic-ilm\",\"recordset_completeness_assessed\":false,\"resources\":[{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-0\",\"diagnostics\":[],\"policy_resolution\":\"unresolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"unavailable\",\"target\":{\"index\":\"events-0\"}},{\"canonical_resource_id\":\"enterprise-retention/elastic-ilm/selected/index/events-1\",\"diagnostics\":[],\"policy_resolution\":\"unresolved\",\"read_ids\":[\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"enterprise-retention/elastic-ilm/selected/elastic-status/service\"],\"status\":\"unavailable\",\"target\":{\"index\":\"events-1\"}}],\"schema_version\":\"enterprise-retention-collection/v1\",\"scope_label\":\"synthetic\",\"source_reads\":[{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-status\",\"method_id\":\"elastic.ilm.get_status\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-status/service\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"service\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-0\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-0\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"},{\"attempts\":1,\"conflicts_quarantined\":0,\"decoded_bytes\":0,\"diagnostics\":[{\"code\":\"http_denied\",\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"safe_http_status\":403}],\"duplicates_coalesced\":0,\"finished_at\":\"2026-01-01T00:00:00.000000Z\",\"kind\":\"elastic-explain\",\"method_id\":\"elastic.ilm.explain_lifecycle\",\"observations\":[],\"pages_admitted\":0,\"pages_received\":0,\"raw_bytes\":0,\"read_id\":\"enterprise-retention/elastic-ilm/selected/elastic-explain/events-1\",\"records_admitted\":0,\"records_received\":0,\"responses_received\":1,\"safe_http_status\":403,\"source_id\":\"events-1\",\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"terminal_reason\":\"http_denied\"}],\"started_at\":\"2026-01-01T00:00:00.000000Z\",\"status\":\"unavailable\",\"unassessed_surfaces\":[\"document_coverage\",\"lifecycle_execution_guarantees\",\"templates_and_unselected_indices\",\"atomic_provider_snapshot\"]}"
    }
  }
} as const;
