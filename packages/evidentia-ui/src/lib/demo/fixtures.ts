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
    },
    {
      id: "nist-800-53-rev5-high",
      name: "NIST SP 800-53 Rev 5 High Baseline",
      version: "5.2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "nist-800-53-rev5-low",
      name: "NIST SP 800-53 Rev 5 Low Baseline",
      version: "5.2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "nist-csf-2.0",
      name: "NIST Cybersecurity Framework 2.0",
      version: "2.0",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "fedramp-rev5-moderate",
      name: "FedRAMP Rev 5 Moderate Baseline",
      version: "Rev 5 (2023)",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "cmmc-2-l2",
      name: "CMMC 2.0 Level 2 (Advanced)",
      version: "2.0 (2024 Final Rule)",
      tier: "A",
      category: "control",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "eu-gdpr",
      name: "EU General Data Protection Regulation (GDPR)",
      version: "Regulation (EU) 2016/679",
      tier: "D",
      category: "obligation",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "mitre-attack-enterprise",
      name: "MITRE ATT&CK Enterprise",
      version: "v15.1 (2024)",
      tier: "B",
      category: "technique",
      placeholder: "false",
      license_required: "false",
    },
    {
      id: "soc2-tsc",
      name: "SOC 2 Trust Services Criteria (stub)",
      version: "2017 (with 2022 Points of Focus revisions)",
      tier: "C",
      category: "control",
      placeholder: "true",
      license_required: "true",
    },
    {
      id: "iso-27001-2022",
      name: "ISO/IEC 27001:2022 (Annex A controls)",
      version: "2022",
      tier: "C",
      category: "control",
      placeholder: "true",
      license_required: "true",
    },
  ],
};
