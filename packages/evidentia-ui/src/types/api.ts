/**
 * TypeScript mirrors of the Pydantic response models in
 * packages/evidentia-api/src/evidentia_api/schemas.py.
 *
 * v0.4.0: hand-authored for correctness.
 * v0.4.1: planned auto-generation from the FastAPI OpenAPI schema so
 * drift between Python and TS types becomes impossible.
 */

export interface HealthResponse {
  status: string;
  version: string;
  auth_configured: boolean;
}

export interface VersionResponse {
  api_version: string;
  core_version: string;
  ai_version: string;
  python_version: string;
}

// ── Gap models (mirrored from evidentia_core.models.gap) ───────────

export type GapSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type ImplementationEffort = "low" | "medium" | "high" | "very_high";

export type GapStatus =
  | "open"
  | "in_progress"
  | "remediated"
  | "accepted"
  | "not_applicable";

export interface ControlGap {
  id: string;
  framework: string;
  control_id: string;
  control_title: string;
  control_description: string;
  control_family: string | null;
  gap_severity: GapSeverity;
  implementation_status: string;
  gap_description: string;
  status: GapStatus;
  equivalent_controls_in_inventory: string[];
  cross_framework_value: string[];
  remediation_guidance: string;
  implementation_effort: ImplementationEffort;
  priority_score: number;
  jira_issue_key: string | null;
  servicenow_ticket_id: string | null;
  created_at: string;
  remediated_at: string | null;
  assigned_to: string | null;
  tags: string[];
}

export interface EfficiencyOpportunity {
  control_id: string;
  control_title: string;
  frameworks_satisfied: string[];
  framework_count: number;
  total_gaps_closed: number;
  implementation_effort: ImplementationEffort;
  value_score: number;
}

export interface GapAnalysisReport {
  id: string;
  organization: string;
  frameworks_analyzed: string[];
  analyzed_at: string;
  total_controls_required: number;
  total_controls_in_inventory: number;
  total_gaps: number;
  critical_gaps: number;
  high_gaps: number;
  medium_gaps: number;
  low_gaps: number;
  informational_gaps: number;
  coverage_percentage: number;
  gaps: ControlGap[];
  efficiency_opportunities: EfficiencyOpportunity[];
  prioritized_roadmap: string[];
  inventory_source: string | null;
  evidentia_version: string;
  notes: string | null;
}

// ── Gap diff (mirrored from evidentia_core.gap_diff models) ─────────

export type DiffStatus =
  | "closed"
  | "opened"
  | "severity_increased"
  | "severity_decreased"
  | "unchanged";

export interface GapDiffEntry {
  framework: string;
  control_id: string;
  control_title: string | null;
  status: DiffStatus;
  base_severity: GapSeverity | null;
  head_severity: GapSeverity | null;
  base_priority: number | null;
  head_priority: number | null;
  gap_description: string | null;
  remediation_guidance: string | null;
}

export interface GapDiffSummary {
  closed: number;
  opened: number;
  severity_increased: number;
  severity_decreased: number;
  unchanged: number;
}

export interface GapDiff {
  id: string;
  generated_at: string;
  base_organization: string;
  base_inventory_source: string | null;
  head_organization: string;
  head_inventory_source: string | null;
  frameworks_analyzed: string[];
  summary: GapDiffSummary;
  entries: GapDiffEntry[];
}

// ── Config + LLM status ────────────────────────────────────────────────

export interface LlmProviderState {
  configured: boolean;
  source: string | null;
}

export interface LlmStatusResponse {
  providers: Record<string, LlmProviderState>;
  configured_model: string;
}

// ── Air-gap ────────────────────────────────────────────────────────────

export interface AirGapCheck {
  subsystem: string;
  status: "ok" | "would_leak" | "skipped";
  detail: string;
}

export interface AirGapCheckResponse {
  air_gapped: boolean;
  checks: AirGapCheck[];
}

// ── Init wizard ────────────────────────────────────────────────────────

export interface InitWizardRequest {
  organization: string;
  system_name?: string | null;
  industry?: string | null;
  hosting?: string | null;
  data_classification: string[];
  regulatory_requirements: string[];
  preset?: string;
}

export interface InitWizardResponse {
  evidentia_yaml: string;
  my_controls_yaml: string;
  system_context_yaml: string;
  recommended_frameworks: string[];
}
