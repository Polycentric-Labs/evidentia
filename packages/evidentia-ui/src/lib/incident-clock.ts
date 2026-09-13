import type { components, operations } from "@/types/openapi";

export type IncidentClockRequest =
  operations["collect_incident_clock"]["requestBody"]["content"]["application/json"];
export type IncidentClockResult = components["schemas"]["IncidentClockResult"];
export type IncidentProvider = IncidentClockRequest["provider"];
export const INCIDENT_PROVIDERS = ["servicenow", "jira", "pagerduty"] as const;
export const INCIDENT_REQUEST_BYTES = 16_384;
export const INCIDENT_RESULT_BYTES = 16_777_216;
export class IncidentClockResponseError extends Error {
  constructor() {
    super(
      "The incident clock JSON is invalid or does not match the selected request.",
    );
    this.name = "IncidentClockResponseError";
  }
}
const failure = (): never => {
  throw new IncidentClockResponseError();
};
const size = (value: string): number => new TextEncoder().encode(value).length;
const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
interface JsonSchema {
  $ref?: string;
  $defs?: Record<string, JsonSchema>;
  type?: string;
  properties?: Record<string, JsonSchema>;
  additionalProperties?: boolean | JsonSchema;
  required?: string[];
  oneOf?: JsonSchema[];
  anyOf?: JsonSchema[];
  allOf?: JsonSchema[];
  items?: JsonSchema;
  const?: unknown;
  enum?: unknown[];
  format?: string;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  minProperties?: number;
  maxProperties?: number;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
}

// Validation constraints exported from the current incident models.
export const REQUEST_SCHEMA: JsonSchema = {
  $defs: {
    JiraOccurrence: {
      additionalProperties: false,
      properties: {
        history_id: {
          maxLength: 256,
          minLength: 1,
          type: "string",
        },
        item_index: {
          maximum: 255,
          minimum: 0,
          type: "integer",
        },
      },
      required: ["history_id", "item_index"],
      type: "object",
    },
    JiraRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        clock_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        provider: {
          const: "jira",
          type: "string",
        },
        record_id: {
          maxLength: 32,
          minLength: 1,
          pattern: "^[1-9][0-9]{0,31}$",
          type: "string",
        },
        start_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        end_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["profile_alias", "clock_alias", "provider", "record_id"],
      type: "object",
    },
    PagerDutyOccurrence: {
      additionalProperties: false,
      properties: {
        event_id: {
          maxLength: 256,
          minLength: 1,
          type: "string",
        },
      },
      required: ["event_id"],
      type: "object",
    },
    PagerDutyRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        clock_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        provider: {
          const: "pagerduty",
          type: "string",
        },
        record_id: {
          maxLength: 128,
          minLength: 1,
          pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$",
          type: "string",
        },
        since: {
          maxLength: 2048,
          minLength: 1,
          type: "string",
        },
        until: {
          maxLength: 2048,
          minLength: 1,
          type: "string",
        },
        start_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        end_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: [
        "profile_alias",
        "clock_alias",
        "provider",
        "record_id",
        "since",
        "until",
      ],
      type: "object",
    },
    ServiceNowRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        clock_alias: {
          maxLength: 64,
          minLength: 1,
          type: "string",
        },
        provider: {
          const: "servicenow",
          type: "string",
        },
        record_id: {
          maxLength: 32,
          minLength: 32,
          pattern: "^[0-9a-f]{32}$",
          type: "string",
        },
      },
      required: ["profile_alias", "clock_alias", "provider", "record_id"],
      type: "object",
    },
  },
  oneOf: [
    {
      $ref: "#/$defs/ServiceNowRequest",
    },
    {
      $ref: "#/$defs/JiraRequest",
    },
    {
      $ref: "#/$defs/PagerDutyRequest",
    },
  ],
};
export const RESULT_SCHEMA: JsonSchema = {
  $defs: {
    ClockOutcome: {
      additionalProperties: false,
      properties: {
        state: {
          enum: [
            "computed",
            "unresolved_events",
            "reversed_order",
            "incomplete_source",
          ],
          type: "string",
        },
        start: {
          $ref: "#/$defs/EventSelection",
        },
        end: {
          $ref: "#/$defs/EventSelection",
        },
        elapsed_seconds: {
          anyOf: [
            {
              maxLength: 2024,
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["state", "start", "end", "elapsed_seconds"],
      type: "object",
    },
    ControlMapping: {
      additionalProperties: false,
      properties: {
        framework: {
          type: "string",
        },
        control_id: {
          type: "string",
        },
        control_title: {
          anyOf: [
            {
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        relationship: {
          $ref: "#/$defs/OLIRRelationship",
        },
        justification: {
          maxLength: 1024,
          type: "string",
        },
      },
      required: ["framework", "control_id"],
      type: "object",
    },
    DeclaredPagination: {
      additionalProperties: false,
      properties: {
        start: {
          maximum: 10000,
          minimum: 0,
          type: "integer",
        },
        limit: {
          maximum: 100,
          minimum: 1,
          type: "integer",
        },
        total: {
          maximum: 1000000000,
          minimum: 0,
          type: "integer",
        },
        terminal: {
          type: "boolean",
        },
        returned: {
          maximum: 100,
          minimum: 0,
          type: "integer",
        },
      },
      required: ["start", "limit", "total", "terminal", "returned"],
      type: "object",
    },
    Diagnostic: {
      additionalProperties: false,
      properties: {
        code: {
          enum: [
            "profile_refused",
            "credential_missing",
            "credential_expired",
            "credential_invalid",
            "offline_refused",
            "destination_refused",
            "dns_failure",
            "dns_timeout",
            "connect_failure",
            "tls_failure",
            "read_timeout",
            "deadline_exceeded",
            "redirect_refused",
            "http_unauthorized",
            "http_forbidden",
            "http_not_found",
            "http_status_refused",
            "body_limit",
            "response_budget",
            "unsupported_encoding",
            "invalid_json",
            "source_shape",
            "record_mismatch",
            "site_grant_refused",
            "pagination_conflict",
            "duplicate_occurrence",
            "source_conflict",
            "page_limit",
            "event_limit",
            "result_limit",
            "timestamp_unsupported",
            "event_missing",
            "event_null",
            "event_empty",
            "event_ambiguous",
            "occurrence_not_found",
            "reversed_order",
            "incomplete_source",
            "cleanup_failure",
            "header_limit",
            "framing_limit",
            "wire_budget",
            "framing_invalid",
          ],
          type: "string",
        },
        read_id: {
          anyOf: [
            {
              maxLength: 69,
              minLength: 69,
              pattern: "^read-[0-9a-f]{64}$",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        side: {
          anyOf: [
            {
              enum: ["start", "end"],
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["code", "read_id", "side"],
      type: "object",
    },
    EventSelection: {
      additionalProperties: false,
      properties: {
        state: {
          enum: [
            "selected",
            "missing",
            "null",
            "empty",
            "unsupported_timestamp",
            "ambiguous",
            "occurrence_not_found",
            "conflicting_source",
            "incomplete",
          ],
          type: "string",
        },
        candidate_event_ids: {
          items: {
            maxLength: 70,
            minLength: 70,
            pattern: "^event-[0-9a-f]{64}$",
            type: "string",
          },
          maxItems: 10000,
          type: "array",
        },
        selected_event_id: {
          anyOf: [
            {
              maxLength: 70,
              minLength: 70,
              pattern: "^event-[0-9a-f]{64}$",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        explicit_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowOccurrence",
            },
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        source_literal: {
          anyOf: [
            {
              maxLength: 2048,
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        utc_seconds: {
          anyOf: [
            {
              maxLength: 2024,
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: [
        "state",
        "candidate_event_ids",
        "selected_event_id",
        "explicit_occurrence",
        "source_literal",
        "utc_seconds",
      ],
      type: "object",
    },
    IncidentClockContext: {
      additionalProperties: false,
      properties: {
        collector_id: {
          const: "incident-clock",
          type: "string",
        },
        collector_version: {
          maxLength: 64,
          minLength: 1,
          pattern: "^[0-9][A-Za-z0-9.+_-]{0,63}$",
          type: "string",
        },
        run_id: {
          maxLength: 26,
          minLength: 26,
          pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
          type: "string",
        },
        collected_at: {
          type: "string",
        },
        credential_identity: {
          const: "not-established",
          type: "string",
        },
        source_system_id: {
          maxLength: 90,
          minLength: 84,
          pattern: "^incident-clock:(servicenow|jira|pagerduty):[0-9a-f]{64}$",
          type: "string",
        },
        filter_applied: {
          $ref: "#/$defs/SelectionFilter",
        },
        pagination_context: {
          type: "null",
        },
        evidentia_version: {
          maxLength: 64,
          minLength: 1,
          pattern: "^[0-9][A-Za-z0-9.+_-]{0,63}$",
          type: "string",
        },
      },
      required: [
        "collector_id",
        "collector_version",
        "run_id",
        "collected_at",
        "credential_identity",
        "source_system_id",
        "filter_applied",
        "pagination_context",
        "evidentia_version",
      ],
      type: "object",
    },
    IncidentClockCoverage: {
      additionalProperties: false,
      properties: {
        resource_type: {
          const: "selected_incident_clock",
          type: "string",
        },
        scanned: {
          maximum: 1,
          minimum: 0,
          type: "integer",
        },
        matched_filter: {
          maximum: 1,
          minimum: 0,
          type: "integer",
        },
        collected: {
          maximum: 1,
          minimum: 0,
          type: "integer",
        },
      },
      required: ["resource_type", "scanned", "matched_filter", "collected"],
      type: "object",
    },
    IncidentClockFinding: {
      additionalProperties: false,
      properties: {
        id: {
          maxLength: 36,
          minLength: 36,
          pattern:
            "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
          type: "string",
        },
        title: {
          const: "Incident clock observation",
          type: "string",
        },
        description: {
          maxLength: 256,
          minLength: 1,
          pattern: "^[ -~]{1,256}$",
          type: "string",
        },
        severity: {
          const: "informational",
          type: "string",
        },
        status: {
          const: "active",
          type: "string",
        },
        compliance_status: {
          const: "unknown",
          type: "string",
        },
        remediation: {
          type: "null",
        },
        source_system: {
          const: "incident-clock",
          type: "string",
        },
        source_finding_id: {
          type: "null",
        },
        resource_type: {
          const: "selected_incident_clock",
          type: "string",
        },
        resource_id: {
          maxLength: 128,
          minLength: 1,
          pattern: "^[A-Za-z0-9_-]+$",
          type: "string",
        },
        resource_region: {
          type: "null",
        },
        resource_account: {
          type: "null",
        },
        control_mappings: {
          items: {
            $ref: "#/$defs/ControlMapping",
          },
          maxItems: 0,
          type: "array",
        },
        collection_context: {
          $ref: "#/$defs/IncidentClockContext",
        },
        raw_data: {
          $ref: "#/$defs/IncidentClockSummary",
        },
        first_observed: {
          type: "string",
        },
        last_observed: {
          type: "string",
        },
        resolved_at: {
          type: "null",
        },
      },
      required: [
        "id",
        "title",
        "description",
        "severity",
        "status",
        "compliance_status",
        "remediation",
        "source_system",
        "source_finding_id",
        "resource_type",
        "resource_id",
        "resource_region",
        "resource_account",
        "control_mappings",
        "collection_context",
        "raw_data",
        "first_observed",
        "last_observed",
        "resolved_at",
      ],
      type: "object",
    },
    IncidentClockManifest: {
      additionalProperties: false,
      properties: {
        run_id: {
          maxLength: 26,
          minLength: 26,
          pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
          type: "string",
        },
        collector_id: {
          const: "incident-clock",
          type: "string",
        },
        collector_version: {
          maxLength: 64,
          minLength: 1,
          pattern: "^[0-9][A-Za-z0-9.+_-]{0,63}$",
          type: "string",
        },
        collection_started_at: {
          type: "string",
        },
        collection_finished_at: {
          type: "string",
        },
        source_system_ids: {
          items: {
            maxLength: 90,
            minLength: 84,
            pattern:
              "^incident-clock:(servicenow|jira|pagerduty):[0-9a-f]{64}$",
            type: "string",
          },
          maxItems: 1,
          minItems: 1,
          type: "array",
        },
        filters_applied: {
          $ref: "#/$defs/SelectionFilter",
        },
        coverage_counts: {
          items: {
            $ref: "#/$defs/IncidentClockCoverage",
          },
          type: "array",
        },
        total_findings: {
          maximum: 1,
          minimum: 0,
          type: "integer",
        },
        is_complete: {
          type: "boolean",
        },
        incomplete_reason: {
          anyOf: [
            {
              enum: [
                "selected_source_incomplete",
                "selected_source_unavailable",
              ],
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        empty_categories: {
          items: {
            type: "string",
          },
          maxItems: 0,
          type: "array",
        },
        warnings: {
          items: {
            type: "string",
          },
          maxItems: 3,
          minItems: 2,
          type: "array",
        },
        errors: {
          items: {
            type: "string",
          },
          maxItems: 64,
          type: "array",
        },
        evidentia_version: {
          maxLength: 64,
          minLength: 1,
          pattern: "^[0-9][A-Za-z0-9.+_-]{0,63}$",
          type: "string",
        },
      },
      required: [
        "run_id",
        "collector_id",
        "collector_version",
        "collection_started_at",
        "collection_finished_at",
        "source_system_ids",
        "filters_applied",
        "coverage_counts",
        "total_findings",
        "is_complete",
        "incomplete_reason",
        "empty_categories",
        "warnings",
        "errors",
        "evidentia_version",
      ],
      type: "object",
    },
    IncidentClockSummary: {
      additionalProperties: false,
      properties: {
        observation_scope: {
          const: "selected_incident_clock",
          type: "string",
        },
        source_state: {
          enum: ["complete", "incomplete", "unavailable"],
          type: "string",
        },
        clock_state: {
          enum: [
            "computed",
            "unresolved_events",
            "reversed_order",
            "incomplete_source",
          ],
          type: "string",
        },
        elapsed_seconds: {
          anyOf: [
            {
              maxLength: 2024,
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        start_event_id: {
          anyOf: [
            {
              maxLength: 70,
              minLength: 70,
              pattern: "^event-[0-9a-f]{64}$",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        end_event_id: {
          anyOf: [
            {
              maxLength: 70,
              minLength: 70,
              pattern: "^event-[0-9a-f]{64}$",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        start_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowOccurrence",
            },
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        end_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowOccurrence",
            },
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        definition_sha256: {
          maxLength: 64,
          minLength: 64,
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
        profile_binding_sha256: {
          maxLength: 64,
          minLength: 64,
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
      },
      required: [
        "observation_scope",
        "source_state",
        "clock_state",
        "elapsed_seconds",
        "start_event_id",
        "end_event_id",
        "start_occurrence",
        "end_occurrence",
        "definition_sha256",
        "profile_binding_sha256",
      ],
      type: "object",
    },
    JiraMapping: {
      additionalProperties: false,
      properties: {
        label: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        meaning: {
          maxLength: 512,
          minLength: 1,
          type: "string",
        },
        field_id: {
          maxLength: 256,
          minLength: 1,
          type: "string",
        },
        from: {
          $ref: "#/$defs/NativeTextCell",
        },
        to: {
          $ref: "#/$defs/NativeTextCell",
        },
      },
      required: ["label", "meaning", "field_id", "from", "to"],
      type: "object",
    },
    JiraOccurrence: {
      additionalProperties: false,
      properties: {
        history_id: {
          maxLength: 256,
          minLength: 1,
          type: "string",
        },
        item_index: {
          maximum: 255,
          minimum: 0,
          type: "integer",
        },
      },
      required: ["history_id", "item_index"],
      type: "object",
    },
    JiraRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        clock_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        provider: {
          const: "jira",
          type: "string",
        },
        record_id: {
          maxLength: 32,
          minLength: 1,
          pattern: "^[1-9][0-9]{0,31}$",
          type: "string",
        },
        start_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        end_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["profile_alias", "clock_alias", "provider", "record_id"],
      type: "object",
    },
    NativeTextCell: {
      additionalProperties: false,
      properties: {
        state: {
          enum: ["missing", "null", "empty", "value"],
          type: "string",
        },
        value: {
          anyOf: [
            {
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["state", "value"],
      type: "object",
    },
    OLIRRelationship: {
      enum: [
        "equivalent-to",
        "equal-to",
        "subset-of",
        "superset-of",
        "intersects-with",
        "related-to",
      ],
      type: "string",
    },
    PagerDutyMapping: {
      additionalProperties: false,
      properties: {
        label: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        meaning: {
          maxLength: 512,
          minLength: 1,
          type: "string",
        },
        event_type: {
          enum: [
            "acknowledge_log_entry",
            "annotate_log_entry",
            "assign_log_entry",
            "delegate_log_entry",
            "escalate_log_entry",
            "exhaust_escalation_path_log_entry",
            "notify_log_entry",
            "reach_ack_limit_log_entry",
            "reach_trigger_limit_log_entry",
            "repeat_escalation_path_log_entry",
            "resolve_log_entry",
            "snooze_log_entry",
            "trigger_log_entry",
            "unacknowledge_log_entry",
            "urgency_change_log_entry",
            "field_value_change_log_entry",
            "custom_field_value_change_log_entry",
          ],
          type: "string",
        },
      },
      required: ["label", "meaning", "event_type"],
      type: "object",
    },
    PagerDutyOccurrence: {
      additionalProperties: false,
      properties: {
        event_id: {
          maxLength: 256,
          minLength: 1,
          type: "string",
        },
      },
      required: ["event_id"],
      type: "object",
    },
    PagerDutyRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        clock_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        provider: {
          const: "pagerduty",
          type: "string",
        },
        record_id: {
          maxLength: 128,
          minLength: 1,
          pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$",
          type: "string",
        },
        since: {
          maxLength: 2048,
          minLength: 1,
          type: "string",
        },
        until: {
          maxLength: 2048,
          minLength: 1,
          type: "string",
        },
        start_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
        end_occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: [
        "profile_alias",
        "clock_alias",
        "provider",
        "record_id",
        "since",
        "until",
      ],
      type: "object",
    },
    PublishedClockDefinition: {
      additionalProperties: false,
      properties: {
        clock_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        label: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        mapping_reference: {
          maxLength: 512,
          minLength: 1,
          type: "string",
        },
        declared_workflow_meaning: {
          maxLength: 1024,
          minLength: 1,
          type: "string",
        },
        definition_sha256: {
          maxLength: 64,
          minLength: 64,
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
        start: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowMapping",
            },
            {
              $ref: "#/$defs/JiraMapping",
            },
            {
              $ref: "#/$defs/PagerDutyMapping",
            },
          ],
        },
        end: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowMapping",
            },
            {
              $ref: "#/$defs/JiraMapping",
            },
            {
              $ref: "#/$defs/PagerDutyMapping",
            },
          ],
        },
      },
      required: [
        "clock_alias",
        "label",
        "mapping_reference",
        "declared_workflow_meaning",
        "definition_sha256",
        "start",
        "end",
      ],
      type: "object",
    },
    SelectedRecordProjection: {
      additionalProperties: false,
      properties: {
        provider: {
          enum: ["servicenow", "jira", "pagerduty"],
          type: "string",
        },
        record_id: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        read_id: {
          maxLength: 69,
          minLength: 69,
          pattern: "^read-[0-9a-f]{64}$",
          type: "string",
        },
        fields: {
          additionalProperties: {
            $ref: "#/$defs/NativeTextCell",
          },
          maxProperties: 3,
          minProperties: 2,
          type: "object",
        },
      },
      required: ["provider", "record_id", "read_id", "fields"],
      type: "object",
    },
    SelectionFilter: {
      additionalProperties: false,
      properties: {
        observation_scope: {
          const: "selected_incident_clock",
          type: "string",
        },
        request: {
          oneOf: [
            {
              $ref: "#/$defs/ServiceNowRequest",
            },
            {
              $ref: "#/$defs/JiraRequest",
            },
            {
              $ref: "#/$defs/PagerDutyRequest",
            },
          ],
        },
        profile_binding_sha256: {
          maxLength: 64,
          minLength: 64,
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
        definition_sha256: {
          maxLength: 64,
          minLength: 64,
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
      },
      required: [
        "observation_scope",
        "request",
        "profile_binding_sha256",
        "definition_sha256",
      ],
      type: "object",
    },
    ServiceNowMapping: {
      additionalProperties: false,
      properties: {
        label: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        meaning: {
          maxLength: 512,
          minLength: 1,
          type: "string",
        },
        field: {
          maxLength: 80,
          minLength: 1,
          pattern: "^[a-z][a-z0-9_]{0,79}$",
          type: "string",
        },
      },
      required: ["label", "meaning", "field"],
      type: "object",
    },
    ServiceNowOccurrence: {
      additionalProperties: false,
      properties: {
        field: {
          maxLength: 80,
          minLength: 1,
          pattern: "^[a-z][a-z0-9_]{0,79}$",
          type: "string",
        },
      },
      required: ["field"],
      type: "object",
    },
    ServiceNowRequest: {
      additionalProperties: false,
      properties: {
        profile_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        clock_alias: {
          pattern: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$",
          type: "string",
        },
        provider: {
          const: "servicenow",
          type: "string",
        },
        record_id: {
          maxLength: 32,
          minLength: 32,
          pattern: "^[0-9a-f]{32}$",
          type: "string",
        },
      },
      required: ["profile_alias", "clock_alias", "provider", "record_id"],
      type: "object",
    },
    SourceEvent: {
      additionalProperties: false,
      properties: {
        event_id: {
          maxLength: 70,
          minLength: 70,
          pattern: "^event-[0-9a-f]{64}$",
          type: "string",
        },
        record_id: {
          maxLength: 128,
          minLength: 1,
          type: "string",
        },
        read_id: {
          maxLength: 69,
          minLength: 69,
          pattern: "^read-[0-9a-f]{64}$",
          type: "string",
        },
        occurrence: {
          anyOf: [
            {
              $ref: "#/$defs/ServiceNowOccurrence",
            },
            {
              $ref: "#/$defs/JiraOccurrence",
            },
            {
              $ref: "#/$defs/PagerDutyOccurrence",
            },
          ],
        },
        timestamp: {
          $ref: "#/$defs/NativeTextCell",
        },
        native_fields: {
          additionalProperties: {
            $ref: "#/$defs/NativeTextCell",
          },
          maxProperties: 4,
          minProperties: 2,
          type: "object",
        },
        matches: {
          items: {
            enum: ["start", "end"],
            type: "string",
          },
          maxItems: 2,
          type: "array",
        },
      },
      required: [
        "event_id",
        "record_id",
        "read_id",
        "occurrence",
        "timestamp",
        "native_fields",
        "matches",
      ],
      type: "object",
    },
    SourceRead: {
      additionalProperties: false,
      properties: {
        read_id: {
          maxLength: 69,
          minLength: 69,
          pattern: "^read-[0-9a-f]{64}$",
          type: "string",
        },
        ordinal: {
          maximum: 101,
          minimum: 0,
          type: "integer",
        },
        kind: {
          enum: ["jira_access", "record", "history"],
          type: "string",
        },
        template: {
          enum: [
            "servicenow_record",
            "jira_accessible_resources",
            "jira_issue",
            "jira_changelog",
            "pagerduty_incident",
            "pagerduty_log_entries",
          ],
          type: "string",
        },
        state: {
          enum: ["admitted", "rejected", "unavailable"],
          type: "string",
        },
        http_status: {
          anyOf: [
            {
              maximum: 599,
              minimum: 100,
              type: "integer",
            },
            {
              type: "null",
            },
          ],
        },
        retrieved_at: {
          type: "string",
        },
        body_bytes: {
          maximum: 1048577,
          minimum: 0,
          type: "integer",
        },
        body_complete: {
          type: "boolean",
        },
        body_sha256: {
          anyOf: [
            {
              maxLength: 64,
              minLength: 64,
              pattern: "^[0-9a-f]{64}$",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        accepted: {
          type: "boolean",
        },
        pagination: {
          anyOf: [
            {
              $ref: "#/$defs/DeclaredPagination",
            },
            {
              type: "null",
            },
          ],
        },
        received_records: {
          anyOf: [
            {
              maximum: 100000,
              minimum: 0,
              type: "integer",
            },
            {
              type: "null",
            },
          ],
        },
        admitted_events: {
          maximum: 10000,
          minimum: 0,
          type: "integer",
        },
        diagnostic_codes: {
          items: {
            enum: [
              "profile_refused",
              "credential_missing",
              "credential_expired",
              "credential_invalid",
              "offline_refused",
              "destination_refused",
              "dns_failure",
              "dns_timeout",
              "connect_failure",
              "tls_failure",
              "read_timeout",
              "deadline_exceeded",
              "redirect_refused",
              "http_unauthorized",
              "http_forbidden",
              "http_not_found",
              "http_status_refused",
              "body_limit",
              "response_budget",
              "unsupported_encoding",
              "invalid_json",
              "source_shape",
              "record_mismatch",
              "site_grant_refused",
              "pagination_conflict",
              "duplicate_occurrence",
              "source_conflict",
              "page_limit",
              "event_limit",
              "result_limit",
              "timestamp_unsupported",
              "event_missing",
              "event_null",
              "event_empty",
              "event_ambiguous",
              "occurrence_not_found",
              "reversed_order",
              "incomplete_source",
              "cleanup_failure",
              "header_limit",
              "framing_limit",
              "wire_budget",
              "framing_invalid",
            ],
            type: "string",
          },
          maxItems: 64,
          type: "array",
        },
        wire_bytes: {
          maximum: 1179649,
          minimum: 0,
          type: "integer",
        },
      },
      required: [
        "read_id",
        "ordinal",
        "kind",
        "template",
        "state",
        "http_status",
        "retrieved_at",
        "body_bytes",
        "body_complete",
        "body_sha256",
        "accepted",
        "pagination",
        "received_records",
        "admitted_events",
        "diagnostic_codes",
        "wire_bytes",
      ],
      type: "object",
    },
  },
  additionalProperties: false,
  properties: {
    schema_version: {
      const: "1",
      type: "string",
    },
    provider: {
      enum: ["servicenow", "jira", "pagerduty"],
      type: "string",
    },
    request: {
      oneOf: [
        {
          $ref: "#/$defs/ServiceNowRequest",
        },
        {
          $ref: "#/$defs/JiraRequest",
        },
        {
          $ref: "#/$defs/PagerDutyRequest",
        },
      ],
    },
    run_id: {
      maxLength: 26,
      minLength: 26,
      pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
      type: "string",
    },
    observation_scope: {
      const: "selected_incident_clock",
      type: "string",
    },
    definition: {
      $ref: "#/$defs/PublishedClockDefinition",
    },
    source_state: {
      enum: ["complete", "incomplete", "unavailable"],
      type: "string",
    },
    clock: {
      $ref: "#/$defs/ClockOutcome",
    },
    events: {
      items: {
        $ref: "#/$defs/SourceEvent",
      },
      maxItems: 10000,
      type: "array",
    },
    record: {
      anyOf: [
        {
          $ref: "#/$defs/SelectedRecordProjection",
        },
        {
          type: "null",
        },
      ],
    },
    source_reads: {
      items: {
        $ref: "#/$defs/SourceRead",
      },
      maxItems: 102,
      type: "array",
    },
    diagnostics: {
      items: {
        $ref: "#/$defs/Diagnostic",
      },
      maxItems: 64,
      type: "array",
    },
    findings: {
      items: {
        $ref: "#/$defs/IncidentClockFinding",
      },
      maxItems: 1,
      type: "array",
    },
    manifest: {
      $ref: "#/$defs/IncidentClockManifest",
    },
    profile_binding_sha256: {
      maxLength: 64,
      minLength: 64,
      pattern: "^[0-9a-f]{64}$",
      type: "string",
    },
    credential_validity: {
      enum: ["expiry_checked", "expiry_unknown", "not_established"],
      type: "string",
    },
  },
  required: [
    "schema_version",
    "provider",
    "request",
    "run_id",
    "observation_scope",
    "definition",
    "source_state",
    "clock",
    "events",
    "record",
    "source_reads",
    "diagnostics",
    "findings",
    "manifest",
    "profile_binding_sha256",
    "credential_validity",
  ],
  type: "object",
};

/** Refuse duplicate members, unsafe numeric values and invalid Unicode before native decoding. */
export function parseIncidentJson(
  raw: string,
  maximum = INCIDENT_RESULT_BYTES,
): unknown {
  if (typeof raw !== "string" || raw.length > maximum || size(raw) > maximum)
    return failure();
  let cursor = 0;
  let nodes = 0;
  const number = /-?(?:0|[1-9][0-9]*)/y;
  const whitespace = () => {
    while (cursor < raw.length && " \t\r\n".includes(raw[cursor])) cursor++;
  };
  const string = (): string => {
    const start = cursor++;
    let escaped = false;
    while (cursor < raw.length) {
      const character = raw[cursor++];
      if (!escaped && character === '"') {
        const value: unknown = JSON.parse(raw.slice(start, cursor));
        if (
          typeof value !== "string" ||
          /\p{Surrogate}/u.test(value) ||
          size(value) > 65_536
        )
          return failure();
        return value;
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    return failure();
  };
  const visit = (depth: number): void => {
    if (++nodes > 8_388_608 || depth > 32) return failure();
    whitespace();
    const character = raw[cursor];
    if (character === '"') {
      string();
      return;
    }
    if (character === "{" || character === "[") {
      const object = character === "{";
      const close = object ? "}" : "]";
      const keys = new Set<string>();
      let count = 0;
      cursor++;
      whitespace();
      if (raw[cursor] !== close)
        for (;;) {
          if (++count > (object ? 128 : 10_000)) return failure();
          if (object) {
            if (raw[cursor] !== '"') return failure();
            const key = string();
            if (keys.has(key)) return failure();
            keys.add(key);
            whitespace();
            if (raw[cursor++] !== ":") return failure();
          }
          visit(depth + 1);
          whitespace();
          if (raw[cursor] === close) break;
          if (raw[cursor++] !== ",") return failure();
          whitespace();
        }
      cursor++;
      return;
    }
    for (const literal of ["null", "true", "false"])
      if (raw.startsWith(literal, cursor)) {
        cursor += literal.length;
        return;
      }
    number.lastIndex = cursor;
    const matched = number.exec(raw);
    if (!matched || !Number.isSafeInteger(Number(matched[0]))) return failure();
    cursor = number.lastIndex;
  };
  try {
    visit(0);
    whitespace();
    if (cursor !== raw.length) return failure();
    return JSON.parse(raw);
  } catch {
    return failure();
  }
}
function matches(
  value: unknown,
  schema: JsonSchema,
  root: JsonSchema = RESULT_SCHEMA,
  requireAll = false,
): boolean {
  if (
    schema.allOf &&
    !schema.allOf.every((item) => matches(value, item, root, requireAll))
  )
    return false;
  if (schema.$ref) {
    if (!schema.$ref.startsWith("#/$defs/")) return false;
    const name = schema.$ref.slice(8);
    const definitions = root.$defs!;
    if (
      !Object.hasOwn(definitions, name) ||
      !matches(value, definitions[name], root, requireAll)
    )
      return false;
  }
  if (
    schema.oneOf &&
    schema.oneOf.filter((item) => matches(value, item, root, requireAll))
      .length !== 1
  )
    return false;
  if (
    schema.anyOf &&
    !schema.anyOf.some((item) => matches(value, item, root, requireAll))
  )
    return false;
  if (Object.hasOwn(schema, "const") && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "null") return value === null;
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "string") {
    if (typeof value !== "string" || /\p{Surrogate}/u.test(value)) return false;
    const length = [...value].length;
    if (
      (schema.minLength !== undefined && length < schema.minLength) ||
      (schema.maxLength !== undefined && length > schema.maxLength)
    )
      return false;
    if (
      schema.pattern &&
      !new RegExp(schema.pattern.replace(/\$$/, "(?![\\s\\S])"), "u").test(
        value,
      )
    )
      return false;
    if (schema.format === "date-time") {
      if (
        !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/.test(
          value,
        )
      )
        return false;
      const date = new Date(value);
      if (
        !Number.isFinite(date.getTime()) ||
        date.toISOString().slice(0, 19) !== value.slice(0, 19)
      )
        return false;
    }
  } else if (schema.type === "integer" || schema.type === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) return false;
    if (schema.type === "integer" && !Number.isSafeInteger(value)) return false;
    if (
      (schema.minimum !== undefined && value < schema.minimum) ||
      (schema.maximum !== undefined && value > schema.maximum) ||
      (schema.exclusiveMinimum !== undefined &&
        value <= schema.exclusiveMinimum) ||
      (schema.exclusiveMaximum !== undefined &&
        value >= schema.exclusiveMaximum)
    )
      return false;
  } else if (schema.type === "array") {
    if (
      !Array.isArray(value) ||
      (schema.minItems !== undefined && value.length < schema.minItems) ||
      (schema.maxItems !== undefined && value.length > schema.maxItems)
    )
      return false;
    if (
      schema.items &&
      !value.every((item) => matches(item, schema.items!, root, requireAll))
    )
      return false;
  } else if (schema.type === "object") {
    if (!isObject(value)) return false;
    const keys = Object.keys(value);
    if (
      (schema.minProperties !== undefined &&
        keys.length < schema.minProperties) ||
      (schema.maxProperties !== undefined && keys.length > schema.maxProperties)
    )
      return false;
    if (
      (requireAll && schema.properties
        ? Object.keys(schema.properties)
        : schema.required
      )?.some((key) => !Object.hasOwn(value, key))
    )
      return false;
    for (const key of keys) {
      const properties = schema.properties ?? {};
      if (Object.hasOwn(properties, key)) {
        if (!matches(value[key], properties[key], root, requireAll))
          return false;
      } else if (schema.additionalProperties === false) return false;
      else if (
        isObject(schema.additionalProperties) &&
        !matches(value[key], schema.additionalProperties, root, requireAll)
      )
        return false;
    }
  }
  return true;
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function same(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right))
    return (
      left.length === right.length &&
      left.every((item, i) => same(item, right[i]))
    );
  if (!isObject(left) || !isObject(right)) return false;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every(
      (key) => Object.hasOwn(right, key) && same(left[key], right[key]),
    )
  );
}
function applicationClock(value: string): void {
  const match =
    /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z$/.exec(
      value,
    );
  if (!match || match[0] !== value) return failure();
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > days[month - 1] ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  )
    return failure();
}

function nativeRequest(
  value: unknown,
  depth = 0,
  budget = { nodes: 0 },
): unknown {
  if (depth > 16 || ++budget.nodes > 64) return failure();
  if (
    value === null ||
    typeof value === "string" ||
    (typeof value === "number" && Number.isSafeInteger(value))
  )
    return value;
  if (
    !isObject(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    return failure();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 16) return failure();
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    if (typeof key !== "string") return failure();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      return failure();
    Object.defineProperty(copy, key, {
      value: nativeRequest(descriptor.value, depth + 1, budget),
      enumerable: true,
    });
  }
  return copy;
}

type ExactInstant = { ticks: bigint; scale: number };
const power = (scale: number) => 10n ** BigInt(scale);
function decimal(ticks: bigint, scale: number): string {
  const sign = ticks < 0n ? "-" : "";
  const absolute = ticks < 0n ? -ticks : ticks;
  const whole = absolute / power(scale);
  const fraction = (absolute % power(scale))
    .toString()
    .padStart(scale, "0")
    .replace(/0+$/, "");
  return sign + whole.toString() + (fraction ? "." + fraction : "");
}
export function incidentInstant(
  literal: string,
  provider: IncidentProvider,
): ExactInstant {
  if (
    typeof literal !== "string" ||
    literal.length > 2048 ||
    /[^\x00-\x7f]/.test(literal)
  )
    return failure();
  const head =
    "([0-9]{4})-([0-9]{2})-([0-9]{2})" +
    (provider === "servicenow" ? " " : "[Tt]") +
    "([0-9]{2}):([0-9]{2}):([0-9]{2})";
  const tail =
    provider === "servicenow"
      ? ""
      : "(?:\\.([0-9]{1,2000}))?([Zz]|[+-][0-9]{2}" +
        (provider === "jira" ? ":?" : ":") +
        "[0-9]{2})";
  const match = new RegExp("^" + head + tail + "$").exec(literal);
  if (!match || match[0] !== literal) return failure();
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > days[month - 1] ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  )
    return failure();
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  let offset = 0;
  const zone = match[8] ?? "Z";
  if (!/^[Zz]$/.test(zone)) {
    const compact = zone.replace(":", "");
    const hours = Number(compact.slice(1, 3)),
      minutes = Number(compact.slice(3));
    if (hours > 23 || minutes > 59 || compact === "-0000") return failure();
    offset = (hours * 60 + minutes) * 60 * (compact[0] === "-" ? -1 : 1);
  }
  const seconds = date.getTime() / 1000 - offset;
  if (
    !Number.isSafeInteger(seconds) ||
    seconds < -62_135_596_800 ||
    seconds > 253_402_300_799
  )
    return failure();
  const fraction = match[7] ?? "";
  return {
    ticks: BigInt(seconds) * power(fraction.length) + BigInt(fraction || "0"),
    scale: fraction.length,
  };
}
function difference(start: ExactInstant, end: ExactInstant): ExactInstant {
  const scale = Math.max(start.scale, end.scale);
  return {
    ticks:
      end.ticks * power(scale - end.scale) -
      start.ticks * power(scale - start.scale),
    scale,
  };
}
const pythonBlank =
  /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;
function safeText(value: unknown, maximum: number): asserts value is string {
  if (
    typeof value !== "string" ||
    size(value) > maximum ||
    pythonBlank.test(value) ||
    /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)
  )
    return failure();
}
export function snapshotIncidentRequest(input: unknown): IncidentClockRequest {
  try {
    const detached = nativeRequest(input);
    const raw = JSON.stringify(detached);
    if (
      size(raw) > INCIDENT_REQUEST_BYTES ||
      !matches(detached, REQUEST_SCHEMA, REQUEST_SCHEMA) ||
      !isObject(detached)
    )
      return failure();
    if (
      typeof detached.profile_alias !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(detached.profile_alias) ||
      typeof detached.clock_alias !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(detached.clock_alias)
    )
      return failure();
    const result = JSON.parse(raw) as IncidentClockRequest;
    if (result.provider !== "servicenow") {
      result.start_occurrence ??= null;
      result.end_occurrence ??= null;
      for (const occurrence of [result.start_occurrence, result.end_occurrence])
        if (occurrence !== null)
          safeText(
            "history_id" in occurrence
              ? occurrence.history_id
              : occurrence.event_id,
            256,
          );
    }
    if (result.provider === "pagerduty") {
      const delta = difference(
        incidentInstant(result.since, "pagerduty"),
        incidentInstant(result.until, "pagerduty"),
      );
      if (delta.ticks <= 0n || delta.ticks > 31_622_400n * power(delta.scale))
        return failure();
    }
    return freeze(result);
  } catch {
    return failure();
  }
}
export function parseIncidentRequest(raw: string): IncidentClockRequest {
  return snapshotIncidentRequest(
    parseIncidentJson(raw, INCIDENT_REQUEST_BYTES),
  );
}

type SourceEvent = IncidentClockResult["events"][number];
type NativeCell = SourceEvent["timestamp"];
type Mapping = IncidentClockResult["definition"]["start"];
type Side = "start" | "end";
function cell(value: NativeCell, maximum: number): void {
  if (value.state === "missing" || value.state === "null") {
    if (value.value !== null) return failure();
  } else if (value.state === "empty") {
    if (value.value !== "") return failure();
  } else if (
    typeof value.value !== "string" ||
    value.value.length === 0 ||
    size(value.value) > maximum
  )
    return failure();
}
function mappingMatches(
  provider: IncidentProvider,
  mapping: Mapping,
  event: SourceEvent,
): boolean {
  if (provider === "servicenow") {
    if (!("field" in mapping) || !("field" in event.occurrence))
      return failure();
    return mapping.field === event.occurrence.field;
  }
  if (provider === "jira") {
    if (!("field_id" in mapping) || !("history_id" in event.occurrence))
      return failure();
    return (
      event.native_fields.fieldId.value === mapping.field_id &&
      same(event.native_fields.from, mapping.from) &&
      same(event.native_fields.to, mapping.to)
    );
  }
  if (!("event_type" in mapping) || !("event_id" in event.occurrence))
    return failure();
  return event.native_fields.type.value === mapping.event_type;
}
function selectedSide(
  request: IncidentClockRequest,
  side: Side,
  events: SourceEvent[],
  complete: boolean,
): IncidentClockResult["clock"]["start"] {
  const explicit =
    request.provider === "servicenow"
      ? null
      : (request[side === "start" ? "start_occurrence" : "end_occurrence"] ??
        null);
  const selected: IncidentClockResult["clock"]["start"] = {
    state: "missing",
    candidate_event_ids: events.map((event) => event.event_id),
    selected_event_id: null,
    explicit_occurrence: explicit,
    source_literal: null,
    utc_seconds: null,
  };
  if (!complete) {
    selected.state = "incomplete";
    return selected;
  }
  const eligible =
    explicit === null
      ? events
      : events.filter((event) => same(event.occurrence, explicit));
  if (eligible.length === 0)
    selected.state = explicit === null ? "missing" : "occurrence_not_found";
  else if (eligible.length > 1) selected.state = "ambiguous";
  else {
    const event = eligible[0];
    selected.selected_event_id = event.event_id;
    selected.source_literal = event.timestamp.value;
    selected.state =
      event.timestamp.state === "value"
        ? "unsupported_timestamp"
        : event.timestamp.state;
    if (event.timestamp.state === "value")
      try {
        const instant = incidentInstant(
          event.timestamp.value!,
          request.provider,
        );
        selected.utc_seconds = decimal(instant.ticks, instant.scale);
        selected.state = "selected";
      } catch {
        selected.state = "unsupported_timestamp";
      }
  }
  return selected;
}
export interface IncidentClockResponse {
  readonly result: IncidentClockResult;
  readonly rawJson: string;
}
/** Validate full source and selection correspondence while retaining the original JSON text. */
export function parseIncidentResponse(
  rawJson: string,
  request: unknown,
): IncidentClockResponse {
  try {
    const expected = snapshotIncidentRequest(request);
    const value = parseIncidentJson(rawJson);
    if (!matches(value, RESULT_SCHEMA, RESULT_SCHEMA, true)) return failure();
    const result = value as IncidentClockResult;
    if (
      result.provider !== expected.provider ||
      !same(result.request, expected) ||
      result.definition.clock_alias !== expected.clock_alias
    )
      return failure();
    safeText(result.definition.label, 128);
    safeText(result.definition.mapping_reference, 512);
    safeText(result.definition.declared_workflow_meaning, 1024);
    for (const mapping of [result.definition.start, result.definition.end]) {
      safeText(mapping.label, 128);
      safeText(mapping.meaning, 512);
      if (
        (result.provider === "servicenow" && !("field" in mapping)) ||
        (result.provider === "jira" && !("field_id" in mapping)) ||
        (result.provider === "pagerduty" && !("event_type" in mapping))
      )
        return failure();
      if ("field_id" in mapping) {
        safeText(mapping.field_id, 256);
        cell(mapping.from, 65_536);
        cell(mapping.to, 65_536);
      }
    }
    const firstMapping = result.definition.start,
      lastMapping = result.definition.end;
    if (
      ("field" in firstMapping &&
        "field" in lastMapping &&
        firstMapping.field === lastMapping.field) ||
      ("event_type" in firstMapping &&
        "event_type" in lastMapping &&
        firstMapping.event_type === lastMapping.event_type) ||
      ("field_id" in firstMapping &&
        "field_id" in lastMapping &&
        firstMapping.field_id === lastMapping.field_id &&
        same(firstMapping.from, lastMapping.from) &&
        same(firstMapping.to, lastMapping.to))
    )
      return failure();
    const reads = new Map(
      result.source_reads.map((read) => [read.read_id, read]),
    );
    const events = new Map(
      result.events.map((event) => [event.event_id, event]),
    );
    if (
      reads.size !== result.source_reads.length ||
      events.size !== result.events.length
    )
      return failure();
    if (
      (result.credential_validity === "not_established" && reads.size) ||
      (result.credential_validity === "expiry_unknown" &&
        result.provider !== "pagerduty")
    )
      return failure();
    const clockCodes = new Set([
      "timestamp_unsupported",
      "event_missing",
      "event_null",
      "event_empty",
      "event_ambiguous",
      "occurrence_not_found",
      "reversed_order",
      "incomplete_source",
    ]);
    const causal = result.diagnostics.filter(
      (item) => !clockCodes.has(item.code),
    );
    const diagnosticKeys = result.diagnostics.map((item) =>
      JSON.stringify([item.code, item.read_id, item.side]),
    );
    if (
      new Set(diagnosticKeys).size !== diagnosticKeys.length ||
      result.diagnostics.some(
        (item) => item.read_id !== null && !reads.has(item.read_id),
      )
    )
      return failure();
    let cursor = 0,
      total: number | null = null,
      terminal = false,
      bodyBytes = 0,
      wireBytes = 0;
    const recordIndex = result.provider === "jira" ? 1 : 0;
    for (const [index, read] of result.source_reads.entries()) {
      applicationClock(read.retrieved_at);
      if (
        read.ordinal !== index ||
        (index > 0 && !result.source_reads[index - 1].accepted)
      )
        return failure();
      const kind =
        result.provider === "jira" && index === 0
          ? "jira_access"
          : index === recordIndex
            ? "record"
            : "history";
      const template =
        kind === "jira_access"
          ? "jira_accessible_resources"
          : kind === "record"
            ? (
                {
                  jira: "jira_issue",
                  servicenow: "servicenow_record",
                  pagerduty: "pagerduty_incident",
                } as const
              )[result.provider]
            : result.provider === "jira"
              ? "jira_changelog"
              : "pagerduty_log_entries";
      if (
        read.kind !== kind ||
        read.template !== template ||
        (result.provider === "servicenow" && index > 0)
      )
        return failure();
      if (
        read.body_complete !== (read.body_sha256 !== null) ||
        (read.body_complete &&
          (read.http_status !== 200 || read.body_bytes > 1_048_576))
      )
        return failure();
      if (
        (read.accepted &&
          (!read.body_complete ||
            read.received_records === null ||
            read.state !== "admitted")) ||
        (!read.accepted &&
          (read.state === "admitted" ||
            read.admitted_events !== 0 ||
            read.pagination !== null))
      )
        return failure();
      if (
        ((!read.body_complete ||
          read.diagnostic_codes.includes("invalid_json")) &&
          read.received_records !== null) ||
        (read.accepted && kind === "record" && read.received_records !== 1)
      )
        return failure();
      if (read.wire_bytes < read.body_bytes) return failure();
      bodyBytes += read.body_bytes;
      wireBytes += read.wire_bytes;
      if (bodyBytes > 8_388_609 || wireBytes > 10_485_761) return failure();
      const codes = [
        ...new Set(
          result.diagnostics
            .filter((item) => item.read_id === read.read_id)
            .map((item) => item.code),
        ),
      ];
      if (!same(codes, read.diagnostic_codes)) return failure();
      if (kind === "history") {
        if (terminal) return failure();
        if (read.accepted) {
          const page = read.pagination;
          if (
            !page ||
            page.start !== cursor ||
            (total !== null && total !== page.total) ||
            page.returned !== read.received_records ||
            page.returned > page.limit ||
            page.start + page.returned > page.total ||
            page.terminal !== (page.start + page.returned === page.total) ||
            (!page.terminal && page.returned === 0)
          )
            return failure();
          cursor += page.returned;
          total = page.total;
          terminal = page.terminal;
          if (cursor > 10_000) return failure();
        }
      } else if (read.pagination !== null) return failure();
    }
    const recordRead = result.source_reads[recordIndex];
    if ((result.record !== null) !== Boolean(recordRead?.accepted))
      return failure();
    if (result.record) {
      const record = result.record;
      if (
        record.provider !== result.provider ||
        record.record_id !== expected.record_id ||
        record.read_id !== recordRead.read_id
      )
        return failure();
      const fields =
        result.provider === "servicenow" &&
        "field" in result.definition.start &&
        "field" in result.definition.end
          ? [
              "sys_id",
              result.definition.start.field,
              result.definition.end.field,
            ]
          : result.provider === "jira"
            ? ["id", "fields.created"]
            : ["id", "created_at"];
      if (!same(Object.keys(record.fields).sort(), fields.sort()))
        return failure();
      const identity = result.provider === "servicenow" ? "sys_id" : "id";
      if (
        record.fields[identity].state !== "value" ||
        record.fields[identity].value !== expected.record_id
      )
        return failure();
      for (const [name, value] of Object.entries(record.fields))
        cell(value, name === identity ? 128 : 2048);
    } else if (result.events.length) return failure();
    const counts = new Map<string, number>();
    const occurrences = new Set<string>();
    const sides: Record<Side, SourceEvent[]> = { start: [], end: [] };
    let lastOrdinal = -1;
    for (const event of result.events) {
      const read = reads.get(event.read_id);
      if (
        event.record_id !== expected.record_id ||
        !read?.accepted ||
        read.ordinal < lastOrdinal ||
        read.kind !== (result.provider === "servicenow" ? "record" : "history")
      )
        return failure();
      lastOrdinal = read.ordinal;
      const occurrenceKey = JSON.stringify(
        Object.entries(event.occurrence).sort(([left], [right]) =>
          left.localeCompare(right),
        ),
      );
      if (occurrences.has(occurrenceKey)) return failure();
      occurrences.add(occurrenceKey);
      counts.set(event.read_id, (counts.get(event.read_id) ?? 0) + 1);
      const fields =
        result.provider === "servicenow"
          ? ["field", "value"]
          : result.provider === "jira"
            ? ["fieldId", "from", "to", "created"]
            : ["id", "type", "created_at", "incident.id"];
      const timeKey =
        result.provider === "servicenow"
          ? "value"
          : result.provider === "jira"
            ? "created"
            : "created_at";
      if (
        !same(Object.keys(event.native_fields).sort(), fields.sort()) ||
        !same(event.timestamp, event.native_fields[timeKey])
      )
        return failure();
      cell(event.timestamp, 2048);
      for (const [name, value] of Object.entries(event.native_fields))
        cell(
          value,
          name === timeKey
            ? 2048
            : name === "field"
              ? 80
              : ["fieldId", "id", "type", "incident.id"].includes(name)
                ? 256
                : 65_536,
        );
      if (result.provider === "servicenow") {
        if (
          !("field" in event.occurrence) ||
          event.native_fields.field.value !== event.occurrence.field ||
          event.native_fields.field.state !== "value" ||
          !same(event.timestamp, result.record?.fields[event.occurrence.field])
        )
          return failure();
      } else if (result.provider === "jira") {
        if (
          !("history_id" in event.occurrence) ||
          event.native_fields.fieldId.state !== "value"
        )
          return failure();
        safeText(event.occurrence.history_id, 256);
        if (
          !("field_id" in firstMapping) ||
          !("field_id" in lastMapping) ||
          ![firstMapping.field_id, lastMapping.field_id].includes(
            event.native_fields.fieldId.value!,
          )
        )
          return failure();
      } else {
        if (
          !("event_id" in event.occurrence) ||
          event.native_fields.id.value !== event.occurrence.event_id ||
          event.native_fields.id.state !== "value" ||
          event.native_fields["incident.id"].value !== expected.record_id ||
          event.native_fields["incident.id"].state !== "value" ||
          event.native_fields.type.state !== "value"
        )
          return failure();
        safeText(event.occurrence.event_id, 256);
        if (
          ![
            "acknowledge_log_entry",
            "annotate_log_entry",
            "assign_log_entry",
            "delegate_log_entry",
            "escalate_log_entry",
            "exhaust_escalation_path_log_entry",
            "notify_log_entry",
            "reach_ack_limit_log_entry",
            "reach_trigger_limit_log_entry",
            "repeat_escalation_path_log_entry",
            "resolve_log_entry",
            "snooze_log_entry",
            "trigger_log_entry",
            "unacknowledge_log_entry",
            "urgency_change_log_entry",
            "field_value_change_log_entry",
            "custom_field_value_change_log_entry",
          ].includes(event.native_fields.type.value!)
        )
          return failure();
      }
      const matched: Side[] = [];
      for (const side of ["start", "end"] as const)
        if (mappingMatches(result.provider, result.definition[side], event)) {
          matched.push(side);
          sides[side].push(event);
        }
      if (!same(matched, event.matches)) return failure();
    }
    for (const read of result.source_reads)
      if (
        read.admitted_events !== (counts.get(read.read_id) ?? 0) ||
        (read.accepted &&
          read.kind === "history" &&
          (result.provider === "pagerduty"
            ? read.admitted_events !== read.received_records
            : read.admitted_events > read.received_records! * 256))
      )
        return failure();
    if (
      result.provider === "servicenow" &&
      result.record &&
      result.events.length !== 2
    )
      return failure();
    if (
      size(JSON.stringify({ record: result.record, events: result.events })) >
      12_582_912
    )
      return failure();
    const sourceState = !result.record
      ? "unavailable"
      : causal.length ||
          result.source_reads.some((read) => !read.accepted) ||
          (result.provider !== "servicenow" && !terminal)
        ? "incomplete"
        : "complete";
    if (result.source_state !== sourceState) return failure();
    const start = selectedSide(
      expected,
      "start",
      sides.start,
      sourceState === "complete",
    );
    const end = selectedSide(
      expected,
      "end",
      sides.end,
      sourceState === "complete",
    );
    let clockState: IncidentClockResult["clock"]["state"] =
      sourceState === "complete" ? "unresolved_events" : "incomplete_source";
    let elapsed: string | null = null;
    if (
      sourceState === "complete" &&
      start.state === "selected" &&
      end.state === "selected"
    ) {
      const delta = difference(
        incidentInstant(start.source_literal!, result.provider),
        incidentInstant(end.source_literal!, result.provider),
      );
      clockState = delta.ticks < 0n ? "reversed_order" : "computed";
      if (delta.ticks >= 0n) elapsed = decimal(delta.ticks, delta.scale);
    }
    if (
      !same(result.clock, {
        state: clockState,
        start,
        end,
        elapsed_seconds: elapsed,
      })
    )
      return failure();
    const clockDiagnostics: IncidentClockResult["diagnostics"] = [];
    const stateCodes: Record<
      string,
      IncidentClockResult["diagnostics"][number]["code"]
    > = {
      missing: "event_missing",
      null: "event_null",
      empty: "event_empty",
      unsupported_timestamp: "timestamp_unsupported",
      ambiguous: "event_ambiguous",
      occurrence_not_found: "occurrence_not_found",
    };
    if (clockState === "incomplete_source") {
      const seen = new Set<string>();
      for (const event of result.events) {
        let code = stateCodes[event.timestamp.state];
        if (event.timestamp.state === "value") {
          try {
            incidentInstant(event.timestamp.value!, result.provider);
          } catch {
            code = "timestamp_unsupported";
          }
        }
        if (code)
          for (const side of event.matches) {
            const key = side + ":" + code;
            if (!seen.has(key)) {
              clockDiagnostics.push({ code, read_id: event.read_id, side });
              seen.add(key);
            }
          }
      }
      clockDiagnostics.push({
        code: "incomplete_source",
        read_id: null,
        side: null,
      });
    } else {
      for (const [side, selected] of [
        ["start", start],
        ["end", end],
      ] as const) {
        const code = stateCodes[selected.state];
        if (code)
          clockDiagnostics.push({
            code,
            read_id:
              events.get(selected.selected_event_id ?? "")?.read_id ?? null,
            side,
          });
      }
      if (clockState === "reversed_order")
        clockDiagnostics.push({
          code: "reversed_order",
          read_id: null,
          side: null,
        });
    }
    if (
      causal.some((item) => item.side !== null) ||
      !same(result.diagnostics, [...causal, ...clockDiagnostics])
    )
      return failure();
    const filter = {
      observation_scope: "selected_incident_clock",
      request: expected,
      profile_binding_sha256: result.profile_binding_sha256,
      definition_sha256: result.definition.definition_sha256,
    };
    const sourceSystem =
      "incident-clock:" + result.provider + ":" + result.profile_binding_sha256;
    const count = result.record === null ? 0 : 1;
    const manifest = result.manifest;
    const warnings = ["selected_scope_only", "workflow_mapping_only"];
    if (result.credential_validity === "expiry_unknown")
      warnings.push("credential_expiry_unknown");
    let errors =
      sourceState === "complete"
        ? []
        : [...new Set(causal.map((item) => item.code))];
    if (sourceState !== "complete" && !errors.length)
      errors = ["incomplete_source"];
    if (
      !same(manifest.warnings, warnings) ||
      !same(manifest.errors, errors) ||
      manifest.empty_categories.length
    )
      return failure();
    applicationClock(manifest.collection_started_at);
    applicationClock(manifest.collection_finished_at);
    if (
      manifest.collection_finished_at < manifest.collection_started_at ||
      manifest.run_id !== result.run_id ||
      !same(manifest.filters_applied, filter) ||
      !same(manifest.source_system_ids, [sourceSystem]) ||
      result.findings.length !== count ||
      manifest.total_findings !== count ||
      manifest.is_complete !== (sourceState === "complete") ||
      manifest.incomplete_reason !==
        (sourceState === "complete"
          ? null
          : "selected_source_" + sourceState) ||
      !same(manifest.coverage_counts, [
        {
          resource_type: "selected_incident_clock",
          scanned: count,
          matched_filter: count,
          collected: count,
        },
      ])
    )
      return failure();
    for (const finding of result.findings) {
      const context = finding.collection_context;
      const observed = recordRead.retrieved_at;
      const summary = {
        observation_scope: "selected_incident_clock",
        source_state: sourceState,
        clock_state: clockState,
        elapsed_seconds: elapsed,
        start_event_id: start.selected_event_id,
        end_event_id: end.selected_event_id,
        start_occurrence:
          events.get(start.selected_event_id ?? "")?.occurrence ?? null,
        end_occurrence:
          events.get(end.selected_event_id ?? "")?.occurrence ?? null,
        definition_sha256: result.definition.definition_sha256,
        profile_binding_sha256: result.profile_binding_sha256,
      };
      if (
        !same(finding.raw_data, summary) ||
        !context ||
        !same(context.filter_applied, filter) ||
        context.run_id !== result.run_id ||
        context.source_system_id !== sourceSystem ||
        context.collector_version !== manifest.collector_version ||
        context.evidentia_version !== manifest.evidentia_version ||
        context.collected_at !== observed ||
        finding.first_observed !== observed ||
        finding.last_observed !== observed ||
        finding.resource_id !== expected.record_id ||
        finding.description !==
          "Visible source is " +
            sourceState +
            "; configured clock is " +
            clockState +
            "."
      )
        return failure();
    }
    return Object.freeze({ result: freeze(result), rawJson });
  } catch {
    return failure();
  }
}
export function boundedIncidentPreview(value: string, maximum = 4096): string {
  if (size(value) <= maximum) return value;
  let kept = "",
    bytes = 0;
  for (const character of value) {
    const next = size(character);
    if (bytes + next > maximum) break;
    kept += character;
    bytes += next;
  }
  return kept;
}
/** Read actual UTF-8 bytes, independent of Content-Length, with prompt cancellation on refusal. */
export async function readIncidentResponse(
  response: Response,
  expected: unknown,
): Promise<IncidentClockResponse> {
  if (response.body === null) return failure();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let completed = false;
  try {
    if (
      response.status !== 200 ||
      !/^application\/json(?:[ \t]*;[^\r\n]*)?$/i.test(
        response.headers.get("content-type") ?? "",
      )
    )
      return failure();
    for (;;) {
      const part = await reader.read();
      if (part.done) {
        completed = true;
        break;
      }
      size += part.value.byteLength;
      if (size > INCIDENT_RESULT_BYTES) return failure();
      chunks.push(part.value.slice());
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
    return parseIncidentResponse(text, expected);
  } catch {
    return failure();
  } finally {
    if (!completed) {
      try {
        await reader.cancel();
      } catch {
        /* Keep the fixed refusal. */
      }
    }
    reader.releaseLock();
  }
}
