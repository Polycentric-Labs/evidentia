/** Strict native-catalog wire checks. Publisher content stays inert.
 * Ordinary prose remains a server-validated projection; there is no public projection digest.
 */

export type CatalogAuditContext = {
  authority: string;
  version: string;
  source_url: string;
  verified_on: string;
  valid_through: string | null;
  notes: string | null;
};

export type CatalogControl = {
  id: string;
  title: string;
  description: string;
  family: string | null;
  class: string | null;
  control_class: string | null;
  priority: string | null;
  baseline_impact: string[];
  enhancements: CatalogControl[];
  related_controls: string[];
  assessment_objectives: string[];
  objective: string | null;
  risk_tier: string | null;
  applies_to_annex_iii: string | null;
  guidance: string | null;
  examples: string[];
  parameters: Record<string, string>;
  ordering: number | null;
  tier: string | null;
  license_required: boolean;
  license_url: string | null;
  placeholder: boolean;
  withdrawn: boolean;
  properties: Record<string, string>;
  source_rows: CatalogSourceRow[];
  native_source_ref: CatalogNativeControlSourceRef | null;
};

export type CatalogNativeAbsentSelection = {
  state: "absent";
};

export type CatalogNativeControlBinding = {
  control_id: string;
  occurrence_index: number;
  family_occurrence_index: number | null;
  parent_control_id: string | null;
  admitted_criticality: "SHALL" | "SHOULD" | null;
};

export type CatalogNativeControlSourceRef = {
  bundle_sha256: string;
  occurrence_index: number;
};

export type CatalogNativeDiagnostic = {
  code:
    | "source_identity_conflict"
    | "missing_reference_record"
    | "source_reference_difference"
    | "legacy_ids_retired";
  occurrence_index: number | null;
  refs: CatalogNativeValueRef[];
};

export type CatalogNativeFieldRef = {
  name: string;
  key: CatalogNativeValueRef;
  value: CatalogNativeValueRef;
};

export type CatalogNativeNativeBundle = {
  bundle_sha256: string;
  data: CatalogNativeNativeData;
};

export type CatalogNativeNativeData = {
  schema_version: "catalog-native-v1";
  profile:
    | "au-ism-2026.09.4"
    | "cisa-scuba-m365-7ef9501d"
    | "bsi-grundschutz-plus-plus-367d7750";
  catalog_id: "au-ism" | "cisa-scuba" | "bsi-grundschutz-plus-plus";
  converter_id: "evidentia-open-corpora-v1";
  converter_sha256: string;
  documents: CatalogNativeSourceDocument[];
  occurrences: CatalogNativeOccurrence[];
  control_bindings: CatalogNativeControlBinding[];
  context_indices: number[];
  diagnostics: CatalogNativeDiagnostic[];
};

export type CatalogNativeNullSelection = {
  state: "native_null";
  refs: CatalogNativeValueRef[];
};

export type CatalogNativeOccurrence = {
  index: number;
  kind:
    | "catalog"
    | "metadata"
    | "group"
    | "control"
    | "principle"
    | "section"
    | "policy"
    | "reference_policy"
    | "context_block";
  parent_index: number | null;
  sibling_ordinal: number;
  source: CatalogNativeValueRef;
  fields: CatalogNativeFieldRef[];
  selections: CatalogNativeSemanticSelection[];
};

export type CatalogNativePresentSelection = {
  state: "present";
  refs: CatalogNativeValueRef[];
};

export type CatalogNativeSemanticSelection = {
  role:
    | "native_id"
    | "title"
    | "class"
    | "statement"
    | "guidance"
    | "parameter"
    | "applicability"
    | "essential_eight_applicability"
    | "rationale"
    | "note"
    | "last_modified"
    | "implementation"
    | "criticality"
    | "criticality_identity"
    | "resources"
    | "license_requirements"
    | "badge"
    | "nist_mapping"
    | "mitre_mapping"
    | "status"
    | "publication_time"
    | "native_version"
    | "schema_version"
    | "reference_record";
  value:
    | CatalogNativeAbsentSelection
    | CatalogNativeNullSelection
    | CatalogNativePresentSelection;
};

export type CatalogNativeSourceBinding = {
  source_key: string;
  role: "authoritative" | "reference" | "license" | "publication_context";
  media_type: "application/json" | "text/markdown" | "text/plain";
  repository: string;
  commit: string;
  upstream_path: string;
  raw_bytes: number;
  raw_sha256: string;
};

export type CatalogNativeSourceDocument = {
  binding: CatalogNativeSourceBinding;
  raw_utf8: string;
};

export type CatalogNativeValueRef = {
  document_index: number;
  byte_start: number;
  byte_end: number;
  kind:
    | "json_object"
    | "json_array"
    | "json_string"
    | "json_number"
    | "json_boolean"
    | "json_null"
    | "markdown_block"
    | "utf8_text";
  sha256: string;
};

export type CatalogPublicationNotice = {
  id: string;
  title: string;
  status: "approved-future" | "approved-superseded" | "pending";
  source_url: string;
  approved_on: string | null;
  published_on: string | null;
  order_effective_on: string | null;
  effective_on: string | null;
  inactive_on: string | null;
  superseded_by: string | null;
  notes: string | null;
};

export type CatalogSourceRow = {
  source_sha256: string;
  sheet: string;
  row: number;
  source_id: string | number | number | boolean | null;
  source_id_format: string | null;
  interpreted_id: string | null;
  kind: "aggregate" | "clause" | "fragment";
  values: Record<string, string | number | number | boolean | null>;
  resolved_values: Record<string, string | number | number | boolean | null>;
  provenance: Record<string, string>;
};

export type ControlCatalog = {
  framework_id: string;
  framework_name: string;
  version: string;
  source: string;
  controls: CatalogControl[];
  families: string[];
  family_hierarchy: Record<string, string[]> | null;
  category: "control" | "technique" | "vulnerability" | "obligation";
  tier: string | null;
  v0_9_3_note: string | null;
  annex_iii_risk_categories: string[] | null;
  license_required: boolean;
  license_terms: string | null;
  license_url: string | null;
  placeholder: boolean;
  status: "current" | "superseded" | "retired" | "historical" | null;
  notes: string | null;
  verified_on: string | null;
  superseded_by: string | null;
  audit_contexts: Record<string, CatalogAuditContext>;
  publication_notices: CatalogPublicationNotice[];
  native_source: CatalogNativeNativeBundle | null;
};

export type CatalogNativeSourceUpload = {
  source_key: "bsi-catalog" | "bsi-license" | "bsi-readme";
  raw_utf8: string;
};

export type CatalogNativeExternalImportRequest = {
  profile: "bsi-grundschutz-plus-plus-367d7750";
  documents: CatalogNativeSourceUpload[];
};

export type CatalogNativeImportResult = {
  schema_version: "catalog-native-import-result-v1";
  catalog_id: "bsi-grundschutz-plus-plus";
  bundle_sha256: string;
  projection_sha256: string;
  status: "imported" | "already_present";
  control_count: 1000;
  storage: "external";
  source_hashes: string[];
};

export type CatalogNativeNativeReadRequest = {
  framework_id: "au-ism" | "cisa-scuba" | "bsi-grundschutz-plus-plus";
  bundle_sha256: string;
};

export type CatalogNativeNativeReadError = {
  code:
    | "native_source_unavailable"
    | "catalog_generation_changed"
    | "native_source_invalid"
    | "processing_deadline_exceeded";
};

export type CatalogNativeCatalogPublicationObservation = {
  schema_version: "catalog-publication-observation-v1";
  operation:
    "native_import" | "legacy_import" | "remove" | "compatibility_replace";
  publication_state:
    | "not_attempted"
    | "unchanged"
    | "not_committed"
    | "committed"
    | "indeterminate";
  prior_manifest_state: "unread" | "absent" | "present";
  prior_sha256: string | null;
  proposed_sha256: string | null;
  replace_outcome: "not_called" | "returned" | "raised";
  observed_manifest_state: "not_observed" | "absent" | "present";
  observed_sha256: string | null;
  readback_result:
    | "not_attempted"
    | "matches_prior"
    | "matches_proposed"
    | "other"
    | "unavailable";
  cleanup_state: "not_started" | "complete" | "failed";
  cleanup_errors: (
    "temporary_cleanup_failed" | "handle_close_failed" | "lock_release_failed"
  )[];
  failure_phase:
    | null
    | "admission"
    | "preparation"
    | "lock"
    | "manifest_read"
    | "generation"
    | "manifest_stage"
    | "replace"
    | "readback"
    | "cleanup";
  primary_kind: "none" | "exception" | "base_exception";
  error_code:
    | null
    | "catalog_transaction_conflict"
    | "catalog_storage_unsupported"
    | "catalog_manifest_invalid"
    | "catalog_storage_limit_exceeded"
    | "catalog_generation_conflict"
    | "catalog_storage_failed"
    | "catalog_publication_failed"
    | "catalog_publication_indeterminate"
    | "catalog_cleanup_failed"
    | "processing_deadline_exceeded"
    | "catalog_interrupted";
};

export type CatalogNativeCatalogStorageErrorEnvelope = {
  code:
    | "catalog_transaction_conflict"
    | "catalog_generation_conflict"
    | "catalog_storage_unsupported"
    | "catalog_manifest_invalid"
    | "catalog_storage_limit_exceeded"
    | "catalog_storage_failed"
    | "catalog_publication_failed"
    | "catalog_publication_indeterminate"
    | "catalog_cleanup_failed"
    | "processing_deadline_exceeded";
  publication: CatalogNativeCatalogPublicationObservation;
};

export type NativeBundle = CatalogNativeNativeBundle;
export type NativeCatalog = ControlCatalog;
export type ValueRef = CatalogNativeValueRef;
export type NativeRequest = CatalogNativeNativeReadRequest;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };
type Schema = {
  $ref?: string;
  anyOf?: Schema[];
  const?: Json;
  enum?: Json[];
  type?: string;
  properties?: Record<string, Schema>;
  additionalProperties?: boolean | Schema;
  items?: Schema;
  required?: string[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  pattern?: string;
  format?: string;
  native?: boolean;
};

// Finite metadata mirrors the Python validation and serialization field contract.
const SCHEMAS: Record<string, Schema> = {
  CatalogAuditContext: {
    additionalProperties: false,
    properties: {
      authority: {
        type: "string",
      },
      version: {
        type: "string",
      },
      source_url: {
        type: "string",
      },
      verified_on: {
        format: "date",
        type: "string",
      },
      valid_through: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      notes: {
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
    required: ["authority", "version", "source_url", "verified_on"],
    type: "object",
    native: false,
  },
  CatalogControl: {
    additionalProperties: false,
    properties: {
      id: {
        type: "string",
      },
      title: {
        type: "string",
      },
      description: {
        type: "string",
      },
      family: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      class: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      control_class: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      priority: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      baseline_impact: {
        items: {
          type: "string",
        },
        type: "array",
      },
      enhancements: {
        items: {
          $ref: "#/$defs/CatalogControl",
        },
        type: "array",
      },
      related_controls: {
        items: {
          type: "string",
        },
        type: "array",
      },
      assessment_objectives: {
        items: {
          type: "string",
        },
        type: "array",
      },
      objective: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      risk_tier: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      applies_to_annex_iii: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      guidance: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      examples: {
        items: {
          type: "string",
        },
        type: "array",
      },
      parameters: {
        additionalProperties: {
          type: "string",
        },
        type: "object",
      },
      ordering: {
        anyOf: [
          {
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      tier: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      license_required: {
        type: "boolean",
      },
      license_url: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      placeholder: {
        type: "boolean",
      },
      withdrawn: {
        type: "boolean",
      },
      properties: {
        type: "object",
        additionalProperties: {
          type: "string",
        },
      },
      source_rows: {
        items: {
          $ref: "#/$defs/CatalogSourceRow",
        },
        type: "array",
      },
      native_source_ref: {
        anyOf: [
          {
            $ref: "#/$defs/CatalogNativeControlSourceRef",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["id", "title", "description"],
    type: "object",
    native: false,
  },
  CatalogNativeAbsentSelection: {
    additionalProperties: false,
    properties: {
      state: {
        const: "absent",
        type: "string",
      },
    },
    required: ["state"],
    type: "object",
    native: true,
  },
  CatalogNativeControlBinding: {
    additionalProperties: false,
    properties: {
      control_id: {
        maxLength: 128,
        type: "string",
      },
      occurrence_index: {
        maximum: 4095,
        minimum: 0,
        type: "integer",
      },
      family_occurrence_index: {
        anyOf: [
          {
            maximum: 4095,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      parent_control_id: {
        anyOf: [
          {
            maxLength: 128,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      admitted_criticality: {
        anyOf: [
          {
            enum: ["SHALL", "SHOULD"],
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: [
      "control_id",
      "occurrence_index",
      "family_occurrence_index",
      "parent_control_id",
      "admitted_criticality",
    ],
    type: "object",
    native: true,
  },
  CatalogNativeControlSourceRef: {
    additionalProperties: false,
    properties: {
      bundle_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      occurrence_index: {
        maximum: 4095,
        minimum: 0,
        type: "integer",
      },
    },
    required: ["bundle_sha256", "occurrence_index"],
    type: "object",
    native: true,
  },
  CatalogNativeDiagnostic: {
    additionalProperties: false,
    properties: {
      code: {
        enum: [
          "source_identity_conflict",
          "missing_reference_record",
          "source_reference_difference",
          "legacy_ids_retired",
        ],
        type: "string",
      },
      occurrence_index: {
        anyOf: [
          {
            maximum: 4095,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      refs: {
        items: {
          $ref: "#/$defs/CatalogNativeValueRef",
        },
        maxItems: 8,
        type: "array",
      },
    },
    required: ["code", "occurrence_index", "refs"],
    type: "object",
    native: true,
  },
  CatalogNativeFieldRef: {
    additionalProperties: false,
    properties: {
      name: {
        maxLength: 1024,
        type: "string",
      },
      key: {
        $ref: "#/$defs/CatalogNativeValueRef",
      },
      value: {
        $ref: "#/$defs/CatalogNativeValueRef",
      },
    },
    required: ["name", "key", "value"],
    type: "object",
    native: true,
  },
  CatalogNativeNativeBundle: {
    additionalProperties: false,
    properties: {
      bundle_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      data: {
        $ref: "#/$defs/CatalogNativeNativeData",
      },
    },
    required: ["bundle_sha256", "data"],
    type: "object",
    native: true,
  },
  CatalogNativeNativeData: {
    additionalProperties: false,
    properties: {
      schema_version: {
        const: "catalog-native-v1",
        type: "string",
      },
      profile: {
        enum: [
          "au-ism-2026.09.4",
          "cisa-scuba-m365-7ef9501d",
          "bsi-grundschutz-plus-plus-367d7750",
        ],
        type: "string",
      },
      catalog_id: {
        enum: ["au-ism", "cisa-scuba", "bsi-grundschutz-plus-plus"],
        type: "string",
      },
      converter_id: {
        const: "evidentia-open-corpora-v1",
        type: "string",
      },
      converter_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      documents: {
        items: {
          $ref: "#/$defs/CatalogNativeSourceDocument",
        },
        maxItems: 16,
        type: "array",
      },
      occurrences: {
        items: {
          $ref: "#/$defs/CatalogNativeOccurrence",
        },
        maxItems: 4096,
        type: "array",
      },
      control_bindings: {
        items: {
          $ref: "#/$defs/CatalogNativeControlBinding",
        },
        maxItems: 2048,
        type: "array",
      },
      context_indices: {
        items: {
          maximum: 4095,
          minimum: 0,
          type: "integer",
        },
        maxItems: 1024,
        type: "array",
      },
      diagnostics: {
        items: {
          $ref: "#/$defs/CatalogNativeDiagnostic",
        },
        maxItems: 512,
        type: "array",
      },
    },
    required: [
      "schema_version",
      "profile",
      "catalog_id",
      "converter_id",
      "converter_sha256",
      "documents",
      "occurrences",
      "control_bindings",
      "context_indices",
      "diagnostics",
    ],
    type: "object",
    native: true,
  },
  CatalogNativeNullSelection: {
    additionalProperties: false,
    properties: {
      state: {
        const: "native_null",
        type: "string",
      },
      refs: {
        items: {
          $ref: "#/$defs/CatalogNativeValueRef",
        },
        maxItems: 1,
        minItems: 1,
        type: "array",
      },
    },
    required: ["state", "refs"],
    type: "object",
    native: true,
  },
  CatalogNativeOccurrence: {
    additionalProperties: false,
    properties: {
      index: {
        maximum: 4095,
        minimum: 0,
        type: "integer",
      },
      kind: {
        enum: [
          "catalog",
          "metadata",
          "group",
          "control",
          "principle",
          "section",
          "policy",
          "reference_policy",
          "context_block",
        ],
        type: "string",
      },
      parent_index: {
        anyOf: [
          {
            maximum: 4095,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      sibling_ordinal: {
        maximum: 4095,
        minimum: 0,
        type: "integer",
      },
      source: {
        $ref: "#/$defs/CatalogNativeValueRef",
      },
      fields: {
        items: {
          $ref: "#/$defs/CatalogNativeFieldRef",
        },
        maxItems: 64,
        type: "array",
      },
      selections: {
        items: {
          $ref: "#/$defs/CatalogNativeSemanticSelection",
        },
        maxItems: 32,
        type: "array",
      },
    },
    required: [
      "index",
      "kind",
      "parent_index",
      "sibling_ordinal",
      "source",
      "fields",
      "selections",
    ],
    type: "object",
    native: true,
  },
  CatalogNativePresentSelection: {
    additionalProperties: false,
    properties: {
      state: {
        const: "present",
        type: "string",
      },
      refs: {
        items: {
          $ref: "#/$defs/CatalogNativeValueRef",
        },
        maxItems: 256,
        minItems: 1,
        type: "array",
      },
    },
    required: ["state", "refs"],
    type: "object",
    native: true,
  },
  CatalogNativeSemanticSelection: {
    additionalProperties: false,
    properties: {
      role: {
        enum: [
          "native_id",
          "title",
          "class",
          "statement",
          "guidance",
          "parameter",
          "applicability",
          "essential_eight_applicability",
          "rationale",
          "note",
          "last_modified",
          "implementation",
          "criticality",
          "criticality_identity",
          "resources",
          "license_requirements",
          "badge",
          "nist_mapping",
          "mitre_mapping",
          "status",
          "publication_time",
          "native_version",
          "schema_version",
          "reference_record",
        ],
        type: "string",
      },
      value: {
        anyOf: [
          {
            $ref: "#/$defs/CatalogNativeAbsentSelection",
          },
          {
            $ref: "#/$defs/CatalogNativeNullSelection",
          },
          {
            $ref: "#/$defs/CatalogNativePresentSelection",
          },
        ],
      },
    },
    required: ["role", "value"],
    type: "object",
    native: true,
  },
  CatalogNativeSourceBinding: {
    additionalProperties: false,
    properties: {
      source_key: {
        maxLength: 64,
        type: "string",
      },
      role: {
        enum: ["authoritative", "reference", "license", "publication_context"],
        type: "string",
      },
      media_type: {
        enum: ["application/json", "text/markdown", "text/plain"],
        type: "string",
      },
      repository: {
        maxLength: 256,
        type: "string",
      },
      commit: {
        pattern: "^[0-9a-f]{40}$",
        type: "string",
      },
      upstream_path: {
        maxLength: 1024,
        type: "string",
      },
      raw_bytes: {
        maximum: 8388608,
        minimum: 0,
        type: "integer",
      },
      raw_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: [
      "source_key",
      "role",
      "media_type",
      "repository",
      "commit",
      "upstream_path",
      "raw_bytes",
      "raw_sha256",
    ],
    type: "object",
    native: true,
  },
  CatalogNativeSourceDocument: {
    additionalProperties: false,
    properties: {
      binding: {
        $ref: "#/$defs/CatalogNativeSourceBinding",
      },
      raw_utf8: {
        maxLength: 8388608,
        type: "string",
      },
    },
    required: ["binding", "raw_utf8"],
    type: "object",
    native: true,
  },
  CatalogNativeValueRef: {
    additionalProperties: false,
    properties: {
      document_index: {
        maximum: 15,
        minimum: 0,
        type: "integer",
      },
      byte_start: {
        maximum: 8388608,
        minimum: 0,
        type: "integer",
      },
      byte_end: {
        maximum: 8388608,
        minimum: 0,
        type: "integer",
      },
      kind: {
        enum: [
          "json_object",
          "json_array",
          "json_string",
          "json_number",
          "json_boolean",
          "json_null",
          "markdown_block",
          "utf8_text",
        ],
        type: "string",
      },
      sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: ["document_index", "byte_start", "byte_end", "kind", "sha256"],
    type: "object",
    native: true,
  },
  CatalogPublicationNotice: {
    additionalProperties: false,
    properties: {
      id: {
        type: "string",
      },
      title: {
        type: "string",
      },
      status: {
        enum: ["approved-future", "approved-superseded", "pending"],
        type: "string",
      },
      source_url: {
        type: "string",
      },
      approved_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      published_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      order_effective_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      effective_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      inactive_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      superseded_by: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      notes: {
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
    required: ["id", "title", "status", "source_url"],
    type: "object",
    native: false,
  },
  CatalogSourceRow: {
    additionalProperties: false,
    properties: {
      source_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      sheet: {
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      row: {
        minimum: 1,
        type: "integer",
      },
      source_id: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "integer",
          },
          {
            type: "number",
          },
          {
            type: "boolean",
          },
          {
            type: "null",
          },
        ],
      },
      source_id_format: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      interpreted_id: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      kind: {
        enum: ["aggregate", "clause", "fragment"],
        type: "string",
      },
      values: {
        additionalProperties: {
          anyOf: [
            {
              type: "string",
            },
            {
              type: "integer",
            },
            {
              type: "number",
            },
            {
              type: "boolean",
            },
            {
              type: "null",
            },
          ],
        },
        type: "object",
      },
      resolved_values: {
        additionalProperties: {
          anyOf: [
            {
              type: "string",
            },
            {
              type: "integer",
            },
            {
              type: "number",
            },
            {
              type: "boolean",
            },
            {
              type: "null",
            },
          ],
        },
        type: "object",
      },
      provenance: {
        additionalProperties: {
          type: "string",
        },
        type: "object",
      },
    },
    required: ["source_sha256", "sheet", "row", "source_id", "kind", "values"],
    type: "object",
    native: false,
  },
  ControlCatalog: {
    additionalProperties: false,
    properties: {
      framework_id: {
        type: "string",
      },
      framework_name: {
        type: "string",
      },
      version: {
        type: "string",
      },
      source: {
        type: "string",
      },
      controls: {
        items: {
          $ref: "#/$defs/CatalogControl",
        },
        type: "array",
      },
      families: {
        items: {
          type: "string",
        },
        type: "array",
      },
      family_hierarchy: {
        anyOf: [
          {
            additionalProperties: {
              items: {
                type: "string",
              },
              type: "array",
            },
            type: "object",
          },
          {
            type: "null",
          },
        ],
      },
      category: {
        enum: ["control", "technique", "vulnerability", "obligation"],
        type: "string",
      },
      tier: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      v0_9_3_note: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      annex_iii_risk_categories: {
        anyOf: [
          {
            items: {
              type: "string",
            },
            type: "array",
          },
          {
            type: "null",
          },
        ],
      },
      license_required: {
        type: "boolean",
      },
      license_terms: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      license_url: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      placeholder: {
        type: "boolean",
      },
      status: {
        anyOf: [
          {
            enum: ["current", "superseded", "retired", "historical"],
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      notes: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      verified_on: {
        anyOf: [
          {
            format: "date",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      superseded_by: {
        anyOf: [
          {
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      audit_contexts: {
        additionalProperties: {
          $ref: "#/$defs/CatalogAuditContext",
        },
        type: "object",
      },
      publication_notices: {
        items: {
          $ref: "#/$defs/CatalogPublicationNotice",
        },
        type: "array",
      },
      native_source: {
        anyOf: [
          {
            $ref: "#/$defs/CatalogNativeNativeBundle",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: [
      "framework_id",
      "framework_name",
      "version",
      "source",
      "controls",
    ],
    type: "object",
    native: false,
  },
  CatalogNativeSourceUpload: {
    additionalProperties: false,
    properties: {
      source_key: {
        enum: ["bsi-catalog", "bsi-license", "bsi-readme"],
        type: "string",
      },
      raw_utf8: {
        maxLength: 8388608,
        type: "string",
      },
    },
    required: ["source_key", "raw_utf8"],
    type: "object",
    native: true,
  },
  CatalogNativeExternalImportRequest: {
    additionalProperties: false,
    properties: {
      profile: {
        const: "bsi-grundschutz-plus-plus-367d7750",
        type: "string",
      },
      documents: {
        items: {
          $ref: "#/$defs/CatalogNativeSourceUpload",
        },
        maxItems: 3,
        minItems: 3,
        type: "array",
      },
    },
    required: ["profile", "documents"],
    type: "object",
    native: true,
  },
  CatalogNativeImportResult: {
    additionalProperties: false,
    properties: {
      schema_version: {
        const: "catalog-native-import-result-v1",
        type: "string",
      },
      catalog_id: {
        const: "bsi-grundschutz-plus-plus",
        type: "string",
      },
      bundle_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      projection_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      status: {
        enum: ["imported", "already_present"],
        type: "string",
      },
      control_count: {
        const: 1000,
        type: "integer",
      },
      storage: {
        const: "external",
        type: "string",
      },
      source_hashes: {
        items: {
          pattern: "^[0-9a-f]{64}$",
          type: "string",
        },
        maxItems: 3,
        type: "array",
      },
    },
    required: [
      "schema_version",
      "catalog_id",
      "bundle_sha256",
      "projection_sha256",
      "status",
      "control_count",
      "storage",
      "source_hashes",
    ],
    type: "object",
    native: true,
  },
  CatalogNativeNativeReadRequest: {
    additionalProperties: false,
    properties: {
      framework_id: {
        enum: ["au-ism", "cisa-scuba", "bsi-grundschutz-plus-plus"],
        type: "string",
      },
      bundle_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: ["framework_id", "bundle_sha256"],
    type: "object",
    native: true,
  },
  CatalogNativeNativeReadError: {
    additionalProperties: false,
    properties: {
      code: {
        enum: [
          "native_source_unavailable",
          "catalog_generation_changed",
          "native_source_invalid",
          "processing_deadline_exceeded",
        ],
        type: "string",
      },
    },
    required: ["code"],
    type: "object",
    native: true,
  },
  CatalogNativeCatalogPublicationObservation: {
    additionalProperties: false,
    properties: {
      schema_version: {
        const: "catalog-publication-observation-v1",
        type: "string",
      },
      operation: {
        enum: [
          "native_import",
          "legacy_import",
          "remove",
          "compatibility_replace",
        ],
        type: "string",
      },
      publication_state: {
        enum: [
          "not_attempted",
          "unchanged",
          "not_committed",
          "committed",
          "indeterminate",
        ],
        type: "string",
      },
      prior_manifest_state: {
        enum: ["unread", "absent", "present"],
        type: "string",
      },
      prior_sha256: {
        anyOf: [
          {
            pattern: "^[0-9a-f]{64}$",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      proposed_sha256: {
        anyOf: [
          {
            pattern: "^[0-9a-f]{64}$",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      replace_outcome: {
        enum: ["not_called", "returned", "raised"],
        type: "string",
      },
      observed_manifest_state: {
        enum: ["not_observed", "absent", "present"],
        type: "string",
      },
      observed_sha256: {
        anyOf: [
          {
            pattern: "^[0-9a-f]{64}$",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      readback_result: {
        enum: [
          "not_attempted",
          "matches_prior",
          "matches_proposed",
          "other",
          "unavailable",
        ],
        type: "string",
      },
      cleanup_state: {
        enum: ["not_started", "complete", "failed"],
        type: "string",
      },
      cleanup_errors: {
        items: {
          enum: [
            "temporary_cleanup_failed",
            "handle_close_failed",
            "lock_release_failed",
          ],
          type: "string",
        },
        maxItems: 3,
        type: "array",
        uniqueItems: true,
      },
      failure_phase: {
        enum: [
          null,
          "admission",
          "preparation",
          "lock",
          "manifest_read",
          "generation",
          "manifest_stage",
          "replace",
          "readback",
          "cleanup",
        ],
      },
      primary_kind: {
        enum: ["none", "exception", "base_exception"],
        type: "string",
      },
      error_code: {
        enum: [
          null,
          "catalog_transaction_conflict",
          "catalog_storage_unsupported",
          "catalog_manifest_invalid",
          "catalog_storage_limit_exceeded",
          "catalog_generation_conflict",
          "catalog_storage_failed",
          "catalog_publication_failed",
          "catalog_publication_indeterminate",
          "catalog_cleanup_failed",
          "processing_deadline_exceeded",
          "catalog_interrupted",
        ],
      },
    },
    required: [
      "schema_version",
      "operation",
      "publication_state",
      "prior_manifest_state",
      "prior_sha256",
      "proposed_sha256",
      "replace_outcome",
      "observed_manifest_state",
      "observed_sha256",
      "readback_result",
      "cleanup_state",
      "cleanup_errors",
      "failure_phase",
      "primary_kind",
      "error_code",
    ],
    type: "object",
    native: true,
  },
  CatalogNativeCatalogStorageErrorEnvelope: {
    additionalProperties: false,
    properties: {
      code: {
        enum: [
          "catalog_transaction_conflict",
          "catalog_generation_conflict",
          "catalog_storage_unsupported",
          "catalog_manifest_invalid",
          "catalog_storage_limit_exceeded",
          "catalog_storage_failed",
          "catalog_publication_failed",
          "catalog_publication_indeterminate",
          "catalog_cleanup_failed",
          "processing_deadline_exceeded",
        ],
        type: "string",
      },
      publication: {
        $ref: "#/$defs/CatalogNativeCatalogPublicationObservation",
      },
    },
    required: ["code", "publication"],
    type: "object",
    native: true,
  },
};
const MAX_WIRE = 16_777_216;
const MAX_RAW = 8_388_608;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const bundleBytes = new WeakMap<
  NativeBundle,
  { wire: Uint8Array; documents: Uint8Array[]; refs: Set<string> }
>();

export class NativeCatalogError extends Error {
  constructor() {
    super("Invalid native catalog response");
    this.name = "NativeCatalogError";
  }
}
function requireThat(ok: unknown): asserts ok {
  if (!ok) throw new NativeCatalogError();
}
function active(signal?: AbortSignal) {
  if (signal?.aborted)
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
}
function unicode(s: string) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(++i);
      requireThat(d >= 0xdc00 && d <= 0xdfff);
    } else requireThat(c < 0xdc00 || c > 0xdfff);
  }
}
function utf8(s: string) {
  unicode(s);
  return encoder.encode(s);
}
function obj(value: Json): Obj {
  requireThat(
    value !== null && !Array.isArray(value) && typeof value === "object",
  );
  return value;
}
function ascii(value: Json): string {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
async function sha(bytes: Uint8Array, signal?: AbortSignal) {
  active(signal);
  const result = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(bytes).buffer,
  );
  active(signal);
  return Array.from(new Uint8Array(result), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

type Token = {
  kind: string;
  start: number;
  end: number;
  value: Json;
  members: [Token, Token][];
};
type Parsed = { value: Json; tokens: Map<string, Token> };
/** Parse duplicates before object construction. Source numbers remain lexical strings. */
function parse(text: string, source = false, signal?: AbortSignal): Parsed {
  requireThat(
    typeof text === "string" && text.length <= (source ? MAX_RAW : MAX_WIRE),
  );
  const raw = utf8(text);
  requireThat(raw.length <= (source ? MAX_RAW : MAX_WIRE));
  const offsets = source ? new Uint32Array(text.length + 1) : undefined;
  if (offsets) {
    let at = 0;
    for (let i = 0; i < text.length; i++) {
      offsets[i] = at;
      const c = text.codePointAt(i)!;
      if (c > 0xffff) {
        offsets[++i] = 0xffffffff;
        at += 4;
      } else at += c < 128 ? 1 : c < 2048 ? 2 : 3;
    }
    offsets[text.length] = at;
  }
  const tokens = new Map<string, Token>();
  let pos = 0;
  let nodes = 0;
  let strings = 0;
  let members = 0;
  let elements = 0;
  function space() {
    while (pos < text.length && " \t\r\n".includes(text[pos])) pos++;
  }
  function token(depth: number, key = false): Token {
    active(signal);
    requireThat(depth <= (source ? 32 : 64));
    space();
    const start = pos;
    const c = text[pos];
    let kind: string;
    let value: Json;
    const pairs: [Token, Token][] = [];
    if (c === '"') {
      pos++;
      while (pos < text.length && text[pos] !== '"') {
        requireThat(text.charCodeAt(pos) >= 32);
        if (text[pos++] === "\\") {
          requireThat(pos < text.length);
          if (text[pos] === "u") {
            requireThat(/^[0-9a-fA-F]{4}$/.test(text.slice(pos + 1, pos + 5)));
            pos += 5;
          } else {
            requireThat('"\\/bfnrt'.includes(text[pos]));
            pos++;
          }
        }
      }
      requireThat(text[pos++] === '"');
      value = JSON.parse(text.slice(start, pos)) as string;
      unicode(value);
      const count = utf8(value).length;
      strings += count;
      requireThat(
        count <= (source ? (key ? 1024 : 262144) : MAX_RAW) &&
          strings <= (source ? MAX_RAW : MAX_WIRE),
      );
      kind = "json_string";
    } else if (c === "{") {
      pos++;
      space();
      value = Object.create(null) as Obj;
      const names = new Set<string>();
      if (text[pos] !== "}")
        do {
          space();
          requireThat(text[pos] === '"');
          const name = token(depth + 1, true);
          requireThat(typeof name.value === "string" && !names.has(name.value));
          names.add(name.value);
          space();
          requireThat(text[pos++] === ":");
          const child = token(depth + 1);
          value[name.value] = child.value;
          pairs.push([name, child]);
          members++;
          requireThat(!source || (names.size <= 64 && members <= 100000));
          space();
          if (text[pos] !== ",") break;
          pos++;
        } while (true);
      requireThat(text[pos++] === "}");
      kind = "json_object";
    } else if (c === "[") {
      pos++;
      space();
      value = [];
      if (text[pos] !== "]")
        do {
          const child = token(depth + 1);
          value.push(child.value);
          elements++;
          requireThat(
            value.length <= (source ? 4096 : 262144) &&
              (!source || elements <= 100000),
          );
          space();
          if (text[pos] !== ",") break;
          pos++;
        } while (true);
      requireThat(text[pos++] === "]");
      kind = "json_array";
    } else if (
      text.startsWith("true", pos) ||
      text.startsWith("false", pos) ||
      text.startsWith("null", pos)
    ) {
      if (text.startsWith("null", pos)) {
        value = null;
        pos += 4;
        kind = "json_null";
      } else {
        value = text.startsWith("true", pos);
        pos += value ? 4 : 5;
        kind = "json_boolean";
      }
    } else {
      const match =
        /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
          text.slice(pos),
        );
      requireThat(match && match[0].length <= 128);
      pos += match[0].length;
      kind = "json_number";
      value = source ? match[0] : Number(match[0]);
      requireThat(
        source ||
          (Number.isFinite(value) &&
            (!Number.isInteger(value) || Number.isSafeInteger(value))),
      );
    }
    if (source ? !key : kind !== "json_object" && !key) nodes++;
    requireThat(nodes <= (source ? 100000 : 262144));
    const item = {
      kind,
      start: offsets ? offsets[start] : start,
      end: offsets ? offsets[pos] : pos,
      value,
      members: pairs,
    };
    if (source) tokens.set(item.start + ":" + item.end, item);
    return item;
  }
  try {
    const root = token(0);
    space();
    requireThat(pos === text.length);
    return { value: root.value, tokens };
  } catch (error) {
    tokens.clear();
    active(signal);
    if (error instanceof NativeCatalogError) throw error;
    throw new NativeCatalogError();
  }
}

function date(value: string) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  requireThat(m);
  const y = Number(m[1]);
  const month = Number(m[2]);
  const d = Number(m[3]);
  const days = [
    31,
    y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  requireThat(
    y >= 1 && month >= 1 && month <= 12 && d >= 1 && d <= days[month - 1],
  );
}
/** Reconstruct fixed field order; do not insert defaults, coerce values or drop unknown keys. */
function shape(value: Json, schema: Schema, native = false): Json {
  if (schema.$ref) {
    const target = SCHEMAS[schema.$ref.split("/").at(-1)!];
    requireThat(target);
    return shape(value, target);
  }
  native ||= schema.native === true;
  if (schema.anyOf) {
    for (const arm of schema.anyOf) {
      try {
        return shape(value, arm, native);
      } catch (e) {
        if (!(e instanceof NativeCatalogError)) throw e;
      }
    }
    throw new NativeCatalogError();
  }
  if ("const" in schema) requireThat(value === schema.const);
  if (schema.enum)
    requireThat(schema.enum.some((candidate) => candidate === value));
  if (schema.type === "null") requireThat(value === null);
  else if (schema.type === "boolean") requireThat(typeof value === "boolean");
  else if (schema.type === "integer" || schema.type === "number") {
    requireThat(typeof value === "number" && Number.isFinite(value));
    if (schema.type === "integer") requireThat(Number.isSafeInteger(value));
    requireThat(
      (schema.minimum === undefined || value >= schema.minimum) &&
        (schema.maximum === undefined || value <= schema.maximum),
    );
  } else if (schema.type === "string") {
    requireThat(typeof value === "string");
    unicode(value);
    let n = 0;
    for (const _scalar of value) n++;
    requireThat(
      (schema.minLength === undefined || n >= schema.minLength) &&
        (schema.maxLength === undefined || n <= schema.maxLength),
    );
    requireThat(
      utf8(value).length <= (native ? (schema.maxLength ?? 262144) : 262144),
    );
    if (schema.pattern)
      requireThat(new RegExp(schema.pattern, "u").test(value));
    if (schema.format === "date") date(value);
  } else if (schema.type === "array") {
    requireThat(
      Array.isArray(value) &&
        (schema.minItems === undefined || value.length >= schema.minItems) &&
        (schema.maxItems === undefined || value.length <= schema.maxItems),
    );
    const result = value.map((item) => shape(item, schema.items!, native));
    if (schema.uniqueItems)
      requireThat(new Set(result.map(ascii)).size === result.length);
    return result;
  } else if (schema.type === "object") {
    const record = obj(value);
    const result: Obj = Object.create(null) as Obj;
    if (schema.properties) {
      const fields = Object.keys(schema.properties);
      requireThat(
        Object.keys(record).length === fields.length &&
          fields.every((k) => Object.hasOwn(record, k)),
      );
      for (const name of fields)
        result[name] = shape(record[name], schema.properties[name], native);
    } else {
      requireThat(typeof schema.additionalProperties === "object");
      for (const name of Object.keys(record))
        result[name] = shape(record[name], schema.additionalProperties, native);
    }
    return result;
  }
  return value;
}

function publication(p: CatalogNativeCatalogPublicationObservation) {
  requireThat(
    (p.prior_manifest_state === "present") === (p.prior_sha256 !== null),
  );
  requireThat(
    (p.observed_manifest_state === "present") === (p.observed_sha256 !== null),
  );
  requireThat(
    p.publication_state === "not_attempted" || p.proposed_sha256 !== null,
  );
  if (["not_attempted", "unchanged"].includes(p.publication_state))
    requireThat(p.replace_outcome === "not_called");
  if (["not_committed", "indeterminate"].includes(p.publication_state))
    requireThat(p.replace_outcome === "raised");
  if (p.replace_outcome === "returned")
    requireThat(p.publication_state === "committed");
  const prior =
    p.prior_manifest_state !== "unread" &&
    p.observed_manifest_state === p.prior_manifest_state &&
    p.observed_sha256 === p.prior_sha256;
  const proposed =
    p.observed_manifest_state === "present" &&
    p.observed_sha256 === p.proposed_sha256;
  if (p.readback_result === "matches_prior") requireThat(prior);
  if (p.readback_result === "matches_proposed") requireThat(proposed);
  if (["unavailable", "not_attempted"].includes(p.readback_result))
    requireThat(p.observed_manifest_state === "not_observed");
  if (p.readback_result === "other")
    requireThat(
      p.observed_manifest_state !== "not_observed" && !prior && !proposed,
    );
  if (p.publication_state === "unchanged")
    requireThat(
      p.prior_manifest_state === "present" &&
        p.prior_sha256 === p.proposed_sha256 &&
        p.readback_result === "matches_proposed",
    );
  if (p.publication_state === "not_committed")
    requireThat(
      p.readback_result === "matches_prior" &&
        p.prior_sha256 !== p.proposed_sha256,
    );
  if (p.publication_state === "committed")
    requireThat(
      p.replace_outcome !== "not_called" &&
        (p.replace_outcome !== "raised" ||
          p.readback_result === "matches_proposed"),
    );
  if (p.replace_outcome === "raised") {
    requireThat(p.primary_kind !== "none");
    if (p.primary_kind === "exception")
      requireThat(
        p.error_code ===
          (p.publication_state === "indeterminate"
            ? "catalog_publication_indeterminate"
            : "catalog_publication_failed"),
      );
  }
  if (p.publication_state === "indeterminate")
    requireThat(
      ["unavailable", "not_attempted", "other"].includes(p.readback_result),
    );
  if (
    p.replace_outcome === "returned" &&
    p.readback_result === "other" &&
    p.primary_kind !== "base_exception"
  )
    requireThat(p.error_code === "catalog_generation_conflict");
  if (p.error_code === "catalog_cleanup_failed")
    requireThat(
      p.primary_kind === "exception" &&
        p.failure_phase === "cleanup" &&
        p.cleanup_state === "failed" &&
        p.replace_outcome !== "raised",
    );
  requireThat((p.cleanup_state === "failed") === p.cleanup_errors.length > 0);
  requireThat(
    (p.primary_kind === "base_exception") ===
      (p.error_code === "catalog_interrupted"),
  );
  requireThat((p.primary_kind === "none") === (p.failure_phase === null));
  const verified =
    ["committed", "unchanged"].includes(p.publication_state) &&
    p.readback_result === "matches_proposed" &&
    p.primary_kind === "none" &&
    p.cleanup_state === "complete";
  requireThat((p.error_code === null) === verified);
}
const surfaces = {
  importRequest: "CatalogNativeExternalImportRequest",
  importResult: "CatalogNativeImportResult",
  readRequest: "CatalogNativeNativeReadRequest",
  readError: "CatalogNativeNativeReadError",
  publication: "CatalogNativeCatalogPublicationObservation",
  storageError: "CatalogNativeCatalogStorageErrorEnvelope",
} as const;
export function decodeNativeSurface(
  kind: keyof typeof surfaces,
  text: string,
): Json {
  requireThat(Object.hasOwn(surfaces, kind));
  const value = shape(parse(text).value, SCHEMAS[surfaces[kind]]);
  if (kind === "importRequest") {
    const request = value as unknown as CatalogNativeExternalImportRequest;
    requireThat(new Set(request.documents.map((d) => d.source_key)).size === 3);
    requireThat(
      request.documents.reduce((n, d) => n + utf8(d.raw_utf8).length, 0) <=
        MAX_RAW,
    );
  }
  if (kind === "publication")
    publication(value as unknown as CatalogNativeCatalogPublicationObservation);
  if (kind === "storageError") {
    const error = value as unknown as CatalogNativeCatalogStorageErrorEnvelope;
    publication(error.publication);
    requireThat(error.code === error.publication.error_code);
  }
  if (kind === "publication" || kind === "storageError")
    requireThat(utf8(ascii(value)).length <= 4096);
  return freeze(value);
}

function refIdentity(ref: ValueRef) {
  return refKey(ref) + ":" + ref.kind + ":" + ref.sha256;
}
function refKey(ref: ValueRef) {
  return ref.document_index + ":" + ref.byte_start + ":" + ref.byte_end;
}
function contains(parent: ValueRef, child: ValueRef) {
  return (
    parent.document_index === child.document_index &&
    parent.byte_start <= child.byte_start &&
    parent.byte_end >= child.byte_end
  );
}
function familyKey(occurrence: CatalogNativeOccurrence) {
  return (
    (occurrence.kind === "section" ? "native-section:" : "native-group:") +
    occurrence.index
  );
}

function requestData(request: NativeRequest): NativeRequest {
  requireThat(request !== null && typeof request === "object");
  requireThat(
    Object.getPrototypeOf(request) === Object.prototype ||
      Object.getPrototypeOf(request) === null,
  );
  const keys = Reflect.ownKeys(request);
  requireThat(
    keys.length === 2 &&
      keys.includes("framework_id") &&
      keys.includes("bundle_sha256"),
  );
  const descriptors = Object.getOwnPropertyDescriptors(request);
  const framework = descriptors.framework_id;
  const bundle = descriptors.bundle_sha256;
  requireThat(framework && bundle && "value" in framework && "value" in bundle);
  requireThat(
    typeof framework.value === "string" && typeof bundle.value === "string",
  );
  return shape(
    {
      framework_id: framework.value as string,
      bundle_sha256: bundle.value as string,
    },
    SCHEMAS.CatalogNativeNativeReadRequest,
  ) as unknown as NativeRequest;
}

async function verifyBundle(
  value: Json,
  request: NativeRequest,
  signal?: AbortSignal,
): Promise<NativeBundle> {
  active(signal);
  const accepted = shape(value, SCHEMAS.CatalogNativeNativeBundle);
  const bundle = accepted as unknown as NativeBundle;
  const data = bundle.data;
  const requestCopy = requestData(request);
  requireThat(
    bundle.bundle_sha256 === requestCopy.bundle_sha256 &&
      data.catalog_id === requestCopy.framework_id,
  );
  const profiles = {
    "au-ism": "au-ism-2026.09.4",
    "cisa-scuba": "cisa-scuba-m365-7ef9501d",
    "bsi-grundschutz-plus-plus": "bsi-grundschutz-plus-plus-367d7750",
  };
  requireThat(data.profile === profiles[data.catalog_id]);
  const wire = utf8(ascii(accepted));
  requireThat(wire.length <= 12_058_624);
  const encoded = utf8(
    "evidentia.catalog-native.v1\0" + ascii((accepted as Obj).data),
  );
  requireThat((await sha(encoded, signal)) === bundle.bundle_sha256);
  const documents: Uint8Array[] = [];
  const parsed: (Parsed | null)[] = [];
  const seenSources = new Set<string>();
  let totalRaw = 0;
  const refs = new Map<string, string>();
  const verifiedRefs = new Set<string>();
  async function checkRef(ref: ValueRef) {
    active(signal);
    const raw = documents[ref.document_index];
    requireThat(
      raw && ref.byte_start < ref.byte_end && ref.byte_end <= raw.length,
    );
    const span = raw.subarray(ref.byte_start, ref.byte_end);
    try {
      decoder.decode(span);
    } catch {
      throw new NativeCatalogError();
    }
    const key = refKey(ref);
    let digest = refs.get(key);
    if (digest === undefined) {
      digest = await sha(span, signal);
      refs.set(key, digest);
    }
    requireThat(digest === ref.sha256);
    if (ref.kind.startsWith("json_"))
      requireThat(
        parsed[ref.document_index]?.tokens.get(
          ref.byte_start + ":" + ref.byte_end,
        )?.kind === ref.kind,
      );
    verifiedRefs.add(refIdentity(ref));
  }
  try {
    requireThat(data.documents.length > 0);
    for (const doc of data.documents) {
      active(signal);
      const raw = utf8(doc.raw_utf8);
      totalRaw += raw.length;
      requireThat(
        totalRaw <= MAX_RAW &&
          raw.length === doc.binding.raw_bytes &&
          !seenSources.has(doc.binding.source_key),
      );
      seenSources.add(doc.binding.source_key);
      requireThat((await sha(raw, signal)) === doc.binding.raw_sha256);
      documents.push(raw);
      parsed.push(
        doc.binding.media_type === "application/json"
          ? parse(doc.raw_utf8, true, signal)
          : null,
      );
    }
    const siblings = new Map<string, number>();
    let lastDocument = -1;
    let lastStart = -1;
    const context: number[] = [];
    for (let i = 0; i < data.occurrences.length; i++) {
      const occurrence = data.occurrences[i];
      requireThat(occurrence.index === i);
      const source = occurrence.source;
      requireThat(
        source.document_index >= lastDocument &&
          (source.document_index !== lastDocument ||
            source.byte_start >= lastStart),
      );
      lastDocument = source.document_index;
      lastStart = source.byte_start;
      const siblingKey = source.document_index + ":" + occurrence.parent_index;
      requireThat(
        occurrence.sibling_ordinal === (siblings.get(siblingKey) ?? 0),
      );
      siblings.set(siblingKey, occurrence.sibling_ordinal + 1);
      if (occurrence.parent_index !== null) {
        requireThat(occurrence.parent_index < i);
        const parent = data.occurrences[occurrence.parent_index];
        requireThat(parent && contains(parent.source, source));
        if (source.kind === "json_object")
          requireThat(
            parent.source.byte_start < source.byte_start ||
              parent.source.byte_end > source.byte_end,
          );
      }
      await checkRef(source);
      if (
        [
          "group",
          "control",
          "principle",
          "metadata",
          "reference_policy",
        ].includes(occurrence.kind)
      )
        requireThat(source.kind === "json_object");
      if (["policy", "section"].includes(occurrence.kind))
        requireThat(source.kind === "markdown_block");
      if (occurrence.kind === "catalog")
        requireThat(
          source.kind ===
            (parsed[source.document_index] ? "json_object" : "markdown_block"),
        );
      if (occurrence.kind === "context_block")
        requireThat(["markdown_block", "utf8_text"].includes(source.kind));
      const token = parsed[source.document_index]?.tokens.get(
        source.byte_start + ":" + source.byte_end,
      );
      if (source.kind === "json_object")
        requireThat(token && token.members.length === occurrence.fields.length);
      let lastField = -1;
      for (let f = 0; f < occurrence.fields.length; f++) {
        const field = occurrence.fields[f];
        await checkRef(field.key);
        await checkRef(field.value);
        requireThat(
          contains(source, field.key) &&
            contains(source, field.value) &&
            field.key.byte_start >= lastField,
        );
        lastField = field.key.byte_start;
        if (source.kind === "json_object") {
          const [key, child] = token!.members[f];
          requireThat(
            key.value === field.name &&
              field.key.kind === key.kind &&
              field.value.kind === child.kind,
          );
          requireThat(
            field.key.byte_start === key.start &&
              field.key.byte_end === key.end &&
              field.value.byte_start === child.start &&
              field.value.byte_end === child.end,
          );
        }
      }
      const roles = new Set<string>();
      for (const selection of occurrence.selections) {
        requireThat(!roles.has(selection.role));
        roles.add(selection.role);
        if (selection.value.state === "absent") continue;
        let previous: ValueRef | undefined;
        for (const ref of selection.value.refs) {
          await checkRef(ref);
          requireThat(
            selection.value.state === "native_null"
              ? ref.kind === "json_null"
              : ref.kind !== "json_null",
          );
          if (previous)
            requireThat(
              ref.document_index > previous.document_index ||
                (ref.document_index === previous.document_index &&
                  ref.byte_start >= previous.byte_end),
            );
          previous = ref;
        }
      }
      if (!["control", "policy", "reference_policy"].includes(occurrence.kind))
        context.push(i);
    }
    requireThat(
      JSON.stringify(context) === JSON.stringify(data.context_indices),
    );
    const controls = data.occurrences.filter(
      (o) => o.kind === "control" || o.kind === "policy",
    );
    requireThat(controls.length === data.control_bindings.length);
    const ids = new Set<string>();
    const normals = new Set<string>();
    const occurrenceIds = new Map(
      data.control_bindings.map((b) => [b.occurrence_index, b.control_id]),
    );
    for (let i = 0; i < data.control_bindings.length; i++) {
      const binding = data.control_bindings[i];
      const occurrence = controls[i];
      const normal = binding.control_id
        .trim()
        .toUpperCase()
        .replace(/\(([^()]+)\)/g, ".$1");
      requireThat(
        binding.control_id.length > 0 &&
          !ids.has(binding.control_id) &&
          !normals.has(normal) &&
          binding.occurrence_index === occurrence.index,
      );
      ids.add(binding.control_id);
      normals.add(normal);
      if (binding.parent_control_id !== null)
        requireThat(
          ids.has(binding.parent_control_id) &&
            binding.parent_control_id !== binding.control_id,
        );
      let parent = occurrence.parent_index;
      let family: number | null = null;
      let control: string | null = null;
      while (parent !== null) {
        const ancestor = data.occurrences[parent];
        if (family === null && ["group", "section"].includes(ancestor.kind))
          family = parent;
        if (control === null && ["control", "policy"].includes(ancestor.kind))
          control = occurrenceIds.get(parent) ?? null;
        parent = ancestor.parent_index;
      }
      requireThat(
        binding.family_occurrence_index === family &&
          binding.parent_control_id === control,
      );
      const identity = occurrence.selections.find(
        (s) => s.role === "native_id",
      );
      requireThat(
        identity?.value.state === "present" && identity.value.refs.length === 1,
      );
      const ref = identity.value.refs[0];
      const literal = decoder.decode(
        documents[ref.document_index].subarray(ref.byte_start, ref.byte_end),
      );
      const nativeId =
        ref.kind === "json_string" ? JSON.parse(literal) : literal;
      requireThat(
        typeof nativeId === "string" && nativeId === binding.control_id,
      );
    }
    for (const diagnostic of data.diagnostics) {
      requireThat(
        diagnostic.occurrence_index === null ||
          diagnostic.occurrence_index < data.occurrences.length,
      );
      for (const ref of diagnostic.refs) await checkRef(ref);
    }
    requireThat(
      utf8(ascii(data.documents as unknown as Json)).length <= 7_340_032,
    );
    requireThat(
      utf8(ascii(data.occurrences as unknown as Json)).length <= 6_291_456,
    );
    active(signal);
    freeze(bundle);
    bundleBytes.set(bundle, { wire, documents, refs: verifiedRefs });
    return bundle;
  } catch (error) {
    documents.length = 0;
    throw error;
  } finally {
    parsed.forEach((p) => p?.tokens.clear());
    parsed.length = 0;
    refs.clear();
  }
}

export async function decodeNativeBundle(
  text: string,
  request: NativeRequest,
  signal?: AbortSignal,
): Promise<NativeBundle> {
  return verifyBundle(parse(text, false, signal).value, request, signal);
}
export async function decodeNativeCatalog(
  text: string,
  request: NativeRequest,
  signal?: AbortSignal,
): Promise<NativeCatalog> {
  const value = shape(parse(text, false, signal).value, SCHEMAS.ControlCatalog);
  const catalog = value as unknown as NativeCatalog;
  requireThat(catalog.native_source !== null);
  const bundle = await verifyBundle(
    catalog.native_source as unknown as Json,
    request,
    signal,
  );
  catalog.native_source = bundle;
  requireThat(catalog.framework_id === bundle.data.catalog_id);
  const bindings = bundle.data.control_bindings;
  let count = 0;
  function controls(rows: CatalogControl[], parent: string | null) {
    for (const row of rows) {
      const binding = bindings[count++];
      requireThat(
        binding &&
          row.id === binding.control_id &&
          parent === binding.parent_control_id,
      );
      requireThat(
        row.native_source_ref !== null &&
          row.native_source_ref.bundle_sha256 === bundle.bundle_sha256 &&
          row.native_source_ref.occurrence_index === binding.occurrence_index,
      );
      const family = binding.family_occurrence_index;
      requireThat(
        row.family ===
          (family === null ? null : familyKey(bundle.data.occurrences[family])),
      );
      controls(row.enhancements, row.id);
    }
  }
  controls(catalog.controls, null);
  requireThat(count === bindings.length);
  const families = bundle.data.occurrences
    .filter((o) => o.kind === "group" || o.kind === "section")
    .map(familyKey);
  requireThat(
    JSON.stringify(catalog.families) === JSON.stringify(families) &&
      catalog.family_hierarchy === null,
  );
  const documentsSize = utf8(
    ascii(bundle.data.documents as unknown as Json),
  ).length;
  const occurrencesSize = utf8(
    ascii(bundle.data.occurrences as unknown as Json),
  ).length;
  const controlsSize = utf8(ascii(catalog.controls as unknown as Json)).length;
  const whole = utf8(ascii(value)).length;
  const remainder = whole - documentsSize - occurrencesSize - controlsSize;
  requireThat(
    whole <= MAX_WIRE &&
      controlsSize <= 2_097_152 &&
      remainder >= 0 &&
      remainder <= 524_288,
  );
  active(signal);
  return freeze(catalog);
}

/** Count actual bytes before decoding; no Content-Length trust or text-before-cap. */
export async function readNativeResponse(
  response: Response,
  signal?: AbortSignal,
): Promise<string> {
  active(signal);
  requireThat(response.ok && response.body !== null);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let complete = false;
  const aborted = () => {
    void reader.cancel(signal?.reason).catch(() => undefined);
  };
  signal?.addEventListener("abort", aborted, { once: true });
  try {
    while (true) {
      active(signal);
      const next = await reader.read();
      active(signal);
      if (next.done) {
        complete = true;
        break;
      }
      requireThat(next.value instanceof Uint8Array);
      size += next.value.byteLength;
      requireThat(size <= MAX_WIRE);
      chunks.push(new Uint8Array(next.value));
    }
    const raw = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      raw.set(chunk, offset);
      offset += chunk.length;
    }
    try {
      return decoder.decode(raw);
    } catch {
      throw new NativeCatalogError();
    }
  } finally {
    signal?.removeEventListener("abort", aborted);
    if (!complete) {
      try {
        await reader.cancel();
      } catch {
        /* Preserve the original refusal or cancellation. */
      }
    }
    chunks.length = 0;
    reader.releaseLock();
  }
}
function captured(bundle: NativeBundle) {
  const data = bundleBytes.get(bundle);
  requireThat(data);
  return data;
}
export function nativeBundleDownload(bundle: NativeBundle): Uint8Array {
  return new Uint8Array(captured(bundle).wire);
}
export function nativeDocumentDownload(
  bundle: NativeBundle,
  document: number,
): Uint8Array {
  requireThat(Number.isSafeInteger(document) && document >= 0);
  const raw = captured(bundle).documents[document];
  requireThat(raw);
  return new Uint8Array(raw);
}
export function nativeRefText(bundle: NativeBundle, ref: ValueRef): string {
  captured(bundle);
  requireThat(captured(bundle).refs.has(refIdentity(ref)));
  return decoder.decode(
    captured(bundle).documents[ref.document_index].subarray(
      ref.byte_start,
      ref.byte_end,
    ),
  );
}
export function bindNativeControl(
  bundle: NativeBundle,
  controlId: string,
  ref: CatalogNativeControlSourceRef,
): CatalogNativeOccurrence {
  captured(bundle);
  const binding = bundle.data.control_bindings.find(
    (b) => b.control_id === controlId,
  );
  requireThat(
    binding &&
      ref.bundle_sha256 === bundle.bundle_sha256 &&
      ref.occurrence_index === binding.occurrence_index,
  );
  return bundle.data.occurrences[binding.occurrence_index];
}
export function nativePreview(text: string): {
  text: string;
  truncated: boolean;
} {
  requireThat(typeof text === "string");
  unicode(text);
  let size = 0;
  let end = 0;
  for (const char of text) {
    const n = utf8(char).length;
    if (size + n > 4096) return { text: text.slice(0, end), truncated: true };
    size += n;
    end += char.length;
  }
  return { text, truncated: false };
}
export function occurrencePage(
  bundle: NativeBundle,
  page: number,
): readonly CatalogNativeOccurrence[] {
  captured(bundle);
  requireThat(
    Number.isSafeInteger(page) &&
      page >= 0 &&
      page <= Math.floor(bundle.data.occurrences.length / 20),
  );
  return Object.freeze(
    bundle.data.occurrences.slice(page * 20, page * 20 + 20),
  );
}
/** Selection authority stays outside wire data; errors and stale work retain the last accepted bundle. */
export function createNativeSelection() {
  type Ticket = Readonly<{
    framework: string;
    bundle: string;
    selection: string;
    auth: number;
    signal: AbortSignal;
  }>;
  let current: Ticket | null = null;
  let controller: AbortController | null = null;
  let last: NativeBundle | null = null;
  return {
    get lastGood() {
      return last;
    },
    begin(
      framework: string,
      bundle: string,
      selection: string,
      auth: number,
    ): Ticket {
      controller?.abort();
      controller = new AbortController();
      current = Object.freeze({
        framework,
        bundle,
        selection,
        auth,
        signal: controller.signal,
      });
      return current;
    },
    invalidate() {
      controller?.abort();
      current = null;
    },
    accept(ticket: Ticket, bundle: NativeBundle): boolean {
      if (
        ticket !== current ||
        ticket.signal.aborted ||
        !bundleBytes.has(bundle) ||
        bundle.data.catalog_id !== ticket.framework ||
        bundle.bundle_sha256 !== ticket.bundle
      )
        return false;
      if (
        !bundle.data.control_bindings.some(
          (b) => b.control_id === ticket.selection,
        )
      )
        return false;
      last = bundle;
      return true;
    },
  };
}
