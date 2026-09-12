import type { components, operations } from "@/types/openapi";

export type RegistryRequest =
  operations["collect_registry"]["requestBody"]["content"]["application/json"];
export type RegistryResult = components["schemas"]["RegistryLookupResult"];
export type RegistryName = RegistryRequest["registry"];
export const REGISTRY_REQUEST_BYTE_LIMIT = 65_536;
export const REGISTRY_RESULT_BYTE_LIMIT = 4_194_304;
export const REGISTRY_NAMES = [
  "tls",
  "rdap",
  "sam-entity",
  "sam-exclusions",
  "gleif",
  "fedramp",
  "cmvp",
  "fcc-covered-list",
  "incommon",
  "ssl-labs",
  "security-txt",
] as const;
export class RegistryResponseError extends Error {
  constructor() {
    super(
      "The registry JSON is invalid or does not match the selected request.",
    );
    this.name = "RegistryResponseError";
  }
}
const failure = (): never => {
  throw new RegistryResponseError();
};
const size = (value: string): number => new TextEncoder().encode(value).length;
const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
type JsonPath = (string | number)[];
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
// Shape exported from the Python registry models. Data is validated without replacing it with a filtered clone.
export const RESULT_SCHEMA: JsonSchema = {
  $defs: {
    CMVPRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "cmvp",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/CertificateTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    CertificateTarget: {
      additionalProperties: false,
      properties: {
        certificate_number: {
          allOf: [
            {
              pattern: "^[0-9]+$",
              type: "string",
            },
          ],
          maxLength: 128,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["certificate_number"],
      type: "object",
    },
    ControlMapping: {
      additionalProperties: false,
      properties: {
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
        framework: {
          type: "string",
        },
        justification: {
          maxLength: 1024,
          type: "string",
        },
        relationship: {
          $ref: "#/$defs/OLIRRelationship",
        },
      },
      required: ["framework", "control_id"],
      type: "object",
    },
    CoverageCount: {
      additionalProperties: false,
      properties: {
        collected: {
          minimum: 0,
          type: "integer",
        },
        matched_filter: {
          minimum: 0,
          type: "integer",
        },
        resource_type: {
          type: "string",
        },
        scanned: {
          minimum: 0,
          type: "integer",
        },
      },
      required: ["resource_type", "scanned", "matched_filter", "collected"],
      type: "object",
    },
    DomainTarget: {
      additionalProperties: false,
      properties: {
        domain: {
          maxLength: 254,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["domain"],
      type: "object",
    },
    EndpointTarget: {
      additionalProperties: false,
      properties: {
        endpoint_ip: {
          maxLength: 45,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        hostname: {
          maxLength: 254,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["hostname", "endpoint_ip"],
      type: "object",
    },
    EntityTarget: {
      additionalProperties: false,
      properties: {
        entity_id: {
          maxLength: 2048,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["entity_id"],
      type: "object",
    },
    FCCOrganizationTarget: {
      additionalProperties: false,
      properties: {
        organization_name: {
          maxLength: 512,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        query_scope: {
          const: "named_organization_entries",
          type: "string",
        },
      },
      required: ["organization_name", "query_scope"],
      type: "object",
    },
    FCCRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "fcc-covered-list",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/FCCOrganizationTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    FedRAMPRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "fedramp",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/ProductTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    GLEIFRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "gleif",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/LEITarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    HostnameTarget: {
      additionalProperties: false,
      properties: {
        hostname: {
          maxLength: 254,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["hostname"],
      type: "object",
    },
    InCommonRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "incommon",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/EntityTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    LEITarget: {
      additionalProperties: false,
      properties: {
        lei: {
          maxLength: 20,
          minLength: 20,
          pattern: "^[A-Z0-9]{20}$",
          type: "string",
        },
      },
      required: ["lei"],
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
    ObservationTrust: {
      additionalProperties: false,
      properties: {
        source_signature: {
          enum: ["verified", "unverified", "not_applicable"],
          type: "string",
        },
        transport_verified: {
          anyOf: [
            {
              type: "boolean",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: ["transport_verified", "source_signature"],
      type: "object",
    },
    ProductTarget: {
      additionalProperties: false,
      properties: {
        product_id: {
          maxLength: 128,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["product_id"],
      type: "object",
    },
    RDAPRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "rdap",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/DomainTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    RegistryContext: {
      additionalProperties: false,
      properties: {
        collected_at: {
          type: "string",
        },
        collector_id: {
          const: "public-registry",
          type: "string",
        },
        collector_version: {
          allOf: [
            {
              pattern: "^[0-9A-Za-z.+-]{1,32}$",
              type: "string",
            },
          ],
          maxLength: 32,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        credential_identity: {
          const: "not-established",
          type: "string",
        },
        evidentia_version: {
          allOf: [
            {
              pattern: "^[0-9A-Za-z.+-]{1,32}$",
              type: "string",
            },
          ],
          maxLength: 32,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        filter_applied: {
          additionalProperties: true,
          type: "object",
        },
        pagination_context: {
          type: "null",
        },
        run_id: {
          maxLength: 26,
          minLength: 26,
          pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
          type: "string",
        },
        source_system_id: {
          maxLength: 64,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
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
    RegistryDiagnostic: {
      additionalProperties: false,
      properties: {
        code: {
          enum: [
            "offline_refused",
            "live_disabled",
            "missing_credential",
            "invalid_credential",
            "missing_extra",
            "dependency_failure",
            "destination_refused",
            "dns_failure",
            "tls_failure",
            "tls_certificate_verification_failed",
            "connection_failure",
            "timeout",
            "http_error",
            "redirect_refused",
            "retry_exhausted",
            "body_limit",
            "run_byte_limit",
            "invalid_response",
            "identity_mismatch",
            "source_terminal_unproven",
            "source_match_scope_limited",
            "traversal_incomplete",
            "page_limit",
            "record_limit",
            "attempt_limit",
            "read_limit",
            "diagnostic_limit",
            "observation_limit",
            "result_limit",
            "deadline_exceeded",
            "duplicate_conflict",
            "repeated_page",
            "total_changed",
            "projection_mismatch",
            "snapshot_missing",
            "snapshot_invalid",
            "signature_missing",
            "signature_invalid",
            "signature_unsupported",
            "signature_expired",
            "source_time_unsupported",
            "source_value_unknown",
            "source_name_conflict",
            "source_name_comparison_unsupported",
            "expired_source",
            "expiry_beyond_one_year",
            "syntax_invalid",
            "signature_unverified",
            "cache_miss",
            "category_applicability_not_assessed",
            "indirect_affiliate_applicability_not_assessed",
            "conditional_approval_applicability_not_assessed",
            "cleanup_failure",
          ],
          type: "string",
        },
        effect: {
          enum: ["advisory", "gap"],
          type: "string",
        },
        source_read_id: {
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
      },
      required: ["code", "effect"],
      type: "object",
    },
    RegistryFinding: {
      additionalProperties: false,
      properties: {
        collection_context: {
          $ref: "#/$defs/RegistryContext",
        },
        compliance_status: {
          const: "unknown",
          type: "string",
        },
        control_mappings: {
          items: {
            $ref: "#/$defs/ControlMapping",
          },
          maxItems: 0,
          type: "array",
        },
        description: {
          maxLength: 256,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        first_observed: {
          type: "string",
        },
        id: {
          maxLength: 36,
          minLength: 36,
          type: "string",
        },
        last_observed: {
          type: "string",
        },
        raw_data: {
          $ref: "#/$defs/_FindingData",
        },
        remediation: {
          type: "null",
        },
        resolved_at: {
          type: "null",
        },
        resource_account: {
          type: "null",
        },
        resource_id: {
          maxLength: 2048,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        resource_region: {
          type: "null",
        },
        resource_type: {
          const: "selected_registry_query",
          type: "string",
        },
        severity: {
          const: "informational",
          type: "string",
        },
        source_finding_id: {
          maxLength: 76,
          minLength: 76,
          type: "string",
        },
        source_system: {
          const: "public-registry",
          type: "string",
        },
        status: {
          const: "active",
          type: "string",
        },
        title: {
          maxLength: 128,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
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
    RegistryJsonValue: {
      anyOf: [
        {
          type: "boolean",
        },
        {
          type: "integer",
        },
        {
          type: "number",
        },
        {
          type: "string",
        },
        {
          items: {
            $ref: "#/$defs/RegistryJsonValue",
          },
          type: "array",
        },
        {
          additionalProperties: {
            $ref: "#/$defs/RegistryJsonValue",
          },
          type: "object",
        },
        {
          type: "null",
        },
      ],
    },
    RegistryLookupRequest: {
      oneOf: [
        {
          $ref: "#/$defs/TLSRequest",
        },
        {
          $ref: "#/$defs/RDAPRequest",
        },
        {
          $ref: "#/$defs/SAMEntityRequest",
        },
        {
          $ref: "#/$defs/SAMExclusionsRequest",
        },
        {
          $ref: "#/$defs/GLEIFRequest",
        },
        {
          $ref: "#/$defs/FedRAMPRequest",
        },
        {
          $ref: "#/$defs/CMVPRequest",
        },
        {
          $ref: "#/$defs/FCCRequest",
        },
        {
          $ref: "#/$defs/InCommonRequest",
        },
        {
          $ref: "#/$defs/SSLLabsRequest",
        },
        {
          $ref: "#/$defs/SecurityTxtRequest",
        },
      ],
    },
    RegistryManifest: {
      additionalProperties: false,
      properties: {
        collection_finished_at: {
          type: "string",
        },
        collection_started_at: {
          type: "string",
        },
        collector_id: {
          const: "public-registry",
          type: "string",
        },
        collector_version: {
          allOf: [
            {
              pattern: "^[0-9A-Za-z.+-]{1,32}$",
              type: "string",
            },
          ],
          maxLength: 32,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        coverage_counts: {
          items: {
            $ref: "#/$defs/CoverageCount",
          },
          maxItems: 1,
          minItems: 1,
          type: "array",
        },
        empty_categories: {
          items: {
            type: "string",
          },
          maxItems: 1,
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
          allOf: [
            {
              pattern: "^[0-9A-Za-z.+-]{1,32}$",
              type: "string",
            },
          ],
          maxLength: 32,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        filters_applied: {
          additionalProperties: true,
          type: "object",
        },
        incomplete_reason: {
          anyOf: [
            {
              const: "selected_query_incomplete",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        is_complete: {
          type: "boolean",
        },
        run_id: {
          maxLength: 26,
          minLength: 26,
          pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
          type: "string",
        },
        source_system_ids: {
          items: {
            type: "string",
          },
          maxItems: 1,
          type: "array",
        },
        total_findings: {
          maximum: 100,
          minimum: 0,
          type: "integer",
        },
        warnings: {
          items: {
            type: "string",
          },
          maxItems: 64,
          type: "array",
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
    RegistryObservation: {
      additionalProperties: false,
      properties: {
        field_coverage: {
          additionalProperties: {
            enum: ["present", "absent", "null", "unknown"],
            type: "string",
          },
          maxProperties: 128,
          type: "object",
        },
        fields: {
          additionalProperties: {
            $ref: "#/$defs/RegistryJsonValue",
          },
          type: "object",
        },
        interpretation: {
          maxLength: 256,
          type: "string",
        },
        match_basis: {
          enum: [
            "exact_identifier",
            "exact_normalized_name",
            "provider_candidate",
          ],
          type: "string",
        },
        matched_identity: {
          maxLength: 2048,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        observation_id: {
          maxLength: 76,
          minLength: 76,
          pattern: "^observation-[0-9a-f]{64}$",
          type: "string",
        },
        registry: {
          enum: [
            "tls",
            "rdap",
            "sam-entity",
            "sam-exclusions",
            "gleif",
            "fedramp",
            "cmvp",
            "fcc-covered-list",
            "incommon",
            "ssl-labs",
            "security-txt",
          ],
          type: "string",
        },
        source_identity: {
          additionalProperties: {
            $ref: "#/$defs/RegistryJsonValue",
          },
          type: "object",
        },
        source_read_id: {
          maxLength: 69,
          minLength: 69,
          pattern: "^read-[0-9a-f]{64}$",
          type: "string",
        },
        source_times: {
          items: {
            $ref: "#/$defs/SourceTime",
          },
          maxItems: 64,
          type: "array",
        },
        trust: {
          $ref: "#/$defs/ObservationTrust",
        },
      },
      required: [
        "registry",
        "observation_id",
        "source_read_id",
        "source_identity",
        "matched_identity",
        "match_basis",
        "fields",
        "field_coverage",
        "source_times",
        "trust",
        "interpretation",
      ],
      type: "object",
    },
    SAMEntityRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "sam-entity",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/UEITarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    SAMExclusionsRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "sam-exclusions",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          anyOf: [
            {
              $ref: "#/$defs/UEITarget",
            },
            {
              $ref: "#/$defs/SAMOrganizationTarget",
            },
          ],
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    SAMOrganizationTarget: {
      additionalProperties: false,
      properties: {
        organization_name: {
          maxLength: 512,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
      },
      required: ["organization_name"],
      type: "object",
    },
    SSLLabsRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "ssl-labs",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/EndpointTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    SecurityTxtRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "security-txt",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/HostnameTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    SourceRead: {
      additionalProperties: false,
      properties: {
        accepted_pages: {
          maximum: 20,
          minimum: 0,
          type: "integer",
        },
        admitted_records: {
          maximum: 100,
          minimum: 0,
          type: "integer",
        },
        attempted_pages: {
          maximum: 64,
          minimum: 0,
          type: "integer",
        },
        body_complete: {
          type: "boolean",
        },
        cache_state: {
          enum: ["not_applicable", "cache_only", "unknown"],
          type: "string",
        },
        decoded_bytes: {
          anyOf: [
            {
              maximum: 16777216,
              minimum: 0,
              type: "integer",
            },
            {
              type: "null",
            },
          ],
        },
        freshness: {
          enum: ["current_observation", "dated_snapshot", "stale", "unknown"],
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
        method: {
          enum: ["GET", "TLS", "LOCAL", "DISABLED"],
          type: "string",
        },
        network_attempts: {
          maximum: 64,
          minimum: 0,
          type: "integer",
        },
        ordinal: {
          exclusiveMaximum: 24,
          minimum: 0,
          type: "integer",
        },
        publisher_date: {
          anyOf: [
            {
              maxLength: 512,
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        publisher_version: {
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
        query_scope: {
          $ref: "#/$defs/RegistryLookupRequest",
        },
        raw_bytes: {
          anyOf: [
            {
              maximum: 16777216,
              minimum: 0,
              type: "integer",
            },
            {
              type: "null",
            },
          ],
        },
        read_id: {
          maxLength: 69,
          minLength: 69,
          pattern: "^read-[0-9a-f]{64}$",
          type: "string",
        },
        registry: {
          enum: [
            "tls",
            "rdap",
            "sam-entity",
            "sam-exclusions",
            "gleif",
            "fedramp",
            "cmvp",
            "fcc-covered-list",
            "incommon",
            "ssl-labs",
            "security-txt",
          ],
          type: "string",
        },
        retrieved_at: {
          type: "string",
        },
        snapshot_source: {
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
        source_digest: {
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
        source_records: {
          maximum: 50000,
          minimum: 0,
          type: "integer",
        },
        source_signature: {
          enum: ["verified", "unverified", "not_applicable"],
          type: "string",
        },
        status: {
          enum: ["complete", "partial", "unavailable"],
          type: "string",
        },
        template: {
          maxLength: 64,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        transport_kind: {
          enum: ["https", "tls", "snapshot", "none"],
          type: "string",
        },
        transport_verified: {
          anyOf: [
            {
              type: "boolean",
            },
            {
              type: "null",
            },
          ],
        },
      },
      required: [
        "read_id",
        "registry",
        "ordinal",
        "method",
        "template",
        "query_scope",
        "transport_kind",
        "status",
        "freshness",
        "http_status",
        "network_attempts",
        "attempted_pages",
        "accepted_pages",
        "source_records",
        "admitted_records",
        "raw_bytes",
        "decoded_bytes",
        "body_complete",
        "source_digest",
        "retrieved_at",
        "publisher_date",
        "publisher_version",
        "snapshot_source",
        "cache_state",
        "transport_verified",
        "source_signature",
      ],
      type: "object",
    },
    SourceTime: {
      additionalProperties: false,
      properties: {
        literal: {
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
              type: "null",
            },
          ],
        },
        normalized_utc: {
          anyOf: [
            {
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        path: {
          maxLength: 128,
          minLength: 1,
          pattern:
            "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
          type: "string",
        },
        representation: {
          enum: ["rfc3339", "unix_milliseconds", "source_text"],
          type: "string",
        },
      },
      required: ["path", "literal", "representation", "normalized_utc"],
      type: "object",
    },
    TLSRequest: {
      additionalProperties: false,
      properties: {
        registry: {
          const: "tls",
          type: "string",
        },
        scope_label: {
          anyOf: [
            {
              maxLength: 128,
              minLength: 1,
              pattern:
                "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
              type: "string",
            },
            {
              type: "null",
            },
          ],
        },
        target: {
          $ref: "#/$defs/HostnameTarget",
        },
      },
      required: ["registry", "target"],
      type: "object",
    },
    UEITarget: {
      additionalProperties: false,
      properties: {
        uei: {
          maxLength: 12,
          minLength: 12,
          pattern: "^[A-Z0-9]{12}$",
          type: "string",
        },
      },
      required: ["uei"],
      type: "object",
    },
    _FindingData: {
      additionalProperties: false,
      properties: {
        observation: {
          $ref: "#/$defs/RegistryObservation",
        },
      },
      required: ["observation"],
      type: "object",
    },
  },
  additionalProperties: false,
  properties: {
    collection_status: {
      enum: ["complete", "partial", "unavailable"],
      type: "string",
    },
    diagnostics: {
      items: {
        $ref: "#/$defs/RegistryDiagnostic",
      },
      maxItems: 64,
      type: "array",
    },
    findings: {
      items: {
        $ref: "#/$defs/RegistryFinding",
      },
      maxItems: 100,
      type: "array",
    },
    freshness: {
      enum: ["current_observation", "dated_snapshot", "stale", "unknown"],
      type: "string",
    },
    lookup_outcome: {
      enum: ["found", "not_found", "ambiguous", "unavailable"],
      type: "string",
    },
    manifest: {
      $ref: "#/$defs/RegistryManifest",
    },
    observation_scope: {
      const: "selected_registry_query",
      type: "string",
    },
    observations: {
      items: {
        $ref: "#/$defs/RegistryObservation",
      },
      maxItems: 100,
      type: "array",
    },
    registry: {
      enum: [
        "tls",
        "rdap",
        "sam-entity",
        "sam-exclusions",
        "gleif",
        "fedramp",
        "cmvp",
        "fcc-covered-list",
        "incommon",
        "ssl-labs",
        "security-txt",
      ],
      type: "string",
    },
    request: {
      $ref: "#/$defs/RegistryLookupRequest",
    },
    run_id: {
      maxLength: 26,
      minLength: 26,
      pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
      type: "string",
    },
    schema_version: {
      const: "1",
      type: "string",
    },
    source_reads: {
      items: {
        $ref: "#/$defs/SourceRead",
      },
      maxItems: 24,
      type: "array",
    },
  },
  required: [
    "schema_version",
    "registry",
    "request",
    "run_id",
    "observation_scope",
    "lookup_outcome",
    "collection_status",
    "freshness",
    "observations",
    "source_reads",
    "findings",
    "diagnostics",
    "manifest",
  ],
  type: "object",
};
const CASEFOLD: Readonly<Record<string, string>> = {
  "\u00b5": "\u03bc",
  "\u00df": "ss",
  "\u0149": "\u02bcn",
  "\u017f": "s",
  "\u01f0": "j\u030c",
  "\u0345": "\u03b9",
  "\u0390": "\u03b9\u0308\u0301",
  "\u03b0": "\u03c5\u0308\u0301",
  "\u03c2": "\u03c3",
  "\u03d0": "\u03b2",
  "\u03d1": "\u03b8",
  "\u03d5": "\u03c6",
  "\u03d6": "\u03c0",
  "\u03f0": "\u03ba",
  "\u03f1": "\u03c1",
  "\u03f5": "\u03b5",
  "\u0587": "\u0565\u0582",
  "\u13a0": "\u13a0",
  "\u13a1": "\u13a1",
  "\u13a2": "\u13a2",
  "\u13a3": "\u13a3",
  "\u13a4": "\u13a4",
  "\u13a5": "\u13a5",
  "\u13a6": "\u13a6",
  "\u13a7": "\u13a7",
  "\u13a8": "\u13a8",
  "\u13a9": "\u13a9",
  "\u13aa": "\u13aa",
  "\u13ab": "\u13ab",
  "\u13ac": "\u13ac",
  "\u13ad": "\u13ad",
  "\u13ae": "\u13ae",
  "\u13af": "\u13af",
  "\u13b0": "\u13b0",
  "\u13b1": "\u13b1",
  "\u13b2": "\u13b2",
  "\u13b3": "\u13b3",
  "\u13b4": "\u13b4",
  "\u13b5": "\u13b5",
  "\u13b6": "\u13b6",
  "\u13b7": "\u13b7",
  "\u13b8": "\u13b8",
  "\u13b9": "\u13b9",
  "\u13ba": "\u13ba",
  "\u13bb": "\u13bb",
  "\u13bc": "\u13bc",
  "\u13bd": "\u13bd",
  "\u13be": "\u13be",
  "\u13bf": "\u13bf",
  "\u13c0": "\u13c0",
  "\u13c1": "\u13c1",
  "\u13c2": "\u13c2",
  "\u13c3": "\u13c3",
  "\u13c4": "\u13c4",
  "\u13c5": "\u13c5",
  "\u13c6": "\u13c6",
  "\u13c7": "\u13c7",
  "\u13c8": "\u13c8",
  "\u13c9": "\u13c9",
  "\u13ca": "\u13ca",
  "\u13cb": "\u13cb",
  "\u13cc": "\u13cc",
  "\u13cd": "\u13cd",
  "\u13ce": "\u13ce",
  "\u13cf": "\u13cf",
  "\u13d0": "\u13d0",
  "\u13d1": "\u13d1",
  "\u13d2": "\u13d2",
  "\u13d3": "\u13d3",
  "\u13d4": "\u13d4",
  "\u13d5": "\u13d5",
  "\u13d6": "\u13d6",
  "\u13d7": "\u13d7",
  "\u13d8": "\u13d8",
  "\u13d9": "\u13d9",
  "\u13da": "\u13da",
  "\u13db": "\u13db",
  "\u13dc": "\u13dc",
  "\u13dd": "\u13dd",
  "\u13de": "\u13de",
  "\u13df": "\u13df",
  "\u13e0": "\u13e0",
  "\u13e1": "\u13e1",
  "\u13e2": "\u13e2",
  "\u13e3": "\u13e3",
  "\u13e4": "\u13e4",
  "\u13e5": "\u13e5",
  "\u13e6": "\u13e6",
  "\u13e7": "\u13e7",
  "\u13e8": "\u13e8",
  "\u13e9": "\u13e9",
  "\u13ea": "\u13ea",
  "\u13eb": "\u13eb",
  "\u13ec": "\u13ec",
  "\u13ed": "\u13ed",
  "\u13ee": "\u13ee",
  "\u13ef": "\u13ef",
  "\u13f0": "\u13f0",
  "\u13f1": "\u13f1",
  "\u13f2": "\u13f2",
  "\u13f3": "\u13f3",
  "\u13f4": "\u13f4",
  "\u13f5": "\u13f5",
  "\u13f8": "\u13f0",
  "\u13f9": "\u13f1",
  "\u13fa": "\u13f2",
  "\u13fb": "\u13f3",
  "\u13fc": "\u13f4",
  "\u13fd": "\u13f5",
  "\u1c80": "\u0432",
  "\u1c81": "\u0434",
  "\u1c82": "\u043e",
  "\u1c83": "\u0441",
  "\u1c84": "\u0442",
  "\u1c85": "\u0442",
  "\u1c86": "\u044a",
  "\u1c87": "\u0463",
  "\u1c88": "\ua64b",
  "\u1e96": "h\u0331",
  "\u1e97": "t\u0308",
  "\u1e98": "w\u030a",
  "\u1e99": "y\u030a",
  "\u1e9a": "a\u02be",
  "\u1e9b": "\u1e61",
  "\u1e9e": "ss",
  "\u1f50": "\u03c5\u0313",
  "\u1f52": "\u03c5\u0313\u0300",
  "\u1f54": "\u03c5\u0313\u0301",
  "\u1f56": "\u03c5\u0313\u0342",
  "\u1f80": "\u1f00\u03b9",
  "\u1f81": "\u1f01\u03b9",
  "\u1f82": "\u1f02\u03b9",
  "\u1f83": "\u1f03\u03b9",
  "\u1f84": "\u1f04\u03b9",
  "\u1f85": "\u1f05\u03b9",
  "\u1f86": "\u1f06\u03b9",
  "\u1f87": "\u1f07\u03b9",
  "\u1f88": "\u1f00\u03b9",
  "\u1f89": "\u1f01\u03b9",
  "\u1f8a": "\u1f02\u03b9",
  "\u1f8b": "\u1f03\u03b9",
  "\u1f8c": "\u1f04\u03b9",
  "\u1f8d": "\u1f05\u03b9",
  "\u1f8e": "\u1f06\u03b9",
  "\u1f8f": "\u1f07\u03b9",
  "\u1f90": "\u1f20\u03b9",
  "\u1f91": "\u1f21\u03b9",
  "\u1f92": "\u1f22\u03b9",
  "\u1f93": "\u1f23\u03b9",
  "\u1f94": "\u1f24\u03b9",
  "\u1f95": "\u1f25\u03b9",
  "\u1f96": "\u1f26\u03b9",
  "\u1f97": "\u1f27\u03b9",
  "\u1f98": "\u1f20\u03b9",
  "\u1f99": "\u1f21\u03b9",
  "\u1f9a": "\u1f22\u03b9",
  "\u1f9b": "\u1f23\u03b9",
  "\u1f9c": "\u1f24\u03b9",
  "\u1f9d": "\u1f25\u03b9",
  "\u1f9e": "\u1f26\u03b9",
  "\u1f9f": "\u1f27\u03b9",
  "\u1fa0": "\u1f60\u03b9",
  "\u1fa1": "\u1f61\u03b9",
  "\u1fa2": "\u1f62\u03b9",
  "\u1fa3": "\u1f63\u03b9",
  "\u1fa4": "\u1f64\u03b9",
  "\u1fa5": "\u1f65\u03b9",
  "\u1fa6": "\u1f66\u03b9",
  "\u1fa7": "\u1f67\u03b9",
  "\u1fa8": "\u1f60\u03b9",
  "\u1fa9": "\u1f61\u03b9",
  "\u1faa": "\u1f62\u03b9",
  "\u1fab": "\u1f63\u03b9",
  "\u1fac": "\u1f64\u03b9",
  "\u1fad": "\u1f65\u03b9",
  "\u1fae": "\u1f66\u03b9",
  "\u1faf": "\u1f67\u03b9",
  "\u1fb2": "\u1f70\u03b9",
  "\u1fb3": "\u03b1\u03b9",
  "\u1fb4": "\u03ac\u03b9",
  "\u1fb6": "\u03b1\u0342",
  "\u1fb7": "\u03b1\u0342\u03b9",
  "\u1fbc": "\u03b1\u03b9",
  "\u1fbe": "\u03b9",
  "\u1fc2": "\u1f74\u03b9",
  "\u1fc3": "\u03b7\u03b9",
  "\u1fc4": "\u03ae\u03b9",
  "\u1fc6": "\u03b7\u0342",
  "\u1fc7": "\u03b7\u0342\u03b9",
  "\u1fcc": "\u03b7\u03b9",
  "\u1fd2": "\u03b9\u0308\u0300",
  "\u1fd3": "\u03b9\u0308\u0301",
  "\u1fd6": "\u03b9\u0342",
  "\u1fd7": "\u03b9\u0308\u0342",
  "\u1fe2": "\u03c5\u0308\u0300",
  "\u1fe3": "\u03c5\u0308\u0301",
  "\u1fe4": "\u03c1\u0313",
  "\u1fe6": "\u03c5\u0342",
  "\u1fe7": "\u03c5\u0308\u0342",
  "\u1ff2": "\u1f7c\u03b9",
  "\u1ff3": "\u03c9\u03b9",
  "\u1ff4": "\u03ce\u03b9",
  "\u1ff6": "\u03c9\u0342",
  "\u1ff7": "\u03c9\u0342\u03b9",
  "\u1ffc": "\u03c9\u03b9",
  "\uab70": "\u13a0",
  "\uab71": "\u13a1",
  "\uab72": "\u13a2",
  "\uab73": "\u13a3",
  "\uab74": "\u13a4",
  "\uab75": "\u13a5",
  "\uab76": "\u13a6",
  "\uab77": "\u13a7",
  "\uab78": "\u13a8",
  "\uab79": "\u13a9",
  "\uab7a": "\u13aa",
  "\uab7b": "\u13ab",
  "\uab7c": "\u13ac",
  "\uab7d": "\u13ad",
  "\uab7e": "\u13ae",
  "\uab7f": "\u13af",
  "\uab80": "\u13b0",
  "\uab81": "\u13b1",
  "\uab82": "\u13b2",
  "\uab83": "\u13b3",
  "\uab84": "\u13b4",
  "\uab85": "\u13b5",
  "\uab86": "\u13b6",
  "\uab87": "\u13b7",
  "\uab88": "\u13b8",
  "\uab89": "\u13b9",
  "\uab8a": "\u13ba",
  "\uab8b": "\u13bb",
  "\uab8c": "\u13bc",
  "\uab8d": "\u13bd",
  "\uab8e": "\u13be",
  "\uab8f": "\u13bf",
  "\uab90": "\u13c0",
  "\uab91": "\u13c1",
  "\uab92": "\u13c2",
  "\uab93": "\u13c3",
  "\uab94": "\u13c4",
  "\uab95": "\u13c5",
  "\uab96": "\u13c6",
  "\uab97": "\u13c7",
  "\uab98": "\u13c8",
  "\uab99": "\u13c9",
  "\uab9a": "\u13ca",
  "\uab9b": "\u13cb",
  "\uab9c": "\u13cc",
  "\uab9d": "\u13cd",
  "\uab9e": "\u13ce",
  "\uab9f": "\u13cf",
  "\uaba0": "\u13d0",
  "\uaba1": "\u13d1",
  "\uaba2": "\u13d2",
  "\uaba3": "\u13d3",
  "\uaba4": "\u13d4",
  "\uaba5": "\u13d5",
  "\uaba6": "\u13d6",
  "\uaba7": "\u13d7",
  "\uaba8": "\u13d8",
  "\uaba9": "\u13d9",
  "\uabaa": "\u13da",
  "\uabab": "\u13db",
  "\uabac": "\u13dc",
  "\uabad": "\u13dd",
  "\uabae": "\u13de",
  "\uabaf": "\u13df",
  "\uabb0": "\u13e0",
  "\uabb1": "\u13e1",
  "\uabb2": "\u13e2",
  "\uabb3": "\u13e3",
  "\uabb4": "\u13e4",
  "\uabb5": "\u13e5",
  "\uabb6": "\u13e6",
  "\uabb7": "\u13e7",
  "\uabb8": "\u13e8",
  "\uabb9": "\u13e9",
  "\uabba": "\u13ea",
  "\uabbb": "\u13eb",
  "\uabbc": "\u13ec",
  "\uabbd": "\u13ed",
  "\uabbe": "\u13ee",
  "\uabbf": "\u13ef",
  "\ufb00": "ff",
  "\ufb01": "fi",
  "\ufb02": "fl",
  "\ufb03": "ffi",
  "\ufb04": "ffl",
  "\ufb05": "st",
  "\ufb06": "st",
  "\ufb13": "\u0574\u0576",
  "\ufb14": "\u0574\u0565",
  "\ufb15": "\u0574\u056b",
  "\ufb16": "\u057e\u0576",
  "\ufb17": "\u0574\u056d",
};
const IP_NETWORKS: Readonly<
  Record<string, { private: string[]; exceptions: string[] }>
> = {
  "4": {
    private: [
      "0.0.0.0/8",
      "10.0.0.0/8",
      "127.0.0.0/8",
      "169.254.0.0/16",
      "172.16.0.0/12",
      "192.0.0.0/24",
      "192.0.0.170/31",
      "192.0.2.0/24",
      "192.168.0.0/16",
      "198.18.0.0/15",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "240.0.0.0/4",
      "255.255.255.255/32",
    ],
    exceptions: ["192.0.0.9/32", "192.0.0.10/32"],
  },
  "6": {
    private: [
      "::1/128",
      "::/128",
      "::ffff:0.0.0.0/96",
      "64:ff9b:1::/48",
      "100::/64",
      "2001::/23",
      "2001:db8::/32",
      "2002::/16",
      "3fff::/20",
      "fc00::/7",
      "fe80::/10",
    ],
    exceptions: [
      "2001:1::1/128",
      "2001:1::2/128",
      "2001:3::/32",
      "2001:4:112::/48",
      "2001:20::/28",
      "2001:30::/28",
    ],
  },
};

export function indexRegistryJson(raw: string): Map<string, string> {
  const fail = (): never => {
    throw new RegistryResponseError();
  };
  const encoder = new TextEncoder();
  if (typeof raw !== "string" || encoder.encode(raw).length > 4_194_304) fail();
  let cursor = 0;
  let nodes = 0;
  let canonicalBytes = 0;
  const spans = new Map<string, string>();
  const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const path: (string | number)[] = [];
  type Observation = { parentDepth: number; nodes: number; bytes: number };

  const whitespace = () => {
    while (cursor < raw.length && " \t\r\n".includes(raw[cursor])) ++cursor;
  };
  const node = (observation: Observation | null) => {
    if (++nodes > 2_097_152) fail();
    if (observation && ++observation.nodes > 10_000) fail();
  };
  const add = (bytes: number, observation: Observation | null) => {
    canonicalBytes += bytes;
    if (canonicalBytes > 4_194_304) fail();
    if (observation) {
      observation.bytes += bytes;
      if (observation.bytes > 65_536) fail();
    }
  };
  const string = (): string => {
    const start = cursor++;
    let escaped = false;
    while (cursor < raw.length) {
      const character = raw[cursor++];
      if (!escaped && character === '"') {
        let value: unknown;
        try {
          value = JSON.parse(raw.slice(start, cursor));
        } catch {
          return fail();
        }
        if (typeof value !== "string" || /\p{Surrogate}/u.test(value))
          return fail();
        return value;
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    return fail();
  };
  const quoted = (value: string): string => {
    const text = JSON.stringify(value);
    // Aggregate parsing retains the storage primitive's per-string bound.
    if (encoder.encode(text).length > 1_048_576) return fail();
    return text;
  };
  type Decimal = { digits: string; exponent: bigint; negative: boolean };
  const decimal = (token: string): Decimal => {
    const [mantissa, exponentToken = "0"] = token.toLowerCase().split("e");
    const negative = mantissa.startsWith("-");
    const [whole, fraction = ""] = (
      negative ? mantissa.slice(1) : mantissa
    ).split(".");
    const exponentDigits =
      exponentToken.replace(/^[+-]/, "").replace(/^0+/, "") || "0";
    if (exponentDigits.length > 19) return fail();
    const parsedExponent = BigInt(
      (exponentToken.startsWith("-") ? "-" : "") + exponentDigits,
    );
    const exponent = parsedExponent - BigInt(fraction.length);
    // These are the 64-bit Decimal construction bounds used by both supported Pythons.
    if (
      exponent < -1_999_999_999_999_999_997n ||
      exponent > 999_999_999_999_999_999n
    )
      return fail();
    const significant = (whole + fraction).replace(/^0+/, "");
    if (!significant) return { digits: "0", exponent: 0n, negative };
    const digits = significant.replace(/0+$/, "");
    return {
      digits,
      exponent: exponent + BigInt(significant.length - digits.length),
      negative,
    };
  };
  const float = (token: string): string => {
    const value = Number(token);
    if (!Number.isFinite(value)) return fail();
    const supplied = decimal(token);
    const shortest = decimal(value.toString());
    if (
      supplied.digits !== shortest.digits ||
      supplied.exponent !== shortest.exponent
    )
      return fail();
    if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
    const sign = value < 0 ? "-" : "";
    const digits = shortest.digits;
    const exponent = Number(shortest.exponent);
    const scientificExponent = exponent + digits.length - 1;
    if (scientificExponent < -4 || scientificExponent >= 16) {
      const mantissa =
        digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "");
      const exponentSign = scientificExponent < 0 ? "-" : "+";
      return (
        sign +
        mantissa +
        "e" +
        exponentSign +
        Math.abs(scientificExponent).toString().padStart(2, "0")
      );
    }
    const point = digits.length + exponent;
    if (point <= 0) return sign + "0." + "0".repeat(-point) + digits;
    if (point >= digits.length)
      return sign + digits + "0".repeat(point - digits.length) + ".0";
    return sign + digits.slice(0, point) + "." + digits.slice(point);
  };
  const compareKeys = (left: string, right: string): number => {
    let a = 0;
    let b = 0;
    while (a < left.length && b < right.length) {
      const x = left.codePointAt(a)!;
      const y = right.codePointAt(b)!;
      if (x !== y) return x - y;
      a += x > 0xffff ? 2 : 1;
      b += y > 0xffff ? 2 : 1;
    }
    return left.length - right.length;
  };
  const visit = (
    parentDepth: number,
    inherited: Observation | null,
  ): string | null => {
    whitespace();
    const start = cursor;
    const rootObservation =
      path.length === 2 &&
      path[0] === "observations" &&
      typeof path[1] === "number";
    const findingObservation =
      path.length === 4 &&
      path[0] === "findings" &&
      typeof path[1] === "number" &&
      path[2] === "raw_data" &&
      path[3] === "observation";
    const isObservation = rootObservation || findingObservation;
    const observation = isObservation
      ? { parentDepth, nodes: 0, bytes: 0 }
      : inherited;
    node(observation);
    const character = raw[cursor];
    let canonical: string | null = null;
    if (character === "{" || character === "[") {
      const depth = parentDepth + 1;
      if (depth > 20 || (observation && depth - observation.parentDepth > 16))
        return fail();
      const object = character === "{";
      const close = object ? "}" : "]";
      ++cursor;
      add(2, observation);
      whitespace();
      const keys = new Set<string>();
      const entries: { key: string; text: string }[] = [];
      const items: string[] = [];
      let index = 0;
      if (raw[cursor] !== close) {
        for (;;) {
          if (index) add(1, observation);
          let key: string | number = index;
          if (object) {
            if (raw[cursor] !== '"') return fail();
            node(observation);
            key = string();
            if (keys.has(key)) return fail();
            keys.add(key);
            add(encoder.encode(quoted(key)).length + 1, observation);
            whitespace();
            if (raw[cursor++] !== ":") return fail();
          }
          path.push(key);
          const child = visit(depth, observation);
          path.pop();
          if (observation) {
            if (child === null) return fail();
            if (typeof key === "string")
              entries.push({ key, text: JSON.stringify(key) + ":" + child });
            else items.push(child);
          }
          ++index;
          whitespace();
          if (raw[cursor] === close) break;
          if (raw[cursor++] !== ",") return fail();
          whitespace();
        }
      }
      ++cursor;
      if (observation) {
        canonical = object
          ? "{" +
            entries
              .sort((a, b) => compareKeys(a.key, b.key))
              .map((entry) => entry.text)
              .join(",") +
            "}"
          : "[" + items.join(",") + "]";
      }
    } else {
      let text: string;
      if (character === '"') text = quoted(string());
      else if (raw.startsWith("true", cursor)) {
        cursor += 4;
        text = "true";
      } else if (raw.startsWith("false", cursor)) {
        cursor += 5;
        text = "false";
      } else if (raw.startsWith("null", cursor)) {
        cursor += 4;
        text = "null";
      } else {
        number.lastIndex = cursor;
        const match = number.exec(raw);
        if (!match) return fail();
        const token = match[0];
        const kind = /[.eE]/.test(token) ? "float" : "int";
        if (kind === "int") {
          if (token.length - (token.startsWith("-") ? 1 : 0) > 128)
            return fail();
          text = token === "-0" ? "0" : token;
        } else text = float(token);
        cursor = number.lastIndex;
        spans.set("number:" + JSON.stringify(path), kind);
      }
      add(encoder.encode(text).length, observation);
      if (observation) canonical = text;
    }
    spans.set("value:" + JSON.stringify(path), raw.slice(start, cursor));
    if (isObservation) {
      if (canonical === null) return fail();
      spans.set(
        (rootObservation ? "observation:" : "finding-observation:") + path[1],
        canonical,
      );
    }
    return canonical;
  };
  visit(0, null);
  whitespace();
  if (cursor !== raw.length) fail();
  return spans;
}

function matches(
  value: unknown,
  schema: JsonSchema,
  path: JsonPath,
  spans: ReadonlyMap<string, string>,
): boolean {
  if (
    schema.allOf &&
    !schema.allOf.every((item) => matches(value, item, path, spans))
  )
    return false;
  if (schema.$ref) {
    if (!schema.$ref.startsWith("#/$defs/")) return false;
    const name = schema.$ref.slice(8);
    const definitions = RESULT_SCHEMA.$defs!;
    if (
      !Object.hasOwn(definitions, name) ||
      !matches(value, definitions[name], path, spans)
    )
      return false;
  }
  if (
    schema.oneOf &&
    schema.oneOf.filter((item) => matches(value, item, path, spans)).length !==
      1
  )
    return false;
  if (
    schema.anyOf &&
    !schema.anyOf.some((item) => matches(value, item, path, spans))
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
    if (
      schema.type === "integer" &&
      (spans.get("number:" + JSON.stringify(path)) !== "int" ||
        !Number.isInteger(value))
    )
      return false;
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
      !value.every((item, i) =>
        matches(item, schema.items!, [...path, i], spans),
      )
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
    if (schema.required?.some((key) => !Object.hasOwn(value, key)))
      return false;
    for (const key of keys) {
      const properties = schema.properties ?? {};
      if (Object.hasOwn(properties, key)) {
        if (!matches(value[key], properties[key], [...path, key], spans))
          return false;
      } else if (schema.additionalProperties === false) return false;
      else if (
        isObject(schema.additionalProperties) &&
        !matches(value[key], schema.additionalProperties, [...path, key], spans)
      )
        return false;
    }
  }
  return true;
}

const pythonBlank =
  /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;
function text(value: unknown, limit: number): asserts value is string {
  if (
    typeof value !== "string" ||
    size(value) > limit ||
    pythonBlank.test(value) ||
    /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)
  )
    failure();
}
function hostname(value: string): string {
  text(value, 254);
  if (!/^[\x00-\x7f]+$/.test(value)) return failure();
  const name = value.toLowerCase().replace(/\.$/, "");
  const labels = name.split(".");
  if (
    !name ||
    name.length > 253 ||
    labels.some(
      (label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label),
    ) ||
    labels.every((label) => /^(?:[0-9]+|0x[0-9a-f]+)$/.test(label))
  )
    return failure();
  return name;
}
function ipNumber(value: string, version: number): bigint {
  if (version === 4) {
    if (!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value))
      return failure();
    return value.split(".").reduce((total, part) => {
      const item = Number(part);
      if (item > 255) return failure();
      return (total << 8n) + BigInt(item);
    }, 0n);
  }
  if (!/^[0-9a-fA-F:.]+$/.test(value)) return failure();
  let normal: string;
  try {
    normal = new URL("https://[" + value + "]/").hostname.slice(1, -1);
  } catch {
    return failure();
  }
  const halves = normal.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  const groups =
    halves.length > 1
      ? [
          ...left,
          ...Array<string>(8 - left.length - right.length).fill("0"),
          ...right,
        ]
      : left;
  if (groups.length !== 8) return failure();
  return groups.reduce(
    (total, group) => (total << 16n) + BigInt("0x" + group),
    0n,
  );
}
function inNetwork(address: bigint, network: string, version: number): boolean {
  const [base, bits] = network.split("/");
  const shift = BigInt((version === 4 ? 32 : 128) - Number(bits));
  return address >> shift === ipNumber(base, version) >> shift;
}
function globalIp(address: bigint, version: number): boolean {
  if (version === 6 && address >> 32n === 0xffffn)
    return globalIp(address & 0xffffffffn, 4);
  const table = IP_NETWORKS[String(version)];
  if (version === 4 && inNetwork(address, "100.64.0.0/10", 4)) return false;
  return (
    !table.private.some((network) => inNetwork(address, network, version)) ||
    table.exceptions.some((network) => inNetwork(address, network, version))
  );
}
function endpoint(value: string): void {
  const version = value.includes(":") ? 6 : 4;
  const number = ipNumber(value, version);
  if (
    number === 0n ||
    !globalIp(number, version) ||
    inNetwork(number, version === 4 ? "224.0.0.0/4" : "ff00::/8", version)
  )
    failure();
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
  if (value === null || typeof value === "string") return value;
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

export function snapshotRegistryRequest(input: unknown): RegistryRequest {
  input = nativeRequest(input);
  const raw = JSON.stringify(input);
  if (size(raw) > REGISTRY_REQUEST_BYTE_LIMIT) return failure();
  const spans = indexRegistryJson(raw);
  if (
    !matches(input, RESULT_SCHEMA.$defs!.RegistryLookupRequest, [], spans) ||
    !isObject(input) ||
    !isObject(input.target)
  )
    return failure();
  const target = input.target;
  const selector = input.registry;
  for (const [name, value] of Object.entries(target))
    text(
      value,
      name === "entity_id" ? 2048 : name === "organization_name" ? 512 : 254,
    );
  if (typeof target.hostname === "string") hostname(target.hostname);
  if (typeof target.domain === "string") hostname(target.domain);
  if (typeof target.endpoint_ip === "string") endpoint(target.endpoint_ip);
  if (typeof target.product_id === "string") text(target.product_id, 128);
  if (typeof target.organization_name === "string") {
    const normalized = [...target.organization_name.normalize("NFC")]
      .map((char) => CASEFOLD[char] ?? char.toLowerCase())
      .join("")
      .replace(/^ +| +$/g, "")
      .replace(/ +/g, " ");
    text(normalized, 512);
    if (
      selector === "sam-exclusions" &&
      (!/^[A-Za-z0-9 ',.\-]+$/.test(target.organization_name) ||
        !/[A-Za-z0-9]/.test(target.organization_name))
    )
      return failure();
  }
  if (input.scope_label !== undefined && input.scope_label !== null)
    text(input.scope_label, 128);
  const detached = JSON.parse(raw) as RegistryRequest;
  detached.scope_label ??= null;
  return freeze(detached);
}
export function parseRegistryRequest(raw: string): RegistryRequest {
  if (size(raw) > REGISTRY_REQUEST_BYTE_LIMIT) return failure();
  indexRegistryJson(raw);
  return snapshotRegistryRequest(JSON.parse(raw));
}
export function buildRegistryRequest(
  registry: RegistryName,
  target: Record<string, string>,
  scopeLabel = "",
): RegistryRequest {
  return snapshotRegistryRequest({
    registry,
    target,
    scope_label: scopeLabel || null,
  });
}
export interface RegistryResponse {
  readonly result: RegistryResult;
  readonly rawJson: string;
  readonly observationJson: readonly string[];
  readonly nativeFieldsJson: readonly string[];
}

export function parseRegistryResponse(
  rawJson: string,
  request: unknown,
): RegistryResponse {
  try {
    const expected = snapshotRegistryRequest(request);
    const spans = indexRegistryJson(rawJson);
    const value: unknown = JSON.parse(rawJson);
    if (!matches(value, RESULT_SCHEMA, [], spans)) return failure();
    const result = value as RegistryResult;
    if (
      result.registry !== expected.registry ||
      !same(snapshotRegistryRequest(result.request), expected)
    )
      return failure();
    const observations = result.observations;
    const reads = result.source_reads;
    applicationClock(result.manifest.collection_started_at);
    applicationClock(result.manifest.collection_finished_at);
    if (
      result.manifest.collection_finished_at <
      result.manifest.collection_started_at
    )
      return failure();
    for (const finding of result.findings) {
      applicationClock(finding.collection_context.collected_at);
      applicationClock(finding.first_observed);
      applicationClock(finding.last_observed);
    }
    for (const read of reads) applicationClock(read.retrieved_at);
    for (const observation of observations)
      for (const stamp of observation.source_times) {
        if (stamp.normalized_utc !== null)
          applicationClock(stamp.normalized_utc);
      }
    for (const [field, maximum] of [
      ["network_attempts", 64],
      ["accepted_pages", 20],
      ["admitted_records", 100],
    ] as const) {
      if (reads.reduce((total, read) => total + read[field], 0) > maximum)
        return failure();
    }
    for (const field of ["raw_bytes", "decoded_bytes"] as const) {
      if (
        reads
          .filter((read) => read.transport_kind === "https")
          .reduce((total, read) => total + (read[field] ?? 0), 0) > 8_388_608
      )
        return failure();
    }
    const observedCounts = new Map<string, number>();
    for (const observation of observations)
      observedCounts.set(
        observation.source_read_id,
        (observedCounts.get(observation.source_read_id) ?? 0) + 1,
      );
    if (
      reads.some(
        (read) =>
          read.admitted_records !== (observedCounts.get(read.read_id) ?? 0),
      )
    )
      return failure();
    const filters = {
      request: expected,
      observation_scope: "selected_registry_query",
    };
    if (
      !same(result.manifest.filters_applied, filters) ||
      result.manifest.run_id !== result.run_id ||
      result.manifest.total_findings !== result.findings.length ||
      result.findings.length !== observations.length
    )
      return failure();
    if (
      result.manifest.is_complete !==
        (result.collection_status === "complete") ||
      result.manifest.incomplete_reason !==
        (result.collection_status === "complete"
          ? null
          : "selected_query_incomplete")
    )
      return failure();
    if (
      (observations.length === 0) !==
      ["not_found", "unavailable"].includes(result.lookup_outcome)
    )
      return failure();
    if (
      result.lookup_outcome === "not_found" &&
      result.collection_status !== "complete"
    )
      return failure();
    if (
      (result.collection_status === "unavailable") !==
      (result.lookup_outcome === "unavailable")
    )
      return failure();
    const ids = new Set(reads.map((read) => read.read_id));
    if (
      ids.size !== reads.length ||
      new Set(observations.map((observation) => observation.observation_id))
        .size !== observations.length
    )
      return failure();
    for (const [index, read] of reads.entries()) {
      if (
        read.ordinal !== index ||
        read.registry !== result.registry ||
        !same(read.query_scope, expected) ||
        read.accepted_pages > read.attempted_pages ||
        read.admitted_records > read.source_records
      )
        return failure();
      if (!read.body_complete && read.source_digest !== null) return failure();
    }
    if (
      result.diagnostics.some(
        (item) =>
          item.source_read_id !== null &&
          item.source_read_id !== undefined &&
          !ids.has(item.source_read_id),
      )
    )
      return failure();
    const count = result.manifest.coverage_counts[0];
    for (const number of [count.scanned, count.matched_filter, count.collected])
      if (!Number.isSafeInteger(number) || number < 0 || number > 1_200_000)
        return failure();
    if (count.collected !== observations.length) return failure();
    let total = 0;
    const observationJson: string[] = [];
    const nativeFieldsJson: string[] = [];
    for (const [index, observation] of observations.entries()) {
      const read = reads.find(
        (item) => item.read_id === observation.source_read_id,
      );
      if (
        !read ||
        observation.registry !== result.registry ||
        observation.trust.transport_verified !== read.transport_verified ||
        observation.trust.source_signature !== read.source_signature
      )
        return failure();
      if (
        result.registry === "incommon" &&
        observation.trust.source_signature !== "verified"
      )
        return failure();
      const canonical = spans.get("observation:" + index);
      if (!canonical || canonical !== spans.get("finding-observation:" + index))
        return failure();
      total += size(canonical);
      if (total > 2_097_152) return failure();
      const finding = result.findings[index];
      if (
        finding.source_finding_id !== observation.observation_id ||
        finding.collection_context.run_id !== result.run_id ||
        !same(finding.collection_context.filter_applied, filters)
      )
        return failure();
      observationJson.push(
        spans.get("value:" + JSON.stringify(["observations", index]))!,
      );
      nativeFieldsJson.push(
        spans.get(
          "value:" + JSON.stringify(["observations", index, "fields"]),
        )!,
      );
    }
    return Object.freeze({
      result: freeze(result),
      rawJson,
      observationJson: Object.freeze(observationJson),
      nativeFieldsJson: Object.freeze(nativeFieldsJson),
    });
  } catch {
    return failure();
  }
}

export function boundedRegistryPreview(
  value: string,
  maximum = 16_384,
): string {
  if (size(value) <= maximum) return value;
  let kept = "";
  let bytes = 0;
  for (const character of value) {
    const next = size(character);
    if (bytes + next > maximum) break;
    kept += character;
    bytes += next;
  }
  return kept;
}

/** Read actual UTF-8 bytes, independent of Content-Length, with prompt cancellation on refusal. */
export async function readRegistryResponse(
  response: Response,
  expected: unknown,
): Promise<RegistryResponse> {
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
      if (size > REGISTRY_RESULT_BYTE_LIMIT) return failure();
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
    return parseRegistryResponse(text, expected);
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
