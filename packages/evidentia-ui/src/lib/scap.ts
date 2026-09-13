import type { components } from "@/types/openapi";

export const SCAP_PROFILES = [
  "xccdf-1.2-results",
  "oval-5.8-core-results",
  "oval-5.11.2-core-results",
  "oval-5.12.3-core-results",
] as const;
export type ScapProfile = (typeof SCAP_PROFILES)[number];
export type ScapResult = components["schemas"]["ScapCollectionResult"];
export type ScapCompletionAssertion = Pick<
  components["schemas"]["StableCompletionAssertion"],
  | "schema_version"
  | "source_sha256"
  | "source_profile"
  | "assessment_index"
  | "completed_at"
  | "reference"
>;
export interface ScapRequest {
  source_profile: ScapProfile;
  assessment_index: number;
  cadence_slug: string | null;
  completion_assertion: ScapCompletionAssertion | null;
}
export interface ScapExpected {
  readonly request: Readonly<ScapRequest>;
  readonly sourceSha256: string;
  readonly sourceBytes: number;
}
export interface ScapResponse {
  readonly result: ScapResult;
  readonly rawJson: string;
  readonly artifactRawJson: string | null;
}
export const SCAP_SOURCE_BYTES = 8_388_608;
export const SCAP_RESULT_BYTES = 16_777_216;
export const SCAP_ASSERTION_BYTES = 2_048;
const NATIVE_BYTES = 5_242_880;
const ASSESSMENT_BYTES = 2_097_152;
const REMAINDER_BYTES = 524_288;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };
interface Schema {
  $ref?: string;
  type?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: boolean | Schema;
  items?: Schema;
  oneOf?: Schema[];
  anyOf?: Schema[];
  allOf?: Schema[];
  const?: Json;
  enum?: Json[];
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  ge?: number;
  le?: number;
  minimum?: number;
  maximum?: number;
  discriminator?: { propertyName: string; mapping: Record<string, string> };
}
export class ScapResponseError extends Error {
  constructor() {
    super(
      "The SCAP input or response is invalid or does not match the selected source.",
    );
    this.name = "ScapResponseError";
  }
}
const fail = (): never => {
  throw new ScapResponseError();
};
const ensure: (condition: unknown) => asserts condition = (condition) => {
  if (!condition) fail();
};
const own = (value: object, key: PropertyKey) =>
  Object.prototype.hasOwnProperty.call(value, key);
const object = (value: unknown): value is Obj =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const encoder = new TextEncoder();
const utf8 = (value: string) => encoder.encode(value).byteLength;
function unicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = value.charCodeAt(++i);
      ensure(d >= 0xdc00 && d <= 0xdfff);
    } else ensure(c < 0xdc00 || c > 0xdfff);
  }
}
function asciiString(value: string): string {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}
function canonical(
  value: Json,
  spaced = false,
  limit = SCAP_RESULT_BYTES,
): string {
  let charged = 0;
  const take = (bytes: number) => {
    charged += bytes;
    ensure(charged <= limit);
  };
  const text = (item: string) => {
    take(2);
    for (let i = 0; i < item.length; i++) {
      const c = item.charCodeAt(i);
      take(
        c >= 127 || (c < 32 && ![8, 9, 10, 12, 13].includes(c))
          ? 6
          : c < 32 || c === 34 || c === 92
            ? 2
            : 1,
      );
    }
    return asciiString(item);
  };
  const visit = (item: Json): string => {
    if (typeof item === "string") return text(item);
    if (item === null || typeof item !== "object") {
      const scalar = JSON.stringify(item);
      take(scalar.length);
      return scalar;
    }
    const comma = spaced ? ", " : ",";
    take(2);
    if (Array.isArray(item)) {
      take(Math.max(0, item.length - 1) * comma.length);
      return "[" + item.map(visit).join(comma) + "]";
    }
    const keys = Object.keys(item).sort();
    take(
      Math.max(0, keys.length - 1) * comma.length +
        keys.length * (spaced ? 2 : 1),
    );
    return (
      "{" +
      keys
        .map((key) => text(key) + (spaced ? ": " : ":") + visit(item[key]))
        .join(comma) +
      "}"
    );
  };
  return visit(value);
}
const same = (a: unknown, b: unknown) =>
  canonical(a as Json) === canonical(b as Json);
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// Only this bounded owned clone is used after native ingress. Caller descriptors
// are inspected without invoking getters, toJSON or inherited callbacks.
function clone(value: unknown, limit = SCAP_ASSERTION_BYTES): Json {
  let count = 0;
  let charged = 0;
  const active = new Set<object>();
  function visit(item: unknown, depth: number): Json {
    ensure(++count <= limit && depth <= 32);
    if (item === null || typeof item === "boolean") {
      charged += item === null ? 4 : item ? 4 : 5;
      ensure(charged <= limit);
      return item;
    }
    if (typeof item === "number") {
      ensure(Number.isSafeInteger(item) && !Object.is(item, -0));
      charged += String(item).length;
      ensure(charged <= limit);
      return item;
    }
    if (typeof item === "string") {
      ensure(item.length <= limit && utf8(item) <= limit);
      unicode(item);
      charged += asciiString(item).length;
      ensure(charged <= limit);
      return item;
    }
    ensure(typeof item === "object" && item !== null && !active.has(item));
    const array = Array.isArray(item);
    const proto = Object.getPrototypeOf(item);
    ensure(
      array
        ? proto === Array.prototype
        : proto === Object.prototype || proto === null,
    );
    const keys = Reflect.ownKeys(item);
    ensure(keys.length <= (array ? 32769 : 128));
    active.add(item);
    charged += 2;
    ensure(charged <= limit);
    const result: Json[] | Obj = array ? [] : (Object.create(null) as Obj);
    let index = 0;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      ensure(descriptor && own(descriptor, "value"));
      if (array && key === "length") {
        ensure(descriptor.value === keys.length - 1);
        continue;
      }
      ensure(typeof key === "string" && descriptor.enumerable);
      if (array) ensure(key === String(index));
      else {
        unicode(key);
        charged += asciiString(key).length + 1;
      }
      if (index++) charged++;
      ensure(charged <= limit);
      const child = visit(descriptor.value, depth + 1);
      if (Array.isArray(result)) result.push(child);
      else result[key] = child;
    }
    active.delete(item);
    return result;
  }
  return visit(value, 0);
}

interface Parsed {
  value: Json;
  artifactSpan: readonly [number, number] | null;
}
function parse(input: unknown, limit: number): Parsed {
  ensure(
    typeof input === "string" && input.length <= limit && utf8(input) <= limit,
  );
  const raw: string = input;
  unicode(raw);
  let cursor = 0;
  let values = 0;
  let artifactSpan: readonly [number, number] | null = null;
  const whitespace = () => {
    while (cursor < raw.length && /[ \r\n\t]/.test(raw[cursor])) cursor++;
  };
  function string(): string {
    ensure(raw[cursor] === '"');
    const begin = cursor++;
    while (cursor < raw.length) {
      const c = raw.charCodeAt(cursor++);
      if (c === 34) {
        const result: unknown = JSON.parse(raw.slice(begin, cursor));
        ensure(typeof result === "string");
        unicode(result);
        ensure(utf8(result) <= 262144);
        return result;
      }
      ensure(c >= 32);
      if (c === 92) {
        const escaped = raw[cursor++];
        ensure(escaped !== undefined && '"\\/bfnrtu'.includes(escaped));
        if (escaped === "u") {
          ensure(/^[0-9a-fA-F]{4}$/.test(raw.slice(cursor, cursor + 4)));
          cursor += 4;
        }
      }
    }
    return fail();
  }
  function value(depth: number): Json {
    whitespace();
    ensure(depth <= 32 && ++values <= Math.ceil(limit / 2));
    const c = raw[cursor];
    if (c === '"') return string();
    if (c === "{" || c === "[") {
      const array = c === "[";
      cursor++;
      whitespace();
      const result: Obj | Json[] = array ? [] : (Object.create(null) as Obj);
      const end = array ? "]" : "}";
      if (raw[cursor] === end) {
        cursor++;
        return result;
      }
      let n = 0;
      while (true) {
        ensure(++n <= (array ? 32768 : 128));
        let key = "";
        if (!array) {
          whitespace();
          key = string();
          ensure(!own(result, key));
          whitespace();
          ensure(raw[cursor++] === ":");
        }
        whitespace();
        const begin = cursor;
        const child = value(depth + 1);
        if (array) (result as Json[]).push(child);
        else (result as Obj)[key] = child;
        if (depth === 0 && key === "evidence_artifact")
          artifactSpan = [begin, cursor];
        whitespace();
        const separator = raw[cursor++];
        if (separator === end) break;
        ensure(separator === ",");
      }
      return result;
    }
    for (const [word, result] of [
      ["null", null],
      ["true", true],
      ["false", false],
    ] as const) {
      if (raw.startsWith(word, cursor)) {
        cursor += word.length;
        return result;
      }
    }
    const begin = cursor;
    if (raw[cursor] === "-") cursor++;
    if (raw[cursor] === "0") cursor++;
    else {
      ensure(/[1-9]/.test(raw[cursor] ?? ""));
      while (/[0-9]/.test(raw[cursor] ?? "")) cursor++;
    }
    const result = Number(raw.slice(begin, cursor));
    ensure(Number.isSafeInteger(result) && !Object.is(result, -0));
    return result;
  }
  try {
    const result = value(0);
    whitespace();
    ensure(cursor === raw.length);
    return { value: result, artifactSpan };
  } catch (error) {
    if (error instanceof ScapResponseError) throw error;
    return fail();
  }
}
export function parseScapJson(
  raw: unknown,
  limit = SCAP_RESULT_BYTES,
): unknown {
  ensure(
    Number.isSafeInteger(limit) && limit >= 1 && limit <= SCAP_RESULT_BYTES,
  );
  return freeze(parse(raw, limit).value);
}

// Exact validation projection of the accepted SCAP OpenAPI components.
// Annotation removal does not remove numeric ge/le or source patterns.
export const SCAP_RESPONSE_SCHEMAS: Readonly<Record<string, Schema>> = freeze({
  ArtifactAvailability: {
    additionalProperties: false,
    properties: {
      reasons: {
        items: {
          enum: [
            "native_completion_absent",
            "native_completion_timezone_missing",
            "native_completion_precision_unsupported",
            "native_completion_range_unsupported",
            "native_completion_normalization_unsupported",
            "native_completion_future",
            "native_start_unresolved",
            "native_completion_before_start",
          ],
          type: "string",
        },
        maxItems: 8,
        minItems: 0,
        type: "array",
      },
      state: {
        enum: ["available", "unavailable"],
        type: "string",
      },
    },
    required: ["state", "reasons"],
    type: "object",
  },
  AssertionActor: {
    additionalProperties: false,
    properties: {
      basis: {
        enum: ["caller_declared", "api_authenticated"],
        type: "string",
      },
      provider: {
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
      subject: {
        maxLength: 128,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
    },
    required: ["basis", "subject", "provider"],
    type: "object",
  },
  AssessmentProjection: {
    additionalProperties: false,
    properties: {
      coverage: {
        $ref: "#/components/schemas/CoverageProjection",
      },
      finding_refs: {
        items: {
          $ref: "#/components/schemas/FindingReference",
        },
        maxItems: 1,
        minItems: 1,
        type: "array",
      },
      outcomes: {
        items: {
          $ref: "#/components/schemas/OutcomeOccurrence",
        },
        maxItems: 10000,
        minItems: 0,
        type: "array",
      },
      selection: {
        $ref: "#/components/schemas/AssessmentSelection",
      },
      times: {
        items: {
          $ref: "#/components/schemas/SourceTimeObservation",
        },
        maxItems: 10000,
        minItems: 0,
        type: "array",
      },
      uninterpreted_roots: {
        items: {
          ge: 0,
          le: 32767,
          type: "integer",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      units: {
        items: {
          $ref: "#/components/schemas/AssessmentUnit",
        },
        maxItems: 256,
        minItems: 1,
        type: "array",
      },
    },
    required: [
      "selection",
      "units",
      "outcomes",
      "times",
      "coverage",
      "uninterpreted_roots",
      "finding_refs",
    ],
    type: "object",
  },
  AssessmentSelection: {
    additionalProperties: false,
    properties: {
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      unit_kind: {
        enum: ["xccdf_test_result", "oval_system"],
        type: "string",
      },
    },
    required: ["assessment_index", "unit_kind", "node_index"],
    type: "object",
  },
  AssessmentUnit: {
    additionalProperties: false,
    properties: {
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      unit_kind: {
        enum: ["xccdf_test_result", "oval_system"],
        type: "string",
      },
    },
    required: ["assessment_index", "unit_kind", "node_index"],
    type: "object",
  },
  CadenceProjection: {
    additionalProperties: false,
    properties: {
      linked_slug: {
        anyOf: [
          {
            maxLength: 256,
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
      reasons: {
        items: {
          anyOf: [
            {
              enum: [
                "native_completion_absent",
                "native_completion_timezone_missing",
                "native_completion_precision_unsupported",
                "native_completion_range_unsupported",
                "native_completion_normalization_unsupported",
                "native_completion_future",
                "native_start_unresolved",
                "native_completion_before_start",
              ],
              type: "string",
            },
            {
              enum: [
                "no_selected_outcome_evidence",
                "selected_outcomes_not_evaluated",
              ],
              type: "string",
            },
          ],
        },
        maxItems: 10,
        minItems: 0,
        type: "array",
      },
      requested_slug: {
        anyOf: [
          {
            maxLength: 256,
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
      state: {
        enum: ["not_requested", "linked", "ineligible"],
        type: "string",
      },
    },
    required: ["state", "requested_slug", "linked_slug", "reasons"],
    type: "object",
  },
  ClassDirectives: {
    additionalProperties: false,
    properties: {
      class_ref: {
        $ref: "#/components/schemas/NativeValueRef",
      },
      definition_class: {
        enum: [
          "compliance",
          "inventory",
          "miscellaneous",
          "patch",
          "vulnerability",
        ],
        type: "string",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      rules: {
        items: {
          $ref: "#/components/schemas/DirectiveRule",
        },
        maxItems: 6,
        minItems: 6,
        type: "array",
      },
    },
    required: ["node_index", "class_ref", "definition_class", "rules"],
    type: "object",
  },
  CompletionProjection: {
    additionalProperties: false,
    properties: {
      assertion: {
        anyOf: [
          {
            $ref: "#/components/schemas/StableCompletionAssertion",
          },
          {
            type: "null",
          },
        ],
      },
      basis: {
        enum: ["native_reported", "operator_asserted", "none"],
        type: "string",
      },
      native_ref: {
        anyOf: [
          {
            $ref: "#/components/schemas/NativeValueRef",
          },
          {
            type: "null",
          },
        ],
      },
      qualification_reasons: {
        items: {
          enum: [
            "native_completion_absent",
            "native_completion_timezone_missing",
            "native_completion_precision_unsupported",
            "native_completion_range_unsupported",
            "native_completion_normalization_unsupported",
            "native_completion_future",
            "native_start_unresolved",
            "native_completion_before_start",
          ],
          type: "string",
        },
        maxItems: 8,
        minItems: 0,
        type: "array",
      },
      state: {
        enum: ["native_qualified", "operator_qualified", "unqualified"],
        type: "string",
      },
      utc: {
        anyOf: [
          {
            pattern:
              "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
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
      "basis",
      "utc",
      "native_ref",
      "assertion",
      "qualification_reasons",
    ],
    type: "object",
  },
  CoreStatusDefault: {
    additionalProperties: false,
    properties: {
      effective_status: {
        enum: ["error", "exists", "does not exist", "not collected"],
        type: "string",
      },
      interpretation: {
        const: "reviewed_5_8_core_ip_address_status",
        type: "string",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      present: {
        type: "boolean",
      },
      value_ref: {
        anyOf: [
          {
            $ref: "#/components/schemas/NativeValueRef",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: [
      "node_index",
      "present",
      "value_ref",
      "effective_status",
      "interpretation",
    ],
    type: "object",
  },
  CoverageProjection: {
    additionalProperties: false,
    properties: {
      cadence_evidence: {
        enum: ["countable", "empty", "not_evaluated"],
        type: "string",
      },
      collection_flags: {
        items: {
          $ref: "#/components/schemas/NativeCollectionFlag",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      complete_schema_validation: {
        const: "not_performed",
        type: "string",
      },
      core_status_defaults: {
        items: {
          $ref: "#/components/schemas/CoreStatusDefault",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      countable_top_level_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      native_export_detail: {
        enum: ["not_applicable", "full", "thin", "mixed", "no_reported_rules"],
        type: "string",
      },
      outcome_counts: {
        items: {
          $ref: "#/components/schemas/OutcomeCountRow",
        },
        maxItems: 36,
        minItems: 9,
        type: "array",
      },
      oval_directives: {
        anyOf: [
          {
            $ref: "#/components/schemas/OvalDirectiveProjection",
          },
          {
            type: "null",
          },
        ],
      },
      platform_validation: {
        const: "not_performed",
        type: "string",
      },
      producer_interoperability: {
        const: "not_established",
        type: "string",
      },
      schema_validation: {
        const: "bounded_core_profile_rules",
        type: "string",
      },
      scope: {
        const: "selected_assessment_native_projection",
        type: "string",
      },
      selected_node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      selected_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      selected_unit_count: {
        const: 1,
        type: "integer",
      },
      signature_node_indices: {
        items: {
          ge: 0,
          le: 32767,
          type: "integer",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      signature_verification: {
        const: "not_performed",
        type: "string",
      },
      source_population_complete: {
        const: "not_established",
        type: "string",
      },
      status_observations: {
        items: {
          $ref: "#/components/schemas/UnverifiedPlatformStatus",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      top_level_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      uninterpreted_node_count: {
        ge: 0,
        le: 32768,
        type: "integer",
      },
      unselected_unit_count: {
        ge: 0,
        le: 256,
        type: "integer",
      },
      visible_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      visible_unit_count: {
        ge: 0,
        le: 256,
        type: "integer",
      },
    },
    required: [
      "scope",
      "selected_node_index",
      "visible_unit_count",
      "selected_unit_count",
      "unselected_unit_count",
      "visible_outcome_count",
      "selected_outcome_count",
      "top_level_outcome_count",
      "countable_top_level_outcome_count",
      "outcome_counts",
      "native_export_detail",
      "oval_directives",
      "collection_flags",
      "uninterpreted_node_count",
      "signature_node_indices",
      "source_population_complete",
      "schema_validation",
      "complete_schema_validation",
      "platform_validation",
      "signature_verification",
      "producer_interoperability",
      "cadence_evidence",
      "status_observations",
      "core_status_defaults",
    ],
    type: "object",
  },
  DefaultedBoolean: {
    additionalProperties: false,
    properties: {
      effective_value: {
        type: "boolean",
      },
      present: {
        type: "boolean",
      },
      value_ref: {
        anyOf: [
          {
            $ref: "#/components/schemas/NativeValueRef",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["present", "value_ref", "effective_value"],
    type: "object",
  },
  DefaultedContent: {
    additionalProperties: false,
    properties: {
      effective_value: {
        enum: ["full", "thin"],
        type: "string",
      },
      present: {
        type: "boolean",
      },
      value_ref: {
        anyOf: [
          {
            $ref: "#/components/schemas/NativeValueRef",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["present", "value_ref", "effective_value"],
    type: "object",
  },
  DirectiveRule: {
    additionalProperties: false,
    properties: {
      content: {
        $ref: "#/components/schemas/DefaultedContent",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      outcome: {
        enum: [
          "true",
          "false",
          "unknown",
          "error",
          "not evaluated",
          "not applicable",
        ],
        type: "string",
      },
      reported: {
        $ref: "#/components/schemas/DefaultedBoolean",
      },
    },
    required: ["node_index", "outcome", "reported", "content"],
    type: "object",
  },
  ExpandedName: {
    additionalProperties: false,
    properties: {
      local_name: {
        maxLength: 256,
        minLength: 1,
        type: "string",
      },
      namespace_uri: {
        maxLength: 2048,
        minLength: 0,
        type: "string",
      },
    },
    required: ["namespace_uri", "local_name"],
    type: "object",
  },
  FindingReference: {
    additionalProperties: false,
    properties: {
      finding_id: {
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        type: "string",
      },
      mapping_rule_id: {
        const: "scap-assessment-summary-v1",
        type: "string",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      source_key_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: [
      "node_index",
      "mapping_rule_id",
      "source_key_sha256",
      "finding_id",
    ],
    type: "object",
  },
  LinkedArtifactMetadata: {
    additionalProperties: false,
    properties: {
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      cadence_slug: {
        maxLength: 256,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      scap_contract: {
        const: "scap-evidence-v1",
        type: "string",
      },
      source_profile: {
        enum: [
          "xccdf-1.2-results",
          "oval-5.8-core-results",
          "oval-5.11.2-core-results",
          "oval-5.12.3-core-results",
        ],
        type: "string",
      },
      source_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      time_basis: {
        enum: ["native_reported", "operator_asserted"],
        type: "string",
      },
    },
    required: [
      "scap_contract",
      "source_sha256",
      "source_profile",
      "assessment_index",
      "time_basis",
      "cadence_slug",
    ],
    type: "object",
  },
  NamespaceDeclaration: {
    additionalProperties: false,
    properties: {
      namespace_uri: {
        maxLength: 2048,
        minLength: 0,
        type: "string",
      },
      prefix: {
        maxLength: 128,
        minLength: 0,
        type: "string",
      },
    },
    required: ["prefix", "namespace_uri"],
    type: "object",
  },
  NativeCollectionFlag: {
    additionalProperties: false,
    properties: {
      native_flag: {
        enum: [
          "error",
          "complete",
          "incomplete",
          "does not exist",
          "not collected",
          "not applicable",
        ],
        type: "string",
      },
      object_node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      value_ref: {
        $ref: "#/components/schemas/NativeValueRef",
      },
    },
    required: ["object_node_index", "value_ref", "native_flag"],
    type: "object",
  },
  NativeDocument: {
    additionalProperties: false,
    properties: {
      children: {
        items: {
          ge: 0,
          le: 32767,
          type: "integer",
        },
        maxItems: 32768,
        minItems: 1,
        type: "array",
      },
      declaration: {
        anyOf: [
          {
            $ref: "#/components/schemas/XmlDeclaration",
          },
          {
            type: "null",
          },
        ],
      },
      nodes: {
        items: {
          discriminator: {
            mapping: {
              comment: "#/components/schemas/XmlComment",
              element: "#/components/schemas/XmlElement",
              processing_instruction: "#/components/schemas/XmlPI",
            },
            propertyName: "kind",
          },
          oneOf: [
            {
              $ref: "#/components/schemas/XmlElement",
            },
            {
              $ref: "#/components/schemas/XmlComment",
            },
            {
              $ref: "#/components/schemas/XmlPI",
            },
          ],
        },
        maxItems: 32768,
        minItems: 1,
        type: "array",
      },
      text: {
        anyOf: [
          {
            maxLength: 262144,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["declaration", "text", "children", "nodes"],
    type: "object",
  },
  NativeValueRef: {
    additionalProperties: false,
    properties: {
      attribute_index: {
        anyOf: [
          {
            ge: 0,
            le: 63,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      slot: {
        enum: ["text", "attribute_value", "element_simple_content"],
        type: "string",
      },
    },
    required: ["node_index", "slot", "attribute_index"],
    type: "object",
  },
  NormalizedSourceTime: {
    additionalProperties: false,
    properties: {
      state: {
        enum: [
          "normalized",
          "timezone_missing",
          "precision_unsupported",
          "range_unsupported",
          "normalization_unsupported",
        ],
        type: "string",
      },
      utc: {
        anyOf: [
          {
            pattern:
              "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["state", "utc"],
    type: "object",
  },
  OutcomeCountRow: {
    additionalProperties: false,
    properties: {
      count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      level: {
        enum: [
          "xccdf_rule_result",
          "oval_definition",
          "oval_criteria",
          "oval_criterion",
          "oval_extend_definition",
          "oval_test",
          "oval_tested_item",
        ],
        type: "string",
      },
      native_result: {
        enum: [
          "pass",
          "fail",
          "error",
          "unknown",
          "notapplicable",
          "informational",
          "fixed",
          "notchecked",
          "notselected",
          "true",
          "false",
          "not evaluated",
          "not applicable",
        ],
        type: "string",
      },
    },
    required: ["level", "native_result", "count"],
    type: "object",
  },
  OutcomeOccurrence: {
    additionalProperties: false,
    properties: {
      level: {
        enum: [
          "xccdf_rule_result",
          "oval_definition",
          "oval_criteria",
          "oval_criterion",
          "oval_extend_definition",
          "oval_test",
          "oval_tested_item",
        ],
        type: "string",
      },
      native_result: {
        enum: [
          "pass",
          "fail",
          "error",
          "unknown",
          "notapplicable",
          "informational",
          "fixed",
          "notchecked",
          "notselected",
          "true",
          "false",
          "not evaluated",
          "not applicable",
        ],
        type: "string",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      unit_node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      value_ref: {
        $ref: "#/components/schemas/NativeValueRef",
      },
    },
    required: [
      "unit_node_index",
      "node_index",
      "level",
      "value_ref",
      "native_result",
    ],
    type: "object",
  },
  OvalDirectiveProjection: {
    additionalProperties: false,
    properties: {
      class_rules: {
        items: {
          $ref: "#/components/schemas/ClassDirectives",
        },
        maxItems: 5,
        minItems: 0,
        type: "array",
      },
      default_rules: {
        items: {
          $ref: "#/components/schemas/DirectiveRule",
        },
        maxItems: 6,
        minItems: 6,
        type: "array",
      },
      embedded_definitions_node_index: {
        anyOf: [
          {
            ge: 0,
            le: 32767,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
      },
      include_source_definitions: {
        $ref: "#/components/schemas/DefaultedBoolean",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
    },
    required: [
      "node_index",
      "include_source_definitions",
      "embedded_definitions_node_index",
      "default_rules",
      "class_rules",
    ],
    type: "object",
  },
  ScapAssessmentSummary: {
    additionalProperties: false,
    properties: {
      countable_top_level_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      schema_version: {
        const: "scap-assessment-summary-v1",
        type: "string",
      },
      selected_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      selection: {
        $ref: "#/components/schemas/AssessmentSelection",
      },
      source: {
        $ref: "#/components/schemas/SourceBinding",
      },
      source_key_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      summary_only: {
        const: true,
        type: "boolean",
      },
      top_level_outcome_count: {
        ge: 0,
        le: 10000,
        type: "integer",
      },
      visible_unit_count: {
        ge: 0,
        le: 256,
        type: "integer",
      },
    },
    required: [
      "schema_version",
      "source",
      "selection",
      "visible_unit_count",
      "selected_outcome_count",
      "top_level_outcome_count",
      "countable_top_level_outcome_count",
      "summary_only",
      "source_key_sha256",
    ],
    type: "object",
  },
  ScapCollectionContext: {
    additionalProperties: false,
    properties: {
      collected_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      collector_id: {
        const: "scap",
        type: "string",
      },
      collector_version: {
        maxLength: 64,
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
        maxLength: 64,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      filter_applied: {
        $ref: "#/components/schemas/ScapImportFilter",
      },
      pagination_context: {
        type: "null",
      },
      run_id: {
        pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        type: "string",
      },
      source_system_id: {
        pattern: "^scap-source:[0-9a-f]{64}$",
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
  ScapCollectionManifest: {
    additionalProperties: false,
    properties: {
      collection_finished_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      collection_started_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      collector_id: {
        const: "scap",
        type: "string",
      },
      collector_version: {
        maxLength: 64,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      coverage_counts: {
        items: {
          $ref: "#/components/schemas/ScapCoverageCount",
        },
        maxItems: 1,
        minItems: 1,
        type: "array",
      },
      empty_categories: {
        items: {
          type: "null",
        },
        maxItems: 0,
        minItems: 0,
        type: "array",
      },
      errors: {
        items: {
          type: "null",
        },
        maxItems: 0,
        minItems: 0,
        type: "array",
      },
      evidentia_version: {
        maxLength: 64,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      filters_applied: {
        $ref: "#/components/schemas/ScapImportFilter",
      },
      incomplete_reason: {
        type: "null",
      },
      is_complete: {
        const: true,
        type: "boolean",
      },
      run_id: {
        pattern: "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        type: "string",
      },
      source_system_ids: {
        items: {
          pattern: "^scap-source:[0-9a-f]{64}$",
          type: "string",
        },
        maxItems: 1,
        minItems: 1,
        type: "array",
      },
      total_findings: {
        const: 1,
        type: "integer",
      },
      warnings: {
        items: {
          enum: [
            "Source authenticity was not verified.",
            "The source does not establish complete scanner population coverage.",
            "Complete schema validation was not performed.",
            "OVAL platform validation was not performed.",
            "The finding summarizes one selected assessment; native outcomes are retained separately.",
            "A source signature is present and was not verified.",
            "The declared OVAL export detail includes thin output.",
            "Native content outside the interpreted core is preserved.",
            "Assessment completion is an explicit operator assertion.",
            "No native assessment completion time is available.",
            "The native completion time has no timezone.",
            "The native completion precision cannot be represented exactly.",
            "The native completion time is outside the supported range.",
            "The native completion time cannot be normalized under the admitted policy.",
            "The native completion is later than the import start.",
            "The native assessment start cannot be compared exactly.",
            "The native completion precedes the native assessment start.",
            "The selected assessment contains no top-level outcome evidence.",
            "The selected assessment contains only unevaluated top-level outcomes.",
          ],
          type: "string",
        },
        maxItems: 19,
        minItems: 0,
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
  ScapCollectionResult: {
    additionalProperties: false,
    properties: {
      artifact_availability: {
        $ref: "#/components/schemas/ArtifactAvailability",
      },
      assessment: {
        $ref: "#/components/schemas/AssessmentProjection",
      },
      cadence: {
        $ref: "#/components/schemas/CadenceProjection",
      },
      completion: {
        $ref: "#/components/schemas/CompletionProjection",
      },
      diagnostics: {
        items: {
          $ref: "#/components/schemas/ScapDiagnostic",
        },
        maxItems: 19,
        minItems: 0,
        type: "array",
      },
      evidence_artifact: {
        anyOf: [
          {
            $ref: "#/components/schemas/ScapEvidenceArtifact",
          },
          {
            type: "null",
          },
        ],
      },
      findings: {
        items: {
          $ref: "#/components/schemas/ScapSecurityFinding",
        },
        maxItems: 1,
        minItems: 1,
        type: "array",
      },
      imported_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      manifest: {
        $ref: "#/components/schemas/ScapCollectionManifest",
      },
      native_document: {
        $ref: "#/components/schemas/NativeDocument",
      },
      schema_version: {
        const: "scap-collection-v1",
        type: "string",
      },
      source: {
        $ref: "#/components/schemas/SourceBinding",
      },
      status: {
        const: "imported",
        type: "string",
      },
    },
    required: [
      "schema_version",
      "status",
      "source",
      "imported_at",
      "native_document",
      "assessment",
      "findings",
      "manifest",
      "completion",
      "evidence_artifact",
      "artifact_availability",
      "cadence",
      "diagnostics",
    ],
    type: "object",
  },
  ScapCoverageCount: {
    additionalProperties: false,
    properties: {
      collected: {
        const: 1,
        type: "integer",
      },
      matched_filter: {
        const: 1,
        type: "integer",
      },
      resource_type: {
        const: "scap-assessment-occurrence",
        type: "string",
      },
      scanned: {
        ge: 0,
        le: 256,
        type: "integer",
      },
    },
    required: ["resource_type", "scanned", "matched_filter", "collected"],
    type: "object",
  },
  ScapDiagnostic: {
    additionalProperties: false,
    properties: {
      code: {
        enum: [
          "source_authenticity_unverified",
          "source_population_not_established",
          "complete_schema_validation_not_performed",
          "platform_validation_not_performed",
          "findings_are_summary_only",
          "signature_unverified",
          "partial_export_detail",
          "uninterpreted_content_preserved",
          "operator_completion_asserted",
          "native_completion_absent",
          "native_completion_timezone_missing",
          "native_completion_precision_unsupported",
          "native_completion_range_unsupported",
          "native_completion_normalization_unsupported",
          "native_completion_future",
          "native_start_unresolved",
          "native_completion_before_start",
          "no_selected_outcome_evidence",
          "selected_outcomes_not_evaluated",
        ],
        type: "string",
      },
      message: {
        enum: [
          "Source authenticity was not verified.",
          "The source does not establish complete scanner population coverage.",
          "Complete schema validation was not performed.",
          "OVAL platform validation was not performed.",
          "The finding summarizes one selected assessment; native outcomes are retained separately.",
          "A source signature is present and was not verified.",
          "The declared OVAL export detail includes thin output.",
          "Native content outside the interpreted core is preserved.",
          "Assessment completion is an explicit operator assertion.",
          "No native assessment completion time is available.",
          "The native completion time has no timezone.",
          "The native completion precision cannot be represented exactly.",
          "The native completion time is outside the supported range.",
          "The native completion time cannot be normalized under the admitted policy.",
          "The native completion is later than the import start.",
          "The native assessment start cannot be compared exactly.",
          "The native completion precedes the native assessment start.",
          "The selected assessment contains no top-level outcome evidence.",
          "The selected assessment contains only unevaluated top-level outcomes.",
        ],
        type: "string",
      },
      node_index: {
        type: "null",
      },
      severity: {
        const: "advisory",
        type: "string",
      },
    },
    required: ["code", "severity", "message", "node_index"],
    type: "object",
  },
  ScapEvidenceArtifact: {
    additionalProperties: false,
    properties: {
      collected_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      collected_by: {
        const: "evidentia-scap-v1",
        type: "string",
      },
      content: {
        $ref: "#/components/schemas/ScapEvidenceContent",
      },
      content_format: {
        const: "json",
        type: "string",
      },
      content_hash: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      control_mappings: {
        items: {
          type: "null",
        },
        maxItems: 0,
        minItems: 0,
        type: "array",
      },
      description: {
        const:
          "Native source observations with disclosed completion provenance; no authenticity, completeness or compliance conclusion.",
        type: "string",
      },
      evidence_type: {
        const: "test_result",
        type: "string",
      },
      expires_at: {
        type: "null",
      },
      file_path: {
        type: "null",
      },
      file_size_bytes: {
        type: "null",
      },
      id: {
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        type: "string",
      },
      lineage_id: {
        type: "null",
      },
      metadata: {
        anyOf: [
          {
            $ref: "#/components/schemas/UnlinkedArtifactMetadata",
          },
          {
            $ref: "#/components/schemas/LinkedArtifactMetadata",
          },
        ],
      },
      missing_elements: {
        items: {
          type: "null",
        },
        maxItems: 0,
        minItems: 0,
        type: "array",
      },
      predecessor_id: {
        type: "null",
      },
      source_system: {
        enum: ["scap-xccdf", "scap-oval"],
        type: "string",
      },
      sufficiency: {
        const: "unknown",
        type: "string",
      },
      sufficiency_rationale: {
        type: "null",
      },
      tags: {
        items: {
          enum: ["scap", "xccdf", "oval"],
          type: "string",
        },
        maxItems: 2,
        minItems: 2,
        type: "array",
      },
      title: {
        enum: ["Imported XCCDF assessment", "Imported OVAL assessment"],
        type: "string",
      },
      validated_at: {
        type: "null",
      },
      validated_by: {
        type: "null",
      },
      validator_confidence: {
        type: "null",
      },
      version: {
        const: 1,
        type: "integer",
      },
    },
    required: [
      "id",
      "title",
      "description",
      "evidence_type",
      "source_system",
      "collected_at",
      "collected_by",
      "content",
      "content_hash",
      "content_format",
      "file_path",
      "file_size_bytes",
      "control_mappings",
      "sufficiency",
      "sufficiency_rationale",
      "missing_elements",
      "validator_confidence",
      "validated_at",
      "validated_by",
      "expires_at",
      "tags",
      "metadata",
      "version",
      "lineage_id",
      "predecessor_id",
    ],
    type: "object",
  },
  ScapEvidenceContent: {
    additionalProperties: false,
    properties: {
      assessment: {
        $ref: "#/components/schemas/AssessmentProjection",
      },
      completion: {
        $ref: "#/components/schemas/StableArtifactCompletion",
      },
      native_document: {
        $ref: "#/components/schemas/NativeDocument",
      },
      schema_version: {
        const: "scap-evidence-v1",
        type: "string",
      },
      source: {
        $ref: "#/components/schemas/SourceBinding",
      },
    },
    required: [
      "schema_version",
      "source",
      "native_document",
      "assessment",
      "completion",
    ],
    type: "object",
  },
  ScapImportFilter: {
    additionalProperties: false,
    properties: {
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      scope: {
        const: "selected_assessment_native_projection",
        type: "string",
      },
      selected_node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      source_profile: {
        enum: [
          "xccdf-1.2-results",
          "oval-5.8-core-results",
          "oval-5.11.2-core-results",
          "oval-5.12.3-core-results",
        ],
        type: "string",
      },
      source_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      time_basis: {
        const: "file_import_observation",
        type: "string",
      },
    },
    required: [
      "source_profile",
      "source_sha256",
      "assessment_index",
      "selected_node_index",
      "scope",
      "time_basis",
    ],
    type: "object",
  },
  ScapSecurityFinding: {
    additionalProperties: false,
    properties: {
      collection_context: {
        $ref: "#/components/schemas/ScapCollectionContext",
      },
      compliance_status: {
        const: "unknown",
        type: "string",
      },
      control_mappings: {
        items: {
          type: "null",
        },
        maxItems: 0,
        minItems: 0,
        type: "array",
      },
      description: {
        const:
          "One selected assessment was imported. Native outcomes remain in the full SCAP result and any evidence artifact; this summary makes no vulnerability or compliance conclusion.",
        type: "string",
      },
      first_observed: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      id: {
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        type: "string",
      },
      last_observed: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      raw_data: {
        $ref: "#/components/schemas/ScapAssessmentSummary",
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
        type: "null",
      },
      resource_region: {
        type: "null",
      },
      resource_type: {
        const: "scap-assessment-occurrence",
        type: "string",
      },
      severity: {
        const: "informational",
        type: "string",
      },
      source_finding_id: {
        type: "null",
      },
      source_system: {
        enum: ["scap-xccdf", "scap-oval"],
        type: "string",
      },
      status: {
        const: "active",
        type: "string",
      },
      title: {
        enum: ["Imported XCCDF assessment", "Imported OVAL assessment"],
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
  SourceBinding: {
    additionalProperties: false,
    properties: {
      bytes: {
        ge: 1,
        le: 8388608,
        type: "integer",
      },
      profile: {
        enum: [
          "xccdf-1.2-results",
          "oval-5.8-core-results",
          "oval-5.11.2-core-results",
          "oval-5.12.3-core-results",
        ],
        type: "string",
      },
      projection_version: {
        const: "scap-native-document-v1",
        type: "string",
      },
      sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: ["sha256", "bytes", "profile", "projection_version"],
    type: "object",
  },
  SourceTimeObservation: {
    additionalProperties: false,
    properties: {
      normalization: {
        $ref: "#/components/schemas/NormalizedSourceTime",
      },
      role: {
        enum: [
          "document_compilation",
          "assessment_start",
          "assessment_completion",
          "rule_completion",
          "override_time",
          "tailoring_version_time",
        ],
        type: "string",
      },
      scope: {
        enum: [
          "document",
          "embedded_definitions",
          "selected_assessment",
          "system_characteristics",
        ],
        type: "string",
      },
      scope_node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      value_ref: {
        $ref: "#/components/schemas/NativeValueRef",
      },
    },
    required: [
      "scope_node_index",
      "scope",
      "role",
      "value_ref",
      "normalization",
    ],
    type: "object",
  },
  StableArtifactCompletion: {
    additionalProperties: false,
    properties: {
      assertion: {
        anyOf: [
          {
            $ref: "#/components/schemas/StableCompletionAssertion",
          },
          {
            type: "null",
          },
        ],
      },
      basis: {
        enum: ["native_reported", "operator_asserted"],
        type: "string",
      },
      native_ref: {
        anyOf: [
          {
            $ref: "#/components/schemas/NativeValueRef",
          },
          {
            type: "null",
          },
        ],
      },
      utc: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
    },
    required: ["basis", "utc", "native_ref", "assertion"],
    type: "object",
  },
  StableCompletionAssertion: {
    additionalProperties: false,
    properties: {
      actor: {
        $ref: "#/components/schemas/AssertionActor",
      },
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      basis: {
        const: "operator_asserted",
        type: "string",
      },
      completed_at: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      normalized_utc: {
        pattern:
          "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$",
        type: "string",
      },
      reference: {
        maxLength: 256,
        minLength: 1,
        pattern:
          "[^\\s\\x1c-\\x1f\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]",
        type: "string",
      },
      schema_version: {
        const: "scap-completion-assertion-v1",
        type: "string",
      },
      source_profile: {
        enum: [
          "oval-5.8-core-results",
          "oval-5.11.2-core-results",
          "oval-5.12.3-core-results",
        ],
        type: "string",
      },
      source_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
    },
    required: [
      "schema_version",
      "source_sha256",
      "source_profile",
      "assessment_index",
      "completed_at",
      "reference",
      "normalized_utc",
      "basis",
      "actor",
    ],
    type: "object",
  },
  UnlinkedArtifactMetadata: {
    additionalProperties: false,
    properties: {
      assessment_index: {
        ge: 0,
        le: 255,
        type: "integer",
      },
      scap_contract: {
        const: "scap-evidence-v1",
        type: "string",
      },
      source_profile: {
        enum: [
          "xccdf-1.2-results",
          "oval-5.8-core-results",
          "oval-5.11.2-core-results",
          "oval-5.12.3-core-results",
        ],
        type: "string",
      },
      source_sha256: {
        pattern: "^[0-9a-f]{64}$",
        type: "string",
      },
      time_basis: {
        enum: ["native_reported", "operator_asserted"],
        type: "string",
      },
    },
    required: [
      "scap_contract",
      "source_sha256",
      "source_profile",
      "assessment_index",
      "time_basis",
    ],
    type: "object",
  },
  UnverifiedPlatformStatus: {
    additionalProperties: false,
    properties: {
      effective_status: {
        type: "null",
      },
      interpretation: {
        const: "unverified_platform_status",
        type: "string",
      },
      node_index: {
        ge: 0,
        le: 32767,
        type: "integer",
      },
      scope: {
        enum: ["direct_system_data_child", "nested_platform_position"],
        type: "string",
      },
      value_ref: {
        $ref: "#/components/schemas/NativeValueRef",
      },
    },
    required: [
      "node_index",
      "scope",
      "value_ref",
      "interpretation",
      "effective_status",
    ],
    type: "object",
  },
  XmlAttribute: {
    additionalProperties: false,
    properties: {
      name: {
        $ref: "#/components/schemas/ExpandedName",
      },
      value: {
        maxLength: 262144,
        minLength: 0,
        type: "string",
      },
    },
    required: ["name", "value"],
    type: "object",
  },
  XmlComment: {
    additionalProperties: false,
    properties: {
      data: {
        maxLength: 262144,
        minLength: 0,
        type: "string",
      },
      kind: {
        const: "comment",
        type: "string",
      },
      tail: {
        anyOf: [
          {
            maxLength: 262144,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: ["kind", "data", "tail"],
    type: "object",
  },
  XmlDeclaration: {
    additionalProperties: false,
    properties: {
      encoding: {
        anyOf: [
          {
            pattern: "^[Uu][Tt][Ff]-8$",
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      standalone: {
        anyOf: [
          {
            enum: ["yes", "no"],
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      version: {
        const: "1.0",
        type: "string",
      },
    },
    required: ["version", "encoding", "standalone"],
    type: "object",
  },
  XmlElement: {
    additionalProperties: false,
    properties: {
      attributes: {
        items: {
          $ref: "#/components/schemas/XmlAttribute",
        },
        maxItems: 64,
        minItems: 0,
        type: "array",
      },
      children: {
        items: {
          ge: 0,
          le: 32767,
          type: "integer",
        },
        maxItems: 32768,
        minItems: 0,
        type: "array",
      },
      kind: {
        const: "element",
        type: "string",
      },
      name: {
        $ref: "#/components/schemas/ExpandedName",
      },
      namespace_declarations: {
        items: {
          $ref: "#/components/schemas/NamespaceDeclaration",
        },
        maxItems: 64,
        minItems: 0,
        type: "array",
      },
      tail: {
        anyOf: [
          {
            maxLength: 262144,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      text: {
        anyOf: [
          {
            maxLength: 262144,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: [
      "kind",
      "name",
      "namespace_declarations",
      "attributes",
      "text",
      "tail",
      "children",
    ],
    type: "object",
  },
  XmlPI: {
    additionalProperties: false,
    properties: {
      data: {
        maxLength: 262144,
        minLength: 0,
        type: "string",
      },
      kind: {
        const: "processing_instruction",
        type: "string",
      },
      tail: {
        anyOf: [
          {
            maxLength: 262144,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
      },
      target: {
        maxLength: 256,
        minLength: 1,
        type: "string",
      },
    },
    required: ["kind", "target", "data", "tail"],
    type: "object",
  },
});

function matches(value: Json, schema: Schema): boolean {
  if (schema.$ref) {
    const name = schema.$ref.replace("#/components/schemas/", "");
    return (
      own(SCAP_RESPONSE_SCHEMAS, name) &&
      matches(value, SCAP_RESPONSE_SCHEMAS[name])
    );
  }
  if (schema.allOf && !schema.allOf.every((part) => matches(value, part)))
    return false;
  if (schema.anyOf && !schema.anyOf.some((part) => matches(value, part)))
    return false;
  if (
    schema.oneOf &&
    schema.oneOf.filter((part) => matches(value, part)).length !== 1
  )
    return false;
  if (own(schema, "const") && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "null") return value === null;
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "integer")
    return (
      typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= (schema.ge ?? schema.minimum ?? -Number.MAX_SAFE_INTEGER) &&
      value <= (schema.le ?? schema.maximum ?? Number.MAX_SAFE_INTEGER)
    );
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    const bytes = utf8(value);
    if (bytes < (schema.minLength ?? 0) || bytes > (schema.maxLength ?? 262144))
      return false;
    if (
      schema.pattern &&
      !new RegExp(schema.pattern.replace(/\$$/, "(?![\\s\\S])"), "u").test(
        value,
      )
    )
      return false;
    return true;
  }
  if (schema.type === "array")
    return (
      Array.isArray(value) &&
      value.length >= (schema.minItems ?? 0) &&
      value.length <= (schema.maxItems ?? 32768) &&
      (!schema.items || value.every((item) => matches(item, schema.items!)))
    );
  if (schema.type === "object") {
    if (
      !object(value) ||
      !(schema.required ?? []).every((key) => own(value, key))
    )
      return false;
    return Object.keys(value).every((key) =>
      schema.properties && own(schema.properties, key)
        ? matches(value[key], schema.properties[key])
        : typeof schema.additionalProperties === "object"
          ? matches(value[key], schema.additionalProperties)
          : schema.additionalProperties !== false,
    );
  }
  return true;
}
const controls = /[\p{Cc}\p{Cf}\p{Cs}]/u;
const blank = /^[\s\x1c-\x1f\x85]*$/u;
function label(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    utf8(value) >= 1 &&
    utf8(value) <= maximum &&
    !blank.test(value) &&
    !controls.test(value)
  );
}
const pad = (n: number, length = 2) => String(n).padStart(length, "0");
const days = (year: number, month: number) =>
  month === 2
    ? year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0)
      ? 29
      : 28
    : [4, 6, 9, 11].includes(month)
      ? 30
      : 31;
function utc(value: string, canonicalRequired = true): string {
  const m =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(
      value,
    );
  ensure(m && m[0].length === value.length);
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  ensure(
    year >= 1 &&
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= days(year, month) &&
      hour <= 23 &&
      minute <= 59 &&
      second <= 59,
  );
  const fraction = (m[7] ?? "").replace(/0+$/, "");
  const result = value.slice(0, 19) + (fraction ? "." + fraction : "") + "Z";
  ensure(!canonicalRequired || result === value);
  return result;
}
const instantKey = (value: string) => {
  const c = utc(value);
  return (
    c.slice(0, 19) + (c.includes(".") ? c.slice(20, -1) : "").padEnd(6, "0")
  );
};
function request(value: unknown): ScapRequest {
  const copy = clone(value, 4096);
  ensure(
    object(copy) &&
      same(Object.keys(copy).sort(), [
        "assessment_index",
        "cadence_slug",
        "completion_assertion",
        "source_profile",
      ]),
  );
  ensure(
    SCAP_PROFILES.includes(copy.source_profile as ScapProfile) &&
      typeof copy.assessment_index === "number" &&
      copy.assessment_index >= 0 &&
      copy.assessment_index <= 255,
  );
  ensure(copy.cadence_slug === null || label(copy.cadence_slug, 256));
  if (copy.completion_assertion !== null) {
    const c = copy.completion_assertion;
    ensure(
      object(c) &&
        same(Object.keys(c).sort(), [
          "assessment_index",
          "completed_at",
          "reference",
          "schema_version",
          "source_profile",
          "source_sha256",
        ]),
    );
    ensure(
      c.schema_version === "scap-completion-assertion-v1" &&
        typeof c.source_sha256 === "string" &&
        /^[0-9a-f]{64}$/.test(c.source_sha256) &&
        c.source_sha256.length === 64,
    );
    ensure(
      c.source_profile === copy.source_profile &&
        c.source_profile !== "xccdf-1.2-results" &&
        c.assessment_index === copy.assessment_index,
    );
    ensure(typeof c.completed_at === "string" && label(c.reference, 256));
    utc(c.completed_at, false);
    ensure(canonical(c).length <= SCAP_ASSERTION_BYTES);
  }
  return freeze(copy as unknown as ScapRequest);
}
export function parseScapAssertion(raw: unknown): ScapCompletionAssertion {
  const claim = parse(raw, SCAP_ASSERTION_BYTES).value;
  ensure(object(claim));
  return request({
    source_profile: claim.source_profile,
    assessment_index: claim.assessment_index,
    cadence_slug: null,
    completion_assertion: claim,
  }).completion_assertion!;
}
async function digest(
  bytes: Uint8Array<ArrayBuffer>,
  algorithm = "SHA-256",
): Promise<string> {
  const result = await globalThis.crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(result)]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
}
export async function prepareScapUpload(
  raw: ArrayBuffer,
  options: unknown,
): Promise<{
  body: ArrayBuffer;
  query: string;
  assertionHeader: string | null;
  expected: ScapExpected;
}> {
  try {
    const getter = Object.getOwnPropertyDescriptor(
      ArrayBuffer.prototype,
      "byteLength",
    )!.get!;
    const length: unknown = getter.call(raw);
    ensure(
      typeof length === "number" &&
        length >= 1 &&
        length <= SCAP_SOURCE_BYTES &&
        Object.getPrototypeOf(raw) === ArrayBuffer.prototype,
    );
    const body = new Uint8Array(length);
    body.set(new Uint8Array(raw));
    const selected = request(options);
    const sourceSha256 = await digest(body);
    const claim = selected.completion_assertion;
    if (claim !== null) ensure(claim.source_sha256 === sourceSha256);
    const params = new URLSearchParams({
      source_profile: selected.source_profile,
      assessment_index: String(selected.assessment_index),
    });
    if (selected.cadence_slug !== null)
      params.set("cadence_slug", selected.cadence_slug);
    const query = params.toString();
    ensure(utf8(query) <= 1024);
    return {
      body: body.buffer,
      query,
      assertionHeader:
        claim === null ? null : canonical(claim as unknown as Json),
      expected: freeze({
        request: selected,
        sourceSha256,
        sourceBytes: length,
      }),
    };
  } catch (error) {
    if (error instanceof ScapResponseError) throw error;
    return fail();
  }
}

type Native = ScapResult["native_document"];
type Element = Extract<Native["nodes"][number], { kind: "element" }>;
type Ref = components["schemas"]["NativeValueRef"];
const XCCDF = "http://checklists.nist.gov/xccdf/1.2";
const OVAL = "http://oval.mitre.org/XMLSchema/oval-results-5";
const XML = "http://www.w3.org/XML/1998/namespace";
const XMLNS = "http://www.w3.org/2000/xmlns/";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const xOutcomes = [
  "pass",
  "fail",
  "error",
  "unknown",
  "notapplicable",
  "informational",
  "fixed",
  "notchecked",
  "notselected",
];
const oOutcomes = [
  "true",
  "false",
  "unknown",
  "error",
  "not evaluated",
  "not applicable",
];
const oLevels = [
  "oval_definition",
  "oval_criteria",
  "oval_criterion",
  "oval_extend_definition",
  "oval_test",
  "oval_tested_item",
];
const topLevels = ["xccdf_rule_result", "oval_definition", "oval_test"];
const collapse = (value: string) =>
  value.replace(/[ \t\r\n]+/g, " ").replace(/^ | $/g, "");
const nameStart = (n: number) =>
  n === 95 ||
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  (n >= 0xc0 && n <= 0xd6) ||
  (n >= 0xd8 && n <= 0xf6) ||
  (n >= 0xf8 && n <= 0x2ff) ||
  (n >= 0x370 && n <= 0x37d) ||
  (n >= 0x37f && n <= 0x1fff) ||
  (n >= 0x200c && n <= 0x200d) ||
  (n >= 0x2070 && n <= 0x218f) ||
  (n >= 0x2c00 && n <= 0x2fef) ||
  (n >= 0x3001 && n <= 0xd7ff) ||
  (n >= 0xf900 && n <= 0xfdcf) ||
  (n >= 0xfdf0 && n <= 0xfffd) ||
  (n >= 0x10000 && n <= 0xeffff);
function xmlName(value: string, colon = false): void {
  let first = true;
  for (const char of value) {
    const n = char.codePointAt(0)!;
    ensure(
      nameStart(n) ||
        (colon && n === 58) ||
        (!first &&
          (n === 45 ||
            n === 46 ||
            (n >= 48 && n <= 57) ||
            n === 0xb7 ||
            (n >= 0x300 && n <= 0x36f) ||
            (n >= 0x203f && n <= 0x2040))),
    );
    first = false;
  }
  ensure(!first);
}
function xmlText(value: string): void {
  for (const char of value) {
    const n = char.codePointAt(0)!;
    ensure(
      n === 9 ||
        n === 10 ||
        n === 13 ||
        (n >= 32 && n <= 0xd7ff) ||
        (n >= 0xe000 && n <= 0xfffd) ||
        (n >= 0x10000 && n <= 0x10ffff),
    );
  }
}
function nativeView(document: Native) {
  const nodes = document.nodes;
  const parents = new Int32Array(nodes.length).fill(-1);
  const ends = new Int32Array(nodes.length);
  let next = 0,
    sourceBytes = 0,
    attributes = 0,
    namespaces = 0,
    roots = 0;
  const env = new Map<string, string>([
    ["xml", XML],
    ["", ""],
  ]);
  const uris = new Map<string, number>([
    [XML, 1],
    ["", 1],
  ]);
  const attributeUris = new Map<string, number>([[XML, 1]]);
  const bind = (prefix: string, value: string | undefined) => {
    const prior = env.get(prefix);
    const count = (map: Map<string, number>, uri: string, delta: number) => {
      const next = (map.get(uri) ?? 0) + delta;
      if (next === 0) map.delete(uri);
      else map.set(uri, next);
    };
    if (prior !== undefined) {
      count(uris, prior, -1);
      if (prefix !== "") count(attributeUris, prior, -1);
    }
    if (value === undefined) env.delete(prefix);
    else {
      env.set(prefix, value);
      count(uris, value, 1);
      if (prefix !== "") count(attributeUris, value, 1);
    }
  };
  const charge = (value: string | null) => {
    if (value !== null) {
      xmlText(value);
      sourceBytes += utf8(value);
      ensure(sourceBytes <= 4_194_304);
    }
  };
  if (document.declaration)
    for (const item of Object.values(document.declaration)) charge(item);
  charge(document.text);
  ensure(document.text === null || /^[ \t\r\n]*$/.test(document.text));
  type Frame = {
    index: number;
    parent: number;
    depth: number;
    restore?: Array<[string, string | undefined]>;
  };
  const pending: Frame[] = document.children
    .slice()
    .reverse()
    .map((index) => ({ index, parent: -1, depth: 0 }));
  while (pending.length) {
    const frame = pending.pop()!;
    if (frame.restore) {
      ends[frame.index] = next;
      for (const [prefix, prior] of frame.restore) {
        bind(prefix, prior);
      }
      continue;
    }
    ensure(frame.index === next && frame.index < nodes.length);
    next++;
    parents[frame.index] = frame.parent;
    const node = nodes[frame.index];
    charge(node.tail);
    if (frame.parent === -1)
      ensure(node.tail === null || /^[ \t\r\n]*$/.test(node.tail));
    if (node.kind !== "element") {
      charge(node.data);
      if (node.kind === "comment")
        ensure(!node.data.includes("--") && !node.data.endsWith("-"));
      else {
        xmlName(node.target, true);
        charge(node.target);
        ensure(
          node.target.toLowerCase() !== "xml" && !node.data.includes("?>"),
        );
      }
      ends[frame.index] = next;
      continue;
    }
    if (frame.parent === -1) roots++;
    ensure(frame.depth < 64);
    const restore: Array<[string, string | undefined]> = [];
    const prefixes = new Set<string>();
    for (const declaration of node.namespace_declarations) {
      charge(declaration.prefix);
      charge(declaration.namespace_uri);
      ensure(++namespaces <= 8192 && !prefixes.has(declaration.prefix));
      prefixes.add(declaration.prefix);
      if (declaration.prefix) xmlName(declaration.prefix);
      ensure(
        declaration.prefix !== "xmlns" &&
          declaration.namespace_uri !== XMLNS &&
          (declaration.prefix === "xml") ===
            (declaration.namespace_uri === XML) &&
          (!declaration.prefix || declaration.namespace_uri !== ""),
      );
      restore.push([declaration.prefix, env.get(declaration.prefix)]);
      bind(declaration.prefix, declaration.namespace_uri);
    }
    const qname = (name: Element["name"], attribute = false) => {
      xmlName(name.local_name);
      charge(name.local_name);
      charge(name.namespace_uri);
      ensure(name.namespace_uri !== XMLNS);
      if (attribute)
        ensure(
          name.namespace_uri
            ? attributeUris.has(name.namespace_uri)
            : name.local_name !== "xmlns",
        );
      else
        ensure(
          name.namespace_uri
            ? uris.has(name.namespace_uri)
            : env.get("") === "",
        );
    };
    qname(node.name);
    const names = new Set<string>();
    for (const attribute of node.attributes) {
      ensure(++attributes <= 65536);
      qname(attribute.name, true);
      charge(attribute.value);
      const key = JSON.stringify([
        attribute.name.namespace_uri,
        attribute.name.local_name,
      ]);
      ensure(!names.has(key));
      names.add(key);
    }
    charge(node.text);
    pending.push({ ...frame, restore });
    for (let offset = node.children.length - 1; offset >= 0; offset--)
      pending.push({
        index: node.children[offset],
        parent: frame.index,
        depth: frame.depth + 1,
      });
  }
  ensure(next === nodes.length && roots === 1);
  const element = (index: number): Element => {
    const node = nodes[index];
    ensure(node?.kind === "element");
    return node;
  };
  const contains = (parent: number, child: number) =>
    parent <= child && child < ends[parent];
  const resolve = (ref: Ref): string => {
    const node = element(ref.node_index);
    if (ref.slot === "attribute_value") {
      ensure(
        ref.attribute_index !== null &&
          ref.attribute_index < node.attributes.length,
      );
      return node.attributes[ref.attribute_index].value;
    }
    ensure(ref.attribute_index === null);
    if (ref.slot === "text") {
      ensure(node.text !== null);
      return node.text;
    }
    let result = node.text ?? "",
      bytes = utf8(result);
    for (const index of node.children) {
      const child = nodes[index];
      ensure(child.kind !== "element");
      bytes += utf8(child.tail ?? "");
      ensure(bytes <= 262144);
      result += child.tail ?? "";
    }
    return result;
  };
  const attribute = (index: number, name: string) =>
    element(index).attributes.findIndex(
      (item) => item.name.namespace_uri === "" && item.name.local_name === name,
    );
  return { element, parents, ends, contains, resolve, attribute };
}

// This checks source-time projections against their retained literal. It does
// not choose source roles or interpret the uploaded XML in the browser.
function sourceTime(
  literal: string,
): components["schemas"]["NormalizedSourceTime"] {
  const text = literal.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  const m =
    /^(-?)([0-9]{4,})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})?$/.exec(
      text,
    );
  ensure(
    m && m[0].length === text.length && !(m[2].length > 4 && m[2][0] === "0"),
  );
  let magnitude = 0,
    residue = 0;
  for (const char of m[2]) {
    magnitude = Math.min(10001, magnitude * 10 + Number(char));
    residue = (residue * 10 + Number(char)) % 400;
  }
  let year = m[1] ? -magnitude : magnitude,
    month = Number(m[3]),
    day = Number(m[4]),
    hour = Number(m[5]);
  const minute = Number(m[6]),
    second = Number(m[7]),
    fraction = m[8] ?? "",
    zone = m[9];
  ensure(
    magnitude !== 0 &&
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= days(residue, month) &&
      hour <= 24 &&
      minute <= 59 &&
      second <= 60,
  );
  ensure(
    hour !== 24 || (minute === 0 && second === 0 && !/[1-9]/.test(fraction)),
  );
  let offset = 0;
  if (zone && zone !== "Z") {
    const h = Number(zone.slice(1, 3)),
      n = Number(zone.slice(4));
    ensure(h <= 14 && n <= 59 && (h !== 14 || n === 0));
    offset = (h * 60 + n) * (zone[0] === "-" ? -1 : 1);
  }
  if (!zone) return { state: "timezone_missing", utc: null };
  if (/[1-9]/.test(fraction.slice(6)))
    return { state: "precision_unsupported", utc: null };
  if (second === 60) return { state: "normalization_unsupported", utc: null };
  if (magnitude > 10000 || (m[1] && magnitude !== 1))
    return { state: "range_unsupported", utc: null };
  const move = (direction: number) => {
    day += direction;
    if (day > days(year, month)) {
      day = 1;
      if (++month === 13) {
        month = 1;
        year = year === -1 ? 1 : year + 1;
      }
    } else if (day === 0) {
      if (--month === 0) {
        month = 12;
        year = year === 1 ? -1 : year - 1;
      }
      day = days(year, month);
    }
  };
  if (hour === 24) {
    move(1);
    hour = 0;
  }
  let minutes = hour * 60 + minute - offset;
  if (minutes < 0) {
    move(-1);
    minutes += 1440;
  } else if (minutes >= 1440) {
    move(1);
    minutes -= 1440;
  }
  if (year < 1 || year > 9999) return { state: "range_unsupported", utc: null };
  const fractional = fraction.slice(0, 6).replace(/0+$/, "");
  return {
    state: "normalized",
    utc: `${pad(year, 4)}-${pad(month)}-${pad(day)}T${pad(Math.floor(minutes / 60))}:${pad(minutes % 60)}:${pad(second)}${fractional ? "." + fractional : ""}Z`,
  };
}
async function uuid5(namespace: string, name: string): Promise<string> {
  const prefix = Uint8Array.from(
    namespace.replaceAll("-", "").match(/../g)!,
    (item) => parseInt(item, 16),
  );
  const bytes = encoder.encode(name);
  const input = new Uint8Array(16 + bytes.length);
  input.set(prefix);
  input.set(bytes, 16);
  const result = (await digest(input, "SHA-1")).slice(0, 32).split("");
  result[12] = "5";
  result[16] = ((parseInt(result[16], 16) & 3) | 8).toString(16);
  const raw = result.join("");
  return `${raw.slice(0, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}-${raw.slice(20)}`;
}
async function validateResult(
  result: ScapResult,
  expected: ScapExpected,
): Promise<void> {
  const {
    assessment: a,
    completion: completion,
    source,
    manifest,
    evidence_artifact: artifact,
  } = result;
  const coverage = a.coverage,
    selected = a.selection.node_index,
    oval = source.profile !== "xccdf-1.2-results";
  const sourceSystem = oval ? "scap-oval" : "scap-xccdf",
    title = oval ? "Imported OVAL assessment" : "Imported XCCDF assessment";
  ensure(
    source.sha256 === expected.sourceSha256 &&
      source.bytes === expected.sourceBytes &&
      source.profile === expected.request.source_profile &&
      a.selection.assessment_index === expected.request.assessment_index,
  );
  const view = nativeView(result.native_document);
  const root = result.native_document.children.find(
    (index) => result.native_document.nodes[index].kind === "element",
  )!;
  const rootNode = view.element(root);
  ensure(
    rootNode.name.namespace_uri === (oval ? OVAL : XCCDF) &&
      (oval
        ? rootNode.name.local_name === "oval_results"
        : ["Benchmark", "TestResult"].includes(rootNode.name.local_name)),
  );
  const kind = oval ? "oval_system" : "xccdf_test_result";
  const children = (index: number, namespace: string, local: string) =>
    view.element(index).children.filter((child) => {
      const node = result.native_document.nodes[child];
      return (
        node.kind === "element" &&
        node.name.namespace_uri === namespace &&
        node.name.local_name === local
      );
    });
  const containers = oval ? children(root, OVAL, "results") : [];
  if (oval) ensure(containers.length === 1);
  const units = oval
    ? children(containers[0], OVAL, "system")
    : rootNode.name.local_name === "TestResult"
      ? [root]
      : children(root, XCCDF, "TestResult");
  ensure(
    same(
      a.units.map((unit) => unit.node_index),
      units,
    ),
  );
  let previous = -1;
  a.units.forEach((unit, index) => {
    ensure(
      unit.assessment_index === index &&
        unit.unit_kind === kind &&
        unit.node_index > previous,
    );
    previous = unit.node_index;
    const node = view.element(unit.node_index);
    ensure(
      node.name.namespace_uri === (oval ? OVAL : XCCDF) &&
        node.name.local_name === (oval ? "system" : "TestResult"),
    );
  });
  ensure(
    same(a.units[a.selection.assessment_index], a.selection) &&
      coverage.selected_node_index === selected &&
      coverage.visible_unit_count === a.units.length &&
      coverage.unselected_unit_count === a.units.length - 1,
  );
  const levels = oval ? oLevels : ["xccdf_rule_result"],
    values = oval ? oOutcomes : xOutcomes;
  const counts = new Map<string, number>();
  let visible = 0;
  for (const unit of units) {
    const occurrences: number[] = [];
    if (!oval) occurrences.push(...children(unit, XCCDF, "rule-result"));
    else {
      for (const container of children(unit, OVAL, "definitions")) {
        for (const definition of children(container, OVAL, "definition")) {
          occurrences.push(definition);
          const pending = children(definition, OVAL, "criteria").reverse();
          while (pending.length) {
            const index = pending.pop()!;
            occurrences.push(index);
            if (view.element(index).name.local_name === "criteria") {
              for (const child of view
                .element(index)
                .children.slice()
                .reverse()) {
                const node = result.native_document.nodes[child];
                if (
                  node.kind === "element" &&
                  node.name.namespace_uri === OVAL &&
                  ["criteria", "criterion", "extend_definition"].includes(
                    node.name.local_name,
                  )
                )
                  pending.push(child);
              }
            }
          }
        }
      }
      for (const container of children(unit, OVAL, "tests"))
        for (const test of children(container, OVAL, "test")) {
          occurrences.push(test, ...children(test, OVAL, "tested_item"));
        }
    }
    visible += occurrences.length;
    ensure(visible <= 10000);
    if (unit === selected)
      ensure(
        same(
          a.outcomes.map((outcome) => outcome.node_index),
          occurrences.sort((left, right) => left - right),
        ),
      );
  }
  ensure(coverage.visible_outcome_count === visible);
  let top = 0,
    countable = 0;
  previous = -1;
  for (const outcome of a.outcomes) {
    ensure(
      outcome.unit_node_index === selected &&
        view.contains(selected, outcome.node_index) &&
        outcome.node_index > previous &&
        levels.includes(outcome.level) &&
        values.includes(outcome.native_result),
    );
    previous = outcome.node_index;
    const node = view.element(outcome.node_index);
    ensure(
      node.name.namespace_uri === (oval ? OVAL : XCCDF) &&
        node.name.local_name ===
          (oval ? outcome.level.slice(5) : "rule-result"),
    );
    ensure(collapse(view.resolve(outcome.value_ref)) === outcome.native_result);
    if (oval)
      ensure(
        outcome.value_ref.node_index === outcome.node_index &&
          outcome.value_ref.slot === "attribute_value" &&
          outcome.value_ref.attribute_index ===
            view.attribute(outcome.node_index, "result"),
      );
    else {
      const n = view.element(outcome.value_ref.node_index);
      ensure(
        view.parents[outcome.value_ref.node_index] === outcome.node_index &&
          n.name.namespace_uri === XCCDF &&
          n.name.local_name === "result" &&
          outcome.value_ref.slot === "element_simple_content",
      );
    }
    const key = outcome.level + ":" + outcome.native_result;
    counts.set(key, (counts.get(key) ?? 0) + 1);
    if (topLevels.includes(outcome.level)) {
      top++;
      if (
        !["notchecked", "notselected", "not evaluated"].includes(
          outcome.native_result,
        )
      )
        countable++;
    }
  }
  ensure(
    coverage.selected_outcome_count === a.outcomes.length &&
      coverage.top_level_outcome_count === top &&
      coverage.countable_top_level_outcome_count === countable &&
      coverage.visible_outcome_count >= a.outcomes.length,
  );
  ensure(
    same(
      coverage.outcome_counts,
      levels.flatMap((level) =>
        values.map((value) => ({
          level,
          native_result: value,
          count: counts.get(level + ":" + value) ?? 0,
        })),
      ),
    ),
  );
  ensure(
    coverage.cadence_evidence ===
      (top === 0 ? "empty" : countable === 0 ? "not_evaluated" : "countable"),
  );
  // Every retained observation must match a native position exactly once.
  // Source parsing and profile admission remain owned by the server.
  type TimeCell = Omit<(typeof a.times)[number], "normalization">;
  const expectedTimes: TimeCell[] = [];
  const expectedFlags: unknown[] = [],
    expectedStatuses: unknown[] = [],
    expectedCoreStatuses: unknown[] = [];
  const reference = (index: number, name: string | null = null): Ref => {
    const attribute = name === null ? null : view.attribute(index, name);
    ensure(attribute === null || attribute >= 0);
    return {
      node_index: index,
      slot: name === null ? "element_simple_content" : "attribute_value",
      attribute_index: attribute,
    };
  };
  const timePosition = (
    index: number,
    name: string | null,
    owner: number,
    scope: TimeCell["scope"],
    role: TimeCell["role"],
  ) => {
    ensure(expectedTimes.length < 10000);
    expectedTimes.push({
      scope_node_index: owner,
      scope,
      role,
      value_ref: reference(index, name),
    });
  };
  if (oval) {
    const common = "http://oval.mitre.org/XMLSchema/oval-common-5",
      definitions = "http://oval.mitre.org/XMLSchema/oval-definitions-5",
      characteristics =
        "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5";
    const generatorTime = (
      owner: number,
      namespace: string,
      scope: TimeCell["scope"],
    ) => {
      const generators = children(owner, namespace, "generator");
      ensure(generators.length === 1);
      const timestamps = children(generators[0], common, "timestamp");
      ensure(timestamps.length === 1);
      timePosition(timestamps[0], null, owner, scope, "document_compilation");
    };
    generatorTime(root, OVAL, "document");
    const embedded = children(root, definitions, "oval_definitions");
    ensure(embedded.length <= 1);
    for (const index of embedded)
      generatorTime(index, definitions, "embedded_definitions");
    for (const unit of units) {
      const contexts = children(
        unit,
        characteristics,
        "oval_system_characteristics",
      );
      ensure(contexts.length === 1);
      const context = contexts[0];
      generatorTime(context, characteristics, "system_characteristics");
      if (unit !== selected) continue;
      for (const container of children(
        context,
        characteristics,
        "collected_objects",
      ))
        for (const index of children(container, characteristics, "object")) {
          const valueRef = reference(index, "flag");
          expectedFlags.push({
            object_node_index: index,
            value_ref: valueRef,
            native_flag: collapse(view.resolve(valueRef)),
          });
        }
      for (const container of children(context, characteristics, "system_data"))
        for (const item of view.element(container).children) {
          if (result.native_document.nodes[item].kind !== "element") continue;
          for (let index = item; index < view.ends[item]; index++) {
            if (
              result.native_document.nodes[index].kind !== "element" ||
              view.attribute(index, "status") < 0
            )
              continue;
            expectedStatuses.push({
              node_index: index,
              scope:
                index === item
                  ? "direct_system_data_child"
                  : "nested_platform_position",
              value_ref: reference(index, "status"),
              interpretation: "unverified_platform_status",
              effective_status: null,
            });
          }
        }
      if (source.profile === "oval-5.8-core-results")
        for (const info of children(context, characteristics, "system_info"))
          for (const interfaces of children(
            info,
            characteristics,
            "interfaces",
          ))
            for (const entry of children(
              interfaces,
              characteristics,
              "interface",
            ))
              for (const index of children(
                entry,
                characteristics,
                "ip_address",
              )) {
                const present = view.attribute(index, "status") >= 0;
                const valueRef = present ? reference(index, "status") : null;
                expectedCoreStatuses.push({
                  node_index: index,
                  present,
                  value_ref: valueRef,
                  effective_status:
                    valueRef === null
                      ? "exists"
                      : collapse(view.resolve(valueRef)),
                  interpretation: "reviewed_5_8_core_ip_address_status",
                });
              }
    }
  } else {
    for (const [name, role] of [
      ["start-time", "assessment_start"],
      ["end-time", "assessment_completion"],
    ] as const)
      if (view.attribute(selected, name) >= 0)
        timePosition(selected, name, selected, "selected_assessment", role);
    for (const index of children(selected, XCCDF, "tailoring-file"))
      timePosition(
        index,
        "time",
        index,
        "selected_assessment",
        "tailoring_version_time",
      );
    for (const rule of children(selected, XCCDF, "rule-result")) {
      if (view.attribute(rule, "time") >= 0)
        timePosition(
          rule,
          "time",
          rule,
          "selected_assessment",
          "rule_completion",
        );
      for (const index of children(rule, XCCDF, "override"))
        timePosition(
          index,
          "time",
          index,
          "selected_assessment",
          "override_time",
        );
    }
  }
  expectedTimes.sort(
    (left, right) =>
      left.value_ref.node_index - right.value_ref.node_index ||
      (left.value_ref.attribute_index ?? 0) -
        (right.value_ref.attribute_index ?? 0),
  );
  ensure(
    same(
      a.times.map((time) => ({
        scope_node_index: time.scope_node_index,
        scope: time.scope,
        role: time.role,
        value_ref: time.value_ref,
      })),
      expectedTimes,
    ),
  );
  ensure(same(coverage.collection_flags, expectedFlags));
  ensure(same(coverage.status_observations, expectedStatuses));
  ensure(same(coverage.core_status_defaults, expectedCoreStatuses));
  let lastTime: [number, number] = [-1, -1];
  for (const time of a.times) {
    const key: [number, number] = [
      time.value_ref.node_index,
      time.value_ref.attribute_index ?? 0,
    ];
    ensure(
      key[0] > lastTime[0] || (key[0] === lastTime[0] && key[1] > lastTime[1]),
    );
    lastTime = key;
    view.element(time.scope_node_index);
    ensure(view.contains(time.scope_node_index, time.value_ref.node_index));
    ensure(same(time.normalization, sourceTime(view.resolve(time.value_ref))));
    if (time.scope === "selected_assessment")
      ensure(view.contains(selected, time.scope_node_index));
    if (oval)
      ensure(
        time.role === "document_compilation" &&
          time.scope !== "selected_assessment",
      );
    else if (
      time.role === "assessment_completion" ||
      time.role === "assessment_start"
    )
      ensure(
        time.scope_node_index === selected &&
          time.scope === "selected_assessment" &&
          time.value_ref.node_index === selected &&
          time.value_ref.slot === "attribute_value" &&
          time.value_ref.attribute_index ===
            view.attribute(
              selected,
              time.role === "assessment_completion" ? "end-time" : "start-time",
            ),
      );
  }
  previous = -1;
  let unknownCount = 0;
  for (const index of a.uninterpreted_roots) {
    ensure(index > previous && index < result.native_document.nodes.length);
    unknownCount += view.ends[index] - index;
    previous = view.ends[index] - 1;
  }
  ensure(unknownCount === coverage.uninterpreted_node_count);
  ensure(
    same(
      coverage.signature_node_indices,
      result.native_document.nodes.flatMap((node, index) =>
        node.kind === "element" &&
        node.name.namespace_uri === DS &&
        node.name.local_name === "Signature"
          ? [index]
          : [],
      ),
    ),
  );
  for (const flag of coverage.collection_flags) {
    ensure(
      view.contains(selected, flag.object_node_index) &&
        flag.value_ref.node_index === flag.object_node_index &&
        flag.value_ref.attribute_index ===
          view.attribute(flag.object_node_index, "flag") &&
        flag.value_ref.slot === "attribute_value" &&
        collapse(view.resolve(flag.value_ref)) === flag.native_flag,
    );
  }
  for (const observation of coverage.status_observations) {
    view.element(observation.node_index);
    ensure(
      observation.value_ref.node_index === observation.node_index &&
        observation.value_ref.slot === "attribute_value" &&
        observation.value_ref.attribute_index ===
          view.attribute(observation.node_index, "status"),
    );
    view.resolve(observation.value_ref);
  }
  for (const observation of coverage.core_status_defaults) {
    const node = view.element(observation.node_index);
    ensure(
      source.profile === "oval-5.8-core-results" &&
        node.name.local_name === "ip_address" &&
        node.name.namespace_uri ===
          "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5",
    );
    const index = view.attribute(observation.node_index, "status");
    ensure(observation.present === index >= 0);
    if (observation.present)
      ensure(
        observation.value_ref !== null &&
          observation.value_ref.node_index === observation.node_index &&
          observation.value_ref.attribute_index === index &&
          observation.value_ref.slot === "attribute_value" &&
          collapse(view.resolve(observation.value_ref)) ===
            observation.effective_status,
      );
    else
      ensure(
        observation.value_ref === null &&
          observation.effective_status === "exists",
      );
  }
  if (!oval)
    ensure(
      coverage.oval_directives === null &&
        coverage.native_export_detail === "not_applicable" &&
        coverage.collection_flags.length === 0 &&
        coverage.status_observations.length === 0 &&
        coverage.core_status_defaults.length === 0,
    );
  else validateDirectives(coverage, view);
  const imported = utc(result.imported_at);
  utc(manifest.collection_finished_at);
  ensure(
    manifest.collection_started_at === imported &&
      instantKey(manifest.collection_finished_at) >= instantKey(imported) &&
      label(manifest.collector_version, 64) &&
      label(manifest.evidentia_version, 64),
  );
  const reasons: string[] = [];
  const end = a.times.find(
    (time) =>
      time.scope === "selected_assessment" &&
      time.role === "assessment_completion",
  );
  const start = a.times.find(
    (time) =>
      time.scope === "selected_assessment" && time.role === "assessment_start",
  );
  if (!oval) {
    for (const [attribute, observation] of [
      ["end-time", end],
      ["start-time", start],
    ] as const)
      ensure(
        view.attribute(selected, attribute) >= 0 ===
          (observation !== undefined),
      );
  }
  ensure(
    a.times.filter(
      (time) =>
        time.scope === "selected_assessment" &&
        time.role === "assessment_completion",
    ).length <= 1 &&
      a.times.filter(
        (time) =>
          time.scope === "selected_assessment" &&
          time.role === "assessment_start",
      ).length <= 1,
  );
  const claim = expected.request.completion_assertion;
  if (claim !== null) {
    const assertion = completion.assertion;
    ensure(
      oval &&
        assertion !== null &&
        assertion.actor.basis === "api_authenticated" &&
        label(assertion.actor.provider, 128) &&
        label(assertion.actor.subject, 128),
    );
    ensure(
      same(assertion, {
        ...claim,
        normalized_utc: utc(claim.completed_at, false),
        basis: "operator_asserted",
        actor: assertion.actor,
      }),
    );
    ensure(
      canonical(assertion as unknown as Json).length <= 4096 &&
        instantKey(assertion.normalized_utc) <= instantKey(imported),
    );
    ensure(
      completion.state === "operator_qualified" &&
        completion.basis === "operator_asserted" &&
        completion.utc === assertion.normalized_utc &&
        completion.native_ref === null &&
        completion.qualification_reasons.length === 0,
    );
  } else {
    if (!end) reasons.push("native_completion_absent");
    else if (end.normalization.utc === null)
      reasons.push("native_completion_" + end.normalization.state);
    else if (instantKey(end.normalization.utc) > instantKey(imported))
      reasons.push("native_completion_future");
    if (start && start.normalization.utc === null)
      reasons.push("native_start_unresolved");
    if (
      start?.normalization.utc &&
      end?.normalization.utc &&
      instantKey(end.normalization.utc) < instantKey(start.normalization.utc)
    )
      reasons.push("native_completion_before_start");
    ensure(
      completion.assertion === null &&
        same(completion.native_ref, end?.value_ref ?? null) &&
        same(completion.qualification_reasons, reasons),
    );
    ensure(
      completion.state ===
        (reasons.length ? "unqualified" : "native_qualified") &&
        completion.basis === (reasons.length ? "none" : "native_reported") &&
        completion.utc === (reasons.length ? null : end!.normalization.utc),
    );
  }
  const available = completion.state !== "unqualified";
  ensure(
    (artifact !== null) === available &&
      same(result.artifact_availability, {
        state: available ? "available" : "unavailable",
        reasons: available ? [] : completion.qualification_reasons,
      }),
  );
  const cadenceReasons: string[] = [...completion.qualification_reasons];
  if (coverage.cadence_evidence === "empty")
    cadenceReasons.push("no_selected_outcome_evidence");
  if (coverage.cadence_evidence === "not_evaluated")
    cadenceReasons.push("selected_outcomes_not_evaluated");
  const slug = expected.request.cadence_slug;
  const linked = slug !== null && cadenceReasons.length === 0;
  ensure(
    same(result.cadence, {
      requested_slug: slug,
      linked_slug: linked ? slug : null,
      state: slug === null ? "not_requested" : linked ? "linked" : "ineligible",
      reasons: slug === null ? [] : cadenceReasons,
    }),
  );
  const diagnosticCodes = [
    "source_authenticity_unverified",
    "source_population_not_established",
    "complete_schema_validation_not_performed",
    ...(oval ? ["platform_validation_not_performed"] : []),
    "findings_are_summary_only",
    ...(coverage.signature_node_indices.length ? ["signature_unverified"] : []),
    ...(["thin", "mixed"].includes(coverage.native_export_detail)
      ? ["partial_export_detail"]
      : []),
    ...(unknownCount ? ["uninterpreted_content_preserved"] : []),
    ...(claim ? ["operator_completion_asserted"] : []),
    ...completion.qualification_reasons,
    ...(coverage.cadence_evidence === "empty"
      ? ["no_selected_outcome_evidence"]
      : coverage.cadence_evidence === "not_evaluated"
        ? ["selected_outcomes_not_evaluated"]
        : []),
  ];
  const diagnosticSchema = SCAP_RESPONSE_SCHEMAS.ScapDiagnostic.properties!;
  const codes = diagnosticSchema.code.enum!,
    messages = diagnosticSchema.message.enum!;
  ensure(
    same(
      result.diagnostics,
      diagnosticCodes.map((code) => ({
        code,
        severity: "advisory",
        message: messages[codes.indexOf(code)],
        node_index: null,
      })),
    ),
  );
  ensure(
    same(
      manifest.warnings,
      result.diagnostics.map((diagnostic) => diagnostic.message),
    ),
  );
  const filter = {
    source_profile: source.profile,
    source_sha256: source.sha256,
    assessment_index: a.selection.assessment_index,
    selected_node_index: selected,
    scope: "selected_assessment_native_projection",
    time_basis: "file_import_observation",
  };
  ensure(
    same(manifest.filters_applied, filter) &&
      same(manifest.source_system_ids, ["scap-source:" + source.sha256]) &&
      manifest.coverage_counts[0].scanned === a.units.length,
  );
  const frame = {
    schema_version: "scap-finding-identity-v1",
    source_sha256: source.sha256,
    source_profile: source.profile,
    assessment_index: a.selection.assessment_index,
    unit_node_index: selected,
    mapping_rule_id: "scap-assessment-summary-v1",
  };
  const sourceKey = await digest(encoder.encode(canonical(frame)));
  const findingId = await uuid5(
    "c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6",
    sourceSystem + "\0" + sourceKey,
  );
  ensure(
    same(a.finding_refs, [
      {
        node_index: selected,
        mapping_rule_id: "scap-assessment-summary-v1",
        source_key_sha256: sourceKey,
        finding_id: findingId,
      },
    ]),
  );
  const finding = result.findings[0],
    context = finding.collection_context;
  ensure(
    finding.id === findingId &&
      finding.title === title &&
      finding.source_system === sourceSystem &&
      finding.first_observed === imported &&
      finding.last_observed === imported,
  );
  ensure(
    context.run_id === manifest.run_id &&
      context.collected_at === imported &&
      context.collector_version === manifest.collector_version &&
      context.evidentia_version === manifest.evidentia_version &&
      context.source_system_id === "scap-source:" + source.sha256 &&
      same(context.filter_applied, filter),
  );
  ensure(
    same(finding.raw_data, {
      schema_version: "scap-assessment-summary-v1",
      source,
      selection: a.selection,
      visible_unit_count: a.units.length,
      selected_outcome_count: a.outcomes.length,
      top_level_outcome_count: top,
      countable_top_level_outcome_count: countable,
      summary_only: true,
      source_key_sha256: sourceKey,
    }),
  );
  if (artifact) {
    ensure(
      artifact.title === title &&
        artifact.source_system === sourceSystem &&
        artifact.collected_at === completion.utc &&
        same(artifact.tags, ["scap", oval ? "oval" : "xccdf"]),
    );
    ensure(
      same(artifact.content, {
        schema_version: "scap-evidence-v1",
        source,
        native_document: result.native_document,
        assessment: a,
        completion: {
          basis: completion.basis,
          utc: completion.utc,
          native_ref: completion.native_ref,
          assertion: completion.assertion,
        },
      }),
    );
    ensure(
      same(artifact.metadata, {
        scap_contract: "scap-evidence-v1",
        source_sha256: source.sha256,
        source_profile: source.profile,
        assessment_index: a.selection.assessment_index,
        time_basis: completion.basis,
        ...(linked ? { cadence_slug: slug } : {}),
      }),
    );
    ensure(
      artifact.content_hash ===
        (await digest(
          encoder.encode(canonical(artifact.content as unknown as Json, true)),
        )),
    );
    const withoutId = Object.fromEntries(
      Object.entries(artifact).filter(([key]) => key !== "id"),
    );
    const artifactDigest = await digest(
      encoder.encode(
        canonical({
          schema_version: "scap-artifact-identity-v1",
          artifact_without_id: withoutId,
        } as Json),
      ),
    );
    const namespace = await uuid5(
      "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
      "https://evidentiagrc.com/scap/evidence/v1",
    );
    ensure(artifact.id === (await uuid5(namespace, artifactDigest)));
  }
  const n = canonical(result.native_document as unknown as Json).length,
    assessmentBytes = canonical(a as unknown as Json).length;
  ensure(n <= NATIVE_BYTES && assessmentBytes <= ASSESSMENT_BYTES);
  const remainder = {
    ...result,
    native_document: null,
    assessment: null,
    evidence_artifact:
      artifact === null
        ? null
        : {
            ...artifact,
            content: {
              ...artifact.content,
              native_document: null,
              assessment: null,
            },
          },
  };
  const r = canonical(remainder as unknown as Json).length,
    f = canonical(result as unknown as Json).length;
  ensure(
    r <= REMAINDER_BYTES &&
      f <= SCAP_RESULT_BYTES &&
      f ===
        r +
          (artifact ? 2 : 1) * (n - 4) +
          (artifact ? 2 : 1) * (assessmentBytes - 4),
  );
}
function validateDirectives(
  coverage: ScapResult["assessment"]["coverage"],
  view: ReturnType<typeof nativeView>,
): void {
  const d = coverage.oval_directives;
  ensure(d !== null && coverage.native_export_detail !== "not_applicable");
  ensure(
    view.element(d.node_index).name.namespace_uri === OVAL &&
      view.element(d.node_index).name.local_name === "directives",
  );
  const boolean = (
    node: number,
    attribute: string,
    value: {
      present: boolean;
      value_ref: Ref | null;
      effective_value: boolean;
    },
    fallback: boolean,
  ) => {
    const index = view.attribute(node, attribute);
    ensure(value.present === index >= 0);
    if (value.present) {
      ensure(
        value.value_ref !== null &&
          value.value_ref.slot === "attribute_value" &&
          value.value_ref.node_index === node &&
          value.value_ref.attribute_index === index,
      );
      const literal = collapse(view.resolve(value.value_ref));
      ensure(
        ["true", "false", "0", "1"].includes(literal) &&
          value.effective_value === ["true", "1"].includes(literal),
      );
    } else
      ensure(value.value_ref === null && value.effective_value === fallback);
  };
  boolean(
    d.node_index,
    "include_source_definitions",
    d.include_source_definitions,
    true,
  );
  ensure(
    d.include_source_definitions.effective_value ===
      (d.embedded_definitions_node_index !== null),
  );
  if (d.embedded_definitions_node_index !== null)
    ensure(
      view.element(d.embedded_definitions_node_index).name.local_name ===
        "oval_definitions" &&
        view.element(d.embedded_definitions_node_index).name.namespace_uri ===
          "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    );
  const details = new Set<string>();
  const rules = (items: typeof d.default_rules, parent: number) => {
    ensure(items.length === 6);
    items.forEach((rule, index) => {
      const node = view.element(rule.node_index);
      ensure(
        view.parents[rule.node_index] === parent &&
          node.name.namespace_uri === OVAL &&
          rule.outcome === oOutcomes[index],
      );
      ensure(
        node.name.local_name ===
          "definition_" + rule.outcome.replaceAll(" ", "_"),
      );
      boolean(rule.node_index, "reported", rule.reported, true);
      ensure(rule.reported.present);
      if (rule.reported.effective_value)
        details.add(rule.content.effective_value);
      const attr = view.attribute(rule.node_index, "content");
      ensure(rule.content.present === attr >= 0);
      if (rule.content.present)
        ensure(
          rule.content.value_ref !== null &&
            rule.content.value_ref.node_index === rule.node_index &&
            rule.content.value_ref.attribute_index === attr &&
            rule.content.value_ref.slot === "attribute_value" &&
            collapse(view.resolve(rule.content.value_ref)) ===
              rule.content.effective_value,
        );
      else
        ensure(
          rule.content.value_ref === null &&
            rule.content.effective_value === "full",
        );
    });
  };
  rules(d.default_rules, d.node_index);
  const classes = new Set<string>();
  let previous = -1;
  for (const item of d.class_rules) {
    ensure(!classes.has(item.definition_class) && item.node_index > previous);
    classes.add(item.definition_class);
    previous = item.node_index;
    ensure(
      view.element(item.node_index).name.local_name === "class_directives" &&
        view.element(item.node_index).name.namespace_uri === OVAL &&
        item.class_ref.node_index === item.node_index &&
        item.class_ref.slot === "attribute_value" &&
        item.class_ref.attribute_index ===
          view.attribute(item.node_index, "class") &&
        collapse(view.resolve(item.class_ref)) === item.definition_class,
    );
    rules(item.rules, item.node_index);
  }
  ensure(
    coverage.native_export_detail ===
      (details.size === 0
        ? "no_reported_rules"
        : details.size === 2
          ? "mixed"
          : [...details][0]),
  );
}

export async function parseScapResponse(
  rawJson: string,
  suppliedExpected: ScapExpected,
): Promise<ScapResponse> {
  try {
    const expected = clone(suppliedExpected, 8192);
    ensure(
      object(expected) &&
        same(Object.keys(expected).sort(), [
          "request",
          "sourceBytes",
          "sourceSha256",
        ]),
    );
    const selected = request(expected.request);
    ensure(
      typeof expected.sourceSha256 === "string" &&
        /^[0-9a-f]{64}$/.test(expected.sourceSha256) &&
        expected.sourceSha256.length === 64 &&
        typeof expected.sourceBytes === "number" &&
        expected.sourceBytes >= 1 &&
        expected.sourceBytes <= SCAP_SOURCE_BYTES,
    );
    if (selected.completion_assertion)
      ensure(
        selected.completion_assertion.source_sha256 === expected.sourceSha256,
      );
    const parsed = parse(rawJson, SCAP_RESULT_BYTES);
    ensure(matches(parsed.value, SCAP_RESPONSE_SCHEMAS.ScapCollectionResult));
    const result = parsed.value as unknown as ScapResult;
    await validateResult(result, {
      request: selected,
      sourceSha256: expected.sourceSha256,
      sourceBytes: expected.sourceBytes,
    });
    ensure(parsed.artifactSpan !== null);
    return freeze({
      result,
      rawJson,
      artifactRawJson:
        result.evidence_artifact === null
          ? null
          : rawJson.slice(parsed.artifactSpan[0], parsed.artifactSpan[1]),
    });
  } catch (error) {
    if (error instanceof ScapResponseError) throw error;
    return fail();
  }
}
export async function readScapResponse(
  response: Response,
  expected: ScapExpected,
): Promise<ScapResponse> {
  let reader:
    ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | undefined;
  let completed = false;
  try {
    ensure(
      response.status === 200 &&
        /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
          response.headers.get("content-type") ?? "",
        ) &&
        response.body !== null,
    );
    reader = response.body.getReader();
    let bytes = new Uint8Array(65536);
    let size = 0;
    const typed = Object.getPrototypeOf(Uint8Array.prototype) as object;
    const tag = Object.getOwnPropertyDescriptor(
      typed,
      Symbol.toStringTag,
    )!.get!;
    const length = Object.getOwnPropertyDescriptor(typed, "byteLength")!.get!;
    const offsetOf = Object.getOwnPropertyDescriptor(typed, "byteOffset")!.get!;
    const bufferOf = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      ensure(tag.call(next.value) === "Uint8Array");
      const count: number = length.call(next.value);
      size += count;
      ensure(size <= SCAP_RESULT_BYTES);
      const buffer: ArrayBuffer = bufferOf.call(next.value),
        offset: number = offsetOf.call(next.value);
      Object.getOwnPropertyDescriptor(
        ArrayBuffer.prototype,
        "byteLength",
      )!.get!.call(buffer);
      if (size > bytes.length) {
        const nextBuffer = new Uint8Array(
          Math.min(SCAP_RESULT_BYTES, Math.max(size, bytes.length * 2)),
        );
        nextBuffer.set(bytes);
        bytes = nextBuffer;
      }
      bytes.set(new Uint8Array(buffer, offset, count), size - count);
    }
    const raw = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes.subarray(0, size));
    const result = await parseScapResponse(raw, expected);
    completed = true;
    return result;
  } catch (error) {
    if (error instanceof ScapResponseError) throw error;
    return fail();
  } finally {
    if (reader) {
      if (!completed) {
        try {
          await reader.cancel();
        } catch {
          /* A refusal remains a refusal. */
        }
      }
      reader.releaseLock();
    } else if (!completed && response.body) {
      try {
        await response.body.cancel();
      } catch {
        /* No source error text is surfaced. */
      }
    }
  }
}

export function boundedScapPreview(value: unknown, maximum = 4096): string {
  ensure(Number.isSafeInteger(maximum) && maximum >= 1 && maximum <= 16384);
  let result = "",
    bytes = 0,
    truncated = false;
  const active = new Set<object>();
  const emit = (text: string) => {
    if (truncated) return;
    for (const char of text) {
      const count = utf8(char);
      if (bytes + count > maximum) {
        truncated = true;
        return;
      }
      result += char;
      bytes += count;
    }
  };
  const quote = (text: string) => {
    emit('"');
    for (const char of text) {
      if (truncated) return;
      emit(JSON.stringify(char).slice(1, -1));
    }
    emit('"');
  };
  const visit = (item: unknown, depth: number) => {
    if (truncated) return;
    if (typeof item === "string") {
      quote(item);
      return;
    }
    if (
      item === null ||
      typeof item === "boolean" ||
      typeof item === "number"
    ) {
      emit(JSON.stringify(item));
      return;
    }
    if (typeof item !== "object" || active.has(item) || depth > 32) {
      emit("[Unavailable]");
      return;
    }
    active.add(item);
    const array = Array.isArray(item);
    emit(array ? "[" : "{");
    let index = 0;
    for (const key of Object.keys(item)) {
      if (truncated) break;
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (index++) emit(",");
      if (!array) {
        quote(key);
        emit(":");
      }
      if (!descriptor || !own(descriptor, "value")) emit("[Unavailable]");
      else visit(descriptor.value, depth + 1);
    }
    emit(array ? "]" : "}");
    active.delete(item);
  };
  if (typeof value === "string") emit(value);
  else visit(value, 0);
  return (
    result +
    (truncated ? "\n[Preview truncated; full value is in the download.]" : "")
  );
}
