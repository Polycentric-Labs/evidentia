import type { components } from "@/types/openapi";
export type ReleasePollRequest = components["schemas"]["PollRequest"];
export type ReleaseSeriesRequest =
  components["schemas"]["ReleaseSeriesRequest"];
export type ReleasePollResult = components["schemas"]["PollResult"];
export type ReleaseSeriesResult = components["schemas"]["ReleaseSeriesResult"];
export interface ReleasePollResponse {
  readonly result: ReleasePollResult;
  readonly rawJson: string;
}
export interface ReleaseSeriesResponse {
  readonly result: ReleaseSeriesResult;
  readonly rawJson: string;
}
export const RELEASE_SOURCE_PROFILE =
  "github-public-releases-2026-03-10" as const;
export const RELEASE_RESULT_BYTES = 16_777_216;
export const RELEASE_REQUEST_BYTES = 4_096;
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
export class ReleaseResponseError extends Error {
  constructor(
    message = "The release input or response is invalid or does not match the requested operation.",
    readonly code: string | null = null,
    readonly status: number | null = null,
  ) {
    super(message);
    this.name = "ReleaseResponseError";
  }
}
const fail = (): never => {
  throw new ReleaseResponseError();
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
  limit = RELEASE_RESULT_BYTES,
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
function clone(value: unknown, limit = RELEASE_REQUEST_BYTES): Json {
  let count = 0;
  let charged = 0;
  const active = new Set<object>();
  function visit(item: unknown, depth: number): Json {
    ensure(++count <= 64 && depth <= 8);
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
    ensure(keys.length <= 64);
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
        ensure(++count <= 64);
        unicode(key);
        ensure(utf8(key) <= 256);
        charged += asciiString(key).length + 1;
      }
      if (index++) charged++;
      ensure(charged <= limit);
      const child = visit(descriptor.value, depth + 1);
      if (Array.isArray(result)) result.push(child);
      else result[key] = child;
    }
    return result;
  }
  return visit(value, 0);
}

interface Parsed {
  value: Json;
}
function parse(input: unknown, limit: number): Parsed {
  ensure(
    typeof input === "string" && input.length <= limit && utf8(input) <= limit,
  );
  const raw: string = input;
  unicode(raw);
  let cursor = 0;
  let values = 0;
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
        ensure(utf8(result) <= 4_194_304);
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
    ensure(depth <= 64 && ++values <= limit);
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
          ensure(++values <= limit && utf8(key) <= 256 && !own(result, key));
          whitespace();
          ensure(raw[cursor++] === ":");
        }
        whitespace();
        const child = value(depth + 1);
        if (array) (result as Json[]).push(child);
        else (result as Obj)[key] = child;
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
    ensure(cursor - begin <= 128);
    const result = Number(raw.slice(begin, cursor));
    ensure(Number.isSafeInteger(result) && !Object.is(result, -0));
    return result;
  }
  try {
    const result = value(0);
    whitespace();
    ensure(cursor === raw.length);
    return { value: result };
  } catch (error) {
    if (error instanceof ReleaseResponseError) throw error;
    return fail();
  }
}
export function parseReleaseJson(
  raw: unknown,
  limit = RELEASE_RESULT_BYTES,
): unknown {
  ensure(
    Number.isSafeInteger(limit) && limit >= 1 && limit <= RELEASE_RESULT_BYTES,
  );
  return freeze(parse(raw, limit).value);
}

// Exact serialization schemas exported from the accepted shared foundation.
export const RELEASE_SCHEMAS: Readonly<Record<string, Schema>> = freeze({
  DiscoveryResult: {
    additionalProperties: false,
    properties: {
      canonical_files_read: {
        maximum: 16386,
        minimum: 0,
        title: "Canonical Files Read",
        type: "integer",
      },
      child_entries_observed: {
        maximum: 32770,
        minimum: 0,
        title: "Child Entries Observed",
        type: "integer",
      },
      inventory_sha256: {
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
        title: "Inventory Sha256",
      },
      meaning: {
        const: "bounded_recorded_store_observation",
        title: "Meaning",
        type: "string",
      },
      passes: {
        maximum: 2,
        minimum: 0,
        title: "Passes",
        type: "integer",
      },
      raw_file_bytes_observed: {
        maximum: 67108865,
        minimum: 0,
        title: "Raw File Bytes Observed",
        type: "integer",
      },
      release_records_observed: {
        maximum: 2049,
        minimum: 0,
        title: "Release Records Observed",
        type: "integer",
      },
      root_entries_observed: {
        maximum: 8194,
        minimum: 0,
        title: "Root Entries Observed",
        type: "integer",
      },
      status: {
        enum: [
          "complete",
          "unavailable",
          "changed",
          "limit_exceeded",
          "record_invalid",
          "identity_conflict",
          "deadline_exceeded",
        ],
        title: "Status",
        type: "string",
      },
    },
    required: [
      "status",
      "passes",
      "root_entries_observed",
      "child_entries_observed",
      "canonical_files_read",
      "raw_file_bytes_observed",
      "release_records_observed",
      "inventory_sha256",
      "meaning",
    ],
    title: "DiscoveryResult",
    type: "object",
  },
  DiscoverySummary: {
    additionalProperties: false,
    properties: {
      canonical_files_read: {
        maximum: 16386,
        minimum: 0,
        title: "Canonical Files Read",
        type: "integer",
      },
      child_entries_observed: {
        maximum: 32770,
        minimum: 0,
        title: "Child Entries Observed",
        type: "integer",
      },
      conflicting_events: {
        anyOf: [
          {
            maximum: 1024,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Conflicting Events",
      },
      inventory_sha256: {
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
        title: "Inventory Sha256",
      },
      passes: {
        maximum: 2,
        minimum: 0,
        title: "Passes",
        type: "integer",
      },
      raw_file_bytes_observed: {
        maximum: 67108865,
        minimum: 0,
        title: "Raw File Bytes Observed",
        type: "integer",
      },
      release_record_reads_observed: {
        maximum: 2049,
        minimum: 0,
        title: "Release Record Reads Observed",
        type: "integer",
      },
      root_entries_observed: {
        maximum: 8194,
        minimum: 0,
        title: "Root Entries Observed",
        type: "integer",
      },
      selected_scope_records: {
        anyOf: [
          {
            maximum: 1024,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Selected Scope Records",
      },
      status: {
        enum: [
          "not_requested",
          "not_started",
          "complete",
          "unavailable",
          "changed",
          "limit_exceeded",
          "record_invalid",
          "identity_conflict",
          "deadline_exceeded",
          "cancelled",
        ],
        title: "Status",
        type: "string",
      },
    },
    required: [
      "status",
      "passes",
      "root_entries_observed",
      "child_entries_observed",
      "canonical_files_read",
      "raw_file_bytes_observed",
      "release_record_reads_observed",
      "inventory_sha256",
      "selected_scope_records",
      "conflicting_events",
    ],
    title: "DiscoverySummary",
    type: "object",
  },
  EventGroup: {
    additionalProperties: false,
    properties: {
      blocks_all_published: {
        anyOf: [
          {
            type: "boolean",
          },
          {
            type: "null",
          },
        ],
        title: "Blocks All Published",
      },
      blocks_full_releases: {
        anyOf: [
          {
            type: "boolean",
          },
          {
            type: "null",
          },
        ],
        title: "Blocks Full Releases",
      },
      current_vs_parent: {
        anyOf: [
          {
            $ref: "#/$defs/FactComparison",
          },
          {
            type: "null",
          },
        ],
      },
      event_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Event Id",
        type: "string",
      },
      event_index: {
        maximum: 999,
        minimum: 0,
        title: "Event Index",
        type: "integer",
      },
      known_observation_count: {
        anyOf: [
          {
            maximum: 1023,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Known Observation Count",
      },
      observation_outcome_index: {
        anyOf: [
          {
            maximum: 1999,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Observation Outcome Index",
      },
      occurrence_count: {
        maximum: 1000,
        minimum: 1,
        title: "Occurrence Count",
        type: "integer",
      },
      publication_outcome_index: {
        anyOf: [
          {
            maximum: 1999,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Publication Outcome Index",
      },
      release_id: {
        maximum: 9007199254740991,
        minimum: 1,
        title: "Release Id",
        type: "integer",
      },
      representative_row_index: {
        maximum: 999,
        minimum: 0,
        title: "Representative Row Index",
        type: "integer",
      },
      stored_state: {
        enum: ["not_observed", "absent", "verified", "conflict", "unavailable"],
        title: "Stored State",
        type: "string",
      },
      stored_union_change_codes: {
        items: {
          enum: [
            "non_cadence_facts_changed",
            "publication_literal_changed",
            "node_id_changed",
            "publication_instant_changed",
            "publication_time_unqualified",
            "draft_changed_to_true",
            "prerelease_changed",
          ],
          type: "string",
        },
        maxItems: 7,
        minItems: 0,
        title: "Stored Union Change Codes",
        type: "array",
      },
    },
    required: [
      "event_index",
      "event_id",
      "release_id",
      "representative_row_index",
      "occurrence_count",
      "stored_state",
      "known_observation_count",
      "current_vs_parent",
      "stored_union_change_codes",
      "blocks_full_releases",
      "blocks_all_published",
      "publication_outcome_index",
      "observation_outcome_index",
    ],
    title: "EventGroup",
    type: "object",
  },
  FactComparison: {
    additionalProperties: false,
    properties: {
      blocks_all_published: {
        title: "Blocks All Published",
        type: "boolean",
      },
      blocks_full_releases: {
        title: "Blocks Full Releases",
        type: "boolean",
      },
      change_codes: {
        items: {
          enum: [
            "non_cadence_facts_changed",
            "publication_literal_changed",
            "node_id_changed",
            "publication_instant_changed",
            "publication_time_unqualified",
            "draft_changed_to_true",
            "prerelease_changed",
          ],
          type: "string",
        },
        maxItems: 7,
        minItems: 0,
        title: "Change Codes",
        type: "array",
      },
      changed_fields: {
        items: {
          enum: [
            "id",
            "node_id",
            "url",
            "html_url",
            "tag_name",
            "target_commitish",
            "name",
            "draft",
            "prerelease",
            "immutable",
            "created_at",
            "published_at",
            "updated_at",
          ],
          type: "string",
        },
        maxItems: 13,
        minItems: 0,
        title: "Changed Fields",
        type: "array",
      },
    },
    required: [
      "changed_fields",
      "change_codes",
      "blocks_full_releases",
      "blocks_all_published",
    ],
    title: "FactComparison",
    type: "object",
  },
  LocalSaveOutcome: {
    additionalProperties: false,
    properties: {
      candidate_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Candidate Id",
        type: "string",
      },
      candidate_selected_facts_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Candidate Selected Facts Sha256",
        type: "string",
      },
      event_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Event Id",
        type: "string",
      },
      local_state: {
        enum: [
          "local_verified",
          "local_absent",
          "local_conflict",
          "local_indeterminate",
          "not_attempted",
        ],
        title: "Local State",
        type: "string",
      },
      mirror_outcome: {
        const: "unobserved",
        title: "Mirror Outcome",
        type: "string",
      },
      outcome: {
        enum: [
          "created",
          "already_saved",
          "existing_different_facts",
          "present_after_uncertain_save",
          "not_applicable",
          "not_attempted",
          "failed",
          "indeterminate",
          "conflict",
        ],
        title: "Outcome",
        type: "string",
      },
      planned_action: {
        enum: [
          "reuse_publication",
          "create_publication",
          "create_observation",
          "conditional_observation",
        ],
        title: "Planned Action",
        type: "string",
      },
      reason: {
        anyOf: [
          {
            enum: [
              "publication_not_eligible",
              "observation_not_needed",
              "known_parent_absent",
              "save_failed",
              "save_readback_mismatch",
              "store_record_invalid",
              "store_identity_conflict",
              "store_digest_conflict",
              "store_parent_missing",
              "store_parent_conflict",
              "store_changed",
              "store_unavailable",
              "store_limit_exceeded",
              "deadline_exceeded",
              "cancelled",
            ],
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Reason",
      },
      record_kind: {
        enum: ["release_publication", "release_source_observation"],
        title: "Record Kind",
        type: "string",
      },
      save_call: {
        enum: ["not_called", "returned_created", "returned_collided", "raised"],
        title: "Save Call",
        type: "string",
      },
      verified_record: {
        anyOf: [
          {
            $ref: "#/$defs/StoredRecordReference",
          },
          {
            type: "null",
          },
        ],
      },
    },
    required: [
      "record_kind",
      "event_id",
      "candidate_id",
      "candidate_selected_facts_sha256",
      "planned_action",
      "save_call",
      "outcome",
      "local_state",
      "verified_record",
      "mirror_outcome",
      "reason",
    ],
    title: "LocalSaveOutcome",
    type: "object",
  },
  OutcomeCounts: {
    additionalProperties: false,
    properties: {
      already_saved: {
        maximum: 2000,
        minimum: 0,
        title: "Already Saved",
        type: "integer",
      },
      conflict: {
        maximum: 2000,
        minimum: 0,
        title: "Conflict",
        type: "integer",
      },
      created: {
        maximum: 2000,
        minimum: 0,
        title: "Created",
        type: "integer",
      },
      existing_different_facts: {
        maximum: 2000,
        minimum: 0,
        title: "Existing Different Facts",
        type: "integer",
      },
      failed: {
        maximum: 2000,
        minimum: 0,
        title: "Failed",
        type: "integer",
      },
      indeterminate: {
        maximum: 2000,
        minimum: 0,
        title: "Indeterminate",
        type: "integer",
      },
      not_applicable: {
        maximum: 2000,
        minimum: 0,
        title: "Not Applicable",
        type: "integer",
      },
      not_attempted: {
        maximum: 2000,
        minimum: 0,
        title: "Not Attempted",
        type: "integer",
      },
      present_after_uncertain_save: {
        maximum: 2000,
        minimum: 0,
        title: "Present After Uncertain Save",
        type: "integer",
      },
    },
    required: [
      "created",
      "already_saved",
      "existing_different_facts",
      "present_after_uncertain_save",
      "not_applicable",
      "not_attempted",
      "failed",
      "indeterminate",
      "conflict",
    ],
    title: "OutcomeCounts",
    type: "object",
  },
  PageLedger: {
    additionalProperties: false,
    properties: {
      admitted: {
        title: "Admitted",
        type: "boolean",
      },
      decoded_body_complete: {
        title: "Decoded Body Complete",
        type: "boolean",
      },
      decoded_body_sha256: {
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
        title: "Decoded Body Sha256",
      },
      decoded_bytes_observed: {
        maximum: 4259840,
        minimum: 0,
        title: "Decoded Bytes Observed",
        type: "integer",
      },
      decoded_row_count: {
        anyOf: [
          {
            maximum: 131071,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Decoded Row Count",
      },
      first_page: {
        anyOf: [
          {
            maximum: 9007199254740991,
            minimum: 1,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "First Page",
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
        title: "Http Status",
      },
      json_depth_observed: {
        anyOf: [
          {
            maximum: 65,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Json Depth Observed",
      },
      json_value_key_occurrences: {
        anyOf: [
          {
            maximum: 131073,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Json Value Key Occurrences",
      },
      last_page: {
        anyOf: [
          {
            maximum: 9007199254740991,
            minimum: 1,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Last Page",
      },
      link_state: {
        enum: ["absent", "valid", "invalid", "unavailable"],
        title: "Link State",
        type: "string",
      },
      link_values_sha256: {
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
        title: "Link Values Sha256",
      },
      next_page: {
        anyOf: [
          {
            maximum: 9007199254740991,
            minimum: 1,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Next Page",
      },
      page_index: {
        maximum: 9,
        minimum: 0,
        title: "Page Index",
        type: "integer",
      },
      page_number: {
        maximum: 9007199254740991,
        minimum: 1,
        title: "Page Number",
        type: "integer",
      },
      page_ordinal: {
        maximum: 10,
        minimum: 1,
        title: "Page Ordinal",
        type: "integer",
      },
      previous_page: {
        anyOf: [
          {
            maximum: 9007199254740991,
            minimum: 1,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Previous Page",
      },
      raw_body_complete: {
        title: "Raw Body Complete",
        type: "boolean",
      },
      raw_body_sha256: {
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
        title: "Raw Body Sha256",
      },
      raw_bytes_observed: {
        maximum: 4259840,
        minimum: 0,
        title: "Raw Bytes Observed",
        type: "integer",
      },
      reason: {
        anyOf: [
          {
            enum: [
              "offline_refused",
              "destination_refused",
              "dns_failure",
              "tls_failure",
              "connection_failure",
              "timeout",
              "cleanup_failure",
              "dependency_unavailable",
              "dependency_broken",
              "invalid_response",
              "unsupported_media",
              "unsupported_encoding",
              "unsupported_link",
              "page_limit",
              "row_limit",
              "raw_limit",
              "decoded_limit",
              "json_syntax",
              "json_depth",
              "json_count",
              "json_scalar",
              "source_field",
              "source_conflict",
              "selected_limit",
              "result_limit",
              "clock_invalid",
              "deadline_exceeded",
              "cancelled",
              "redirect_refused",
              "upstream_unauthorized",
              "upstream_forbidden",
              "upstream_not_found",
              "upstream_rate_limited",
              "upstream_server_error",
              "upstream_http_error",
              "store_record_invalid",
              "store_identity_conflict",
              "store_digest_conflict",
              "store_parent_missing",
              "store_parent_conflict",
              "store_changed",
              "store_unavailable",
              "store_limit_exceeded",
              "publication_not_eligible",
              "observation_not_needed",
              "known_parent_absent",
              "save_failed",
              "save_readback_mismatch",
            ],
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Reason",
      },
      retrieved_at: {
        anyOf: [
          {
            maxLength: 27,
            minLength: 27,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Retrieved At",
      },
      row_count: {
        maximum: 100,
        minimum: 0,
        title: "Row Count",
        type: "integer",
      },
      row_start: {
        anyOf: [
          {
            maximum: 1000,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Row Start",
      },
    },
    required: [
      "page_index",
      "page_ordinal",
      "page_number",
      "http_status",
      "retrieved_at",
      "raw_bytes_observed",
      "decoded_bytes_observed",
      "raw_body_complete",
      "decoded_body_complete",
      "raw_body_sha256",
      "decoded_body_sha256",
      "link_state",
      "link_values_sha256",
      "first_page",
      "previous_page",
      "next_page",
      "last_page",
      "json_value_key_occurrences",
      "json_depth_observed",
      "decoded_row_count",
      "admitted",
      "row_start",
      "row_count",
      "reason",
    ],
    title: "PageLedger",
    type: "object",
  },
  PersistenceSummary: {
    additionalProperties: false,
    properties: {
      attempted_calls: {
        maximum: 2000,
        minimum: 0,
        title: "Attempted Calls",
        type: "integer",
      },
      last_attempted_slot: {
        anyOf: [
          {
            maximum: 1999,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Last Attempted Slot",
      },
      mirror_outcome: {
        const: "unobserved",
        title: "Mirror Outcome",
        type: "string",
      },
      outcome_counts: {
        $ref: "#/$defs/OutcomeCounts",
      },
      planned_slots: {
        maximum: 2000,
        minimum: 0,
        title: "Planned Slots",
        type: "integer",
      },
      requested: {
        title: "Requested",
        type: "boolean",
      },
      state: {
        enum: [
          "not_requested",
          "not_started",
          "complete",
          "partial",
          "indeterminate",
        ],
        title: "State",
        type: "string",
      },
      stop_reason: {
        anyOf: [
          {
            enum: [
              "offline_refused",
              "destination_refused",
              "dns_failure",
              "tls_failure",
              "connection_failure",
              "timeout",
              "cleanup_failure",
              "dependency_unavailable",
              "dependency_broken",
              "invalid_response",
              "unsupported_media",
              "unsupported_encoding",
              "unsupported_link",
              "page_limit",
              "row_limit",
              "raw_limit",
              "decoded_limit",
              "json_syntax",
              "json_depth",
              "json_count",
              "json_scalar",
              "source_field",
              "source_conflict",
              "selected_limit",
              "result_limit",
              "clock_invalid",
              "deadline_exceeded",
              "cancelled",
              "redirect_refused",
              "upstream_unauthorized",
              "upstream_forbidden",
              "upstream_not_found",
              "upstream_rate_limited",
              "upstream_server_error",
              "upstream_http_error",
              "store_record_invalid",
              "store_identity_conflict",
              "store_digest_conflict",
              "store_parent_missing",
              "store_parent_conflict",
              "store_changed",
              "store_unavailable",
              "store_limit_exceeded",
              "publication_not_eligible",
              "observation_not_needed",
              "known_parent_absent",
              "save_failed",
              "save_readback_mismatch",
            ],
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Stop Reason",
      },
    },
    required: [
      "requested",
      "state",
      "planned_slots",
      "attempted_calls",
      "last_attempted_slot",
      "outcome_counts",
      "stop_reason",
      "mirror_outcome",
    ],
    title: "PersistenceSummary",
    type: "object",
  },
  PollCounters: {
    additionalProperties: false,
    properties: {
      attempts: {
        maximum: 10,
        minimum: 0,
        title: "Attempts",
        type: "integer",
      },
      decoded_entity_bytes_observed: {
        maximum: 16842752,
        minimum: 0,
        title: "Decoded Entity Bytes Observed",
        type: "integer",
      },
      pages_admitted: {
        maximum: 10,
        minimum: 0,
        title: "Pages Admitted",
        type: "integer",
      },
      raw_entity_bytes_observed: {
        maximum: 16842752,
        minimum: 0,
        title: "Raw Entity Bytes Observed",
        type: "integer",
      },
      rows_admitted: {
        maximum: 1000,
        minimum: 0,
        title: "Rows Admitted",
        type: "integer",
      },
      selected_ccompact_bytes_admitted: {
        maximum: 8388608,
        minimum: 0,
        title: "Selected Ccompact Bytes Admitted",
        type: "integer",
      },
      targeted_raw_bytes_observed: {
        maximum: 67108865,
        minimum: 0,
        title: "Targeted Raw Bytes Observed",
        type: "integer",
      },
      targeted_record_reads: {
        maximum: 4000,
        minimum: 0,
        title: "Targeted Record Reads",
        type: "integer",
      },
      total_store_raw_bytes_observed: {
        maximum: 67108865,
        minimum: 0,
        title: "Total Store Raw Bytes Observed",
        type: "integer",
      },
      unique_source_events: {
        maximum: 1000,
        minimum: 0,
        title: "Unique Source Events",
        type: "integer",
      },
    },
    required: [
      "attempts",
      "pages_admitted",
      "rows_admitted",
      "unique_source_events",
      "raw_entity_bytes_observed",
      "decoded_entity_bytes_observed",
      "selected_ccompact_bytes_admitted",
      "targeted_record_reads",
      "targeted_raw_bytes_observed",
      "total_store_raw_bytes_observed",
    ],
    title: "PollCounters",
    type: "object",
  },
  PollRequest: {
    additionalProperties: false,
    properties: {
      channel: {
        enum: ["full_releases", "all_published"],
        title: "Channel",
        type: "string",
      },
      owner: {
        maxLength: 39,
        minLength: 0,
        pattern: "^[\\x00-\\x7f]*$",
        title: "Owner",
        type: "string",
      },
      persist: {
        title: "Persist",
        type: "boolean",
      },
      repository: {
        maxLength: 100,
        minLength: 0,
        pattern: "^[\\x00-\\x7f]*$",
        title: "Repository",
        type: "string",
      },
      schema_version: {
        const: "release-poll-request-v1",
        title: "Schema Version",
        type: "string",
      },
      source_profile: {
        const: "github-public-releases-2026-03-10",
        title: "Source Profile",
        type: "string",
      },
    },
    required: [
      "schema_version",
      "source_profile",
      "owner",
      "repository",
      "channel",
      "persist",
    ],
    title: "PollRequest",
    type: "object",
  },
  PollResult: {
    additionalProperties: false,
    properties: {
      clocks: {
        $ref: "#/$defs/RunClocks",
      },
      collection_state: {
        enum: ["complete", "partial", "unavailable"],
        title: "Collection State",
        type: "string",
      },
      counters: {
        $ref: "#/$defs/PollCounters",
      },
      discovery: {
        $ref: "#/$defs/DiscoverySummary",
      },
      events: {
        items: {
          $ref: "#/$defs/EventGroup",
        },
        maxItems: 1000,
        minItems: 0,
        title: "Events",
        type: "array",
      },
      meaning: {
        const: "visible_upstream_release_observation",
        title: "Meaning",
        type: "string",
      },
      outcomes: {
        items: {
          $ref: "#/$defs/LocalSaveOutcome",
        },
        maxItems: 2000,
        minItems: 0,
        title: "Outcomes",
        type: "array",
      },
      pages: {
        items: {
          $ref: "#/$defs/PageLedger",
        },
        maxItems: 10,
        minItems: 0,
        title: "Pages",
        type: "array",
      },
      persistence: {
        $ref: "#/$defs/PersistenceSummary",
      },
      reasons: {
        items: {
          enum: [
            "offline_refused",
            "destination_refused",
            "dns_failure",
            "tls_failure",
            "connection_failure",
            "timeout",
            "cleanup_failure",
            "dependency_unavailable",
            "dependency_broken",
            "invalid_response",
            "unsupported_media",
            "unsupported_encoding",
            "unsupported_link",
            "page_limit",
            "row_limit",
            "raw_limit",
            "decoded_limit",
            "json_syntax",
            "json_depth",
            "json_count",
            "json_scalar",
            "source_field",
            "source_conflict",
            "selected_limit",
            "result_limit",
            "clock_invalid",
            "deadline_exceeded",
            "cancelled",
            "redirect_refused",
            "upstream_unauthorized",
            "upstream_forbidden",
            "upstream_not_found",
            "upstream_rate_limited",
            "upstream_server_error",
            "upstream_http_error",
            "store_record_invalid",
            "store_identity_conflict",
            "store_digest_conflict",
            "store_parent_missing",
            "store_parent_conflict",
            "store_changed",
            "store_unavailable",
            "store_limit_exceeded",
            "publication_not_eligible",
            "observation_not_needed",
            "known_parent_absent",
            "save_failed",
            "save_readback_mismatch",
          ],
          type: "string",
        },
        maxItems: 32,
        minItems: 0,
        title: "Reasons",
        type: "array",
      },
      request: {
        $ref: "#/$defs/PollRequest",
      },
      request_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Request Sha256",
        type: "string",
      },
      rows: {
        items: {
          $ref: "#/$defs/RowOccurrence",
        },
        maxItems: 1000,
        minItems: 0,
        title: "Rows",
        type: "array",
      },
      schema_version: {
        const: "release-poll-result-v1",
        title: "Schema Version",
        type: "string",
      },
      scope: {
        $ref: "#/$defs/PollScope",
      },
      terminal_reason: {
        anyOf: [
          {
            enum: [
              "offline_refused",
              "destination_refused",
              "dns_failure",
              "tls_failure",
              "connection_failure",
              "timeout",
              "cleanup_failure",
              "dependency_unavailable",
              "dependency_broken",
              "invalid_response",
              "unsupported_media",
              "unsupported_encoding",
              "unsupported_link",
              "page_limit",
              "row_limit",
              "raw_limit",
              "decoded_limit",
              "json_syntax",
              "json_depth",
              "json_count",
              "json_scalar",
              "source_field",
              "source_conflict",
              "selected_limit",
              "result_limit",
              "clock_invalid",
              "deadline_exceeded",
              "cancelled",
              "redirect_refused",
              "upstream_unauthorized",
              "upstream_forbidden",
              "upstream_not_found",
              "upstream_rate_limited",
              "upstream_server_error",
              "upstream_http_error",
              "store_record_invalid",
              "store_identity_conflict",
              "store_digest_conflict",
              "store_parent_missing",
              "store_parent_conflict",
              "store_changed",
              "store_unavailable",
              "store_limit_exceeded",
              "publication_not_eligible",
              "observation_not_needed",
              "known_parent_absent",
              "save_failed",
              "save_readback_mismatch",
            ],
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Terminal Reason",
      },
    },
    required: [
      "schema_version",
      "request",
      "request_sha256",
      "scope",
      "clocks",
      "collection_state",
      "terminal_reason",
      "reasons",
      "counters",
      "discovery",
      "persistence",
      "rows",
      "pages",
      "events",
      "outcomes",
      "meaning",
    ],
    title: "PollResult",
    type: "object",
  },
  PollScope: {
    additionalProperties: false,
    properties: {
      canonical_owner: {
        maxLength: 39,
        minLength: 0,
        pattern: "^[\\x00-\\x7f]*$",
        title: "Canonical Owner",
        type: "string",
      },
      canonical_repository: {
        maxLength: 100,
        minLength: 0,
        pattern: "^[\\x00-\\x7f]*$",
        title: "Canonical Repository",
        type: "string",
      },
      channel: {
        enum: ["full_releases", "all_published"],
        title: "Channel",
        type: "string",
      },
      identity_version: {
        const: "evidentia.release-publication.v1",
        title: "Identity Version",
        type: "string",
      },
      source_host: {
        const: "api.github.com",
        title: "Source Host",
        type: "string",
      },
      source_profile: {
        const: "github-public-releases-2026-03-10",
        title: "Source Profile",
        type: "string",
      },
    },
    required: [
      "identity_version",
      "source_profile",
      "source_host",
      "canonical_owner",
      "canonical_repository",
      "channel",
    ],
    title: "PollScope",
    type: "object",
  },
  RecordReference: {
    additionalProperties: false,
    properties: {
      artifact_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Artifact Id",
        type: "string",
      },
      content_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Content Sha256",
        type: "string",
      },
      event_index: {
        maximum: 2047,
        minimum: 0,
        title: "Event Index",
        type: "integer",
      },
      first_observed_at: {
        maxLength: 27,
        minLength: 27,
        title: "First Observed At",
        type: "string",
      },
      record_kind: {
        enum: ["release_publication", "release_source_observation"],
        title: "Record Kind",
        type: "string",
      },
      selected_facts_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Selected Facts Sha256",
        type: "string",
      },
      stored_file_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Stored File Sha256",
        type: "string",
      },
      version: {
        const: 1,
        title: "Version",
        type: "integer",
      },
    },
    required: [
      "artifact_id",
      "record_kind",
      "event_index",
      "version",
      "selected_facts_sha256",
      "content_sha256",
      "stored_file_sha256",
      "first_observed_at",
    ],
    title: "RecordReference",
    type: "object",
  },
  ReleaseError: {
    additionalProperties: false,
    properties: {
      code: {
        enum: [
          "invalid_request",
          "request_limit_exceeded",
          "result_limit_exceeded",
          "unsupported_media",
          "support_unavailable",
          "support_broken",
          "authority_unavailable",
          "operation_failed",
          "persistence_outcome_unavailable",
        ],
        title: "Code",
        type: "string",
      },
      message: {
        enum: [
          "The release request is invalid.",
          "The release request exceeds its limit.",
          "The release result exceeds its limit.",
          "The release request media type is unsupported.",
          "Release support is unavailable.",
          "Release support failed.",
          "Release authority is unavailable.",
          "The release operation failed.",
          "The release deadline expired after a save was attempted. Persistence may have occurred. Inspect local records before retrying.",
        ],
        title: "Message",
        type: "string",
      },
      schema_version: {
        const: "release-error-v1",
        title: "Schema Version",
        type: "string",
      },
    },
    required: ["schema_version", "code", "message"],
    title: "ReleaseError",
    type: "object",
  },
  ReleaseSeriesRequest: {
    additionalProperties: false,
    properties: {
      channel: {
        enum: ["full_releases", "all_published"],
        title: "Channel",
        type: "string",
      },
      interval_days: {
        maximum: 3660,
        minimum: 1,
        title: "Interval Days",
        type: "integer",
      },
      owner: {
        maxLength: 39,
        minLength: 1,
        title: "Owner",
        type: "string",
      },
      repository: {
        maxLength: 100,
        minLength: 1,
        title: "Repository",
        type: "string",
      },
      schema_version: {
        const: "release-series-request-v1",
        title: "Schema Version",
        type: "string",
      },
      source_profile: {
        const: "github-public-releases-2026-03-10",
        title: "Source Profile",
        type: "string",
      },
      tolerance_days: {
        maximum: 3660,
        minimum: 0,
        title: "Tolerance Days",
        type: "integer",
      },
      window_end: {
        maxLength: 27,
        minLength: 20,
        title: "Window End",
        type: "string",
      },
      window_start: {
        maxLength: 27,
        minLength: 20,
        title: "Window Start",
        type: "string",
      },
    },
    required: [
      "schema_version",
      "source_profile",
      "owner",
      "repository",
      "channel",
      "window_start",
      "window_end",
      "interval_days",
      "tolerance_days",
    ],
    title: "ReleaseSeriesRequest",
    type: "object",
  },
  ReleaseSeriesResult: {
    additionalProperties: false,
    properties: {
      completed_at: {
        maxLength: 27,
        minLength: 27,
        title: "Completed At",
        type: "string",
      },
      discovery: {
        $ref: "#/$defs/DiscoveryResult",
      },
      evaluation_at: {
        maxLength: 27,
        minLength: 27,
        title: "Evaluation At",
        type: "string",
      },
      events: {
        items: {
          $ref: "#/$defs/SeriesEvent",
        },
        maxItems: 2048,
        title: "Events",
        type: "array",
      },
      gaps: {
        items: {
          $ref: "#/$defs/SeriesGap",
        },
        maxItems: 2049,
        title: "Gaps",
        type: "array",
      },
      meaning: {
        const: "recorded_upstream_publication_spacing",
        title: "Meaning",
        type: "string",
      },
      reasons: {
        items: {
          enum: [
            "gap_exceeds_allowed",
            "insufficient_events",
            "source_conflict",
            "store_unavailable",
            "store_changed",
            "store_limit_exceeded",
            "store_record_invalid",
            "store_identity_conflict",
            "deadline_exceeded",
          ],
          type: "string",
        },
        maxItems: 32,
        title: "Reasons",
        type: "array",
      },
      records: {
        items: {
          $ref: "#/$defs/RecordReference",
        },
        maxItems: 2048,
        title: "Records",
        type: "array",
      },
      request: {
        $ref: "#/$defs/ReleaseSeriesRequest",
      },
      request_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Request Sha256",
        type: "string",
      },
      schema_version: {
        const: "release-series-result-v1",
        title: "Schema Version",
        type: "string",
      },
      scope: {
        $ref: "#/$defs/SeriesScope",
      },
      state: {
        enum: [
          "continuous",
          "gapped",
          "insufficient",
          "unavailable",
          "conflict",
        ],
        title: "State",
        type: "string",
      },
    },
    required: [
      "schema_version",
      "request",
      "request_sha256",
      "scope",
      "evaluation_at",
      "completed_at",
      "discovery",
      "state",
      "reasons",
      "records",
      "events",
      "gaps",
      "meaning",
    ],
    title: "ReleaseSeriesResult",
    type: "object",
  },
  RowMetadata: {
    additionalProperties: false,
    properties: {
      eligibility_reasons: {
        items: {
          enum: [
            "draft",
            "prerelease_excluded",
            "publication_time_absent",
            "publication_time_unsupported",
            "publication_time_future",
          ],
          type: "string",
        },
        maxItems: 5,
        minItems: 0,
        title: "Eligibility Reasons",
        type: "array",
      },
      event_index: {
        maximum: 999,
        minimum: 0,
        title: "Event Index",
        type: "integer",
      },
      initial_publication_eligible: {
        title: "Initial Publication Eligible",
        type: "boolean",
      },
      page_index: {
        maximum: 9,
        minimum: 0,
        title: "Page Index",
        type: "integer",
      },
      record_index: {
        maximum: 99,
        minimum: 0,
        title: "Record Index",
        type: "integer",
      },
      row_index: {
        maximum: 999,
        minimum: 0,
        title: "Row Index",
        type: "integer",
      },
      selected_facts_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Selected Facts Sha256",
        type: "string",
      },
      source_time: {
        $ref: "#/$defs/SourceTimeView",
      },
    },
    required: [
      "row_index",
      "page_index",
      "record_index",
      "event_index",
      "selected_facts_sha256",
      "source_time",
      "initial_publication_eligible",
      "eligibility_reasons",
    ],
    title: "RowMetadata",
    type: "object",
  },
  RowOccurrence: {
    additionalProperties: false,
    properties: {
      metadata: {
        $ref: "#/$defs/RowMetadata",
      },
      selected: {
        $ref: "#/$defs/SelectedReleaseFacts",
      },
    },
    required: ["metadata", "selected"],
    title: "RowOccurrence",
    type: "object",
  },
  RunClocks: {
    additionalProperties: false,
    properties: {
      completed_at: {
        maxLength: 27,
        minLength: 27,
        title: "Completed At",
        type: "string",
      },
      poll_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Poll Id",
        type: "string",
      },
      started_at: {
        maxLength: 27,
        minLength: 27,
        title: "Started At",
        type: "string",
      },
      traversal_completed_at: {
        anyOf: [
          {
            maxLength: 27,
            minLength: 27,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Traversal Completed At",
      },
    },
    required: [
      "poll_id",
      "started_at",
      "traversal_completed_at",
      "completed_at",
    ],
    title: "RunClocks",
    type: "object",
  },
  SelectedReleaseFacts: {
    additionalProperties: false,
    properties: {
      created_at: {
        maxLength: 128,
        minLength: 0,
        title: "Created At",
        type: "string",
      },
      draft: {
        title: "Draft",
        type: "boolean",
      },
      html_url: {
        maxLength: 16384,
        minLength: 0,
        title: "Html Url",
        type: "string",
      },
      id: {
        maximum: 9007199254740991,
        minimum: 1,
        title: "Id",
        type: "integer",
      },
      immutable: {
        title: "Immutable",
        type: "boolean",
      },
      name: {
        anyOf: [
          {
            maxLength: 16384,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Name",
      },
      node_id: {
        maxLength: 16384,
        minLength: 0,
        title: "Node Id",
        type: "string",
      },
      prerelease: {
        title: "Prerelease",
        type: "boolean",
      },
      published_at: {
        anyOf: [
          {
            maxLength: 128,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Published At",
      },
      tag_name: {
        maxLength: 16384,
        minLength: 0,
        title: "Tag Name",
        type: "string",
      },
      target_commitish: {
        maxLength: 16384,
        minLength: 0,
        title: "Target Commitish",
        type: "string",
      },
      updated_at: {
        anyOf: [
          {
            maxLength: 128,
            minLength: 0,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Updated At",
      },
      url: {
        maxLength: 16384,
        minLength: 0,
        title: "Url",
        type: "string",
      },
    },
    required: [
      "id",
      "node_id",
      "url",
      "html_url",
      "tag_name",
      "target_commitish",
      "name",
      "draft",
      "prerelease",
      "created_at",
      "published_at",
    ],
    title: "SelectedReleaseFacts",
    type: "object",
  },
  SeriesEvent: {
    additionalProperties: false,
    properties: {
      eligibility: {
        enum: ["eligible", "channel_excluded", "conflict"],
        title: "Eligibility",
        type: "string",
      },
      event_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Event Id",
        type: "string",
      },
      in_window: {
        title: "In Window",
        type: "boolean",
      },
      observation_count: {
        maximum: 2047,
        minimum: 0,
        title: "Observation Count",
        type: "integer",
      },
      publication_record_index: {
        maximum: 2047,
        minimum: 0,
        title: "Publication Record Index",
        type: "integer",
      },
      published_at: {
        maxLength: 27,
        minLength: 27,
        title: "Published At",
        type: "string",
      },
      published_at_literal: {
        maxLength: 128,
        minLength: 0,
        title: "Published At Literal",
        type: "string",
      },
      reasons: {
        items: {
          enum: [
            "prerelease_excluded",
            "node_id_changed",
            "publication_instant_changed",
            "publication_time_unqualified",
            "draft_changed_to_true",
            "prerelease_changed",
          ],
          type: "string",
        },
        maxItems: 16,
        title: "Reasons",
        type: "array",
      },
      release_id: {
        maximum: 9007199254740991,
        minimum: 1,
        title: "Release Id",
        type: "integer",
      },
    },
    required: [
      "event_id",
      "release_id",
      "publication_record_index",
      "observation_count",
      "published_at_literal",
      "published_at",
      "in_window",
      "eligibility",
      "reasons",
    ],
    title: "SeriesEvent",
    type: "object",
  },
  SeriesGap: {
    additionalProperties: false,
    properties: {
      allowed_microseconds: {
        maximum: 632448000000000,
        minimum: 86400000000,
        title: "Allowed Microseconds",
        type: "integer",
      },
      boundary: {
        enum: ["start", "between", "end"],
        title: "Boundary",
        type: "string",
      },
      elapsed_microseconds: {
        maximum: 3162240000000000,
        minimum: 0,
        title: "Elapsed Microseconds",
        type: "integer",
      },
      end_at: {
        maxLength: 27,
        minLength: 27,
        title: "End At",
        type: "string",
      },
      exceeds_allowed: {
        title: "Exceeds Allowed",
        type: "boolean",
      },
      left_event_index: {
        anyOf: [
          {
            maximum: 2047,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Left Event Index",
      },
      right_event_index: {
        anyOf: [
          {
            maximum: 2047,
            minimum: 0,
            type: "integer",
          },
          {
            type: "null",
          },
        ],
        title: "Right Event Index",
      },
      start_at: {
        maxLength: 27,
        minLength: 27,
        title: "Start At",
        type: "string",
      },
    },
    required: [
      "start_at",
      "end_at",
      "left_event_index",
      "right_event_index",
      "boundary",
      "elapsed_microseconds",
      "allowed_microseconds",
      "exceeds_allowed",
    ],
    title: "SeriesGap",
    type: "object",
  },
  SeriesScope: {
    additionalProperties: false,
    properties: {
      canonical_owner: {
        maxLength: 256,
        minLength: 1,
        pattern: "^[a-z0-9._-]{1,256}$",
        title: "Canonical Owner",
        type: "string",
      },
      canonical_repository: {
        maxLength: 256,
        minLength: 1,
        pattern: "^[a-z0-9._-]{1,256}$",
        title: "Canonical Repository",
        type: "string",
      },
      channel: {
        enum: ["full_releases", "all_published"],
        title: "Channel",
        type: "string",
      },
      source_host: {
        const: "api.github.com",
        title: "Source Host",
        type: "string",
      },
      source_profile: {
        const: "github-public-releases-2026-03-10",
        title: "Source Profile",
        type: "string",
      },
    },
    required: [
      "source_profile",
      "source_host",
      "canonical_owner",
      "canonical_repository",
      "channel",
    ],
    title: "SeriesScope",
    type: "object",
  },
  SourceTimeView: {
    additionalProperties: false,
    properties: {
      classification: {
        enum: [
          "absent",
          "unsupported_syntax",
          "unsupported_year",
          "invalid_calendar",
          "unsupported_leap_second",
          "unsupported_precision",
          "utc_out_of_range",
          "normalized",
        ],
        title: "Classification",
        type: "string",
      },
      normalized_utc: {
        anyOf: [
          {
            maxLength: 27,
            minLength: 27,
            type: "string",
          },
          {
            type: "null",
          },
        ],
        title: "Normalized Utc",
      },
    },
    required: ["classification", "normalized_utc"],
    title: "SourceTimeView",
    type: "object",
  },
  StoredRecordReference: {
    additionalProperties: false,
    properties: {
      artifact_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Artifact Id",
        type: "string",
      },
      artifact_semantic_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Artifact Semantic Sha256",
        type: "string",
      },
      collected_at: {
        maxLength: 27,
        minLength: 27,
        title: "Collected At",
        type: "string",
      },
      content_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Content Sha256",
        type: "string",
      },
      event_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "Event Id",
        type: "string",
      },
      first_observation_poll_id: {
        maxLength: 36,
        minLength: 36,
        pattern:
          "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        title: "First Observation Poll Id",
        type: "string",
      },
      first_observed_at: {
        maxLength: 27,
        minLength: 27,
        title: "First Observed At",
        type: "string",
      },
      record_kind: {
        enum: ["release_publication", "release_source_observation"],
        title: "Record Kind",
        type: "string",
      },
      relative_path: {
        maxLength: 44,
        minLength: 44,
        pattern: "^[0-9a-f-]{36}/v1\\.json$",
        title: "Relative Path",
        type: "string",
      },
      selected_facts_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Selected Facts Sha256",
        type: "string",
      },
      stored_file_bytes: {
        maximum: 131072,
        minimum: 1,
        title: "Stored File Bytes",
        type: "integer",
      },
      stored_file_sha256: {
        maxLength: 64,
        minLength: 64,
        pattern: "^[0-9a-f]{64}$",
        title: "Stored File Sha256",
        type: "string",
      },
      verified_at: {
        maxLength: 27,
        minLength: 27,
        title: "Verified At",
        type: "string",
      },
      version: {
        const: 1,
        title: "Version",
        type: "integer",
      },
    },
    required: [
      "record_kind",
      "artifact_id",
      "event_id",
      "version",
      "relative_path",
      "content_sha256",
      "selected_facts_sha256",
      "artifact_semantic_sha256",
      "stored_file_sha256",
      "stored_file_bytes",
      "collected_at",
      "first_observation_poll_id",
      "verified_at",
      "first_observed_at",
    ],
    title: "StoredRecordReference",
    type: "object",
  },
} as unknown as Record<string, Schema>);

function matches(value: Json, schema: Schema): boolean {
  if (schema.$ref) {
    const name = schema.$ref.slice(schema.$ref.lastIndexOf("/") + 1);
    return own(RELEASE_SCHEMAS, name) && matches(value, RELEASE_SCHEMAS[name]);
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
      !Object.is(value, -0) &&
      value >= (schema.minimum ?? schema.ge ?? -Number.MAX_SAFE_INTEGER) &&
      value <= (schema.maximum ?? schema.le ?? Number.MAX_SAFE_INTEGER)
    );
  if (schema.type === "string" || (!schema.type && typeof value === "string")) {
    if (typeof value !== "string") return false;
    const size = utf8(value);
    return (
      size >= (schema.minLength ?? 0) &&
      size <= (schema.maxLength ?? 4_194_304) &&
      (!schema.pattern ||
        new RegExp(schema.pattern.replace(/\$$/, "(?![\\s\\S])"), "u").test(
          value,
        ))
    );
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
const monthDays = (y: number, m: number) =>
  m === 2
    ? y % 400 === 0 || (y % 4 === 0 && y % 100 !== 0)
      ? 29
      : 28
    : [4, 6, 9, 11].includes(m)
      ? 30
      : 31;
function calendar(
  y: number,
  m: number,
  d: number,
  h: number,
  min: number,
  s: number,
): boolean {
  return (
    y >= 1 &&
    y <= 9999 &&
    m >= 1 &&
    m <= 12 &&
    d >= 1 &&
    d <= monthDays(y, m) &&
    h <= 23 &&
    min <= 59 &&
    s <= 59
  );
}
function micro(
  y: number,
  m: number,
  d: number,
  h: number,
  min: number,
  s: number,
  f: string,
): bigint {
  const date = new Date(0);
  date.setUTCFullYear(y, m - 1, d);
  date.setUTCHours(h, min, s, 0);
  return BigInt(date.getTime()) * 1000n + BigInt(f.padEnd(6, "0") || "0");
}
function normalizedTime(
  value: Json,
  required = true,
): { text: string; micros: bigint } {
  ensure(typeof value === "string");
  const m =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(
      value,
    );
  ensure(m && m[0] === value);
  const [y, mon, d, h, min, s] = m.slice(1, 7).map(Number);
  ensure(calendar(y, mon, d, h, min, s));
  const text = value.slice(0, 19) + "." + (m[7] ?? "").padEnd(6, "0") + "Z";
  ensure(!required || text === value);
  return { text, micros: micro(y, mon, d, h, min, s, m[7] ?? "") };
}
function classify(value: Json): Obj {
  const result = (
    classification: string,
    normalized_utc: string | null = null,
  ): Obj => ({ classification, normalized_utc });
  if (value === null) return result("absent");
  ensure(typeof value === "string");
  const m =
    /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!m || m[0] !== value) return result("unsupported_syntax");
  const [y, mon, d, h, min, s] = m.slice(1, 7).map(Number),
    zone = m[8],
    oh = zone.length === 1 ? 0 : Number(zone.slice(1, 3)),
    om = zone.length === 1 ? 0 : Number(zone.slice(4));
  if (h > 23 || min > 59 || s > 60 || oh > 23 || om > 59)
    return result("unsupported_syntax");
  if (y === 0) return result("unsupported_year");
  if (!calendar(y, mon, d, h, min, Math.min(s, 59)))
    return result("invalid_calendar");
  if (s === 60) return result("unsupported_leap_second");
  if ((m[7] ?? "").length > 6) return result("unsupported_precision");
  const valueMicro =
    micro(y, mon, d, h, min, s, m[7] ?? "") -
    BigInt((oh * 60 + om) * (zone[0] === "-" ? -1 : 1)) * 60_000_000n;
  if (
    valueMicro < micro(1, 1, 1, 0, 0, 0, "") ||
    valueMicro > micro(9999, 12, 31, 23, 59, 59, "999999")
  )
    return result("utc_out_of_range");
  const sec =
      valueMicro >= 0n
        ? valueMicro / 1_000_000n
        : (valueMicro - 999999n) / 1_000_000n,
    fraction = valueMicro - sec * 1_000_000n;
  const text =
    new Date(Number(sec * 1000n)).toISOString().slice(0, 19) +
    "." +
    String(fraction).padStart(6, "0") +
    "Z";
  return result("normalized", text);
}
function repository(value: Obj): void {
  ensure(
    typeof value.owner === "string" &&
      /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value.owner) &&
      !value.owner.endsWith("\n"),
  );
  ensure(
    typeof value.repository === "string" &&
      /^[A-Za-z0-9_.-]{1,100}$/.test(value.repository) &&
      !value.repository.endsWith("\n") &&
      !value.repository.toLowerCase().endsWith(".git") &&
      ![".", ".."].includes(value.repository),
  );
}
function request(value: unknown, series: boolean): Obj {
  const copied = clone(value);
  ensure(
    object(copied) &&
      matches(
        copied,
        RELEASE_SCHEMAS[series ? "ReleaseSeriesRequest" : "PollRequest"],
      ),
  );
  repository(copied);
  canonical(copied, false, RELEASE_REQUEST_BYTES);
  if (series) {
    const a = normalizedTime(copied.window_start, false).micros,
      b = normalizedTime(copied.window_end, false).micros;
    ensure(a < b && b - a <= 36_600n * 86_400_000_000n);
  }
  return freeze(copied);
}
export function snapshotReleasePollRequest(value: unknown): ReleasePollRequest {
  return request(value, false) as unknown as ReleasePollRequest;
}
export function snapshotReleaseSeriesRequest(
  value: unknown,
): ReleaseSeriesRequest {
  return request(value, true) as unknown as ReleaseSeriesRequest;
}
async function digest(value: string, algorithm = "SHA-256"): Promise<string> {
  const bytes = await crypto.subtle.digest(algorithm, encoder.encode(value));
  return Array.from(new Uint8Array(bytes), (n) =>
    n.toString(16).padStart(2, "0"),
  ).join("");
}
async function uuid5(namespace: string, name: string): Promise<string> {
  const ns = new Uint8Array(
    namespace
      .replaceAll("-", "")
      .match(/../g)!
      .map((x) => parseInt(x, 16)),
  );
  const text = encoder.encode(name),
    bytes = new Uint8Array(16 + text.length);
  bytes.set(ns);
  bytes.set(text, 16);
  const raw = new Uint8Array(await crypto.subtle.digest("SHA-1", bytes)).slice(
    0,
    16,
  );
  raw[6] = (raw[6] & 15) | 80;
  raw[8] = (raw[8] & 63) | 128;
  const hex = Array.from(raw, (n) => n.toString(16).padStart(2, "0")).join("");
  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20)
  );
}
const FIELDS = [
  "id",
  "node_id",
  "url",
  "html_url",
  "tag_name",
  "target_commitish",
  "name",
  "draft",
  "prerelease",
  "immutable",
  "created_at",
  "published_at",
  "updated_at",
];
const CHANGES = [
  "non_cadence_facts_changed",
  "publication_literal_changed",
  "node_id_changed",
  "publication_instant_changed",
  "publication_time_unqualified",
  "draft_changed_to_true",
  "prerelease_changed",
];
const ID_VERSION = "evidentia.release-publication.v1";
const URL_NAMESPACE = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
const OBS_NAMESPACE = "5b09e574-978a-5490-8446-a914e8a9dadf";
const eventTuple = (req: Obj, id: Json): Json[] => [
  ID_VERSION,
  "api.github.com",
  (req.owner as string).toLowerCase(),
  (req.repository as string).toLowerCase(),
  String(id),
];
const num = (v: Json) => v as number;
const obj = (v: Json) => v as Obj;
const list = (v: Json) => v as Obj[];
function ordered(values: Json, allowed: readonly string[]): boolean {
  return (
    Array.isArray(values) &&
    same(
      values,
      allowed.filter((x) => values.includes(x)),
    )
  );
}
function genericRelations(value: Json, schema: Schema): void {
  if (schema.$ref) {
    const name = schema.$ref.split("/").at(-1)!;
    const row = value as Obj;
    const limits: Record<string, number> = {
      SelectedReleaseFacts: 16384,
      SourceTimeView: 256,
      RowMetadata: 2048,
      RowOccurrence: 18432,
      PageLedger: 12288,
      EventGroup: 2048,
      FactComparison: 1024,
      LocalSaveOutcome: 2048,
      StoredRecordReference: 1536,
      DiscoverySummary: 4096,
      DiscoveryResult: 4096,
      RecordReference: 1024,
      SeriesEvent: 1536,
      SeriesGap: 768,
    };
    if (limits[name]) canonical(value, false, limits[name]);
    if (name === "SelectedReleaseFacts")
      ensure(!own(row, "immutable") || typeof row.immutable === "boolean");
    if (name === "SourceTimeView")
      ensure(
        (row.classification === "normalized") === (row.normalized_utc !== null),
      );
    if (name === "StoredRecordReference")
      ensure(row.relative_path === String(row.artifact_id) + "/v1.json");
    if (name === "FactComparison") {
      ensure(
        ordered(row.changed_fields, FIELDS) &&
          ordered(row.change_codes, CHANGES),
      );
      const codes = row.change_codes as string[],
        material = CHANGES.slice(2, 6).some((x) => codes.includes(x));
      ensure(
        row.blocks_all_published === material &&
          row.blocks_full_releases ===
            (material || codes.includes("prerelease_changed")) &&
          Boolean((row.changed_fields as Json[]).length) ===
            Boolean(codes.length),
      );
    }
    if (name === "LocalSaveOutcome") outcomeRelations(row);
    return genericRelations(value, RELEASE_SCHEMAS[name]);
  }
  if (schema.anyOf) {
    const part = schema.anyOf.find((x) => matches(value, x));
    if (part) genericRelations(value, part);
  }
  if (schema.allOf)
    for (const part of schema.allOf) genericRelations(value, part);
  if (schema.type === "object")
    for (const [key, child] of Object.entries(value as Obj)) {
      if (schema.properties?.[key])
        genericRelations(child, schema.properties[key]);
      if (
        [
          "started_at",
          "completed_at",
          "traversal_completed_at",
          "retrieved_at",
          "normalized_utc",
          "collected_at",
          "verified_at",
          "first_observed_at",
          "evaluation_at",
          "published_at",
          "start_at",
          "end_at",
        ].includes(key) &&
        child !== null &&
        schema.properties?.[key] &&
        !own(value as Obj, "node_id")
      )
        normalizedTime(child);
    }
  if (schema.type === "array" && schema.items)
    for (const child of value as Json[]) genericRelations(child, schema.items);
}
function outcomeRelations(row: Obj): void {
  const rules: Record<
    string,
    [string, string[], (string | null)[] | null, boolean | null]
  > = {
    created: ["local_verified", ["returned_created"], [null], true],
    already_saved: [
      "local_verified",
      ["not_called", "returned_collided"],
      [null],
      true,
    ],
    existing_different_facts: [
      "local_verified",
      ["returned_collided", "raised"],
      [null, "save_failed"],
      true,
    ],
    present_after_uncertain_save: [
      "local_verified",
      ["raised"],
      ["save_failed"],
      true,
    ],
    not_applicable: [
      "not_attempted",
      ["not_called"],
      [
        "publication_not_eligible",
        "observation_not_needed",
        "known_parent_absent",
      ],
      false,
    ],
    not_attempted: ["not_attempted", ["not_called"], null, false],
    failed: ["local_absent", ["raised"], ["save_failed"], false],
    indeterminate: [
      "local_indeterminate",
      ["returned_created", "returned_collided", "raised"],
      [
        "store_changed",
        "store_unavailable",
        "store_limit_exceeded",
        "deadline_exceeded",
        "cancelled",
      ],
      false,
    ],
    conflict: [
      "local_conflict",
      ["returned_created", "returned_collided", "raised"],
      [
        "save_readback_mismatch",
        "store_record_invalid",
        "store_identity_conflict",
        "store_digest_conflict",
        "store_parent_missing",
        "store_parent_conflict",
        "store_changed",
      ],
      null,
    ],
  };
  const [state, calls, reasons, recordRequired] = rules[row.outcome as string];
  ensure(
    row.local_state === state &&
      calls.includes(row.save_call as string) &&
      (reasons
        ? reasons.includes(row.reason as string | null)
        : row.reason !== null) &&
      (recordRequired === null ||
        (row.verified_record !== null) === recordRequired),
  );
  if (row.record_kind === "release_publication")
    ensure(
      row.candidate_id === row.event_id &&
        ["create_publication", "reuse_publication"].includes(
          row.planned_action as string,
        ),
    );
  else
    ensure(
      ["create_observation", "conditional_observation"].includes(
        row.planned_action as string,
      ),
    );
  if (row.planned_action === "reuse_publication")
    ensure(row.save_call === "not_called" && row.outcome === "already_saved");
  if (row.verified_record !== null) {
    const record = obj(row.verified_record);
    ensure(
      record.record_kind === row.record_kind &&
        record.artifact_id === row.candidate_id &&
        record.event_id === row.event_id,
    );
    if (
      ["created", "already_saved", "present_after_uncertain_save"].includes(
        row.outcome as string,
      )
    )
      ensure(
        record.selected_facts_sha256 === row.candidate_selected_facts_sha256,
      );
  }
  if (row.outcome === "existing_different_facts")
    ensure(
      row.record_kind === "release_publication" &&
        obj(row.verified_record).selected_facts_sha256 !==
          row.candidate_selected_facts_sha256 &&
        row.reason === (row.save_call === "raised" ? "save_failed" : null),
    );
}

async function pollRelations(value: Obj): Promise<void> {
  const req = obj(value.request),
    scope = obj(value.scope),
    clocks = obj(value.clocks);
  ensure(
    value.request_sha256 === (await digest(canonical(req))) &&
      scope.canonical_owner === (req.owner as string).toLowerCase() &&
      scope.canonical_repository === (req.repository as string).toLowerCase() &&
      scope.channel === req.channel,
  );
  const start = normalizedTime(clocks.started_at).micros,
    end = normalizedTime(clocks.completed_at).micros,
    completion = clocks.traversal_completed_at;
  const completed =
    completion === null ? null : normalizedTime(completion).micros;
  ensure(
    start <= end &&
      (completed === null || (start <= completed && completed <= end)),
  );
  const pages = list(value.pages),
    rows = list(value.rows),
    events = list(value.events),
    outcomes = list(value.outcomes);
  let raw = 0,
    decoded = 0,
    admitted = 0,
    rowCount = 0,
    lastReceipt = start;
  const emptyDigest = await digest("[]");
  for (const [index, page] of pages.entries()) {
    ensure(
      page.page_index === index &&
        page.page_ordinal === index + 1 &&
        page.page_number === index + 1,
    );
    if (index)
      ensure(
        pages[index - 1].admitted && pages[index - 1].next_page === index + 1,
      );
    raw += num(page.raw_bytes_observed);
    decoded += num(page.decoded_bytes_observed);
    for (const prefix of ["raw", "decoded"]) {
      ensure(
        page[prefix + "_body_complete"] ===
          (page[prefix + "_body_sha256"] !== null),
      );
      if (page[prefix + "_body_complete"])
        ensure(num(page[prefix + "_bytes_observed"]) <= 4_194_304);
    }
    ensure(!page.decoded_body_complete || page.raw_body_complete);
    if (page.retrieved_at !== null) {
      const instant = normalizedTime(page.retrieved_at).micros;
      ensure(
        page.decoded_body_complete &&
          lastReceipt <= instant &&
          instant <= end &&
          (completed === null || instant <= completed),
      );
      lastReceipt = instant;
    }
    const relations = [
      "first_page",
      "previous_page",
      "next_page",
      "last_page",
    ].map((k) => page[k]);
    const state = page.link_state;
    if (["absent", "invalid", "unavailable"].includes(state as string))
      ensure(relations.every((x) => x === null));
    if (state === "absent") ensure(page.link_values_sha256 === emptyDigest);
    if (state === "unavailable") ensure(page.link_values_sha256 === null);
    if (state === "valid") {
      ensure(
        page.link_values_sha256 !== null &&
          page.link_values_sha256 !== emptyDigest &&
          relations.some((x) => x !== null),
      );
      const [first, previous, next, last] = relations;
      ensure(
        (first === null || first === 1) &&
          (previous === null || (index !== 0 && previous === index)) &&
          (next === null || next === index + 2) &&
          (last === null ||
            num(last) >= Math.max(index + 1, num(next) || index + 1)) &&
          !(next === null && last !== null && num(last) > index + 1),
      );
    }
    if (page.admitted) {
      ensure(
        page.http_status === 200 &&
          page.retrieved_at !== null &&
          page.raw_body_complete &&
          page.decoded_body_complete &&
          ["absent", "valid"].includes(state as string) &&
          page.row_start === rowCount &&
          page.decoded_row_count === page.row_count &&
          page.json_value_key_occurrences !== null &&
          page.json_depth_observed !== null,
      );
      for (let pos = 0; pos < num(page.row_count); pos++) {
        ensure(rowCount + pos < rows.length);
        const md = obj(rows[rowCount + pos].metadata);
        ensure(md.page_index === index && md.record_index === pos);
      }
      rowCount += num(page.row_count);
      admitted++;
    } else
      ensure(
        page.row_start === null &&
          page.row_count === 0 &&
          index === pages.length - 1,
      );
    if (page.reason !== null)
      ensure(
        index === pages.length - 1 && page.reason === value.terminal_reason,
      );
    canonical(page, false, 12288);
  }
  ensure(rowCount === rows.length);
  const terminal = value.terminal_reason,
    collection = value.collection_state;
  if (collection === "complete")
    ensure(
      completion !== null &&
        terminal === null &&
        pages.length > 0 &&
        admitted === pages.length &&
        pages.at(-1)!.next_page === null &&
        pages.every((p) => p.reason === null),
    );
  else
    ensure(
      completion === null &&
        terminal !== null &&
        (collection === "partial") === admitted > 0,
    );
  if (terminal === "page_limit")
    ensure(
      pages.length === 10 &&
        pages.at(-1)!.admitted &&
        pages.at(-1)!.next_page === 11 &&
        pages.at(-1)!.reason === terminal,
    );
  let selectedSize = 0;
  const facts = new Map<number, string>(),
    members = new Map<number, number[]>();
  for (const [index, row] of rows.entries()) {
    const selected = obj(row.selected),
      md = obj(row.metadata),
      encoded = canonical(selected, false, 16384),
      id = num(selected.id);
    selectedSize += encoded.length;
    ensure(!facts.has(id) || facts.get(id) === encoded);
    facts.set(id, encoded);
    members.set(id, [...(members.get(id) ?? []), index]);
    const time = classify(selected.published_at),
      reasons: string[] = [];
    if (selected.draft) reasons.push("draft");
    if (req.channel === "full_releases" && selected.prerelease)
      reasons.push("prerelease_excluded");
    if (time.classification === "absent")
      reasons.push("publication_time_absent");
    else if (time.classification !== "normalized")
      reasons.push("publication_time_unsupported");
    else if (
      completed !== null &&
      normalizedTime(time.normalized_utc).micros > completed
    )
      reasons.push("publication_time_future");
    ensure(
      md.row_index === index &&
        md.selected_facts_sha256 ===
          (await digest(
            canonical(["evidentia.release-selected-facts.v1", selected]),
          )) &&
        same(md.source_time, time) &&
        same(md.eligibility_reasons, reasons) &&
        md.initial_publication_eligible ===
          (completion !== null && reasons.length === 0),
    );
    canonical({ metadata: md }, false, 2048);
  }
  ensure(selectedSize <= 8_388_608);
  const orderedIds = [...members.keys()].sort((a, b) =>
    String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0,
  );
  ensure(events.length === orderedIds.length);
  const used = new Set<number>();
  for (const [index, event] of events.entries()) {
    const id = orderedIds[index],
      positions = members.get(id)!,
      tuple = eventTuple(req, id),
      eventId = await uuid5(URL_NAMESPACE, canonical(tuple));
    ensure(
      event.event_index === index &&
        event.release_id === id &&
        event.event_id === eventId &&
        event.representative_row_index === positions[0] &&
        event.occurrence_count === positions.length &&
        positions.every((pos) => obj(rows[pos].metadata).event_index === index),
    );
    const parentSlot = event.publication_outcome_index,
      obsSlot = event.observation_outcome_index,
      sourceSha = obj(rows[positions[0]].metadata).selected_facts_sha256;
    for (const [slot, kind] of [
      [parentSlot, "release_publication"],
      [obsSlot, "release_source_observation"],
    ] as const) {
      if (slot === null) continue;
      const pos = num(slot);
      ensure(pos < outcomes.length && !used.has(pos));
      used.add(pos);
      const outcome = outcomes[pos];
      ensure(outcome.event_id === eventId && outcome.record_kind === kind);
      if (outcome.planned_action !== "reuse_publication")
        ensure(outcome.candidate_selected_facts_sha256 === sourceSha);
      if (kind === "release_source_observation")
        ensure(
          outcome.candidate_id ===
            (await uuid5(
              OBS_NAMESPACE,
              canonical([
                "evidentia.release-source-observation.v1",
                tuple,
                sourceSha,
              ]),
            )),
        );
    }
    const state = event.stored_state,
      union = event.stored_union_change_codes as string[];
    if (["not_observed", "unavailable"].includes(state as string))
      ensure(
        event.known_observation_count === null &&
          event.current_vs_parent === null &&
          union.length === 0 &&
          event.blocks_full_releases === null &&
          event.blocks_all_published === null,
      );
    else if (state === "absent")
      ensure(
        event.known_observation_count === 0 &&
          event.current_vs_parent === null &&
          union.length === 0 &&
          event.blocks_full_releases === false &&
          event.blocks_all_published === false,
      );
    if (event.current_vs_parent !== null) {
      ensure(
        parentSlot !== null &&
          outcomes[num(parentSlot)].verified_record !== null,
      );
      const parent = obj(outcomes[num(parentSlot)].verified_record),
        comparison = obj(event.current_vs_parent);
      ensure(
        (sourceSha === parent.selected_facts_sha256) ===
          ((comparison.changed_fields as Json[]).length === 0) &&
          ordered(union, CHANGES) &&
          (comparison.change_codes as string[]).every((code) =>
            union.includes(code),
          ),
      );
      const material = CHANGES.slice(2, 6).some((code) => union.includes(code));
      ensure(
        event.blocks_all_published === material &&
          event.blocks_full_releases ===
            (material || union.includes("prerelease_changed")),
      );
    } else ensure(state !== "verified");
    canonical(event, false, 2048);
  }
  ensure(used.size === outcomes.length);
  const counters = obj(value.counters),
    discovery = obj(value.discovery),
    persistence = obj(value.persistence);
  const expected: Obj = {
    attempts: pages.length,
    pages_admitted: admitted,
    rows_admitted: rows.length,
    unique_source_events: events.length,
    raw_entity_bytes_observed: raw,
    decoded_entity_bytes_observed: decoded,
    selected_ccompact_bytes_admitted: selectedSize,
    total_store_raw_bytes_observed:
      num(discovery.raw_file_bytes_observed) +
      num(counters.targeted_raw_bytes_observed),
  };
  for (const [key, number] of Object.entries(expected))
    ensure(counters[key] === number);
  const called = outcomes
      .map((o, index) => (o.save_call !== "not_called" ? index : null))
      .filter((x): x is number => x !== null),
    counts: Obj = Object.create(null) as Obj;
  for (const key of Object.keys(obj(persistence.outcome_counts)))
    counts[key] = outcomes.filter((o) => o.outcome === key).length;
  ensure(
    persistence.requested === req.persist &&
      persistence.planned_slots === outcomes.length &&
      persistence.attempted_calls === called.length &&
      persistence.last_attempted_slot === (called.at(-1) ?? null) &&
      same(persistence.outcome_counts, counts) &&
      num(counters.targeted_record_reads) <= 2 * called.length,
  );
  const state = persistence.state,
    stop = persistence.stop_reason;
  if (!req.persist)
    ensure(
      state === "not_requested" &&
        stop === null &&
        outcomes.length === 0 &&
        discovery.status === "not_requested" &&
        counters.targeted_record_reads === 0 &&
        counters.targeted_raw_bytes_observed === 0 &&
        events.every((e) => e.stored_state === "not_observed"),
    );
  else ensure(state !== "not_requested");
  if (state === "not_started")
    ensure(
      called.length === 0 &&
        stop !== null &&
        outcomes.every((o) =>
          ["already_saved", "not_attempted", "not_applicable"].includes(
            o.outcome as string,
          ),
        ),
    );
  if (state === "complete")
    ensure(
      stop === null &&
        collection === "complete" &&
        discovery.status === "complete" &&
        outcomes.every(
          (o) =>
            [
              "created",
              "already_saved",
              "existing_different_facts",
              "not_applicable",
            ].includes(o.outcome as string) && o.save_call !== "raised",
        ),
    );
  if (state === "partial")
    ensure(
      called.length > 0 &&
        stop !== null &&
        outcomes.every((o) => o.outcome !== "indeterminate"),
    );
  if (state === "indeterminate")
    ensure(
      called.length > 0 &&
        stop !== null &&
        outcomes.some((o) => o.outcome === "indeterminate"),
    );
  if (["not_requested", "not_started"].includes(discovery.status as string)) {
    for (const key of [
      "passes",
      "root_entries_observed",
      "child_entries_observed",
      "canonical_files_read",
      "raw_file_bytes_observed",
      "release_record_reads_observed",
    ])
      ensure(discovery[key] === 0);
    for (const key of [
      "inventory_sha256",
      "selected_scope_records",
      "conflicting_events",
    ])
      ensure(discovery[key] === null);
  }
  if (discovery.status === "complete")
    ensure(
      discovery.passes === 2 &&
        discovery.inventory_sha256 !== null &&
        discovery.selected_scope_records !== null &&
        discovery.conflicting_events === 0,
    );
  if (discovery.inventory_sha256 !== null) ensure(discovery.passes === 2);
  if (collection !== "complete")
    ensure(
      called.length === 0 &&
        ["not_requested", "not_started"].includes(discovery.status as string),
    );
  ensure(
    same(value.reasons, [
      ...new Set([terminal, stop].filter((x) => x !== null)),
    ]),
  );
}

async function seriesRelations(value: Obj): Promise<void> {
  const req = obj(value.request),
    scope = obj(value.scope);
  ensure(
    value.request_sha256 === (await digest(canonical(req))) &&
      same(scope, {
        source_profile: RELEASE_SOURCE_PROFILE,
        source_host: "api.github.com",
        canonical_owner: (req.owner as string).toLowerCase(),
        canonical_repository: (req.repository as string).toLowerCase(),
        channel: req.channel,
      }),
  );
  const evaluation = normalizedTime(value.evaluation_at).micros,
    completion = normalizedTime(value.completed_at).micros,
    start = normalizedTime(req.window_start, false),
    end = normalizedTime(req.window_end, false);
  ensure(end.micros <= evaluation && evaluation <= completion);
  const discovery = obj(value.discovery),
    records = list(value.records),
    events = list(value.events),
    gaps = list(value.gaps);
  if (discovery.status !== "complete") {
    const reason: Record<string, string> = {
      unavailable: "store_unavailable",
      changed: "store_changed",
      limit_exceeded: "store_limit_exceeded",
      record_invalid: "store_record_invalid",
      identity_conflict: "store_identity_conflict",
      deadline_exceeded: "deadline_exceeded",
    };
    ensure(
      value.state === "unavailable" &&
        same(value.reasons, [reason[discovery.status as string]]) &&
        records.length === 0 &&
        events.length === 0 &&
        gaps.length === 0,
    );
    return;
  }
  const seen = new Set<Json>(),
    members = events.map(() => [] as number[]),
    orders: string[][] = [];
  for (const [index, record] of records.entries()) {
    const eventIndex = num(record.event_index);
    ensure(!seen.has(record.artifact_id) && eventIndex < events.length);
    seen.add(record.artifact_id);
    members[eventIndex].push(index);
    orders.push([
      ...eventTuple(req, events[eventIndex].release_id).map(String),
      record.record_kind === "release_publication" ? "0" : "1",
      record.artifact_id as string,
    ]);
  }
  const compare = (a: string[], b: string[]) => {
    for (let i = 0; i < a.length; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  };
  ensure(same(orders, [...orders].sort(compare)));
  const eventOrders: string[][] = [];
  for (const [index, event] of events.entries()) {
    const tuple = eventTuple(req, event.release_id);
    eventOrders.push(tuple.map(String));
    ensure(event.event_id === (await uuid5(URL_NAMESPACE, canonical(tuple))));
    const pub = num(event.publication_record_index),
      positions = members[index];
    ensure(
      same(
        positions.filter(
          (p) => records[p].record_kind === "release_publication",
        ),
        [pub],
      ) &&
        records[pub].artifact_id === event.event_id &&
        event.observation_count === positions.length - 1,
    );
    const instant = normalizedTime(event.published_at).micros;
    ensure(
      classify(event.published_at_literal).normalized_utc ===
        event.published_at &&
        event.in_window === (start.micros <= instant && instant <= end.micros),
    );
    const reasons = event.reasons as string[];
    if (event.eligibility === "eligible") ensure(reasons.length === 0);
    if (event.eligibility === "channel_excluded")
      ensure(
        req.channel === "full_releases" &&
          same(reasons, ["prerelease_excluded"]),
      );
    if (event.eligibility === "conflict")
      ensure(
        reasons.length > 0 &&
          ordered(reasons, CHANGES.slice(2)) &&
          !(
            req.channel === "all_published" &&
            reasons.includes("prerelease_changed")
          ),
      );
  }
  ensure(
    same(eventOrders, [...eventOrders].sort(compare)) &&
      new Set(eventOrders.map((row) => canonical(row))).size ===
        eventOrders.length,
  );
  const selected = events
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.eligibility === "eligible" && event.in_window)
    .sort((a, b) =>
      compare(
        [a.event.published_at as string, a.event.event_id as string],
        [b.event.published_at as string, b.event.event_id as string],
      ),
    );
  let state: string;
  const expectedGaps: Obj[] = [];
  if (events.some((e) => e.eligibility === "conflict")) state = "conflict";
  else if (selected.length < 2) state = "insufficient";
  else {
    const allowed =
      BigInt(num(req.interval_days) + num(req.tolerance_days)) *
      86_400_000_000n;
    const edges: [string, string, number | null, number | null, string][] = [
      [
        start.text,
        selected[0].event.published_at as string,
        null,
        selected[0].index,
        "start",
      ],
    ];
    for (let i = 1; i < selected.length; i++)
      edges.push([
        selected[i - 1].event.published_at as string,
        selected[i].event.published_at as string,
        selected[i - 1].index,
        selected[i].index,
        "between",
      ]);
    const last = selected.at(-1)!;
    edges.push([
      last.event.published_at as string,
      end.text,
      last.index,
      null,
      "end",
    ]);
    for (const [a, b, left, right, boundary] of edges) {
      const elapsed = normalizedTime(b).micros - normalizedTime(a).micros;
      expectedGaps.push({
        start_at: a,
        end_at: b,
        left_event_index: left,
        right_event_index: right,
        boundary,
        elapsed_microseconds: Number(elapsed),
        allowed_microseconds: Number(allowed),
        exceeds_allowed: elapsed > allowed,
      });
    }
    state = expectedGaps.some((g) => g.exceeds_allowed)
      ? "gapped"
      : "continuous";
  }
  const reasons: Record<string, string[]> = {
    continuous: [],
    gapped: ["gap_exceeds_allowed"],
    insufficient: ["insufficient_events"],
    conflict: ["source_conflict"],
  };
  ensure(
    value.state === state &&
      same(value.reasons, reasons[state]) &&
      same(gaps, expectedGaps),
  );
}
const ERRORS: Readonly<Record<string, readonly [number, string]>> = {
  invalid_request: [422, "The release request is invalid."],
  request_limit_exceeded: [413, "The release request exceeds its limit."],
  result_limit_exceeded: [413, "The release result exceeds its limit."],
  unsupported_media: [415, "The release request media type is unsupported."],
  support_unavailable: [503, "Release support is unavailable."],
  support_broken: [500, "Release support failed."],
  authority_unavailable: [503, "Release authority is unavailable."],
  operation_failed: [500, "The release operation failed."],
  persistence_outcome_unavailable: [
    500,
    "The release deadline expired after a save was attempted. Persistence may have occurred. Inspect local records before retrying.",
  ],
};
async function decodedResponse(
  rawJson: unknown,
  captured: Obj,
  series: boolean,
  status = 200,
): Promise<ReleasePollResponse | ReleaseSeriesResponse> {
  try {
    const value = parse(rawJson, RELEASE_RESULT_BYTES).value;
    ensure(object(value));
    if (status !== 200) {
      if (status === 401 || status === 403)
        throw new ReleaseResponseError(
          "Release access was refused.",
          null,
          status,
        );
      ensure(matches(value, RELEASE_SCHEMAS.ReleaseError));
      const row = ERRORS[value.code as string];
      ensure(row && row[0] === status && row[1] === value.message);
      throw new ReleaseResponseError(row[1], value.code as string, status);
    }
    const schema =
      RELEASE_SCHEMAS[series ? "ReleaseSeriesResult" : "PollResult"];
    ensure(matches(value, schema) && same(value.request, captured));
    request(value.request, series);
    genericRelations(value, schema);
    ensure(rawJson === canonical(value));
    if (series) await seriesRelations(value);
    else await pollRelations(value);
    return freeze({ result: value, rawJson: rawJson as string }) as unknown as
      ReleasePollResponse | ReleaseSeriesResponse;
  } catch (error) {
    if (error instanceof ReleaseResponseError) throw error;
    return fail();
  }
}
export async function parseReleasePollResponse(
  rawJson: unknown,
  expected: unknown,
): Promise<ReleasePollResponse> {
  const captured = request(expected, false);
  return (await decodedResponse(
    rawJson,
    captured,
    false,
  )) as ReleasePollResponse;
}
export async function parseReleaseSeriesResponse(
  rawJson: unknown,
  expected: unknown,
): Promise<ReleaseSeriesResponse> {
  const captured = request(expected, true);
  return (await decodedResponse(
    rawJson,
    captured,
    true,
  )) as ReleaseSeriesResponse;
}
async function readResponse(
  response: Response,
  captured: Obj,
  series: boolean,
): Promise<ReleasePollResponse | ReleaseSeriesResponse> {
  let reader:
    ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | undefined;
  let body: ReadableStream<Uint8Array<ArrayBufferLike>> | null = null;
  let completed = false;
  try {
    const property = (name: string) =>
      Object.getOwnPropertyDescriptor(Response.prototype, name)!.get!.call(
        response,
      );
    const status: number = property("status"),
      headers: Headers = property("headers");
    body = property("body");
    const get = (name: string) => Headers.prototype.get.call(headers, name);
    ensure(
      /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
        get("content-type") ?? "",
      ) && body !== null,
    );
    const sizeHeader = get("content-length"),
      encoding = get("content-encoding");
    let expectedLength: number | null = null;
    if (sizeHeader !== null) {
      ensure(
        /^(?:0|[1-9][0-9]{0,8})$/.test(sizeHeader) &&
          !sizeHeader.endsWith("\n"),
      );
      const length = Number(sizeHeader);
      ensure(length <= RELEASE_RESULT_BYTES);
      if (encoding === null || encoding === "identity") expectedLength = length;
    }
    reader = ReadableStream.prototype.getReader.call(
      body,
    ) as ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>>;
    ensure(reader);
    let bytes = new Uint8Array(65536),
      size = 0;
    const typed = Object.getPrototypeOf(Uint8Array.prototype) as object,
      tag = Object.getOwnPropertyDescriptor(typed, Symbol.toStringTag)!.get!,
      length = Object.getOwnPropertyDescriptor(typed, "byteLength")!.get!,
      offsetOf = Object.getOwnPropertyDescriptor(typed, "byteOffset")!.get!,
      bufferOf = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
    while (true) {
      const next =
        await ReadableStreamDefaultReader.prototype.read.call(reader);
      if (next.done) break;
      ensure(tag.call(next.value) === "Uint8Array");
      const count: number = length.call(next.value);
      size += count;
      ensure(size <= RELEASE_RESULT_BYTES);
      const buffer: ArrayBuffer = bufferOf.call(next.value),
        offset: number = offsetOf.call(next.value);
      Object.getOwnPropertyDescriptor(
        ArrayBuffer.prototype,
        "byteLength",
      )!.get!.call(buffer);
      if (size > bytes.length) {
        const grown = new Uint8Array(
          Math.min(RELEASE_RESULT_BYTES, Math.max(size, bytes.length * 2)),
        );
        grown.set(bytes);
        bytes = grown;
      }
      bytes.set(new Uint8Array(buffer, offset, count), size - count);
    }
    ensure(expectedLength === null || expectedLength === size);
    const raw = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes.subarray(0, size));
    const result = await decodedResponse(raw, captured, series, status);
    completed = true;
    return result;
  } catch (error) {
    if (error instanceof ReleaseResponseError) throw error;
    return fail();
  } finally {
    if (reader) {
      if (!completed) {
        try {
          await ReadableStreamDefaultReader.prototype.cancel.call(reader);
        } catch {
          /* Preserve the original refusal. */
        }
      }
      try {
        ReadableStreamDefaultReader.prototype.releaseLock.call(reader);
      } catch {
        /* No reader cleanup error replaces the admitted result or refusal. */
      }
    } else if (body && !completed) {
      try {
        await ReadableStream.prototype.cancel.call(body);
      } catch {
        /* No upstream text is displayed. */
      }
    }
  }
}
export async function readReleasePollResponse(
  response: Response,
  expected: unknown,
): Promise<ReleasePollResponse> {
  const captured = request(expected, false);
  return (await readResponse(response, captured, false)) as ReleasePollResponse;
}
export async function readReleaseSeriesResponse(
  response: Response,
  expected: unknown,
): Promise<ReleaseSeriesResponse> {
  const captured = request(expected, true);
  return (await readResponse(
    response,
    captured,
    true,
  )) as ReleaseSeriesResponse;
}
export function releasePreview(value: unknown, maximum = 512): string {
  ensure(Number.isSafeInteger(maximum) && maximum >= 1 && maximum <= 4096);
  if (typeof value !== "string") return "";
  let text = "",
    count = 0;
  for (const char of value) {
    const bytes = utf8(char);
    if (count + bytes > maximum) return text + "…";
    text += char;
    count += bytes;
  }
  return text;
}

export function releaseFailureMessage(error: unknown): string {
  const fallback =
    "The release operation did not complete. Check the request and current authentication before retrying.";
  try {
    if (error === null || typeof error !== "object") return fallback;
    const slot = (key: string) => {
      const descriptor = Object.getOwnPropertyDescriptor(error, key);
      return descriptor && own(descriptor, "value")
        ? descriptor.value
        : undefined;
    };
    const code: unknown = slot("code"),
      status: unknown = slot("status"),
      message: unknown = slot("message");
    if (typeof code === "string" && own(ERRORS, code)) {
      const fixed = ERRORS[code];
      if (status === fixed[0] && message === fixed[1]) return fixed[1];
    }
    if (
      (status === 401 || status === 403) &&
      code === null &&
      message === "Release access was refused."
    )
      return "Release access was refused.";
    return fallback;
  } catch {
    return fallback;
  }
}
