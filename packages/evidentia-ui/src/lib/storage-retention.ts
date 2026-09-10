import { z } from "zod";
import type {
  StorageRetentionCollectResult,
  StorageRetentionCollectRequest,
} from "@/lib/api";

export type StorageProvider = StorageRetentionCollectRequest["provider"];
export type StorageTargetDraft = Partial<
  Record<
    | "bucket"
    | "region"
    | "expected_owner"
    | "subscription_id"
    | "resource_group"
    | "account"
    | "container",
    string
  >
>;

/** Frozen selected-resource regions, matching the collector request contract. */
export const STORAGE_S3_REGIONS = [
  "af-south-1",
  "ap-east-1",
  "ap-east-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-south-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ap-southeast-7",
  "ca-central-1",
  "ca-west-1",
  "eu-central-1",
  "eu-central-2",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "il-central-1",
  "me-central-1",
  "me-south-1",
  "mx-central-1",
  "sa-east-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
] as const;

const IP_FORM = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?![\s\S])/;
const FIELD_LABELS = {
  bucket: "bucket",
  region: "region",
  expected_owner: "expected owner",
  subscription_id: "subscription ID",
  resource_group: "resource group",
  account: "account",
  container: "container",
};
function field(
  draft: StorageTargetDraft,
  name: keyof StorageTargetDraft,
  grammar: RegExp,
  index: number,
): string {
  const value = draft[name];
  if (typeof value !== "string" || !grammar.test(value))
    throw new Error(`Target ${index + 1}: invalid ${FIELD_LABELS[name]}.`);
  return value;
}
function region(value: string): value is (typeof STORAGE_S3_REGIONS)[number] {
  return STORAGE_S3_REGIONS.some((name) => name === value);
}

/** Validate selected provider fields; normalize only the subscription UUID. */
export function buildStorageRetentionRequest(
  provider: StorageProvider,
  scopeLabel: string,
  drafts: readonly StorageTargetDraft[],
): StorageRetentionCollectRequest {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])/.test(scopeLabel))
    throw new Error(
      "Scope label must start with an ASCII letter or digit and contain at most 64 letters, digits, underscores, dots or hyphens.",
    );
  if (drafts.length < 1 || drafts.length > 20)
    throw new Error("Select 1 to 20 targets.");
  let body: StorageRetentionCollectRequest;
  const identities: string[] = [];
  if (provider === "s3") {
    const targets = drafts.map((draft, index) => {
      const bucket = field(
        draft,
        "bucket",
        /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?![\s\S])/,
        index,
      );
      if (
        bucket.includes("..") ||
        IP_FORM.test(bucket) ||
        ["xn--", "sthree-", "amzn-s3-demo-"].some((prefix) =>
          bucket.startsWith(prefix),
        ) ||
        ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"].some(
          (suffix) => bucket.endsWith(suffix),
        )
      )
        throw new Error(`Target ${index + 1}: unsupported bucket name.`);
      const selectedRegion = draft.region ?? "";
      if (!region(selectedRegion))
        throw new Error(`Target ${index + 1}: select a supported region.`);
      identities.push(`s3:${selectedRegion}:${bucket}`);
      const expected = draft.expected_owner;
      return {
        bucket,
        region: selectedRegion,
        ...(expected === undefined || expected === ""
          ? {}
          : {
              expected_owner: field(
                draft,
                "expected_owner",
                /^[0-9]{12}(?![\s\S])/,
                index,
              ),
            }),
      };
    });
    body = { provider, scope_label: scopeLabel, targets };
  } else if (provider === "azure") {
    const targets = drafts.map((draft, index) => {
      const subscription_id = field(
        draft,
        "subscription_id",
        /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![\s\S])/,
        index,
      ).toLowerCase();
      const resource_group = field(
        draft,
        "resource_group",
        /^[A-Za-z0-9_().-]{1,90}(?![\s\S])/,
        index,
      );
      const account = field(
        draft,
        "account",
        /^[a-z0-9]{3,24}(?![\s\S])/,
        index,
      );
      const container = field(
        draft,
        "container",
        /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9](?![\s\S])/,
        index,
      );
      if (resource_group.endsWith("."))
        throw new Error(
          `Target ${index + 1}: resource group cannot end with a dot.`,
        );
      if (container.includes("--"))
        throw new Error(
          `Target ${index + 1}: container cannot contain consecutive hyphens.`,
        );
      identities.push(
        `${subscription_id}/${resource_group.toLowerCase()}/${account}/${container}`,
      );
      return { subscription_id, resource_group, account, container };
    });
    body = { provider, scope_label: scopeLabel, targets };
  } else if (provider === "gcs") {
    const targets = drafts.map((draft, index) => {
      const bucket = field(
        draft,
        "bucket",
        /^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9](?![\s\S])/,
        index,
      );
      if (
        IP_FORM.test(bucket) ||
        bucket.split(".").some((label) => label.length < 1 || label.length > 63)
      )
        throw new Error(`Target ${index + 1}: unsupported bucket name.`);
      identities.push(`gcs:${bucket}`);
      return { bucket };
    });
    body = { provider, scope_label: scopeLabel, targets };
  } else {
    throw new Error("Select a supported storage provider.");
  }
  if (new Set(identities).size !== identities.length)
    throw new Error("Remove duplicate targets before collection.");
  if (new TextEncoder().encode(JSON.stringify(body)).byteLength > 65_536)
    throw new Error("The encoded request exceeds the 64 KiB size limit.");
  return body;
}

/** Parsed numbers are for structural summaries only. Export and native values use the wire text. */
export interface StorageRetentionResponse {
  readonly result: StorageRetentionCollectResult;
  readonly rawJson: string;
  readonly nativeFieldsJson: readonly (readonly (string | null)[])[];
}
export class StorageRetentionResponseError extends Error {
  constructor() {
    super(
      "The storage response is invalid or does not match the selected request.",
    );
    this.name = "StorageRetentionResponseError";
  }
}
export const STORAGE_RESULT_BYTE_LIMIT = 4_194_304;
// Native projections permit depth 32. The result/finding wrappers fit within 64.
// At most 2^21 value/key nodes can fit in the 4 MiB JSON response byte budget.
const RESULT_DEPTH_LIMIT = 64;
const RESULT_NODE_LIMIT = 2_097_152;
const failure = (): never => {
  throw new StorageRetentionResponseError();
};

/** Index exact native-field spans without converting their numeric tokens. */
export function indexStorageRetentionJson(raw: string): Map<string, string> {
  if (new TextEncoder().encode(raw).length > STORAGE_RESULT_BYTE_LIMIT)
    failure();
  let cursor = 0;
  let nodes = 0;
  const spans = new Map<string, string>();
  const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const path: (string | number)[] = [];
  const whitespace = () => {
    while (cursor < raw.length && " \t\r\n".includes(raw[cursor])) ++cursor;
  };
  const node = () => {
    if (++nodes > RESULT_NODE_LIMIT) failure();
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
          return failure();
        }
        if (typeof value !== "string" || /\p{Surrogate}/u.test(value))
          return failure();
        return value;
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
    }
    return failure();
  };
  const visit = (depth: number): void => {
    if (depth > RESULT_DEPTH_LIMIT) failure();
    node();
    whitespace();
    const start = cursor;
    const character = raw[cursor];
    if (character === "{") {
      ++cursor;
      whitespace();
      const keys = new Set<string>();
      if (raw[cursor] !== "}")
        for (;;) {
          if (raw[cursor] !== '"') failure();
          node();
          const key = string();
          if (keys.has(key)) failure();
          keys.add(key);
          whitespace();
          if (raw[cursor++] !== ":") failure();
          path.push(key);
          visit(depth + 1);
          path.pop();
          whitespace();
          if (raw[cursor] === "}") break;
          if (raw[cursor++] !== ",") failure();
          whitespace();
        }
      ++cursor;
    } else if (character === "[") {
      ++cursor;
      whitespace();
      let index = 0;
      if (raw[cursor] !== "]")
        for (;;) {
          path.push(index++);
          visit(depth + 1);
          path.pop();
          whitespace();
          if (raw[cursor] === "]") break;
          if (raw[cursor++] !== ",") failure();
          whitespace();
        }
      ++cursor;
    } else if (character === '"') {
      string();
    } else if (raw.startsWith("true", cursor)) cursor += 4;
    else if (raw.startsWith("false", cursor)) cursor += 5;
    else if (raw.startsWith("null", cursor)) cursor += 4;
    else {
      number.lastIndex = cursor;
      const match = number.exec(raw);
      if (!match || !Number.isFinite(Number(match[0]))) failure();
      cursor = number.lastIndex;
    }
    if (
      path.length === 6 &&
      path[0] === "resources" &&
      typeof path[1] === "number" &&
      path[2] === "components" &&
      typeof path[3] === "number" &&
      path[4] === "projection" &&
      path[5] === "fields"
    )
      spans.set(`${path[1]}:${path[3]}`, raw.slice(start, cursor));
  };
  visit(1);
  whitespace();
  if (cursor !== raw.length) failure();
  return spans;
}

const counter = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const clock = z
  .string()
  .regex(
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z(?![\s\S])/,
  )
  .refine((value) => {
    const date = new Date(value);
    return (
      Number.isFinite(date.getTime()) &&
      date.toISOString().slice(0, 19) === value.slice(0, 19)
    );
  });
const state = z.enum(["complete", "partial", "unavailable"]);
const jsonObject = z.record(z.string(), z.json());
const httpStatus = z.number().int().min(100).max(599).nullable();
const diagnostic = z.strictObject({
  code: z.enum([
    "configuration_missing",
    "configuration_invalid",
    "credential_unavailable",
    "credential_rejected",
    "forbidden",
    "resource_not_found",
    "unsafe_destination",
    "offline_refused",
    "redirect_refused",
    "endpoint_mismatch",
    "timeout",
    "rate_limited",
    "upstream_error",
    "invalid_response",
    "source_identity_mismatch",
    "unsupported_source_value",
    "missing_source_detail",
    "projection_limit",
    "response_limit",
    "run_budget_exhausted",
    "internal_error",
    "cleanup_failed",
    "signing_unsupported",
    "retry_after_invalid",
  ]),
  http_status: httpStatus.optional(),
});
const s3Target = z.strictObject({
  bucket: z.string(),
  region: z.string(),
  expected_owner: z.string().nullable().optional(),
});
const azureTarget = z.strictObject({
  subscription_id: z.string(),
  resource_group: z.string(),
  account: z.string(),
  container: z.string(),
});
const gcsTarget = z.strictObject({ bucket: z.string() });
const requestShape = z.discriminatedUnion("provider", [
  z.strictObject({
    provider: z.literal("s3"),
    scope_label: z.string(),
    targets: z.array(s3Target).min(1).max(20),
  }),
  z.strictObject({
    provider: z.literal("azure"),
    scope_label: z.string(),
    targets: z.array(azureTarget).min(1).max(20),
  }),
  z.strictObject({
    provider: z.literal("gcs"),
    scope_label: z.string(),
    targets: z.array(gcsTarget).min(1).max(20),
  }),
]);
export function snapshotStorageRetentionRequest(
  input: unknown,
): StorageRetentionCollectRequest {
  const parsed = requestShape.safeParse(input);
  if (!parsed.success) return failure();
  const drafts = parsed.data.targets.map((target): StorageTargetDraft => {
    if ("subscription_id" in target) return { ...target };
    if ("region" in target)
      return {
        bucket: target.bucket,
        region: target.region,
        ...(target.expected_owner == null
          ? {}
          : { expected_owner: target.expected_owner }),
      };
    return { bucket: target.bucket };
  });
  let request: StorageRetentionCollectRequest;
  try {
    request = buildStorageRetentionRequest(
      parsed.data.provider,
      parsed.data.scope_label,
      drafts,
    );
  } catch {
    return failure();
  }
  for (const target of request.targets) Object.freeze(target);
  Object.freeze(request.targets);
  return Object.freeze(request);
}
const projection = z.strictObject({
  api_version: z.string().min(1).max(128),
  projection_version: z.literal("storage-retention-projection/v1"),
  native_scope: z.string().min(1).max(256),
  fields: jsonObject,
  source_etag: z.string().max(1024).nullable().optional(),
  source_metageneration: z.string().max(128).nullable().optional(),
  canonical_projection_sha256: z.string().regex(/^[0-9a-f]{64}(?![\s\S])/),
});
const componentShape = z.strictObject({
  component_id: z.enum([
    "s3-object-lock",
    "s3-versioning",
    "azure-account",
    "azure-blob-service",
    "azure-container",
    "gcs-bucket",
  ]),
  canonical_resource_id: z.string(),
  status: state,
  attempts: counter.max(3),
  raw_bytes: counter,
  decoded_bytes: counter,
  started_at: clock.nullable(),
  finished_at: clock.nullable(),
  http_status: httpStatus,
  diagnostics: z.array(diagnostic),
  projection: projection.nullable(),
});
const contextShape = z.strictObject({
  collected_at: clock,
  collector_id: z.string(),
  collector_version: z.string(),
  credential_identity: z.string(),
  evidentia_version: z.string().optional(),
  filter_applied: jsonObject,
  pagination_context: z.null().optional(),
  run_id: z.string(),
  source_system_id: z.string(),
});
const mappingShape = z.strictObject({
  control_id: z.string(),
  control_title: z.string().nullable().optional(),
  framework: z.string(),
  justification: z.string(),
  relationship: z.enum([
    "equivalent-to",
    "equal-to",
    "subset-of",
    "superset-of",
    "intersects-with",
    "related-to",
  ]),
});
const findingShape = z.strictObject({
  collection_context: contextShape,
  compliance_status: z.enum([
    "pass",
    "fail",
    "warning",
    "not_applicable",
    "unknown",
  ]),
  control_mappings: z.array(mappingShape).optional(),
  description: z.string(),
  first_observed: clock,
  id: z.string().optional(),
  last_observed: clock,
  raw_data: jsonObject,
  remediation: z.string().nullable().optional(),
  resolved_at: z.null().optional(),
  resource_account: z.string().nullable().optional(),
  resource_id: z.string().nullable().optional(),
  resource_region: z.string().nullable().optional(),
  resource_type: z.string().nullable().optional(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  source_finding_id: z.string().nullable().optional(),
  source_system: z.string(),
  status: z.enum(["active", "resolved", "suppressed"]),
  title: z.string(),
});
const manifestShape = z.strictObject({
  collection_finished_at: clock,
  collection_started_at: clock,
  collector_id: z.string(),
  collector_version: z.string(),
  coverage_counts: z.array(
    z.strictObject({
      collected: counter,
      matched_filter: counter,
      resource_type: z.string(),
      scanned: counter,
    }),
  ),
  empty_categories: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  evidentia_version: z.string().optional(),
  filters_applied: jsonObject,
  incomplete_reason: z.string().nullable().optional(),
  is_complete: z.boolean(),
  run_id: z.string().min(1),
  source_system_ids: z.array(z.string()).optional(),
  total_findings: counter,
  warnings: z.array(z.string()).optional(),
});
// Shape validation protects rendering; Python remains authoritative for factory/digest validation.
const resultShape: z.ZodType<StorageRetentionCollectResult> = z.strictObject({
  schema_version: z.literal("storage-retention-collection/v1"),
  provider: z.enum(["s3", "azure", "gcs"]),
  scope_label: z.string(),
  status: state,
  started_at: clock,
  finished_at: clock,
  observation_scope: z.literal("configuration"),
  coverage_scope: z.literal("selected_resources"),
  object_enforcement_assessed: z.literal(false),
  recordset_completeness_assessed: z.literal(false),
  identity_basis: z.literal("operator-declared"),
  authenticated_identity_verified: z.literal(false),
  requested_resources: counter,
  attempted_resources: counter,
  planned_components: counter,
  attempted_components: counter,
  completed_components: counter,
  resources: z
    .array(
      z.strictObject({
        target: z.union([s3Target, azureTarget, gcsTarget]),
        canonical_resource_id: z.string(),
        status: state,
        components: z.array(componentShape),
      }),
    )
    .min(1)
    .max(20),
  findings: z.array(findingShape),
  diagnostics: z.array(diagnostic),
  manifest: manifestShape,
});
function isResult(value: unknown): value is StorageRetentionCollectResult {
  return resultShape.safeParse(value).success;
}
const componentsByProvider = {
  s3: ["s3-object-lock", "s3-versioning"],
  azure: ["azure-account", "azure-blob-service", "azure-container"],
  gcs: ["gcs-bucket"],
} as const;
function identity(
  target: StorageRetentionCollectResult["resources"][number]["target"],
): string {
  if ("subscription_id" in target)
    return `azure:/subscriptions/${target.subscription_id}/resourceGroups/${target.resource_group}/providers/Microsoft.Storage/storageAccounts/${target.account}/blobServices/default/containers/${target.container}`.toLowerCase();
  if ("region" in target) return `s3:${target.region}:${target.bucket}`;
  return `gcs:${target.bucket}`;
}
function equalTarget(
  expected: StorageRetentionCollectRequest["targets"][number],
  actual: StorageRetentionCollectResult["resources"][number]["target"],
): boolean {
  if ("subscription_id" in expected)
    return (
      "subscription_id" in actual &&
      expected.subscription_id === actual.subscription_id &&
      expected.resource_group === actual.resource_group &&
      expected.account === actual.account &&
      expected.container === actual.container
    );
  if ("region" in expected)
    return (
      "region" in actual &&
      expected.bucket === actual.bucket &&
      expected.region === actual.region &&
      (expected.expected_owner ?? null) === (actual.expected_owner ?? null)
    );
  return (
    !("region" in actual) &&
    !("subscription_id" in actual) &&
    expected.bucket === actual.bucket
  );
}
export function parseStorageRetentionResponse(
  rawJson: string,
  expectedInput: unknown,
): StorageRetentionResponse {
  try {
    const expected = snapshotStorageRetentionRequest(expectedInput);
    const spans = indexStorageRetentionJson(rawJson);
    const value: unknown = JSON.parse(rawJson);
    if (!isResult(value)) return failure();
    if (
      value.provider !== expected.provider ||
      value.scope_label !== expected.scope_label ||
      value.resources.length !== expected.targets.length ||
      value.requested_resources !== expected.targets.length
    )
      return failure();
    const nativeFieldsJson: (string | null)[][] = [];
    let attempted = 0;
    let completed = 0;
    let attemptedResources = 0;
    let admitted = 0;
    let evidenceResources = 0;
    const names = componentsByProvider[expected.provider];
    for (const [i, resource] of value.resources.entries()) {
      if (
        !equalTarget(expected.targets[i], resource.target) ||
        resource.canonical_resource_id !== identity(resource.target) ||
        resource.components.length !== names.length
      )
        return failure();
      const fields: (string | null)[] = [];
      let resourceAdmitted = 0;
      for (const [j, component] of resource.components.entries()) {
        if (
          component.component_id !== names[j] ||
          component.canonical_resource_id !== resource.canonical_resource_id
        )
          return failure();
        if (component.attempts > 0) ++attempted;
        const status =
          component.projection === null
            ? "unavailable"
            : component.diagnostics.length
              ? "partial"
              : "complete";
        if (
          component.status !== status ||
          (component.projection === null && component.diagnostics.length === 0)
        )
          return failure();
        if (status === "complete") ++completed;
        if (component.projection !== null) {
          ++admitted;
          ++resourceAdmitted;
          const text = spans.get(`${i}:${j}`);
          if (text === undefined) return failure();
          fields.push(text);
        } else fields.push(null);
      }
      if (resource.components.some((component) => component.attempts > 0))
        ++attemptedResources;
      if (resourceAdmitted) ++evidenceResources;
      const status = resource.components.every(
        (component) => component.status === "complete",
      )
        ? "complete"
        : resourceAdmitted
          ? "partial"
          : "unavailable";
      if (resource.status !== status) return failure();
      nativeFieldsJson.push(fields);
    }
    const status =
      value.resources.every((resource) => resource.status === "complete") &&
      value.diagnostics.length === 0
        ? "complete"
        : admitted
          ? "partial"
          : "unavailable";
    if (
      value.status !== status ||
      value.planned_components !== expected.targets.length * names.length ||
      value.attempted_components !== attempted ||
      value.completed_components !== completed ||
      value.attempted_resources !== attemptedResources ||
      value.findings.length !== evidenceResources ||
      value.manifest.total_findings !== value.findings.length ||
      value.manifest.is_complete !== (status === "complete")
    )
      return failure();
    return { result: value, rawJson, nativeFieldsJson };
  } catch {
    return failure();
  }
}

/** Read actual UTF-8 bytes, independent of Content-Length, with prompt cancellation on refusal. */
export async function readStorageRetentionResponse(
  response: Response,
  expected: unknown,
): Promise<StorageRetentionResponse> {
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
      if (size > STORAGE_RESULT_BYTE_LIMIT) return failure();
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
    return parseStorageRetentionResponse(text, expected);
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
