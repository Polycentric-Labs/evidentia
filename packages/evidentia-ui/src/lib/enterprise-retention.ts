import { z } from "zod";
import type { EnterpriseRetentionCollectRequest, EnterpriseRetentionCollectResult } from "@/lib/api";

export type EnterpriseProvider = EnterpriseRetentionCollectRequest["provider"];
export const ENTERPRISE_REQUEST_BYTE_LIMIT = 65_536;
export const ENTERPRISE_RESULT_BYTE_LIMIT = 4_194_304;
const alias = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])/;
const vaultId = /^[A-Za-z0-9_-]{1,128}(?![\s\S])/;
const splunkId = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}(?![\s\S])/;
const elasticId = /^[a-z0-9.][a-z0-9_.-]{0,254}(?![\s\S])/;
const policyId = /^[A-Za-z0-9_.-]{1,255}(?![\s\S])/;
const providers = z.enum(["google-vault", "splunk-enterprise", "elastic-ilm"]);
const vaultTarget = z.strictObject({ matter_id: z.string().regex(vaultId) });
const splunkTarget = z.strictObject({ index: z.string().regex(splunkId).refine(value => !["_new", "_reload", "_all"].includes(value.toLowerCase())) });
const elasticTarget = z.strictObject({ index: z.string().regex(elasticId).refine(value => ![".", ".."].includes(value)) });
const requestShape = z.discriminatedUnion("provider", [
  z.strictObject({ provider: z.literal("google-vault"), profile_alias: z.string().regex(alias), scope_label: z.string().regex(alias), targets: z.array(vaultTarget).min(1).max(20) }),
  z.strictObject({ provider: z.literal("splunk-enterprise"), profile_alias: z.string().regex(alias), scope_label: z.string().regex(alias), targets: z.array(splunkTarget).min(1).max(20) }),
  z.strictObject({ provider: z.literal("elastic-ilm"), profile_alias: z.string().regex(alias), scope_label: z.string().regex(alias), targets: z.array(elasticTarget).min(1).max(20) }),
]);

export class EnterpriseRetentionResponseError extends Error {
  constructor() {
    super("The enterprise response is invalid or does not match the selected request.");
    this.name = "EnterpriseRetentionResponseError";
  }
}
const failure = (): never => { throw new EnterpriseRetentionResponseError(); };
const targetId = (target: { matter_id: string } | { index: string }): string => "matter_id" in target ? target.matter_id : target.index;

/** Preserve exact aliases and source names in a detached selection. */
export function snapshotEnterpriseRetentionRequest(input: unknown): EnterpriseRetentionCollectRequest {
  const parsed = requestShape.safeParse(input);
  if (!parsed.success) return failure();
  const request = parsed.data;
  if (new Set(request.targets.map(targetId)).size !== request.targets.length ||
      new TextEncoder().encode(JSON.stringify(request)).length > ENTERPRISE_REQUEST_BYTE_LIMIT) return failure();
  request.targets.forEach(Object.freeze);
  Object.freeze(request.targets);
  return Object.freeze(request);
}

export function buildEnterpriseRetentionRequest(provider: EnterpriseProvider, profileAlias: string, scopeLabel: string, ids: readonly string[]): EnterpriseRetentionCollectRequest {
  if (!alias.test(profileAlias) || !alias.test(scopeLabel)) throw new Error("Profile and scope labels must start with an ASCII letter or digit and contain at most 64 letters, digits, underscores, dots or hyphens.");
  if (ids.length < 1 || ids.length > 20) throw new Error("Select 1 to 20 unique targets.");
  try {
    return snapshotEnterpriseRetentionRequest({ provider, profile_alias: profileAlias, scope_label: scopeLabel, targets: ids.map(id => provider === "google-vault" ? { matter_id: id } : { index: id }) });
  } catch {
    throw new Error("Use unique literal matter IDs or index names supported by the selected provider. Wildcards, paths and URLs are not accepted.");
  }
}

/** Parsed numbers support structural summaries only; display and export retain wire text. */
export interface EnterpriseRetentionResponse {
  readonly result: EnterpriseRetentionCollectResult;
  readonly rawJson: string;
  readonly nativeFieldsJson: readonly (readonly string[])[];
}

export function parseEnterpriseRetentionRequest(raw: string): EnterpriseRetentionCollectRequest {
  if (new TextEncoder().encode(raw).length > ENTERPRISE_REQUEST_BYTE_LIMIT) throw new Error("The request exceeds the 64 KiB size limit.");
  try {
    indexEnterpriseRetentionJson(raw);
    return snapshotEnterpriseRetentionRequest(JSON.parse(raw));
  } catch {
    throw new Error("Provide a strict UTF-8 JSON enterprise request with a profile alias and 1 to 20 unique targets.");
  }
}

export function indexEnterpriseRetentionJson(raw: string): Map<string, string> {
  const fail = (): never => {
    throw new EnterpriseRetentionResponseError();
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
        if (typeof value !== "string" || /\p{Surrogate}/u.test(value)) return fail();
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
    const [whole, fraction = ""] = (negative ? mantissa.slice(1) : mantissa).split(".");
    const exponentDigits = exponentToken.replace(/^[+-]/, "").replace(/^0+/, "") || "0";
    if (exponentDigits.length > 19) return fail();
    const parsedExponent = BigInt((exponentToken.startsWith("-") ? "-" : "") + exponentDigits);
    const exponent = parsedExponent - BigInt(fraction.length);
    // These are the 64-bit Decimal construction bounds used by both supported Pythons.
    if (exponent < -1_999_999_999_999_999_997n || exponent > 999_999_999_999_999_999n) return fail();
    const significant = (whole + fraction).replace(/^0+/, "");
    if (!significant) return { digits: "0", exponent: 0n, negative };
    const digits = significant.replace(/0+$/, "");
    return { digits, exponent: exponent + BigInt(significant.length - digits.length), negative };
  };
  const float = (token: string): string => {
    const value = Number(token);
    if (!Number.isFinite(value)) return fail();
    const supplied = decimal(token);
    const shortest = decimal(value.toString());
    if (supplied.digits !== shortest.digits || supplied.exponent !== shortest.exponent) return fail();
    if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
    const sign = value < 0 ? "-" : "";
    const digits = shortest.digits;
    const exponent = Number(shortest.exponent);
    const scientificExponent = exponent + digits.length - 1;
    if (scientificExponent < -4 || scientificExponent >= 16) {
      const mantissa = digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "");
      const exponentSign = scientificExponent < 0 ? "-" : "+";
      return sign + mantissa + "e" + exponentSign + Math.abs(scientificExponent).toString().padStart(2, "0");
    }
    const point = digits.length + exponent;
    if (point <= 0) return sign + "0." + "0".repeat(-point) + digits;
    if (point >= digits.length) return sign + digits + "0".repeat(point - digits.length) + ".0";
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
  const visit = (parentDepth: number, inherited: Observation | null): string | null => {
    whitespace();
    const start = cursor;
    const isObservation = path.length === 4 && path[0] === "source_reads" &&
      typeof path[1] === "number" && path[2] === "observations" && typeof path[3] === "number";
    const observation = isObservation ? { parentDepth, nodes: 0, bytes: 0 } : inherited;
    node(observation);
    const character = raw[cursor];
    let canonical: string | null = null;
    if (character === "{" || character === "[") {
      const depth = parentDepth + 1;
      if (depth > 20 || (observation && depth - observation.parentDepth > 16)) return fail();
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
            if (typeof key === "string") entries.push({ key, text: JSON.stringify(key) + ":" + child });
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
          ? "{" + entries.sort((a, b) => compareKeys(a.key, b.key)).map((entry) => entry.text).join(",") + "}"
          : "[" + items.join(",") + "]";
      }
    } else {
      let text: string;
      if (character === '"') text = quoted(string());
      else if (raw.startsWith("true", cursor)) { cursor += 4; text = "true"; }
      else if (raw.startsWith("false", cursor)) { cursor += 5; text = "false"; }
      else if (raw.startsWith("null", cursor)) { cursor += 4; text = "null"; }
      else {
        number.lastIndex = cursor;
        const match = number.exec(raw);
        if (!match) return fail();
        const token = match[0];
        const kind = /[.eE]/.test(token) ? "float" : "int";
        if (kind === "int") {
          if (token.length - (token.startsWith("-") ? 1 : 0) > 128) return fail();
          text = token === "-0" ? "0" : token;
        } else text = float(token);
        cursor = number.lastIndex;
        spans.set("number:" + JSON.stringify(path), kind);
      }
      add(encoder.encode(text).length, observation);
      if (observation) canonical = text;
    }
    if (path.length === 5 && path[0] === "source_reads" && typeof path[1] === "number" &&
        path[2] === "observations" && typeof path[3] === "number" && path[4] === "fields") {
      spans.set(`${path[1]}:${path[3]}`, raw.slice(start, cursor));
    }
    if (isObservation) {
      if (canonical === null) return fail();
      spans.set(`observation:${path[1]}:${path[3]}`, raw.slice(start, cursor));
      spans.set(`canonical-observation:${path[1]}:${path[3]}`, canonical);
    }
    return canonical;
  };
  visit(0, null);
  whitespace();
  if (cursor !== raw.length) fail();
  return spans;
}

// Structural declarations from the pinned Python contract.
// Field interpretation, digest and finding-ID validation remain server-side.
const DIAGNOSTIC_CODES = ["credential_missing","credential_invalid","credential_expired","credential_resolution_failed","credential_rejected","offline_refused","destination_refused","dns_failed","transport_failed","timeout","deadline_exceeded","attempt_limit","response_limit","run_byte_limit","invalid_encoding","invalid_json","invalid_response","identity_mismatch","redirect_refused","http_denied","http_not_found","http_error","retry_after_invalid","page_limit","record_limit","token_invalid","token_repeated","projection_limit","result_limit","duplicate_conflict","policy_reference_missing","policy_reference_unsupported","policy_unavailable","upstream_error","upstream_warning","unsupported_source_value","missing_source_detail","cleanup_failed","internal_error","dependency_unavailable"] as const;
const READ_KINDS = ["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"] as const;
const METHOD_IDS = ["vault.matters.get","vault.matters.holds.list","splunk.data.indexes.get","elastic.ilm.explain_lifecycle","elastic.ilm.get_lifecycle","elastic.ilm.get_status"] as const;
const METHODS = {"vault-matter":["google-vault","v1","vault.matters.get"],"vault-holds":["google-vault","v1","vault.matters.holds.list"],"splunk-index":["splunk-enterprise","splunk-enterprise-10.4","splunk.data.indexes.get"],"elastic-explain":["elastic-ilm","elastic-stack-ilm","elastic.ilm.explain_lifecycle"],"elastic-policy":["elastic-ilm","elastic-stack-ilm","elastic.ilm.get_lifecycle"],"elastic-status":["elastic-ilm","elastic-stack-ilm","elastic.ilm.get_status"]} as const;
const NATIVE_SCOPES = {"vault-matter":"matter","vault-holds":"hold","splunk-index":"index","elastic-explain":"index","elastic-policy":"policy","elastic-status":"service"} as const;
const IDENTITY_FIELDS = {"vault-matter":"matterId","vault-holds":"holdId","splunk-index":"name","elastic-explain":"index","elastic-policy":null,"elastic-status":null} as const;
const COVERAGE_KEYS = {"vault-matter":["matterId","state"],"vault-holds":["holdId","name","corpus","updateTime","accounts","orgUnit","query"],"splunk-index":["name","datatype","disabled","frozenTimePeriodInSecs","maxTotalDataSizeMB","coldToFrozenDir","coldToFrozenScript"],"elastic-explain":["index","managed","policy","phase","action","step","failed_step","index_creation_date_millis","lifecycle_date_millis","phase_time_millis","action_time_millis","step_time_millis","phase_execution"],"elastic-policy":["version","modified_date","policy"],"elastic-status":["operation_mode"]} as const;
const ROOT_RULES = {"vault-matter":[{"source_path":["matterId"],"output_path":["matterId"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"exact_target_matter_id","shape":null,"coverage_key":"matterId","protected":true,"item_types":[]},{"source_path":["state"],"output_path":["state"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"vault_matter_state","shape":null,"coverage_key":"state","protected":false,"item_types":[]}],"vault-holds":[{"source_path":["holdId"],"output_path":["holdId"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"nonblank_utf8_max_1024","shape":null,"coverage_key":"holdId","protected":true,"item_types":[]},{"source_path":["name"],"output_path":["name"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"name","protected":false,"item_types":[]},{"source_path":["corpus"],"output_path":["corpus"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"vault_corpus","shape":null,"coverage_key":"corpus","protected":false,"item_types":[]},{"source_path":["updateTime"],"output_path":["updateTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":"updateTime","protected":false,"item_types":[]},{"source_path":["accounts"],"output_path":["accounts"],"required":false,"accepted_native_types":["list","null"],"transform":"selected_child_list","validator":"declared_shape","shape":"vault_account","coverage_key":"accounts","protected":false,"item_types":["object"]},{"source_path":["orgUnit"],"output_path":["orgUnit"],"required":false,"accepted_native_types":["object","null"],"transform":"selected_child_object","validator":"declared_shape","shape":"vault_org_unit","coverage_key":"orgUnit","protected":false,"item_types":[]},{"source_path":["query"],"output_path":["query"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_query","coverage_key":"query","protected":false,"item_types":[]}],"splunk-index":[{"source_path":["name"],"output_path":["name"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"exact_target_index","shape":null,"coverage_key":"name","protected":true,"item_types":[]},{"source_path":["content","datatype"],"output_path":["datatype"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"splunk_datatype","shape":null,"coverage_key":"datatype","protected":false,"item_types":[]},{"source_path":["content","disabled"],"output_path":["disabled"],"required":false,"accepted_native_types":["bool","int","str","float","null"],"transform":"literal","validator":"splunk_disabled","shape":null,"coverage_key":"disabled","protected":false,"item_types":[]},{"source_path":["content","frozenTimePeriodInSecs"],"output_path":["frozenTimePeriodInSecs"],"required":false,"accepted_native_types":["int","str","float","null"],"transform":"literal","validator":"splunk_nonnegative_setting","shape":null,"coverage_key":"frozenTimePeriodInSecs","protected":false,"item_types":[]},{"source_path":["content","maxTotalDataSizeMB"],"output_path":["maxTotalDataSizeMB"],"required":false,"accepted_native_types":["int","str","float","null"],"transform":"literal","validator":"splunk_nonnegative_setting","shape":null,"coverage_key":"maxTotalDataSizeMB","protected":false,"item_types":[]},{"source_path":["content","coldToFrozenDir"],"output_path":["coldToFrozenDirState"],"required":false,"accepted_native_types":["str","null"],"transform":"archive_presence","validator":"archive_presence","shape":null,"coverage_key":"coldToFrozenDir","protected":false,"item_types":[]},{"source_path":["content","coldToFrozenScript"],"output_path":["coldToFrozenScriptState"],"required":false,"accepted_native_types":["str","null"],"transform":"archive_presence","validator":"archive_presence","shape":null,"coverage_key":"coldToFrozenScript","protected":false,"item_types":[]}],"elastic-explain":[{"source_path":["index"],"output_path":["index"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"exact_target_index","shape":null,"coverage_key":"index","protected":true,"item_types":[]},{"source_path":["managed"],"output_path":["managed"],"required":true,"accepted_native_types":["bool"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"managed","protected":true,"item_types":[]},{"source_path":["policy"],"output_path":["policy"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"supported_policy_reference","shape":null,"coverage_key":"policy","protected":true,"item_types":[]},{"source_path":["phase"],"output_path":["phase"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"phase","protected":false,"item_types":[]},{"source_path":["action"],"output_path":["action"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"action","protected":false,"item_types":[]},{"source_path":["step"],"output_path":["step"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"step","protected":false,"item_types":[]},{"source_path":["failed_step"],"output_path":["failed_step"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":"failed_step","protected":false,"item_types":[]},{"source_path":["index_creation_date_millis"],"output_path":["index_creation_date_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"index_creation_date_millis","protected":false,"item_types":[]},{"source_path":["lifecycle_date_millis"],"output_path":["lifecycle_date_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"lifecycle_date_millis","protected":false,"item_types":[]},{"source_path":["phase_time_millis"],"output_path":["phase_time_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"phase_time_millis","protected":false,"item_types":[]},{"source_path":["action_time_millis"],"output_path":["action_time_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"action_time_millis","protected":false,"item_types":[]},{"source_path":["step_time_millis"],"output_path":["step_time_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"step_time_millis","protected":false,"item_types":[]},{"source_path":["phase_execution"],"output_path":["phase_execution"],"required":false,"accepted_native_types":["object","null"],"transform":"selected_child_object","validator":"declared_shape","shape":"elastic_phase_execution","coverage_key":"phase_execution","protected":false,"item_types":[]}],"elastic-policy":[{"source_path":["version"],"output_path":["version"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":"version","protected":false,"item_types":[]},{"source_path":["modified_date"],"output_path":["modified_date"],"required":false,"accepted_native_types":["str","int","null"],"transform":"literal","validator":"timestamp_text_or_native_millis","shape":null,"coverage_key":"modified_date","protected":false,"item_types":[]},{"source_path":["policy"],"output_path":["policy"],"required":false,"accepted_native_types":["object","null"],"transform":"selected_child_object","validator":"declared_shape","shape":"elastic_policy","coverage_key":"policy","protected":false,"item_types":[]}],"elastic-status":[{"source_path":["operation_mode"],"output_path":["operation_mode"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"elastic_operation_mode","shape":null,"coverage_key":"operation_mode","protected":false,"item_types":[]}]} as const;
const SHAPES = {"vault_account":{"fields":[{"source_path":["accountId"],"output_path":["accountId"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"nonblank","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["holdTime"],"output_path":["holdTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"discard","value_shape":null,"value_types":[]},"vault_org_unit":{"fields":[{"source_path":["orgUnitId"],"output_path":["orgUnitId"],"required":true,"accepted_native_types":["str"],"transform":"literal","validator":"nonblank","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["holdTime"],"output_path":["holdTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"discard","value_shape":null,"value_types":[]},"vault_drive_query":{"fields":[{"source_path":["includeSharedDriveFiles"],"output_path":["includeSharedDriveFiles"],"required":false,"accepted_native_types":["bool","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["includeTeamDriveFiles"],"output_path":["includeTeamDriveFiles"],"required":false,"accepted_native_types":["bool","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_chat_query":{"fields":[{"source_path":["includeRooms"],"output_path":["includeRooms"],"required":false,"accepted_native_types":["bool","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_mail_query":{"fields":[{"source_path":["startTime"],"output_path":["startTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["endTime"],"output_path":["endTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["terms"],"output_path":["terms"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_groups_query":{"fields":[{"source_path":["startTime"],"output_path":["startTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["endTime"],"output_path":["endTime"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"aware_rfc3339_text","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["terms"],"output_path":["terms"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_voice_query":{"fields":[{"source_path":["coveredData"],"output_path":["coveredData"],"required":false,"accepted_native_types":["list","null"],"transform":"literal","validator":"voice_covered_data","shape":null,"coverage_key":null,"protected":false,"item_types":["str"]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_empty_query":{"fields":[],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"vault_query":{"fields":[{"source_path":["driveQuery"],"output_path":["driveQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_drive_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["hangoutsChatQuery"],"output_path":["hangoutsChatQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_chat_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["mailQuery"],"output_path":["mailQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_mail_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["groupsQuery"],"output_path":["groupsQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_groups_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["voiceQuery"],"output_path":["voiceQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_voice_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["calendarQuery"],"output_path":["calendarQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_empty_query","coverage_key":null,"protected":false,"item_types":[]},{"source_path":["geminiQuery"],"output_path":["geminiQuery"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"vault_empty_query","coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"elastic_phase_definition":{"fields":[{"source_path":["min_age"],"output_path":["min_age"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["actions"],"output_path":["actions"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"opaque_named_actions","shape":null,"coverage_key":null,"protected":false,"item_types":["object","list","str","int","float","bool","null"]}],"unknown_keys":"retain_exact_and_mark_unknown","value_shape":null,"value_types":[]},"elastic_phases":{"fields":[],"unknown_keys":"all_keys_are_dynamic_phase_entries","value_shape":"elastic_phase_definition","value_types":["object","null"]},"elastic_policy":{"fields":[{"source_path":["phases"],"output_path":["phases"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"elastic_phases","coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"discard","value_shape":null,"value_types":[]},"elastic_phase_execution":{"fields":[{"source_path":["policy"],"output_path":["policy"],"required":false,"accepted_native_types":["str","null"],"transform":"literal","validator":"literal","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["version"],"output_path":["version"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["modified_date_in_millis"],"output_path":["modified_date_in_millis"],"required":false,"accepted_native_types":["int","null"],"transform":"literal","validator":"nonnegative_int","shape":null,"coverage_key":null,"protected":false,"item_types":[]},{"source_path":["phase_definition"],"output_path":["phase_definition"],"required":false,"accepted_native_types":["object","null"],"transform":"literal","validator":"declared_shape","shape":"elastic_phase_definition","coverage_key":null,"protected":false,"item_types":[]}],"unknown_keys":"discard","value_shape":null,"value_types":[]}} as const;
const DIAGNOSTIC_RULES = {"credential_missing":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"credential_invalid":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"credential_expired":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"credential_resolution_failed":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"credential_rejected":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"offline_refused":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"destination_refused":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"dns_failed":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"transport_failed":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"timeout":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"deadline_exceeded":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"attempt_limit":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"response_limit":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"run_byte_limit":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"invalid_encoding":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"invalid_json":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"invalid_response":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"identity_mismatch":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"redirect_refused":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"http_denied":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"http_not_found":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"http_error":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"retry_after_invalid":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true]],"page_limit":[["run",["google-vault"],[],"stop_run",true]],"record_limit":[["run",["google-vault"],[],"stop_run",true]],"token_invalid":[["read",["google-vault"],["vault-holds"],"end_read",true]],"token_repeated":[["read",["google-vault"],["vault-holds"],"end_read",true]],"projection_limit":[["read",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"end_read",true],["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"result_limit":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"duplicate_conflict":[["read",["google-vault"],["vault-holds"],"continue_safe_enumeration",false]],"policy_reference_missing":[["resource",["elastic-ilm"],["elastic-explain"],"no_unsupported_followup",false]],"policy_reference_unsupported":[["resource",["elastic-ilm"],["elastic-explain"],"no_unsupported_followup",false]],"policy_unavailable":[["resource",["elastic-ilm"],["elastic-policy"],"no_unsupported_followup",false]],"upstream_error":[["read",["splunk-enterprise"],["splunk-index"],"end_read",true]],"upstream_warning":[["read",["splunk-enterprise"],["splunk-index"],"continue",false]],"unsupported_source_value":[["read",["splunk-enterprise"],["splunk-index"],"continue",false],["observation",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"continue",false]],"missing_source_detail":[["observation",["google-vault","splunk-enterprise","elastic-ilm"],["vault-matter","vault-holds","splunk-index","elastic-explain","elastic-policy","elastic-status"],"continue",false]],"cleanup_failed":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"internal_error":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]],"dependency_unavailable":[["run",["google-vault","splunk-enterprise","elastic-ilm"],[],"stop_run",true]]} as const;
const DIAGNOSTIC_HTTP = {"credential_missing":"none","credential_invalid":"none","credential_expired":"none","credential_resolution_failed":"none","credential_rejected":"401","offline_refused":"none","destination_refused":"none","dns_failed":"none","transport_failed":"observed","timeout":"observed","deadline_exceeded":"observed","attempt_limit":"none","response_limit":"observed","run_byte_limit":"observed","invalid_encoding":"observed","invalid_json":"observed","invalid_response":"observed","identity_mismatch":"200","redirect_refused":"3xx","http_denied":"403","http_not_found":"404","http_error":"other_non_200","retry_after_invalid":"retryable","page_limit":"observed","record_limit":"observed","token_invalid":"200","token_repeated":"200","projection_limit":"observed","result_limit":"observed","duplicate_conflict":"200","policy_reference_missing":"none","policy_reference_unsupported":"none","policy_unavailable":"none","upstream_error":"200","upstream_warning":"200","unsupported_source_value":"200","missing_source_detail":"200","cleanup_failed":"observed","internal_error":"none","dependency_unavailable":"none"} as const;
const DIAGNOSTIC_ORDER = ["credential_missing","credential_invalid","credential_expired","credential_resolution_failed","credential_rejected","offline_refused","destination_refused","dns_failed","transport_failed","timeout","deadline_exceeded","attempt_limit","response_limit","run_byte_limit","invalid_encoding","invalid_json","invalid_response","identity_mismatch","redirect_refused","http_denied","http_not_found","http_error","retry_after_invalid","page_limit","record_limit","token_invalid","token_repeated","projection_limit","result_limit","duplicate_conflict","policy_reference_missing","policy_reference_unsupported","policy_unavailable","upstream_error","upstream_warning","unsupported_source_value","missing_source_detail","cleanup_failed","internal_error","dependency_unavailable"] as const;
const RETRYABLE_STATUS = [408,429,500,502,503,504] as const;
const FINDING_TEXT = {"google-vault":["Google Vault matter and hold configuration","Selected matter and hold configuration; retention rules and held-record coverage are unassessed.","GoogleVault::Matter"],"splunk-enterprise":["Splunk Enterprise index retention configuration","Selected index configuration; event coverage and archival execution are unassessed.","SplunkEnterprise::Index"],"elastic-ilm":["Elasticsearch ILM configuration","Selected index, service and current policy configuration; document coverage and lifecycle execution are unassessed.","ElasticsearchILM::Index"]} as const;
const COUNTER_NAMES = ["attempts","responses_received","pages_received","pages_admitted","records_received","records_admitted","duplicates_coalesced","conflicts_quarantined","raw_bytes","decoded_bytes"] as const;

const counter = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const clock = z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z(?![\s\S])/).refine(value => {
  const date = new Date(value);
  return Number(value.slice(0, 4)) >= 1 && Number.isFinite(date.getTime()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
});
const state = z.enum(["complete", "partial", "unavailable"]);
const coverageState = z.enum(["absent", "null", "known", "unknown"]);
const coverage = z.record(z.string(), z.strictObject({ absent: counter, null: counter, known: counter, unknown: counter }));
const digest = z.string().regex(/^[0-9a-f]{64}(?![\s\S])/);
const version = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}(?![\s\S])/);
const runId = z.string().regex(/^[0-7][0-9A-HJKMNP-TV-Z]{25}(?![\s\S])/);
const diagnostic = z.strictObject({ code: z.enum(DIAGNOSTIC_CODES), read_id: z.string().min(1).max(384).nullable(), safe_http_status: z.number().int().min(100).max(599).nullable() });
const observation = z.strictObject({
  source_identity: z.string().min(1).max(1024),
  api_version: z.enum(["v1", "splunk-enterprise-10.4", "elastic-stack-ilm"]),
  projection_version: z.literal("enterprise-retention-projection/v1"),
  native_scope: z.enum(["matter", "hold", "index", "policy", "service"]),
  fields: z.record(z.string(), z.json()),
  field_coverage: z.record(z.string(), coverageState),
  interpretation_status: z.enum(["known", "limited"]),
  diagnostics: z.array(diagnostic).max(2),
  canonical_projection_sha256: digest,
});
const readCounters = {
  attempts: counter, responses_received: counter, pages_received: counter, pages_admitted: counter,
  records_received: counter, records_admitted: counter, duplicates_coalesced: counter, conflicts_quarantined: counter,
  raw_bytes: counter, decoded_bytes: counter,
};
const readShape = z.strictObject({
  read_id: z.string().min(1).max(384), kind: z.enum(READ_KINDS), source_id: z.string().min(1).max(255),
  method_id: z.enum(METHOD_IDS), status: state, ...readCounters,
  started_at: clock.nullable(), finished_at: clock.nullable(), safe_http_status: z.number().int().min(100).max(599).nullable(),
  terminal_reason: z.enum(DIAGNOSTIC_CODES).nullable(), diagnostics: z.array(diagnostic).max(40), observations: z.array(observation).max(2000),
});
const resourceFields = {
  canonical_resource_id: z.string().min(1).max(384), status: state, read_ids: z.array(z.string()).min(1).max(3),
  policy_resolution: z.enum(["not_applicable", "resolved", "unresolved"]), diagnostics: z.array(diagnostic).max(3),
};
const target = z.union([vaultTarget, splunkTarget, elasticTarget]);
const finding = z.strictObject({
  id: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/),
  title: z.enum(["Google Vault matter and hold configuration", "Splunk Enterprise index retention configuration", "Elasticsearch ILM configuration"]),
  description: z.enum([
    "Selected matter and hold configuration; retention rules and held-record coverage are unassessed.",
    "Selected index configuration; event coverage and archival execution are unassessed.",
    "Selected index, service and current policy configuration; document coverage and lifecycle execution are unassessed.",
  ]),
  severity: z.literal("informational"), status: z.literal("active"), compliance_status: z.literal("unknown"), remediation: z.null(),
  source_system: z.literal("enterprise-retention"), source_finding_id: z.string(), resource_id: z.string(),
  resource_type: z.enum(["GoogleVault::Matter", "SplunkEnterprise::Index", "ElasticsearchILM::Index"]),
  resource_region: z.null(), resource_account: z.null(), control_mappings: z.array(z.never()).max(0),
  collection_context: z.strictObject({
    collector_id: z.literal("enterprise-retention"), collector_version: version, run_id: runId, collected_at: clock,
    credential_identity: z.literal("operator-configured:identity-unverified"), source_system_id: z.string().max(128),
    filter_applied: z.strictObject({ provider: providers, profile_alias: z.string().regex(alias), scope_label: z.string().regex(alias), target, observation_scope: z.literal("configuration"), coverage_scope: z.literal("selected_resources") }),
    pagination_context: z.strictObject({ page_size: z.literal(100).nullable(), page_number: z.null(), total_pages: counter, continuation_token: z.null(), is_complete: z.boolean() }),
    evidentia_version: version,
  }),
  raw_data: z.strictObject({ target, status: state, policy_resolution: resourceFields.policy_resolution,
    reads: z.array(z.strictObject({ read_id: z.string(), status: state, observations: counter, observation_digests_sha256: digest })).min(1).max(3), field_coverage: coverage }),
  first_observed: clock, last_observed: clock, resolved_at: z.null(),
});
const manifest = z.strictObject({
  schema_version: z.literal("enterprise-retention-manifest/v1"), run_id: runId, collector_version: version, evidentia_version: version, status: state,
  resources_requested: counter, resources_attempted: counter, reads_planned: counter, reads_attempted: counter, reads_completed: counter,
  ...readCounters, canonical_observation_bytes: counter.max(2_097_152), findings: counter.max(20),
});
const resultFields = {
  schema_version: z.literal("enterprise-retention-collection/v1"), profile_alias: z.string().regex(alias), scope_label: z.string().regex(alias),
  status: state, started_at: clock, finished_at: clock, observation_scope: z.literal("configuration"), coverage_scope: z.literal("selected_resources"),
  identity_basis: z.literal("operator-declared"), authenticated_identity_verified: z.literal(false), object_enforcement_assessed: z.literal(false), recordset_completeness_assessed: z.literal(false),
  source_reads: z.array(readShape).min(1).max(41), findings: z.array(finding).max(20), diagnostics: z.array(diagnostic).max(40), field_coverage: coverage, manifest,
};
const resultShape: z.ZodType<EnterpriseRetentionCollectResult> = z.discriminatedUnion("provider", [
  z.strictObject({ ...resultFields, provider: z.literal("google-vault"), resources: z.array(z.strictObject({ ...resourceFields, target: vaultTarget })).min(1).max(20), retention_rules_assessed: z.literal(false), unassessed_surfaces: z.tuple([z.literal("default_retention_rules"), z.literal("custom_retention_rules"), z.literal("held_record_coverage")]) }),
  z.strictObject({ ...resultFields, provider: z.literal("splunk-enterprise"), resources: z.array(z.strictObject({ ...resourceFields, target: splunkTarget })).min(1).max(20), unassessed_surfaces: z.tuple([z.literal("event_coverage"), z.literal("archive_execution_and_durability"), z.literal("smartstore_and_volume_configuration"), z.literal("cluster_wide_configuration")]) }),
  z.strictObject({ ...resultFields, provider: z.literal("elastic-ilm"), resources: z.array(z.strictObject({ ...resourceFields, target: elasticTarget })).min(1).max(20), unassessed_surfaces: z.tuple([z.literal("document_coverage"), z.literal("lifecycle_execution_guarantees"), z.literal("templates_and_unselected_indices"), z.literal("atomic_provider_snapshot")]) }),
]);

/** Validate without replacing native records with a schema library's filtered copy. */
function assertResultShape(value: unknown): asserts value is EnterpriseRetentionCollectResult {
  resultShape.parse(value);
}

type Read = EnterpriseRetentionCollectResult["source_reads"][number];
type Coverage = z.infer<typeof coverage>;
type NativeKind = "str" | "int" | "float" | "bool" | "null" | "object" | "list";
type JsonPath = readonly (string | number)[];
type ReadKind = typeof READ_KINDS[number];
type DiagnosticCode = typeof DIAGNOSTIC_CODES[number];
type Diagnostic = z.infer<typeof diagnostic>;
type DiagnosticScope = "run" | "read" | "resource" | "observation";
type DiagnosticRule = readonly [DiagnosticScope, readonly EnterpriseProvider[], readonly ReadKind[], string, boolean];
interface FieldRule {
  readonly output_path: readonly string[];
  readonly required: boolean;
  readonly accepted_native_types: readonly NativeKind[];
  readonly transform: string;
  readonly validator: string;
  readonly shape: string | null;
  readonly coverage_key: string | null;
  readonly item_types: readonly NativeKind[];
}
interface ShapeRule {
  readonly fields: readonly FieldRule[];
  readonly unknown_keys: string;
  readonly value_shape: string | null;
  readonly value_types: readonly NativeKind[];
}
interface Presence {
  readonly unknown: boolean;
  readonly missing: boolean;
}
const rootRules: Readonly<Record<ReadKind, readonly FieldRule[]>> = ROOT_RULES;
const shapeRules: Readonly<Record<string, ShapeRule>> = SHAPES;
const diagnosticRules: Readonly<Record<DiagnosticCode, readonly DiagnosticRule[]>> = DIAGNOSTIC_RULES;
const diagnosticOrder: readonly DiagnosticCode[] = DIAGNOSTIC_ORDER;
const retryableStatuses: readonly number[] = RETRYABLE_STATUS;
// Python str.strip whitespace, excluding JS-only U+FEFF and including U+001C..001F/U+0085.
const pythonBlank = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;
const isObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const owns = (value: Record<string, unknown>, key: string): boolean => Object.hasOwn(value, key);
const utf8Size = (value: string): number => new TextEncoder().encode(value).length;
const present = { unknown: false, missing: false };

function nativeKind(value: unknown, path: JsonPath, spans: ReadonlyMap<string, string>): NativeKind {
  if (value === null) return "null";
  if (typeof value === "string") return "str";
  if (typeof value === "boolean") return "bool";
  if (typeof value === "number") {
    const token = spans.get(`number:${JSON.stringify(path)}`);
    if (!Number.isFinite(value) || (token !== "int" && token !== "float")) return failure();
    return token;
  }
  if (Array.isArray(value)) return "list";
  if (isObject(value)) return "object";
  return failure();
}

/** Structural counters/status codes retain integer token types before JSON.parse. */
function checkStructuralNumbers(value: unknown, path: JsonPath, spans: ReadonlyMap<string, string>): void {
  if (path.length === 5 && path[0] === "source_reads" && typeof path[1] === "number" && path[2] === "observations" && typeof path[3] === "number" && path[4] === "fields") return;
  if (typeof value === "number") {
    if (nativeKind(value, path, spans) !== "int") return failure();
  } else if (Array.isArray(value)) {
    value.forEach((item: unknown, index: number) => checkStructuralNumbers(item, [...path, index], spans));
  } else if (isObject(value)) {
    for (const [key, item] of Object.entries(value)) checkStructuralNumbers(item, [...path, key], spans);
  }
}

function outputKey(rule: FieldRule): string {
  if (rule.output_path.length !== 1) return failure();
  return rule.output_path[0];
}

/** Check declared shape/presence only; Python owns semantic interpretation. */
function checkNativeField(rule: FieldRule, value: unknown, path: JsonPath, spans: ReadonlyMap<string, string>): Presence {
  const kind = nativeKind(value, path, spans);
  if (!rule.accepted_native_types.includes(kind)) return failure();
  if (value === null) return { unknown: false, missing: true };
  if ((rule.validator === "nonblank" || rule.validator === "nonblank_utf8_max_1024") && (typeof value !== "string" || pythonBlank.test(value) || (rule.validator === "nonblank_utf8_max_1024" && utf8Size(value) > 1024))) return failure();
  if (Array.isArray(value) && rule.item_types.length) {
    value.forEach((item: unknown, index: number) => {
      if (!rule.item_types.includes(nativeKind(item, [...path, index], spans))) return failure();
    });
  }
  if (rule.shape !== null) {
    if (rule.transform === "selected_child_list") {
      if (!Array.isArray(value)) return failure();
      const children = value.map((item: unknown, index: number) => checkNativeShape(rule.shape ?? failure(), item, [...path, index], spans));
      return { unknown: children.some(child => child.unknown), missing: children.some(child => child.missing) };
    }
    return checkNativeShape(rule.shape, value, path, spans);
  }
  return present;
}

function checkNativeShape(shapeName: string, value: unknown, path: JsonPath, spans: ReadonlyMap<string, string>): Presence {
  if (!isObject(value) || !Object.hasOwn(shapeRules, shapeName)) return failure();
  const shape = shapeRules[shapeName];
  let unknown = false;
  let missing = false;
  if (shape.value_shape !== null) {
    for (const [key, item] of Object.entries(value)) {
      if (!shape.value_types.includes(nativeKind(item, [...path, key], spans))) return failure();
      if (item === null) missing = true;
      else {
        const child = checkNativeShape(shape.value_shape, item, [...path, key], spans);
        unknown ||= child.unknown;
        missing ||= child.missing;
      }
    }
    return { unknown, missing };
  }
  const keys = new Set(shape.fields.map(outputKey));
  for (const key of Object.keys(value)) {
    if (!keys.has(key)) {
      if (shape.unknown_keys !== "retain_exact_and_mark_unknown") return failure();
      unknown = true;
    }
  }
  for (const rule of shape.fields) {
    const key = outputKey(rule);
    if (!owns(value, key)) {
      if (rule.required) return failure();
      if (shapeName !== "vault_query") missing = true;
      continue;
    }
    const child = checkNativeField(rule, value[key], [...path, key], spans);
    unknown ||= child.unknown;
    missing ||= child.missing;
  }
  return { unknown, missing };
}

function checkProjection(read: Read, observed: Read["observations"][number], path: JsonPath, spans: ReadonlyMap<string, string>): void {
  const fields = observed.fields;
  const rules = rootRules[read.kind];
  const keys = new Set(rules.map(outputKey));
  if (Object.keys(fields).some(key => !keys.has(key))) return failure();
  if (pythonBlank.test(observed.source_identity) || utf8Size(observed.source_identity) > 1024) return failure();
  const identityField = IDENTITY_FIELDS[read.kind];
  if (identityField !== null && (!Object.hasOwn(fields, identityField) || fields[identityField] !== observed.source_identity)) return failure();
  let unknown = false;
  let missing = false;
  for (const rule of rules) {
    const key = outputKey(rule);
    const coverage = observed.field_coverage[rule.coverage_key ?? failure()];
    const hasValue = Object.hasOwn(fields, key);
    const value = fields[key];
    if (rule.transform === "archive_presence") {
      if (!hasValue || typeof value !== "string" || !["absent", "null", "empty", "nonempty"].includes(value)) return failure();
      const expected = value === "absent" || value === "null" ? value : "known";
      if (coverage !== expected) return failure();
      missing ||= coverage === "absent" || coverage === "null";
      continue;
    }
    if (!hasValue) {
      if (rule.required || coverage !== "absent") return failure();
      missing = true;
      continue;
    }
    if (value === null ? coverage !== "null" : coverage !== "known" && coverage !== "unknown") return failure();
    const child = checkNativeField(rule, value, [...path, key], spans);
    if (child.unknown && coverage !== "unknown") return failure();
    unknown ||= child.unknown || coverage === "unknown";
    missing ||= child.missing;
  }
  const codes = new Set(observed.diagnostics.map(item => item.code));
  if (unknown && !codes.has("unsupported_source_value")) return failure();
  if (missing !== codes.has("missing_source_detail")) return failure();
}

function checkReadIdentity(kind: ReadKind, source: string): void {
  if (kind === "vault-matter" || kind === "vault-holds") {
    if (!vaultTarget.safeParse({ matter_id: source }).success) return failure();
  } else if (kind === "splunk-index") {
    if (!splunkTarget.safeParse({ index: source }).success) return failure();
  } else if (kind === "elastic-explain") {
    if (!elasticTarget.safeParse({ index: source }).success) return failure();
  } else if (kind === "elastic-policy") {
    if (!policyId.test(source) || source === "." || source === ".." || source.toLowerCase() === "_all") return failure();
  } else if (source !== "service") return failure();
}

function checkDiagnosticHttp(item: Diagnostic): void {
  const association = DIAGNOSTIC_HTTP[item.code];
  const status = item.safe_http_status;
  if (association === "none" && status !== null) return failure();
  if ((association === "200" || association === "401" || association === "403" || association === "404") && status !== Number(association)) return failure();
  if (status !== null) {
    if (association === "3xx" && (status < 300 || status > 399)) return failure();
    if (association === "retryable" && !retryableStatuses.includes(status)) return failure();
    if (association === "other_non_200" && ([200, 401, 403, 404].includes(status) || (status >= 300 && status <= 399))) return failure();
  }
}

function checkDiagnostics(items: readonly Diagnostic[], scope: DiagnosticScope, provider: EnterpriseProvider, ledger: ReadonlyMap<string, Read>, owner?: Read): void {
  let previous = -1;
  for (const item of items) {
    const reference = item.read_id === null ? undefined : ledger.get(item.read_id);
    if (item.read_id !== null && reference === undefined) return failure();
    if ((scope === "read" || scope === "observation") && (owner === undefined || item.read_id !== owner.read_id)) return failure();
    if (scope === "resource" && reference === undefined) return failure();
    const kind = scope === "resource" ? reference?.kind : owner?.kind;
    if (!diagnosticRules[item.code].some(rule => rule[0] === scope && rule[1].includes(provider) && (rule[2].length === 0 || (kind !== undefined && rule[2].includes(kind))))) return failure();
    const order = diagnosticOrder.indexOf(item.code);
    if (order <= previous) return failure();
    previous = order;
    checkDiagnosticHttp(item);
  }
}

function checkReadTerminal(read: Read, provider: EnterpriseProvider, runCodes: ReadonlySet<DiagnosticCode>): void {
  const codes = new Set(read.diagnostics.map(item => item.code));
  if ((read.conflicts_quarantined > 0) !== codes.has("duplicate_conflict")) return failure();
  if (read.terminal_reason !== null) {
    const rules = diagnosticRules[read.terminal_reason];
    const allowed = rules.filter(rule => rule[4] && rule[1].includes(provider) && (rule[0] === "run" || (rule[0] === "read" && rule[2].includes(read.kind))));
    if (!allowed.length || (allowed.every(rule => rule[0] === "read") && !codes.has(read.terminal_reason))) return failure();
    if (rules.some(rule => rule[0] === "run") && !runCodes.has(read.terminal_reason) && !codes.has(read.terminal_reason)) return failure();
  }
  if (read.terminal_reason === null && read.diagnostics.some(item => diagnosticRules[item.code].some(rule => rule[0] === "read" && rule[1].includes(provider) && rule[2].includes(read.kind) && rule[4]))) return failure();
}

const equal = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
const sameTarget = (a: unknown, b: unknown): boolean => equal(a, b);
function fieldTotals(provider: EnterpriseProvider, reads: readonly Read[]): Coverage {
  const totals: Coverage = {};
  for (const kind of READ_KINDS) if (METHODS[kind][0] === provider) {
    for (const key of COVERAGE_KEYS[kind]) totals[`${kind}/${key}`] = { absent: 0, null: 0, known: 0, unknown: 0 };
  }
  for (const read of reads) for (const observed of read.observations) for (const [key, state] of Object.entries(observed.field_coverage)) {
    const tally = totals[`${read.kind}/${key}`];
    if (tally === undefined) return failure();
    ++tally[state];
  }
  return totals;
}
const equalCoverage = (a: Coverage, b: Coverage): boolean => equal(Object.keys(a).sort(), Object.keys(b).sort()) && Object.keys(a).every(key => ["absent", "null", "known", "unknown"].every(state => a[key][state as keyof Coverage[string]] === b[key][state as keyof Coverage[string]]));

/** Validate structure, presence and ledger bindings before rendering.
 * Python remains authoritative for semantic interpretation, digests and finding IDs.
 */
export function parseEnterpriseRetentionResponse(rawJson: string, input: unknown): EnterpriseRetentionResponse {
  try {
    const expected = snapshotEnterpriseRetentionRequest(input);
    const spans = indexEnterpriseRetentionJson(rawJson);
    const parsed: unknown = JSON.parse(rawJson);
    checkStructuralNumbers(parsed, [], spans);
    assertResultShape(parsed);
    const value = parsed;
    if (value.provider !== expected.provider || value.profile_alias !== expected.profile_alias || value.scope_label !== expected.scope_label || value.resources.length !== expected.targets.length || value.started_at > value.finished_at) return failure();
    const prefix = `enterprise-retention/${expected.provider}/${expected.profile_alias}`;
    const readId = (kind: string, source: string) => `${prefix}/${kind}/${source}`;
    const ledger = new Map(value.source_reads.map(read => [read.read_id, read]));
    if (ledger.size !== value.source_reads.length) return failure();
    checkDiagnostics(value.diagnostics, "run", expected.provider, ledger);
    const runCodes = new Set(value.diagnostics.map(item => item.code));
    const fields: string[][] = [];
    let observationBytes = 0;
    for (const [i, read] of value.source_reads.entries()) {
      checkReadIdentity(read.kind, read.source_id);
      checkDiagnostics(read.diagnostics, "read", expected.provider, ledger, read);
      checkReadTerminal(read, expected.provider, runCodes);
      if (METHODS[read.kind][0] !== expected.provider || read.method_id !== METHODS[read.kind][2] || read.read_id !== readId(read.kind, read.source_id)) return failure();
      if (!(read.pages_admitted <= read.pages_received && read.pages_received <= read.responses_received && read.responses_received <= read.attempts) || read.records_admitted !== read.observations.length || read.records_admitted + read.duplicates_coalesced > read.records_received || read.conflicts_quarantined * 2 > read.records_received) return failure();
      if (read.attempts === 0) {
        if (COUNTER_NAMES.some(key => read[key] !== 0) || read.started_at !== null || read.finished_at !== null || read.safe_http_status !== null) return failure();
      } else if (read.started_at === null || read.finished_at === null || read.started_at < value.started_at || read.finished_at > value.finished_at || read.started_at > read.finished_at) return failure();
      if ((read.responses_received === 0 && read.safe_http_status !== null) || (read.responses_received === 1 && read.safe_http_status === null) || (read.pages_received > 0 && read.safe_http_status !== null && read.safe_http_status !== 200)) return failure();
      if ((read.pages_admitted === 0) !== (read.status === "unavailable")) return failure();
      if (read.status === "complete" && (read.terminal_reason !== null || read.conflicts_quarantined !== 0 || read.pages_received !== read.pages_admitted || read.records_received !== read.records_admitted + read.duplicates_coalesced)) return failure();
      if (read.kind !== "vault-holds" && (read.pages_admitted > 1 || read.records_admitted !== read.pages_admitted || read.duplicates_coalesced !== 0 || read.conflicts_quarantined !== 0)) return failure();
      if (read.diagnostics.some(item => item.read_id !== read.read_id)) return failure();
      const seen = new Set<string>();
      const native: string[] = [];
      for (const [j, observed] of read.observations.entries()) {
        if (seen.has(observed.source_identity) || (read.kind !== "vault-holds" && observed.source_identity !== read.source_id) || observed.api_version !== METHODS[read.kind][1] || observed.native_scope !== NATIVE_SCOPES[read.kind]) return failure();
        seen.add(observed.source_identity);
        checkProjection(read, observed, ["source_reads", i, "observations", j, "fields"], spans);
        checkDiagnostics(observed.diagnostics, "observation", expected.provider, ledger, read);
        if (!equal(Object.keys(observed.field_coverage).sort(), [...COVERAGE_KEYS[read.kind]].sort())) return failure();
        if (observed.interpretation_status !== (observed.diagnostics.length ? "limited" : "known") || observed.diagnostics.some(item => item.read_id !== read.read_id || !["unsupported_source_value", "missing_source_detail"].includes(item.code))) return failure();
        const raw = spans.get(`${i}:${j}`);
        const rawObservation = spans.get(`canonical-observation:${i}:${j}`);
        if (raw === undefined || rawObservation === undefined) return failure();
        native.push(raw);
        const size = utf8Size(rawObservation);
        if (size > 65_536) return failure();
        observationBytes += size;
      }
      fields.push(native);
    }
    const selectedKind = expected.provider === "google-vault" ? "vault-matter" : expected.provider === "splunk-enterprise" ? "splunk-index" : "elastic-explain";
    const plan = expected.provider === "elastic-ilm" ? [readId("elastic-status", "service")] : [];
    for (const target of expected.targets) {
      plan.push(readId(selectedKind, targetId(target)));
      if (expected.provider === "google-vault") plan.push(readId("vault-holds", targetId(target)));
    }
    const policies = new Set<string>();
    const findings: Array<EnterpriseRetentionCollectResult["resources"][number]> = [];
    for (const [i, resource] of value.resources.entries()) {
      const id = targetId(expected.targets[i]);
      if (!sameTarget(resource.target, expected.targets[i]) || resource.canonical_resource_id !== `${prefix}/${expected.provider === "google-vault" ? "matter" : "index"}/${id}`) return failure();
      const primary = ledger.get(readId(selectedKind, id));
      if (!primary) return failure();
      const references = [primary.read_id];
      let resolution = "not_applicable";
      const expectedDiagnostics: Diagnostic[] = [];
      if (expected.provider === "google-vault") {
        const holds = ledger.get(readId("vault-holds", id));
        if (!holds || (holds.attempts > 0 && primary.pages_admitted === 0)) return failure();
        references.push(holds.read_id);
      } else if (expected.provider === "elastic-ilm") {
        const projected = primary.observations[0]?.fields;
        const policy = projected?.policy;
        if (!projected) resolution = "unresolved";
        else if (projected.managed !== false) {
          resolution = typeof policy === "string" && policyId.test(policy) && ![".", ".."].includes(policy) && policy.toLowerCase() !== "_all" ? "resolved" : "unresolved";
          if (resolution === "resolved" && typeof policy === "string") {
            const policyReadId = readId("elastic-policy", policy);
            references.push(policyReadId);
            if (ledger.get(policyReadId)?.status === "unavailable") expectedDiagnostics.push({ code: "policy_unavailable", read_id: policyReadId, safe_http_status: null });
            if (!policies.has(policy)) { policies.add(policy); plan.push(readId("elastic-policy", policy)); }
          } else {
            expectedDiagnostics.push({ code: policy === undefined || policy === null || policy === "" ? "policy_reference_missing" : "policy_reference_unsupported", read_id: primary.read_id, safe_http_status: null });
          }
        }
        references.push(readId("elastic-status", "service"));
      }
      if (!equal(resource.read_ids, references) || resource.policy_resolution !== resolution || resource.diagnostics.some(item => item.read_id === null || !references.includes(item.read_id))) return failure();
      checkDiagnostics(resource.diagnostics, "resource", expected.provider, ledger);
      if (resource.diagnostics.length !== expectedDiagnostics.length || resource.diagnostics.some((item, index) => item.code !== expectedDiagnostics[index].code || item.read_id !== expectedDiagnostics[index].read_id || item.safe_http_status !== expectedDiagnostics[index].safe_http_status)) return failure();
      const reads = references.map(id => { const read = ledger.get(id); return read ?? failure(); });
      const status = reads.every(read => read.status === "complete") && resolution !== "unresolved" ? "complete" : reads.some(read => read.pages_admitted > 0) ? "partial" : "unavailable";
      if (resource.status !== status) return failure();
      if (reads.some(read => !["elastic-status", "elastic-policy"].includes(read.kind) && read.pages_admitted > 0)) findings.push(resource);
    }
    if (!equal(plan, value.source_reads.map(read => read.read_id))) return failure();
    const status = value.resources.every(resource => resource.status === "complete") && value.diagnostics.length === 0 ? "complete" : findings.length ? "partial" : "unavailable";
    if (value.status !== status || value.manifest.status !== status || value.findings.length !== findings.length || value.manifest.findings !== findings.length || value.manifest.resources_requested !== expected.targets.length || value.manifest.resources_attempted !== expected.targets.filter(target => (ledger.get(readId(selectedKind, targetId(target)))?.attempts ?? 0) > 0).length || value.manifest.reads_planned !== ledger.size || value.manifest.reads_attempted !== value.source_reads.filter(read => read.attempts > 0).length || value.manifest.reads_completed !== value.source_reads.filter(read => read.status === "complete").length) return failure();
    if (COUNTER_NAMES.some(key => value.manifest[key] !== value.source_reads.reduce((sum, read) => sum + read[key], 0)) || value.manifest.attempts > 100 || value.manifest.canonical_observation_bytes !== observationBytes) return failure();
    if (expected.provider === "google-vault") {
      const holds = value.source_reads.filter(read => read.kind === "vault-holds");
      if (holds.reduce((sum, read) => sum + read.pages_admitted, 0) > 20 || holds.reduce((sum, read) => sum + read.records_admitted, 0) > 2000) return failure();
    }
    if (!equalCoverage(value.field_coverage, fieldTotals(expected.provider, value.source_reads))) return failure();
    for (const [i, finding] of value.findings.entries()) {
      const resource = findings[i];
      const expectedText = FINDING_TEXT[expected.provider];
      if (finding.title !== expectedText[0] || finding.description !== expectedText[1] || finding.resource_type !== expectedText[2]) return failure();
      const context = finding.collection_context;
      const reads = resource.read_ids.map(id => ledger.get(id) ?? failure());
      if (finding.resource_id !== resource.canonical_resource_id || finding.source_finding_id !== resource.canonical_resource_id || finding.first_observed !== value.started_at || finding.last_observed !== value.finished_at || context.collected_at !== value.finished_at || context.run_id !== value.manifest.run_id || context.collector_version !== value.manifest.collector_version || context.evidentia_version !== value.manifest.evidentia_version || context.source_system_id !== prefix) return failure();
      if (context.filter_applied.provider !== expected.provider || context.filter_applied.profile_alias !== expected.profile_alias || context.filter_applied.scope_label !== expected.scope_label || !sameTarget(context.filter_applied.target, resource.target) || !sameTarget(finding.raw_data.target, resource.target) || finding.raw_data.status !== resource.status || finding.raw_data.policy_resolution !== resource.policy_resolution || finding.raw_data.reads.length !== reads.length) return failure();
      if (context.pagination_context.is_complete !== (resource.status === "complete") || context.pagination_context.page_size !== (expected.provider === "google-vault" ? 100 : null) || context.pagination_context.total_pages !== reads.reduce((sum, read) => sum + read.pages_admitted, 0) || !equalCoverage(finding.raw_data.field_coverage, fieldTotals(expected.provider, reads))) return failure();
      if (finding.raw_data.reads.some((item, j) => item.read_id !== reads[j].read_id || item.status !== reads[j].status || item.observations !== reads[j].observations.length)) return failure();
    }
    return { result: value, rawJson, nativeFieldsJson: fields };
  } catch { return failure(); }
}

/** Read actual UTF-8 bytes, independent of Content-Length, with prompt cancellation on refusal. */
export async function readEnterpriseRetentionResponse(
  response: Response,
  expected: unknown,
): Promise<EnterpriseRetentionResponse> {
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
      if (size > ENTERPRISE_RESULT_BYTE_LIMIT) return failure();
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
    return parseEnterpriseRetentionResponse(text, expected);
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
