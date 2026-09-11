import { describe, expect, it } from "vitest";
import schema from "../../openapi.json";
import { ENTERPRISE_RETENTION_DEMO } from "@/lib/demo/fixtures";
import { buildEnterpriseRetentionRequest, snapshotEnterpriseRetentionRequest, parseEnterpriseRetentionRequest, parseEnterpriseRetentionResponse, indexEnterpriseRetentionJson, readEnterpriseRetentionResponse, ENTERPRISE_RESULT_BYTE_LIMIT } from "@/lib/enterprise-retention";

const providers = ["google-vault", "splunk-enterprise", "elastic-ilm"] as const;
const example = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete;
function response(bytes: Uint8Array[], headers: Record<string, string> = {}, close = true, cancel?: () => void) {
  return new Response(new ReadableStream<Uint8Array>({ start(controller) { for (const part of bytes) controller.enqueue(part); if (close) controller.close(); }, cancel }), { headers: { "content-type": "application/json", ...headers } });
}

describe("enterprise request grammar", () => {
  it("agrees with the generated API provider branches and strict target bounds", () => {
    const branches = schema.paths["/api/collectors/enterprise-retention/collect"].post.requestBody.content["application/json"].schema.oneOf;
    expect(branches.map(branch => branch.properties.provider.const)).toEqual(providers);
    for (const branch of branches) {
      expect(branch.additionalProperties).toBe(false);
      expect(branch.properties.targets.minItems).toBe(1);
      expect(branch.properties.targets.maxItems).toBe(20);
      expect(branch.properties.targets.items.additionalProperties).toBe(false);
    }
  });
  it.each(["", " ", " name", "name ", "a\n", "a\r", "a\u2028", ".alias", "_alias", "-alias", "\u00e9", "a".repeat(65)])("refuses the whole invalid profile/scope %j without trimming", value => {
    expect(() => buildEnterpriseRetentionRequest("google-vault", value, "scope", ["a"])).toThrow();
    expect(() => buildEnterpriseRetentionRequest("google-vault", "profile", value, ["a"])).toThrow();
  });
  it.each([
    ["google-vault", ["", "a.b", "a/b", "a?x", "a%2fb", "a*", "\u00e9", "a\n", "a".repeat(129)]],
    ["splunk-enterprise", ["", ".name", "_new", "_NEW", "_Reload", "_aLl", "a.b", "a/b", "a*", "a,b", "a".repeat(81)]],
    ["elastic-ilm", ["", ".", "..", "Upper", "_hidden", "-start", "+start", "a/b", "a*", "a,b", "a".repeat(256)]],
  ] as const)("bounds exact %s target names", (provider, values) => {
    for (const value of values) expect(() => buildEnterpriseRetentionRequest(provider, "profile", "scope", [value])).toThrow();
  });
  it.each(providers)("preserves order and forbids duplicate, zero and 21 targets for %s", provider => {
    const ids = Array.from({ length: 20 }, (_, n) => `resource-${n}`);
    const selected = buildEnterpriseRetentionRequest(provider, "Alias_1", "Scope.1", ids);
    expect(selected.targets.map(target => "matter_id" in target ? target.matter_id : target.index)).toEqual(ids);
    expect(Object.isFrozen(selected)).toBe(true);
    expect(Object.isFrozen(selected.targets)).toBe(true);
    expect(selected.targets.every(Object.isFrozen)).toBe(true);
    for (const invalid of [[], ["same", "same"], [...ids, "extra"]]) expect(() => buildEnterpriseRetentionRequest(provider, "profile", "scope", invalid)).toThrow();
    expect(() => snapshotEnterpriseRetentionRequest({ ...selected, origin: "https://example.invalid" })).toThrow();
    expect(() => snapshotEnterpriseRetentionRequest({ ...selected, targets: [{ index: "a", secret: "synthetic" }] })).toThrow();
  });
  it("accepts maximum literal identifiers and preserves case where allowed", () => {
    for (const [provider, id] of [["google-vault", "A".repeat(128)], ["splunk-enterprise", "A".repeat(80)], ["elastic-ilm", "a".repeat(255)]] as const) {
      expect(buildEnterpriseRetentionRequest(provider, "A".repeat(64), "s".repeat(64), [id]).targets).toHaveLength(1);
    }
  });
  it("makes a detached selection even when the caller later mutates its request", () => {
    const offered = JSON.parse(JSON.stringify(example.request));
    const selected = snapshotEnterpriseRetentionRequest(offered);
    offered.profile_alias = "changed"; offered.targets[0].index = "changed"; offered.targets.splice(1);
    expect(selected).toEqual(example.request);
  });
  it.each([65536, 65537])("checks actual request text bytes at %s", size => {
    const raw = JSON.stringify(example.request);
    const padded = raw + " ".repeat(size - new TextEncoder().encode(raw).length);
    if (size === 65536) expect(parseEnterpriseRetentionRequest(padded)).toEqual(example.request);
    else expect(() => parseEnterpriseRetentionRequest(padded)).toThrow(/64 KiB/);
  });
});

describe("exact enterprise response wire and ledger", () => {
  it.each(providers.flatMap(provider => (["complete", "partial", "unavailable"] as const).map(status => [provider, status] as const)))("retains the actual synthetic %s %s result", (provider, status) => {
    const fixture = ENTERPRISE_RETENTION_DEMO[provider][status];
    const parsed = parseEnterpriseRetentionResponse(fixture.rawJson, fixture.request);
    expect(parsed.rawJson).toBe(fixture.rawJson);
    expect(parsed.result.status).toBe(status);
    expect(parsed.nativeFieldsJson.flat()).toHaveLength(parsed.result.source_reads.reduce((sum, read) => sum + read.observations.length, 0));
    expect(parsed.result.authenticated_identity_verified).toBe(false);
  });
  it("retains large native integers, digit strings and fractional timestamps without numeric reserialization", () => {
    const parsed = parseEnterpriseRetentionResponse(example.rawJson, example.request);
    expect(parsed.nativeFieldsJson.flat().join("\n")).toContain("9007199254740993");
    expect(parsed.nativeFieldsJson.flat().join("\n")).toContain('"00042"');
    const fixture = ENTERPRISE_RETENTION_DEMO["google-vault"].complete;
    const vault = parseEnterpriseRetentionResponse(fixture.rawJson, fixture.request);
    expect(vault.nativeFieldsJson.flat().join("\n")).toContain("2026-01-01T00:00:00.123456789Z");
    expect(vault.rawJson).toContain("<synthetic-query>");
  });
  it("does not make absent or limited field interpretation into enumeration failure", () => {
    const fixture = ENTERPRISE_RETENTION_DEMO["elastic-ilm"].complete;
    const parsed = parseEnterpriseRetentionResponse(fixture.rawJson, fixture.request);
    expect(parsed.result.status).toBe("complete");
    expect(parsed.result.source_reads.some(read => read.observations.some(observation => Object.values(observation.field_coverage).includes("absent")))).toBe(true);
    expect(parsed.result.source_reads.filter(read => read.kind === "elastic-status")).toHaveLength(1);
    expect(parsed.result.source_reads.filter(read => read.kind === "elastic-policy")).toHaveLength(1);
  });
  it.each(["provider", "profile_alias", "scope_label", "target", "order"])("refuses a response substituted for the selected %s", field => {
    const offered = JSON.parse(JSON.stringify(example.request));
    if (field === "provider") offered.provider = "elastic-ilm";
    else if (field === "target") offered.targets[0].index = "other";
    else if (field === "order") offered.targets.reverse();
    else offered[field] = "other";
    expect(() => parseEnterpriseRetentionResponse(example.rawJson, offered)).toThrow();
  });
  it.each([
    ["unknown top field", (value: ReturnType<typeof JSON.parse>) => { value.secret = "synthetic"; }],
    ["false literal", (value: ReturnType<typeof JSON.parse>) => { value.authenticated_identity_verified = 0; }],
    ["invented complete", (value: ReturnType<typeof JSON.parse>) => { value.status = "unavailable"; }],
    ["manifest counter", (value: ReturnType<typeof JSON.parse>) => { ++value.manifest.attempts; }],
    ["duplicate ledger", (value: ReturnType<typeof JSON.parse>) => { value.source_reads.push(value.source_reads[0]); }],
    ["ledger order", (value: ReturnType<typeof JSON.parse>) => { value.source_reads.reverse(); }],
    ["unknown read reference", (value: ReturnType<typeof JSON.parse>) => { value.resources[0].read_ids[0] += "-other"; }],
    ["duplicate reference", (value: ReturnType<typeof JSON.parse>) => { value.resources[0].read_ids.push(value.resources[0].read_ids[0]); }],
    ["counter accounting", (value: ReturnType<typeof JSON.parse>) => { ++value.source_reads[0].records_admitted; }],
    ["coverage sum", (value: ReturnType<typeof JSON.parse>) => { ++value.field_coverage["splunk-index/name"].known; }],
    ["finding selection", (value: ReturnType<typeof JSON.parse>) => { value.findings[0].raw_data.target.index = "other"; }],
    ["unassessed scope", (value: ReturnType<typeof JSON.parse>) => { value.unassessed_surfaces = []; }],
  ] as const)("refuses %s", (_label, change) => {
    const value = JSON.parse(example.rawJson);
    change(value);
    expect(() => parseEnterpriseRetentionResponse(JSON.stringify(value), example.request)).toThrow();
  });
  it.each(["\ufeff{}", '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":"\\ud800"}', '{"x":"\\udfff"}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', '{"x":01}', '{} false', '{"x":true,}', '[1,]'])("rejects ambiguous or non-JSON wire %j", raw => {
    expect(() => indexEnterpriseRetentionJson(raw)).toThrow();
    expect(() => parseEnterpriseRetentionRequest(raw)).toThrow();
  });
  it("accepts JSON string escapes, paired surrogate characters and native numeric spellings", () => {
    expect(() => indexEnterpriseRetentionJson('{"x":[-0,1.0,1e2,"\\ud83d\\ude00","a\\\"b"]}')).not.toThrow();
    expect(() => indexEnterpriseRetentionJson("[".repeat(20) + "0" + "]".repeat(20))).not.toThrow();
    expect(() => indexEnterpriseRetentionJson("[".repeat(21) + "0" + "]".repeat(21))).toThrow();
  });
});

describe("bounded enterprise response streams", () => {
  it.each(["missing", "lying", "invalid"])("ignores %s Content-Length and joins UTF-8 chunks", async mode => {
    const bytes = new TextEncoder().encode(example.rawJson);
    const headers: Record<string, string> = mode === "missing" ? {} : { "content-length": mode === "lying" ? "1" : "invalid" };
    const received = await readEnterpriseRetentionResponse(response([bytes.slice(0, 31), bytes.slice(31)], headers), example.request);
    expect(received.rawJson).toBe(example.rawJson);
  });
  it("accepts exactly 4 MiB and refuses the first byte beyond it with stream cleanup", async () => {
    const bytes = new TextEncoder().encode(example.rawJson + " ".repeat(ENTERPRISE_RESULT_BYTE_LIMIT - new TextEncoder().encode(example.rawJson).length));
    expect((await readEnterpriseRetentionResponse(response([bytes]), example.request)).rawJson.length).toBe(ENTERPRISE_RESULT_BYTE_LIMIT);
    let cancelled = false;
    const oversized = response([bytes, new Uint8Array([32])], {}, false, () => { cancelled = true; });
    await expect(readEnterpriseRetentionResponse(oversized, example.request)).rejects.toThrow();
    expect(cancelled).toBe(true); expect(oversized.body?.locked).toBe(false);
  });
  it.each([201, 204, 400, 500])("refuses HTTP %s before consuming its body", async status => {
    let cancelled = false;
    const offered = response([], {}, false, () => { cancelled = true; throw new Error("synthetic private cleanup"); });
    Object.defineProperty(offered, "status", { value: status });
    await expect(readEnterpriseRetentionResponse(offered, example.request)).rejects.toThrow("The enterprise response is invalid or does not match the selected request.");
    expect(cancelled).toBe(true); expect(offered.body?.locked).toBe(false);
  });
  it.each([[0xc3, 0x28], [0xe2, 0x82], [0xed, 0xa0, 0x80], [0xc0, 0x80]])("rejects malformed UTF-8 %j", async (...bytes) => {
    const offered = response([new Uint8Array(bytes)]);
    await expect(readEnterpriseRetentionResponse(offered, example.request)).rejects.toThrow();
    expect(offered.body?.locked).toBe(false);
  });
  it("rejects wrong media type and missing streams", async () => {
    await expect(readEnterpriseRetentionResponse(response([], { "content-type": "text/html" }), example.request)).rejects.toThrow();
    await expect(readEnterpriseRetentionResponse(new Response(null), example.request)).rejects.toThrow();
  });
});

describe("reviewed enterprise parser boundaries", () => {
  const envelope = (observation: string) => `{"source_reads":[{"observations":[${observation}]}]}`;
  it("counts container depth without charging an extra scalar level", () => {
    for (const depth of [15, 16, 20]) expect(() => indexEnterpriseRetentionJson("[".repeat(depth) + "0" + "]".repeat(depth))).not.toThrow();
    expect(() => indexEnterpriseRetentionJson("[".repeat(21) + "0" + "]".repeat(21))).toThrow();
    const observed = (nested: number) => envelope(`{"fields":{"future":${"[".repeat(nested)}0${"]".repeat(nested)}}}`);
    expect(() => indexEnterpriseRetentionJson(observed(14))).not.toThrow();
    expect(() => indexEnterpriseRetentionJson(observed(15))).toThrow();
  });
  it("enforces independent exact observation node and canonical byte budgets", () => {
    const nodes = (count: number) => envelope(`{"fields":{"values":[${Array.from({ length: count }, () => "null").join(",")}]}}`);
    // Observation object, two keys, fields object and array account for five nodes.
    expect(() => indexEnterpriseRetentionJson(nodes(9995))).not.toThrow();
    expect(() => indexEnterpriseRetentionJson(nodes(9996))).toThrow();
    const empty = '{"fields":{"text":""}}';
    const overhead = new TextEncoder().encode(empty).length;
    const bounded = (bytes: number) => empty.replace('"text":""', `"text":"${"x".repeat(bytes - overhead)}"`);
    expect(indexEnterpriseRetentionJson(envelope(bounded(65536))).get("canonical-observation:0:0")).toBe(bounded(65536));
    expect(() => indexEnterpriseRetentionJson(envelope(bounded(65537)))).toThrow();
    const pretty = JSON.stringify(JSON.parse(envelope(bounded(65536))), null, 2);
    expect(indexEnterpriseRetentionJson(pretty).get("canonical-observation:0:0")).toBe(bounded(65536));
  });
  it("preserves native numeric tokens while independently computing canonical text", () => {
    const rawFields = '{"z":-0.0,"small":1e-7,"float":1.0,"integer":-0,"large":1e20}';
    const spans = indexEnterpriseRetentionJson(envelope(`{"fields":${rawFields}}`));
    expect(spans.get("0:0")).toBe(rawFields);
    expect(spans.get("canonical-observation:0:0")).toBe('{"fields":{"float":1.0,"integer":0,"large":1e+20,"small":1e-07,"z":-0.0}}');
    expect(spans.get('number:["source_reads",0,"observations",0,"fields","float"]')).toBe("float");
    expect(spans.get('number:["source_reads",0,"observations",0,"fields","integer"]')).toBe("int");
    expect(() => indexEnterpriseRetentionJson(`{"value":${"9".repeat(128)}}`)).not.toThrow();
    expect(() => indexEnterpriseRetentionJson(`{"value":${"9".repeat(129)}}`)).toThrow();
    for (const value of ["1e-400", "1.0000000000000001", "1e999"]) expect(() => indexEnterpriseRetentionJson(`{"value":${value}}`)).toThrow();
  });
  it("retains valid pretty-formatted complete results without raw-span byte confusion", () => {
    const pretty = JSON.stringify(JSON.parse(example.rawJson), null, 2);
    expect(parseEnterpriseRetentionResponse(pretty, example.request).rawJson).toBe(pretty);
  });

  type Wire = ReturnType<typeof JSON.parse>;
  function rewire(value: Wire): string {
    const totals = (reads: Wire[]) => {
      const result = structuredClone(value.field_coverage);
      for (const key of Object.keys(result)) result[key] = { absent: 0, null: 0, known: 0, unknown: 0 };
      for (const read of reads) for (const observed of read.observations) for (const key of Object.keys(observed.field_coverage)) ++result[`${read.kind}/${key}`][observed.field_coverage[key]];
      return result;
    };
    // Keep unrelated structural totals consistent so each fault reaches its own guard.
    value.field_coverage = totals(value.source_reads);
    value.manifest.canonical_observation_bytes = value.source_reads.reduce((sum: number, read: Wire) => sum + read.observations.reduce((bytes: number, observed: Wire) => bytes + new TextEncoder().encode(JSON.stringify(observed)).length, 0), 0);
    for (const finding of value.findings) {
      const resource = value.resources.find((item: Wire) => item.canonical_resource_id === finding.resource_id);
      finding.raw_data.field_coverage = totals(value.source_reads.filter((read: Wire) => resource.read_ids.includes(read.read_id)));
    }
    return JSON.stringify(value);
  }
  it.each([
    ["excluded archive source path", (value: Wire) => { value.source_reads[0].observations[0].fields.coldToFrozenDir = "/synthetic/excluded"; }],
    ["wrong native field type", (value: Wire) => { value.source_reads[0].observations[0].fields.datatype = 0; }],
    ["mismatched output identity", (value: Wire) => { value.source_reads[0].observations[0].fields.name = "other-index"; }],
    ["absent field with known coverage", (value: Wire) => { delete value.source_reads[0].observations[0].fields.datatype; }],
    ["orphan run diagnostic", (value: Wire) => { value.diagnostics = [{ code: "internal_error", read_id: "unknown", safe_http_status: null }]; value.status = "partial"; value.manifest.status = "partial"; }],
    ["run-only code on complete read", (value: Wire) => { value.source_reads[0].diagnostics.push({ code: "credential_missing", read_id: value.source_reads[0].read_id, safe_http_status: null }); }],
    ["provider-specific finding text", (value: Wire) => { value.findings[0].title = "Google Vault matter and hold configuration"; value.findings[0].description = "Selected matter and hold configuration; retention rules and held-record coverage are unassessed."; value.findings[0].resource_type = "GoogleVault::Matter"; }],
  ] as const)("refuses %s with otherwise consistent structural totals", (_name, change) => {
    const value = JSON.parse(example.rawJson);
    expect(() => parseEnterpriseRetentionResponse(rewire(value), example.request)).not.toThrow();
    change(value);
    expect(() => parseEnterpriseRetentionResponse(rewire(value), example.request)).toThrow();
  });
  it.each(["__proto__", "constructor", "prototype"])("rejects excluded %s keys at closed response levels", key => {
    const locations: ((value: Wire) => Wire)[] = [
      value => value, value => value.manifest, value => value.resources[0],
      value => value.source_reads[0], value => value.source_reads[0].observations[0],
      value => value.source_reads[0].observations[0].fields,
      value => value.source_reads[0].observations[0].field_coverage,
      value => value.field_coverage, value => value.findings[0], value => value.findings[0].raw_data,
    ];
    for (const location of locations) {
      const initial = rewire(JSON.parse(example.rawJson));
      expect(() => parseEnterpriseRetentionResponse(initial, example.request)).not.toThrow();
      const value = JSON.parse(initial);
      Object.defineProperty(location(value), key, { value: { synthetic: "excluded" }, enumerable: true });
      value.manifest.canonical_observation_bytes = value.source_reads.reduce((sum: number, read: Wire) => sum + read.observations.reduce((bytes: number, observed: Wire) => bytes + new TextEncoder().encode(JSON.stringify(observed)).length, 0), 0);
      expect(() => parseEnterpriseRetentionResponse(JSON.stringify(value), example.request)).toThrow();
    }
  });
  it.each(["__proto__", "constructor", "prototype"])("preserves allowed %s keys as own data in retained query JSON", key => {
    const fixture = ENTERPRISE_RETENTION_DEMO["google-vault"].complete;
    const value = JSON.parse(fixture.rawJson);
    const read = value.source_reads.find((item: Wire) => item.kind === "vault-holds");
    const observed = read.observations[0];
    observed.fields.query = JSON.parse(`{${JSON.stringify(key)}:{"synthetic":"retained"}}`);
    observed.field_coverage.query = "unknown";
    observed.interpretation_status = "limited";
    observed.diagnostics.unshift({ code: "unsupported_source_value", read_id: read.read_id, safe_http_status: read.safe_http_status });
    const raw = rewire(value);
    const parsed = parseEnterpriseRetentionResponse(raw, fixture.request);
    const retained = parsed.result.source_reads.find(item => item.kind === "vault-holds")!.observations[0].fields.query;
    expect(retained).toEqual(observed.fields.query);
    expect(Object.hasOwn(retained as object, key)).toBe(true);
    expect(Object.getPrototypeOf(retained)).toBe(Object.prototype);
    expect(parsed.rawJson).toBe(raw);
    expect(parsed.nativeFieldsJson.flat().join("\n")).toContain(`${JSON.stringify(key)}:{"synthetic":"retained"}`);
  });
  it("rejects year zero and float tokens in integer-only counters", () => {
    expect(() => parseEnterpriseRetentionResponse(example.rawJson.replaceAll("2026-01-01T", "0000-01-01T"), example.request)).toThrow();
    const changed = example.rawJson.replace(/"attempts":([0-9]+)/, '"attempts":$1.0');
    expect(changed).not.toBe(example.rawJson);
    expect(() => parseEnterpriseRetentionResponse(changed, example.request)).toThrow();
  });
  it.each([[256, true], [257, false]] as const)("bounds hold identity by UTF-8 bytes for %s emoji", (count, accepted) => {
    const fixture = ENTERPRISE_RETENTION_DEMO["google-vault"].complete;
    const value = JSON.parse(fixture.rawJson);
    const observed = value.source_reads.find((read: Wire) => read.kind === "vault-holds").observations[0];
    observed.source_identity = "\ud83d\ude00".repeat(count);
    observed.fields.holdId = observed.source_identity;
    if (accepted) expect(() => parseEnterpriseRetentionResponse(rewire(value), fixture.request)).not.toThrow();
    else expect(() => parseEnterpriseRetentionResponse(rewire(value), fixture.request)).toThrow();
  });
  it.each(["\u001c", "\u001d", "\u001e", "\u001f", "\u0085"])("rejects a Python-blank source identity %j", blank => {
    const fixture = ENTERPRISE_RETENTION_DEMO["google-vault"].complete;
    const value = JSON.parse(fixture.rawJson);
    const observed = value.source_reads.find((read: Wire) => read.kind === "vault-holds").observations[0];
    observed.source_identity = blank; observed.fields.holdId = blank;
    expect(() => parseEnterpriseRetentionResponse(rewire(value), fixture.request)).toThrow();
  });
});
