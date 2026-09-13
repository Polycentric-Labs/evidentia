import { afterEach, beforeEach, expect, test, vi } from "vitest";
import openapi from "../../openapi.json";
import { scapDemoResponse, scapDemoSource } from "./demo/scap-fixtures";
import {
  SCAP_RESPONSE_SCHEMAS,
  SCAP_SOURCE_BYTES,
  SCAP_RESULT_BYTES,
  parseScapAssertion,
  parseScapJson,
  parseScapResponse,
  prepareScapUpload,
  readScapResponse,
  boundedScapPreview,
  type ScapResult,
} from "./scap";

beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

test("original JSON refuses duplicate keys before they are discarded", () => {
  expect(() => parseScapJson('{"a":1,"a":2}')).toThrow();
});

test("request preparation refuses non-native objects without callbacks", async () => {
  let calls = 0;
  const options = Object.defineProperty({}, "source_profile", {
    enumerable: true,
    get: () => {
      calls += 1;
      return "xccdf-1.2-results";
    },
  });
  await expect(
    prepareScapUpload(new ArrayBuffer(1), options),
  ).rejects.toThrow();
  expect(calls).toBe(0);
});

test.each([
  '{"a":1,"\\u0061":2}',
  '{"x":{"b":null,"b":true}}',
  '{"x":1.0}',
  '{"x":1e0}',
  '{"x":9007199254740992}',
  '{"x":-0}',
  '{"x":NaN}',
  '{"x":01}',
  '{"x":"\\ud800"}',
  '{"x":"\\udc00"}',
  '{"x":"\u0000"}',
  '{"x":true,}',
  "[1,]",
  "null null",
  "\ufeffnull",
  '{"x":Infinity}',
])("original JSON refuses malformed or lossy input %#", (raw) => {
  expect(() => parseScapJson(raw)).toThrow();
});
test("JSON preserves null, empty, controls, Unicode, distinct keys and source spelling", () => {
  expect(
    parseScapJson(
      '{"__proto__":{"constructor":null},"x":["",null,"\\r\\n","😀","0001",0,false]}',
    ),
  ).toEqual({
    ["__proto__"]: { constructor: null },
    x: ["", null, "\r\n", "😀", "0001", 0, false],
  });
  expect(Object.getPrototypeOf(parseScapJson("{}"))).toBeNull();
  expect(Object.isFrozen(parseScapJson('{"x":[]}'))).toBe(true);
});
test("JSON source, depth, array and decoded scalar caps refuse before adoption", () => {
  expect(() => parseScapJson('"' + "x".repeat(262145) + '"')).toThrow();
  expect(() => parseScapJson("[".repeat(34) + "0" + "]".repeat(34))).toThrow();
  expect(() => parseScapJson("[" + "0,".repeat(32768) + "0]")).toThrow();
  expect(() => parseScapJson(" ".repeat(SCAP_RESULT_BYTES) + "0")).toThrow();
  expect(parseScapJson(" ".repeat(60) + "null", 64)).toBeNull();
  expect(() => parseScapJson(" ".repeat(61) + "null", 64)).toThrow();
});

test("schema projection preserves every validation rule and property named title or description", () => {
  const all = openapi.components.schemas as unknown as Record<
    string,
    Record<string, unknown>
  >;
  const result: Record<string, unknown> = {};
  function project(schema: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(schema)) {
      if (
        ["title", "description", "examples", "default", "deprecated"].includes(
          key,
        )
      )
        continue;
      if (key === "properties")
        out[key] = Object.fromEntries(
          Object.entries(value as Record<string, Record<string, unknown>>).map(
            ([name, item]) => [name, project(item)],
          ),
        );
      else if (["oneOf", "anyOf", "allOf"].includes(key))
        out[key] = (value as Record<string, unknown>[]).map(project);
      else if (
        key === "items" ||
        (key === "additionalProperties" && typeof value === "object")
      )
        out[key] = project(value as Record<string, unknown>);
      else out[key] = value;
    }
    return out;
  }
  function include(name: string) {
    if (Object.hasOwn(result, name)) return;
    result[name] = project(all[name]);
    const walk = (value: unknown) => {
      if (value !== null && typeof value === "object") {
        const entry = value as Record<string, unknown>;
        if (typeof entry.$ref === "string")
          include(entry.$ref.split("/").at(-1)!);
        Object.values(entry).forEach(walk);
      }
    };
    walk(all[name]);
  }
  include("ScapCollectionResult");
  expect(SCAP_RESPONSE_SCHEMAS).toEqual(result);
  expect(Object.keys(result)).toHaveLength(45);
  expect(SCAP_RESPONSE_SCHEMAS.ScapEvidenceArtifact.properties).toHaveProperty(
    "description",
  );
  expect(Object.isFrozen(SCAP_RESPONSE_SCHEMAS.SourceBinding.properties)).toBe(
    true,
  );
});

test.each([
  "prototype",
  "accessor",
  "symbol",
  "non-enumerable",
  "toJSON",
  "undefined",
  "boolean index",
  "string index",
  "negative index",
  "overflow index",
  "extra",
  "cycle",
])("request refuses %s without custom callbacks", async (kind) => {
  const source = scapDemoSource("xccdf-qualified");
  let calls = 0;
  const value: Record<string, unknown> = { ...source.request };
  if (kind === "prototype") Object.setPrototypeOf(value, { inherited: true });
  if (kind === "accessor")
    Object.defineProperty(value, "source_profile", {
      get: () => {
        calls++;
        return "xccdf-1.2-results";
      },
      enumerable: true,
    });
  if (kind === "symbol")
    Object.defineProperty(value, Symbol("hidden"), { value: true });
  if (kind === "non-enumerable")
    Object.defineProperty(value, "hidden", { value: true });
  if (kind === "toJSON")
    value.toJSON = () => {
      calls++;
      return source.request;
    };
  if (kind === "undefined") value.cadence_slug = undefined;
  if (kind === "boolean index") value.assessment_index = true;
  if (kind === "string index") value.assessment_index = "0";
  if (kind === "negative index") value.assessment_index = -1;
  if (kind === "overflow index") value.assessment_index = 256;
  if (kind === "extra") value.actor = "not allowed";
  if (kind === "cycle") value.completion_assertion = value;
  await expect(prepareScapUpload(source.raw, value)).rejects.toThrow();
  expect(calls).toBe(0);
});
test("native request and source are detached before the asynchronous digest", async () => {
  const source = scapDemoSource("xccdf-qualified");
  const prior = new Uint8Array(source.raw).slice();
  const pending = prepareScapUpload(source.raw, source.request);
  new Uint8Array(source.raw).fill(0);
  source.request.assessment_index = 255;
  const prepared = await pending;
  expect(new Uint8Array(prepared.body)).toEqual(prior);
  expect(prepared.expected.request.assessment_index).toBe(0);
  expect(prepared.query).toBe(
    "source_profile=xccdf-1.2-results&assessment_index=0",
  );
  expect(prepared.assertionHeader).toBeNull();
  const selected = Object.assign(
    Object.create(null) as object,
    scapDemoSource("xccdf-qualified").request,
  );
  await expect(
    prepareScapUpload(prior.buffer, selected),
  ).resolves.toHaveProperty("query");
});
test("raw byte cap and actual ArrayBuffer brand are enforced before hashing", async () => {
  const source = scapDemoSource("xccdf-qualified");
  const spy = vi.spyOn(crypto.subtle, "digest");
  for (const raw of [
    new ArrayBuffer(0),
    new ArrayBuffer(SCAP_SOURCE_BYTES + 1),
    new Uint8Array(1),
    { byteLength: 1 },
    new SharedArrayBuffer(1),
  ])
    await expect(
      prepareScapUpload(raw as ArrayBuffer, source.request),
    ).rejects.toThrow();
  expect(spy).not.toHaveBeenCalled();
  expect(
    (
      await prepareScapUpload(
        new ArrayBuffer(SCAP_SOURCE_BYTES),
        source.request,
      )
    ).body.byteLength,
  ).toBe(SCAP_SOURCE_BYTES);
});
test.each([
  "\u0000",
  "\u200b",
  "\u007f",
  "\ud800",
  " ",
  "x".repeat(257),
  "é".repeat(129),
])("cadence labels reject bounded native control case %#", async (value) => {
  const source = scapDemoSource("xccdf-qualified");
  await expect(
    prepareScapUpload(source.raw, { ...source.request, cadence_slug: value }),
  ).rejects.toThrow();
});
test("assertion sidecar requires the six exact fields and canonical ASCII header", async () => {
  const source = scapDemoSource("oval-5.8-asserted");
  const claim = {
    ...source.request.completion_assertion!,
    reference: "Synthetic café observation",
  };
  expect(parseScapAssertion(JSON.stringify(claim))).toEqual(claim);
  const prepared = await prepareScapUpload(source.raw, {
    ...source.request,
    completion_assertion: claim,
  });
  expect(prepared.assertionHeader).toContain("caf\\u00e9");
  expect(prepared.assertionHeader).toMatch(/^[\x20-\x7e]+$/);
  for (const key of Object.keys(claim)) {
    const missing = { ...claim } as Record<string, unknown>;
    delete missing[key];
    expect(() => parseScapAssertion(JSON.stringify(missing))).toThrow();
  }
  expect(() =>
    parseScapAssertion(JSON.stringify({ ...claim, actor: "untrusted" })),
  ).toThrow();
  expect(() =>
    parseScapAssertion('{"schema_version":"x","schema_version":"y"}'),
  ).toThrow();
  for (const completed_at of [
    "0000-01-01T00:00:00Z",
    "2024-02-30T00:00:00Z",
    "2024-01-01T24:00:00Z",
    "2024-01-01T00:00:60Z",
    "2024-01-01T00:00:00+00:00",
    "2024-01-01T00:00:00.0000001Z",
    "2024-01-01T00:00:00Z\n",
  ])
    expect(() =>
      parseScapAssertion(JSON.stringify({ ...claim, completed_at })),
    ).toThrow();
  await expect(
    prepareScapUpload(source.raw, {
      ...source.request,
      completion_assertion: { ...claim, source_sha256: "0".repeat(64) },
    }),
  ).rejects.toThrow();
});

const mutations: Array<[string, (r: ScapResult) => void]> = [
  [
    "source hash",
    (r) => {
      r.source.sha256 = "0".repeat(64);
    },
  ],
  [
    "source bytes",
    (r) => {
      r.source.bytes++;
    },
  ],
  [
    "selection",
    (r) => {
      r.assessment.selection.assessment_index = 1;
    },
  ],
  [
    "extra top field",
    (r) => {
      Object.assign(r, { extra: true });
    },
  ],
  [
    "missing nullable artifact",
    (r) => {
      Reflect.deleteProperty(r, "evidence_artifact");
    },
  ],
  [
    "artifact content hash",
    (r) => {
      r.evidence_artifact!.content_hash = "0".repeat(64);
    },
  ],
  [
    "artifact identity",
    (r) => {
      r.evidence_artifact!.id = "00000000-0000-5000-8000-000000000000";
    },
  ],
  [
    "artifact native copy",
    (r) => {
      r.evidence_artifact!.content.native_document.text = "changed";
    },
  ],
  [
    "artifact assessment copy",
    (r) => {
      r.evidence_artifact!.content.assessment.coverage.visible_unit_count++;
    },
  ],
  [
    "artifact source copy",
    (r) => {
      r.evidence_artifact!.content.source.bytes++;
    },
  ],
  [
    "finding hash",
    (r) => {
      r.assessment.finding_refs[0].source_key_sha256 = "0".repeat(64);
    },
  ],
  [
    "finding copy",
    (r) => {
      r.findings[0].raw_data.selected_outcome_count++;
    },
  ],
  [
    "native duplicate edge",
    (r) => {
      r.native_document.children.push(r.native_document.children[0]);
    },
  ],
  [
    "native missing edge",
    (r) => {
      r.native_document.children.pop();
    },
  ],
  [
    "native invalid index",
    (r) => {
      r.native_document.children[0] = 32768;
    },
  ],
  [
    "native extra nullable",
    (r) => {
      Object.assign(r.native_document, { unknown: null });
    },
  ],
  [
    "outcome count",
    (r) => {
      r.assessment.coverage.selected_outcome_count++;
    },
  ],
  [
    "outcome literal",
    (r) => {
      r.assessment.outcomes[0].native_result = "true";
    },
  ],
  [
    "outcome wrong reference",
    (r) => {
      r.assessment.outcomes[0].value_ref.attribute_index = 63;
    },
  ],
  [
    "outcome duplicates",
    (r) => {
      r.assessment.outcomes.push(r.assessment.outcomes[0]);
    },
  ],
  [
    "time normalization",
    (r) => {
      r.assessment.times[0].normalization.utc = "2024-01-01T00:00:00Z";
    },
  ],
  [
    "time role",
    (r) => {
      r.assessment.times[0].role = "assessment_completion";
    },
  ],
  [
    "invalid calendar",
    (r) => {
      r.imported_at = "2026-02-30T00:00:00Z";
    },
  ],
  [
    "noncanonical clock",
    (r) => {
      r.imported_at = "2026-09-13T00:00:00.000000Z";
    },
  ],
  [
    "clock order",
    (r) => {
      r.manifest.collection_finished_at = "2024-01-01T00:00:00Z";
    },
  ],
  [
    "manifest run copy",
    (r) => {
      r.findings[0].collection_context.run_id = "00000000000000000000000000";
    },
  ],
  [
    "actor missing provider",
    (r) => {
      r.completion.assertion!.actor.provider = null;
    },
  ],
  [
    "actor caller declared",
    (r) => {
      r.completion.assertion!.actor.basis = "caller_declared";
    },
  ],
  [
    "assertion source",
    (r) => {
      r.completion.assertion!.source_sha256 = "0".repeat(64);
    },
  ],
  [
    "assertion changed literal",
    (r) => {
      r.completion.assertion!.completed_at = "2024-03-01T00:00:00Z";
    },
  ],
  [
    "assertion future",
    (r) => {
      r.completion.assertion!.normalized_utc = "9999-01-01T00:00:00Z";
    },
  ],
  [
    "artifact availability",
    (r) => {
      r.artifact_availability.state = "unavailable";
    },
  ],
  [
    "cadence forged link",
    (r) => {
      r.cadence.linked_slug = "synthetic";
    },
  ],
  [
    "diagnostic message",
    (r) => {
      r.diagnostics[0].message = r.diagnostics[1].message;
    },
  ],
  [
    "diagnostic order",
    (r) => {
      r.diagnostics.reverse();
    },
  ],
  [
    "diagnostic duplicate",
    (r) => {
      r.diagnostics.push(r.diagnostics[0]);
    },
  ],
  [
    "warning copy",
    (r) => {
      r.manifest.warnings.pop();
    },
  ],
  [
    "nullable primitive",
    (r) => {
      Object.assign(r.findings[0], { resolved_at: false });
    },
  ],
  [
    "summary result mapping",
    (r) => {
      Object.assign(r.findings[0], { compliance_status: "compliant" });
    },
  ],
  [
    "data callback encoding",
    (r) => {
      Object.assign(r.source, { toJSON: "refused" });
    },
  ],
];
test.each(mutations)("complete response refuses %s", async (_name, mutate) => {
  const source = scapDemoSource("oval-5.8-asserted");
  const base = await scapDemoResponse(
    source.raw,
    source.request,
    "oval-5.8-asserted",
  );
  const input = JSON.parse(base.rawJson) as ScapResult;
  mutate(input);
  await expect(
    parseScapResponse(
      JSON.stringify(input),
      (await prepareScapUpload(source.raw, source.request)).expected,
    ),
  ).rejects.toThrow();
});
test("every top-level and artifact field remains required, including explicit nulls", async () => {
  const source = scapDemoSource("xccdf-qualified"),
    base = await scapDemoResponse(
      source.raw,
      source.request,
      "xccdf-qualified",
    );
  const expected = (await prepareScapUpload(source.raw, source.request))
    .expected;
  expect(Object.keys(base.result)).toHaveLength(13);
  expect(Object.keys(base.result.evidence_artifact!)).toHaveLength(25);
  for (const key of Object.keys(base.result)) {
    const input = JSON.parse(base.rawJson) as Record<string, unknown>;
    delete input[key];
    await expect(
      parseScapResponse(JSON.stringify(input), expected),
    ).rejects.toThrow();
  }
  for (const key of Object.keys(base.result.evidence_artifact!)) {
    const input = JSON.parse(base.rawJson) as ScapResult;
    Reflect.deleteProperty(input.evidence_artifact!, key);
    await expect(
      parseScapResponse(JSON.stringify(input), expected),
    ).rejects.toThrow();
  }
});
test("raw download preserves original whitespace, property order and artifact slice", async () => {
  const source = scapDemoSource("xccdf-qualified"),
    base = await scapDemoResponse(
      source.raw,
      source.request,
      "xccdf-qualified",
    );
  const raw =
    " \n" + JSON.stringify(JSON.parse(base.rawJson), null, 2) + "\r\n";
  const response = await parseScapResponse(
    raw,
    (await prepareScapUpload(source.raw, source.request)).expected,
  );
  expect(response.rawJson).toBe(raw);
  expect(raw.includes(response.artifactRawJson!)).toBe(true);
  expect(JSON.parse(response.artifactRawJson!)).toEqual(
    response.result.evidence_artifact,
  );
});
test("stream enforces actual bytes, content type, UTF-8 and cancellation", async () => {
  const source = scapDemoSource("xccdf-qualified"),
    base = await scapDemoResponse(
      source.raw,
      source.request,
      "xccdf-qualified",
    ),
    expected = (await prepareScapUpload(source.raw, source.request)).expected;
  const raw = new TextEncoder().encode(base.rawJson);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(raw.slice(0, 17));
      controller.enqueue(raw.slice(17));
      controller.close();
    },
  });
  expect(
    (
      await readScapResponse(
        new Response(stream, {
          headers: {
            "Content-Type": "application/json",
            "Content-Length": "1",
          },
        }),
        expected,
      )
    ).rawJson,
  ).toBe(base.rawJson);
  const cancel = vi.fn();
  const huge = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(SCAP_RESULT_BYTES + 1));
    },
    cancel,
  });
  await expect(
    readScapResponse(
      new Response(huge, { headers: { "Content-Type": "application/json" } }),
      expected,
    ),
  ).rejects.toThrow();
  expect(cancel).toHaveBeenCalledOnce();
  await expect(
    readScapResponse(
      new Response(new Uint8Array([0xff]), {
        headers: { "Content-Type": "application/json" },
      }),
      expected,
    ),
  ).rejects.toThrow();
  await expect(
    readScapResponse(
      new Response(base.rawJson, { headers: { "Content-Type": "text/html" } }),
      expected,
    ),
  ).rejects.toThrow();
});

test("bounded preview preserves Unicode boundaries and never invokes source accessors", () => {
  const text = boundedScapPreview("😀".repeat(10000), 16);
  expect(text.startsWith("😀".repeat(4) + "\n")).toBe(true);
  expect(text).toContain("Preview truncated");
  let calls = 0;
  const value = Object.defineProperty({}, "source", {
    enumerable: true,
    get: () => {
      calls++;
      return "hidden";
    },
  });
  expect(boundedScapPreview(value)).toContain("Unavailable");
  expect(calls).toBe(0);
  expect(() => boundedScapPreview("text", 1000000)).toThrow();
});

test("corresponding counter edits cannot omit a native outcome from a null-artifact result", async () => {
  const source = scapDemoSource("oval-5.8-undated"),
    good = await scapDemoResponse(
      source.raw,
      source.request,
      "oval-5.8-undated",
    );
  const input = JSON.parse(good.rawJson) as ScapResult;
  const removed = input.assessment.outcomes.pop()!;
  expect(removed.level).toBe("oval_test");
  const coverage = input.assessment.coverage;
  coverage.visible_outcome_count--;
  coverage.selected_outcome_count--;
  coverage.top_level_outcome_count--;
  coverage.countable_top_level_outcome_count--;
  coverage.outcome_counts.find(
    (row) => row.level === "oval_test" && row.native_result === "false",
  )!.count--;
  input.findings[0].raw_data.selected_outcome_count--;
  input.findings[0].raw_data.top_level_outcome_count--;
  input.findings[0].raw_data.countable_top_level_outcome_count--;
  await expect(
    parseScapResponse(
      JSON.stringify(input),
      (await prepareScapUpload(source.raw, source.request)).expected,
    ),
  ).rejects.toThrow();
});

test("directive detail agrees with every retained reported rule", async () => {
  const source = scapDemoSource("oval-5.8-undated"),
    good = await scapDemoResponse(
      source.raw,
      source.request,
      "oval-5.8-undated",
    );
  const input = JSON.parse(good.rawJson) as ScapResult;
  input.assessment.coverage.native_export_detail = "thin";
  await expect(
    parseScapResponse(
      JSON.stringify(input),
      (await prepareScapUpload(source.raw, source.request)).expected,
    ),
  ).rejects.toThrow();
});

const cadenceCases = [
  ["cadence-qualified", "linked", []],
  ["cadence-undated", "ineligible", ["native_completion_absent"]],
  ["cadence-empty", "ineligible", ["no_selected_outcome_evidence"]],
  ["cadence-unevaluated", "ineligible", ["selected_outcomes_not_evaluated"]],
] as const;
test.each(cadenceCases)(
  "%s preserves the required requested-cadence state",
  async (id, state, reasons) => {
    const source = scapDemoSource(id);
    const response = await scapDemoResponse(source.raw, source.request, id);
    expect(response.result.cadence).toEqual({
      requested_slug: "fedramp-conmon-scans",
      linked_slug: state === "linked" ? "fedramp-conmon-scans" : null,
      state,
      reasons,
    });
  },
);

const ovalPositionIds = ["5.8", "5.11.2", "5.12.3"].map(
  (version) => "oval-" + version + "-native-positions",
);
test.each(ovalPositionIds)(
  "%s retains every compilation scope and only selected status positions",
  async (id) => {
    const source = scapDemoSource(id);
    const { result } = await scapDemoResponse(source.raw, source.request, id);
    expect(result.evidence_artifact).toBeNull();
    expect(result.assessment.selection.assessment_index).toBe(1);
    expect(result.assessment.units).toHaveLength(2);
    expect(
      result.assessment.times.map((time) => [time.scope, time.role]),
    ).toEqual([
      ["document", "document_compilation"],
      ["embedded_definitions", "document_compilation"],
      ["system_characteristics", "document_compilation"],
      ["system_characteristics", "document_compilation"],
    ]);
    for (const time of result.assessment.times) {
      const node = result.native_document.nodes[time.value_ref.node_index];
      expect(node.kind).toBe("element");
      if (node.kind === "element")
        expect(node.name).toEqual({
          namespace_uri: "http://oval.mitre.org/XMLSchema/oval-common-5",
          local_name: "timestamp",
        });
      expect(time.value_ref.slot).toBe("element_simple_content");
      expect(time.value_ref.attribute_index).toBeNull();
    }
    const coverage = result.assessment.coverage;
    expect(coverage.collection_flags.map((flag) => flag.native_flag)).toEqual([
      "complete",
    ]);
    expect(
      coverage.status_observations.map((status) => [
        status.scope,
        status.effective_status,
        status.interpretation,
      ]),
    ).toEqual([
      ["direct_system_data_child", null, "unverified_platform_status"],
      ["nested_platform_position", null, "unverified_platform_status"],
    ]);
    expect(
      coverage.core_status_defaults.map((status) => [
        status.present,
        status.effective_status,
      ]),
    ).toEqual(id === "oval-5.8-native-positions" ? [[true, "error"]] : []);
  },
);

const positionMutations: Array<[string, (result: ScapResult) => void]> = [
  [
    "missing root generator time",
    (r) => {
      r.assessment.times.splice(0, 1);
    },
  ],
  [
    "missing embedded generator time",
    (r) => {
      r.assessment.times.splice(1, 1);
    },
  ],
  [
    "missing unselected system generator time",
    (r) => {
      r.assessment.times.splice(2, 1);
    },
  ],
  [
    "missing selected system generator time",
    (r) => {
      r.assessment.times.splice(3, 1);
    },
  ],
  [
    "root generator mislabeled as system characteristics",
    (r) => {
      r.assessment.times[0].scope = "system_characteristics";
    },
  ],
  [
    "embedded generator assigned to document root",
    (r) => {
      r.assessment.times[1].scope_node_index = 0;
      r.assessment.times[1].scope = "document";
    },
  ],
  [
    "generator reference changes its native slot",
    (r) => {
      r.assessment.times[0].value_ref.slot = "text";
    },
  ],
  [
    "time order changed",
    (r) => {
      r.assessment.times.reverse();
    },
  ],
  [
    "missing selected collection flag",
    (r) => {
      r.assessment.coverage.collection_flags.pop();
    },
  ],
  [
    "duplicated selected collection flag",
    (r) => {
      r.assessment.coverage.collection_flags.push(
        structuredClone(r.assessment.coverage.collection_flags[0]),
      );
    },
  ],
  [
    "missing direct platform status",
    (r) => {
      r.assessment.coverage.status_observations.splice(0, 1);
    },
  ],
  [
    "missing nested platform status",
    (r) => {
      r.assessment.coverage.status_observations.pop();
    },
  ],
  [
    "duplicated platform status",
    (r) => {
      r.assessment.coverage.status_observations.push(
        structuredClone(r.assessment.coverage.status_observations[0]),
      );
    },
  ],
  [
    "nested platform status mislabeled as direct",
    (r) => {
      r.assessment.coverage.status_observations[1].scope =
        "direct_system_data_child";
    },
  ],
  [
    "platform status order changed",
    (r) => {
      r.assessment.coverage.status_observations.reverse();
    },
  ],
  [
    "unselected platform status substituted",
    (r) => {
      const index = r.native_document.nodes.findIndex(
        (node) =>
          node.kind === "element" &&
          node.name.namespace_uri === "urn:synthetic:console:status" &&
          node.name.local_name === "item",
      );
      expect(index).toBeGreaterThanOrEqual(0);
      r.assessment.coverage.status_observations[0].node_index = index;
      r.assessment.coverage.status_observations[0].value_ref.node_index = index;
    },
  ],
];
const positionCases: Array<[string, string, (result: ScapResult) => void]> =
  ovalPositionIds.flatMap((id) =>
    positionMutations.map<[string, string, (result: ScapResult) => void]>(
      ([name, mutate]) => [id, name, mutate],
    ),
  );
test.each(positionCases)(
  "%s refuses %s with unchanged source and native graph",
  async (id, _name, mutate) => {
    const source = scapDemoSource(id);
    const good = await scapDemoResponse(source.raw, source.request, id);
    const input = JSON.parse(good.rawJson) as ScapResult;
    expect(input.evidence_artifact).toBeNull();
    const before = JSON.stringify([input.source, input.native_document]);
    mutate(input);
    expect(JSON.stringify([input.source, input.native_document])).toBe(before);
    await expect(
      parseScapResponse(
        JSON.stringify(input),
        (await prepareScapUpload(source.raw, source.request)).expected,
      ),
    ).rejects.toThrow();
  },
);

test.each(["oval-5.8-undated", "oval-5.8-native-positions"])(
  "%s refuses omitted or duplicate core status cells",
  async (id) => {
    const source = scapDemoSource(id);
    const good = await scapDemoResponse(source.raw, source.request, id);
    for (const duplicate of [false, true]) {
      const input = JSON.parse(good.rawJson) as ScapResult;
      expect(input.evidence_artifact).toBeNull();
      expect(input.assessment.coverage.core_status_defaults).toHaveLength(1);
      if (duplicate)
        input.assessment.coverage.core_status_defaults.push(
          structuredClone(input.assessment.coverage.core_status_defaults[0]),
        );
      else input.assessment.coverage.core_status_defaults.pop();
      await expect(
        parseScapResponse(
          JSON.stringify(input),
          (await prepareScapUpload(source.raw, source.request)).expected,
        ),
      ).rejects.toThrow();
    }
  },
);
test("selected core status cannot be replaced by the same literal in an unselected system", async () => {
  const source = scapDemoSource("oval-5.8-native-positions");
  const good = await scapDemoResponse(
    source.raw,
    source.request,
    "oval-5.8-native-positions",
  );
  const input = JSON.parse(good.rawJson) as ScapResult;
  const index = input.native_document.nodes.findIndex(
    (node) =>
      node.kind === "element" &&
      node.name.namespace_uri ===
        "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" &&
      node.name.local_name === "ip_address",
  );
  expect(index).toBeGreaterThanOrEqual(0);
  const cell = input.assessment.coverage.core_status_defaults[0];
  cell.node_index = index;
  cell.value_ref!.node_index = index;
  await expect(
    parseScapResponse(
      JSON.stringify(input),
      (await prepareScapUpload(source.raw, source.request)).expected,
    ),
  ).rejects.toThrow();
});
test("XCCDF retains selected start, completion, tailoring, rule and override times exactly once", async () => {
  const source = scapDemoSource("xccdf-native-times");
  const good = await scapDemoResponse(
    source.raw,
    source.request,
    "xccdf-native-times",
  );
  expect(good.result.evidence_artifact).toBeNull();
  expect(good.result.assessment.times.map((time) => time.role)).toEqual([
    "assessment_start",
    "assessment_completion",
    "tailoring_version_time",
    "rule_completion",
    "override_time",
  ]);
  for (let index = 0; index < 5; index++) {
    const input = JSON.parse(good.rawJson) as ScapResult;
    input.assessment.times.splice(index, 1);
    await expect(
      parseScapResponse(
        JSON.stringify(input),
        (await prepareScapUpload(source.raw, source.request)).expected,
      ),
    ).rejects.toThrow();
  }
});
