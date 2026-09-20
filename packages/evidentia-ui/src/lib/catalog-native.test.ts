// @vitest-environment node
/// <reference types="node" />
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type {
  NativeBundle,
  NativeCatalog,
  NativeRequest,
  CatalogNativeNativeData,
  ValueRef,
} from "./catalog-native";
import {
  decodeNativeBundle,
  decodeNativeCatalog,
  decodeNativeSurface,
  readNativeResponse,
  nativeBundleDownload,
  nativeDocumentDownload,
  nativeRefText,
  nativePreview,
  occurrencePage,
  createNativeSelection,
  bindNativeControl,
} from "./catalog-native";

const hash = (value: string | Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
const compact = (value: unknown): string =>
  JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
const source =
  '{"id":"G","controls":[{"id":"C","n":9007199254740993,"x":null,"u":"é"}]}';
const bytes = (value: string) => new TextEncoder().encode(value);
function ref(start: number, end: number, kind: ValueRef["kind"]): ValueRef {
  return {
    document_index: 0,
    byte_start: start,
    byte_end: end,
    kind,
    sha256: hash(bytes(source).slice(start, end)),
  };
}
// These offsets count the authored UTF-8 source, including the two-byte é.
function example(): NativeBundle {
  const group = ref(0, 73, "json_object");
  const control = ref(22, 71, "json_object");
  const data: CatalogNativeNativeData = {
    schema_version: "catalog-native-v1",
    profile: "au-ism-2026.09.4",
    catalog_id: "au-ism",
    converter_id: "evidentia-open-corpora-v1",
    converter_sha256: "a".repeat(64),
    documents: [
      {
        binding: {
          source_key: "synthetic",
          role: "authoritative",
          media_type: "application/json",
          repository: "Synthetic/source",
          commit: "b".repeat(40),
          upstream_path: "synthetic.json",
          raw_bytes: 73,
          raw_sha256: hash(source),
        },
        raw_utf8: source,
      },
    ],
    occurrences: [
      {
        index: 0,
        kind: "group",
        parent_index: null,
        sibling_ordinal: 0,
        source: group,
        fields: [
          {
            name: "id",
            key: ref(1, 5, "json_string"),
            value: ref(6, 9, "json_string"),
          },
          {
            name: "controls",
            key: ref(10, 20, "json_string"),
            value: ref(21, 72, "json_array"),
          },
        ],
        selections: [],
      },
      {
        index: 1,
        kind: "control",
        parent_index: 0,
        sibling_ordinal: 0,
        source: control,
        fields: [
          {
            name: "id",
            key: ref(23, 27, "json_string"),
            value: ref(28, 31, "json_string"),
          },
          {
            name: "n",
            key: ref(32, 35, "json_string"),
            value: ref(36, 52, "json_number"),
          },
          {
            name: "x",
            key: ref(53, 56, "json_string"),
            value: ref(57, 61, "json_null"),
          },
          {
            name: "u",
            key: ref(62, 65, "json_string"),
            value: ref(66, 70, "json_string"),
          },
        ],
        selections: [
          {
            role: "native_id",
            value: { state: "present", refs: [ref(28, 31, "json_string")] },
          },
          {
            role: "parameter",
            value: { state: "native_null", refs: [ref(57, 61, "json_null")] },
          },
          { role: "statement", value: { state: "absent" } },
        ],
      },
    ],
    control_bindings: [
      {
        control_id: "C",
        occurrence_index: 1,
        family_occurrence_index: 0,
        parent_control_id: null,
        admitted_criticality: null,
      },
    ],
    context_indices: [0],
    diagnostics: [],
  };
  return seal(data);
}
function seal(data: CatalogNativeNativeData): NativeBundle {
  return {
    bundle_sha256: hash("evidentia.catalog-native.v1\0" + compact(data)),
    data,
  };
}
const expected = (bundle: NativeBundle): NativeRequest => ({
  framework_id: "au-ism",
  bundle_sha256: bundle.bundle_sha256,
});
function ordinary(bundle: NativeBundle): NativeCatalog {
  return {
    framework_id: "au-ism",
    framework_name: "Synthetic",
    version: "1",
    source: "Synthetic/source",
    controls: [
      {
        id: "C",
        title: "Synthetic control",
        description: "Server-projected prose",
        family: "native-group:0",
        class: null,
        control_class: null,
        priority: null,
        baseline_impact: [],
        enhancements: [],
        related_controls: [],
        assessment_objectives: [],
        objective: null,
        risk_tier: null,
        applies_to_annex_iii: null,
        guidance: null,
        examples: [],
        parameters: {},
        ordering: 0,
        tier: null,
        license_required: false,
        license_url: null,
        placeholder: false,
        withdrawn: false,
        properties: {},
        source_rows: [],
        native_source_ref: {
          bundle_sha256: bundle.bundle_sha256,
          occurrence_index: 1,
        },
      },
    ],
    families: ["native-group:0"],
    family_hierarchy: null,
    category: "control",
    tier: null,
    v0_9_3_note: null,
    annex_iii_risk_categories: null,
    license_required: false,
    license_terms: null,
    license_url: null,
    placeholder: false,
    status: null,
    notes: null,
    verified_on: null,
    superseded_by: null,
    audit_contexts: {},
    publication_notices: [],
    native_source: bundle,
  };
}

describe("native catalog boundary", () => {
  it("checks independently authored source dimensions before decoder execution", () => {
    expect(bytes(source).length).toBe(73);
    expect(new TextDecoder().decode(bytes(source).slice(36, 52))).toBe(
      "9007199254740993",
    );
  });
  it("retains source spelling, exact large numbers and immutable context", async () => {
    const b = example();
    const result = await decodeNativeBundle(JSON.stringify(b), expected(b));
    expect(
      nativeRefText(result, result.data.occurrences[1].fields[1].value),
    ).toBe("9007199254740993");
    expect(new TextDecoder().decode(nativeDocumentDownload(result, 0))).toBe(
      source,
    );
    expect(new TextDecoder().decode(nativeBundleDownload(result))).toBe(
      compact(b),
    );
    expect(Object.isFrozen(result.data.occurrences[1].fields)).toBe(true);
    expect(occurrencePage(result, 0)).toHaveLength(2);
    expect(() => occurrencePage(result, -1)).toThrow();
    expect(
      bindNativeControl(result, "C", {
        bundle_sha256: b.bundle_sha256,
        occurrence_index: 1,
      }),
    ).toBe(result.data.occurrences[1]);
    expect(() =>
      bindNativeControl(result, "missing", {
        bundle_sha256: b.bundle_sha256,
        occurrence_index: 1,
      }),
    ).toThrow();
  });
  it.each([
    (b: NativeBundle) => {
      b.data.documents[0].binding.raw_bytes++;
    },
    (b: NativeBundle) => {
      b.data.documents[0].raw_utf8 += " ";
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].fields.pop();
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].fields.reverse();
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].index = 3;
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].parent_index = 1;
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].sibling_ordinal = 1;
    },
    (b: NativeBundle) => {
      b.data.context_indices = [0, 0];
    },
    (b: NativeBundle) => {
      b.data.control_bindings.push({ ...b.data.control_bindings[0] });
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].fields[0].value.sha256 = "f".repeat(64);
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].selections[1].value.state = "present";
    },
    (b: NativeBundle) => {
      b.data.occurrences[1].selections.push(
        b.data.occurrences[1].selections[0],
      );
    },
    (b: NativeBundle) => {
      Object.assign(b.data, { extra: 1 });
    },
  ])(
    "refuses self-consistent rehashing of a malformed graph (%#)",
    async (change) => {
      const b = example();
      change(b);
      const bad = seal(b.data);
      await expect(
        decodeNativeBundle(JSON.stringify(bad), expected(bad)),
      ).rejects.toThrow();
    },
  );
  it("refuses wrong generation, duplicate decoded keys, invalid Unicode and native coercions", async () => {
    const b = example();
    const wire = JSON.stringify(b);
    await expect(
      decodeNativeBundle(wire, {
        ...expected(b),
        bundle_sha256: "0".repeat(64),
      }),
    ).rejects.toThrow();
    await expect(
      decodeNativeBundle(wire, { ...expected(b), framework_id: "cisa-scuba" }),
    ).rejects.toThrow();
    await expect(
      decodeNativeBundle(
        wire.replace('"data":', '"\\u0064ata":{},"data":'),
        expected(b),
      ),
    ).rejects.toThrow();
    await expect(
      decodeNativeBundle(wire.replace('"synthetic"', '"\\ud800"'), expected(b)),
    ).rejects.toThrow();
    await expect(
      decodeNativeBundle(
        wire.replace('"index":0', '"index":false'),
        expected(b),
      ),
    ).rejects.toThrow();
  });
  it("binds all ordinary identities, hierarchy and refs, with prose semantics owned by the server", async () => {
    const b = example();
    const catalog = ordinary(b);
    const result = await decodeNativeCatalog(
      JSON.stringify(catalog),
      expected(b),
    );
    expect(result.controls[0].id).toBe("C");
    catalog.controls[0].description =
      "Different prose still needs server source verification";
    expect(
      (await decodeNativeCatalog(JSON.stringify(catalog), expected(b)))
        .controls[0].description,
    ).toBe(catalog.controls[0].description);
    for (const mutate of [
      (c: NativeCatalog) => {
        c.framework_id = "cisa-scuba";
      },
      (c: NativeCatalog) => {
        c.controls[0].id = "D";
      },
      (c: NativeCatalog) => {
        c.controls = [];
      },
      (c: NativeCatalog) => {
        c.controls.push(structuredClone(c.controls[0]));
      },
      (c: NativeCatalog) => {
        c.controls[0].enhancements.push(structuredClone(c.controls[0]));
      },
      (c: NativeCatalog) => {
        c.controls[0].native_source_ref!.bundle_sha256 = "d".repeat(64);
      },
      (c: NativeCatalog) => {
        c.controls[0].native_source_ref!.occurrence_index = 0;
      },
      (c: NativeCatalog) => {
        c.controls[0].family = "native-group:1";
      },
      (c: NativeCatalog) => {
        Object.assign(c.controls[0], { unknown: true });
      },
    ]) {
      const c = ordinary(b);
      mutate(c);
      await expect(
        decodeNativeCatalog(JSON.stringify(c), expected(b)),
      ).rejects.toThrow();
    }
  });
  it("bounds bytes before parsing and releases a refused stream", async () => {
    let canceled = 0;
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array(16_777_217));
      },
      cancel() {
        canceled++;
      },
    });
    await expect(readNativeResponse(new Response(stream))).rejects.toThrow();
    expect(canceled).toBe(1);
    expect(stream.locked).toBe(false);
    await expect(
      readNativeResponse(new Response(new Uint8Array([0xc0, 0xaf]))),
    ).rejects.toThrow();
  });
  it("keeps literal inert previews within 4096 UTF-8 bytes", () => {
    const p = nativePreview("é".repeat(3000));
    expect(bytes(p.text).length).toBe(4096);
    expect(p.truncated).toBe(true);
    expect(nativePreview("<script>alert(1)</script>").text).toBe(
      "<script>alert(1)</script>",
    );
  });
  it("keeps last good state when cancellation, selection or auth changes", async () => {
    const b = example();
    const state = createNativeSelection();
    const first = state.begin("au-ism", b.bundle_sha256, "C", 1);
    const result = await decodeNativeBundle(JSON.stringify(b), expected(b));
    expect(state.accept(first, result)).toBe(true);
    const pending = state.begin("au-ism", b.bundle_sha256, "C", 1);
    state.invalidate();
    expect(pending.signal.aborted).toBe(true);
    expect(state.accept(pending, result)).toBe(false);
    expect(state.lastGood).toBe(result);
    const other = state.begin("au-ism", "e".repeat(64), "C", 2);
    expect(state.accept(other, result)).toBe(false);
    expect(state.lastGood).toBe(result);
  });
  it("validates the complete three-document key set and aggregate bytes", () => {
    const req = {
      profile: "bsi-grundschutz-plus-plus-367d7750",
      documents: ["bsi-catalog", "bsi-license", "bsi-readme"].map(
        (source_key) => ({ source_key, raw_utf8: "" }),
      ),
    };
    expect(decodeNativeSurface("importRequest", JSON.stringify(req))).toEqual(
      req,
    );
    req.documents[2].source_key = "bsi-license";
    expect(() =>
      decodeNativeSurface("importRequest", JSON.stringify(req)),
    ).toThrow();
  });
});

const failedObservation = (code = "catalog_storage_failed") => ({
  schema_version: "catalog-publication-observation-v1",
  operation: "native_import",
  publication_state: "not_attempted",
  prior_manifest_state: "unread",
  prior_sha256: null,
  proposed_sha256: null,
  replace_outcome: "not_called",
  observed_manifest_state: "not_observed",
  observed_sha256: null,
  readback_result: "not_attempted",
  cleanup_state: "complete",
  cleanup_errors: [],
  failure_phase: code === "catalog_cleanup_failed" ? "cleanup" : "admission",
  primary_kind: "exception",
  error_code: code,
  ...(code === "catalog_cleanup_failed"
    ? { cleanup_state: "failed", cleanup_errors: ["handle_close_failed"] }
    : {}),
});
it.each([
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
])("keeps ordinary error envelope code equal to its ledger: %s", (code) => {
  const value = { code, publication: failedObservation(code) };
  expect(decodeNativeSurface("storageError", JSON.stringify(value))).toEqual(
    value,
  );
  expect(() =>
    decodeNativeSurface(
      "storageError",
      JSON.stringify({ ...value, code: "native_source_invalid" }),
    ),
  ).toThrow();
});
it("rejects interruption in HTTP envelopes and duplicate cleanup errors", () => {
  const p = {
    ...failedObservation("catalog_interrupted"),
    primary_kind: "base_exception",
  };
  expect(decodeNativeSurface("publication", JSON.stringify(p))).toEqual(p);
  expect(() =>
    decodeNativeSurface(
      "storageError",
      JSON.stringify({ code: "catalog_interrupted", publication: p }),
    ),
  ).toThrow();
  expect(() =>
    decodeNativeSurface(
      "publication",
      JSON.stringify({
        ...p,
        cleanup_state: "failed",
        cleanup_errors: ["handle_close_failed", "handle_close_failed"],
      }),
    ),
  ).toThrow();
  expect(() =>
    decodeNativeSurface(
      "storageError",
      JSON.stringify({
        code: "catalog_publication_failed",
        publication: failedObservation(),
      }),
    ),
  ).toThrow();
});
it("admits exact aggregate uploads and rejects a one-byte excess", () => {
  const request = {
    profile: "bsi-grundschutz-plus-plus-367d7750",
    documents: [
      { source_key: "bsi-catalog", raw_utf8: "x".repeat(4_194_304) },
      { source_key: "bsi-license", raw_utf8: "y".repeat(4_194_304) },
      { source_key: "bsi-readme", raw_utf8: "" },
    ],
  };
  expect(decodeNativeSurface("importRequest", JSON.stringify(request))).toEqual(
    request,
  );
  request.documents[2].raw_utf8 = "z";
  expect(() =>
    decodeNativeSurface("importRequest", JSON.stringify(request)),
  ).toThrow();
});
it("retains empty, false, zero and opaque native tokens without interpreting numbers", async () => {
  const raw = '{"x":false,"n":0,"s":"","a":[],"o":{}}';
  const reference = (
    start: number,
    end: number,
    kind: ValueRef["kind"],
  ): ValueRef => ({
    document_index: 0,
    byte_start: start,
    byte_end: end,
    kind,
    sha256: hash(bytes(raw).slice(start, end)),
  });
  const facts = [
    ["x", "false", "json_boolean"],
    ["n", "0", "json_number"],
    ["s", '""', "json_string"],
    ["a", "[]", "json_array"],
    ["o", "{}", "json_object"],
  ] as const;
  const fields = facts.map(([name, token, kind]) => {
    const start = raw.indexOf('"' + name + '"');
    const value = start + name.length + 3;
    return {
      name,
      key: reference(start, start + name.length + 2, "json_string"),
      value: reference(value, value + token.length, kind),
    };
  });
  const d = example().data;
  d.documents[0].raw_utf8 = raw;
  d.documents[0].binding.raw_bytes = bytes(raw).length;
  d.documents[0].binding.raw_sha256 = hash(raw);
  d.occurrences = [
    {
      index: 0,
      kind: "metadata",
      parent_index: null,
      sibling_ordinal: 0,
      source: reference(0, bytes(raw).length, "json_object"),
      fields,
      selections: [],
    },
  ];
  d.control_bindings = [];
  d.context_indices = [0];
  const b = seal(d);
  const result = await decodeNativeBundle(JSON.stringify(b), expected(b));
  expect(
    result.data.occurrences[0].fields.map((f) =>
      nativeRefText(result, f.value),
    ),
  ).toEqual(["false", "0", '""', "[]", "{}"]);
});
it("refuses duplicated keys inside retained source and mid-codepoint references", async () => {
  const b = example();
  b.data.documents[0].raw_utf8 = '{"k":1,"\\u006b":2}';
  b.data.documents[0].binding.raw_bytes = bytes(
    b.data.documents[0].raw_utf8,
  ).length;
  b.data.documents[0].binding.raw_sha256 = hash(b.data.documents[0].raw_utf8);
  let bad = seal(b.data);
  await expect(
    decodeNativeBundle(JSON.stringify(bad), expected(bad)),
  ).rejects.toThrow();
  const x = example();
  const r = x.data.occurrences[1].fields[3].value;
  r.byte_start = 68;
  r.byte_end = 69;
  r.sha256 = hash(bytes(source).slice(68, 69));
  bad = seal(x.data);
  await expect(
    decodeNativeBundle(JSON.stringify(bad), expected(bad)),
  ).rejects.toThrow();
});
it("cancels a blocked response read and ignores headers that understate bytes", async () => {
  let canceled = 0;
  const abort = new AbortController();
  const stream = new ReadableStream<Uint8Array>({
    cancel() {
      canceled++;
    },
  });
  const pending = readNativeResponse(
    new Response(stream, { headers: { "Content-Length": "0" } }),
    abort.signal,
  );
  abort.abort(new DOMException("Synthetic abort", "AbortError"));
  await expect(pending).rejects.toThrow("Synthetic abort");
  expect(canceled).toBe(1);
  expect(stream.locked).toBe(false);
});
it("refuses decoding after captured cancellation without publishing a bundle", async () => {
  const b = example();
  const abort = new AbortController();
  abort.abort();
  await expect(
    decodeNativeBundle(JSON.stringify(b), expected(b), abort.signal),
  ).rejects.toThrow();
});

it("enforces the two literal publication error precedence rules", () => {
  const p = {
    ...failedObservation("catalog_generation_conflict"),
    publication_state: "committed",
    proposed_sha256: "1".repeat(64),
    replace_outcome: "returned",
    observed_manifest_state: "present",
    observed_sha256: "2".repeat(64),
    readback_result: "other",
    failure_phase: "readback",
  };
  expect(decodeNativeSurface("publication", JSON.stringify(p))).toEqual(p);
  expect(() =>
    decodeNativeSurface(
      "publication",
      JSON.stringify({ ...p, error_code: "catalog_storage_failed" }),
    ),
  ).toThrow();
  const interrupted = {
    ...p,
    primary_kind: "base_exception",
    error_code: "catalog_interrupted",
  };
  expect(
    decodeNativeSurface("publication", JSON.stringify(interrupted)),
  ).toEqual(interrupted);
  expect(() =>
    decodeNativeSurface(
      "publication",
      JSON.stringify({
        ...failedObservation("catalog_cleanup_failed"),
        failure_phase: "admission",
      }),
    ),
  ).toThrow();
});
it("applies the wire prose bound separately from source-owner raw fields", async () => {
  const b = example();
  const c = ordinary(b);
  c.controls[0].description = "é".repeat(131072);
  expect(
    (await decodeNativeCatalog(JSON.stringify(c), expected(b))).controls[0]
      .description,
  ).toBe(c.controls[0].description);
  c.controls[0].description += "a";
  await expect(
    decodeNativeCatalog(JSON.stringify(c), expected(b)),
  ).rejects.toThrow();
});
it("does not apply the publisher 64-member object cap to the canonical wire", async () => {
  const b = example();
  const c = ordinary(b);
  for (let i = 0; i < 65; i++)
    c.controls[0].properties["synthetic-" + i] = "inert";
  expect(
    Object.keys(
      (await decodeNativeCatalog(JSON.stringify(c), expected(b))).controls[0]
        .properties,
    ),
  ).toHaveLength(65);
});
it("captures exact own request data without invoking getters or toJSON", async () => {
  const b = example();
  let calls = 0;
  const request = Object.defineProperties(
    {},
    {
      framework_id: {
        enumerable: true,
        get() {
          calls++;
          return "au-ism";
        },
      },
      bundle_sha256: { enumerable: true, value: b.bundle_sha256 },
    },
  ) as NativeRequest;
  await expect(
    decodeNativeBundle(JSON.stringify(b), request),
  ).rejects.toThrow();
  expect(calls).toBe(0);
  const converted = {
    ...expected(b),
    toJSON() {
      calls++;
      return expected(b);
    },
  };
  await expect(
    decodeNativeBundle(JSON.stringify(b), converted),
  ).rejects.toThrow();
  expect(calls).toBe(0);
});
it("retains astral raw bytes and exact ensure-ascii serialization", async () => {
  const raw = "😀\r\n<inert>&\u007f";
  const d = example().data;
  d.documents[0] = {
    ...d.documents[0],
    binding: {
      ...d.documents[0].binding,
      media_type: "text/plain",
      raw_bytes: bytes(raw).length,
      raw_sha256: hash(raw),
    },
    raw_utf8: raw,
  };
  const r: ValueRef = {
    document_index: 0,
    byte_start: 0,
    byte_end: bytes(raw).length,
    kind: "utf8_text",
    sha256: hash(raw),
  };
  d.occurrences = [
    {
      index: 0,
      kind: "context_block",
      parent_index: null,
      sibling_ordinal: 0,
      source: r,
      fields: [],
      selections: [],
    },
  ];
  d.control_bindings = [];
  d.context_indices = [0];
  const b = seal(d);
  const result = await decodeNativeBundle(JSON.stringify(b), expected(b));
  expect(new TextDecoder().decode(nativeBundleDownload(result))).toBe(
    compact(b),
  );
  expect(nativeDocumentDownload(result, 0)).toEqual(bytes(raw));
  expect(nativeRefText(result, r)).toBe(raw);
  const download = nativeDocumentDownload(result, 0);
  download.fill(0);
  expect(nativeDocumentDownload(result, 0)).toEqual(bytes(raw));
});
it("admits the actual exact reader byte limit independently of JSON shape", async () => {
  const raw = new Uint8Array(16_777_216).fill(0x20);
  expect((await readNativeResponse(new Response(raw))).length).toBe(raw.length);
});

describe("publication readback classification with equal hashes", () => {
  const observation = (
    replace_outcome: "returned" | "raised",
    readback_result: "matches_prior" | "matches_proposed",
  ) => ({
    schema_version: "catalog-publication-observation-v1",
    operation: "native_import",
    publication_state: "committed",
    prior_manifest_state: "present",
    prior_sha256: "a".repeat(64),
    proposed_sha256: "a".repeat(64),
    replace_outcome,
    observed_manifest_state: "present",
    observed_sha256: "a".repeat(64),
    readback_result,
    cleanup_state: "complete",
    cleanup_errors: [],
    failure_phase: replace_outcome === "raised" ? "replace" : null,
    primary_kind: replace_outcome === "raised" ? "exception" : "none",
    error_code:
      replace_outcome === "raised" ? "catalog_publication_failed" : null,
  });

  it.each(["returned", "raised"] as const)(
    "refuses matches_prior for %s committed outcomes despite equal hashes",
    (replaceOutcome) => {
      const value = observation(replaceOutcome, "matches_prior");
      expect(() =>
        decodeNativeSurface("publication", JSON.stringify(value)),
      ).toThrow();
    },
  );

  it.each(["returned", "raised"] as const)(
    "retains matches_proposed for %s committed outcomes with equal hashes",
    (replaceOutcome) => {
      const value = observation(replaceOutcome, "matches_proposed");
      expect(decodeNativeSurface("publication", JSON.stringify(value))).toEqual(
        value,
      );
    },
  );

  it("refuses matches_prior in the ordinary raised-replace error envelope", () => {
    const value = {
      code: "catalog_publication_failed",
      publication: observation("raised", "matches_prior"),
    };
    expect(() =>
      decodeNativeSurface("storageError", JSON.stringify(value)),
    ).toThrow();
  });

  it("retains matches_proposed in the ordinary raised-replace error envelope", () => {
    const value = {
      code: "catalog_publication_failed",
      publication: observation("raised", "matches_proposed"),
    };
    expect(decodeNativeSurface("storageError", JSON.stringify(value))).toEqual(
      value,
    );
  });
});

describe("raised replacement publication table", () => {
  const states = ["committed", "not_committed", "indeterminate"] as const;
  const observation = (state: (typeof states)[number]) => ({
    schema_version: "catalog-publication-observation-v1",
    operation: "native_import",
    publication_state: state,
    prior_manifest_state: "present",
    prior_sha256: (state === "not_committed" ? "b" : "a").repeat(64),
    proposed_sha256: "a".repeat(64),
    replace_outcome: "raised",
    observed_manifest_state:
      state === "indeterminate" ? "not_observed" : "present",
    observed_sha256:
      state === "indeterminate"
        ? null
        : (state === "not_committed" ? "b" : "a").repeat(64),
    readback_result:
      state === "indeterminate"
        ? "unavailable"
        : state === "not_committed"
          ? "matches_prior"
          : "matches_proposed",
    cleanup_state: "complete",
    cleanup_errors: [],
    failure_phase: "replace",
    primary_kind: "exception",
    error_code:
      state === "indeterminate"
        ? "catalog_publication_indeterminate"
        : "catalog_publication_failed",
  });

  it.each(states)("requires the primary failure for %s", (state) => {
    const value = {
      ...observation(state),
      primary_kind: "none",
      failure_phase: null,
      error_code: null,
    };
    expect(() =>
      decodeNativeSurface("publication", JSON.stringify(value)),
    ).toThrow();
  });

  it.each(states)("refuses a generic storage error for %s", (state) => {
    const value = {
      ...observation(state),
      error_code: "catalog_storage_failed",
    };
    expect(() =>
      decodeNativeSurface("publication", JSON.stringify(value)),
    ).toThrow();
  });

  it.each(states)(
    "refuses another publication state's code for %s",
    (state) => {
      const value = {
        ...observation(state),
        error_code:
          state === "indeterminate"
            ? "catalog_publication_failed"
            : "catalog_publication_indeterminate",
      };
      expect(() =>
        decodeNativeSurface("publication", JSON.stringify(value)),
      ).toThrow();
    },
  );

  it.each(states)("retains the fixed ordinary failure for %s", (state) => {
    const value = observation(state);
    expect(decodeNativeSurface("publication", JSON.stringify(value))).toEqual(
      value,
    );
  });

  it.each(states)("preserves interruption precedence for %s", (state) => {
    const value = {
      ...observation(state),
      primary_kind: "base_exception",
      error_code: "catalog_interrupted",
    };
    expect(decodeNativeSurface("publication", JSON.stringify(value))).toEqual(
      value,
    );
    expect(() =>
      decodeNativeSurface(
        "publication",
        JSON.stringify({ ...value, error_code: "catalog_publication_failed" }),
      ),
    ).toThrow();
  });

  it.each(states)(
    "enforces the same table inside an error envelope for %s",
    (state) => {
      const publication = observation(state);
      const value = { code: publication.error_code, publication };
      expect(
        decodeNativeSurface("storageError", JSON.stringify(value)),
      ).toEqual(value);
      expect(() =>
        decodeNativeSurface(
          "storageError",
          JSON.stringify({
            code: "catalog_storage_failed",
            publication: {
              ...publication,
              error_code: "catalog_storage_failed",
            },
          }),
        ),
      ).toThrow();
    },
  );
});
