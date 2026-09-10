import {
  STORAGE_RETENTION_EXAMPLES,
  STORAGE_RETENTION_NUMERIC_WIRES,
  STORAGE_RETENTION_ORDERED_WIRE,
} from "@/lib/demo/storage-retention-fixture";
import schema from "../../openapi.json";
import { describe, expect, it } from "vitest";
import {
  buildStorageRetentionRequest,
  indexStorageRetentionJson,
  parseStorageRetentionResponse,
  readStorageRetentionResponse,
  snapshotStorageRetentionRequest,
  STORAGE_RESULT_BYTE_LIMIT,
  STORAGE_S3_REGIONS,
  type StorageTargetDraft,
} from "@/lib/storage-retention";

const azure: StorageTargetDraft = {
  subscription_id: "11111111-ABCD-4333-ABCD-555555555555",
  resource_group: "Synthetic_Group",
  account: "syntheticstore",
  container: "synthetic-container",
};
const s3 = { bucket: "synthetic.bucket", region: "us-east-1" };
const gcs = { bucket: "synthetic_bucket" };

describe("selected storage request validation", () => {
  it("keeps the offered regions and target count aligned with generated API constraints", () => {
    const branches =
      schema.paths["/api/collectors/retention/collect"].post.requestBody
        .content["application/json"].schema.oneOf;
    const s3Branch = branches.find(
      (branch) => branch.properties.provider.const === "s3",
    );
    expect(s3Branch).toBeDefined();
    expect(s3Branch?.properties.targets.items.properties.region?.enum).toEqual([
      ...STORAGE_S3_REGIONS,
    ]);
    for (const branch of branches) {
      expect(branch.properties.targets.minItems).toBe(1);
      expect(branch.properties.targets.maxItems).toBe(20);
      expect(branch.additionalProperties).toBe(false);
    }
  });

  it.each([
    "",
    " ",
    "alias\n",
    "alias\r",
    "alias\u2028",
    ".alias",
    "_alias",
    "-alias",
    "\u00e9",
    "a".repeat(65),
  ])("rejects the complete invalid alias %j without trimming", (scope) => {
    expect(() => buildStorageRetentionRequest("s3", scope, [s3])).toThrow(
      /Scope label/,
    );
  });
  it("preserves native request text and omits unrelated form fields", () => {
    expect(
      buildStorageRetentionRequest("s3", "Scope_1", [
        { ...s3, expected_owner: "001234567890", account: "unused" },
      ]),
    ).toEqual({
      provider: "s3",
      scope_label: "Scope_1",
      targets: [{ ...s3, expected_owner: "001234567890" }],
    });
    expect(buildStorageRetentionRequest("azure", "Scope_1", [azure])).toEqual({
      provider: "azure",
      scope_label: "Scope_1",
      targets: [
        { ...azure, subscription_id: azure.subscription_id?.toLowerCase() },
      ],
    });
    expect(buildStorageRetentionRequest("gcs", "Scope_1", [gcs])).toEqual({
      provider: "gcs",
      scope_label: "Scope_1",
      targets: [gcs],
    });
  });
  it("allows all 34 frozen S3 regions and no global partition alias", () => {
    expect(new Set(STORAGE_S3_REGIONS).size).toBe(34);
    for (const region of STORAGE_S3_REGIONS)
      expect(
        buildStorageRetentionRequest("s3", "Scope_1", [{ ...s3, region }])
          .targets,
      ).toEqual([{ ...s3, region }]);
    for (const region of [
      "aws-global",
      "cn-north-1",
      "us-gov-west-1",
      "us-east-1\n",
      "",
    ])
      expect(() =>
        buildStorageRetentionRequest("s3", "Scope_1", [{ ...s3, region }]),
      ).toThrow(/region/);
  });
  it.each([
    "ab",
    "x".repeat(64),
    "A-bucket",
    "a..b",
    "192.168.001.1",
    "999.888.777.666",
    "xn--bucket",
    "sthree-bucket",
    "amzn-s3-demo-bucket",
    "bucket-s3alias",
    "bucket--ol-s3",
    "bucket.mrap",
    "bucket--x-s3",
    "bucket--table-s3",
    "bucket\n",
    "https://example.com/bucket",
    "bucket%2fother",
    "bucket?x=1",
  ])("refuses unsupported S3 name %j", (bucket) => {
    expect(() =>
      buildStorageRetentionRequest("s3", "Scope_1", [{ ...s3, bucket }]),
    ).toThrow(/bucket/);
  });
  it.each([
    "1",
    "1234567890123",
    "12345678901a",
    "123456789012\n",
    " 123456789012",
  ])("refuses an invalid expected owner %j", (expected_owner) => {
    expect(() =>
      buildStorageRetentionRequest("s3", "Scope_1", [
        { ...s3, expected_owner },
      ]),
    ).toThrow(/owner/);
  });
  it.each([
    ["subscription_id", "11111111abcd4333abcd555555555555"],
    ["subscription_id", "11111111-abcd-4333-abcd-555555555555\n"],
    ["resource_group", "group."],
    ["resource_group", "group/name"],
    ["resource_group", "\u00e9"],
    ["resource_group", "x".repeat(91)],
    ["account", "Uppercase"],
    ["account", "ab"],
    ["account", "x".repeat(25)],
    ["container", "ab"],
    ["container", "two--parts"],
    ["container", "container_1"],
    ["container", "container\n"],
  ])("rejects invalid Azure %s", (key, value) => {
    expect(() =>
      buildStorageRetentionRequest("azure", "Scope_1", [
        { ...azure, [key]: value },
      ]),
    ).toThrow();
  });
  it.each([
    "ab",
    "Uppercase",
    "a..b",
    "x".repeat(64),
    "999.888.777.666",
    "bucket\n",
    "bucket/objects",
    "https://example.com",
    "a".repeat(223),
  ])("refuses unsupported GCS name %j", (bucket) => {
    expect(() =>
      buildStorageRetentionRequest("gcs", "Scope_1", [{ bucket }]),
    ).toThrow(/bucket/);
  });
  it("accepts a dotted GCS name up to 222 characters while bounding each label", () => {
    const bucket = [
      "a".repeat(63),
      "b".repeat(63),
      "c".repeat(63),
      "d".repeat(30),
    ].join(".");
    expect(bucket).toHaveLength(222);
    expect(
      buildStorageRetentionRequest("gcs", "Scope_1", [{ bucket }]).targets,
    ).toEqual([{ bucket }]);
  });
  it("rejects canonical duplicates, including owner differences and Azure case", () => {
    expect(() =>
      buildStorageRetentionRequest("s3", "Scope_1", [
        s3,
        { ...s3, expected_owner: "001234567890" },
      ]),
    ).toThrow(/duplicate/i);
    expect(() =>
      buildStorageRetentionRequest("azure", "Scope_1", [
        azure,
        { ...azure, resource_group: "synthetic_group" },
      ]),
    ).toThrow(/duplicate/i);
    expect(() =>
      buildStorageRetentionRequest("gcs", "Scope_1", [gcs, gcs]),
    ).toThrow(/duplicate/i);
    expect(
      buildStorageRetentionRequest("s3", "Scope_1", [
        s3,
        { ...s3, region: "us-west-2" },
      ]).targets,
    ).toHaveLength(2);
  });
  it("preserves input order, refuses zero/21 targets and bounds the encoded request", () => {
    const targets = Array.from({ length: 20 }, (_, n) => ({
      ...s3,
      bucket: `synthetic-${n}`,
    }));
    const body = buildStorageRetentionRequest("s3", "Scope_1", targets);
    expect(body.targets).toEqual(targets);
    expect(
      new TextEncoder().encode(JSON.stringify(body)).length,
    ).toBeLessThanOrEqual(65_536);
    expect(() => buildStorageRetentionRequest("s3", "Scope_1", [])).toThrow(
      /1 to 20/,
    );
    expect(() =>
      buildStorageRetentionRequest("s3", "Scope_1", [
        ...targets,
        { ...s3, bucket: "extra" },
      ]),
    ).toThrow(/1 to 20/);
    expect(() =>
      buildStorageRetentionRequest("s3", "Scope_1", [
        { ...s3, bucket: "a".repeat(65_537) },
      ]),
    ).toThrow();
  });
});

describe("storage response cleanup", () => {
  it.each([201, 204, 400])(
    "cancels an available body on status %s refusal",
    async (status) => {
      let cancelled = false;
      const stream = new ReadableStream<Uint8Array>({
        cancel() {
          cancelled = true;
          throw new Error("PRIVATE_CLEANUP");
        },
      });
      // A 204 Response cannot have a body; use a real 200 stream with a status accessor.
      const response = new Response(stream, {
        headers: { "content-type": "application/json" },
      });
      Object.defineProperty(response, "status", { value: status });
      await expect(readStorageRetentionResponse(response, {})).rejects.toThrow(
        "The storage response is invalid or does not match the selected request.",
      );
      expect(cancelled).toBe(true);
      expect(stream.locked).toBe(false);
    },
  );
  it("cancels an available body on content-type refusal", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    await expect(
      readStorageRetentionResponse(
        new Response(stream, { headers: { "content-type": "text/html" } }),
        {},
      ),
    ).rejects.toThrow(/storage response/);
    expect(cancelled).toBe(true);
    expect(stream.locked).toBe(false);
  });
});

const numericRequests = {
  s3: snapshotStorageRetentionRequest({
    provider: "s3",
    scope_label: "synthetic",
    targets: [
      {
        bucket: "synthetic-retention",
        region: "us-east-1",
        expected_owner: "123456789012",
      },
    ],
  }),
  contract: snapshotStorageRetentionRequest({
    provider: "gcs",
    scope_label: "synthetic-contract",
    targets: [{ bucket: "synthetic-contract" }],
  }),
};
function expectedExample(status: keyof typeof STORAGE_RETENTION_EXAMPLES) {
  const result = STORAGE_RETENTION_EXAMPLES[status];
  return snapshotStorageRetentionRequest({
    provider: result.provider,
    scope_label: result.scope_label,
    targets: result.resources.map((item) => item.target),
  });
}
function byteResponse(
  bytes: Uint8Array[],
  options: {
    closed?: boolean;
    cancelled?: () => void;
    headers?: Record<string, string>;
  } = {},
) {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        for (const part of bytes) controller.enqueue(part);
        if (options.closed !== false) controller.close();
      },
      cancel() {
        options.cancelled?.();
      },
    }),
    { headers: { "content-type": "application/json", ...options.headers } },
  );
}
describe("exact storage JSON source", () => {
  it.each(["s3", "contract"] as const)(
    "indexes the exact factory %s native fields and preserves the complete wire",
    (name) => {
      const raw = STORAGE_RETENTION_NUMERIC_WIRES[name];
      const response = parseStorageRetentionResponse(
        raw,
        numericRequests[name],
      );
      expect(response.rawJson).toBe(raw);
      expect(response.nativeFieldsJson[0][0]).toBe(
        indexStorageRetentionJson(raw).get("0:0"),
      );
      expect(response.nativeFieldsJson[0][0]).toContain(
        name === "s3" ? "9007199254740993" : "-0.0",
      );
      if (name === "contract") {
        for (const token of [
          "1.0",
          "1e+20",
          "1e-6",
          "__proto__",
          "constructor",
        ])
          expect(response.nativeFieldsJson[0][0]).toContain(token);
        expect(
          Object.prototype.hasOwnProperty.call(
            response.result.resources[0].components[0].projection?.fields,
            "__proto__",
          ),
        ).toBe(true);
      }
    },
  );
  it("selects only the exact fields path despite nested lookalikes, strings, arrays and escaped keys", () => {
    const fields =
      '{"quoted\\\"key":"a\\\\b } ] \\\" fields:9007199254740993","projection":{"fields":{"Days":4}},"array":[{},[],null,false],"num":-0.0}';
    const raw =
      '{"fields":0,"resources":[{"components":[{"projection":{"fields":' +
      fields +
      ',"lookalike":{"fields":99}}}]}]}';
    expect([...indexStorageRetentionJson(raw)]).toEqual([["0:0", fields]]);
  });
  it.each([
    '{"a":0,"\\u0061":1}',
    '{"x":{"a":0,"a":1}}',
    '{"__proto__":0,"__proto__":1}',
    "NaN",
    "Infinity",
    "-Infinity",
    "1e309",
    "01",
    "1.",
    "+1",
    "[0,]",
    '{"x":1,}',
    '"\\ud800"',
    '"\\udfff"',
    '"unclosed',
    '"\\x20"',
    "{",
    "[",
    "[0] true",
    "\ufeff{}",
    '{"a"\u2028:0}',
  ])("rejects malformed, ambiguous or nonfinite JSON: %s", (raw) => {
    expect(() => indexStorageRetentionJson(raw)).toThrow(/storage response/);
  });
  it.each([
    "-0",
    "-0.0",
    "1.0",
    "1e+20",
    "1e-06",
    '"\\ud83d\\ude00"',
    '"9007199254740993"',
    '{"__proto__":{},"constructor":null}',
    " \r\n\t{} \r\n",
  ])("accepts unambiguous JSON source %s", (raw) => {
    expect(() => indexStorageRetentionJson(raw)).not.toThrow();
  });
  it("bounds result depth without rejecting the native projection depth allowance", () => {
    expect(() =>
      indexStorageRetentionJson("[".repeat(63) + "0" + "]".repeat(63)),
    ).not.toThrow();
    expect(() =>
      indexStorageRetentionJson("[".repeat(64) + "0" + "]".repeat(64)),
    ).toThrow(/storage response/);
    const fixture = structuredClone(STORAGE_RETENTION_EXAMPLES.complete);
    const projected = fixture.resources[0].components[0].projection;
    if (!projected) throw new Error("Missing fixture projection");
    // A shape-only boundary control; source digest validation remains in Python.
    const original = JSON.stringify(projected.fields);
    const fields = '{"deep":' + "[".repeat(31) + "[]" + "]".repeat(31) + "}";
    const raw = JSON.stringify(fixture).replace(original, fields);
    expect(
      parseStorageRetentionResponse(raw, expectedExample("complete"))
        .nativeFieldsJson[0][0],
    ).toBe(fields);
  });
  it("admits the largest minimal node array within the byte budget and refuses the next value", () => {
    const raw = "[" + "0,".repeat(2_097_150) + "0]";
    expect(new TextEncoder().encode(raw).length).toBe(
      STORAGE_RESULT_BYTE_LIMIT - 1,
    );
    expect(() => indexStorageRetentionJson(raw)).not.toThrow();
    expect(() => indexStorageRetentionJson(raw.slice(0, -1) + ",0]")).toThrow(
      /storage response/,
    );
  });
});
describe("immutable request and response binding", () => {
  it("detaches and freezes primitives, ordered targets and optional owners", () => {
    const input = {
      provider: "s3",
      scope_label: "synthetic",
      targets: [
        {
          bucket: "synthetic-retention",
          region: "us-east-1",
          expected_owner: "123456789012",
        },
      ],
    };
    const captured = snapshotStorageRetentionRequest(input);
    input.scope_label = "changed";
    input.targets[0].bucket = "changed";
    input.targets.push({ ...input.targets[0] });
    expect(captured).toEqual(numericRequests.s3);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(Object.isFrozen(captured.targets)).toBe(true);
    expect(Object.isFrozen(captured.targets[0])).toBe(true);
    expect(() => {
      captured.scope_label = "changed";
    }).toThrow(TypeError);
  });
  it("accepts omitted expected owner against the serialized null default", () => {
    const result = STORAGE_RETENTION_EXAMPLES.unavailable;
    const expected = expectedExample("unavailable");
    expect(expected.provider).toBe("s3");
    expect(expected.targets[0]).not.toHaveProperty("expected_owner");
    expect(
      parseStorageRetentionResponse(JSON.stringify(result), expected).result,
    ).toEqual(result);
  });
  it.each([
    {
      provider: "s3",
      scope_label: "other",
      targets: [
        {
          bucket: "synthetic-retention",
          region: "us-east-1",
          expected_owner: "123456789012",
        },
      ],
    },
    {
      provider: "s3",
      scope_label: "synthetic",
      targets: [
        {
          bucket: "synthetic-retention",
          region: "us-east-2",
          expected_owner: "123456789012",
        },
      ],
    },
    {
      provider: "s3",
      scope_label: "synthetic",
      targets: [
        {
          bucket: "other-retention",
          region: "us-east-1",
          expected_owner: "123456789012",
        },
      ],
    },
    {
      provider: "s3",
      scope_label: "synthetic",
      targets: [
        {
          bucket: "synthetic-retention",
          region: "us-east-1",
          expected_owner: "999999999999",
        },
      ],
    },
    {
      provider: "s3",
      scope_label: "synthetic",
      targets: [{ bucket: "synthetic-retention", region: "us-east-1" }],
    },
    {
      provider: "gcs",
      scope_label: "synthetic",
      targets: [{ bucket: "synthetic-retention" }],
    },
  ])("refuses a response for different selected input %#", (request) => {
    expect(() =>
      parseStorageRetentionResponse(
        STORAGE_RETENTION_NUMERIC_WIRES.s3,
        request,
      ),
    ).toThrow(/does not match/);
  });
  it.each([
    "scope_label",
    "provider",
    "resources",
    "manifest",
    "findings",
    "status",
    "observation_scope",
    "object_enforcement_assessed",
  ])("refuses missing required result field %s", (field) => {
    const result: Record<string, unknown> = {
      ...STORAGE_RETENTION_EXAMPLES.complete,
    };
    delete result[field];
    expect(() =>
      parseStorageRetentionResponse(
        JSON.stringify(result),
        expectedExample("complete"),
      ),
    ).toThrow(/storage response/);
  });
  it("checks component identities/order and derived summary state", () => {
    const original = STORAGE_RETENTION_EXAMPLES.partial;
    const altered = structuredClone(original);
    altered.resources[0].components.reverse();
    expect(() =>
      parseStorageRetentionResponse(
        JSON.stringify(altered),
        expectedExample("partial"),
      ),
    ).toThrow();
    const counts = structuredClone(original);
    counts.attempted_components += 1;
    expect(() =>
      parseStorageRetentionResponse(
        JSON.stringify(counts),
        expectedExample("partial"),
      ),
    ).toThrow();
    const state = structuredClone(original);
    state.status = "complete";
    expect(() =>
      parseStorageRetentionResponse(
        JSON.stringify(state),
        expectedExample("partial"),
      ),
    ).toThrow();
  });
});
describe("bounded UTF-8 response bytes", () => {
  it("keeps fragmented UTF-8 bytes and ignores a lying content length", async () => {
    const raw = STORAGE_RETENTION_NUMERIC_WIRES.contract;
    const bytes = new TextEncoder().encode(raw);
    const chunks = Array.from(bytes, (byte) => new Uint8Array([byte]));
    const response = await readStorageRetentionResponse(
      byteResponse(chunks, { headers: { "content-length": "1" } }),
      numericRequests.contract,
    );
    expect(response.rawJson).toBe(raw);
  });
  it.each([
    { bytes: [0xc3] },
    { bytes: [0xc3, 0x28] },
    { bytes: [0xed, 0xa0, 0x80] },
    { bytes: [0xff] },
  ])("rejects malformed or truncated UTF-8 %#", async ({ bytes }) => {
    await expect(
      readStorageRetentionResponse(
        byteResponse([new Uint8Array(bytes)]),
        numericRequests.s3,
      ),
    ).rejects.toThrow(/storage response/);
  });
  it("accepts exactly the byte limit and cancels through the first refused chunk", async () => {
    const raw = STORAGE_RETENTION_NUMERIC_WIRES.s3;
    const bytes = new TextEncoder().encode(
      raw +
        " ".repeat(
          STORAGE_RESULT_BYTE_LIMIT - new TextEncoder().encode(raw).length,
        ),
    );
    expect(
      (
        await readStorageRetentionResponse(
          byteResponse([bytes]),
          numericRequests.s3,
        )
      ).rawJson.length,
    ).toBe(bytes.length);
    let cancelled = false;
    const refused = byteResponse([bytes, new Uint8Array([0x20])], {
      closed: false,
      cancelled() {
        cancelled = true;
        throw new Error("PRIVATE_CANCEL");
      },
      headers: { "content-length": "1" },
    });
    await expect(
      readStorageRetentionResponse(refused, numericRequests.s3),
    ).rejects.toThrow(
      "The storage response is invalid or does not match the selected request.",
    );
    expect(cancelled).toBe(true);
    expect(refused.body?.locked).toBe(false);
  });
  it("reports a fixed error for a failed stream and releases its reader", async () => {
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error("PRIVATE_BODY"));
      },
    });
    await expect(
      readStorageRetentionResponse(
        new Response(stream, {
          headers: { "content-type": "application/json" },
        }),
        numericRequests.s3,
      ),
    ).rejects.toThrow(
      "The storage response is invalid or does not match the selected request.",
    );
    expect(stream.locked).toBe(false);
  });
});

it("binds exact ordered targets without depending on object-key order", () => {
  const value: unknown = JSON.parse(STORAGE_RETENTION_ORDERED_WIRE);
  if (
    typeof value !== "object" ||
    value === null ||
    !("resources" in value) ||
    !Array.isArray(value.resources) ||
    !("provider" in value) ||
    !("scope_label" in value)
  )
    throw new Error("Missing ordered fixture");
  const targets: unknown[] = value.resources.map((entry: unknown) => {
    if (typeof entry !== "object" || entry === null || !("target" in entry))
      throw new Error("Missing fixture target");
    return entry.target;
  });
  const selected = snapshotStorageRetentionRequest({
    targets,
    scope_label: value.scope_label,
    provider: value.provider,
  });
  expect(
    parseStorageRetentionResponse(STORAGE_RETENTION_ORDERED_WIRE, selected)
      .result.resources,
  ).toHaveLength(2);
  const reverse = snapshotStorageRetentionRequest({
    provider: selected.provider,
    scope_label: selected.scope_label,
    targets: [...selected.targets].reverse(),
  });
  expect(() =>
    parseStorageRetentionResponse(STORAGE_RETENTION_ORDERED_WIRE, reverse),
  ).toThrow(/does not match/);
});
