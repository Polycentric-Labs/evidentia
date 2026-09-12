import { describe, expect, test, vi } from "vitest";
import {
  registryDemoCases,
  registryDemoResponse,
} from "@/lib/demo/registry-fixtures";
import {
  REGISTRY_NAMES,
  REGISTRY_RESULT_BYTE_LIMIT,
  boundedRegistryPreview,
  buildRegistryRequest,
  indexRegistryJson,
  parseRegistryRequest,
  parseRegistryResponse,
  readRegistryResponse,
  snapshotRegistryRequest,
} from "./registry";

const cases = REGISTRY_NAMES.flatMap((registry) => registryDemoCases(registry));
const unavailable = () => {
  const item = cases.find((item) => item.request.registry === "ssl-labs")!;
  return registryDemoResponse(item.request, item.name);
};

test.each([
  ["collector_version", "invalid/version"],
  ["evidentia_version", "invalid/version"],
  ["collector_version", " "],
  ["evidentia_version", " "],
])(
  "rejects an invalid %s value %j through every schema constraint",
  (field, value) => {
    const fixture = unavailable();
    const result = JSON.parse(fixture.rawJson);
    result.manifest[field] = value;
    expect(() =>
      parseRegistryResponse(JSON.stringify(result), fixture.result.request),
    ).toThrow();
  },
);

test.each(cases)(
  "accepts the real collector's synthetic $name result without changing bytes",
  ({ name, request }) => {
    const response = registryDemoResponse(request, name);
    expect(parseRegistryResponse(response.rawJson, request).rawJson).toBe(
      response.rawJson,
    );
    expect(Object.isFrozen(response.result)).toBe(true);
    expect(response.observationJson).toHaveLength(
      response.result.observations.length,
    );
  },
);

describe("request admission", () => {
  test("detaches inputs and keeps exact case, trailing dot and scope", () => {
    const input = {
      registry: "tls",
      target: { hostname: "EXAMPLE.org." },
      scope_label: "Selected scope",
    };
    const snapshot = snapshotRegistryRequest(input);
    input.target.hostname = "changed.example";
    expect(snapshot.target).toEqual({ hostname: "EXAMPLE.org." });
    expect(snapshot.scope_label).toBe("Selected scope");
    expect(Object.isFrozen(snapshot.target)).toBe(true);
  });
  test.each([
    "127.1",
    "0x7f.1",
    "2130706433",
    "bad_name.example",
    "https://example.org",
    "example.org\n",
  ])("refuses invalid hostname %s", (hostname) => {
    expect(() => buildRegistryRequest("tls", { hostname })).toThrow();
  });
  test.each([
    "127.0.0.1",
    "10.0.0.1",
    "100.64.0.1",
    "224.0.0.1",
    "::1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "fe80::1%1",
  ])("refuses nonpublic endpoint %s", (endpoint_ip) => {
    expect(() =>
      buildRegistryRequest("ssl-labs", {
        hostname: "example.org",
        endpoint_ip,
      }),
    ).toThrow();
  });
  test("rejects structural extras, duplicate keys, non-native callbacks and unpaired surrogates", () => {
    for (const raw of [
      '{"registry":"tls","registry":"rdap","target":{"hostname":"example.org"}}',
      '{"registry":"tls","target":{"hostname":"example.org","__proto__":{}}}',
      '{"registry":"tls","target":{"hostname":"example.org"},"scope_label":"\\ud800"}',
    ])
      expect(() => parseRegistryRequest(raw)).toThrow();
    const getter = vi.fn(() => "tls");
    expect(() =>
      snapshotRegistryRequest({
        get registry() {
          return getter();
        },
        target: { hostname: "example.org" },
      }),
    ).toThrow();
    expect(getter).not.toHaveBeenCalled();
  });
  test("bounds actual UTF-8 request bytes and exact identifier shapes", () => {
    expect(() =>
      buildRegistryRequest("gleif", { lei: "A".repeat(19) }),
    ).toThrow();
    expect(() =>
      buildRegistryRequest("sam-entity", { uei: "abcdefghijkl" }),
    ).toThrow();
    expect(() =>
      buildRegistryRequest("cmvp", { certificate_number: "123\n" }),
    ).toThrow();
    expect(() =>
      buildRegistryRequest("incommon", { entity_id: "é".repeat(1025) }),
    ).toThrow();
    expect(() => parseRegistryRequest(" ".repeat(65_537))).toThrow();
  });
});

test("strict JSON indexing preserves native integer, float and string representations", () => {
  const raw = '{"i":9007199254740993,"f":1.0,"s":"9007199254740993","n":null}';
  const indexed = indexRegistryJson(raw);
  expect(indexed.get('number:["i"]')).toBe("int");
  expect(indexed.get('number:["f"]')).toBe("float");
  expect(indexed.get('value:["i"]')).toBe("9007199254740993");
  expect(indexed.get('value:["f"]')).toBe("1.0");
  for (const invalid of [
    '{"x":1,"x":2}',
    '{"x":NaN}',
    '{"x":1e999}',
    '{"x":1e-999}',
    '{"x":' + "1".repeat(129) + "}",
  ]) {
    expect(() => indexRegistryJson(invalid)).toThrow();
  }
});

test("rejects wrong identities, undeclared structural fields and incoherent finite counters", () => {
  const response = unavailable();
  type EditableResult = {
    registry: string;
    extra?: unknown;
    source_reads: { ordinal: number; attempted_pages: number }[];
    manifest: { total_findings: number };
    collection_status: string;
  };
  for (const alter of [
    (value: EditableResult) => {
      value.registry = "tls";
    },
    (value: EditableResult) => {
      value.extra = null;
    },
    (value: EditableResult) => {
      value.source_reads[0].ordinal = 1;
    },
    (value: EditableResult) => {
      value.manifest.total_findings = 1;
    },
    (value: EditableResult) => {
      value.collection_status = "complete";
    },
    (value: EditableResult) => {
      value.source_reads[0].attempted_pages = -1;
    },
  ]) {
    const changed = JSON.parse(response.rawJson);
    alter(changed);
    expect(() =>
      parseRegistryResponse(JSON.stringify(changed), response.result.request),
    ).toThrow();
  }
  expect(() =>
    parseRegistryResponse(
      response.rawJson.replace('"ordinal":0', '"ordinal":0.0'),
      response.result.request,
    ),
  ).toThrow();
});

test("streaming response enforces actual bytes and content type before parsing", async () => {
  const response = unavailable();
  const good = new Response(response.rawJson, {
    headers: { "content-type": "application/json", "content-length": "1" },
  });
  expect(
    (await readRegistryResponse(good, response.result.request)).rawJson,
  ).toBe(response.rawJson);
  for (const bytes of [
    new Uint8Array([0xc3, 0x28]),
    new TextEncoder().encode("\uFEFF" + response.rawJson),
  ]) {
    await expect(
      readRegistryResponse(
        new Response(bytes, {
          headers: { "content-type": "application/json" },
        }),
        response.result.request,
      ),
    ).rejects.toThrow();
  }
  const cancel = vi.fn();
  const oversized = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(REGISTRY_RESULT_BYTE_LIMIT + 1));
    },
    cancel,
  });
  await expect(
    readRegistryResponse(
      new Response(oversized, {
        headers: { "content-type": "application/json", "content-length": "1" },
      }),
      response.result.request,
    ),
  ).rejects.toThrow();
  expect(cancel).toHaveBeenCalledOnce();
  await expect(
    readRegistryResponse(
      new Response(response.rawJson, {
        headers: { "content-type": "text/html" },
      }),
      response.result.request,
    ),
  ).rejects.toThrow();
});

test("preview byte bounds preserve whole Unicode code points", () => {
  const raw = "é".repeat(8192) + "🙂";
  expect(boundedRegistryPreview(raw)).toBe("é".repeat(8192));
  expect(
    new TextEncoder().encode(boundedRegistryPreview("🙂".repeat(5000))).length,
  ).toBe(16384);
});

test("open selected JSON keeps own prototype-like keys and exact numeric tokens", () => {
  const sample = cases.find((item) => item.name === "gleif-lei-active")!;
  const source = registryDemoResponse(sample.request, sample.name);
  const changed = JSON.parse(source.rawJson);
  const fields = JSON.parse(
    '{"__proto__":{"constructor":{"prototype":"inert"}},"large":"LARGE_INTEGER","float":"NATIVE_FLOAT","null":null,"quoted":"9007199254740993"}',
  );
  changed.observations[0].fields = fields;
  changed.findings[0].raw_data.observation.fields = fields;
  const raw = JSON.stringify(changed)
    .replaceAll('"LARGE_INTEGER"', "9007199254740993")
    .replaceAll('"NATIVE_FLOAT"', "1.0");
  const result = parseRegistryResponse(raw, sample.request);
  expect(result.rawJson).toBe(raw);
  expect(result.nativeFieldsJson[0]).toContain('"large":9007199254740993');
  expect(result.nativeFieldsJson[0]).toContain('"float":1.0');
  expect(Object.hasOwn(result.result.observations[0].fields, "__proto__")).toBe(
    true,
  );
  expect(Object.getPrototypeOf(result.result.observations[0].fields)).toBe(
    Object.prototype,
  );
  const brokenCopy = raw.replace(
    '"large":9007199254740993',
    '"large":9007199254740994',
  );
  expect(() => parseRegistryResponse(brokenCopy, sample.request)).toThrow();
  const structural = JSON.parse(raw);
  Object.defineProperty(structural.observations[0], "constructor", {
    value: {},
    enumerable: true,
  });
  expect(() =>
    parseRegistryResponse(JSON.stringify(structural), sample.request),
  ).toThrow();
});

describe("reviewed browser input and ledger boundaries", () => {
  test.each(["registry", "target", "unexpected"])(
    "refuses the non-enumerable own key %s",
    (key) => {
      const input = { registry: "rdap", target: { domain: "example.org" } };
      Object.defineProperty(input, key, {
        value:
          key === "registry"
            ? "rdap"
            : key === "target"
              ? input.target
              : "hidden",
        enumerable: false,
      });
      expect(() => snapshotRegistryRequest(input)).toThrow();
    },
  );
  test("copies proxy-owned descriptors without invoking its toJSON substitution", () => {
    const original = { registry: "rdap", target: { domain: "example.org" } };
    const toJSON = vi.fn(() => ({
      registry: "tls",
      target: { hostname: "https://invalid.example" },
    }));
    const get = vi.fn(
      (target: typeof original, key: string | symbol, receiver: unknown) =>
        key === "toJSON" ? toJSON : Reflect.get(target, key, receiver),
    );
    const result = snapshotRegistryRequest(new Proxy(original, { get }));
    expect(result).toEqual({ ...original, scope_label: null });
    expect(toJSON).not.toHaveBeenCalled();
    expect(get).not.toHaveBeenCalled();
  });
  test("retains valid null-prototype inputs and refuses hidden nested properties", () => {
    const target = Object.assign(Object.create(null), {
      domain: "example.org",
    });
    const input = Object.assign(Object.create(null), {
      registry: "rdap",
      target,
    });
    expect(snapshotRegistryRequest(input)).toEqual({
      registry: "rdap",
      target: { domain: "example.org" },
      scope_label: null,
    });
    Object.defineProperty(target, "unexpected", {
      value: "hidden",
      enumerable: false,
    });
    expect(() => snapshotRegistryRequest(input)).toThrow();
  });
  test.each([
    "not-a-time",
    "X".repeat(16_385),
    "0000-01-01T00:00:00.000000Z",
    "2025-02-29T00:00:00.000000Z",
    "2026-04-31T00:00:00.000000Z",
    "2026-09-12T24:00:00.000000Z",
    "2026-09-12T00:60:00.000000Z",
    "2026-09-12T00:00:60.000000Z",
    "2026-09-12T00:00:00.0000000Z",
    "2026-09-12T00:00:00.000000Z\n",
  ])("refuses malformed application clock %#", (clock) => {
    const sample = cases.find((item) => item.request.registry === "tls")!;
    const response = registryDemoResponse(sample.request, sample.name);
    const changed = JSON.parse(response.rawJson);
    changed.source_reads[0].retrieved_at = clock;
    expect(() =>
      parseRegistryResponse(JSON.stringify(changed), sample.request),
    ).toThrow();
  });
  test.each([
    "0001-01-01T00:00:00.000000Z",
    "2000-02-29T23:59:59.999999Z",
    "9999-12-31T23:59:59.999999Z",
  ])("retains supported retrieval clock %s", (clock) => {
    const sample = cases.find((item) => item.request.registry === "tls")!;
    const response = registryDemoResponse(sample.request, sample.name);
    const changed = JSON.parse(response.rawJson);
    changed.source_reads[0].retrieved_at = clock;
    const raw = JSON.stringify(changed);
    expect(parseRegistryResponse(raw, sample.request).rawJson).toBe(raw);
  });
  test("checks all application-clock slots without rewriting publisher time literals", () => {
    const sample = cases.find((item) => item.request.registry === "tls")!;
    const response = registryDemoResponse(sample.request, sample.name);
    const paths = [
      ["manifest", "collection_started_at"],
      ["manifest", "collection_finished_at"],
      ["findings", 0, "collection_context", "collected_at"],
      ["findings", 0, "first_observed"],
      ["findings", 0, "last_observed"],
    ];
    for (const path of paths) {
      const changed = JSON.parse(response.rawJson);
      let parent = changed;
      for (const key of path.slice(0, -1)) parent = parent[key];
      parent[path.at(-1)!] = "not-a-time";
      expect(() =>
        parseRegistryResponse(JSON.stringify(changed), sample.request),
      ).toThrow();
    }
  });
  test.each([
    "network_attempts",
    "accepted_pages",
    "admitted_records",
    "raw_bytes",
    "decoded_bytes",
  ])("enforces the complete lookup %s budget", (field) => {
    const sample = cases.find((item) =>
      item.name.includes("sam-exclusions-partial"),
    )!;
    const response = registryDemoResponse(sample.request, sample.name);
    const changed = JSON.parse(response.rawJson);
    expect(changed.source_reads).toHaveLength(2);
    for (const read of changed.source_reads) {
      if (field === "network_attempts") read.network_attempts = 64;
      if (field === "accepted_pages") {
        read.accepted_pages = 20;
        read.attempted_pages = 20;
      }
      if (field === "admitted_records") {
        read.admitted_records = 100;
        read.source_records = 100;
      }
      if (field === "raw_bytes" || field === "decoded_bytes")
        read[field] = 8_388_608;
    }
    expect(() =>
      parseRegistryResponse(JSON.stringify(changed), sample.request),
    ).toThrow();
  });
});
