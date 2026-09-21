import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { RELEASE_DEMO_FIXTURES } from "./demo/release-cadence-fixtures";
import {
  readReleasePollResponse,
  readReleaseSeriesResponse,
  ReleaseResponseError,
  RELEASE_RESULT_BYTES,
} from "./release-cadence";
beforeEach(async () =>
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  ),
);
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.resetModules();
});
const fixture = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-observed")!;
async function live() {
  vi.stubEnv("VITE_DEMO", "false");
  vi.resetModules();
  return (await import("./api")).api;
}
test.each(RELEASE_DEMO_FIXTURES)(
  "$id uses actual API route, captured request and one bounded response",
  async (entry) => {
    const api = await live(),
      abort = new AbortController(),
      fetch = vi.fn().mockResolvedValue(
        new Response(entry.rawJson, {
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetch);
    const result =
      entry.kind === "poll"
        ? await api.collectReleaseCadence(
            entry.request as Parameters<typeof api.collectReleaseCadence>[0],
            { signal: abort.signal },
          )
        : await api.releaseSeries(
            entry.request as Parameters<typeof api.releaseSeries>[0],
            { signal: abort.signal },
          );
    expect(result.rawJson).toBe(entry.rawJson);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      entry.kind === "poll"
        ? "/api/collect/release-cadence"
        : "/api/conmon/release-series",
    );
    expect(init.method).toBe("POST");
    expect(init.signal).toBe(abort.signal);
    expect(JSON.parse(init.body as string)).toEqual(entry.request);
    expect(init.headers).toEqual({
      "Content-Type": "application/json",
      Accept: "application/json",
    });
  },
);
test("actual API snapshots before fetch yields", async () => {
  const api = await live(),
    request = { ...fixture.request } as Parameters<
      typeof api.collectReleaseCadence
    >[0];
  let resolve!: (v: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(() => new Promise<Response>((done) => (resolve = done))),
  );
  const pending = api.collectReleaseCadence(request);
  request.owner = "Changed";
  resolve(
    new Response(fixture.rawJson, {
      headers: { "content-type": "application/json" },
    }),
  );
  expect((await pending).result.request.owner).toBe("Example");
});
test("invalid native request never contacts API", async () => {
  const api = await live(),
    fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(
    api.collectReleaseCadence({
      ...fixture.request,
      owner: "wrong/name",
    } as Parameters<typeof api.collectReleaseCadence>[0]),
  ).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});
const errors: [number, string, string][] = [
  [422, "invalid_request", "The release request is invalid."],
  [413, "request_limit_exceeded", "The release request exceeds its limit."],
  [413, "result_limit_exceeded", "The release result exceeds its limit."],
  [415, "unsupported_media", "The release request media type is unsupported."],
  [503, "support_unavailable", "Release support is unavailable."],
  [500, "support_broken", "Release support failed."],
  [503, "authority_unavailable", "Release authority is unavailable."],
  [500, "operation_failed", "The release operation failed."],
  [
    500,
    "persistence_outcome_unavailable",
    "The release deadline expired after a save was attempted. Persistence may have occurred. Inspect local records before retrying.",
  ],
];
test.each(errors)(
  "HTTP %s code %s keeps only the fixed error",
  async (status, code, message) => {
    const response = new Response(
      JSON.stringify({ schema_version: "release-error-v1", code, message }),
      { status, headers: { "content-type": "application/json" } },
    );
    await expect(
      readReleasePollResponse(response, fixture.request),
    ).rejects.toMatchObject({ message, code, status });
    expect(response.body?.locked).toBe(false);
  },
);
test.each([401, 403])(
  "authentication HTTP %s never exposes upstream detail",
  async (status) => {
    const response = new Response(
      JSON.stringify({ detail: "Synthetic untrusted server detail" }),
      { status, headers: { "content-type": "application/json" } },
    );
    await expect(
      readReleasePollResponse(response, fixture.request),
    ).rejects.toMatchObject({ message: "Release access was refused.", status });
  },
);
test.each(["wrong-message", "wrong-status", "extra", "unknown-code"])(
  "malformed fixed error %s refuses",
  async (mode) => {
    const error = {
      schema_version: "release-error-v1",
      code: "operation_failed",
      message: "The release operation failed.",
    };
    if (mode === "wrong-message") error.message = "Synthetic server detail";
    if (mode === "unknown-code") error.code = "invented";
    if (mode === "extra") Object.assign(error, { details: "Synthetic detail" });
    const response = new Response(JSON.stringify(error), {
      status: mode === "wrong-status" ? 503 : 500,
      headers: { "content-type": "application/json" },
    });
    await expect(
      readReleasePollResponse(response, fixture.request),
    ).rejects.toMatchObject({ code: null, status: null });
  },
);
test.each(["text/plain", "application/json; charset=utf-16", ""])(
  "unsupported content type %s cancels and refuses",
  async (type) => {
    const cancel = vi.fn(),
      stream = new ReadableStream<Uint8Array>({ cancel });
    const response = new Response(stream, {
      headers: { "content-type": type },
    });
    await expect(
      readReleasePollResponse(response, fixture.request),
    ).rejects.toThrow();
    expect(cancel).toHaveBeenCalledOnce();
    expect(response.body?.locked).toBe(false);
  },
);
test("truncated declared identity body refuses", async () => {
  const response = new Response(fixture.rawJson, {
    headers: {
      "content-type": "application/json",
      "content-length": String(fixture.rawJson.length + 1),
    },
  });
  await expect(
    readReleasePollResponse(response, fixture.request),
  ).rejects.toThrow();
});
test("encoded content length does not pretend to count decoded bytes", async () => {
  const response = new Response(fixture.rawJson, {
    headers: {
      "content-type": "application/json",
      "content-encoding": "gzip",
      "content-length": "12",
    },
  });
  expect(
    (await readReleasePollResponse(response, fixture.request)).rawJson,
  ).toBe(fixture.rawJson);
});
test("oversized declared body refuses before reading and cancels", async () => {
  const cancel = vi.fn(),
    pull = vi.fn(),
    stream = new ReadableStream<Uint8Array>(
      { pull, cancel },
      { highWaterMark: 0 },
    );
  await expect(
    readReleasePollResponse(
      new Response(stream, {
        headers: {
          "content-type": "application/json",
          "content-length": String(RELEASE_RESULT_BYTES + 1),
        },
      }),
      fixture.request,
    ),
  ).rejects.toThrow();
  expect(pull).not.toHaveBeenCalled();
  expect(cancel).toHaveBeenCalledOnce();
});
test("stream cap refuses an extra byte and cancels without reading further", async () => {
  let calls = 0;
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        calls++;
        controller.enqueue(
          calls <= 16 ? new Uint8Array(1_048_576) : new Uint8Array(1),
        );
      },
      cancel,
    },
    { highWaterMark: 0 },
  );
  await expect(
    readReleasePollResponse(
      new Response(stream, { headers: { "content-type": "application/json" } }),
      fixture.request,
    ),
  ).rejects.toThrow();
  expect(calls).toBe(17);
  expect(cancel).toHaveBeenCalledOnce();
});
test.each([
  new Uint8Array([0xff]),
  new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
])("invalid UTF-8 or BOM refuses", async (bytes) => {
  await expect(
    readReleasePollResponse(
      new Response(bytes, { headers: { "content-type": "application/json" } }),
      fixture.request,
    ),
  ).rejects.toThrow();
});
test("read failure and throwing cancel preserve fixed refusal and release lock", async () => {
  const response = new Response(
    new ReadableStream<Uint8Array>({
      pull() {
        throw new Error("Synthetic read failure");
      },
      cancel() {
        throw new Error("Synthetic cleanup failure");
      },
    }),
    { headers: { "content-type": "application/json" } },
  );
  await expect(
    readReleasePollResponse(response, fixture.request),
  ).rejects.toThrow(ReleaseResponseError);
  expect(response.body?.locked).toBe(false);
});
test("body split across every code-unit boundary retains exact bytes", async () => {
  const bytes = new TextEncoder().encode(fixture.rawJson);
  let offset = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (offset === bytes.length) c.close();
      else c.enqueue(bytes.slice(offset, ++offset));
    },
  });
  expect(
    (
      await readReleasePollResponse(
        new Response(stream, {
          headers: { "content-type": "application/json" },
        }),
        fixture.request,
      )
    ).rawJson,
  ).toBe(fixture.rawJson);
});
test("series transport refuses poll shape", async () => {
  const request = RELEASE_DEMO_FIXTURES.find(
    (x) => x.id === "series-two",
  )!.request;
  await expect(
    readReleaseSeriesResponse(
      new Response(fixture.rawJson, {
        headers: { "content-type": "application/json" },
      }),
      request,
    ),
  ).rejects.toThrow();
});

test.each(["fake", "wrong-array"])(
  "response chunk %s is refused without invoking user callbacks",
  async (mode) => {
    const getter = vi.fn(() => 1);
    const chunk =
      mode === "wrong-array"
        ? new Uint16Array([123, 125])
        : Object.defineProperty({}, "byteLength", { get: getter });
    Object.defineProperty(chunk, "buffer", { get: getter });
    const cancel = vi.fn();
    const response = new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(chunk);
        },
        cancel,
      }),
      { headers: { "content-type": "application/json" } },
    );
    await expect(
      readReleasePollResponse(response, fixture.request),
    ).rejects.toThrow();
    expect(getter).not.toHaveBeenCalled();
    expect(cancel).toHaveBeenCalledOnce();
  },
);
test("a branded byte view is read through intrinsic accessors without subclass callbacks", async () => {
  const getter = vi.fn(() => {
    throw new Error("Synthetic callback");
  });
  class CustomBytes extends Uint8Array {}
  const chunk = new CustomBytes(new TextEncoder().encode(fixture.rawJson));
  Object.defineProperty(chunk, "buffer", { get: getter });
  Object.defineProperty(chunk, "byteLength", { get: getter });
  Object.defineProperty(chunk, "byteOffset", { get: getter });
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(chunk);
        controller.close();
      },
    }),
    { headers: { "content-type": "application/json" } },
  );
  expect(
    (await readReleasePollResponse(response, fixture.request)).rawJson,
  ).toBe(fixture.rawJson);
  expect(getter).not.toHaveBeenCalled();
});
test("error descriptors cannot execute a getter or publish unknown message text", async () => {
  const { releaseFailureMessage } = await import("./release-cadence");
  const getter = vi.fn(() => "persistence_outcome_unavailable");
  const value = Object.defineProperty({}, "code", { get: getter });
  expect(releaseFailureMessage(value)).toBe(
    "The release operation did not complete. Check the request and current authentication before retrying.",
  );
  expect(getter).not.toHaveBeenCalled();
});
