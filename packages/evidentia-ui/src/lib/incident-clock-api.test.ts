import { afterEach, expect, test, vi } from "vitest";
import {
  INCIDENT_FIXTURES,
  incidentDemoCases,
  incidentDemoResponse,
} from "@/lib/demo/incident-clock-fixtures";
import {
  INCIDENT_RESULT_BYTES,
  readIncidentResponse,
  type IncidentClockRequest,
} from "@/lib/incident-clock";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});
const request = incidentDemoCases("servicenow")[0].request;
const raw = incidentDemoResponse(request, "servicenow-complete").rawJson;
const headers = { "content-type": "application/json" };
async function liveApi() {
  vi.stubEnv("VITE_DEMO", "false");
  vi.resetModules();
  return (await import("@/lib/api")).api;
}

test.each(INCIDENT_FIXTURES)(
  "keeps the complete $name response and exact request",
  async (sample) => {
    const api = await liveApi();
    const input = JSON.parse(sample.raw).request as IncidentClockRequest;
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(sample.raw, { headers }));
    vi.stubGlobal("fetch", fetch);
    expect((await api.collectIncidentClock(input)).rawJson).toBe(sample.raw);
    expect(fetch).toHaveBeenCalledExactlyOnceWith(
      "/api/collectors/incident-clock",
      {
        method: "POST",
        body: JSON.stringify(input),
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
      },
    );
  },
);

test.each([401, 403, 413, 415, 422, 500, 503])(
  "HTTP %s refuses with a fixed error and cancels unread content",
  async (status) => {
    const api = await liveApi();
    const cancel = vi.fn(() => {
      throw new Error("Synthetic upstream detail");
    });
    const body = new ReadableStream<Uint8Array>({ cancel });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(body, { status })),
    );
    await expect(api.collectIncidentClock(request)).rejects.toMatchObject({
      message: "Incident clock collection failed",
      status,
      payload: null,
    });
    expect(cancel).toHaveBeenCalledOnce();
  },
);

test("invalid requests do not contact the API", async () => {
  const api = await liveApi();
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(
    api.collectIncidentClock({ ...request, profile_alias: "../invalid" }),
  ).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});

test("detaches request identity before asynchronous collection", async () => {
  const api = await liveApi();
  const input = { ...request };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      input.record_id = "2".repeat(32);
      return new Response(raw, { headers });
    }),
  );
  expect((await api.collectIncidentClock(input)).rawJson).toBe(raw);
});

test("rejects a structurally valid result for a different request", async () => {
  const api = await liveApi();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(new Response(raw, { headers })),
  );
  await expect(
    api.collectIncidentClock({ ...request, clock_alias: "other" }),
  ).rejects.toThrow(
    "The incident clock JSON is invalid or does not match the selected request.",
  );
});

test("demo collection for all providers uses detached validated results and no fetch", async () => {
  vi.stubEnv("VITE_DEMO", "true");
  vi.resetModules();
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { api } = await import("@/lib/api");
  for (const sample of INCIDENT_FIXTURES) {
    const input = JSON.parse(sample.raw).request;
    const first = await api.collectIncidentClock(input, sample.name);
    const second = await api.collectIncidentClock(input, sample.name);
    expect(first.rawJson).toBe(sample.raw);
    expect(second.rawJson).toBe(sample.raw);
    expect(first.result).not.toBe(second.result);
  }
  expect(fetch).not.toHaveBeenCalled();
});

test.each(["0", "1", String(INCIDENT_RESULT_BYTES + 100)])(
  "actual bytes determine admission when Content-Length is %s",
  async (length) => {
    const bytes = new TextEncoder().encode(raw);
    let offset = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset === bytes.length) controller.close();
        else {
          controller.enqueue(bytes.slice(offset, offset + 7));
          offset = Math.min(offset + 7, bytes.length);
        }
      },
    });
    expect(
      (
        await readIncidentResponse(
          new Response(body, {
            headers: { ...headers, "content-length": length },
          }),
          request,
        )
      ).rawJson,
    ).toBe(raw);
    expect(body.locked).toBe(false);
  },
);

test("accepts exactly 16 MiB without changing original JSON bytes", async () => {
  const padded =
    raw +
    " ".repeat(INCIDENT_RESULT_BYTES - new TextEncoder().encode(raw).length);
  expect(
    (await readIncidentResponse(new Response(padded, { headers }), request))
      .rawJson,
  ).toBe(padded);
});

test("the first over-limit chunk cancels and releases the stream", async () => {
  const cancel = vi.fn();
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(INCIDENT_RESULT_BYTES + 1));
    },
    cancel,
  });
  await expect(
    readIncidentResponse(new Response(body, { headers }), request),
  ).rejects.toThrow(
    "The incident clock JSON is invalid or does not match the selected request.",
  );
  expect(cancel).toHaveBeenCalledOnce();
  expect(body.locked).toBe(false);
  expect(pulls).toBeLessThanOrEqual(2);
});

test.each(["text/html", "text/plain", "application/problem+json", ""])(
  "rejects media type %s before reading body contents",
  async (media) => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    await expect(
      readIncidentResponse(
        new Response(body, { headers: { "content-type": media } }),
        request,
      ),
    ).rejects.toThrow();
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
  },
);

test.each([
  new Uint8Array([0xff]),
  new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]),
  new TextEncoder().encode('{"provider":"jira","provider":"jira"}'),
])("rejects malformed UTF-8, BOM and duplicate JSON keys", async (bytes) => {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  await expect(
    readIncidentResponse(new Response(body, { headers }), request),
  ).rejects.toThrow();
  expect(body.locked).toBe(false);
});

test("reader failure has a fixed error and releases ownership", async () => {
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.error(new Error("Synthetic stream detail"));
    },
  });
  await expect(
    readIncidentResponse(new Response(body, { headers }), request),
  ).rejects.toThrow(
    "The incident clock JSON is invalid or does not match the selected request.",
  );
  expect(body.locked).toBe(false);
});
