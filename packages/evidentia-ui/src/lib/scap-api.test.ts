import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  SCAP_DEMO_CASES,
  scapDemoResponse,
  scapDemoSource,
} from "./demo/scap-fixtures";

beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.resetModules();
});
async function liveApi() {
  vi.stubEnv("VITE_DEMO", "false");
  vi.resetModules();
  return (await import("./api")).api;
}
test.each(SCAP_DEMO_CASES)(
  "$id sends exact local bytes and validated explicit options with one POST",
  async ({ id }) => {
    const source = scapDemoSource(id),
      response = await scapDemoResponse(source.raw, source.request, id);
    const api = await liveApi(),
      fetch = vi.fn().mockResolvedValue(
        new Response(response.rawJson, {
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetch);
    const result = await api.collectScap(source.raw, source.request);
    expect(result.rawJson).toBe(response.rawJson);
    expect(fetch).toHaveBeenCalledOnce();
    const [url, options] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      `/api/collectors/scap/collect?source_profile=${source.request.source_profile}&assessment_index=${source.request.assessment_index}` +
        (source.request.cadence_slug === null
          ? ""
          : "&cadence_slug=" + encodeURIComponent(source.request.cadence_slug)),
    );
    expect(options.method).toBe("POST");
    expect(new Uint8Array(options.body as ArrayBuffer)).toEqual(
      new Uint8Array(source.raw),
    );
    const headers = options.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/xml");
    expect(headers.Accept).toBe("application/json");
    if (source.request.completion_assertion)
      expect(
        JSON.parse(headers["X-Evidentia-SCAP-Completion-Assertion"]),
      ).toEqual(source.request.completion_assertion);
    else
      expect(headers).not.toHaveProperty(
        "X-Evidentia-SCAP-Completion-Assertion",
      );
    expect(
      fetch.mock.calls.every(([path]) => !String(path).includes("/evidence")),
    ).toBe(true);
  },
);
test.each([400, 401, 403, 413, 415, 422, 500, 503])(
  "HTTP %s preserves a fixed error and cancels source-bearing content",
  async (status) => {
    const source = scapDemoSource("xccdf-qualified"),
      api = await liveApi(),
      cancel = vi.fn(() => {
        throw new Error("Synthetic server detail");
      });
    const body = new ReadableStream<Uint8Array>({ cancel });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(body, { status })),
    );
    await expect(
      api.collectScap(source.raw, source.request),
    ).rejects.toMatchObject({
      message: "SCAP collection failed",
      status,
      payload: null,
    });
    expect(cancel).toHaveBeenCalledOnce();
  },
);
test("invalid raw or claim values do not contact any API", async () => {
  const api = await liveApi(),
    fetch = vi.fn(),
    source = scapDemoSource("xccdf-qualified");
  vi.stubGlobal("fetch", fetch);
  await expect(
    api.collectScap(new ArrayBuffer(0), source.request),
  ).rejects.toThrow();
  await expect(
    api.collectScap(source.raw, { ...source.request, assessment_index: 256 }),
  ).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
});
test("response source mismatch cannot become a successful API result", async () => {
  const source = scapDemoSource("xccdf-qualified"),
    other = scapDemoSource("xccdf-future"),
    response = await scapDemoResponse(other.raw, other.request, "xccdf-future"),
    api = await liveApi();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(response.rawJson, {
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
  await expect(api.collectScap(source.raw, source.request)).rejects.toThrow();
});
