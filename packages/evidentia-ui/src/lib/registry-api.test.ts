import { afterEach, expect, test, vi } from "vitest";
import {
  registryDemoCases,
  registryDemoResponse,
} from "@/lib/demo/registry-fixtures";
import { REGISTRY_NAMES, type RegistryRequest } from "@/lib/registry";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});
const cases = REGISTRY_NAMES.flatMap((registry) => registryDemoCases(registry));

test.each(cases.filter((item) => item.request.registry !== "ssl-labs"))(
  "API preserves the full $name response",
  async ({ name, request }) => {
    vi.stubEnv("VITE_DEMO", "false");
    vi.resetModules();
    const example = registryDemoResponse(request, name);
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(example.rawJson, {
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetch);
    const { api } = await import("@/lib/api");
    expect((await api.collectRegistry(request)).rawJson).toBe(example.rawJson);
    expect(fetch).toHaveBeenCalledExactlyOnceWith("/api/collectors/registry", {
      method: "POST",
      body: JSON.stringify(request),
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    });
  },
);

test.each([401, 403, 422, 503, 500])(
  "HTTP %s failure cancels the body without reading its contents",
  async (status) => {
    vi.stubEnv("VITE_DEMO", "false");
    vi.resetModules();
    const cancel = vi.fn(() => {
      throw new Error("Synthetic upstream detail");
    });
    const body = new ReadableStream<Uint8Array>({ cancel });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(body, { status })),
    );
    const { api } = await import("@/lib/api");
    await expect(api.collectRegistry(cases[0].request)).rejects.toMatchObject({
      message: "Registry collection failed",
      status,
      payload: null,
    });
    expect(cancel).toHaveBeenCalledOnce();
  },
);

test("invalid input and live-disabled SSL Labs cause zero fetch calls", async () => {
  vi.stubEnv("VITE_DEMO", "false");
  vi.resetModules();
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { api } = await import("@/lib/api");
  await expect(
    api.collectRegistry({ registry: "tls", target: { hostname: "127.0.0.1" } }),
  ).rejects.toThrow();
  await expect(
    api.collectRegistry(registryDemoCases("ssl-labs")[0].request),
  ).rejects.toThrow("SSL Labs live collection is disabled");
  expect(fetch).not.toHaveBeenCalled();
});

test("response binding uses the detached request if a caller mutates its input", async () => {
  vi.stubEnv("VITE_DEMO", "false");
  vi.resetModules();
  const sample = cases[0];
  const expected = registryDemoResponse(sample.request, sample.name);
  const input = JSON.parse(JSON.stringify(sample.request)) as RegistryRequest;
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      input.scope_label = "Changed during request";
      return new Response(expected.rawJson, {
        headers: { "content-type": "application/json" },
      });
    }),
  );
  const { api } = await import("@/lib/api");
  expect((await api.collectRegistry(input)).rawJson).toBe(expected.rawJson);
});

test("demo API is isolated for all eleven selectors and returns detached validated results", async () => {
  vi.stubEnv("VITE_DEMO", "true");
  vi.resetModules();
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { api } = await import("@/lib/api");
  for (const sample of cases) {
    const first = await api.collectRegistry(sample.request, sample.name);
    const second = await api.collectRegistry(sample.request, sample.name);
    expect(second.result).not.toBe(first.result);
    expect(second.rawJson).toBe(first.rawJson);
  }
  expect(fetch).not.toHaveBeenCalled();
});
