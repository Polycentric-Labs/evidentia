import { afterEach, describe, expect, it, vi } from "vitest";
import { ENTERPRISE_RETENTION_DEMO } from "@/lib/demo/fixtures";
import { snapshotEnterpriseRetentionRequest } from "@/lib/enterprise-retention";

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.resetModules(); });
describe("enterprise API boundary", () => {
  it.each(["complete", "partial", "unavailable"] as const)("posts only the selected request and retains the %s wire", async status => {
    vi.stubEnv("VITE_DEMO", "false"); vi.resetModules();
    const example = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"][status];
    const fetch = vi.fn().mockResolvedValue(new Response(example.rawJson, { headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetch);
    const { api } = await import("@/lib/api");
    const request = snapshotEnterpriseRetentionRequest(example.request);
    const received = await api.collectEnterpriseRetention(request);
    expect(received.rawJson).toBe(example.rawJson);
    expect(received.result.status).toBe(status);
    expect(fetch).toHaveBeenCalledExactlyOnceWith("/api/collectors/enterprise-retention/collect", { method: "POST", body: JSON.stringify(request), headers: { "Content-Type": "application/json", Accept: "application/json" } });
  });
  it.each([401, 403, 413, 503, 500])("cancels HTTP %s errors without reading private provider text", async status => {
    vi.stubEnv("VITE_DEMO", "false"); vi.resetModules();
    let cancelled = false;
    const response = new Response(new ReadableStream<Uint8Array>({ cancel() { cancelled = true; throw new Error("PRIVATE_CANCEL"); } }), { status });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    const { api } = await import("@/lib/api");
    await expect(api.collectEnterpriseRetention(snapshotEnterpriseRetentionRequest(ENTERPRISE_RETENTION_DEMO["google-vault"].complete.request))).rejects.toMatchObject({ message: "Enterprise collection failed", status, payload: null });
    expect(cancelled).toBe(true);
  });
  it("refuses malformed input before fetch and binds responses to the original detached request", async () => {
    vi.stubEnv("VITE_DEMO", "false"); vi.resetModules();
    const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
    const { api } = await import("@/lib/api");
    const sample = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete;
    await expect(api.collectEnterpriseRetention({ ...sample.request, targets: [] })).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
    const input = JSON.parse(JSON.stringify(sample.request));
    fetch.mockImplementation(async () => {
      input.scope_label = "other";
      return new Response(sample.rawJson, { headers: { "content-type": "application/json" } });
    });
    expect((await api.collectEnterpriseRetention(input)).rawJson).toBe(sample.rawJson);
  });
});
