import { afterEach, expect, it, vi } from "vitest";
import { ENTERPRISE_RETENTION_DEMO } from "@/lib/demo/fixtures";
import { parseEnterpriseRetentionResponse, snapshotEnterpriseRetentionRequest } from "@/lib/enterprise-retention";

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.resetModules(); });
it.each(["google-vault", "splunk-enterprise", "elastic-ilm"] as const)("validates all actual-session synthetic %s fixture statuses", provider => {
  for (const status of ["complete", "partial", "unavailable"] as const) {
    const example = ENTERPRISE_RETENTION_DEMO[provider][status];
    const result = parseEnterpriseRetentionResponse(example.rawJson, example.request);
    expect(result.result.provider).toBe(provider);
    expect(result.result.status).toBe(status);
    expect(result.result.findings.every(finding => finding.compliance_status === "unknown")).toBe(true);
    expect(result.rawJson).not.toMatch(/credential_ref|api_principals|Authorization|https:\/\//);
  }
});
it("uses the real demo dispatcher, returns detached results and rejects alternate selections with no network", async () => {
  vi.stubEnv("VITE_DEMO", "true"); vi.resetModules();
  const fetch = vi.fn(() => { throw new Error("Unexpected network"); }); vi.stubGlobal("fetch", fetch);
  const { api } = await import("@/lib/api");
  for (const provider of ["google-vault", "splunk-enterprise", "elastic-ilm"] as const) for (const status of ["complete", "partial", "unavailable"] as const) {
    const example = ENTERPRISE_RETENTION_DEMO[provider][status];
    const selected = snapshotEnterpriseRetentionRequest(example.request);
    const first = await api.collectEnterpriseRetention(selected, status);
    first.result.resources.splice(0); first.result.source_reads.splice(0);
    const next = await api.collectEnterpriseRetention(selected, status);
    expect(next.rawJson).toBe(example.rawJson); expect(next.result.resources).toHaveLength(2);
    await expect(api.collectEnterpriseRetention({ ...selected, profile_alias: "other" }, status)).rejects.toThrow();
  }
  expect(fetch).not.toHaveBeenCalled();
});

it("captures the demo selection before the caller can mutate its request", async () => {
  vi.stubEnv("VITE_DEMO", "true"); vi.resetModules();
  const fetch = vi.fn(() => { throw new Error("Unexpected network"); }); vi.stubGlobal("fetch", fetch);
  const { api } = await import("@/lib/api");
  const example = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete;
  const offered = JSON.parse(JSON.stringify(example.request));
  const pending = api.collectEnterpriseRetention(offered, "complete");
  Object.assign(offered, JSON.parse(JSON.stringify(ENTERPRISE_RETENTION_DEMO["google-vault"].complete.request)));
  const result = await pending;
  expect(result.rawJson).toBe(example.rawJson);
  expect(result.result.provider).toBe("splunk-enterprise");
  expect(fetch).not.toHaveBeenCalled();
});
