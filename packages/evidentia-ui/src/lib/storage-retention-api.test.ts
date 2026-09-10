import { snapshotStorageRetentionRequest } from "@/lib/storage-retention";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  STORAGE_RETENTION_EXAMPLES,
  STORAGE_RETENTION_NUMERIC_WIRES,
} from "@/lib/demo/storage-retention-fixture";

const body = {
  provider: "gcs" as const,
  scope_label: "synthetic-ui",
  targets: [{ bucket: "synthetic-archive" }],
};
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});
describe("storage API boundary", () => {
  it.each(["complete", "partial", "unavailable"] as const)(
    "retains the full %s response on the exact endpoint",
    async (status) => {
      vi.stubEnv("VITE_DEMO", "false");
      vi.resetModules();
      const result = structuredClone(STORAGE_RETENTION_EXAMPLES[status]);
      const fetch = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(result), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
      vi.stubGlobal("fetch", fetch);
      const { api } = await import("@/lib/api");
      const selected = snapshotStorageRetentionRequest({
        provider: result.provider,
        scope_label: result.scope_label,
        targets: result.resources.map((item) => item.target),
      });
      const received = await api.collectStorageRetention(selected);
      expect(received.result).toEqual(result);
      expect(received.rawJson).toBe(JSON.stringify(result));
      expect(fetch).toHaveBeenCalledExactlyOnceWith(
        "/api/collectors/retention/collect",
        {
          method: "POST",
          body: JSON.stringify(selected),
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
        },
      );
    },
  );
  it("makes no request for demo, ignores caller changes and returns fresh full examples", async () => {
    vi.stubEnv("VITE_DEMO", "true");
    vi.resetModules();
    const fetch = vi.fn(() => {
      throw new Error("Unexpected network");
    });
    vi.stubGlobal("fetch", fetch);
    const { api } = await import("@/lib/api");
    const first = await api.collectStorageRetention(body);
    expect(first.result).toEqual(STORAGE_RETENTION_EXAMPLES.partial);
    first.result.resources.splice(0);
    expect((await api.collectStorageRetention(body)).result).toEqual(
      STORAGE_RETENTION_EXAMPLES.partial,
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("authoritative storage wire retention", () => {
  it.each(["s3", "contract"] as const)(
    "retains the exact factory %s JSON before any number conversion",
    async (name) => {
      vi.stubEnv("VITE_DEMO", "false");
      vi.resetModules();
      const raw = STORAGE_RETENTION_NUMERIC_WIRES[name];
      const expected = snapshotStorageRetentionRequest(
        name === "s3"
          ? {
              provider: "s3",
              scope_label: "synthetic",
              targets: [
                {
                  bucket: "synthetic-retention",
                  region: "us-east-1",
                  expected_owner: "123456789012",
                },
              ],
            }
          : {
              provider: "gcs",
              scope_label: "synthetic-contract",
              targets: [{ bucket: "synthetic-contract" }],
            },
      );
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          new Response(raw, {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        ),
      );
      const { api } = await import("@/lib/api");
      const receipt = await api.collectStorageRetention(expected);
      expect(receipt.rawJson).toBe(raw);
    },
  );
});

it.each([401, 403, 500])(
  "cancels HTTP %s refusal bodies without reading private error data",
  async (status) => {
    vi.stubEnv("VITE_DEMO", "false");
    vi.resetModules();
    let cancelled = false;
    const response = new Response(
      new ReadableStream<Uint8Array>({
        cancel() {
          cancelled = true;
          throw new Error("PRIVATE_CANCEL");
        },
      }),
      { status, headers: { "content-type": "application/json" } },
    );
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    const { api } = await import("@/lib/api");
    await expect(api.collectStorageRetention(body)).rejects.toMatchObject({
      message: "Storage collection failed",
      status,
    });
    expect(cancelled).toBe(true);
  },
);
