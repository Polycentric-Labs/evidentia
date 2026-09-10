import { afterEach, describe, expect, it, vi } from "vitest";

import { api, extractApiErrorMessage } from "@/lib/api";
import { DEMO_ENTRA_M365_UNAVAILABLE } from "@/lib/demo/fixtures";

describe("extractApiErrorMessage", () => {
  it("extracts message from the structured detail shape", () => {
    // 2026-07-06 error-shape convergence: deliberate 4xx/5xx carry
    // `{detail: {error, ..., message}}` (see evidentia_api.errors).
    expect(
      extractApiErrorMessage({
        detail: {
          error: "not_found",
          resource: "framework",
          message: "Framework 'x' not found.",
        },
      }),
    ).toBe("Framework 'x' not found.");
  });

  it("still accepts the legacy bare-string detail", () => {
    expect(extractApiErrorMessage({ detail: "plain text" })).toBe("plain text");
  });

  it("returns undefined for Pydantic 422 array details", () => {
    expect(
      extractApiErrorMessage({
        detail: [{ loc: ["body", "x"], msg: "field required" }],
      }),
    ).toBeUndefined();
  });

  it("returns undefined for non-object / detail-less payloads", () => {
    expect(extractApiErrorMessage(null)).toBeUndefined();
    expect(extractApiErrorMessage("nope")).toBeUndefined();
    expect(extractApiErrorMessage({})).toBeUndefined();
    expect(extractApiErrorMessage({ detail: { error: "x" } })).toBeUndefined();
  });
});

describe("Entra/M365 request transport", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("posts same-origin JSON and preserves the full unavailable result", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(DEMO_ENTRA_M365_UNAVAILABLE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const request = { tenant_label: "fixture" };
    expect(await api.collectEntraM365(request)).toEqual(
      DEMO_ENTRA_M365_UNAVAILABLE,
    );
    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/collectors/entra-m365/collect",
    );
    expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual(request);
  });
});
