import { describe, expect, it } from "vitest";

import { extractApiErrorMessage } from "@/lib/api";

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
    expect(extractApiErrorMessage({ detail: "plain text" })).toBe(
      "plain text",
    );
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
    expect(
      extractApiErrorMessage({ detail: { error: "x" } }),
    ).toBeUndefined();
  });
});
