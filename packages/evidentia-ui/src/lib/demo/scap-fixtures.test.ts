import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  SCAP_DEMO_CASES,
  scapDemoResponse,
  scapDemoSource,
} from "./scap-fixtures";

beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});
test.each(SCAP_DEMO_CASES)(
  "$id is a complete validated synthetic API output",
  async ({ id }) => {
    const source = scapDemoSource(id);
    const response = await scapDemoResponse(source.raw, source.request, id);
    expect(response.result.source.sha256).toBe(
      [...new Uint8Array(await crypto.subtle.digest("SHA-256", source.raw))]
        .map((n) => n.toString(16).padStart(2, "0"))
        .join(""),
    );
    expect(JSON.parse(response.rawJson)).toEqual(response.result);
    expect(Object.isFrozen(response.result.native_document.nodes)).toBe(true);
    if (response.artifactRawJson !== null)
      expect(JSON.parse(response.artifactRawJson)).toEqual(
        response.result.evidence_artifact,
      );
    else expect(response.result.evidence_artifact).toBeNull();
  },
);
test("demo mode refuses changed bytes or request and does not interpret arbitrary files", async () => {
  const source = scapDemoSource("xccdf-qualified");
  new Uint8Array(source.raw)[0] ^= 1;
  await expect(
    scapDemoResponse(source.raw, source.request, "xccdf-qualified"),
  ).rejects.toThrow();
  const good = scapDemoSource("xccdf-qualified");
  await expect(
    scapDemoResponse(
      good.raw,
      { ...good.request, assessment_index: 1 },
      "xccdf-qualified",
    ),
  ).rejects.toThrow();
});
