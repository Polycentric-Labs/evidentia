import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, exportGapReport, type VexSpecVersion } from "@/lib/api";
import type { GapAnalysisReport } from "@/types/api";

vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));

const REPORT = { id: "synthetic-client-report" } as GapAnalysisReport;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("VEX runtime export selection", () => {
  it.each([undefined, "1.6", "1.7"] as const)(
    "sends resolved VEX version %s and returns the exact server blob",
    async (version) => {
      const blob = new Blob([new Uint8Array([0, 13, 10, 255, 34])]);
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers({
          "content-disposition":
            'attachment; filename="synthetic.vex.cdx.json"',
        }),
        blob: async () => blob,
      });
      vi.stubGlobal("fetch", fetchMock);
      const result = await exportGapReport(REPORT, "cyclonedx-vex", version);
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe("/api/gap/export");
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({
        format: "cyclonedx-vex",
        report: REPORT,
        vex_spec_version: version ?? "1.6",
      });
      expect(result.blob).toBe(blob);
      expect(result.filename).toBe("synthetic.vex.cdx.json");
    },
  );

  it("preserves an omitted selector on a two-argument non-VEX call", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers(),
      blob: async () => new Blob(["old bytes"]),
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await exportGapReport(REPORT, "json");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      format: "json",
      report: REPORT,
    });
    expect(result.filename).toBe("gap-report.json");
  });

  it.each([
    "1.5",
    "1.8",
    " 1.7",
    "1.7 ",
    "",
    null,
    true,
    1.7,
    [],
    {},
    new String("1.7"),
  ])("refuses invalid native selector %s before fetch", async (value) => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      exportGapReport(REPORT, "cyclonedx-vex", value as VexSpecVersion),
    ).rejects.toThrow("Invalid VEX version selection");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["1.6", "1.7"] as const)(
    "refuses explicit %s on non-VEX before fetch",
    async (value) => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      await expect(exportGapReport(REPORT, "json", value)).rejects.toThrow(
        "Invalid VEX version selection",
      );
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([true, false])(
    "keeps the existing HTTP error behavior with JSON=%s",
    async (isJson) => {
      const blob = vi.fn();
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: false,
          status: 400,
          json: async () => {
            if (!isJson) throw new SyntaxError("synthetic non-JSON response");
            return {
              detail: { error: "invalid_body", message: "synthetic refusal" },
            };
          },
          blob,
        }),
      );
      await expect(
        exportGapReport(REPORT, "cyclonedx-vex", "1.7"),
      ).rejects.toEqual(
        expect.objectContaining({
          message: isJson ? "synthetic refusal" : "Export failed (400)",
          status: 400,
        }),
      );
      expect(blob).not.toHaveBeenCalled();
      expect(ApiError).toBeDefined();
    },
  );
});
