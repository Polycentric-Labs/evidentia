import { afterEach, describe, expect, it, vi } from "vitest";

import { exportGapReport, type VexSpecVersion } from "@/lib/api";
import { demoExportGapReport } from "@/lib/demo/demo-api";
import type { GapAnalysisReport } from "@/types/api";

const REPORT = { id: "synthetic-demo-report" } as GapAnalysisReport;
vi.mock("@/lib/demo", () => ({ IS_DEMO: true }));

afterEach(() => vi.unstubAllGlobals());

describe("VEX demo refusal", () => {
  it("uses the demo implementation through the public client export", () => {
    expect(exportGapReport).toBe(demoExportGapReport);
  });
  it.each([undefined, "1.6", "1.7"] as const)(
    "refuses VEX %s before Blob or fetch",
    async (version) => {
      const blob = vi.fn();
      const fetch = vi.fn();
      vi.stubGlobal("Blob", blob);
      vi.stubGlobal("fetch", fetch);
      await expect(
        Promise.resolve().then(() =>
          demoExportGapReport(REPORT, "cyclonedx-vex", version),
        ),
      ).rejects.toThrow("CycloneDX VEX export is unavailable in demo mode.");
      expect(blob).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["1.5", " 1.7", "1.7 ", null, true, 1.7, [], {}, new String("1.7")])(
    "validates %s before format behavior",
    async (version) => {
      const blob = vi.fn();
      const fetch = vi.fn();
      vi.stubGlobal("Blob", blob);
      vi.stubGlobal("fetch", fetch);
      await expect(
        Promise.resolve().then(() =>
          demoExportGapReport(
            REPORT,
            "cyclonedx-vex",
            version as VexSpecVersion,
          ),
        ),
      ).rejects.toThrow("Invalid VEX version selection");
      expect(blob).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["1.6", "1.7"] as const)(
    "refuses non-VEX selection %s before Blob",
    async (version) => {
      const blob = vi.fn();
      vi.stubGlobal("Blob", blob);
      await expect(
        Promise.resolve().then(() =>
          demoExportGapReport(REPORT, "json", version),
        ),
      ).rejects.toThrow("Invalid VEX version selection");
      expect(blob).not.toHaveBeenCalled();
    },
  );

  it.each([
    "json",
    "csv",
    "sarif",
    "oscal-ar",
    "ocsf",
    "ocsf-detection",
    "markdown",
  ] as const)(
    "preserves old demo behavior for %s without a selector",
    async (format) => {
      const NativeBlob = Blob;
      const blob = vi.fn(function (
        parts: BlobPart[],
        options: BlobPropertyBag,
      ) {
        return new NativeBlob(parts, options);
      });
      const fetch = vi.fn();
      vi.stubGlobal("Blob", blob);
      vi.stubGlobal("fetch", fetch);
      const result = await demoExportGapReport(REPORT, format);
      expect(blob).toHaveBeenCalledWith([JSON.stringify(REPORT, null, 2)], {
        type: "application/json",
      });
      expect(result.filename).toBe(
        `gap-report.${format === "json" ? "json" : "txt"}`,
      );
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});
