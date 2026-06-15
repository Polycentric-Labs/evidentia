import { describe, expect, it } from "vitest";

import { DEMO_GAP_REPORT, DEMO_FRAMEWORKS, DEMO_REPORT_LIST } from "./fixtures";

describe("demo fixtures", () => {
  it("the hero gap report mirrors the Meridian v2 baseline shape", () => {
    expect(DEMO_GAP_REPORT.organization).toBe("Meridian Financial");
    expect(DEMO_GAP_REPORT.total_gaps).toBe(311);
    expect(DEMO_GAP_REPORT.critical_gaps).toBe(297);
    expect(DEMO_GAP_REPORT.coverage_percentage).toBeCloseTo(10.6);
    expect(DEMO_GAP_REPORT.total_controls_required).toBe(348);
    expect(DEMO_GAP_REPORT.total_controls_in_inventory).toBe(49);
    expect(DEMO_GAP_REPORT.frameworks_analyzed).toEqual([
      "nist-800-53-rev5-moderate",
      "soc2-tsc",
    ]);
    // every gap carries the fields the GapTable renders
    for (const g of DEMO_GAP_REPORT.gaps) {
      expect(g.control_id).toBeTruthy();
      expect(["critical", "high", "medium", "low", "informational"]).toContain(
        g.gap_severity,
      );
    }
  });

  it("the report list summary matches the hero report", () => {
    const meta = DEMO_REPORT_LIST.reports.find(
      (r) => r.key === "meridian-fintech-v2:baseline",
    );
    expect(meta?.total_gaps).toBe(DEMO_GAP_REPORT.total_gaps);
  });

  it("ships the catalog the demo story references", () => {
    const ids = DEMO_FRAMEWORKS.frameworks.map((f) => f.id);
    expect(ids).toContain("nist-800-53-rev5-moderate");
    expect(ids).toContain("soc2-tsc");
  });
});
