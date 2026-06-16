import { describe, expect, it } from "vitest";

import {
  FDA_524B_EFFICIENCY,
  FDA_524B_FRAMEWORK,
  FDA_524B_GAPS,
  FDA_524B_REPORT,
  FDA_ORG,
  FDA_RUN_STEPS,
  FDA_SIGNED_ARTIFACT,
  FDA_TRACEABILITY,
} from "./fda-fixtures";

const FRAMEWORK_ID = "fda-524b-appendix1";
const SEVERITIES = ["critical", "high", "medium", "low", "informational"];

describe("FDA 524B demo fixtures", () => {
  it("the hero report is the synthetic 8-category / 5-gap 524B baseline", () => {
    expect(FDA_524B_REPORT.frameworks_analyzed).toEqual([FRAMEWORK_ID]);
    expect(FDA_524B_REPORT.total_controls_required).toBe(8);
    expect(FDA_524B_REPORT.total_controls_in_inventory).toBe(3);
    expect(FDA_524B_REPORT.total_gaps).toBe(5);
    expect(FDA_524B_REPORT.critical_gaps).toBe(2);
    expect(FDA_524B_REPORT.high_gaps).toBe(2);
    expect(FDA_524B_REPORT.medium_gaps).toBe(1);
    expect(FDA_524B_REPORT.coverage_percentage).toBeCloseTo(37.5);
    // The gaps array backs the severity counts one-for-one.
    expect(FDA_524B_REPORT.gaps).toBe(FDA_524B_GAPS);
    expect(FDA_524B_GAPS).toHaveLength(5);
  });

  it("every gap carries the fields GapTable/SeverityBar render, on the 524B framework", () => {
    for (const g of FDA_524B_GAPS) {
      expect(g.framework).toBe(FRAMEWORK_ID);
      expect(g.control_id).toMatch(/^524B\.A[1-8]$/);
      expect(g.control_title).toBeTruthy();
      expect(SEVERITIES).toContain(g.gap_severity);
      expect(g.priority_score).toBeGreaterThan(0);
    }
    // Counts derived from the rows match the report header.
    const bySeverity = (s: string) =>
      FDA_524B_GAPS.filter((g) => g.gap_severity === s).length;
    expect(bySeverity("critical")).toBe(FDA_524B_REPORT.critical_gaps);
    expect(bySeverity("high")).toBe(FDA_524B_REPORT.high_gaps);
    expect(bySeverity("medium")).toBe(FDA_524B_REPORT.medium_gaps);
  });

  it("the framework entry is the bundled Tier-A 524B Appendix-1 catalog (not a placeholder)", () => {
    const fw = FDA_524B_FRAMEWORK.frameworks[0];
    expect(fw.id).toBe(FRAMEWORK_ID);
    expect(fw.tier).toBe("A");
    expect(fw.placeholder).toBe("false");
    expect(fw.license_required).toBe("false");
  });

  it("traceability maps eight STRIDE threats onto all eight Appendix-1 controls", () => {
    expect(FDA_TRACEABILITY).toHaveLength(8);
    const controlIds = new Set(FDA_TRACEABILITY.map((r) => r.controlId));
    for (let n = 1; n <= 8; n++) {
      expect(controlIds.has(`524B.A${n}`)).toBe(true);
    }
    for (const row of FDA_TRACEABILITY) {
      expect(row.stride).toBeTruthy();
      expect(row.threat).toBeTruthy();
      expect(row.evidence).toBeTruthy();
      expect(["gap", "partial", "satisfied"]).toContain(row.status);
    }
  });

  it("is generic-synthetic and banner-labeled — no real organization, illustrative signature", () => {
    expect(FDA_ORG.toLowerCase()).toContain("illustrative");
    expect(FDA_524B_REPORT.organization).toBe(FDA_ORG);
    // The signed artifact is an illustration signed with a test identity only.
    expect(FDA_SIGNED_ARTIFACT.signer.toLowerCase()).toContain("test");
    expect(FDA_SIGNED_ARTIFACT.framework).toBe(FRAMEWORK_ID);
  });

  it("ships the run-step sequence + efficiency rows the demo renders", () => {
    expect(FDA_RUN_STEPS.length).toBeGreaterThan(0);
    for (const step of FDA_RUN_STEPS) {
      expect(step.label).toBeTruthy();
      expect(step.detail).toBeTruthy();
    }
    expect(FDA_524B_EFFICIENCY.length).toBeGreaterThan(0);
    for (const e of FDA_524B_EFFICIENCY) {
      expect(e.frameworks_satisfied).toContain(FRAMEWORK_ID);
    }
  });
});
