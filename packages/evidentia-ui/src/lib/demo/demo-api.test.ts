import { describe, expect, it } from "vitest";
import { demoApi, simulateSse } from "./demo-api";

describe("demo-api", () => {
  it("returns the hero report list with no network", async () => {
    const list = await demoApi.listGapReports();
    expect(list.reports[0].organization).toBe("Meridian Financial");
  });
  it("resolves a report by key", async () => {
    const r = await demoApi.getGapReport("meridian-fintech-v2:baseline");
    expect(r.total_gaps).toBe(311);
  });
  it("simulateSse emits a start then a terminal done", async () => {
    const events: Array<{ phase: string }> = [];
    await simulateSse(
      [
        { phase: "start", framework: "x", control_id: "AC-2" },
        { phase: "done", explanation: {} as never },
      ],
      (e) => events.push(e as { phase: string }),
    );
    expect(events.map((e) => e.phase)).toEqual(["start", "done"]);
  });
});
