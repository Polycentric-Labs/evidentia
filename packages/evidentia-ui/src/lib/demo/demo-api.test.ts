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

  it("simulateSse stops on an already-aborted signal — no frames, no terminal", async () => {
    const controller = new AbortController();
    controller.abort();
    const events: Array<{ phase: string }> = [];
    await simulateSse(
      [
        { phase: "start", framework: "x", control_id: "AC-2" },
        { phase: "done", explanation: {} as never },
      ],
      (e) => events.push(e as { phase: string }),
      0,
      controller.signal,
    );
    // Aborting before the loop runs delivers nothing — crucially not the
    // terminal `done` frame that would otherwise undo a Cancel.
    expect(events).toEqual([]);
  });

  it("simulateSse aborts mid-stream and never emits the terminal done frame", async () => {
    const controller = new AbortController();
    const events: Array<{ phase: string }> = [];
    await simulateSse(
      [
        { phase: "start", framework: "x", control_id: "AC-2" },
        { phase: "progress", framework: "x", control_id: "AC-2" },
        { phase: "done", explanation: {} as never },
      ],
      (e) => {
        events.push(e as { phase: string });
        // Cancel as soon as the first frame lands (the user clicking Cancel).
        if ((e as { phase: string }).phase === "start") controller.abort();
      },
      0,
      controller.signal,
    );
    // The `start` frame was delivered, then the abort halts the stream before
    // the terminal `done` re-sets the page's streaming state.
    expect(events.map((e) => e.phase)).toEqual(["start"]);
  });
});
