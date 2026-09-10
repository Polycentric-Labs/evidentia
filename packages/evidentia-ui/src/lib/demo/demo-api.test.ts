import { describe, expect, it } from "vitest";
import { demoApi, simulateSse } from "./demo-api";
import { DEMO_FRAMEWORKS } from "./fixtures";

describe("demo-api", () => {
  it("returns the hero report list with no network", async () => {
    const list = await demoApi.listGapReports();
    expect(list.reports[0].organization).toBe("Meridian Financial");
  });
  it("resolves a report by key", async () => {
    const r = await demoApi.getGapReport("meridian-fintech-v2:baseline");
    expect(r.total_gaps).toBe(311);
  });

  describe.each(["catalogWhere", "catalogLicenseInfo"] as const)(
    "%s text depth",
    (endpoint) => {
      it.each(DEMO_FRAMEWORKS.frameworks)(
        "agrees with the framework list for $id",
        async ({ id }) => {
          const list = await demoApi.listFrameworks();
          const entry = list.frameworks.find(
            (framework) => framework.id === id,
          );
          const detail = await demoApi[endpoint](id);
          expect(entry).toBeDefined();
          expect(detail.text_depth).toBe(entry?.text_depth);
        },
      );

      it.each(["soc2-tsc", "iso-27001-2022"])(
        "reports headings for the %s stub",
        async (id) => {
          expect((await demoApi[endpoint](id)).text_depth).toBe("headings");
        },
      );

      it("does not claim a depth for an unknown framework", async () => {
        expect(
          (await demoApi[endpoint]("unknown-framework")).text_depth,
        ).toBeNull();
      });
    },
  );

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

describe("Entra/M365 synthetic results", () => {
  it.each(["partial", "unavailable"] as const)(
    "returns an isolated %s example with all capability states",
    async (scenario) => {
      const first = await demoApi.collectEntraM365(
        { tenant_label: "synthetic-demo" },
        scenario,
      );
      expect(first.status).toBe(scenario);
      expect(first.provenance.tenant_label).toBe("synthetic-demo");
      expect(first.provenance.authenticated_identity_verified).toBe(false);
      expect(first.capabilities).toHaveLength(9);
      expect(first.full_surface_complete).toBe(false);
      first.capabilities[0].scanned = 999;
      const again = await demoApi.collectEntraM365(
        { tenant_label: "synthetic-demo" },
        scenario,
      );
      expect(again.capabilities[0].scanned).not.toBe(999);
    },
  );
});
