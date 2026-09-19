import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SCAP_DEMO_CASES } from "./scap-demo-cases";
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

describe("SCAP examples loaded on demand", () => {
  beforeEach(async () => {
    vi.stubGlobal(
      "crypto",
      (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
    );
  });
  afterEach(() => {
    vi.doUnmock("@/lib/demo/scap-fixtures");
    vi.unstubAllGlobals();
  });
  it.each(SCAP_DEMO_CASES)(
    "preserves the exact $id result through the demo client",
    async ({ id }) => {
      const fixtures =
        await vi.importActual<typeof import("./scap-fixtures")>(
          "./scap-fixtures",
        );
      const selected = fixtures.scapDemoSource(id);
      const expected = await fixtures.scapDemoResponse(
        selected.raw,
        selected.request,
        id,
      );
      const result = await demoApi.collectScap(
        selected.raw,
        selected.request,
        id,
      );
      expect(result.rawJson).toBe(expected.rawJson);
      expect(result.artifactRawJson).toBe(expected.artifactRawJson);
    },
  );
  it("refuses unknown scenarios before loading the fixture asset", async () => {
    const factory = vi.fn(() => {
      throw new Error("Unexpected fixture load");
    });
    vi.doMock("@/lib/demo/scap-fixtures", factory);
    await expect(
      demoApi.collectScap(new ArrayBuffer(1), {} as never, "unknown-scenario"),
    ).rejects.toThrow("The SCAP input or response is invalid");
    expect(factory).not.toHaveBeenCalled();
  });
  it("captures source bytes and nested request values before a delayed fixture load", async () => {
    const fixtures =
      await vi.importActual<typeof import("./scap-fixtures")>(
        "./scap-fixtures",
      );
    const selected = fixtures.scapDemoSource("oval-5.8-asserted");
    const original = fixtures.scapDemoSource("oval-5.8-asserted");
    const expected = await fixtures.scapDemoResponse(
      original.raw,
      original.request,
      "oval-5.8-asserted",
    );
    let release!: (value: typeof fixtures) => void;
    const module = new Promise<typeof fixtures>((resolve) => {
      release = resolve;
    });
    const factory = vi.fn(() => module);
    vi.doMock("@/lib/demo/scap-fixtures", factory);
    const pending = demoApi.collectScap(
      selected.raw,
      selected.request,
      "oval-5.8-asserted",
    );
    await vi.waitFor(() => expect(factory).toHaveBeenCalledOnce());
    new Uint8Array(selected.raw)[0] ^= 1;
    selected.request.assessment_index = 99;
    selected.request.completion_assertion!.source_sha256 = "0".repeat(64);
    release(fixtures);
    const result = await pending;
    expect(result.rawJson).toBe(expected.rawJson);
    expect(result.artifactRawJson).toBe(expected.artifactRawJson);
  });
  it("returns the fixed refusal when the fixture asset fails to load", async () => {
    const fixtures =
      await vi.importActual<typeof import("./scap-fixtures")>(
        "./scap-fixtures",
      );
    const source = fixtures.scapDemoSource("xccdf-qualified");
    vi.doMock("@/lib/demo/scap-fixtures", () => {
      throw new Error("Synthetic asset-load failure");
    });
    await expect(
      demoApi.collectScap(source.raw, source.request, "xccdf-qualified"),
    ).rejects.toThrow("The SCAP input or response is invalid");
  });
});
