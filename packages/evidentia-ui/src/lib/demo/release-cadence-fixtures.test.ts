import { afterEach, beforeEach, expect, test, vi } from "vitest";
import {
  RELEASE_DEMO_FIXTURES,
  demoCollectReleaseCadence,
  demoReleaseSeries,
  releaseDemoFixture,
} from "./release-cadence-fixtures";
import {
  snapshotReleasePollRequest,
  snapshotReleaseSeriesRequest,
} from "../release-cadence";
beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("Demo must not fetch");
    }),
  );
});
afterEach(() => vi.unstubAllGlobals());
test.each(RELEASE_DEMO_FIXTURES)(
  "$id is explicitly synthetic and uses production decoding",
  async (entry) => {
    const result = await releaseDemoFixture(entry.id);
    expect(result.rawJson).toBe(entry.rawJson);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  },
);
test("demo poll defaults to observation, never an implicit save", async () => {
  const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-observed")!;
  const response = await demoCollectReleaseCadence(
    snapshotReleasePollRequest(entry.request),
  );
  expect(response.result.persistence.state).toBe("not_requested");
  expect(response.result.persistence.attempted_calls).toBe(0);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});
test("demo series returns accepted synthetic complete bytes without discovery", async () => {
  const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === "series-two")!;
  expect(
    (await demoReleaseSeries(snapshotReleaseSeriesRequest(entry.request)))
      .rawJson,
  ).toBe(entry.rawJson);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});
test("unknown valid source cannot become a demo claim", async () => {
  const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-observed")!;
  await expect(
    demoCollectReleaseCadence(
      snapshotReleasePollRequest({ ...entry.request, owner: "Other" }),
    ),
  ).rejects.toThrow();
  expect(globalThis.fetch).not.toHaveBeenCalled();
});
