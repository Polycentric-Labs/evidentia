import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api } from "@/lib/api";
import { RELEASE_DEMO_FIXTURES } from "@/lib/demo/release-cadence-fixtures";
import { ReleaseSeriesAction } from "./ReleaseSeriesAction";
vi.mock("@/lib/api", () => ({
  api: { releaseSeries: vi.fn(), collectReleaseCadence: vi.fn() },
}));
vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
const fixture = (id = "series-two") =>
  RELEASE_DEMO_FIXTURES.find((row) => row.id === id)!;
function fill(id = "series-two") {
  const req = fixture(id).request as {
    owner: string;
    repository: string;
    channel: string;
    window_start: string;
    window_end: string;
    interval_days: number;
    tolerance_days: number;
  };
  for (const [label, value] of Object.entries({
    "GitHub owner": req.owner,
    "GitHub repository": req.repository,
    "Release channel": req.channel,
    "Window start (UTC)": req.window_start,
    "Window end (UTC)": req.window_end,
    "Interval days": String(req.interval_days),
    "Tolerance days": String(req.tolerance_days),
  }))
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
}
beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
  vi.mocked(api.releaseSeries).mockReset();
  vi.mocked(api.collectReleaseCadence).mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
test.each([
  "series-empty",
  "series-one",
  "series-two",
  "series-gapped",
  "series-prerelease",
  "series-conflict",
  "series-unavailable",
])("%s keeps exact offline state and explicit interval policy", async (id) => {
  const f = fixture(id);
  vi.mocked(api.releaseSeries).mockResolvedValue({
    rawJson: f.rawJson,
    result: JSON.parse(f.rawJson),
  });
  render(<ReleaseSeriesAction freshAuth verifyAuth={async () => true} />);
  fill(id);
  expect(screen.queryByLabelText("Save release evidence locally")).toBeNull();
  expect(api.releaseSeries).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByLabelText("Accepted release result");
  expect(api.releaseSeries).toHaveBeenCalledWith(f.request, {
    signal: expect.any(AbortSignal),
  });
  expect(screen.getByLabelText("Accepted release result")).toHaveTextContent(
    JSON.parse(f.rawJson).state,
  );
  expect(api.collectReleaseCadence).not.toHaveBeenCalled();
});
test.each([
  ["Interval days", "0"],
  ["Interval days", "3661"],
  ["Tolerance days", "-1"],
  ["Tolerance days", "3661"],
  ["Window end (UTC)", "1990-01-01T00:00:00Z"],
])("invalid %s=%s has no API call", async (label, value) => {
  const verify = vi.fn().mockResolvedValue(true);
  render(<ReleaseSeriesAction freshAuth verifyAuth={verify} />);
  fill();
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByText("Release operation unavailable");
  expect(api.releaseSeries).not.toHaveBeenCalled();
  expect(verify).not.toHaveBeenCalled();
});
test("deferred successful auth preserves one offline evaluation", async () => {
  const f = fixture();
  vi.mocked(api.releaseSeries).mockResolvedValue({
    rawJson: f.rawJson,
    result: JSON.parse(f.rawJson),
  });
  let release!: (v: boolean) => void;
  render(
    <ReleaseSeriesAction
      freshAuth
      verifyAuth={() => new Promise((done) => (release = done))}
    />,
  );
  fill();
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  expect(api.releaseSeries).not.toHaveBeenCalled();
  await act(async () => release(true));
  await screen.findByLabelText("Accepted release result");
  expect(api.releaseSeries).toHaveBeenCalledOnce();
});
test("download preserves exact complete series bytes", async () => {
  const f = fixture();
  vi.mocked(api.releaseSeries).mockResolvedValue({
    rawJson: f.rawJson,
    result: JSON.parse(f.rawJson),
  });
  const blobs: Blob[] = [];
  vi.stubGlobal(
    "URL",
    Object.assign(class extends URL {}, {
      createObjectURL: (blob: Blob) => {
        blobs.push(blob);
        return "blob:synthetic-series";
      },
      revokeObjectURL: vi.fn(),
    }),
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  render(<ReleaseSeriesAction freshAuth verifyAuth={async () => true} />);
  fill();
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByLabelText("Accepted release result");
  fireEvent.click(
    screen.getByRole("button", { name: "Download complete release JSON" }),
  );
  const text = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsText(blobs[0]);
  });
  expect(text).toBe(f.rawJson);
  expect(URL.revokeObjectURL).toHaveBeenCalledOnce();
});
test("duplicate evaluation remains single-use", async () => {
  const f = fixture();
  let resolve!: (x: Awaited<ReturnType<typeof api.releaseSeries>>) => void;
  vi.mocked(api.releaseSeries).mockImplementation(
    () => new Promise((done) => (resolve = done)),
  );
  render(<ReleaseSeriesAction freshAuth verifyAuth={async () => true} />);
  fill();
  const button = screen.getByRole("button", {
    name: "Evaluate release spacing",
  });
  fireEvent.click(button);
  fireEvent.click(button);
  await waitFor(() => expect(api.releaseSeries).toHaveBeenCalledOnce());
  await act(async () =>
    resolve({ rawJson: f.rawJson, result: JSON.parse(f.rawJson) }),
  );
  await screen.findByLabelText("Accepted release result");
});
