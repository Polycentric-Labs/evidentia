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
const entry = RELEASE_DEMO_FIXTURES.find((row) => row.id === "series-two")!;
const response = () => ({
  rawJson: entry.rawJson,
  result: JSON.parse(entry.rawJson),
});
function fill() {
  for (const [label, value] of Object.entries({
    "GitHub owner": "Example",
    "GitHub repository": "Synthetic",
    "Release channel": "all_published",
    "Window start (UTC)": "1999-12-31T00:00:00.000000Z",
    "Window end (UTC)": "2000-01-03T00:00:00.000000Z",
  }))
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
}
beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
  vi.mocked(api.releaseSeries).mockReset();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
test.each(["input", "cancel", "unmount", "auth"])(
  "late series after %s cannot become current",
  async (mode) => {
    let resolve!: (v: ReturnType<typeof response>) => void;
    vi.mocked(api.releaseSeries).mockImplementation(
      () => new Promise((done) => (resolve = done)),
    );
    const view = render(
      <ReleaseSeriesAction
        freshAuth
        authInvalidated={false}
        verifyAuth={async () => true}
      />,
    );
    fill();
    fireEvent.click(
      screen.getByRole("button", { name: "Evaluate release spacing" }),
    );
    await waitFor(() => expect(api.releaseSeries).toHaveBeenCalledOnce());
    const signal = vi.mocked(api.releaseSeries).mock.calls[0][1]!.signal!;
    if (mode === "input")
      fireEvent.change(screen.getByLabelText("Interval days"), {
        target: { value: "2" },
      });
    if (mode === "cancel")
      fireEvent.click(
        screen.getByRole("button", { name: "Cancel release operation" }),
      );
    if (mode === "unmount") view.unmount();
    if (mode === "auth")
      view.rerender(
        <ReleaseSeriesAction
          freshAuth={false}
          authInvalidated
          verifyAuth={async () => true}
        />,
      );
    expect(signal.aborted).toBe(true);
    await act(async () => resolve(response()));
    expect(screen.queryByLabelText("Accepted release result")).toBeNull();
  },
);
test.each([false, "throw"])(
  "auth %s forbids offline store request",
  async (mode) => {
    render(
      <ReleaseSeriesAction
        freshAuth
        verifyAuth={async () => {
          if (mode === "throw") throw new Error("Synthetic auth detail");
          return false;
        }}
      />,
    );
    fill();
    fireEvent.click(
      screen.getByRole("button", { name: "Evaluate release spacing" }),
    );
    await screen.findByText("Release operation unavailable");
    expect(api.releaseSeries).not.toHaveBeenCalled();
  },
);
test("stale authentication disables offline evaluation", () => {
  render(
    <ReleaseSeriesAction freshAuth={false} verifyAuth={async () => true} />,
  );
  expect(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  ).toBeDisabled();
});
test("series independently rejects forged adapter raw result", async () => {
  vi.mocked(api.releaseSeries).mockResolvedValue({
    ...response(),
    rawJson: "{}",
  });
  render(<ReleaseSeriesAction freshAuth verifyAuth={async () => true} />);
  fill();
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByText("Release operation unavailable");
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
});
test("failed later evaluation does not rewrite last accepted source or window", async () => {
  vi.mocked(api.releaseSeries).mockResolvedValue(response());
  render(<ReleaseSeriesAction freshAuth verifyAuth={async () => true} />);
  fill();
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByLabelText("Accepted release result");
  vi.mocked(api.releaseSeries).mockRejectedValue(
    new Error("Synthetic server text"),
  );
  fireEvent.change(screen.getByLabelText("Interval days"), {
    target: { value: "2" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Evaluate release spacing" }),
  );
  await screen.findByText("Release operation unavailable");
  expect(screen.getByLabelText("Accepted release result")).toHaveTextContent(
    "Interval 1 days plus tolerance 0 days",
  );
  expect(screen.queryByText("Synthetic server text")).toBeNull();
});
