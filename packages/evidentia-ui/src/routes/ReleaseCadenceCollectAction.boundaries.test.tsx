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
import { ReleaseResponseError } from "@/lib/release-cadence";
import { ReleaseCadenceCollectAction } from "./ReleaseCadenceCollectAction";
vi.mock("@/lib/api", () => ({
  api: { collectReleaseCadence: vi.fn(), releaseSeries: vi.fn() },
}));
vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-observed")!;
const response = () => ({
  rawJson: entry.rawJson,
  result: JSON.parse(entry.rawJson),
});
function fill() {
  fireEvent.change(screen.getByLabelText("GitHub owner"), {
    target: { value: "Example" },
  });
  fireEvent.change(screen.getByLabelText("GitHub repository"), {
    target: { value: "Synthetic" },
  });
}
beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
  vi.mocked(api.collectReleaseCadence).mockReset();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
test.each(["input", "unmount", "cancel", "auth"])(
  "late response after %s cannot publish",
  async (mode) => {
    let resolve!: (x: ReturnType<typeof response>) => void;
    vi.mocked(api.collectReleaseCadence).mockImplementation(
      () => new Promise((done) => (resolve = done)),
    );
    const view = render(
      <ReleaseCadenceCollectAction
        freshAuth
        authInvalidated={false}
        verifyAuth={async () => true}
      />,
    );
    fill();
    fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
    await waitFor(() =>
      expect(api.collectReleaseCadence).toHaveBeenCalledOnce(),
    );
    const signal = vi.mocked(api.collectReleaseCadence).mock.calls[0][1]!
      .signal!;
    if (mode === "input")
      fireEvent.change(screen.getByLabelText("GitHub repository"), {
        target: { value: "Changed" },
      });
    if (mode === "unmount") view.unmount();
    if (mode === "cancel")
      fireEvent.click(
        screen.getByRole("button", { name: "Cancel release operation" }),
      );
    if (mode === "auth")
      view.rerender(
        <ReleaseCadenceCollectAction
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
test.each(["input", "unmount", "auth"])(
  "deferred authentication loses ownership on %s before POST",
  async (mode) => {
    let resolve!: (x: boolean) => void;
    const view = render(
      <ReleaseCadenceCollectAction
        freshAuth
        authInvalidated={false}
        verifyAuth={() => new Promise((done) => (resolve = done))}
      />,
    );
    fill();
    fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
    if (mode === "input")
      fireEvent.change(screen.getByLabelText("GitHub owner"), {
        target: { value: "Other" },
      });
    if (mode === "unmount") view.unmount();
    if (mode === "auth")
      view.rerender(
        <ReleaseCadenceCollectAction
          freshAuth={false}
          authInvalidated
          verifyAuth={async () => true}
        />,
      );
    await act(async () => resolve(true));
    expect(api.collectReleaseCadence).not.toHaveBeenCalled();
  },
);
test("stale authentication disables action", () => {
  render(
    <ReleaseCadenceCollectAction
      freshAuth={false}
      verifyAuth={async () => true}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Observe releases" }),
  ).toBeDisabled();
});
test("adapter rawJson getter is refused without invocation", async () => {
  const getter = vi.fn(() => entry.rawJson);
  const forged = Object.defineProperty({}, "rawJson", { get: getter });
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(
    forged as Awaited<ReturnType<typeof api.collectReleaseCadence>>,
  );
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText("Release operation unavailable");
  expect(getter).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
});
test("component revalidates raw bytes instead of trusting adapter result", async () => {
  vi.mocked(api.collectReleaseCadence).mockResolvedValue({
    ...response(),
    rawJson: "{}",
  });
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText("Release operation unavailable");
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
});
test("post-save expiry displays explicit uncertainty and never retries", async () => {
  const message =
    "The release deadline expired after a save was attempted. Persistence may have occurred. Inspect local records before retrying.";
  vi.mocked(api.collectReleaseCadence).mockRejectedValue(
    new ReleaseResponseError(message, "persistence_outcome_unavailable", 500),
  );
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByLabelText("Save release evidence locally"));
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText(message);
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
});

test("forged error-class prose is not displayed as trusted failure text", async () => {
  vi.mocked(api.collectReleaseCadence).mockRejectedValue(
    new ReleaseResponseError("Synthetic source-bearing detail"),
  );
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText("Release operation unavailable");
  expect(screen.queryByText("Synthetic source-bearing detail")).toBeNull();
});

test("authentication ownership loss removes the previous result permanently", async () => {
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(response());
  const verify = async () => true;
  const view = render(
    <ReleaseCadenceCollectAction
      freshAuth
      authInvalidated={false}
      verifyAuth={verify}
    />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  view.rerender(
    <ReleaseCadenceCollectAction
      freshAuth={false}
      authInvalidated
      verifyAuth={verify}
    />,
  );
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
  view.rerender(
    <ReleaseCadenceCollectAction
      freshAuth
      authInvalidated={false}
      verifyAuth={verify}
    />,
  );
  expect(screen.queryByLabelText("Accepted release result")).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Download complete release JSON" }),
  ).toBeNull();
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});
test("transient health refresh preserves the owned pending operation", async () => {
  let done!: (value: boolean) => void;
  const verify = () =>
    new Promise<boolean>((resolve) => {
      done = resolve;
    });
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(response());
  const view = render(
    <ReleaseCadenceCollectAction
      freshAuth
      authInvalidated={false}
      verifyAuth={verify}
    />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  view.rerender(
    <ReleaseCadenceCollectAction
      freshAuth={false}
      authInvalidated={false}
      verifyAuth={verify}
    />,
  );
  await act(async () => done(true));
  await screen.findByLabelText("Accepted release result");
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});
