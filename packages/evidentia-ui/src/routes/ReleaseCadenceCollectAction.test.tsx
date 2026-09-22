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
import { ReleaseCadenceCollectAction } from "./ReleaseCadenceCollectAction";
vi.mock("@/lib/api", () => ({
  api: { collectReleaseCadence: vi.fn(), releaseSeries: vi.fn() },
}));
vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
const observed = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-observed")!,
  saved = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-persist")!;
const response = (
  entry: (typeof RELEASE_DEMO_FIXTURES)[number] = observed,
) => ({ rawJson: entry.rawJson, result: JSON.parse(entry.rawJson) });
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
  vi.mocked(api.collectReleaseCadence)
    .mockReset()
    .mockResolvedValue(response());
  vi.mocked(api.releaseSeries).mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
test("default observation requires explicit action and shows inert native source", async () => {
  const verify = vi.fn().mockResolvedValue(true);
  const { container } = render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={verify} />,
  );
  fill();
  expect(
    screen.getByLabelText("Save release evidence locally"),
  ).not.toBeChecked();
  expect(api.collectReleaseCadence).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  expect(verify).toHaveBeenCalledOnce();
  expect(api.collectReleaseCadence).toHaveBeenCalledWith(observed.request, {
    signal: expect.any(AbortSignal),
  });
  expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
  expect(api.releaseSeries).not.toHaveBeenCalled();
});
test("persistence requires an explicit checkbox and preserves verified outcome", async () => {
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(response(saved));
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByLabelText("Save release evidence locally"));
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  expect(vi.mocked(api.collectReleaseCadence).mock.calls[0][0].persist).toBe(
    true,
  );
  expect(screen.getByText(/1 calls; 1 created/)).toBeInTheDocument();
});
test("immediate invalid input performs no auth refresh or API operation", async () => {
  const verify = vi.fn();
  render(<ReleaseCadenceCollectAction freshAuth verifyAuth={verify} />);
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText("Release operation unavailable");
  expect(verify).not.toHaveBeenCalled();
  expect(api.collectReleaseCadence).not.toHaveBeenCalled();
});
test("deferred successful auth sends exactly one captured request", async () => {
  let resolve!: (x: boolean) => void;
  const verify = vi.fn(() => new Promise<boolean>((done) => (resolve = done)));
  render(<ReleaseCadenceCollectAction freshAuth verifyAuth={verify} />);
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  expect(api.collectReleaseCadence).not.toHaveBeenCalled();
  await act(async () => resolve(true));
  await screen.findByLabelText("Accepted release result");
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});
test.each([false, "throw"])(
  "auth refusal %s does not contact provider",
  async (mode) => {
    render(
      <ReleaseCadenceCollectAction
        freshAuth
        verifyAuth={async () => {
          if (mode === "throw") throw new Error("Synthetic auth detail");
          return false;
        }}
      />,
    );
    fill();
    fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
    await screen.findByText("Release operation unavailable");
    expect(api.collectReleaseCadence).not.toHaveBeenCalled();
    expect(screen.queryByText("Synthetic auth detail")).toBeNull();
  },
);
test("duplicate submit cannot create duplicate provider or save operations", async () => {
  let resolve!: (x: ReturnType<typeof response>) => void;
  vi.mocked(api.collectReleaseCadence).mockImplementation(
    () => new Promise((done) => (resolve = done)),
  );
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  const button = screen.getByRole("button", { name: "Observe releases" });
  fireEvent.click(button);
  fireEvent.click(button);
  await waitFor(() => expect(api.collectReleaseCadence).toHaveBeenCalledOnce());
  await act(async () => resolve(response()));
  await screen.findByLabelText("Accepted release result");
});
test("last good result survives a failed replacement and retains captured request", async () => {
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  vi.mocked(api.collectReleaseCadence).mockRejectedValue(
    new Error("Synthetic unsafe detail"),
  );
  fireEvent.change(screen.getByLabelText("GitHub repository"), {
    target: { value: "Changed" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByText("Release operation unavailable");
  expect(screen.getByLabelText("Accepted release result")).toHaveTextContent(
    "Example/Synthetic",
  );
  expect(screen.queryByText("Synthetic unsafe detail")).toBeNull();
});
test("full JSON download contains exact accepted bytes and revokes its URL", async () => {
  const blobs: Blob[] = [];
  const created = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return "blob:synthetic-release";
    }),
    revoked = vi.fn();
  vi.stubGlobal(
    "URL",
    Object.assign(class extends URL {}, {
      createObjectURL: created,
      revokeObjectURL: revoked,
    }),
  );
  const click = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(() => {});
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  expect(created).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole("button", { name: "Download complete release JSON" }),
  );
  const text = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsText(blobs[0]);
  });
  expect(text).toBe(observed.rawJson);
  expect(click).toHaveBeenCalledOnce();
  expect(revoked).toHaveBeenCalledWith("blob:synthetic-release");
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});

test("twenty-one source rows and event families render one bounded page at a time", async () => {
  const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === "poll-many")!;
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(response(entry));
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.change(screen.getByLabelText("GitHub repository"), {
    target: { value: entry.request.repository },
  });
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  await screen.findByLabelText("Accepted release result");
  expect(screen.getByText("Synthetic 19")).toBeInTheDocument();
  expect(screen.queryByText("Synthetic 20")).toBeNull();
  expect(
    screen.getByLabelText("Observed event families").children,
  ).toHaveLength(20);
  fireEvent.click(screen.getByRole("button", { name: "Next releases" }));
  expect(screen.getByText("Synthetic 20")).toBeInTheDocument();
  expect(screen.queryByText("Synthetic 19")).toBeNull();
  expect(screen.getByRole("button", { name: "Next releases" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Next event families" }));
  expect(
    screen.getByLabelText("Observed event families").children,
  ).toHaveLength(1);
  expect(screen.getByLabelText("Observed event families")).toHaveTextContent(
    "Release 220",
  );
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});
test.each([
  "poll-partial",
  "poll-unavailable",
  "poll-save-failed",
  "poll-indeterminate",
  "poll-readback-conflict",
  "poll-not-applicable",
  "poll-repeat",
])("%s shows source and local persistence as separate facts", async (id) => {
  const entry = RELEASE_DEMO_FIXTURES.find((x) => x.id === id)!;
  const result = JSON.parse(entry.rawJson);
  vi.mocked(api.collectReleaseCadence).mockResolvedValue(response(entry));
  render(
    <ReleaseCadenceCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  fireEvent.change(screen.getByLabelText("GitHub repository"), {
    target: { value: entry.request.repository },
  });
  if ("persist" in entry.request && entry.request.persist)
    fireEvent.click(screen.getByLabelText("Save release evidence locally"));
  fireEvent.click(screen.getByRole("button", { name: "Observe releases" }));
  const accepted = await screen.findByLabelText("Accepted release result");
  expect(accepted).toHaveTextContent(result.collection_state);
  expect(accepted).toHaveTextContent(result.persistence.state);
  expect(accepted).toHaveTextContent(result.discovery.status);
  for (const outcome of result.outcomes)
    expect(accepted).toHaveTextContent(outcome.outcome);
  expect(api.collectReleaseCadence).toHaveBeenCalledOnce();
});
