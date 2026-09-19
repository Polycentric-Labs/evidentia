import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api } from "@/lib/api";
import { scapDemoResponse, scapDemoSource } from "@/lib/demo/scap-fixtures";
import { ScapCollectAction } from "./ScapCollectAction";

vi.mock("@/lib/demo", () => ({ IS_DEMO: true }));
vi.mock("@/lib/api", () => ({ api: { collectScap: vi.fn() } }));
beforeEach(async () => {
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  );
});
afterEach(() => {
  vi.doUnmock("@/lib/demo/scap-fixtures");
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});
async function load(id: string) {
  render(<ScapCollectAction freshAuth verifyAuth={async () => true} />);
  fireEvent.change(screen.getByLabelText("Synthetic SCAP example"), {
    target: { value: id },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Load synthetic example" }),
  );
  await screen.findByText(/^Loaded synthetic bytes: /);
  const source = scapDemoSource(id),
    response = await scapDemoResponse(source.raw, source.request, id);
  vi.mocked(api.collectScap).mockResolvedValue(response);
  expect(api.collectScap).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Collect SCAP" }));
  await screen.findByRole("region", { name: "SCAP collection result" });
  return response;
}
test("all 21 real outcomes are paginated and source markup stays inert", async () => {
  await load("xccdf-21-rows");
  const outcomes = screen.getByRole("region", { name: "Native SCAP outcomes" });
  expect(within(outcomes).getAllByRole("row")).toHaveLength(21);
  fireEvent.click(screen.getByRole("button", { name: "Next outcomes" }));
  expect(within(outcomes).getAllByRole("row")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Next outcomes" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Previous outcomes" }));
  expect(within(outcomes).getAllByRole("row")).toHaveLength(21);
  expect(
    screen.getByText(/<img src=x onerror=alert\(1\)>/, { exact: false }),
  ).toBeInTheDocument();
  expect(
    document.querySelector(
      "img, iframe, script[src], a[href='https://example.invalid/inert']",
    ),
  ).toBeNull();
});
test.each(["xccdf-qualified", "oval-5.8-undated"])(
  "%s downloads exact full wire and only a non-null artifact",
  async (id) => {
    const response = await load(id),
      blobs: Blob[] = [],
      names: string[] = [];
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn((blob: Blob) => {
        blobs.push(blob);
        return "blob:synthetic";
      }),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      names.push(this.download);
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Download full SCAP result" }),
    );
    const read = (blob: Blob) =>
      new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = reject;
        reader.readAsText(blob);
      });
    expect(await read(blobs[0])).toBe(response.rawJson);
    expect(names).toEqual(["scap-result.json"]);
    const artifact = screen.getByRole("button", {
      name: "Download evidence artifact",
    });
    if (response.artifactRawJson === null) {
      expect(artifact).toBeDisabled();
      fireEvent.click(artifact);
      expect(blobs).toHaveLength(1);
    } else {
      expect(artifact).toBeEnabled();
      fireEvent.click(artifact);
      expect(await read(blobs[1])).toBe(response.artifactRawJson);
      expect(names[1]).toBe("scap-evidence.json");
    }
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(blobs.length);
    expect(api.collectScap).toHaveBeenCalledOnce();
  },
);
test("OVAL exposes compilation roles and authenticated operator provenance separately", async () => {
  await load("oval-5.12.3-asserted");
  expect(
    screen.getByText(/api_authenticated/, { exact: false }),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/synthetic-auth/, { exact: false }),
  ).toBeInTheDocument();
  const times = screen.getByRole("region", { name: "SCAP time roles" });
  expect(
    within(times).getAllByText(/document_compilation/, { exact: false }).length,
  ).toBeGreaterThan(0);
  expect(screen.getByText("Import observation time")).toBeInTheDocument();
});

test("a second assessment remains an explicit occurrence with the first unselected", async () => {
  const response = await load("xccdf-second-unit");
  expect(response.result.assessment.selection.assessment_index).toBe(1);
  expect(response.result.assessment.coverage.visible_unit_count).toBe(2);
  expect(response.result.assessment.coverage.unselected_unit_count).toBe(1);
  expect(screen.getByLabelText("Assessment index (zero-based)")).toHaveValue(
    "1",
  );
  expect(vi.mocked(api.collectScap).mock.calls[0][1].assessment_index).toBe(1);
});

async function deferFixtureAsset() {
  const actual = await vi.importActual<
    typeof import("@/lib/demo/scap-fixtures")
  >("@/lib/demo/scap-fixtures");
  const source = vi.fn(actual.scapDemoSource);
  const module = { ...actual, scapDemoSource: source };
  let release!: (value: typeof module) => void;
  const promise = new Promise<typeof module>((resolve) => {
    release = resolve;
  });
  const factory = vi.fn(() => promise);
  vi.doMock("@/lib/demo/scap-fixtures", factory);
  return { source, factory, finish: () => release(module) };
}
const loadExample = () =>
  fireEvent.click(
    screen.getByRole("button", { name: /Load(?:ing)? synthetic example/ }),
  );

test("a changed selection cancels an older asset load and only the newest selection is applied", async () => {
  const delayed = await deferFixtureAsset();
  render(<ScapCollectAction freshAuth verifyAuth={async () => true} />);
  loadExample();
  await waitFor(() => expect(delayed.factory).toHaveBeenCalledOnce());
  fireEvent.change(screen.getByLabelText("Synthetic SCAP example"), {
    target: { value: "oval-5.12.3-asserted" },
  });
  loadExample();
  await act(async () => {
    delayed.finish();
  });
  await screen.findByText(/^Loaded synthetic bytes: /);
  expect(delayed.source).toHaveBeenCalledOnce();
  expect(delayed.source).toHaveBeenCalledWith("oval-5.12.3-asserted");
  expect(screen.getByLabelText("SCAP source profile")).toHaveValue(
    "oval-5.12.3-core-results",
  );
  expect(api.collectScap).not.toHaveBeenCalled();
});

test("an asset completing after unmount does not read its source or collect", async () => {
  const delayed = await deferFixtureAsset();
  const view = render(
    <ScapCollectAction freshAuth verifyAuth={async () => true} />,
  );
  loadExample();
  await waitFor(() => expect(delayed.factory).toHaveBeenCalledOnce());
  view.unmount();
  await act(async () => {
    delayed.finish();
  });
  expect(delayed.source).not.toHaveBeenCalled();
  expect(api.collectScap).not.toHaveBeenCalled();
});

test("known authentication invalidation cancels a pending example load", async () => {
  const delayed = await deferFixtureAsset();
  const auth = vi.fn().mockResolvedValue(true);
  const view = render(
    <ScapCollectAction freshAuth authInvalidated={false} verifyAuth={auth} />,
  );
  loadExample();
  await waitFor(() => expect(delayed.factory).toHaveBeenCalledOnce());
  view.rerender(
    <ScapCollectAction freshAuth={false} authInvalidated verifyAuth={auth} />,
  );
  await act(async () => {
    delayed.finish();
  });
  expect(delayed.source).not.toHaveBeenCalled();
  expect(
    screen.queryByText(/^Loaded synthetic bytes: /),
  ).not.toBeInTheDocument();
  expect(auth).not.toHaveBeenCalled();
  expect(api.collectScap).not.toHaveBeenCalled();
});

test("a failed example asset preserves the last accepted result and exposes a fixed message", async () => {
  await load("xccdf-qualified");
  const previous = screen.getByRole("region", {
    name: "SCAP collection result",
  }).textContent;
  vi.doMock("@/lib/demo/scap-fixtures", () => {
    throw new Error("Synthetic asset-load failure");
  });
  loadExample();
  await screen.findByText(
    "The synthetic SCAP example could not load. Try again.",
  );
  expect(
    screen.getByRole("region", { name: "SCAP collection result" }).textContent,
  ).toBe(previous);
  expect(
    screen.queryByText("Synthetic asset-load failure"),
  ).not.toBeInTheDocument();
  expect(api.collectScap).toHaveBeenCalledOnce();
});
