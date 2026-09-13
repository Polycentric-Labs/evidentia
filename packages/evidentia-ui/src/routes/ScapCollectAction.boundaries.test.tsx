import {
  cleanup,
  fireEvent,
  render,
  screen,
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
