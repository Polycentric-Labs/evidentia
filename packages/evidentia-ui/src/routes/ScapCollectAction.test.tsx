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
import { scapDemoResponse, scapDemoSource } from "@/lib/demo/scap-fixtures";
import type { ScapResponse } from "@/lib/scap";
import { ScapCollectAction } from "./ScapCollectAction";

vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
vi.mock("@/lib/api", () => ({
  api: { collectScap: vi.fn(), saveEvidence: vi.fn() },
}));
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
function file(raw: ArrayBuffer, name = "synthetic.xml") {
  const result = new File([raw], name, { type: "application/xml" });
  Object.defineProperty(result, "arrayBuffer", {
    value: async () => raw.slice(0),
  });
  return result;
}
function select(id = "xccdf-qualified") {
  const selected = scapDemoSource(id);
  fireEvent.change(screen.getByLabelText("SCAP source profile"), {
    target: { value: selected.request.source_profile },
  });
  fireEvent.change(screen.getByLabelText("Local SCAP XML file"), {
    target: { files: [file(selected.raw)] },
  });
  if (selected.request.completion_assertion) {
    fireEvent.click(
      screen.getByLabelText("Use an OVAL completion assertion sidecar"),
    );
    const claim = new TextEncoder().encode(
      JSON.stringify(selected.request.completion_assertion),
    );
    fireEvent.change(
      screen.getByLabelText("Local OVAL assertion JSON (at most 2 KiB)"),
      { target: { files: [file(claim.buffer, "synthetic-assertion.json")] } },
    );
  }
  return selected;
}
const submit = () => screen.getByRole("button", { name: "Collect SCAP" });
test.each([
  "xccdf-qualified",
  "oval-5.8-undated",
  "oval-5.8-asserted",
  "oval-5.11.2-asserted",
  "oval-5.12.3-undated",
])(
  "%s has explicit file selection and fresh authorization before exact collection",
  async (id) => {
    const order: string[] = [];
    render(
      <ScapCollectAction
        freshAuth
        verifyAuth={async () => {
          order.push("auth");
          return true;
        }}
      />,
    );
    const selected = select(id),
      response = await scapDemoResponse(selected.raw, selected.request, id);
    vi.mocked(api.collectScap).mockImplementation(async () => {
      order.push("post");
      return response;
    });
    expect(api.collectScap).not.toHaveBeenCalled();
    fireEvent.click(submit());
    await screen.findByRole("region", { name: "SCAP collection result" });
    expect(order).toEqual(["auth", "post"]);
    expect(api.collectScap).toHaveBeenCalledOnce();
    const [raw, request, scenario] = vi.mocked(api.collectScap).mock.calls[0];
    expect(new Uint8Array(raw)).toEqual(new Uint8Array(selected.raw));
    expect(request).toEqual(selected.request);
    expect(scenario).toBe("");
    expect(
      screen.getByText("Completion and actor provenance"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Selected and unselected scope"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Nothing has been saved to the evidence store.", {
        exact: false,
      }),
    ).toBeInTheDocument();
  },
);
test("absent authentication, missing file and invalid index cause zero collection calls", async () => {
  const auth = vi.fn().mockResolvedValue(true),
    view = render(<ScapCollectAction freshAuth={false} verifyAuth={auth} />);
  expect(submit()).toBeDisabled();
  view.rerender(<ScapCollectAction freshAuth verifyAuth={auth} />);
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(auth).not.toHaveBeenCalled();
  select();
  fireEvent.change(screen.getByLabelText("Assessment index (zero-based)"), {
    target: { value: "01" },
  });
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(api.collectScap).not.toHaveBeenCalled();
  expect(auth).not.toHaveBeenCalled();
});
test("failed authentication refresh prevents POST after local preparation", async () => {
  render(<ScapCollectAction freshAuth verifyAuth={async () => false} />);
  select();
  fireEvent.click(submit());
  await screen.findByText(
    "Current authentication is required to collect SCAP evidence.",
  );
  expect(api.collectScap).not.toHaveBeenCalled();
});
test("the last good result remains after invalid input, HTTP failure and malformed response", async () => {
  render(<ScapCollectAction freshAuth verifyAuth={async () => true} />);
  const source = select();
  const good = await scapDemoResponse(
    source.raw,
    source.request,
    "xccdf-qualified",
  );
  vi.mocked(api.collectScap).mockResolvedValue(good);
  fireEvent.click(submit());
  await screen.findByRole("region", { name: "SCAP collection result" });
  const prior = screen.getByRole("region", {
    name: "SCAP collection result",
  }).textContent;
  fireEvent.change(screen.getByLabelText("Assessment index (zero-based)"), {
    target: { value: "-1" },
  });
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(
    screen.getByRole("region", { name: "SCAP collection result" }).textContent,
  ).toBe(prior);
  fireEvent.change(screen.getByLabelText("Assessment index (zero-based)"), {
    target: { value: "0" },
  });
  vi.mocked(api.collectScap).mockRejectedValue(
    new Error("Synthetic HTTP failure"),
  );
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(
    screen.getByRole("region", { name: "SCAP collection result" }).textContent,
  ).toBe(prior);
  vi.mocked(api.collectScap).mockResolvedValue({
    ...good,
    rawJson: '{"status":"imported"}',
  });
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(
    screen.getByRole("region", { name: "SCAP collection result" }).textContent,
  ).toBe(prior);
  expect(screen.queryByText("Synthetic HTTP failure")).not.toBeInTheDocument();
});
test("changed selection discards an in-flight response without restarting collection", async () => {
  render(<ScapCollectAction freshAuth verifyAuth={async () => true} />);
  const selected = select(),
    good = await scapDemoResponse(
      selected.raw,
      selected.request,
      "xccdf-qualified",
    );
  let finish: (result: ScapResponse) => void = () => {
    throw new Error("No pending response");
  };
  vi.mocked(api.collectScap).mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  fireEvent.click(submit());
  await waitFor(() => expect(api.collectScap).toHaveBeenCalledOnce());
  fireEvent.change(screen.getByLabelText("Assessment index (zero-based)"), {
    target: { value: "1" },
  });
  await act(async () => {
    finish(good);
  });
  await waitFor(() => expect(submit()).toBeEnabled());
  expect(
    screen.queryByRole("region", { name: "SCAP collection result" }),
  ).not.toBeInTheDocument();
  expect(api.collectScap).toHaveBeenCalledOnce();
});
test("changed selection while auth is pending performs no POST", async () => {
  let finish: (value: boolean) => void = () => {
    throw new Error("No pending auth");
  };
  const auth = vi.fn(
    () =>
      new Promise<boolean>((resolve) => {
        finish = resolve;
      }),
  );
  render(<ScapCollectAction freshAuth verifyAuth={auth} />);
  select();
  fireEvent.click(submit());
  await waitFor(() => expect(auth).toHaveBeenCalledOnce());
  fireEvent.change(screen.getByLabelText("Cadence slug (optional)"), {
    target: { value: "changed" },
  });
  await act(async () => {
    finish(true);
  });
  expect(api.collectScap).not.toHaveBeenCalled();
});
test("oversized files and duplicate assertion fields fail locally without auth or POST", async () => {
  const auth = vi.fn().mockResolvedValue(true);
  render(<ScapCollectAction freshAuth verifyAuth={auth} />);
  const large = file(new ArrayBuffer(8_388_609));
  fireEvent.change(screen.getByLabelText("Local SCAP XML file"), {
    target: { files: [large] },
  });
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(auth).not.toHaveBeenCalled();
  select("oval-5.8-undated");
  fireEvent.click(
    screen.getByLabelText("Use an OVAL completion assertion sidecar"),
  );
  fireEvent.change(
    screen.getByLabelText("Local OVAL assertion JSON (at most 2 KiB)"),
    {
      target: {
        files: [file(new TextEncoder().encode('{"x":0,"x":1}').buffer)],
      },
    },
  );
  fireEvent.click(submit());
  await screen.findByText("SCAP collection unavailable");
  expect(auth).not.toHaveBeenCalled();
  expect(api.collectScap).not.toHaveBeenCalled();
});
