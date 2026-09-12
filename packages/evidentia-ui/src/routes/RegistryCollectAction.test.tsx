import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { api } from "@/lib/api";
import {
  registryDemoCases,
  registryDemoResponse,
} from "@/lib/demo/registry-fixtures";
import { RegistryCollectAction } from "./RegistryCollectAction";

vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
vi.mock("@/lib/api", () => ({ api: { collectRegistry: vi.fn() } }));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function fillTls() {
  const sample = registryDemoCases("tls")[0];
  fireEvent.change(screen.getByLabelText("Hostname"), {
    target: {
      value:
        "hostname" in sample.request.target
          ? sample.request.target.hostname
          : "",
    },
  });
  fireEvent.change(screen.getByLabelText("Scope label (optional)"), {
    target: { value: sample.request.scope_label },
  });
  return registryDemoResponse(sample.request, sample.name);
}

test("revalidates authentication immediately before sending the exact finite request", async () => {
  const order: string[] = [];
  const verify = vi.fn(async () => {
    order.push("auth");
    return true;
  });
  render(<RegistryCollectAction freshAuth verifyAuth={verify} />);
  const response = fillTls();
  vi.mocked(api.collectRegistry).mockImplementation(async () => {
    order.push("post");
    return response;
  });
  fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
  expect(
    await screen.findByRole("region", { name: "Registry result" }),
  ).toBeInTheDocument();
  expect(order).toEqual(["auth", "post"]);
  expect(api.collectRegistry).toHaveBeenCalledWith(response.result.request, "");
  expect(screen.getByText("Lookup outcome")).toBeInTheDocument();
  expect(screen.getByText("Traversal status")).toBeInTheDocument();
  expect(screen.getByText("Source dates")).toBeInTheDocument();
});

test("false authentication and invalid inputs never call the collector", async () => {
  const verify = vi.fn().mockResolvedValue(false);
  render(<RegistryCollectAction freshAuth verifyAuth={verify} />);
  expect(
    screen.getByRole("button", { name: "Collect registry" }),
  ).toBeDisabled();
  fillTls();
  fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
  expect(
    await screen.findByText(
      "API read authentication is required before collection.",
    ),
  ).toBeInTheDocument();
  expect(api.collectRegistry).not.toHaveBeenCalled();
});

test("SSL Labs selection causes zero auth and collection calls", () => {
  const verify = vi.fn();
  render(<RegistryCollectAction freshAuth verifyAuth={verify} />);
  fireEvent.change(screen.getByLabelText("Registry"), {
    target: { value: "ssl-labs" },
  });
  fireEvent.change(screen.getByLabelText("Hostname"), {
    target: { value: "example.org" },
  });
  fireEvent.change(screen.getByLabelText("Endpoint IP"), {
    target: { value: "93.184.216.34" },
  });
  expect(
    screen.getByText("SSL Labs live collection is disabled"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
  expect(verify).not.toHaveBeenCalled();
  expect(api.collectRegistry).not.toHaveBeenCalled();
});

test.each([false, true])(
  "input changes discard stale authentication completion (reject=%s)",
  async (reject) => {
    let resolve!: (value: boolean) => void;
    let refuse!: (reason: Error) => void;
    const verify = vi.fn(
      () =>
        new Promise<boolean>((yes, no) => {
          resolve = yes;
          refuse = no;
        }),
    );
    render(<RegistryCollectAction freshAuth verifyAuth={verify} />);
    fillTls();
    fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
    fireEvent.change(screen.getByLabelText("Registry"), {
      target: { value: "rdap" },
    });
    await act(async () => {
      if (reject) refuse(new Error("Stale auth detail"));
      else resolve(true);
    });
    expect(api.collectRegistry).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(
      screen.queryByRole("region", { name: "Registry result" }),
    ).toBeNull();
  },
);

test.each([false, true])(
  "input changes discard stale collector completion (reject=%s)",
  async (reject) => {
    let resolve!: (value: ReturnType<typeof registryDemoResponse>) => void;
    let refuse!: (reason: Error) => void;
    vi.mocked(api.collectRegistry).mockImplementation(
      () =>
        new Promise((yes, no) => {
          resolve = yes;
          refuse = no;
        }),
    );
    render(<RegistryCollectAction freshAuth verifyAuth={async () => true} />);
    const response = fillTls();
    fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
    await waitFor(() => expect(api.collectRegistry).toHaveBeenCalledOnce());
    fireEvent.change(screen.getByLabelText("Scope label (optional)"), {
      target: { value: "Changed scope" },
    });
    await act(async () => {
      if (reject) refuse(new Error("Stale provider detail"));
      else resolve(response);
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(
      screen.queryByRole("region", { name: "Registry result" }),
    ).toBeNull();
  },
);

test("download retains the complete original response bytes", async () => {
  let blob: Blob | null = null;
  vi.stubGlobal(
    "URL",
    class extends URL {
      static createObjectURL(value: Blob) {
        blob = value;
        return "blob:synthetic-registry";
      }
      static revokeObjectURL = vi.fn();
    },
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  render(<RegistryCollectAction freshAuth verifyAuth={async () => true} />);
  const response = fillTls();
  vi.mocked(api.collectRegistry).mockResolvedValue(response);
  fireEvent.click(screen.getByRole("button", { name: "Collect registry" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Download full registry JSON" }),
  );
  expect(blob).not.toBeNull();
  expect(await (blob as unknown as Blob).text()).toBe(response.rawJson);
  vi.unstubAllGlobals();
});
