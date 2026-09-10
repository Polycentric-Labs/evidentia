import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  ApiError,
  type StorageRetentionCollectRequest,
  type StorageRetentionCollectResult,
} from "@/lib/api";
import {
  STORAGE_RETENTION_EXAMPLES,
  STORAGE_RETENTION_NUMERIC_WIRES,
  storageRetentionDemoResult,
} from "@/lib/demo/storage-retention-fixture";
import {
  parseStorageRetentionResponse,
  snapshotStorageRetentionRequest,
  type StorageRetentionResponse,
} from "@/lib/storage-retention";
import { StorageRetentionTab } from "@/routes/StorageRetentionTab";
import { CollectPage } from "@/routes/CollectPage";

const mode = vi.hoisted(() => ({ demo: false }));
vi.mock("@/lib/demo", () => ({
  get IS_DEMO() {
    return mode.demo;
  },
  IS_DEMO_FDA_INDEX: false,
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, health: vi.fn(), collectStorageRetention: vi.fn() },
  };
});
const collect = vi.mocked(api.collectStorageRetention);
const health = vi.mocked(api.health);
const verify = vi.fn<() => Promise<boolean>>();
const clients: QueryClient[] = [];
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (value: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
function fillS3() {
  fireEvent.change(screen.getByLabelText("Scope label"), {
    target: { value: "synthetic-demo" },
  });
  fireEvent.change(screen.getByLabelText("Bucket 1"), {
    target: { value: "synthetic-archive" },
  });
}
function submit() {
  fireEvent.submit(
    screen.getByRole("form", { name: "Storage retention request" }),
  );
}
function open(freshAuth = true) {
  return render(
    <StorageRetentionTab freshAuth={freshAuth} verifyAuth={verify} />,
  );
}
function requestFor(result: StorageRetentionCollectResult) {
  return snapshotStorageRetentionRequest({
    provider: result.provider,
    scope_label: result.scope_label,
    targets: result.resources.map((item) => item.target),
  });
}
function receiptFor(
  result: StorageRetentionCollectResult,
): StorageRetentionResponse {
  return parseStorageRetentionResponse(
    JSON.stringify(result, null, 2) + "\n",
    requestFor(result),
  );
}
async function fillRequest(request: StorageRetentionCollectRequest) {
  await userEvent.selectOptions(
    screen.getByLabelText("Storage provider"),
    request.provider,
  );
  fireEvent.change(screen.getByLabelText("Scope label"), {
    target: { value: request.scope_label },
  });
  const rows: Record<string, string>[] =
    request.provider === "azure"
      ? request.targets.map((target) => ({
          "Subscription ID": target.subscription_id,
          "Resource group": target.resource_group,
          "Storage account": target.account,
          Container: target.container,
        }))
      : request.provider === "s3"
        ? request.targets.map((target) => ({
            Bucket: target.bucket,
            Region: target.region,
            "Expected owner": target.expected_owner ?? "",
          }))
        : request.targets.map((target) => ({ Bucket: target.bucket }));
  for (const [index, labels] of rows.entries()) {
    if (index)
      await userEvent.click(screen.getByRole("button", { name: "Add target" }));
    for (const [label, value] of Object.entries(labels)) {
      const field = screen.getByLabelText(`${label} ${index + 1}`);
      if (field.tagName === "SELECT")
        await userEvent.selectOptions(field, value);
      else fireEvent.change(field, { target: { value } });
    }
  }
}
async function showResult(result: StorageRetentionCollectResult) {
  collect.mockResolvedValueOnce(receiptFor(result));
  open();
  await fillRequest(requestFor(result));
  submit();
  return screen.findByRole("region", { name: "Storage retention result" });
}
beforeEach(() => {
  mode.demo = false;
  verify.mockReset().mockResolvedValue(true);
  collect
    .mockReset()
    .mockResolvedValue(receiptFor(STORAGE_RETENTION_EXAMPLES.unavailable));
  health.mockReset().mockResolvedValue({
    status: "ok",
    version: "synthetic",
    auth_configured: true,
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("Unexpected network");
    }),
  );
});
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
describe("storage collection form", () => {
  it("is wired as a tab in the current Collect page", async () => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    clients.push(client);
    render(
      <QueryClientProvider client={client}>
        <CollectPage />
      </QueryClientProvider>,
    );
    await userEvent.click(
      screen.getByRole("tab", { name: "Storage retention" }),
    );
    fillS3();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Collect storage configuration" }),
      ).toBeEnabled(),
    );
    submit();
    await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
    expect(health).toHaveBeenCalledTimes(2);
  });
  it("blocks live calls before health is known and before each fresh authentication check", async () => {
    const view = open(false);
    fillS3();
    submit();
    expect(
      screen.getByRole("button", { name: "Collect storage configuration" }),
    ).toBeDisabled();
    expect(verify).not.toHaveBeenCalled();
    expect(collect).not.toHaveBeenCalled();
    view.rerender(<StorageRetentionTab freshAuth verifyAuth={verify} />);
    const pending = deferred<boolean>();
    verify.mockReturnValueOnce(pending.promise);
    submit();
    submit();
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    expect(collect).not.toHaveBeenCalled();
    await act(async () => pending.resolve(false));
    expect(
      await screen.findByText(
        /Current API authentication could not be confirmed/,
      ),
    ).toBeInTheDocument();
    expect(collect).not.toHaveBeenCalled();
  });
  it("does not start collection after unmounting during the authentication check", async () => {
    const pending = deferred<boolean>();
    verify.mockReturnValueOnce(pending.promise);
    const view = open();
    fillS3();
    submit();
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    view.unmount();
    await act(async () => pending.resolve(true));
    expect(collect).not.toHaveBeenCalled();
  });
  it("submits only the selected Azure fields in input order", async () => {
    open();
    await userEvent.selectOptions(
      screen.getByLabelText("Storage provider"),
      "azure",
    );
    fireEvent.change(screen.getByLabelText("Scope label"), {
      target: { value: "Synthetic_Scope" },
    });
    fireEvent.change(screen.getByLabelText("Subscription ID 1"), {
      target: { value: "11111111-ABCD-4333-ABCD-555555555555" },
    });
    fireEvent.change(screen.getByLabelText("Resource group 1"), {
      target: { value: "Synthetic_Group" },
    });
    fireEvent.change(screen.getByLabelText("Storage account 1"), {
      target: { value: "syntheticstore" },
    });
    fireEvent.change(screen.getByLabelText("Container 1"), {
      target: { value: "synthetic-container" },
    });
    submit();
    await waitFor(() =>
      expect(collect).toHaveBeenCalledExactlyOnceWith({
        provider: "azure",
        scope_label: "Synthetic_Scope",
        targets: [
          {
            subscription_id: "11111111-abcd-4333-abcd-555555555555",
            resource_group: "Synthetic_Group",
            account: "syntheticstore",
            container: "synthetic-container",
          },
        ],
      }),
    );
  });
  it("does not expose authentication-check exception text", async () => {
    verify.mockRejectedValueOnce(new Error("PRIVATE_AUTH_MARKER"));
    open();
    fillS3();
    submit();
    expect(
      await screen.findByText(
        /Current API authentication could not be confirmed/,
      ),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("PRIVATE_AUTH_MARKER");
    expect(collect).not.toHaveBeenCalled();
  });
  it("refuses invalid input before authentication or collection", async () => {
    open();
    fillS3();
    fireEvent.change(screen.getByLabelText("Bucket 1"), {
      target: { value: "https://example.com" },
    });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(/bucket/);
    expect(verify).not.toHaveBeenCalled();
    expect(collect).not.toHaveBeenCalled();
  });
  it("clears provider-specific targets and previous results on provider changes and reset", async () => {
    await showResult(structuredClone(STORAGE_RETENTION_EXAMPLES.unavailable));
    await userEvent.selectOptions(
      screen.getByLabelText("Storage provider"),
      "azure",
    );
    expect(
      screen.queryByRole("region", { name: "Storage retention result" }),
    ).toBeNull();
    expect(screen.queryByLabelText("Bucket 1")).toBeNull();
    expect(screen.getByLabelText("Subscription ID 1")).toHaveValue("");
    expect(screen.getByLabelText("Scope label")).toHaveValue("synthetic-demo");
    await userEvent.selectOptions(
      screen.getByLabelText("Storage provider"),
      "gcs",
    );
    expect(screen.getByLabelText("Bucket 1")).toHaveValue("");
    expect(screen.queryByLabelText("Region 1")).toBeNull();
    expect(screen.queryByLabelText("Subscription ID 1")).toBeNull();
    await userEvent.click(
      screen.getByRole("button", { name: "Reset storage form" }),
    );
    expect(screen.getByLabelText("Scope label")).toHaveValue("");
    expect(screen.getByLabelText("Storage provider")).toHaveValue("s3");
    expect(screen.getByLabelText("Bucket 1")).toHaveValue("");
  });
  it("adds/removes bounded targets and rejects duplicates before a request", async () => {
    open();
    fillS3();
    await userEvent.click(screen.getByRole("button", { name: "Add target" }));
    fireEvent.change(screen.getByLabelText("Bucket 2"), {
      target: { value: "synthetic-archive" },
    });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(/duplicate/i);
    expect(collect).not.toHaveBeenCalled();
    await userEvent.click(
      screen.getByRole("button", { name: "Remove target 2" }),
    );
    for (let n = 1; n < 20; n++)
      fireEvent.click(screen.getByRole("button", { name: "Add target" }));
    expect(screen.getByRole("button", { name: "Add target" })).toBeDisabled();
    expect(
      screen.getAllByRole("group", { name: /^Target [0-9]+$/ }),
    ).toHaveLength(20);
  });
  it("keeps fields, reset and submission disabled for the whole request, then recovers", async () => {
    const pending = deferred<StorageRetentionResponse>();
    collect.mockReturnValueOnce(pending.promise);
    open();
    fillS3();
    submit();
    await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText("Storage provider")).toBeDisabled();
    expect(screen.getByLabelText("Bucket 1")).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Reset storage form" }),
    ).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent(
      /Collecting storage configuration/,
    );
    submit();
    expect(collect).toHaveBeenCalledTimes(1);
    await act(async () =>
      pending.resolve(receiptFor(STORAGE_RETENTION_EXAMPLES.unavailable)),
    );
    expect(
      await screen.findByRole("region", { name: "Storage retention result" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Bucket 1")).toBeEnabled();
  });
  it.each([401, 403, 422, 503, 500])(
    "uses fixed safe API error messages for HTTP %s",
    async (status) => {
      collect.mockRejectedValueOnce(
        new ApiError("PRIVATE_ERROR", status, { detail: "PRIVATE_PAYLOAD" }),
      );
      open();
      fillS3();
      submit();
      expect(await screen.findByRole("alert")).toHaveTextContent(
        /required|denied|invalid|unavailable|failed/i,
      );
      expect(document.body.textContent).not.toContain("PRIVATE_");
      expect(
        screen.getByRole("button", { name: "Collect storage configuration" }),
      ).toBeEnabled();
    },
  );
  it("demo uses a detached fixed synthetic partial result without health or fetch", async () => {
    mode.demo = true;
    collect.mockImplementation(async () =>
      receiptFor(storageRetentionDemoResult()),
    );
    open(false);
    expect(screen.getByText(/No cloud account is queried/)).toBeInTheDocument();
    expect(screen.getByLabelText("Storage provider")).toHaveValue("azure");
    expect(screen.getByLabelText("Storage provider")).toBeDisabled();
    await userEvent.click(
      screen.getByRole("button", { name: "Show synthetic storage result" }),
    );
    expect(
      await screen.findByText("Collection incomplete: partial"),
    ).toBeInTheDocument();
    expect(verify).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    const first = storageRetentionDemoResult();
    first.resources.splice(0);
    expect(storageRetentionDemoResult().resources).toHaveLength(1);
  });
});
describe("full storage result rendering", () => {
  it.each(["complete", "partial", "unavailable"] as const)(
    "retains every component and manifest for %s",
    async (status) => {
      const result = structuredClone(STORAGE_RETENTION_EXAMPLES[status]);
      const region = await showResult(result);
      expect(
        within(region).getByText(
          status === "complete"
            ? "Selected configuration reads complete"
            : `Collection incomplete: ${status}`,
        ),
      ).toBeInTheDocument();
      expect(
        within(region).getByText(
          /Object enforcement and recordset completeness were not assessed/,
        ),
      ).toBeInTheDocument();
      for (const component of result.resources[0].components)
        expect(
          within(region).getByRole("heading", { name: component.component_id }),
        ).toBeInTheDocument();
      const details = within(region)
        .getByText("Full result, including manifest and findings")
        .closest("details");
      if (!details) throw new Error("Missing disclosure");
      expect(within(details).queryByRole("code")).toBeNull();
      await userEvent.click(
        within(details).getByText(
          details.querySelector("summary")?.textContent ?? "Missing summary",
        ),
      );
      await waitFor(() =>
        expect(details.textContent).toContain(result.manifest.run_id),
      );
      expect(details.textContent).toContain('"resources"');
      expect(details.textContent).toContain('"diagnostics"');
      expect(details.textContent).toContain('"manifest"');
    },
  );
  it("keeps native quoted seconds, fractional timestamp and false values", async () => {
    const region = await showResult(
      structuredClone(STORAGE_RETENTION_EXAMPLES.complete),
    );
    const details = within(region)
      .getByText("Native configuration fields")
      .closest("details");
    if (!details) throw new Error("Missing fields");
    await userEvent.click(
      within(details).getByText(
        details.querySelector("summary")?.textContent ?? "Missing summary",
      ),
    );
    await waitFor(() =>
      expect(details.textContent).toContain('"retentionPeriod": "00086400"'),
    );
    expect(details.textContent).toContain(
      "2024-01-02T03:04:05.123456789+02:00",
    );
    expect(details.textContent).toContain('"enabled": false');
    expect(details.textContent).not.toContain("1 day");
  });
  it("renders hostile text literally, with no HTML or URL interpretation", async () => {
    const result: StorageRetentionCollectResult = structuredClone(
      STORAGE_RETENTION_EXAMPLES.complete,
    );
    const projected = result.resources[0].components[0].projection;
    if (!projected) throw new Error("Missing projection");
    projected.fields = {
      tag: '<script>window.BAD=1</script><img src=x onerror="BAD=1">',
      link: "javascript:alert(1)",
      blank: "",
      missing: null,
      Years: 7,
    };
    const region = await showResult(result);
    const details = within(region)
      .getByText("Native configuration fields")
      .closest("details");
    if (!details) throw new Error("Missing fields");
    await userEvent.click(
      within(details).getByText(
        details.querySelector("summary")?.textContent ?? "Missing summary",
      ),
    );
    await waitFor(() =>
      expect(details.textContent).toContain("<script>window.BAD=1</script>"),
    );
    expect(region.querySelector("script,img")).toBeNull();
    expect(region.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(details.textContent).toContain('"blank": ""');
    expect(details.textContent).toContain('"missing": null');
    expect(details.textContent).toContain('"Years": 7');
  });
  it.each(["complete", "partial", "unavailable"] as const)(
    "exports the full %s result and revokes its object URL",
    async (status) => {
      let saved: Blob | undefined;
      const create = vi.fn((blob: Blob) => {
        saved = blob;
        return "blob:synthetic";
      });
      vi.stubGlobal(
        "URL",
        class extends URL {
          static createObjectURL = create;
          static revokeObjectURL = vi.fn();
        },
      );
      const click = vi
        .spyOn(HTMLAnchorElement.prototype, "click")
        .mockImplementation(() => {});
      const result = structuredClone(STORAGE_RETENTION_EXAMPLES[status]);
      const region = await showResult(result);
      await userEvent.click(
        within(region).getByRole("button", {
          name: "Download full storage result JSON",
        }),
      );
      expect(click).toHaveBeenCalledTimes(1);
      expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:synthetic");
      expect(saved?.type).toBe("application/json");
      const text = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = reject;
        reader.readAsText(saved!);
      });
      expect(text).toBe(receiptFor(result).rawJson);
      expect(JSON.parse(text)).toEqual(result);
      expect(
        document.querySelector('a[download="storage-retention-result.json"]'),
      ).toBeNull();
    },
  );
  it("reports a failed download without dropping evidence", async () => {
    vi.stubGlobal(
      "URL",
      class extends URL {
        static createObjectURL = vi.fn(() => {
          throw new Error("PRIVATE_DOWNLOAD");
        });
      },
    );
    const region = await showResult(
      structuredClone(STORAGE_RETENTION_EXAMPLES.partial),
    );
    await userEvent.click(
      within(region).getByRole("button", {
        name: "Download full storage result JSON",
      }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The JSON download could not be created",
    );
    expect(document.body.textContent).not.toContain("PRIVATE_DOWNLOAD");
    expect(
      within(region).getByRole("heading", { name: "azure-container" }),
    ).toBeInTheDocument();
  });
});

describe("authoritative storage evidence in the UI", () => {
  it.each(["s3", "contract"] as const)(
    "keeps native %s numeric tokens and export bytes through actual fetch",
    async (name) => {
      const raw = STORAGE_RETENTION_NUMERIC_WIRES[name];
      const request = snapshotStorageRetentionRequest(
        name === "s3"
          ? {
              provider: "s3",
              scope_label: "synthetic",
              targets: [
                {
                  bucket: "synthetic-retention",
                  region: "us-east-1",
                  expected_owner: "123456789012",
                },
              ],
            }
          : {
              provider: "gcs",
              scope_label: "synthetic-contract",
              targets: [{ bucket: "synthetic-contract" }],
            },
      );
      const actual =
        await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
      collect.mockImplementation(actual.api.collectStorageRetention);
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(raw, {
          headers: { "content-type": "application/json" },
        }),
      );
      vi.stubGlobal("fetch", fetchMock);
      let saved: Blob | undefined;
      vi.stubGlobal(
        "URL",
        class extends URL {
          static createObjectURL = vi.fn((blob: Blob) => {
            saved = blob;
            return "blob:synthetic-exact";
          });
          static revokeObjectURL = vi.fn();
        },
      );
      vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
        () => {},
      );
      open();
      await fillRequest(request);
      submit();
      const region = await screen.findByRole("region", {
        name: "Storage retention result",
      });
      const disclosure = within(region)
        .getAllByText("Native configuration fields")[0]
        .closest("details");
      if (!disclosure) throw new Error("Missing native fields");
      await userEvent.click(
        within(disclosure).getByText("Native configuration fields"),
      );
      const exact = parseStorageRetentionResponse(raw, request)
        .nativeFieldsJson[0][0];
      await waitFor(() =>
        expect(disclosure.querySelector("code")?.textContent).toBe(exact),
      );
      expect(disclosure.textContent).toContain(
        name === "s3" ? "9007199254740993" : "-0.0",
      );
      if (name === "contract")
        for (const token of [
          "1.0",
          "1e+20",
          "1e-6",
          "9".repeat(128),
          "__proto__",
          "constructor",
        ])
          expect(disclosure.textContent).toContain(token);
      const full = within(region)
        .getByText("Full result, including manifest and findings")
        .closest("details");
      if (!full) throw new Error("Missing full result");
      await userEvent.click(
        within(full).getByText("Full result, including manifest and findings"),
      );
      await waitFor(() =>
        expect(full.querySelector("code")?.textContent).toBe(raw),
      );
      await userEvent.click(
        within(region).getByRole("button", {
          name: "Download full storage result JSON",
        }),
      );
      if (!saved) throw new Error("Missing exported Blob");
      const blob = saved;
      const text = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = reject;
        reader.readAsText(blob);
      });
      expect(text).toBe(raw);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(verify).toHaveBeenCalledTimes(1);
      expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:synthetic-exact");
    },
  );
  it("refuses mismatched selected evidence even if the injected helper mutates the outgoing request", async () => {
    const other = structuredClone(STORAGE_RETENTION_EXAMPLES.unavailable);
    other.scope_label = "other";
    collect.mockImplementationOnce(async (request) => {
      request.scope_label = "other";
      return receiptFor(other);
    });
    open();
    fillS3();
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The storage response is invalid or does not match the selected request.",
    );
    expect(
      screen.queryByRole("region", { name: "Storage retention result" }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", {
        name: "Download full storage result JSON",
      }),
    ).toBeNull();
  });
  it("clears prior evidence before a later authentication refusal", async () => {
    await showResult(structuredClone(STORAGE_RETENTION_EXAMPLES.unavailable));
    verify.mockResolvedValueOnce(false);
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /authentication could not be confirmed/,
    );
    expect(
      screen.queryByRole("region", { name: "Storage retention result" }),
    ).toBeNull();
    expect(collect).toHaveBeenCalledTimes(1);
  });
  it("refuses malformed helper receipt text with the fixed response error", async () => {
    const receipt = receiptFor(STORAGE_RETENTION_EXAMPLES.unavailable);
    collect.mockResolvedValueOnce({
      ...receipt,
      rawJson: '{"PRIVATE_RESPONSE":',
    });
    open();
    fillS3();
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /storage response is invalid/,
    );
    expect(document.body.textContent).not.toContain("PRIVATE_RESPONSE");
    expect(
      screen.queryByRole("region", { name: "Storage retention result" }),
    ).toBeNull();
  });
});
