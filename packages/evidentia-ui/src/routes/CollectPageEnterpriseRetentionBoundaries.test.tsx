import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { ENTERPRISE_RETENTION_DEMO } from "@/lib/demo/fixtures";
import { parseEnterpriseRetentionResponse, snapshotEnterpriseRetentionRequest } from "@/lib/enterprise-retention";
import { CollectPage } from "@/routes/CollectPage";

vi.mock("@/lib/demo", () => ({ IS_DEMO: false, IS_DEMO_FDA_INDEX: false }));
vi.mock("@/lib/api", async original => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, health: vi.fn(), collectEnterpriseRetention: vi.fn() } };
});
const health = vi.mocked(api.health);
const collect = vi.mocked(api.collectEnterpriseRetention);
const clients: QueryClient[] = [];
const verified = (auth = true) => ({ status: "ok", version: "synthetic", auth_configured: auth });
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function openForm() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  const view = render(<QueryClientProvider client={client}><CollectPage /></QueryClientProvider>);
  await userEvent.click(screen.getByRole("tab", { name: "Enterprise retention" }));
  await waitFor(() => expect(health).toHaveBeenCalled());
  return view;
}
function fill(input: unknown = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete.request) {
  const request = snapshotEnterpriseRetentionRequest(input);
  fireEvent.change(screen.getByLabelText("Enterprise provider"), { target: { value: request.provider } });
  fireEvent.change(screen.getByLabelText("Profile alias"), { target: { value: request.profile_alias } });
  fireEvent.change(screen.getByLabelText("Enterprise scope label"), { target: { value: request.scope_label } });
  for (const [index, target] of request.targets.entries()) {
    if (index) fireEvent.click(screen.getByRole("button", { name: "Add enterprise target" }));
    fireEvent.change(screen.getByLabelText(`${request.provider === "google-vault" ? "Matter ID" : "Index name"} ${index + 1}`), { target: { value: "matter_id" in target ? target.matter_id : target.index } });
  }
  return request;
}
function submit() { fireEvent.submit(screen.getByRole("form", { name: "Enterprise retention request" })); }
beforeEach(() => {
  health.mockReset().mockResolvedValue(verified());
  collect.mockReset().mockImplementation(async request => {
    const fixture = ENTERPRISE_RETENTION_DEMO[request.provider].complete;
    return parseEnterpriseRetentionResponse(fixture.rawJson, request);
  });
  vi.stubGlobal("fetch", vi.fn(() => { throw new Error("Unexpected network"); }));
});
afterEach(() => { cleanup(); for (const client of clients.splice(0)) client.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function fileOf(content: string | Uint8Array<ArrayBuffer>, pending?: Promise<ArrayBuffer>) {
  const bytes = typeof content === "string" ? new TextEncoder().encode(content) : content;
  const file = new File([bytes], "synthetic-request.json", { type: "application/json" });
  const read = vi.fn().mockReturnValue(pending ?? Promise.resolve(bytes.buffer));
  Object.defineProperty(file, "arrayBuffer", { value: read });
  return { file, read };
}
async function upload(file: File) { await userEvent.upload(screen.getByLabelText("Enterprise request JSON"), file); }
it.each([false, new Error("PRIVATE_HEALTH")])("refuses collection when fresh auth cannot be confirmed: %s", async outcome => {
  await openForm(); fill();
  const pending = deferred<ReturnType<typeof verified>>(); health.mockReturnValueOnce(pending.promise);
  submit(); submit();
  await waitFor(() => expect(health).toHaveBeenCalledTimes(2)); expect(collect).not.toHaveBeenCalled();
  await act(async () => { if (outcome instanceof Error) pending.reject(outcome); else pending.resolve(verified(outcome)); });
  expect(await screen.findByText(/Current API authentication could not be confirmed/)).toBeInTheDocument();
  expect(collect).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain("PRIVATE_");
});
it("cannot post before initial health or after unmount during the fresh check", async () => {
  const initial = deferred<ReturnType<typeof verified>>(); health.mockReturnValueOnce(initial.promise);
  const view = await openForm(); fill(); submit(); expect(collect).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Collect enterprise configuration" })).toBeDisabled();
  await act(async () => initial.resolve(verified()));
  await waitFor(() => expect(screen.getByRole("button", { name: "Collect enterprise configuration" })).toBeEnabled());
  fill();
  const fresh = deferred<ReturnType<typeof verified>>(); health.mockReturnValueOnce(fresh.promise);
  submit(); await waitFor(() => expect(health).toHaveBeenCalledTimes(2));
  view.unmount(); await act(async () => fresh.resolve(verified())); expect(collect).not.toHaveBeenCalled();
});
it("prevents repeat submissions and field changes throughout the worker request", async () => {
  const pending = deferred<Awaited<ReturnType<typeof api.collectEnterpriseRetention>>>(); collect.mockReturnValueOnce(pending.promise);
  await openForm(); fill(); submit(); await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
  expect(screen.getByLabelText("Enterprise provider")).toBeDisabled(); expect(screen.getByLabelText("Enterprise request JSON")).toBeDisabled();
  expect(screen.getByRole("button", { name: "Reset enterprise form" })).toBeDisabled();
  submit(); expect(collect).toHaveBeenCalledTimes(1);
  await act(async () => pending.reject(new Error("PRIVATE_WORKER")));
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/Enterprise collection failed/);
  expect(screen.getByLabelText("Enterprise provider")).toBeEnabled();
});
it.each(["resolve", "reject"] as const)("ignores stale upload %s after a newer complete selection", async settlement => {
  await openForm();
  const old = deferred<ArrayBuffer>(); await upload(fileOf("old", old.promise).file); submit(); expect(collect).not.toHaveBeenCalled();
  const selected = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete.request;
  await upload(fileOf(JSON.stringify(selected)).file);
  await waitFor(() => expect(screen.getByLabelText("Enterprise provider")).toHaveValue("splunk-enterprise"));
  await act(async () => { if (settlement === "resolve") old.resolve(new TextEncoder().encode("{}").buffer); else old.reject(new Error("PRIVATE_OLD")); });
  submit(); await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
  expect(collect.mock.calls[0][0]).toEqual(selected); expect(screen.queryByText(/request file must contain/)).toBeNull();
});
it.each(["provider", "reset", "clear", "unmount"] as const)("invalidates pending file work on %s", async action => {
  const view = await openForm(); const pending = deferred<ArrayBuffer>();
  await upload(fileOf("old", pending.promise).file);
  if (action === "provider") fireEvent.change(screen.getByLabelText("Enterprise provider"), { target: { value: "elastic-ilm" } });
  else if (action === "reset") fireEvent.click(screen.getByRole("button", { name: "Reset enterprise form" }));
  else if (action === "clear") fireEvent.change(screen.getByLabelText("Enterprise request JSON"), { target: { files: [] } });
  else view.unmount();
  await act(async () => pending.resolve(new TextEncoder().encode(JSON.stringify(ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete.request)).buffer));
  expect(collect).not.toHaveBeenCalled();
  if (action !== "unmount") { expect(screen.getByLabelText("Enterprise provider")).toHaveValue(action === "provider" ? "elastic-ilm" : "google-vault"); expect(screen.getByLabelText("Profile alias")).toHaveValue(""); }
});
it.each([65536, 65537])("checks actual uploaded bytes at %s even if size metadata lies", async size => {
  await openForm();
  const raw = JSON.stringify(ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete.request);
  const bytes = new TextEncoder().encode(raw + " ".repeat(size - new TextEncoder().encode(raw).length));
  await upload(fileOf("small", Promise.resolve(bytes.buffer)).file);
  if (size === 65536) {
    await waitFor(() => expect(screen.getByLabelText("Enterprise provider")).toHaveValue("splunk-enterprise"));
    submit(); await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
  } else {
    expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/within 64 KiB/); submit(); expect(collect).not.toHaveBeenCalled();
  }
});
it("refuses known oversized files before reading bytes", async () => {
  await openForm(); const { file, read } = fileOf(" ".repeat(65537)); await upload(file);
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/within 64 KiB/); expect(read).not.toHaveBeenCalled();
});
it.each(["\ufeff{}", '{"provider":"splunk-enterprise","provider":"google-vault"}', '{"x":"\\ud800"}', '{"x":NaN}', "{}", "[]"])("rejects invalid imported JSON %j and cannot reuse an old valid selection", async raw => {
  await openForm(); fill(); await upload(fileOf(raw).file);
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/strict UTF-8 JSON/);
  submit(); expect(collect).not.toHaveBeenCalled();
});
it.each([[0xc3, 0x28], [0xe2, 0x82], [0xed, 0xa0, 0x80], [0xc0, 0x80]])("rejects malformed request UTF-8 %j", async (...bytes) => {
  await openForm(); await upload(fileOf(new Uint8Array(bytes)).file);
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/strict UTF-8 JSON/); submit(); expect(collect).not.toHaveBeenCalled();
});
