import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, ApiError } from "@/lib/api";
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

it.each(["google-vault", "splunk-enterprise", "elastic-ilm"] as const)("submits strict %s selection through the actual Collect tab after fresh auth", async provider => {
  await openForm();
  const selected = fill(ENTERPRISE_RETENTION_DEMO[provider].complete.request);
  await waitFor(() => expect(screen.getByRole("button", { name: "Collect enterprise configuration" })).toBeEnabled());
  submit();
  await screen.findByRole("region", { name: "Enterprise retention result" });
  expect(collect).toHaveBeenCalledExactlyOnceWith(selected, "partial");
  expect(health).toHaveBeenCalledTimes(2);
  expect(Object.isFrozen(collect.mock.calls[0][0])).toBe(true);
  expect(document.body.textContent).toContain("Authenticated identity verified: no");
  expect(document.body.textContent).toContain("unassessed");
});
it.each(["complete", "partial", "unavailable"] as const)("keeps the %s result, resource states and exact wire download", async status => {
  const fixture = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"][status];
  collect.mockResolvedValue(parseEnterpriseRetentionResponse(fixture.rawJson, fixture.request));
  let blob: Blob | undefined;
  const create = vi.fn((value: Blob) => { blob = value; return "blob:synthetic-enterprise"; });
  const revoke = vi.fn();
  vi.stubGlobal("URL", Object.assign(class extends URL {}, { createObjectURL: create, revokeObjectURL: revoke }));
  const clicked = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await openForm(); fill(fixture.request); submit();
  const region = await screen.findByRole("region", { name: "Enterprise retention result" });
  expect(within(region).getAllByLabelText(/enterprise-retention\/.* result$/)).toHaveLength(2);
  expect(within(region).getByText(status === "complete" ? "Selected reads complete" : `Collection incomplete: ${status}`)).toBeInTheDocument();
  await userEvent.click(within(region).getByRole("button", { name: "Download full enterprise result JSON" }));
  expect(clicked).toHaveBeenCalledTimes(1); expect(revoke).toHaveBeenCalledWith("blob:synthetic-enterprise");
  const exportBlob = blob;
  if (!exportBlob) throw new Error("Missing export blob");
  const exported = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = reject; reader.readAsText(exportBlob); });
  expect(exported).toBe(fixture.rawJson);
  expect(exported.endsWith("\n")).toBe(false);
  if (status !== "unavailable") {
    await userEvent.click(within(region).getByText("Native fields for events-0"));
    await waitFor(() => expect(region.textContent).toContain("9007199254740993"));
    expect(region.textContent).toContain('"00042"');
  }
});
it("keeps shared Elastic reads unique and shows native source tokens as escaped text", async () => {
  await openForm(); fill(ENTERPRISE_RETENTION_DEMO["elastic-ilm"].complete.request); submit();
  const region = await screen.findByRole("region", { name: "Enterprise retention result" });
  expect(within(region).getAllByLabelText(/^elastic-status .* read$/)).toHaveLength(1);
  expect(within(region).getAllByLabelText(/^elastic-policy .* read$/)).toHaveLength(1);
  expect(within(region).getAllByLabelText(/^elastic-explain .* read$/)).toHaveLength(2);
  await userEvent.selectOptions(screen.getByLabelText("Enterprise provider"), "google-vault");
  expect(screen.queryByRole("region", { name: "Enterprise retention result" })).toBeNull();
  expect(screen.getByLabelText("Matter ID 1")).toHaveValue("");
  fill(ENTERPRISE_RETENTION_DEMO["google-vault"].complete.request); submit();
  const vault = await screen.findByRole("region", { name: "Enterprise retention result" });
  await userEvent.click(within(vault).getByText("Native fields for hold-matter-0"));
  await waitFor(() => expect(vault.textContent).toContain("<synthetic-query>"));
  expect(vault.querySelector("synthetic-query")).toBeNull();
  expect(vault.textContent).toContain("2026-01-01T00:00:00.123456789Z");
});
it("rejects invalid/duplicate input before a fresh health request and bounds target additions", async () => {
  await openForm(); fill();
  fireEvent.change(screen.getByLabelText("Index name 2"), { target: { value: "events-0" } });
  submit();
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/unique literal/);
  expect(health).toHaveBeenCalledTimes(1); expect(collect).not.toHaveBeenCalled();
  for (let n = 2; n < 20; n++) fireEvent.click(screen.getByRole("button", { name: "Add enterprise target" }));
  expect(screen.getByRole("button", { name: "Add enterprise target" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Reset enterprise form" }));
  expect(screen.getByLabelText("Profile alias")).toHaveValue("");
  expect(screen.getByLabelText("Enterprise provider")).toHaveValue("google-vault");
  expect(screen.getByLabelText("Matter ID 1")).toHaveValue("");
});
it.each([401, 403, 413, 422, 503, 500])("shows fixed error text for HTTP %s and restores input", async status => {
  collect.mockRejectedValue(new ApiError("PRIVATE_ERROR", status, { detail: "PRIVATE_BODY" }));
  await openForm(); fill(); submit();
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/required|denied|invalid|unavailable|failed/i);
  expect(document.body.textContent).not.toContain("PRIVATE_");
  expect(screen.getByLabelText("Profile alias")).toBeEnabled();
});
it("refuses a typed-looking result for a different original selection", async () => {
  const fixture = ENTERPRISE_RETENTION_DEMO["splunk-enterprise"].complete;
  collect.mockResolvedValue(parseEnterpriseRetentionResponse(fixture.rawJson, fixture.request));
  await openForm(); fill();
  fireEvent.change(screen.getByLabelText("Enterprise scope label"), { target: { value: "different" } });
  submit();
  expect(await within(screen.getByRole("tabpanel", { name: "Enterprise retention" })).findByRole("alert")).toHaveTextContent(/does not match/);
  expect(screen.queryByRole("region", { name: "Enterprise retention result" })).toBeNull();
});
