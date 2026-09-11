import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { demoApi } from "@/lib/demo/demo-api";
import { CollectPage } from "@/routes/CollectPage";
vi.mock("@/lib/demo", () => ({ IS_DEMO: true, IS_DEMO_FDA_INDEX: false }));
const clients: QueryClient[] = [];
afterEach(() => { cleanup(); for (const client of clients.splice(0)) client.clear(); vi.unstubAllGlobals(); });
it("runs all nine provider/scenario presets through the actual demo API without provider access", async () => {
  const fetch = vi.fn(() => { throw new Error("Unexpected network"); }); vi.stubGlobal("fetch", fetch);
  expect(api).toBe(demoApi);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><CollectPage /></QueryClientProvider>);
  await userEvent.click(screen.getByRole("tab", { name: "Enterprise retention" }));
  expect(screen.getByText("Synthetic enterprise examples")).toBeInTheDocument();
  expect(screen.getByLabelText("Profile alias")).toBeDisabled();
  expect(screen.getByLabelText("Enterprise request JSON")).toBeDisabled();
  expect(within(screen.getByLabelText("Enterprise synthetic scenario")).getAllByRole("option")).toHaveLength(3);
  for (const provider of ["google-vault", "splunk-enterprise", "elastic-ilm"]) {
    await userEvent.selectOptions(screen.getByLabelText("Enterprise provider"), provider);
    for (const scenario of ["complete", "partial", "unavailable"]) {
      await userEvent.selectOptions(screen.getByLabelText("Enterprise synthetic scenario"), scenario);
      await userEvent.click(screen.getByRole("button", { name: "Show synthetic enterprise result" }));
      const region = await screen.findByRole("region", { name: "Enterprise retention result" });
      expect(within(region).getByText(scenario === "complete" ? "Selected reads complete" : `Collection incomplete: ${scenario}`)).toBeInTheDocument();
      expect(region.textContent).toContain(`Provider: ${provider}`);
      expect(region.textContent).toContain("Authenticated identity verified: no");
    }
  }
  expect(fetch).not.toHaveBeenCalled();
});
