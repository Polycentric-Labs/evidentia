import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { demoApi } from "@/lib/demo/demo-api";
import { CollectPage } from "@/routes/CollectPage";

vi.mock("@/lib/demo", () => ({ IS_DEMO: true, IS_DEMO_FDA_INDEX: false }));

const clients: QueryClient[] = [];
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  vi.unstubAllGlobals();
});

it("uses the actual isolated demo client and exposes only the two labeled synthetic scenarios", async () => {
  const fetchMock = vi.fn(() => {
    throw new Error("Unexpected network");
  });
  vi.stubGlobal("fetch", fetchMock);
  expect(api).toBe(demoApi);
  for (const scenario of ["partial", "unavailable"] as const) {
    const first = await api.collectEntraM365(
      { tenant_label: "synthetic-demo" },
      scenario,
    );
    const original = structuredClone(first);
    first.provenance.tenant_label = "mutated";
    if (!first.manifest.filters_applied || !first.manifest.coverage_counts) {
      throw new Error("Synthetic fixture is missing manifest details");
    }
    first.manifest.filters_applied.nested = { changed: true };
    first.manifest.coverage_counts[0].scanned = 999;
    first.capabilities[1].diagnostics[0].count = 999;
    if (first.findings.length) first.findings[0].raw_data = { changed: true };
    expect(
      await api.collectEntraM365({ tenant_label: "synthetic-demo" }, scenario),
    ).toEqual(original);
  }
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  clients.push(client);
  render(
    <QueryClientProvider client={client}>
      <CollectPage />
    </QueryClientProvider>,
  );
  await userEvent.click(screen.getByRole("tab", { name: "Entra/M365" }));
  expect(screen.getByText("Synthetic examples")).toBeInTheDocument();
  expect(screen.getByText(/No tenant is queried/)).toBeInTheDocument();
  expect(screen.getByLabelText("Tenant label")).toHaveValue("synthetic-demo");
  for (const input of [
    screen.getByLabelText("Tenant label"),
    screen.getByLabelText("DLP JSON export"),
    screen.getByLabelText("Lookback days"),
    ...screen.getAllByRole("checkbox"),
  ]) {
    expect(input).toBeDisabled();
  }
  const scenarios = screen.getByLabelText("Synthetic result scenario");
  expect(within(scenarios).getAllByRole("option")).toHaveLength(2);
  await userEvent.click(
    screen.getByRole("button", { name: "Collect Entra/M365" }),
  );
  expect(
    await screen.findByText("Collection incomplete: partial"),
  ).toBeInTheDocument();
  await userEvent.selectOptions(scenarios, "unavailable");
  await userEvent.click(
    screen.getByRole("button", { name: "Collect Entra/M365" }),
  );
  expect(
    await screen.findByText("Collection incomplete: unavailable"),
  ).toBeInTheDocument();
  const region = screen.getByLabelText("Entra/M365 result");
  expect(within(region).getAllByLabelText(/capability result$/)).toHaveLength(
    9,
  );
  expect(within(region).getByText(/Findings retained: 0/)).toBeInTheDocument();
  expect(within(region).queryByLabelText("Collector findings")).toBeNull();
  expect(fetchMock).not.toHaveBeenCalled();
});
