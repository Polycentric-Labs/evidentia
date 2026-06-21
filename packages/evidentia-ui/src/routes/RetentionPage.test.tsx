import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, type RetentionMetadata } from "@/lib/api";
import { RetentionPage } from "@/routes/RetentionPage";

// Mock the typed API client — the screen only reaches the backend through it.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listRetention: vi.fn(),
      createRetention: vi.fn(),
      getRetention: vi.fn(),
      extendRetention: vi.fn(),
      transitionRetention: vi.fn(),
      deleteRetention: vi.fn(),
      retentionReport: vi.fn(),
    },
  };
});

const ITEM: RetentionMetadata = {
  id: "ret-1",
  classification: "sec-17a-4",
  retention_period_days: 2190,
  lifecycle_stage: "active",
  legal_hold: false,
  lock_until: "2032-06-20",
  policy_name: "Broker-dealer policy",
  record_pointer: "s3://evidence/audit-2026.tar",
  notes: "Quarterly attestation bundle.",
  created_at: "2026-06-20T00:00:00Z",
  updated_at: "2026-06-20T00:00:00Z",
};

function renderWithClient(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

const mockedApi = vi.mocked(api);

describe("RetentionPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the heading and an empty state when the store is empty", async () => {
    mockedApi.listRetention.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 50,
      items: [],
    });

    renderWithClient(<RetentionPage />);

    expect(
      screen.getByRole("heading", { name: /Retention/i, level: 1 }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/No retention records yet/i),
    ).toBeInTheDocument();
  });

  it("lists records and reveals the detail panel on selection", async () => {
    const user = userEvent.setup();
    mockedApi.listRetention.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 50,
      items: [ITEM],
    });

    renderWithClient(<RetentionPage />);

    // The record card surfaces its record pointer in the list.
    const card = await screen.findByRole("button", {
      name: /audit-2026\.tar/i,
    });
    expect(card).toBeInTheDocument();
    // Detail-only controls are not shown until the record is selected.
    expect(screen.queryByLabelText(/Transition stage/i)).toBeNull();

    await user.click(card);

    // Detail panel renders the transition controls. `active` offers
    // preserved / expired as legal next stages.
    const transition = await screen.findByLabelText(/Transition stage/i);
    expect(
      within(transition).getByRole("button", { name: /Preserved/i }),
    ).toBeInTheDocument();
    expect(
      within(transition).getByRole("button", { name: /Expired/i }),
    ).toBeInTheDocument();
  });

  it("transitions a record through transitionRetention and refreshes the list", async () => {
    const user = userEvent.setup();
    mockedApi.listRetention.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 50,
      items: [ITEM],
    });
    mockedApi.transitionRetention.mockResolvedValue({
      ...ITEM,
      lifecycle_stage: "preserved",
    });

    renderWithClient(<RetentionPage />);

    const card = await screen.findByRole("button", {
      name: /audit-2026\.tar/i,
    });
    await user.click(card);

    const transition = await screen.findByLabelText(/Transition stage/i);
    await user.click(
      within(transition).getByRole("button", { name: /Preserved/i }),
    );

    await waitFor(() =>
      expect(mockedApi.transitionRetention).toHaveBeenCalledWith("ret-1", {
        new_stage: "preserved",
      }),
    );
    // The list query is refetched after a successful transition.
    await waitFor(() =>
      expect(mockedApi.listRetention).toHaveBeenCalledTimes(2),
    );
  });

  it("creates a retention record through createRetention", async () => {
    const user = userEvent.setup();
    mockedApi.listRetention.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 50,
      items: [],
    });
    mockedApi.createRetention.mockResolvedValue(ITEM);

    renderWithClient(<RetentionPage />);

    // Wait for the form to render.
    const addButton = await screen.findByRole("button", {
      name: /Add record/i,
    });
    // The default classification (SEC 17a-4) is pre-selected; submit as-is.
    await user.click(addButton);

    await waitFor(() =>
      expect(mockedApi.createRetention).toHaveBeenCalledWith(
        expect.objectContaining({
          classification: "sec-17a-4",
          legal_hold: false,
        }),
      ),
    );
  });

  it("fetches and renders the markdown report as preformatted text", async () => {
    const user = userEvent.setup();
    mockedApi.listRetention.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 50,
      items: [],
    });
    mockedApi.retentionReport.mockResolvedValue(
      "# Retention Report\n\n- 0 records",
    );

    renderWithClient(<RetentionPage />);

    const reportButton = await screen.findByRole("button", {
      name: /Generate report/i,
    });
    await user.click(reportButton);

    await waitFor(() =>
      expect(mockedApi.retentionReport).toHaveBeenCalledTimes(1),
    );
    expect(
      await screen.findByText(/# Retention Report/),
    ).toBeInTheDocument();
  });
});
