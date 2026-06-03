import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { Vendor } from "@/lib/api";
import { TprmPage } from "@/routes/TprmPage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing still behaves.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      listVendors: vi.fn(),
      createVendor: vi.fn(),
    },
  };
});

const listVendorsMock = vi.mocked(api.listVendors);
const createVendorMock = vi.mocked(api.createVendor);

const VENDOR: Vendor = {
  id: "e5dd135b-e489-4a4a-9fa4-f3da59589f71",
  name: "Acme Cloud Inc.",
  type: "saas",
  criticality_tier: "critical",
  relationship_owner: "alice@example.com",
  contract_start_date: "2026-01-01",
  next_review_due: "2027-02-15",
  residual_risk_score: 16,
};

function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("TprmPage", () => {
  beforeEach(() => {
    listVendorsMock.mockReset();
    createVendorMock.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading and a vendor from the list", async () => {
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });

    renderWithProviders(<TprmPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "TPRM" }),
    ).toBeInTheDocument();

    expect(await screen.findByText("Acme Cloud Inc.")).toBeInTheDocument();
    // Owner + next-review-due render on the card.
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();
    expect(screen.getByText("2027-02-15")).toBeInTheDocument();
  });

  it("renders the empty state when the store is empty", async () => {
    listVendorsMock.mockResolvedValue({ total: 0, vendors: [] });

    renderWithProviders(<TprmPage />);

    expect(
      await screen.findByText(/no vendors yet/i),
    ).toBeInTheDocument();
  });

  it("renders the error card when the list query fails", async () => {
    listVendorsMock.mockRejectedValue(new Error("boom"));

    renderWithProviders(<TprmPage />);

    expect(
      await screen.findByText(/could not fetch vendors/i),
    ).toBeInTheDocument();
  });

  it("submits the new-vendor form with the five required fields", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 0, vendors: [] });
    createVendorMock.mockResolvedValue({ ...VENDOR });

    renderWithProviders(<TprmPage />);

    // Wait for the initial (empty) list to settle.
    await screen.findByText(/no vendors yet/i);

    await user.type(screen.getByLabelText("Name"), "Globex Hosting LLC");
    await user.type(
      screen.getByLabelText("Relationship owner"),
      "bob@example.com",
    );
    // Date input — set the value directly (native date pickers don't take
    // free typing reliably in jsdom).
    const dateInput = screen.getByLabelText(
      "Contract start date",
    ) as HTMLInputElement;
    await user.clear(dateInput);
    await user.type(dateInput, "2025-06-01");

    // Switch the type picker to cloud_provider and the tier to "high".
    const typeGroup = screen.getByRole("radiogroup", { name: "Vendor type" });
    await user.click(
      within(typeGroup).getByRole("radio", { name: "Cloud provider" }),
    );
    const tierGroup = screen.getByRole("radiogroup", {
      name: "Criticality tier",
    });
    await user.click(within(tierGroup).getByRole("radio", { name: "High" }));

    await user.click(screen.getByRole("button", { name: /add vendor/i }));

    await waitFor(() => expect(createVendorMock).toHaveBeenCalledTimes(1));
    expect(createVendorMock).toHaveBeenCalledWith({
      name: "Globex Hosting LLC",
      type: "cloud_provider",
      criticality_tier: "high",
      relationship_owner: "bob@example.com",
      contract_start_date: "2025-06-01",
      residual_risk_score: 0,
    });
  });
});
