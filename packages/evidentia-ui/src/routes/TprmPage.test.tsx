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
      getVendor: vi.fn(),
      updateVendor: vi.fn(),
      deleteVendor: vi.fn(),
      tprmConcentration: vi.fn(),
      ddQuestionnaireGenerate: vi.fn(),
      ddQuestionnaireIngest: vi.fn(),
    },
  };
});

const listVendorsMock = vi.mocked(api.listVendors);
const createVendorMock = vi.mocked(api.createVendor);
const getVendorMock = vi.mocked(api.getVendor);
const updateVendorMock = vi.mocked(api.updateVendor);
const deleteVendorMock = vi.mocked(api.deleteVendor);
const tprmConcentrationMock = vi.mocked(api.tprmConcentration);
const ddQuestionnaireIngestMock = vi.mocked(api.ddQuestionnaireIngest);

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
    getVendorMock.mockReset();
    updateVendorMock.mockReset();
    deleteVendorMock.mockReset();
    tprmConcentrationMock.mockReset();
    ddQuestionnaireIngestMock.mockReset();
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

  it("opens the detail panel when a vendor card is selected", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });
    getVendorMock.mockResolvedValue({ ...VENDOR });

    renderWithProviders(<TprmPage />);

    await user.click(
      await screen.findByRole("button", { name: "Vendor Acme Cloud Inc." }),
    );

    // Detail panel renders + the vendor is fetched by id.
    expect(
      await screen.findByRole("heading", { name: "Vendor detail" }),
    ).toBeInTheDocument();
    await waitFor(() => expect(getVendorMock).toHaveBeenCalledWith(VENDOR.id));
  });

  it("calls updateVendor when the edit form is saved", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });
    getVendorMock.mockResolvedValue({ ...VENDOR });
    updateVendorMock.mockResolvedValue({ ...VENDOR, name: "Acme Renamed" });

    renderWithProviders(<TprmPage />);

    await user.click(
      await screen.findByRole("button", { name: "Vendor Acme Cloud Inc." }),
    );
    await screen.findByRole("heading", { name: "Vendor detail" });

    // Enter edit mode, change the name, save.
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const editForm = await screen.findByRole("form", { name: "Edit vendor" });
    const nameInput = within(editForm).getByLabelText(
      "Name",
    ) as HTMLInputElement;
    await user.clear(nameInput);
    await user.type(nameInput, "Acme Renamed");
    await user.click(
      within(editForm).getByRole("button", { name: /save changes/i }),
    );

    await waitFor(() => expect(updateVendorMock).toHaveBeenCalledTimes(1));
    expect(updateVendorMock).toHaveBeenCalledWith(VENDOR.id, {
      name: "Acme Renamed",
      type: VENDOR.type,
      criticality_tier: VENDOR.criticality_tier,
      relationship_owner: VENDOR.relationship_owner,
      contract_start_date: VENDOR.contract_start_date,
      residual_risk_score: VENDOR.residual_risk_score,
    });
  });

  it("calls deleteVendor after the delete confirmation", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });
    getVendorMock.mockResolvedValue({ ...VENDOR });
    deleteVendorMock.mockResolvedValue(undefined);

    renderWithProviders(<TprmPage />);

    await user.click(
      await screen.findByRole("button", { name: "Vendor Acme Cloud Inc." }),
    );
    await screen.findByRole("heading", { name: "Vendor detail" });

    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.click(
      await screen.findByRole("button", { name: /confirm delete/i }),
    );

    await waitFor(() => expect(deleteVendorMock).toHaveBeenCalledTimes(1));
    expect(deleteVendorMock).toHaveBeenCalledWith(VENDOR.id);
  });

  it("calls tprmConcentration when the report button is pressed", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });
    tprmConcentrationMock.mockResolvedValue({
      total_vendors: 1,
      dimensions: [
        {
          dimension: "type",
          total_unique_values: 1,
          vendors_with_value: 1,
          distribution: [
            {
              value: "saas",
              count: 1,
              percentage: 100,
              exceeds_threshold: false,
            },
          ],
        },
      ],
    });

    renderWithProviders(<TprmPage />);

    await screen.findByText("Acme Cloud Inc.");

    await user.click(
      screen.getByRole("button", { name: /run concentration report/i }),
    );

    await waitFor(() =>
      expect(tprmConcentrationMock).toHaveBeenCalledTimes(1),
    );
    // The returned distribution renders as structured text.
    expect(await screen.findByText(/1 vendors analyzed/i)).toBeInTheDocument();
  });

  it("ingests a pasted questionnaire document and renders the correlation result", async () => {
    const user = userEvent.setup();
    listVendorsMock.mockResolvedValue({ total: 1, vendors: [VENDOR] });
    getVendorMock.mockResolvedValue({ ...VENDOR });
    // The ingest endpoint is PARSE-ONLY: it returns a correlation result, not
    // an updated Vendor.
    ddQuestionnaireIngestMock.mockResolvedValue({
      vendor: { id: VENDOR.id!, name: VENDOR.name },
      questionnaire_id: "q-123",
      format: "evidentia-generic",
      responses: { "EVG-GOV-01": "Yes", "EVG-GOV-02": "" },
      ingested_at: "2026-06-20T12:00:00Z",
    });

    renderWithProviders(<TprmPage />);

    // Open the detail panel (the DD-questionnaire section lives inside it).
    await user.click(
      await screen.findByRole("button", { name: "Vendor Acme Cloud Inc." }),
    );
    await screen.findByRole("heading", { name: "Vendor detail" });

    // Paste a completed questionnaire document into the ingest textarea.
    const document = {
      format: "evidentia-generic",
      questions: [
        { id: "EVG-GOV-01", vendor_response: "Yes" },
        { id: "EVG-GOV-02", vendor_response: "" },
      ],
    };
    const textarea = screen.getByLabelText("Ingest completed questionnaire");
    await user.click(textarea);
    await user.paste(JSON.stringify(document));

    await user.click(
      screen.getByRole("button", { name: /ingest questionnaire/i }),
    );

    // The page posts the parsed document object (not a {responses} payload).
    await waitFor(() =>
      expect(ddQuestionnaireIngestMock).toHaveBeenCalledTimes(1),
    );
    expect(ddQuestionnaireIngestMock).toHaveBeenCalledWith(VENDOR.id, document);

    // The correlation result renders: resolved vendor + per-question responses.
    expect(
      await screen.findByText(/questionnaire ingested/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/parse-only/i)).toBeInTheDocument();
    expect(screen.getByText("EVG-GOV-01")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("EVG-GOV-02")).toBeInTheDocument();
    // Empty response renders as the "no response" placeholder.
    expect(screen.getByText(/no response/i)).toBeInTheDocument();
  });
});
