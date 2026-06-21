import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, type ModelInventory } from "@/lib/api";
import { ModelRiskPage } from "@/routes/ModelRiskPage";

// Mock the typed API client — the screen only reaches the backend through it.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listModels: vi.fn(),
      createModel: vi.fn(),
      getModel: vi.fn(),
      updateModel: vi.fn(),
      deleteModel: vi.fn(),
      modelDocumentation: vi.fn(),
      modelValidationReport: vi.fn(),
    },
  };
});

const MODEL: ModelInventory = {
  id: "model-1",
  name: "Fraud-detector LLM-v0.4",
  owner: "alice@example.com",
  purpose: "Score transactions for fraud likelihood.",
  methodology: "llm",
  tier: "tier_1",
  vendor_or_internal: "internal",
  next_validation_due: "2026-12-31",
  last_validation_date: "2026-06-01",
  inputs: [],
  outputs: [],
  validation_findings: [],
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

describe("ModelRiskPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the heading and an empty state when the store is empty", async () => {
    mockedApi.listModels.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 50,
      items: [],
    });

    renderWithClient(<ModelRiskPage />);

    expect(
      screen.getByRole("heading", { name: /Model risk/i }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/No models yet/i)).toBeInTheDocument();
  });

  it("lists models and reveals detail on selection", async () => {
    const user = userEvent.setup();
    mockedApi.listModels.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 50,
      items: [MODEL],
    });

    renderWithClient(<ModelRiskPage />);

    const card = await screen.findByRole("button", {
      name: /Fraud-detector LLM-v0\.4/i,
    });
    expect(card).toBeInTheDocument();
    // The purpose only appears in the detail panel, not the list card.
    expect(
      screen.queryByText(/Score transactions for fraud likelihood/i),
    ).toBeNull();

    await user.click(card);

    // Detail panel renders the full record + the four actions.
    expect(
      await screen.findByText(/Score transactions for fraud likelihood/i),
    ).toBeInTheDocument();
    const actions = await screen.findByLabelText(/^Actions$/i);
    expect(
      within(actions).getByRole("button", { name: /^Edit$/i }),
    ).toBeInTheDocument();
    expect(
      within(actions).getByRole("button", { name: /Documentation/i }),
    ).toBeInTheDocument();
    expect(
      within(actions).getByRole("button", { name: /Validation report/i }),
    ).toBeInTheDocument();
  });

  it("creates a model through createModel and refreshes the list", async () => {
    const user = userEvent.setup();
    mockedApi.listModels.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 50,
      items: [],
    });
    mockedApi.createModel.mockResolvedValue(MODEL);

    renderWithClient(<ModelRiskPage />);

    // Wait for the first list fetch to settle.
    await screen.findByText(/No models yet/i);

    await user.type(
      screen.getByLabelText(/^Name$/i),
      "Fraud-detector LLM-v0.4",
    );
    await user.type(
      screen.getByLabelText(/^Owner$/i),
      "alice@example.com",
    );
    await user.type(
      screen.getByLabelText(/^Purpose$/i),
      "Score transactions for fraud likelihood.",
    );

    await user.click(screen.getByRole("button", { name: /Add model/i }));

    await waitFor(() =>
      expect(mockedApi.createModel).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Fraud-detector LLM-v0.4",
          owner: "alice@example.com",
          purpose: "Score transactions for fraud likelihood.",
          methodology: "ml",
          tier: "tier_2",
          vendor_or_internal: "internal",
        }),
      ),
    );
    // The list query is refetched after a successful create.
    await waitFor(() =>
      expect(mockedApi.listModels).toHaveBeenCalledTimes(2),
    );
  });

  it("deletes a model through deleteModel after confirmation", async () => {
    const user = userEvent.setup();
    mockedApi.listModels.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 50,
      items: [MODEL],
    });
    mockedApi.deleteModel.mockResolvedValue(undefined);

    renderWithClient(<ModelRiskPage />);

    const card = await screen.findByRole("button", {
      name: /Fraud-detector LLM-v0\.4/i,
    });
    await user.click(card);

    const actions = await screen.findByLabelText(/^Actions$/i);
    // First click reveals the confirm step; it does not call the API yet.
    await user.click(
      within(actions).getByRole("button", { name: /^Delete$/i }),
    );
    expect(mockedApi.deleteModel).not.toHaveBeenCalled();

    await user.click(
      await screen.findByRole("button", { name: /Confirm delete/i }),
    );

    await waitFor(() =>
      expect(mockedApi.deleteModel).toHaveBeenCalledWith("model-1"),
    );
  });
});
