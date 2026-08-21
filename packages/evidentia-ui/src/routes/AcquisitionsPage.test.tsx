import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { AcquisitionsPage } from "@/routes/AcquisitionsPage";

// The page reaches the backend only through the typed client, so every
// acquisition method it can call is mocked.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listAcquisitions: vi.fn(),
      getAcquisition: vi.fn(),
      registerAcquisition: vi.fn(),
      setAcquisitionPhase: vi.fn(),
    },
  };
});

const mockedApi = vi.mocked(api);

const ACQUISITION = {
  acquisition_id: "acq-1",
  name: "Case-triage LLM service",
  solicitation_reference: "RFP-2026-014",
  description: "Commercial LLM for case triage.",
  likely_high_impact: "high_impact",
  phases: {},
} as Awaited<
  ReturnType<typeof api.listAcquisitions>
>["acquisitions"][number];

const PROGRESS = {
  total: 6,
  complete: 2,
  in_progress: 1,
  not_started: 0,
  missing: ["selection_and_award", "contract_closeout"],
  lifecycle_complete: false,
} as Awaited<ReturnType<typeof api.getAcquisition>>["progress"];

function renderWithClient(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe("AcquisitionsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedApi.listAcquisitions.mockResolvedValue({
      count: 1,
      acquisitions: [ACQUISITION],
    });
    mockedApi.getAcquisition.mockResolvedValue({
      acquisition: ACQUISITION,
      progress: PROGRESS,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the page heading", () => {
    renderWithClient(<AcquisitionsPage />);

    expect(
      screen.getByRole("heading", { name: /AI acquisitions/i }),
    ).toBeInTheDocument();
  });

  it("lists tracked acquisitions with the count", async () => {
    renderWithClient(<AcquisitionsPage />);

    expect(await screen.findByText(/Case-triage LLM service/)).toBeInTheDocument();
    expect(screen.getByText("RFP-2026-014")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is tracked", async () => {
    mockedApi.listAcquisitions.mockResolvedValue({
      count: 0,
      acquisitions: [],
    });
    renderWithClient(<AcquisitionsPage />);

    expect(
      await screen.findByText(/No acquisitions tracked yet/i),
    ).toBeInTheDocument();
  });

  it("surfaces a failed list load", async () => {
    mockedApi.listAcquisitions.mockRejectedValue(new Error("boom"));
    renderWithClient(<AcquisitionsPage />);

    expect(
      await screen.findByText(/could not load acquisitions/i),
    ).toBeInTheDocument();
  });

  it("registers an acquisition with the §4(a) determination", async () => {
    mockedApi.registerAcquisition.mockResolvedValue({
      acquisition_id: "acq-2",
      acquisition: ACQUISITION,
    });
    const user = userEvent.setup();
    renderWithClient(<AcquisitionsPage />);

    const form = screen.getByRole("form", { name: /register acquisition/i });
    await user.type(
      within(form).getByLabelText(/^name$/i),
      "Fraud-detection model",
    );
    await user.click(
      within(form).getByRole("radio", { name: /likely high-impact/i }),
    );
    await user.click(
      within(form).getByRole("button", { name: /register acquisition/i }),
    );

    await waitFor(() => {
      expect(mockedApi.registerAcquisition).toHaveBeenCalledWith({
        name: "Fraud-detection model",
        likely_high_impact: "high_impact",
      });
    });
  });

  it("opens the detail panel and shows the §4 progress roll-up", async () => {
    const user = userEvent.setup();
    renderWithClient(<AcquisitionsPage />);

    await user.click(await screen.findByRole("button", { name: /details/i }));

    const detail = await screen.findByLabelText(/acquisition detail/i);
    const progress = within(detail).getByLabelText(/lifecycle progress/i);
    expect(within(progress).getByText(/2 \/ 6 complete/)).toBeInTheDocument();
    // `missing` is a list of phases, rendered by label rather than count.
    // Scoped to the progress section: the same labels also appear as
    // options in the set-phase picker below.
    expect(
      within(progress).getByText(/Selection & award, Contract closeout/),
    ).toBeInTheDocument();
  });

  it("submits a lifecycle-phase update", async () => {
    mockedApi.setAcquisitionPhase.mockResolvedValue({
      acquisition: ACQUISITION,
      progress: PROGRESS,
    });
    const user = userEvent.setup();
    renderWithClient(<AcquisitionsPage />);

    await user.click(await screen.findByRole("button", { name: /details/i }));
    const form = await screen.findByRole("form", {
      name: /set acquisition phase/i,
    });
    await user.click(
      within(form).getByRole("radio", { name: /selection & award/i }),
    );
    await user.click(within(form).getByRole("radio", { name: /^complete$/i }));
    await user.click(within(form).getByRole("button", { name: /set phase/i }));

    await waitFor(() => {
      expect(mockedApi.setAcquisitionPhase).toHaveBeenCalledWith("acq-1", {
        phase: "selection_and_award",
        status: "complete",
      });
    });
  });

  it("surfaces a failed phase update", async () => {
    mockedApi.setAcquisitionPhase.mockRejectedValue(new Error("bad phase"));
    const user = userEvent.setup();
    renderWithClient(<AcquisitionsPage />);

    await user.click(await screen.findByRole("button", { name: /details/i }));
    const form = await screen.findByRole("form", {
      name: /set acquisition phase/i,
    });
    await user.click(within(form).getByRole("button", { name: /set phase/i }));

    expect(
      await screen.findByText(/could not set phase/i),
    ).toBeInTheDocument();
  });
});
