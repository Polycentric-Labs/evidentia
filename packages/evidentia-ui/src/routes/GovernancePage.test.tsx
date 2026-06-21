import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  api,
  type EffectiveChallenge,
  type MetricWithStatus,
  type Workflow,
} from "@/lib/api";
import { GovernancePage } from "@/routes/GovernancePage";

// Mock the typed API client — the screen only reaches the backend through it.
// Every method the page can call is mocked; list methods default to an empty
// envelope so untouched tabs never throw when their queries fire.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listChallenges: vi.fn(),
      createChallenge: vi.fn(),
      getChallenge: vi.fn(),
      listMetrics: vi.fn(),
      createMetric: vi.fn(),
      observeMetric: vi.fn(),
      getMetric: vi.fn(),
      deleteMetric: vi.fn(),
      metricsReport: vi.fn(),
      listWorkflows: vi.fn(),
      runWorkflow: vi.fn(),
      advanceWorkflow: vi.fn(),
      getWorkflow: vi.fn(),
      workflowLog: vi.fn(),
      deleteWorkflow: vi.fn(),
      linesReport: vi.fn(),
    },
  };
});

const METRIC: MetricWithStatus = {
  id: "metric-1",
  name: "Failed-login rate",
  description: "Failed logins per 1,000 attempts.",
  kind: "kri",
  direction: "higher_is_worse",
  unit: "per 1,000 logins",
  owner_email: "owner@example.com",
  warning_threshold: 5,
  critical_threshold: 10,
  observations: [{ value: 3, observed_at: "2026-06-01" }],
  status: "watch",
};

const WORKFLOW: Workflow = {
  id: "wf-1",
  name: "Credit-model quarterly review",
  description: "Quarterly MRM review workflow.",
  initiator: "initiator@example.com",
  subject: "Credit model v3",
  status: "in_progress",
  steps: [
    {
      name: "MRM 2nd-line review",
      required_role: "MRM Director",
      status: "pending",
    },
  ],
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

describe("GovernancePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default every list method to an empty envelope so any tab's query that
    // fires (the active tab on mount, or after a click) resolves cleanly.
    mockedApi.listChallenges.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 0,
      items: [],
    });
    mockedApi.listMetrics.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 0,
      items: [],
    });
    mockedApi.listWorkflows.mockResolvedValue({
      total: 0,
      skip: 0,
      limit: 0,
      items: [],
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the heading and all four tab triggers", () => {
    renderWithClient(<GovernancePage />);

    expect(
      screen.getByRole("heading", { name: /Governance/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: /Challenges/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Metrics/i })).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: /Workflows/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: /Lines of Defense/i }),
    ).toBeInTheDocument();
  });

  it("lists metrics with a derived status badge on the Metrics tab", async () => {
    const user = userEvent.setup();
    mockedApi.listMetrics.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 0,
      items: [METRIC],
    });

    renderWithClient(<GovernancePage />);

    await user.click(screen.getByRole("tab", { name: /Metrics/i }));

    expect(
      await screen.findByText(/Failed-login rate/i),
    ).toBeInTheDocument();
    // The derived `status` ("watch") renders as a badge.
    expect(screen.getAllByText(/watch/i).length).toBeGreaterThan(0);
  });

  it("creates a challenge through createChallenge", async () => {
    const user = userEvent.setup();
    mockedApi.createChallenge.mockResolvedValue({} as EffectiveChallenge);

    renderWithClient(<GovernancePage />);

    // Challenges is the default tab. Fill the six required fields.
    await user.type(screen.getByLabelText(/Subject model id/i), "model-uuid");
    await user.type(
      screen.getByLabelText(/Challenger email/i),
      "mrm@example.com",
    );
    await user.type(screen.getByLabelText(/Challenger role/i), "MRM Director");
    // The date input — fill via its accessible label.
    const dateInput = screen.getByLabelText(/Challenge date/i);
    await user.clear(dateInput);
    await user.type(dateInput, "2026-06-15");
    await user.type(
      screen.getByLabelText(/^Topic$/i),
      "Methodology challenge",
    );
    await user.type(
      screen.getByLabelText(/Substance/i),
      "Questioned the feature-selection rationale.",
    );

    await user.click(
      screen.getByRole("button", { name: /Record challenge/i }),
    );

    await waitFor(() =>
      expect(mockedApi.createChallenge).toHaveBeenCalledTimes(1),
    );
    expect(mockedApi.createChallenge).toHaveBeenCalledWith(
      expect.objectContaining({
        subject_model_id: "model-uuid",
        challenger_email: "mrm@example.com",
        challenger_role: "MRM Director",
        challenge_date: "2026-06-15",
        challenge_topic: "Methodology challenge",
        challenge_substance: "Questioned the feature-selection rationale.",
        outcome: "pending",
      }),
    );
  });

  it("advances a workflow step through advanceWorkflow", async () => {
    const user = userEvent.setup();
    mockedApi.listWorkflows.mockResolvedValue({
      total: 1,
      skip: 0,
      limit: 0,
      items: [WORKFLOW],
    });
    mockedApi.advanceWorkflow.mockResolvedValue(WORKFLOW);

    renderWithClient(<GovernancePage />);

    await user.click(screen.getByRole("tab", { name: /Workflows/i }));

    // Open the workflow detail.
    const card = await screen.findByRole("button", {
      name: /Credit-model quarterly review/i,
    });
    await user.click(card);

    // The step advance control offers the legal successor states.
    const advance = await screen.findByLabelText(/Advance step/i);
    await user.click(
      within(advance).getByRole("button", { name: /Approved/i }),
    );

    await waitFor(() =>
      expect(mockedApi.advanceWorkflow).toHaveBeenCalledTimes(1),
    );
    expect(mockedApi.advanceWorkflow).toHaveBeenCalledWith(
      "wf-1",
      expect.objectContaining({
        step_index: 0,
        new_status: "approved",
      }),
    );
  });
});
