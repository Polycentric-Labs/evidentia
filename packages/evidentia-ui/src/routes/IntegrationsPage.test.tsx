import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { GapReportListResponse } from "@/lib/api";
import type { HealthResponse } from "@/types/api";
import { IntegrationsPage } from "@/routes/IntegrationsPage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing still behaves.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      listGapReports: vi.fn(),
      jiraStatus: vi.fn(),
      jiraStatusMap: vi.fn(),
      jiraPush: vi.fn(),
      jiraSync: vi.fn(),
      servicenowStatus: vi.fn(),
      servicenowPush: vi.fn(),
      tableauPublish: vi.fn(),
      powerbiPublish: vi.fn(),
    },
  };
});

const healthMock = vi.mocked(api.health);
const listGapReportsMock = vi.mocked(api.listGapReports);
const jiraStatusMock = vi.mocked(api.jiraStatus);
const jiraPushMock = vi.mocked(api.jiraPush);
const servicenowPushMock = vi.mocked(api.servicenowPush);

const REPORTS: GapReportListResponse = {
  total: 1,
  store_dir: "/tmp/gap-store",
  reports: [
    {
      key: "acme-soc2-2026",
      mtime_iso: "2026-06-20T12:00:00Z",
      size_bytes: 4096,
      organization: "Acme Corp",
      frameworks_analyzed: ["soc2"],
      total_gaps: 7,
      critical_gaps: 2,
      coverage_percentage: 71,
    },
  ],
};

function health(authConfigured: boolean): HealthResponse {
  return {
    auth_configured: authConfigured,
    status: "ok",
    version: "0.10.12",
  };
}

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("IntegrationsPage", () => {
  beforeEach(() => {
    healthMock.mockReset();
    listGapReportsMock.mockReset();
    jiraStatusMock.mockReset();
    jiraPushMock.mockReset();
    servicenowPushMock.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading", async () => {
    healthMock.mockResolvedValue(health(true));
    listGapReportsMock.mockResolvedValue(REPORTS);

    renderWithClient(<IntegrationsPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Integrations" }),
    ).toBeInTheDocument();
    // The report picker resolves with our seeded report.
    expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
  });

  it("disables write verbs and shows the auth note when auth is not configured, while read probes still work", async () => {
    const user = userEvent.setup();
    healthMock.mockResolvedValue(health(false));
    listGapReportsMock.mockResolvedValue(REPORTS);
    jiraStatusMock.mockResolvedValue({ configured: true, project_key: "GRC" });

    renderWithClient(<IntegrationsPage />);

    // The unsecured-deployment note renders in the top-level notice. (The
    // same text also appears under each disabled write button, so scope the
    // assertion to the notice alert to avoid a multiple-match.)
    const notice = await screen.findByLabelText("Authentication notice");
    expect(
      within(notice).getByText(/EVIDENTIA_API_AUTH_TOKEN_FILE/),
    ).toBeInTheDocument();

    // Every push / publish / sync button is disabled.
    const pushButtons = screen.getAllByRole("button", { name: "Push gaps" });
    for (const btn of pushButtons) {
      expect(btn).toBeDisabled();
    }
    const publishButtons = screen.getAllByRole("button", { name: "Publish" });
    for (const btn of publishButtons) {
      expect(btn).toBeDisabled();
    }
    expect(
      screen.getByRole("button", { name: "Sync status" }),
    ).toBeDisabled();

    // The read-only Jira "Test connection" probe still fires.
    const jiraSection = screen.getByLabelText("Jira integration");
    await user.click(
      within(jiraSection).getByRole("button", { name: /test connection/i }),
    );
    await waitFor(() => expect(jiraStatusMock).toHaveBeenCalledTimes(1));
    // Its result renders as structured text.
    expect(await screen.findByText(/Result — connection/i)).toBeInTheDocument();
  });

  it("fires a confirmed Jira push with the selected report key when authed", async () => {
    const user = userEvent.setup();
    healthMock.mockResolvedValue(health(true));
    listGapReportsMock.mockResolvedValue(REPORTS);
    jiraPushMock.mockResolvedValue({ created: 3, skipped: 0, errored: 0 });

    renderWithClient(<IntegrationsPage />);

    // Select the target report.
    await user.click(
      await screen.findByRole("radio", { name: /Acme Corp/ }),
    );

    // First click reveals the confirmation interstitial; the underlying
    // method has NOT been called yet.
    const jiraSection = screen.getByLabelText("Jira integration");
    await user.click(
      within(jiraSection).getByRole("button", { name: "Push gaps" }),
    );
    expect(jiraPushMock).not.toHaveBeenCalled();
    expect(
      within(jiraSection).getByText(/this writes to jira\. continue\?/i),
    ).toBeInTheDocument();

    // Confirm fires the push with the selected report key.
    await user.click(
      within(jiraSection).getByRole("button", { name: /confirm push gaps/i }),
    );
    await waitFor(() => expect(jiraPushMock).toHaveBeenCalledTimes(1));
    expect(jiraPushMock).toHaveBeenCalledWith("acme-soc2-2026");

    // The push outcome renders as structured text.
    expect(await screen.findByText(/Result — push/i)).toBeInTheDocument();
  });

  it("surfaces an ApiError from a ServiceNow push (503 not-configured)", async () => {
    const user = userEvent.setup();
    const { ApiError } = await import("@/lib/api");
    healthMock.mockResolvedValue(health(true));
    listGapReportsMock.mockResolvedValue(REPORTS);
    servicenowPushMock.mockRejectedValue(
      new ApiError("Service unavailable", 503, {
        detail: "ServiceNow configuration is invalid.",
      }),
    );

    renderWithClient(<IntegrationsPage />);

    await user.click(
      await screen.findByRole("radio", { name: /Acme Corp/ }),
    );

    const snSection = screen.getByLabelText("ServiceNow integration");
    await user.click(
      within(snSection).getByRole("button", { name: "Push gaps" }),
    );
    await user.click(
      within(snSection).getByRole("button", { name: /confirm push gaps/i }),
    );

    await waitFor(() => expect(servicenowPushMock).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText(/servicenow push failed/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/ServiceNow configuration is invalid/),
    ).toBeInTheDocument();
  });
});
