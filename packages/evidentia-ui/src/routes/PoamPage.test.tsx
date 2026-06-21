import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { PoamPage } from "@/routes/PoamPage";
import type { ControlGap } from "@/types/api";

// Mock the typed API client — the screen only reaches the backend through it.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listPoamItems: vi.fn(),
      updatePoamMilestone: vi.fn(),
      createPoamItem: vi.fn(),
      deletePoamItem: vi.fn(),
      addPoamMilestone: vi.fn(),
      replacePoamItem: vi.fn(),
      poamCalendar: vi.fn(),
    },
  };
});

// `api.listPoamItems` is still typed against the hand-authored `ControlGap`
// mirror, which does not model `poam_milestones`; widen locally so the
// fixture satisfies that seam. (The screen itself now uses the generated
// `ControlGap-Output`, which models the field directly.)
type PoamGapFixture = ControlGap & {
  poam_milestones?: Array<{
    id: string;
    description: string;
    target_date: string;
    status: string;
    owner?: string | null;
    reviewer?: string | null;
    evidence_ref?: string | null;
  }>;
};

const ITEM: PoamGapFixture = {
  id: "poam-1",
  framework: "soc2-tsc",
  control_id: "CC6.1",
  control_title: "Logical access controls",
  control_description: "Restrict logical access.",
  control_family: "CC6",
  gap_severity: "critical",
  implementation_status: "missing",
  gap_description: "MFA not enforced on admin accounts.",
  status: "open",
  equivalent_controls_in_inventory: [],
  cross_framework_value: [],
  remediation_guidance: "Enable MFA.",
  implementation_effort: "medium",
  priority_score: 9.5,
  jira_issue_key: null,
  servicenow_ticket_id: null,
  created_at: "2026-05-29T00:00:00Z",
  remediated_at: null,
  assigned_to: null,
  tags: [],
  poam_milestones: [
    {
      id: "ms-1",
      description: "Enable MFA on all admin accounts",
      target_date: "2026-09-30",
      status: "planned",
      owner: "alice@example.com",
      reviewer: null,
      evidence_ref: null,
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

// The calendar attention surface fires on every render of the page; give it a
// benign empty default so the pre-existing list/detail cases stay green. The
// `poamCalendar` API method is typed `Record<string, unknown>` server-side.
const EMPTY_CALENDAR: Record<string, unknown> = {
  today: "2026-06-20",
  overdue: [],
  due_soon: [],
};

describe("PoamPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedApi.poamCalendar.mockResolvedValue(EMPTY_CALENDAR);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the heading and an empty state when the store is empty", async () => {
    mockedApi.listPoamItems.mockResolvedValue({ total: 0, items: [] });

    renderWithClient(<PoamPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: /POA&M/i }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/No POA&M items yet/i)).toBeInTheDocument();
  });

  it("lists items and reveals milestone detail on selection", async () => {
    const user = userEvent.setup();
    mockedApi.listPoamItems.mockResolvedValue({ total: 1, items: [ITEM] });

    renderWithClient(<PoamPage />);

    // The item card surfaces its control id/title in the list.
    const card = await screen.findByRole("button", {
      name: /Logical access controls/i,
    });
    expect(card).toBeInTheDocument();
    // Milestone detail is not shown until the item is selected.
    expect(
      screen.queryByText(/Enable MFA on all admin accounts/i),
    ).toBeNull();

    await user.click(card);

    // Detail panel renders the milestone timeline + a forward-transition.
    const detail = await screen.findByLabelText(/Advance milestone/i);
    expect(
      screen.getByText(/Enable MFA on all admin accounts/i),
    ).toBeInTheDocument();
    // `planned` offers in_progress / overdue / completed as forward states.
    expect(
      within(detail).getByRole("button", { name: /In progress/i }),
    ).toBeInTheDocument();
  });

  it("advances a milestone through updatePoamMilestone and refreshes the list", async () => {
    const user = userEvent.setup();
    mockedApi.listPoamItems.mockResolvedValue({ total: 1, items: [ITEM] });
    mockedApi.updatePoamMilestone.mockResolvedValue(ITEM as ControlGap);

    renderWithClient(<PoamPage />);

    const card = await screen.findByRole("button", {
      name: /Logical access controls/i,
    });
    await user.click(card);

    const detail = await screen.findByLabelText(/Advance milestone/i);
    await user.click(
      within(detail).getByRole("button", { name: /Completed/i }),
    );

    await waitFor(() =>
      expect(mockedApi.updatePoamMilestone).toHaveBeenCalledWith(
        "poam-1",
        "ms-1",
        { status: "completed" },
      ),
    );
    // The list query is refetched after a successful transition.
    await waitFor(() =>
      expect(mockedApi.listPoamItems).toHaveBeenCalledTimes(2),
    );
  });

  it("creates a POA&M item through createPoamItem with the authored fields", async () => {
    const user = userEvent.setup();
    mockedApi.listPoamItems.mockResolvedValue({ total: 0, items: [] });
    mockedApi.createPoamItem.mockResolvedValue(ITEM as ControlGap);

    renderWithClient(<PoamPage />);

    // Wait for the initial (empty) list to settle.
    await screen.findByText(/No POA&M items yet/i);

    await user.type(screen.getByLabelText("Framework"), "soc2-tsc");
    await user.type(screen.getByLabelText("Control ID"), "CC6.1");
    await user.type(
      screen.getByLabelText("Control title"),
      "Logical access controls",
    );
    await user.type(
      screen.getByLabelText("Gap description"),
      "MFA not enforced on admin accounts.",
    );

    // Pick severity + status from the create-form pickers (scoped by their
    // radiogroup labels so the top filter chips are not matched).
    const sevGroup = screen.getByRole("radiogroup", { name: "Gap severity" });
    await user.click(within(sevGroup).getByRole("radio", { name: "Critical" }));
    const statusGroup = screen.getByRole("radiogroup", { name: "Gap status" });
    await user.click(within(statusGroup).getByRole("radio", { name: "Open" }));

    await user.click(screen.getByRole("button", { name: /create item/i }));

    await waitFor(() => expect(mockedApi.createPoamItem).toHaveBeenCalledTimes(1));
    expect(mockedApi.createPoamItem).toHaveBeenCalledWith(
      expect.objectContaining({
        framework: "soc2-tsc",
        control_id: "CC6.1",
        control_title: "Logical access controls",
        gap_description: "MFA not enforced on admin accounts.",
        gap_severity: "critical",
        status: "open",
      }),
    );
  });

  it("adds a milestone through addPoamMilestone from the detail panel", async () => {
    const user = userEvent.setup();
    mockedApi.listPoamItems.mockResolvedValue({ total: 1, items: [ITEM] });
    mockedApi.addPoamMilestone.mockResolvedValue(ITEM as ControlGap);

    renderWithClient(<PoamPage />);

    const card = await screen.findByRole("button", {
      name: /Logical access controls/i,
    });
    await user.click(card);

    const addForm = await screen.findByRole("form", { name: /add milestone/i });
    await user.type(
      within(addForm).getByLabelText("Description"),
      "Roll out hardware tokens",
    );
    const targetDate = within(addForm).getByLabelText(
      "Target date",
    ) as HTMLInputElement;
    await user.clear(targetDate);
    await user.type(targetDate, "2026-12-31");

    await user.click(
      within(addForm).getByRole("button", { name: /add milestone/i }),
    );

    await waitFor(() =>
      expect(mockedApi.addPoamMilestone).toHaveBeenCalledWith(
        "poam-1",
        expect.objectContaining({
          description: "Roll out hardware tokens",
          target_date: "2026-12-31",
          status: "planned",
        }),
      ),
    );
    // The list query is refetched after a successful add.
    await waitFor(() =>
      expect(mockedApi.listPoamItems).toHaveBeenCalledTimes(2),
    );
  });

  it("deletes the item through deletePoamItem after a confirm step", async () => {
    const user = userEvent.setup();
    mockedApi.listPoamItems.mockResolvedValue({ total: 1, items: [ITEM] });
    mockedApi.deletePoamItem.mockResolvedValue(undefined);

    renderWithClient(<PoamPage />);

    const card = await screen.findByRole("button", {
      name: /Logical access controls/i,
    });
    await user.click(card);

    // First click reveals the inline confirm; nothing is deleted yet.
    await user.click(await screen.findByRole("button", { name: "Delete item" }));
    expect(mockedApi.deletePoamItem).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /confirm delete/i }));

    await waitFor(() =>
      expect(mockedApi.deletePoamItem).toHaveBeenCalledWith("poam-1"),
    );
    // The list query is refetched after a successful delete.
    await waitFor(() =>
      expect(mockedApi.listPoamItems).toHaveBeenCalledTimes(2),
    );
  });

  it("fetches the calendar attention surface via poamCalendar", async () => {
    mockedApi.listPoamItems.mockResolvedValue({ total: 0, items: [] });
    mockedApi.poamCalendar.mockResolvedValue({
      today: "2026-06-20",
      overdue: [
        {
          milestone_id: "ms-9",
          poam_id: "poam-9",
          control_id: "soc2-tsc:CC7.2",
          target_date: "2026-05-01",
          status: "overdue",
          description: "Patch the EOL appliance",
        },
      ],
      due_soon: [],
    } as Record<string, unknown>);

    renderWithClient(<PoamPage />);

    await waitFor(() => expect(mockedApi.poamCalendar).toHaveBeenCalled());
    // The overdue milestone surfaces in the calendar section.
    expect(
      await screen.findByText(/Patch the EOL appliance/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/soc2-tsc:CC7\.2/i)).toBeInTheDocument();
  });
});
