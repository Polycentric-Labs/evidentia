import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConmonPage } from "@/routes/ConmonPage";

// Mock the API module. The ConMon screen lists cadences (read) and reaches
// REST parity with the `evidentia conmon` verbs: next/check/health (read-only
// computations), mark-completed (the one mutation), and dedup-list. We spread
// `ApiError` through from the real module so the page's `instanceof ApiError`
// error branch stays intact, and stub every method the page touches.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listConmonCadences: vi.fn(),
      conmonNext: vi.fn(),
      conmonCheck: vi.fn(),
      conmonHealth: vi.fn(),
      conmonSeries: vi.fn(),
      conmonMarkCompleted: vi.fn(),
      conmonDedupList: vi.fn(),
    },
  };
});

// Import after the mock factory so we get the mocked reference.
import { api, ApiError } from "@/lib/api";

const listConmonCadences = vi.mocked(api.listConmonCadences);
const conmonNext = vi.mocked(api.conmonNext);
const conmonCheck = vi.mocked(api.conmonCheck);
const conmonHealth = vi.mocked(api.conmonHealth);
const conmonSeries = vi.mocked(api.conmonSeries);
const conmonMarkCompleted = vi.mocked(api.conmonMarkCompleted);
const conmonDedupList = vi.mocked(api.conmonDedupList);

/**
 * Two sample cadence maps mirroring the API's flat string→(string|null)
 * shape: a fully-populated NIST cadence and one with a null `citation` to
 * exercise the muted em-dash path.
 */
const CADENCES = [
  {
    slug: "nist-800-53-rev5-ca7",
    framework: "nist-800-53-rev5",
    activity: "continuous-monitoring",
    frequency: "monthly",
    description:
      "Re-assess a control subset every month per the ISCM strategy.",
    citation: "NIST SP 800-53 Rev 5 CA-7 (Continuous Monitoring)",
  },
  {
    slug: "org-quarterly-review",
    framework: "internal",
    activity: "security-assessment",
    frequency: "quarterly",
    description: "Internal quarterly control review.",
    citation: null,
  },
];

function renderPage() {
  // retry: false so the error path resolves on the first rejection rather
  // than waiting out React Query's default backoff.
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <ConmonPage />
    </QueryClientProvider>,
  );
}

describe("ConmonPage", () => {
  beforeEach(() => {
    listConmonCadences.mockReset();
    conmonNext.mockReset();
    conmonCheck.mockReset();
    conmonHealth.mockReset();
    conmonSeries.mockReset();
    conmonMarkCompleted.mockReset();
    conmonDedupList.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading and each cadence's content", async () => {
    listConmonCadences.mockResolvedValue(CADENCES);

    renderPage();

    // Heading is present immediately (synchronous render).
    expect(
      screen.getByRole("heading", { name: /continuous monitoring/i }),
    ).toBeInTheDocument();

    // Cadence titles come from the `description` key.
    expect(
      await screen.findByText(
        "Re-assess a control subset every month per the ISCM strategy.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Internal quarterly control review."),
    ).toBeInTheDocument();

    // Slugs render as code subtitles; frequency renders as a badge.
    expect(screen.getByText("nist-800-53-rev5-ca7")).toBeInTheDocument();
    expect(screen.getByText("monthly")).toBeInTheDocument();
    expect(screen.getByText("quarterly")).toBeInTheDocument();

    // The citation value renders in the definition list.
    expect(
      screen.getByText("NIST SP 800-53 Rev 5 CA-7 (Continuous Monitoring)"),
    ).toBeInTheDocument();

    // The null citation surfaces as a muted em-dash, and a humanized
    // definition-list label is present.
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Citation").length).toBeGreaterThan(0);

    // The cadence cards are non-interactive (presentation only); the
    // interactive surface lives in the Actions section above them.
    const cadenceList = screen.getByLabelText("Cadences");
    expect(within(cadenceList).queryByRole("button")).toBeNull();

    // The ConMon action surface renders alongside the read-only list.
    expect(
      screen.getByRole("button", { name: /mark completed/i }),
    ).toBeInTheDocument();
  });

  it("shows the empty-state when no cadences are returned", async () => {
    listConmonCadences.mockResolvedValue([]);

    renderPage();

    expect(
      await screen.findByText(
        /no continuous-monitoring cadences are registered/i,
      ),
    ).toBeInTheDocument();
  });

  it("surfaces the error card when the request fails", async () => {
    listConmonCadences.mockRejectedValue(new Error("network down"));

    renderPage();

    await waitFor(() =>
      expect(
        screen.getByText(/could not fetch continuous-monitoring cadences/i),
      ).toBeInTheDocument(),
    );
  });

  it("computes the next-due date through conmonNext", async () => {
    const user = userEvent.setup();
    listConmonCadences.mockResolvedValue([]);
    conmonNext.mockResolvedValue({
      slug: "nist-800-53-rev5-ca7",
      framework: "nist-800-53-rev5",
      activity: "continuous-monitoring",
      frequency: "monthly",
      last_completed: "2026-06-01",
      next_due: "2026-07-01",
    });

    renderPage();

    await user.type(
      screen.getByLabelText("Cadence slug", {
        selector: "#conmon-next-slug",
      }),
      "nist-800-53-rev5-ca7",
    );
    await user.type(
      screen.getByLabelText("Last completed", {
        selector: "#conmon-next-last",
      }),
      "2026-06-01",
    );
    await user.click(screen.getByRole("button", { name: /compute next due/i }));

    await waitFor(() =>
      expect(conmonNext).toHaveBeenCalledWith({
        slug: "nist-800-53-rev5-ca7",
        last_completed: "2026-06-01",
      }),
    );
    // The computed next-due date renders in the result list.
    expect(await screen.findByText("2026-07-01")).toBeInTheDocument();
  });

  it("asserts a cadence series through conmonSeries", async () => {
    const user = userEvent.setup();
    listConmonCadences.mockResolvedValue([]);
    conmonSeries.mockResolvedValue({
      description:
        "One evidence artifact was collected in the window, with one gap of 14 days against an allowed 9.",
      series: {
        slug: "pci-dss-11-6-1-weekly",
        frequency: "weekly",
        interval_days: 7,
        tolerance_days: 2,
        verdict: "gapped",
        window_start: "2026-01-01T00:00:00Z",
        window_end: "2026-09-01T00:00:00Z",
        observations: [
          {
            collected_at: "2026-06-01T00:00:00Z",
            lineage_id: "lineage-0123456789abcdef",
            source_system: "aws-security-hub",
            version: 3,
          },
        ],
        gaps: [
          {
            after: "2026-06-01T00:00:00Z",
            before: "2026-06-15T00:00:00Z",
            days: 14,
            allowed_days: 9,
            boundary: false,
          },
        ],
      },
    });

    renderPage();

    await user.type(
      screen.getByLabelText("Cadence slug", {
        selector: "#conmon-series-slug",
      }),
      "pci-dss-11-6-1-weekly",
    );
    await user.click(screen.getByRole("button", { name: /assert series/i }));

    await waitFor(() =>
      expect(conmonSeries).toHaveBeenCalledWith(
        expect.objectContaining({
          slug: "pci-dss-11-6-1-weekly",
          lookback_days: 365,
          since: undefined,
          until: undefined,
          tolerance_days: undefined,
        }),
      ),
    );

    // The verdict badge and the plain-language description both render.
    expect(await screen.findByText("gapped")).toBeInTheDocument();
    expect(
      screen.getByText(
        "One evidence artifact was collected in the window, with one gap of 14 days against an allowed 9.",
      ),
    ).toBeInTheDocument();
    // The gap row shows the actual spacing against the allowed interval.
    expect(screen.getByText("14")).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
  });

  it("shows the error card when the series request fails", async () => {
    const user = userEvent.setup();
    listConmonCadences.mockResolvedValue([]);
    conmonSeries.mockRejectedValue(
      new ApiError("API POST /api/conmon/series failed (404)", 404, {
        detail: { error: "unknown_cadence", slug: "does-not-exist" },
      }),
    );

    renderPage();

    await user.type(
      screen.getByLabelText("Cadence slug", {
        selector: "#conmon-series-slug",
      }),
      "does-not-exist",
    );
    await user.click(screen.getByRole("button", { name: /assert series/i }));

    await waitFor(() =>
      expect(
        screen.getByText(/could not assert cadence series/i),
      ).toBeInTheDocument(),
    );
  });

  it("records a completion through conmonMarkCompleted and refreshes the list", async () => {
    const user = userEvent.setup();
    listConmonCadences.mockResolvedValue([]);
    conmonMarkCompleted.mockResolvedValue({
      slug: "nist-800-53-rev5-ca7",
      framework: "nist-800-53-rev5",
      activity: "continuous-monitoring",
      previous_last_completed: "2026-05-01",
      new_last_completed: "2026-06-01",
    });

    renderPage();

    await user.type(
      screen.getByLabelText("Cadence slug", {
        selector: "#conmon-mark-slug",
      }),
      "nist-800-53-rev5-ca7",
    );
    await user.type(
      screen.getByLabelText("Completed on", {
        selector: "#conmon-mark-when",
      }),
      "2026-06-01",
    );
    await user.click(screen.getByRole("button", { name: /mark completed/i }));

    await waitFor(() =>
      expect(conmonMarkCompleted).toHaveBeenCalledWith({
        slug: "nist-800-53-rev5-ca7",
        when: "2026-06-01",
      }),
    );
    // The cadences query is invalidated → refetched after the mutation.
    await waitFor(() => expect(listConmonCadences).toHaveBeenCalledTimes(2));
  });

  it("loads deduplicated alert entries through conmonDedupList", async () => {
    const user = userEvent.setup();
    listConmonCadences.mockResolvedValue([]);
    conmonDedupList.mockResolvedValue({
      count: 1,
      entries: [
        {
          cadence_slug: "nist-800-53-rev5-ca7",
          state: "overdue",
          last_dispatched_at: "2026-06-20T12:00:00Z",
          suppression_remaining_minutes: 90,
        },
      ],
    });

    renderPage();

    await user.click(
      screen.getByRole("button", { name: /load dedup entries/i }),
    );

    await waitFor(() => expect(conmonDedupList).toHaveBeenCalledTimes(1));
    // No slug / suppression-hours typed → both omitted from the call.
    expect(conmonDedupList).toHaveBeenCalledWith({
      slug: undefined,
      suppression_hours: undefined,
    });
    // The dedup entry renders, including its humanized field labels.
    expect(await screen.findByText("overdue")).toBeInTheDocument();
    expect(screen.getByText("Cadence Slug")).toBeInTheDocument();
  });
});
