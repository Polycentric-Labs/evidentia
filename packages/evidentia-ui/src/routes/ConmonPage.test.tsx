import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConmonPage } from "@/routes/ConmonPage";

// Mock the API module — the ConMon screen only calls listConmonCadences.
vi.mock("@/lib/api", () => ({
  api: {
    listConmonCadences: vi.fn(),
  },
}));

// Import after the mock factory so we get the mocked reference.
import { api } from "@/lib/api";

const listConmonCadences = vi.mocked(api.listConmonCadences);

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
    description: "Re-assess a control subset every month per the ISCM strategy.",
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

    // Read-only screen: there is no submit/save button.
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("shows the empty-state when no cadences are returned", async () => {
    listConmonCadences.mockResolvedValue([]);

    renderPage();

    expect(
      await screen.findByText(/no continuous-monitoring cadences are registered/i),
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
});
