import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RiskGeneratePage } from "@/routes/RiskGeneratePage";

// Demo-mode toggle. `IS_DEMO` is a build-time const, so we mock the module
// behind a mutable flag the demo test flips on. Default false keeps every
// other test on the real fetch-streaming path. The flag lives in a hoisted
// block so the (hoisted) vi.mock factory can read it.
const demo = vi.hoisted(() => ({ flag: false }));
vi.mock("@/lib/demo", () => ({
  get IS_DEMO() {
    return demo.flag;
  },
}));

// Mock the typed API client. listGapReports is the only method
// RiskGeneratePage queries on mount (to populate the source-report picker).
vi.mock("@/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      listGapReports: vi.fn(),
    },
  };
});

import { api } from "@/lib/api";

const listGapReportsMock = api.listGapReports as ReturnType<typeof vi.fn>;

const REPORTS = {
  reports: [
    {
      key: "meridian-fintech-v2:baseline",
      organization: "Meridian Financial",
      total_gaps: 311,
      frameworks_analyzed: ["nist-800-53-rev5-moderate", "soc2-tsc"],
      mtime_iso: "2026-04-19T14:47:33.594669Z",
    },
  ],
};

/** Render RiskGeneratePage inside a fresh, retry-disabled QueryClient. */
function renderPage(ui: ReactElement = <RiskGeneratePage />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("RiskGeneratePage", () => {
  beforeEach(() => {
    listGapReportsMock.mockResolvedValue(REPORTS);
  });

  afterEach(() => {
    demo.flag = false;
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("renders the source-report picker from listGapReports", async () => {
    renderPage();

    expect(
      screen.getByRole("heading", { name: /risk generate/i }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/meridian financial/i),
    ).toBeInTheDocument();
  });

  it("in demo mode reaches the done summary with ZERO fetch calls", async () => {
    demo.flag = true;
    const user = userEvent.setup();

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    // Pick the source report, supply a context path, then generate.
    await user.click(await screen.findByText(/meridian financial/i));
    await user.type(
      screen.getByLabelText(/system-context\.yaml path/i),
      "/abs/path/to/system-context.yaml",
    );
    await user.click(screen.getByRole("button", { name: /^generate$/i }));

    // The baked stream resolves to a "Done" summary (5 generated, 0 failed).
    const summary = await screen.findByRole("alert");
    expect(summary.textContent).toMatch(/^Done/);
    // Text is split across JSX nodes, so match on the alert's full content.
    expect(summary.textContent).toMatch(/Generated 5 risk statements/);

    // No backend was touched — the SSE stream was replayed from fixtures.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
