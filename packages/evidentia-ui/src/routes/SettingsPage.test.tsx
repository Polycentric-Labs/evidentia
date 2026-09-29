import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { SettingsPage } from "@/routes/SettingsPage";

vi.mock("@/lib/api", () => ({
  api: {
    getConfig: vi.fn(),
    llmStatus: vi.fn(),
    doctorCheckAirGap: vi.fn(),
  },
}));

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <SettingsPage />
    </QueryClientProvider>,
  );
}

describe("Settings air-gap diagnostics", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getConfig).mockImplementation(() => new Promise(() => {}));
    vi.mocked(api.llmStatus).mockResolvedValue({
      providers: {},
      configured_model: "synthetic-local-model",
    });
  });

  afterEach(cleanup);

  it("describes a positive diagnostic as configuration only", async () => {
    vi.mocked(api.doctorCheckAirGap).mockResolvedValue({
      air_gapped: true,
      checks: [
        {
          subsystem: "ai_telemetry",
          status: "skipped",
          detail: "Dependency telemetry is not checked here.",
        },
      ],
    });
    renderPage();
    expect(await screen.findByText("configuration only")).toBeInTheDocument();
    expect(screen.getByText("not checked")).toBeInTheDocument();
    expect(screen.queryByText("air-gap ready")).not.toBeInTheDocument();
    expect(screen.getByText(/does not probe completions/)).toBeInTheDocument();
  });

  it("does not label a pending diagnostic as a leak", () => {
    vi.mocked(api.doctorCheckAirGap).mockImplementation(
      () => new Promise(() => {}),
    );
    renderPage();
    expect(screen.getByText("checking configuration")).toBeInTheDocument();
    expect(screen.queryByText("review configuration")).not.toBeInTheDocument();
    expect(screen.queryByText("would leak")).not.toBeInTheDocument();
  });

  it("shows an unavailable check without claiming a network verdict", async () => {
    vi.mocked(api.doctorCheckAirGap).mockRejectedValue(
      new Error("synthetic unavailable check"),
    );
    renderPage();
    expect(await screen.findByText("check unavailable")).toBeInTheDocument();
    expect(screen.queryByText("configuration only")).not.toBeInTheDocument();
    expect(screen.queryByText("would leak")).not.toBeInTheDocument();
  });
});
