import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecurityPostureBanner } from "@/components/common/SecurityPostureBanner";
import { api } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { health: vi.fn() } };
});

function renderWithClient(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

const mockedApi = vi.mocked(api);

describe("SecurityPostureBanner", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("shows the unsecured-deployment notice when auth is not configured", async () => {
    mockedApi.health.mockResolvedValue({
      status: "ok",
      version: "0.0.0",
      auth_configured: false,
    });
    renderWithClient(<SecurityPostureBanner />);
    expect(
      await screen.findByText(/unsecured deployment/i),
    ).toBeInTheDocument();
  });

  it("renders nothing when auth IS configured", async () => {
    mockedApi.health.mockResolvedValue({
      status: "ok",
      version: "0.0.0",
      auth_configured: true,
    });
    renderWithClient(<SecurityPostureBanner />);
    await waitFor(() => expect(mockedApi.health).toHaveBeenCalled());
    expect(
      screen.queryByText(/unsecured deployment/i),
    ).not.toBeInTheDocument();
  });
});
