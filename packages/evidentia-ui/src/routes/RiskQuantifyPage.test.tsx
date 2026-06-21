import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/api";
import { RiskQuantifyPage } from "@/routes/RiskQuantifyPage";

// Mock the typed API client. `riskQuantify` is the only method the page
// calls; keep the real `ApiError` so the 400/422 surfacing path is exercised.
vi.mock("@/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      riskQuantify: vi.fn(),
    },
  };
});

import { api } from "@/lib/api";

const riskQuantifyMock = api.riskQuantify as ReturnType<typeof vi.fn>;

/** Render RiskQuantifyPage inside a fresh, retry-disabled QueryClient. */
function renderWithClient(ui: ReactElement = <RiskQuantifyPage />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

/** Fill scenario 1's required name + description (factors come pre-seeded). */
async function fillScenario(
  user: ReturnType<typeof userEvent.setup>,
  { name }: { name: string },
) {
  await user.type(screen.getByLabelText(/^Name$/i), name);
  await user.type(
    screen.getByLabelText(/^Description$/i),
    "Threat actor exploits weak control, causing direct + downstream loss.",
  );
}

describe("RiskQuantifyPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the heading", () => {
    renderWithClient();
    expect(
      screen.getByRole("heading", { name: /risk quantify/i }),
    ).toBeInTheDocument();
  });

  it("submits the entered scenario to riskQuantify with the FAIR factor shape", async () => {
    const user = userEvent.setup();
    riskQuantifyMock.mockResolvedValue({
      method: "open-fair",
      scenario_count: 1,
      total_ale: 180000,
      scenarios: [
        {
          id: "s1",
          name: "Credential stuffing",
          ale: 180000,
          lef: 3.6,
          loss_magnitude: 50000,
          risk_category: "high",
        },
      ],
    });

    renderWithClient();

    await fillScenario(user, { name: "Credential stuffing" });
    await user.click(
      screen.getByRole("button", { name: /quantify risk/i }),
    );

    await waitFor(() => expect(riskQuantifyMock).toHaveBeenCalledTimes(1));

    const body = riskQuantifyMock.mock.calls[0][0];
    expect(body.method).toBe("open-fair");
    expect(body.scenarios).toHaveLength(1);
    expect(body.scenarios[0]).toMatchObject({
      name: "Credential stuffing",
      // The seeded scalar defaults parse to numbers, not strings.
      primary_loss: 50000,
      secondary_loss: 0,
      tef: 12,
      vulnerability: 0.3,
    });
  });

  it("renders total_ale for an open-fair result", async () => {
    const user = userEvent.setup();
    // Use a total distinct from the per-scenario ALE so the total assertion
    // is unambiguous (two scenarios → one $250,000 total, no $250,000 leaf).
    riskQuantifyMock.mockResolvedValue({
      method: "open-fair",
      scenario_count: 1,
      total_ale: 250000,
      scenarios: [
        {
          id: "s1",
          name: "Credential stuffing",
          ale: 180000,
          lef: 3.6,
          loss_magnitude: 50000,
          risk_category: "high",
        },
      ],
    });

    renderWithClient();

    await fillScenario(user, { name: "Credential stuffing" });
    await user.click(
      screen.getByRole("button", { name: /quantify risk/i }),
    );

    // The total ALE renders in the result header; "$250,000" appears only there.
    const total = await screen.findByText(/\$250,000/);
    expect(total).toBeInTheDocument();
    expect(screen.getByText(/Total ALE/i)).toBeInTheDocument();
  });

  it("surfaces a 422 ApiError as an invalid-request alert", async () => {
    const user = userEvent.setup();
    riskQuantifyMock.mockRejectedValue(
      new ApiError("validation failed", 422, {
        detail: [{ loc: ["body", "scenarios", 0, "tef"], msg: "field required" }],
      }),
    );

    renderWithClient();

    await fillScenario(user, { name: "Bad scenario" });
    await user.click(
      screen.getByRole("button", { name: /quantify risk/i }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/Invalid request \(HTTP 422\)/);
    expect(alert.textContent).toMatch(/field required/);
  });
});
