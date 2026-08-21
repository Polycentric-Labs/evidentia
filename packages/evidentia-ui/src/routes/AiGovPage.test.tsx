import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, type AISystemEntry } from "@/lib/api";
import { AiGovPage } from "@/routes/AiGovPage";

// Mock the typed API client — the screen only reaches the backend through it.
// Every method the page can call is mocked; `listAiSystems` defaults to a bare
// empty array (the list endpoint returns no envelope) so the registry query
// resolves cleanly on mount.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      listAiSystems: vi.fn(),
      classifyAiSystem: vi.fn(),
      registerAiSystem: vi.fn(),
      getAiSystem: vi.fn(),
      updateAiSystem: vi.fn(),
      deleteAiSystem: vi.fn(),
      retireAiSystem: vi.fn(),
      categorizeFipsAiSystem: vi.fn(),
      setOmbImpactAiSystem: vi.fn(),
      setHighImpactAiSystem: vi.fn(),
      setPracticeAiSystem: vi.fn(),
    },
  };
});

// A registered system in the real backend's nested shape (descriptor /
// classification / system_id) — the page's normalizer reads this directly.
const SYSTEM: AISystemEntry = {
  system_id: "sys-1",
  descriptor: {
    name: "Credit adjudication assistant",
    purpose: "Recommends consumer-credit decisions for human review.",
  },
  classification: {
    descriptor_name: "Credit adjudication assistant",
    eu_ai_act_tier: "high",
  },
  owner: "ai.gov.lead@example.com",
  provider: "In-house team",
  deployment_status: "production",
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

describe("AiGovPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The list endpoint returns a bare array; default to empty so the
    // registry query resolves on mount.
    mockedApi.listAiSystems.mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the page heading", () => {
    renderWithClient(<AiGovPage />);

    expect(
      screen.getByRole("heading", { name: /AI governance/i }),
    ).toBeInTheDocument();
  });

  it("lists registered systems when listAiSystems resolves", async () => {
    mockedApi.listAiSystems.mockResolvedValue([SYSTEM]);

    renderWithClient(<AiGovPage />);

    expect(
      await screen.findByText(/Credit adjudication assistant/i),
    ).toBeInTheDocument();
    // The EU AI Act tier ("high") renders as a badge on the card.
    expect(screen.getAllByText(/high/i).length).toBeGreaterThan(0);
  });

  it("registers a system through registerAiSystem", async () => {
    const user = userEvent.setup();
    mockedApi.registerAiSystem.mockResolvedValue(SYSTEM);

    renderWithClient(<AiGovPage />);

    const registerForm = screen.getByRole("form", { name: /Register system/i });
    await user.type(
      within(registerForm).getByLabelText(/Name/i),
      "Credit adjudication assistant",
    );
    await user.type(
      within(registerForm).getByLabelText(/Purpose/i),
      "Recommends credit decisions.",
    );
    await user.type(
      within(registerForm).getByLabelText(/Owner/i),
      "ai.gov.lead@example.com",
    );
    await user.type(
      within(registerForm).getByLabelText(/Provider/i),
      "In-house team",
    );

    await user.click(
      within(registerForm).getByRole("button", { name: /Register system/i }),
    );

    await waitFor(() =>
      expect(mockedApi.registerAiSystem).toHaveBeenCalledTimes(1),
    );
    expect(mockedApi.registerAiSystem).toHaveBeenCalledWith(
      expect.objectContaining({
        owner: "ai.gov.lead@example.com",
        provider: "In-house team",
        deployment_status: "proposed",
        descriptor: expect.objectContaining({
          name: "Credit adjudication assistant",
          purpose: "Recommends credit decisions.",
        }),
      }),
    );
  });

  it("retires a system through retireAiSystem from the detail panel", async () => {
    const user = userEvent.setup();
    mockedApi.listAiSystems.mockResolvedValue([
      { ...SYSTEM, deployment_status: "pilot" },
    ]);
    mockedApi.retireAiSystem.mockResolvedValue(SYSTEM);

    renderWithClient(<AiGovPage />);

    // Open the system detail panel.
    const card = await screen.findByRole("button", {
      name: /System Credit adjudication assistant/i,
    });
    await user.click(card);

    const detail = await screen.findByLabelText(/System detail/i);
    await user.click(within(detail).getByRole("button", { name: /^Retire$/i }));

    await waitFor(() =>
      expect(mockedApi.retireAiSystem).toHaveBeenCalledTimes(1),
    );
    expect(mockedApi.retireAiSystem).toHaveBeenCalledWith("sys-1");
  });

  it("shows the OMB M-25-21 high-impact determination when present", async () => {
    mockedApi.listAiSystems.mockResolvedValue([
      {
        ...SYSTEM,
        omb_high_impact: {
          determination: "high_impact",
          bases: ["essential_services_access"],
          rationale: "Adjudicates access to consumer credit.",
        },
      },
    ]);
    const user = userEvent.setup();

    renderWithClient(<AiGovPage />);

    const card = await screen.findByRole("button", {
      name: /System Credit adjudication assistant/i,
    });
    await user.click(card);

    const detail = await screen.findByLabelText(/System detail/i);
    // The M-25-21 determination row label renders (exact text — the form
    // heading "Set high-impact AI (OMB M-25-21)" is a different string).
    expect(
      within(detail).getByText("High-impact AI (OMB M-25-21)"),
    ).toBeInTheDocument();
    // The determination badge + the consequence basis render (each also
    // appears as a form control, so assert presence, not uniqueness).
    expect(
      within(detail).getAllByText(/High-impact/i).length,
    ).toBeGreaterThan(0);
    expect(
      within(detail).getAllByText(/Essential-services access/i).length,
    ).toBeGreaterThan(0);
  });

  it("sets the high-impact determination through setHighImpactAiSystem", async () => {
    const user = userEvent.setup();
    mockedApi.listAiSystems.mockResolvedValue([SYSTEM]);
    mockedApi.setHighImpactAiSystem.mockResolvedValue(SYSTEM);

    renderWithClient(<AiGovPage />);

    const card = await screen.findByRole("button", {
      name: /System Credit adjudication assistant/i,
    });
    await user.click(card);

    const form = await screen.findByRole("form", {
      name: /Set high-impact AI/i,
    });
    // "High-impact" determination is the default; add a consequence basis.
    await user.click(
      within(form).getByRole("button", { name: /Essential-services access/i }),
    );
    await user.click(
      within(form).getByRole("button", { name: /^Set high-impact$/i }),
    );

    await waitFor(() =>
      expect(mockedApi.setHighImpactAiSystem).toHaveBeenCalledTimes(1),
    );
    expect(mockedApi.setHighImpactAiSystem).toHaveBeenCalledWith(
      "sys-1",
      expect.objectContaining({
        determination: "high_impact",
        bases: ["essential_services_access"],
      }),
    );
  });
});

// ── M-25-21 minimum practices (v0.12 GUI parity) ───────────────────────

describe("AiGovPage — set minimum practice", () => {
  // A system that already carries an M-25-21 assessment. The API 400s on a
  // practice update without one, so the console gates the form on it.
  const HIGH_IMPACT_SYSTEM: AISystemEntry = {
    ...SYSTEM,
    omb_high_impact: {
      determination: "high_impact",
      bases: ["essential_services_access"],
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function openDetail(system: AISystemEntry) {
    mockedApi.listAiSystems.mockResolvedValue([system]);
    renderWithClient(<AiGovPage />);
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", {
        name: /System Credit adjudication assistant/i,
      }),
    );
    await screen.findByLabelText(/System detail/i);
    return user;
  }

  it("offers the practice form once a high-impact assessment exists", async () => {
    await openDetail(HIGH_IMPACT_SYSTEM);

    expect(
      await screen.findByRole("form", { name: /set minimum practice/i }),
    ).toBeInTheDocument();
  });

  it("hides the form and explains why when no assessment exists", async () => {
    await openDetail(SYSTEM);

    await screen.findByRole("form", { name: /set high-impact AI/i });
    expect(
      screen.queryByRole("form", { name: /set minimum practice/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/before recording minimum practices/i),
    ).toBeInTheDocument();
  });

  it("submits the selected practice and status", async () => {
    mockedApi.setPracticeAiSystem.mockResolvedValue({
      system_id: "sys-1",
      entry: HIGH_IMPACT_SYSTEM,
      practice_compliance: {
        total: 7,
        implemented: 1,
        in_progress: 0,
        not_started: 0,
        waived: 0,
        missing: [],
        satisfied: false,
      },
      // Double cast: the fixture is the loose `AISystemEntry` shape the
      // registry verbs return, not a fully-populated registry entry. The
      // form does not read `entry` back — it invalidates and refetches.
    } as unknown as Awaited<ReturnType<typeof api.setPracticeAiSystem>>);
    const user = await openDetail(HIGH_IMPACT_SYSTEM);

    const form = await screen.findByRole("form", {
      name: /set minimum practice/i,
    });
    await user.click(
      within(form).getByRole("radio", { name: /human oversight/i }),
    );
    await user.click(within(form).getByRole("radio", { name: /in progress/i }));
    await user.click(within(form).getByRole("button", { name: /set practice/i }));

    await waitFor(() => {
      expect(mockedApi.setPracticeAiSystem).toHaveBeenCalledWith("sys-1", {
        practice: "human_oversight",
        status: "in_progress",
      });
    });
  });

  it("collects the CAIO waiver only when status is waived", async () => {
    const user = await openDetail(HIGH_IMPACT_SYSTEM);

    const form = await screen.findByRole("form", {
      name: /set minimum practice/i,
    });
    // Not shown for the default (implemented) status …
    expect(
      within(form).queryByLabelText(/issued by/i),
    ).not.toBeInTheDocument();

    // … and revealed by selecting `waived`, per M-25-21 §4(a)(ii).
    await user.click(within(form).getByRole("radio", { name: /^waived$/i }));
    expect(within(form).getByLabelText(/issued by/i)).toBeInTheDocument();
    expect(within(form).getByLabelText(/justification/i)).toBeInTheDocument();
  });

  it("surfaces a failed practice update", async () => {
    mockedApi.setPracticeAiSystem.mockRejectedValue(
      new Error("no M-25-21 assessment"),
    );
    const user = await openDetail(HIGH_IMPACT_SYSTEM);

    const form = await screen.findByRole("form", {
      name: /set minimum practice/i,
    });
    await user.click(within(form).getByRole("button", { name: /set practice/i }));

    expect(
      await screen.findByText(/could not set minimum practice/i),
    ).toBeInTheDocument();
  });
});
