import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ExplainPage } from "@/routes/ExplainPage";

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

// Mock the typed API client. listFrameworks + llmStatus are the only two
// methods ExplainPage queries on mount; explainControlUrl is a pure URL
// builder we keep real so the test exercises the actual query string.
vi.mock("@/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      listFrameworks: vi.fn(),
      llmStatus: vi.fn(),
    },
  };
});

import { api } from "@/lib/api";

// jsdom has no ResizeObserver; the Radix Switch (the "Bypass cache" toggle)
// constructs one on mount. Provide a no-op stub so the form renders. (The
// shared src/test/setup.ts doesn't polyfill it, and this file must not edit
// shared setup — see the seam-gap note in the agent report.)
if (!("ResizeObserver" in globalThis)) {
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

const listFrameworksMock = api.listFrameworks as ReturnType<typeof vi.fn>;
const llmStatusMock = api.llmStatus as ReturnType<typeof vi.fn>;

const FRAMEWORKS = {
  total: 2,
  frameworks: [
    {
      id: "soc2-tsc",
      name: "SOC 2 TSC",
      version: "2017",
      tier: "A",
      category: "audit",
      placeholder: "false",
      license_required: "none",
    },
    {
      id: "nist-800-53-rev5-mod",
      name: "NIST 800-53 Rev 5 Moderate",
      version: "5",
      tier: "A",
      category: "federal",
      placeholder: "false",
      license_required: "none",
    },
  ],
};

const LLM_CONFIGURED = {
  providers: { anthropic: { configured: true, source: "env" } },
  configured_model: "anthropic/claude-sonnet-4",
};

const LLM_UNCONFIGURED = {
  providers: { anthropic: { configured: false, source: null } },
  configured_model: "anthropic/claude-sonnet-4",
};

/** Render ExplainPage inside a fresh, retry-disabled QueryClient. */
function renderPage(ui: ReactElement = <ExplainPage />) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ExplainPage", () => {
  beforeEach(() => {
    listFrameworksMock.mockResolvedValue(FRAMEWORKS);
    llmStatusMock.mockResolvedValue(LLM_CONFIGURED);
  });

  afterEach(() => {
    demo.flag = false;
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("renders the form: heading, framework picker, control-id input, submit", async () => {
    renderPage();

    expect(
      screen.getByRole("heading", { name: /explain control/i }),
    ).toBeInTheDocument();

    // Framework pills populate from listFrameworks.
    expect(await screen.findByRole("radio", { name: /soc2-tsc/i })).toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: /nist-800-53-rev5-mod/i }),
    ).toBeInTheDocument();

    expect(screen.getByLabelText(/control id/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /^explain$/i }),
    ).toBeInTheDocument();
  });

  it("disables submit until a framework AND a control id are chosen", async () => {
    const user = userEvent.setup();
    renderPage();

    const submit = screen.getByRole("button", { name: /^explain$/i });
    expect(submit).toBeDisabled();

    // Control id alone is not enough.
    await user.type(screen.getByLabelText(/control id/i), "AC-2");
    expect(submit).toBeDisabled();

    // Picking a framework satisfies both conditions → enabled.
    await user.click(await screen.findByRole("radio", { name: /soc2-tsc/i }));
    await waitFor(() => expect(submit).toBeEnabled());
  });

  it("warns when no LLM provider is configured", async () => {
    llmStatusMock.mockResolvedValue(LLM_UNCONFIGURED);
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/no llm provider configured/i);
  });

  it("streams the explanation and renders it on a `done` SSE frame", async () => {
    const user = userEvent.setup();

    // Minimal one-shot SSE body: a `start` frame then a terminal `done`
    // frame carrying the full PlainEnglishExplanation payload.
    const body = [
      `data: ${JSON.stringify({ phase: "start", framework: "soc2-tsc", control_id: "CC6.1" })}\n\n`,
      `data: ${JSON.stringify({
        phase: "done",
        explanation: {
          framework_id: "soc2-tsc",
          control_id: "CC6.1",
          control_title: "Logical Access Controls",
          plain_english:
            "Restrict who can reach systems and data to only the people who need it.",
          why_it_matters:
            "Unrestricted access lets a stolen credential reach everything, turning one phished password into a full breach.",
          what_to_do: ["Enable SSO", "Require MFA", "Review access quarterly"],
          effort_estimate: "Medium — a few days of IdP configuration.",
          common_misconceptions: null,
          generation_context: { model: "anthropic/claude-sonnet-4" },
        },
      })}\n\n`,
    ].join("");

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    await user.click(await screen.findByRole("radio", { name: /soc2-tsc/i }));
    await user.type(screen.getByLabelText(/control id/i), "CC6.1");
    await user.click(screen.getByRole("button", { name: /^explain$/i }));

    // The explanation card renders the streamed payload.
    const heading = await screen.findByRole("heading", {
      name: /logical access controls/i,
    });
    const card = heading.closest("section") as HTMLElement;
    expect(within(card).getByText(/restrict who can reach systems/i)).toBeInTheDocument();
    expect(within(card).getByText(/enable sso/i)).toBeInTheDocument();
    expect(within(card).getByText(/require mfa/i)).toBeInTheDocument();

    // POSTed to the canonical explain URL (no refresh param when toggle off).
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/explain/soc2-tsc/CC6.1");
    expect(init?.method).toBe("POST");
  });

  it("in demo mode renders the baked explanation with ZERO fetch calls", async () => {
    demo.flag = true;
    const user = userEvent.setup();

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    renderPage();

    await user.click(await screen.findByRole("radio", { name: /soc2-tsc/i }));
    await user.type(screen.getByLabelText(/control id/i), "AC-2");
    await user.click(screen.getByRole("button", { name: /^explain$/i }));

    // The baked DEMO_EXPLANATION (Account Management) reaches the done state.
    const heading = await screen.findByRole("heading", {
      name: /account management/i,
    });
    const card = heading.closest("section") as HTMLElement;
    expect(
      within(card).getByText(/knowing who has accounts/i),
    ).toBeInTheDocument();

    // No backend was touched — the SSE stream was replayed from fixtures.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
