import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, type FrameworkListEntry } from "@/lib/api";
import { FrameworkDetailPage } from "@/routes/FrameworkDetailPage";
import { FrameworksPage } from "@/routes/FrameworksPage";
import type { ControlCatalog } from "@/types/catalog";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: { listFrameworks: vi.fn(), getFramework: vi.fn() },
  };
});

const mockedApi = vi.mocked(api);

function legacyCatalog(): ControlCatalog {
  return {
    framework_id: "sample",
    framework_name: "Sample framework",
    version: "6.0",
    source: "https://example.com/framework",
    category: "control",
    tier: "A",
    license_required: false,
    placeholder: false,
    families: ["Access"],
    controls: [
      {
        id: "AC-1",
        title: "Existing control",
        description: "Existing assessment content.",
        family: "Access",
        baseline_impact: [],
        enhancements: [],
        related_controls: [],
        assessment_objectives: [],
        examples: [],
        parameters: {},
        license_required: false,
        placeholder: false,
      },
    ],
  };
}

function legacyEntry(): FrameworkListEntry {
  return {
    id: "sample",
    name: "Sample framework",
    version: "6.0",
    tier: "A",
    category: "control",
    placeholder: "false",
    license_required: "false",
    text_depth: "headings",
  };
}

function renderPage(path = "/frameworks/sample") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/frameworks" element={<FrameworksPage />} />
          <Route path="/frameworks/:id" element={<FrameworkDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Framework currency", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedApi.getFramework.mockResolvedValue(legacyCatalog());
    mockedApi.listFrameworks.mockResolvedValue({
      total: 1,
      frameworks: [legacyEntry()],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("shows retirement and its notice before a framework is selected", async () => {
    const user = userEvent.setup();
    const entry = {
      ...legacyEntry(),
      status: "retired" as const,
      notes: "Retired on 2025-08-31. Existing references remain available.",
      verified_on: "2026-09-09",
      superseded_by: "next-framework",
    };
    mockedApi.listFrameworks.mockResolvedValue({
      total: 1,
      frameworks: [entry],
    });
    renderPage("/frameworks");

    expect(await screen.findByText("retired")).toBeInTheDocument();
    expect(screen.getByText(entry.notes)).toBeInTheDocument();
    expect(screen.getByText(/2026-09-09/)).toBeInTheDocument();
    expect(screen.getByText(/next-framework/)).toBeInTheDocument();
    expect(mockedApi.getFramework).not.toHaveBeenCalled();
    await user.click(screen.getByRole("link", { name: /Sample framework/ }));
    expect(await screen.findByText("Existing control")).toBeInTheDocument();
    expect(mockedApi.getFramework).toHaveBeenCalledWith("sample");
  });

  it("keeps old list and detail responses usable without assuming current status", async () => {
    const user = userEvent.setup();
    renderPage("/frameworks");
    expect(await screen.findByText("1 of 1 catalogs")).toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: /Sample framework/ }));
    expect(await screen.findByText("Existing control")).toBeInTheDocument();
    expect(
      screen.queryByText("current", { exact: true }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Publication notices" }),
    ).not.toBeInTheDocument();
  });

  it("shows catalog context and independent priority and control properties", async () => {
    const base = legacyCatalog();
    const catalog = {
      ...base,
      status: "superseded" as const,
      notes:
        "Use the successor for a new assessment; historical references are retained.",
      verified_on: "2026-09-09",
      superseded_by: "next/framework",
      controls: [
        {
          ...base.controls[0],
          priority: "P2",
          properties: {
            level: "L1",
            source_url: "https://example.com/control",
          },
        },
      ],
    };
    mockedApi.getFramework.mockResolvedValue(catalog);
    renderPage();

    expect(await screen.findByText(catalog.notes)).toBeInTheDocument();
    expect(screen.getByText("superseded")).toBeInTheDocument();
    expect(screen.getByText("2026-09-09")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "next/framework" }),
    ).toHaveAttribute("href", "/frameworks/next%2Fframework");
    expect(
      screen.getByRole("link", { name: "Catalog source" }),
    ).toHaveAttribute("href", catalog.source);
    const controls = screen.getByRole("region", { name: "Controls" });
    expect(within(controls).getByText("Priority: P2")).toBeInTheDocument();
    expect(within(controls).getByText("level")).toBeInTheDocument();
    expect(within(controls).getByText("L1")).toBeInTheDocument();
    expect(
      within(controls).getByRole("link", { name: "Control source" }),
    ).toHaveAttribute("href", "https://example.com/control");
  });

  it("keeps each CSA audit version separate from the catalog version", async () => {
    const catalog = {
      ...legacyCatalog(),
      audit_contexts: {
        "US-TX": {
          authority: "Texas CSA",
          version: "5.9.5",
          source_url: "https://example.com/texas",
          verified_on: "2026-09-01",
          valid_through: "2026-12-31",
          notes: "Texas audit scope only.",
        },
        "US-OR": {
          authority: "Oregon CSA",
          version: "5.9.4",
          source_url: "https://example.com/oregon",
          verified_on: "2026-08-12",
          valid_through: null,
        },
      },
    };
    mockedApi.getFramework.mockResolvedValue(catalog);
    renderPage();

    const section = await screen.findByRole("region", {
      name: "Audit contexts",
    });
    const texas = within(section).getByRole("article", { name: "US-TX" });
    const oregon = within(section).getByRole("article", { name: "US-OR" });
    expect(within(texas).getByText("Texas CSA")).toBeInTheDocument();
    expect(within(texas).getByText("5.9.5")).toBeInTheDocument();
    expect(within(texas).getByText("2026-12-31")).toBeInTheDocument();
    expect(
      within(texas).getByText("Texas audit scope only."),
    ).toBeInTheDocument();
    expect(within(oregon).getByText("5.9.4")).toBeInTheDocument();
    expect(within(oregon).getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText(/version 6.0/)).toBeInTheDocument();
    expect(
      within(section).getByText("Unlisted CSA audit versions are unknown."),
    ).toBeInTheDocument();
    expect(
      within(texas).getByRole("link", { name: "Audit source" }),
    ).toHaveAttribute("href", catalog.audit_contexts["US-TX"].source_url);
  });

  it.each(["2000-01-01", "2099-01-01"])(
    "keeps notices outside controls on %s",
    async (today) => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date(today));
      const notice = {
        id: "CIP-003-10",
        title: "Future security management",
        status: "approved-future" as const,
        source_url: "https://example.com/order",
        approved_on: "2025-04-17",
        published_on: "2025-05-01",
        order_effective_on: "2025-06-30",
        effective_on: "2028-07-01",
        inactive_on: "2030-01-01",
        superseded_by: "CIP-003-11",
        notes: "US scope. Check separately for phased requirements.",
      };
      const catalog = {
        ...legacyCatalog(),
        publication_notices: [
          notice,
          {
            id: "CIP-014-4",
            title: "Pending revision",
            status: "pending" as const,
            source_url: "https://example.com/pending",
          },
          {
            id: "CIP-003-9",
            title: "Earlier approved revision",
            status: "approved-superseded" as const,
            source_url: "https://example.com/earlier",
          },
        ],
      };
      mockedApi.getFramework.mockResolvedValue(catalog);
      renderPage();

      const notices = await screen.findByRole("region", {
        name: "Publication notices",
      });
      const future = within(notices).getByRole("article", { name: notice.id });
      expect(within(future).getByText("approved-future")).toBeInTheDocument();
      expect(within(notices).getByText("pending")).toBeInTheDocument();
      expect(
        within(notices).getByText("approved-superseded"),
      ).toBeInTheDocument();
      for (const value of [
        "2025-04-17",
        "2025-05-01",
        "2025-06-30",
        "2028-07-01",
        "2030-01-01",
        notice.notes,
        notice.superseded_by,
      ]) {
        expect(within(future).getByText(value)).toBeInTheDocument();
      }
      for (const label of [
        "Approved",
        "Published",
        "Order effective",
        "Applicable",
        "Inactive",
      ]) {
        expect(within(future).getByText(label)).toBeInTheDocument();
      }
      expect(
        within(future).getByRole("link", { name: "Publication source" }),
      ).toHaveAttribute("href", notice.source_url);
      const controls = screen.getByRole("region", { name: "Controls" });
      expect(
        within(controls).getByText("Existing control"),
      ).toBeInTheDocument();
      expect(within(controls).queryByText(notice.id)).not.toBeInTheDocument();
      expect(within(controls).getAllByRole("listitem")).toHaveLength(1);
      expect(screen.getByText(/1 top-level controls/)).toBeInTheDocument();
    },
  );

  it.each([
    "javascript:alert(1)",
    "data:text/html,test",
    "file:///catalog.json",
    "//example.com/source",
    "https://",
    "https://user:password@example.com/source",
    "https:\n//example.com/source",
  ])(
    "renders unsafe or malformed source references as text: %s",
    async (source) => {
      const base = legacyCatalog();
      const catalog = {
        ...base,
        source,
        audit_contexts: {
          "US-TX": {
            authority: "Texas CSA",
            version: "5.9.5",
            source_url: source,
            verified_on: "2026-09-01",
          },
        },
        publication_notices: [
          {
            id: "future",
            title: "Announced revision",
            status: "pending" as const,
            source_url: source,
          },
        ],
        controls: [{ ...base.controls[0], properties: { source_url: source } }],
      };
      mockedApi.getFramework.mockResolvedValue(catalog);
      renderPage();

      await screen.findByText("Existing control");
      expect(
        screen.queryByRole("link", { name: /source/i }),
      ).not.toBeInTheDocument();
      expect(
        screen.getAllByText(
          (_, node) => node?.tagName === "SPAN" && node.textContent === source,
        ),
      ).toHaveLength(4);
    },
  );
});
