import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { FrameworkDetailPage } from "@/routes/FrameworkDetailPage";
import type {
  CatalogControl,
  CatalogSourceRow,
  ControlCatalog,
} from "@/types/catalog";

vi.mock("@/lib/api", () => ({ api: { getFramework: vi.fn() } }));

function sourceRow(
  overrides: Partial<CatalogSourceRow> = {},
): CatalogSourceRow {
  return {
    source_sha256: "a".repeat(64),
    sheet: "Requirements",
    row: 1461,
    source_id: 5.2,
    source_id_format: "0.00",
    interpreted_id: "5.20",
    kind: "fragment",
    values: {
      Statement: "Retained source statement.",
      "Audit / sanctions": null,
      Priority: "Priority 2",
      IaaS: "",
      PaaS: false,
      SaaS: 0,
      "Date text": "2026-06-25T00:00:00+00:00",
    },
    resolved_values: { "Audit / sanctions": "Existing" },
    provenance: {
      "U:anchor": "U1460",
      source_url: "https://example.com/source",
    },
    ...overrides,
  };
}

function control(overrides: Partial<CatalogControl> = {}): CatalogControl {
  return {
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
    ...overrides,
  };
}

function renderCatalog(controls: CatalogControl[]) {
  const catalog: ControlCatalog = {
    framework_id: "sample",
    framework_name: "Sample framework",
    version: "1",
    source: "https://example.com/framework",
    controls,
    families: ["Access"],
    category: "control",
    license_required: false,
    placeholder: false,
  };
  vi.mocked(api.getFramework).mockResolvedValue(catalog);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/frameworks/sample"]}>
        <Routes>
          <Route path="/frameworks/:id" element={<FrameworkDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function sourceCells(article: HTMLElement, column: string) {
  const heading = within(article).getByRole("rowheader", { name: column });
  return within(heading.closest("tr")!).getAllByRole("cell");
}

async function expandSourceRows(id = "AC-1", count = 1) {
  const user = userEvent.setup();
  const button = await screen.findByRole("button", {
    name: `Source rows for ${id} (${count})`,
  });
  await user.click(button);
  return { user, button };
}

describe("Framework source-row evidence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => vi.unstubAllGlobals());

  it("mounts evidence only on expansion and retains row order without adding controls", async () => {
    renderCatalog([
      control({
        source_rows: [sourceRow(), sourceRow({ row: 1462, kind: "clause" })],
      }),
    ]);
    const button = await screen.findByRole("button", {
      name: "Source rows for AC-1 (2)",
    });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(
      screen.queryByText("Retained source statement."),
    ).not.toBeInTheDocument();
    const { user } = await expandSourceRows("AC-1", 2);
    expect(button).toHaveAttribute("aria-expanded", "true");
    const panel = screen.getByRole("region", { name: "Source rows for AC-1" });
    expect(button).toHaveAttribute("aria-controls", panel.id);
    expect(
      within(panel)
        .getAllByRole("article")
        .map((item) => item.getAttribute("aria-label")),
    ).toEqual(["AC-1, source row 1461", "AC-1, source row 1462"]);
    expect(screen.getByText(/1 top-level controls/)).toBeInTheDocument();
    expect(
      within(screen.getByRole("region", { name: "Controls" })).getAllByRole(
        "listitem",
      ),
    ).toHaveLength(1);
    await user.click(button);
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("distinguishes physical blanks, empty text, false and zero from reviewed merge values", async () => {
    renderCatalog([control({ source_rows: [sourceRow()] })]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    const [original, resolved] = sourceCells(article, "Audit / sanctions");
    expect(original).toHaveTextContent("Blank (null)");
    expect(resolved).toHaveTextContent("Existing");
    expect(within(article).getByText("U1460")).toBeInTheDocument();
    expect(within(article).queryByText(/unknown/i)).not.toBeInTheDocument();
    expect(sourceCells(article, "IaaS")[0]).toHaveTextContent(
      'Empty text ("")',
    );
    expect(sourceCells(article, "PaaS")[0]).toHaveTextContent(
      "false (boolean)",
    );
    expect(sourceCells(article, "SaaS")[0]).toHaveTextContent("0 (number)");
    expect(sourceCells(article, "Priority")[0]).toHaveTextContent("Priority 2");
    expect(sourceCells(article, "Priority")[1]).toHaveTextContent(
      "No merge projection",
    );
    expect(sourceCells(article, "Date text")[0]).toHaveTextContent(
      "2026-06-25T00:00:00+00:00",
    );
  });

  it("leaves large source-row collections unmounted while collapsed", async () => {
    const rows = Array.from({ length: 1000 }, (_, index) =>
      sourceRow({ row: index + 1 }),
    );
    renderCatalog([control({ source_rows: rows })]);
    expect(
      await screen.findByRole("button", {
        name: "Source rows for AC-1 (1000)",
      }),
    ).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Retained source statement."),
    ).not.toBeInTheDocument();
  });

  it("lets keyboard users expand and close each control independently", async () => {
    renderCatalog([
      control({ source_rows: [sourceRow()] }),
      control({ id: "AC-2", source_rows: [sourceRow()] }),
    ]);
    const user = userEvent.setup();
    const first = await screen.findByRole("button", {
      name: "Source rows for AC-1 (1)",
    });
    const second = screen.getByRole("button", {
      name: "Source rows for AC-2 (1)",
    });
    first.focus();
    await user.keyboard("{Enter}");
    expect(
      screen.getByRole("article", { name: "AC-1, source row 1461" }),
    ).toBeInTheDocument();
    expect(second).toHaveAttribute("aria-expanded", "false");
    await user.keyboard(" ");
    expect(first).toHaveAttribute("aria-expanded", "false");
    expect(first).toHaveFocus();
    expect(screen.queryByRole("article")).not.toBeInTheDocument();
  });

  it("shows raw numeric identifiers, source format and interpreted text separately", async () => {
    const row = sourceRow();
    renderCatalog([control({ source_rows: [row] })]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    const field = (name: string) =>
      within(article).getByText(name, { selector: "dt" }).nextElementSibling;
    expect(field("Original identifier")).toHaveTextContent("5.2 (number)");
    expect(field("Source number format")).toHaveTextContent("0.00 (text)");
    expect(field("Interpreted identifier")).toHaveTextContent("5.20 (text)");
    expect(field("Sheet")).toHaveTextContent("Requirements");
    expect(field("Source SHA-256 (claimed)")).toHaveTextContent(
      row.source_sha256,
    );
    expect(field("Row kind")).toHaveTextContent("fragment");
  });

  it("renders every metadata value as literal text without constructing HTML", async () => {
    const literal =
      '<script>alert("source")</script><img src=x onerror=alert(1)>';
    const { container } = renderCatalog([
      control({
        source_rows: [
          sourceRow({
            sheet: literal,
            source_id: literal,
            source_id_format: literal,
            interpreted_id: literal,
            values: { [literal]: literal },
            resolved_values: { [literal]: literal },
            provenance: { [literal]: literal },
          }),
        ],
      }),
    ]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    expect(article.textContent?.split(literal)).toHaveLength(10);
    expect(container.querySelector("script, img, iframe")).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("preserves whitespace, scalar-looking strings and literal date text", async () => {
    const value = "  2026-06-25\n\ttext  ";
    renderCatalog([
      control({
        source_rows: [
          sourceRow({
            values: {
              "  Source column  ": value,
              Space: "\u00a0",
              Null: "null",
              Boolean: "false",
              Numeric: "005",
            },
            resolved_values: {},
            provenance: {},
          }),
        ],
      }),
    ]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    const header = within(article).getByRole("rowheader", {
      name: "Source column",
    });
    expect(header.textContent).toBe("  Source column  ");
    expect(header).toHaveStyle({ whiteSpace: "pre-wrap" });
    const text = within(article).getByText(
      (_, node) => node?.tagName === "SPAN" && node.textContent === value,
    );
    expect(text).toHaveStyle({ whiteSpace: "pre-wrap" });
    expect(sourceCells(article, "Space")[0]).toHaveTextContent(
      "whitespace-only text",
    );
    expect(sourceCells(article, "Null")[0]).toHaveTextContent("null (text)");
    expect(sourceCells(article, "Boolean")[0]).toHaveTextContent(
      "false (text)",
    );
    expect(sourceCells(article, "Numeric")[0]).toHaveTextContent("005 (text)");
    expect(
      within(article).getByText("No provenance provided."),
    ).toBeInTheDocument();
  });

  it("preserves explicit null, false, zero and resolved-only columns without inheriting keys", async () => {
    renderCatalog([
      control({
        source_rows: [
          sourceRow({
            values: { toString: null, A: null, B: null, C: null },
            resolved_values: { A: null, B: false, C: 0, D: "Anchor text" },
          }),
        ],
      }),
    ]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    expect(sourceCells(article, "toString")[1]).toHaveTextContent(
      "No merge projection",
    );
    expect(sourceCells(article, "A")[1]).toHaveTextContent("Blank (null)");
    expect(sourceCells(article, "B")[1]).toHaveTextContent("false (boolean)");
    expect(sourceCells(article, "C")[1]).toHaveTextContent("0 (number)");
    expect(sourceCells(article, "D")[0]).toHaveTextContent(
      "Column not retained",
    );
    expect(sourceCells(article, "D")[1]).toHaveTextContent("Anchor text");
  });

  it("opens source rows on nested enhancements without inventing extra control cards", async () => {
    renderCatalog([
      control({
        enhancements: [
          control({
            id: "AC-1(1)",
            enhancements: [
              control({ id: "AC-1(1)(a)", source_rows: [sourceRow()] }),
            ],
          }),
        ],
      }),
    ]);
    await expandSourceRows();
    expect(
      screen.getByRole("article", { name: "AC-1(1)(a), source row 1461" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/1 top-level controls/)).toBeInTheDocument();
  });

  it.each([undefined, []])(
    "keeps catalogs with no source rows usable: %j",
    async (rows) => {
      renderCatalog([control({ source_rows: rows })]);
      expect(
        await screen.findByText("Existing assessment content."),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: /Source rows/ }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByRole("link", { name: "Catalog source" }),
      ).toHaveAttribute("href", "https://example.com/framework");
    },
  );

  it("supports source rows whose optional metadata is omitted", async () => {
    renderCatalog([
      control({
        source_rows: [
          {
            source_sha256: "b".repeat(64),
            sheet: "Sheet",
            row: 1,
            source_id: null,
            kind: "aggregate",
            values: {},
          },
        ],
      }),
    ]);
    await expandSourceRows();
    expect(screen.getByText("Blank (null)")).toBeInTheDocument();
    expect(screen.getByText("No source columns retained.")).toBeInTheDocument();
    expect(screen.getByText("No provenance provided.")).toBeInTheDocument();
  });

  it.each([
    "javascript:alert(1)",
    "data:text/html,test",
    "file:///source.json",
    "//example.com/source",
    "https://",
    "https://user:password@example.com/source",
    "https://user@example.com/source",
    " https://example.com/source",
    "https://example.com/source ",
    "https:\n//example.com/source",
    "https://example.com/\tpath",
    "https://example.com/\u0000path",
    "https://example.com/\u007fpath",
  ])("keeps unsafe source URLs literal: %s", async (source) => {
    renderCatalog([
      control({
        source_rows: [sourceRow({ provenance: { source_url: source } })],
      }),
    ]);
    await expandSourceRows();
    const article = screen.getByRole("article", {
      name: "AC-1, source row 1461",
    });
    expect(within(article).queryByRole("link")).not.toBeInTheDocument();
    expect(
      within(article).getByText(
        (_, node) => node?.tagName === "SPAN" && node.textContent === source,
      ),
    ).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    "https://example.com/source?q=1#part",
    "HTTP://example.com/source",
    "https://example.com/a%20b",
  ])(
    "uses the safe source-link guard for explicit provenance URLs: %s",
    async (source) => {
      renderCatalog([
        control({
          source_rows: [
            sourceRow({
              values: { Link: source },
              provenance: { source_url: source },
            }),
          ],
        }),
      ]);
      await expandSourceRows();
      const article = screen.getByRole("article", {
        name: "AC-1, source row 1461",
      });
      const link = within(article).getByRole("link", { name: source });
      expect(link).toHaveAttribute("href", source);
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
      expect(link).toHaveAttribute("target", "_blank");
      expect(sourceCells(article, "Link")[0].querySelector("a")).toBeNull();
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});
