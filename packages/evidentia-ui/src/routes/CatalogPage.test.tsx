import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError } from "@/lib/api";
import { CatalogPage } from "@/routes/CatalogPage";

// Mock the typed API client — the screen only reaches the backend through it.
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      catalogCrosswalk: vi.fn(),
      catalogWhere: vi.fn(),
      catalogLicenseInfo: vi.fn(),
      catalogImport: vi.fn(),
      catalogRemove: vi.fn(),
    },
  };
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

describe("CatalogPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the page heading", () => {
    renderWithClient(<CatalogPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: /Catalog/i }),
    ).toBeInTheDocument();
  });

  it("runs a Where lookup and renders the resolved fields", async () => {
    const user = userEvent.setup();
    mockedApi.catalogWhere.mockResolvedValue({
      source: "user-import",
      path: "/var/catalogs/my-framework.json",
      shadowed: true,
      tier: "C",
    });

    renderWithClient(<CatalogPage />);

    const input = screen.getByLabelText("Framework id", {
      selector: "#where-framework",
    });
    await user.type(input, "my-framework");
    // The Where section's submit button.
    await user.click(screen.getByRole("button", { name: /^Where$/i }));

    await waitFor(() =>
      expect(mockedApi.catalogWhere).toHaveBeenCalledWith("my-framework"),
    );
    expect(await screen.findByText("user-import")).toBeInTheDocument();
    expect(
      screen.getByText("/var/catalogs/my-framework.json"),
    ).toBeInTheDocument();
  });

  it("runs a License-info lookup and renders license + tier + url", async () => {
    const user = userEvent.setup();
    mockedApi.catalogLicenseInfo.mockResolvedValue({
      license: "CC-BY-4.0",
      tier: "B",
      url: "https://example.com/license",
    });

    renderWithClient(<CatalogPage />);

    const input = screen.getByLabelText("Framework id", {
      selector: "#license-framework",
    });
    await user.type(input, "iso-27001");
    await user.click(screen.getByRole("button", { name: /License info/i }));

    await waitFor(() =>
      expect(mockedApi.catalogLicenseInfo).toHaveBeenCalledWith("iso-27001"),
    );
    expect(await screen.findByText("CC-BY-4.0")).toBeInTheDocument();
    expect(
      screen.getByText("https://example.com/license"),
    ).toBeInTheDocument();
  });

  it("submits the import form with the entered fields", async () => {
    const user = userEvent.setup();
    mockedApi.catalogImport.mockResolvedValue({
      framework_id: "my-framework",
      controls: 12,
    });

    renderWithClient(<CatalogPage />);

    await user.type(
      screen.getByLabelText("Framework id", { selector: "#import-framework" }),
      "my-framework",
    );
    // `{{`/`}}` escape the userEvent keyboard-syntax braces → literal `{}`.
    await user.type(
      screen.getByLabelText(/Catalog content/i),
      '{{"id":"x"}',
    );
    await user.type(
      screen.getByLabelText(/Name \(optional\)/i),
      "My Framework",
    );

    await user.click(
      screen.getByRole("button", { name: /Import catalog/i }),
    );

    await waitFor(() =>
      expect(mockedApi.catalogImport).toHaveBeenCalledWith(
        expect.objectContaining({
          framework_id: "my-framework",
          content: '{"id":"x"}',
          format: "json",
          tier: "C",
          force: false,
          name: "My Framework",
        }),
      ),
    );
    expect(await screen.findByText(/Catalog imported/i)).toBeInTheDocument();
  });

  it("surfaces a 400 ApiError on import", async () => {
    const user = userEvent.setup();
    mockedApi.catalogImport.mockRejectedValue(
      new ApiError("import failed", 400, {
        detail: "Catalog already exists; use force=true to overwrite.",
      }),
    );

    renderWithClient(<CatalogPage />);

    await user.type(
      screen.getByLabelText("Framework id", { selector: "#import-framework" }),
      "dup-framework",
    );
    await user.type(
      screen.getByLabelText(/Catalog content/i),
      '{{"id":"x"}',
    );

    await user.click(
      screen.getByRole("button", { name: /Import catalog/i }),
    );

    expect(
      await screen.findByText(/Import rejected \(400\)/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Catalog already exists; use force=true to overwrite\./i),
    ).toBeInTheDocument();
  });
});
