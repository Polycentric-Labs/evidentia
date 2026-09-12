import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { AppLayout } from "./AppLayout";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isError: false }),
}));
vi.mock("@/hooks/use-theme", () => ({
  useTheme: () => ({ theme: "light", toggle: vi.fn() }),
}));
vi.mock("@/components/common/SecurityPostureBanner", () => ({
  SecurityPostureBanner: () => null,
}));
vi.mock("@/lib/api", () => ({ api: {} }));
vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));

function CurrentPage() {
  return <h1>{useLocation().pathname}</h1>;
}

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="*" element={<CurrentPage />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("Console page navigation", () => {
  it("navigates from the mobile page selector without losing the route outlet", async () => {
    const user = userEvent.setup();
    renderAt("/collect");
    const pages = screen.getByRole("combobox", { name: "Page" });
    expect(pages).toHaveValue("/collect");
    await user.selectOptions(pages, "/retention");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "/retention",
    );
    expect(pages).toHaveValue("/retention");
    await user.selectOptions(pages, "/collect");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "/collect",
    );
  });

  it("selects the specific nested route and preserves its desktop current-page link", () => {
    renderAt("/ai-gov/acquisitions");
    expect(screen.getByRole("combobox", { name: "Page" })).toHaveValue(
      "/ai-gov/acquisitions",
    );
    expect(
      screen.getByRole("link", { name: /AI Acquisitions/ }),
    ).toHaveAttribute("aria-current", "page");
    expect(
      screen.getByRole("link", { name: /^AI Governance/ }),
    ).not.toHaveAttribute("aria-current");
  });
});
