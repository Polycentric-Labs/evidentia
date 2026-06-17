import { render, screen } from "@testing-library/react";
import { MemoryRouter, Outlet } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "@/App";

// `IS_DEMO` / `IS_DEMO_FDA_INDEX` are build-time consts; mock the module behind
// mutable hoisted flags so each test can flip the build mode.
const demo = vi.hoisted(() => ({ isDemo: false, fdaIndex: false }));
vi.mock("@/lib/demo", () => ({
  get IS_DEMO() {
    return demo.isDemo;
  },
  get IS_DEMO_FDA_INDEX() {
    return demo.fdaIndex;
  },
}));

// Stub the route surfaces so this is a focused test of App's routing decision,
// not of each page's internals (HomePage / AppLayout mount their own API
// queries, which are out of scope here).
vi.mock("@/routes/FdaDemoPage", () => ({
  FdaDemoPage: () => <div>FDA_DEMO_PAGE</div>,
}));
vi.mock("@/routes/HomePage", () => ({
  HomePage: () => <div>HOME_PAGE</div>,
}));
vi.mock("@/components/layout/AppLayout", () => ({
  AppLayout: () => (
    <div data-testid="app-layout">
      <Outlet />
    </div>
  ),
}));

beforeEach(() => {
  demo.isDemo = false;
  demo.fdaIndex = false;
});

afterEach(() => {
  vi.clearAllMocks();
});

function renderAppAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("App routing — FDA-index build mode", () => {
  it("renders FdaDemoPage full-bleed as the index (outside AppLayout) when VITE_DEMO_FDA_INDEX is set", () => {
    demo.isDemo = true;
    demo.fdaIndex = true;

    renderAppAt("/");

    expect(screen.getByText("FDA_DEMO_PAGE")).toBeInTheDocument();
    // Full-bleed: the AppLayout chrome must not wrap the FDA index.
    expect(screen.queryByTestId("app-layout")).not.toBeInTheDocument();
  });

  it("serves the FDA page for any path in FDA-index mode (single-page subdomain)", () => {
    demo.isDemo = true;
    demo.fdaIndex = true;

    renderAppAt("/anything/deep");

    expect(screen.getByText("FDA_DEMO_PAGE")).toBeInTheDocument();
    expect(screen.queryByTestId("app-layout")).not.toBeInTheDocument();
  });

  it("renders HomePage inside AppLayout at the index in normal builds", () => {
    renderAppAt("/");

    expect(screen.getByTestId("app-layout")).toBeInTheDocument();
    expect(screen.getByText("HOME_PAGE")).toBeInTheDocument();
    expect(screen.queryByText("FDA_DEMO_PAGE")).not.toBeInTheDocument();
  });
});
