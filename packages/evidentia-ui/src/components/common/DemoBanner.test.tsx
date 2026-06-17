import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DemoBanner } from "@/components/common/DemoBanner";

// IS_DEMO is a build-time const; mock it behind a mutable hoisted flag.
const demo = vi.hoisted(() => ({ isDemo: false }));
vi.mock("@/lib/demo", () => ({
  get IS_DEMO() {
    return demo.isDemo;
  },
}));

beforeEach(() => {
  demo.isDemo = false;
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("DemoBanner", () => {
  it("renders nothing in a normal (non-demo) build", () => {
    const { container } = render(<DemoBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("flags the build as a preview with partial functionality in demo builds", () => {
    demo.isDemo = true;
    render(<DemoBanner />);

    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(/preview/i);
    expect(banner).toHaveTextContent(/partial functionality/i);
    expect(banner).toHaveTextContent(/no live backend/i);
  });
});
