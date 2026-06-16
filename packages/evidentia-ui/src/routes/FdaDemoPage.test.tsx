import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FdaDemoPage } from "@/routes/FdaDemoPage";

// jsdom has no scrollIntoView; the reveal step calls it on the results node.
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FdaDemoPage", () => {
  it("renders the synthetic-data strip + 524B hero, with no backend fetch", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<FdaDemoPage />);

    // The tailored synthetic-data strip disclaims any live backend.
    expect(screen.getByText(/no live backend/i)).toBeInTheDocument();
    // The hero frames the 524B story and offers the run CTA.
    expect(
      screen.getByRole("heading", { name: /device cybersecurity submission/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /run 524b gap analysis/i }),
    ).toBeInTheDocument();
    // Results stay hidden until the analysis is run.
    expect(
      screen.queryByRole("heading", { name: /coverage against fda 524b/i }),
    ).not.toBeInTheDocument();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reveals gap-analysis, traceability + signed-artifact sections on run, still offline", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<FdaDemoPage />);
    fireEvent.click(
      screen.getByRole("button", { name: /run 524b gap analysis/i }),
    );

    // The run replays a baked client-side sequence (~2s); wait for the reveal.
    await waitFor(
      () =>
        expect(
          screen.getByRole("heading", { name: /coverage against fda 524b/i }),
        ).toBeInTheDocument(),
      { timeout: 5000 },
    );
    expect(
      screen.getByRole("heading", { name: /threat.*control.*evidence/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /signed, reproducible evidence/i }),
    ).toBeInTheDocument();

    // The CTA re-arms for another pass; nothing ever touched the network.
    expect(
      screen.getByRole("button", { name: /re-run 524b gap analysis/i }),
    ).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
