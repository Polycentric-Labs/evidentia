import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DemoPage } from "@/routes/DemoPage";

// AsciinemaPlayer is the global the self-hosted bundle exposes. jsdom never
// runs the real script, so we install a spyable stub the component picks up,
// and assert DemoPage drives it against the committed `/demo.cast` artifact.
const createSpy = vi.fn();

beforeEach(() => {
  createSpy.mockReset();
  (
    globalThis as unknown as { AsciinemaPlayer?: { create: typeof createSpy } }
  ).AsciinemaPlayer = { create: createSpy };
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete (globalThis as unknown as { AsciinemaPlayer?: unknown }).AsciinemaPlayer;
  // Clean up any vendor tags DemoPage injected so tests stay independent.
  document
    .querySelectorAll('[data-asciinema-player]')
    .forEach((n) => n.remove());
});

describe("DemoPage", () => {
  it("renders the heading + the player mount, with no backend fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<DemoPage />);

    // The page frames the recording for an evaluator.
    expect(
      screen.getByRole("heading", { name: /watch it run/i }),
    ).toBeInTheDocument();

    // A live region hosts the player; it carries an accessible label.
    expect(
      screen.getByRole("region", { name: /asciinema/i }),
    ).toBeInTheDocument();

    // It drives the self-hosted player against the committed cast — no network.
    await waitFor(() => expect(createSpy).toHaveBeenCalledTimes(1));
    const [src] = createSpy.mock.calls[0];
    expect(src).toBe("/demo.cast");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("injects the pinned, self-hosted player assets (no CDN)", async () => {
    // Without a pre-loaded global, DemoPage must inject the bundle itself.
    // (jsdom never executes the injected script, so `create` is never reached;
    // we only assert the injected <script>/<link> point at the vendored copy.)
    delete (globalThis as unknown as { AsciinemaPlayer?: unknown })
      .AsciinemaPlayer;

    render(<DemoPage />);

    const script = await waitFor(() => {
      const s = document.querySelector<HTMLScriptElement>(
        'script[data-asciinema-player]',
      );
      expect(s).not.toBeNull();
      return s as HTMLScriptElement;
    });
    const link = document.querySelector<HTMLLinkElement>(
      'link[data-asciinema-player]',
    );
    expect(script.getAttribute("src")).toBe(
      "/vendor/asciinema-player/3.15.1/asciinema-player.min.js",
    );
    expect(link?.getAttribute("href")).toBe(
      "/vendor/asciinema-player/3.15.1/asciinema-player.css",
    );
    // Air-gap-on-brand: assets are same-origin, never a CDN.
    expect(script.getAttribute("src") ?? "").not.toMatch(/https?:\/\//);
  });
});
