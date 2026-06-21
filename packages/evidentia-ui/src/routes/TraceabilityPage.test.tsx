import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError } from "@/lib/api";
import { TraceabilityPage } from "@/routes/TraceabilityPage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing still behaves.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      traceabilityEmit: vi.fn(),
    },
  };
});

const traceabilityEmitMock = vi.mocked(api.traceabilityEmit);

// A minimal-but-realistic UNSIGNED OSCAL profile the server returns. Encodes a
// single imported control + a threat-id prop so the derived summary can count.
const EMITTED_PROFILE: Record<string, unknown> = {
  profile: {
    uuid: "11111111-1111-1111-1111-111111111111",
    metadata: { title: "Coverage matrix", version: "1.0" },
    imports: [
      {
        href: "catalogs/nist-800-53-rev5-moderate.json",
        "include-controls": [{ "with-ids": ["AC-2"] }],
      },
    ],
    "back-matter": {
      resources: [
        {
          uuid: "res-1",
          props: [{ name: "threat-id", value: "T1078" }],
        },
      ],
    },
  },
};

function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

/** Fill the matrix header + one mapping row, then click Emit. */
async function buildAndEmit(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Title"), "Coverage matrix");
  await user.type(
    screen.getByLabelText("Framework id"),
    "nist-800-53-rev5-moderate",
  );
  await user.type(
    screen.getByLabelText("Catalog href"),
    "catalogs/nist-800-53-rev5-moderate.json",
  );

  // First (only) mapping row — fill the two required ids.
  await user.type(screen.getByLabelText("Mapping 1 control id"), "AC-2");
  await user.type(screen.getByLabelText("Mapping 1 threat id"), "T1078");

  // Pick the CWE framework + the "detects" relationship to confirm the picker
  // values flow into the emitted body.
  const fwGroup = screen.getByRole("radiogroup", {
    name: "Mapping 1 threat framework",
  });
  await user.click(within(fwGroup).getByRole("radio", { name: "CWE" }));
  const relGroup = screen.getByRole("radiogroup", {
    name: "Mapping 1 relationship",
  });
  await user.click(within(relGroup).getByRole("radio", { name: "Detects" }));

  await user.click(screen.getByRole("button", { name: /^emit$/i }));
}

describe("TraceabilityPage", () => {
  beforeEach(() => {
    traceabilityEmitMock.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading and the unsigned notice", () => {
    renderWithProviders(<TraceabilityPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Traceability" }),
    ).toBeInTheDocument();
    // The UI makes clear the emitted profile is unsigned (sign via the CLI).
    expect(
      screen.getByText(/this console emits an unsigned profile/i),
    ).toBeInTheDocument();
  });

  it("calls traceabilityEmit with the assembled matrix when Emit is clicked", async () => {
    const user = userEvent.setup();
    traceabilityEmitMock.mockResolvedValue({ ...EMITTED_PROFILE });

    renderWithProviders(<TraceabilityPage />);

    await buildAndEmit(user);

    await waitFor(() =>
      expect(traceabilityEmitMock).toHaveBeenCalledTimes(1),
    );
    expect(traceabilityEmitMock).toHaveBeenCalledWith({
      title: "Coverage matrix",
      framework_id: "nist-800-53-rev5-moderate",
      catalog_href: "catalogs/nist-800-53-rev5-moderate.json",
      crosswalk_source: "self-attested",
      mappings: [
        {
          control_id: "AC-2",
          threat_id: "T1078",
          threat_framework: "cwe",
          relationship: "detects",
          coverage: "full",
        },
      ],
    });
  });

  it("renders the emitted unsigned profile JSON + a derived summary", async () => {
    const user = userEvent.setup();
    traceabilityEmitMock.mockResolvedValue({ ...EMITTED_PROFILE });

    renderWithProviders(<TraceabilityPage />);

    await buildAndEmit(user);

    // The result panel + an "Unsigned" badge render.
    expect(
      await screen.findByRole("heading", { name: "Emitted OSCAL profile" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Unsigned")).toBeInTheDocument();

    // The derived summary counts the imported control + threat link.
    expect(screen.getByText(/1 control/i)).toBeInTheDocument();
    expect(screen.getByText(/1 threat link/i)).toBeInTheDocument();

    // The pretty-printed JSON includes the profile uuid.
    expect(
      screen.getByText(/11111111-1111-1111-1111-111111111111/),
    ).toBeInTheDocument();
  });

  it("surfaces a 400 ApiError (no mappings) clearly", async () => {
    const user = userEvent.setup();
    traceabilityEmitMock.mockRejectedValue(
      new ApiError("API POST /api/traceability/emit failed (400)", 400, {
        detail: "The matrix has no mappings — nothing to emit.",
      }),
    );

    renderWithProviders(<TraceabilityPage />);

    // The client-side guard normally blocks an empty matrix, so drive the
    // values directly (fireEvent.change — `userEvent.type` mis-parses braces
    // and is slower for this single-shot fill) and let the server 400 surface.
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "Empty matrix" },
    });
    fireEvent.change(screen.getByLabelText("Framework id"), {
      target: { value: "nist-800-53-rev5-moderate" },
    });
    fireEvent.change(screen.getByLabelText("Catalog href"), {
      target: { value: "catalogs/x.json" },
    });
    fireEvent.change(screen.getByLabelText("Mapping 1 control id"), {
      target: { value: "AC-2" },
    });
    fireEvent.change(screen.getByLabelText("Mapping 1 threat id"), {
      target: { value: "T1078" },
    });

    await user.click(screen.getByRole("button", { name: /^emit$/i }));

    expect(
      await screen.findByText(/could not emit the traceability matrix/i),
    ).toBeInTheDocument();
    // The 400 `detail` string is surfaced verbatim (not the generic message).
    expect(
      screen.getByText(/the matrix has no mappings/i),
    ).toBeInTheDocument();
  });
});
