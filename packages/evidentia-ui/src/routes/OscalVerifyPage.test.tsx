import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError } from "@/lib/api";
import { OscalVerifyPage } from "@/routes/OscalVerifyPage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing still behaves.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      oscalVerify: vi.fn(),
    },
  };
});

const oscalVerifyMock = vi.mocked(api.oscalVerify);

// A minimal-but-realistic AR document the operator would paste.
const AR_CONTENT = '{"assessment-results":{"uuid":"ar-1"}}';

// A clean (valid) verdict — every leg passes, offline so Sigstore is skipped.
const VALID_VERDICT: Record<string, unknown> = {
  overall_valid: true,
  has_verification_surface: true,
  digests_valid: true,
  signature_valid: null,
  offline: true,
  sigstore_checked: false,
  sigstore_status: "skipped (offline)",
  sigstore_signature_valid: null,
  errors: [],
  warnings: [],
  digest_checks: [
    {
      resource_uuid: "res-1",
      title: "finding-001",
      expected_digest: "abc123",
      actual_digest: "abc123",
      valid: true,
    },
  ],
};

// A tampered (invalid) verdict — a digest mismatch fails the overall check.
const INVALID_VERDICT: Record<string, unknown> = {
  overall_valid: false,
  has_verification_surface: true,
  digests_valid: false,
  signature_valid: null,
  offline: true,
  sigstore_checked: false,
  sigstore_status: "skipped (offline)",
  sigstore_signature_valid: null,
  errors: ["Digest mismatch for resource res-1."],
  warnings: [],
  digest_checks: [
    {
      resource_uuid: "res-1",
      title: "finding-001",
      expected_digest: "abc123",
      actual_digest: "deadbeef",
      valid: false,
    },
  ],
};

function renderWithProviders(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("OscalVerifyPage", () => {
  beforeEach(() => {
    oscalVerifyMock.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading and the verify-only notice", () => {
    renderWithProviders(<OscalVerifyPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "OSCAL Verify" }),
    ).toBeInTheDocument();
    // The UI makes clear this console verifies but never signs.
    expect(
      screen.getByText(/this console verifies — it never signs/i),
    ).toBeInTheDocument();
  });

  it("calls oscalVerify with the pasted content when Verify is clicked", async () => {
    const user = userEvent.setup();
    oscalVerifyMock.mockResolvedValue({ ...VALID_VERDICT });

    renderWithProviders(<OscalVerifyPage />);

    // Set the JSON directly (`{`/`}` are special key-descriptors in
    // userEvent.type, and the date-input lesson applies — jsdom doesn't free-type
    // braces reliably).
    fireEvent.change(screen.getByLabelText(/oscal assessment result/i), {
      target: { value: AR_CONTENT },
    });
    await user.click(screen.getByRole("button", { name: /verify/i }));

    await waitFor(() => expect(oscalVerifyMock).toHaveBeenCalledTimes(1));
    expect(oscalVerifyMock).toHaveBeenCalledWith({ content: AR_CONTENT });
  });

  it("renders the positive verdict for a valid result", async () => {
    const user = userEvent.setup();
    oscalVerifyMock.mockResolvedValue({ ...VALID_VERDICT });

    renderWithProviders(<OscalVerifyPage />);

    fireEvent.change(screen.getByLabelText(/oscal assessment result/i), {
      target: { value: AR_CONTENT },
    });
    await user.click(screen.getByRole("button", { name: /verify/i }));

    // Overall verdict badge + a matching digest row.
    expect(await screen.findByText("Valid")).toBeInTheDocument();
    expect(screen.getByText("match")).toBeInTheDocument();
    // The offline Sigstore leg is reported as skipped, not a failure.
    expect(screen.getByText(/skipped \(offline\)/i)).toBeInTheDocument();
  });

  it("renders the negative verdict for a tampered result", async () => {
    const user = userEvent.setup();
    oscalVerifyMock.mockResolvedValue({ ...INVALID_VERDICT });

    renderWithProviders(<OscalVerifyPage />);

    fireEvent.change(screen.getByLabelText(/oscal assessment result/i), {
      target: { value: AR_CONTENT },
    });
    await user.click(screen.getByRole("button", { name: /verify/i }));

    expect(await screen.findByText("Invalid")).toBeInTheDocument();
    // The digest mismatch surfaces as a failing row + an error line.
    expect(screen.getByText("mismatch")).toBeInTheDocument();
    expect(
      screen.getByText(/digest mismatch for resource res-1/i),
    ).toBeInTheDocument();
  });

  it("surfaces a 400 ApiError (unparseable AR) clearly", async () => {
    const user = userEvent.setup();
    oscalVerifyMock.mockRejectedValue(
      new ApiError("API POST /api/oscal/verify failed (400)", 400, {
        detail: "Content is not valid JSON: Expecting value (line 1).",
      }),
    );

    renderWithProviders(<OscalVerifyPage />);

    await user.type(
      screen.getByLabelText(/oscal assessment result/i),
      "not json",
    );
    await user.click(screen.getByRole("button", { name: /verify/i }));

    expect(
      await screen.findByText(/could not verify the assessment result/i),
    ).toBeInTheDocument();
    // The 400 `detail` string is surfaced verbatim (not the generic message).
    expect(
      screen.getByText(/content is not valid json/i),
    ).toBeInTheDocument();
  });
});
