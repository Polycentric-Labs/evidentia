import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, api } from "@/lib/api";
import type { EvidenceArtifact } from "@/lib/api";
import { EvidencePage } from "@/routes/EvidencePage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing (and its 409 `next_version`
// branch) still behaves.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      evidenceHistory: vi.fn(),
      evidenceVersion: vi.fn(),
      saveEvidence: vi.fn(),
    },
  };
});

const evidenceHistoryMock = vi.mocked(api.evidenceHistory);
const saveEvidenceMock = vi.mocked(api.saveEvidence);

const LINEAGE_ID = "8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e";

const ARTIFACT_V1: EvidenceArtifact = {
  id: "artifact-1",
  title: "MFA enforced on admin console",
  evidence_type: "configuration",
  source_system: "aws-iam",
  collected_by: "alice@example.com",
  collected_at: "2026-05-29T00:00:00Z",
  content_format: "json",
  content_hash: "abc123",
  description: "MFA is enforced on all admin accounts.",
  sufficiency: "sufficient",
  tags: ["soc2", "access-control"],
  lineage_id: LINEAGE_ID,
  version: 1,
};

const ARTIFACT_V2: EvidenceArtifact = {
  ...ARTIFACT_V1,
  id: "artifact-2",
  title: "MFA enforced on admin console (refreshed)",
  predecessor_id: "artifact-1",
  version: 2,
};

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("EvidencePage", () => {
  beforeEach(() => {
    evidenceHistoryMock.mockReset();
    saveEvidenceMock.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading and the pre-lookup empty state", () => {
    renderWithClient(<EvidencePage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Evidence" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Enter a lineage id above to load its version chain/i),
    ).toBeInTheDocument();
    // No lookup has been submitted yet.
    expect(evidenceHistoryMock).not.toHaveBeenCalled();
  });

  it("loads a lineage history and renders its versions", async () => {
    const user = userEvent.setup();
    evidenceHistoryMock.mockResolvedValue({
      total: 2,
      items: [ARTIFACT_V1, ARTIFACT_V2],
    });

    renderWithClient(<EvidencePage />);

    await user.type(screen.getByLabelText("Lineage id"), LINEAGE_ID);
    await user.click(screen.getByRole("button", { name: /load history/i }));

    await waitFor(() =>
      expect(evidenceHistoryMock).toHaveBeenCalledWith(LINEAGE_ID),
    );

    // Both versions surface in the chain.
    expect(
      await screen.findByText("MFA enforced on admin console"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("MFA enforced on admin console (refreshed)"),
    ).toBeInTheDocument();
    expect(screen.getByText(/2 versions in this lineage/i)).toBeInTheDocument();
  });

  it("shows a friendly message when the lineage id is not found (404)", async () => {
    const user = userEvent.setup();
    evidenceHistoryMock.mockRejectedValue(
      new ApiError("not found", 404, { detail: "unknown lineage" }),
    );

    renderWithClient(<EvidencePage />);

    await user.type(screen.getByLabelText("Lineage id"), "does-not-exist");
    await user.click(screen.getByRole("button", { name: /load history/i }));

    expect(
      await screen.findByText(/No evidence lineage found for that id/i),
    ).toBeInTheDocument();
  });

  it("saves evidence with the entered fields and shows the summary", async () => {
    const user = userEvent.setup();
    saveEvidenceMock.mockResolvedValue({
      artifact_id: "artifact-9",
      lineage_id: "lineage-9",
      version: 1,
      predecessor_id: null,
    });

    renderWithClient(<EvidencePage />);

    await user.type(
      screen.getByLabelText("Title"),
      "Quarterly access review export",
    );
    await user.type(screen.getByLabelText("Source system"), "okta");
    await user.type(
      screen.getByLabelText("Collected by"),
      "bob@example.com",
    );
    await user.type(
      screen.getByLabelText(/^Tags/),
      "soc2, access-control",
    );

    await user.click(screen.getByRole("button", { name: /save evidence/i }));

    await waitFor(() => expect(saveEvidenceMock).toHaveBeenCalledTimes(1));
    expect(saveEvidenceMock).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Quarterly access review export",
        evidence_type: "configuration",
        source_system: "okta",
        collected_by: "bob@example.com",
        content_format: "json",
        sufficiency: "unknown",
        version: 1,
        tags: ["soc2", "access-control"],
      }),
    );

    // The returned summary surfaces artifact id / lineage id / version.
    expect(await screen.findByText(/Evidence saved/i)).toBeInTheDocument();
    expect(screen.getByText("artifact-9")).toBeInTheDocument();
    expect(screen.getByText("lineage-9")).toBeInTheDocument();
  });

  it("surfaces the next_version hint on a 409 WORM collision", async () => {
    const user = userEvent.setup();
    saveEvidenceMock.mockRejectedValue(
      new ApiError("conflict", 409, {
        detail: {
          detail: "version 2 already exists for this lineage",
          next_version: 3,
        },
      }),
    );

    renderWithClient(<EvidencePage />);

    await user.type(screen.getByLabelText("Title"), "Re-saved evidence");
    await user.type(screen.getByLabelText("Source system"), "aws-iam");
    await user.type(
      screen.getByLabelText("Collected by"),
      "alice@example.com",
    );

    await user.click(screen.getByRole("button", { name: /save evidence/i }));

    // The hint sentence carries the next available version (the alert
    // title also says "Version already exists", so target the body text).
    expect(
      await screen.findByText(/Next available version is v3/i),
    ).toBeInTheDocument();
  });
});
