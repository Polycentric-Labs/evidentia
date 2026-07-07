import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GapExportControl } from "@/components/gap/GapExportControl";
import * as downloadLib from "@/lib/download";
import type { GapAnalysisReport } from "@/types/api";

const REPORT: GapAnalysisReport = {
  id: "report-1",
  organization: "Acme Corp",
  frameworks_analyzed: ["soc2-tsc"],
  analyzed_at: "2026-05-29T00:00:00Z",
  total_controls_required: 10,
  total_controls_in_inventory: 6,
  total_gaps: 4,
  critical_gaps: 1,
  high_gaps: 1,
  medium_gaps: 1,
  low_gaps: 1,
  informational_gaps: 0,
  coverage_percentage: 60,
  gaps: [],
  efficiency_opportunities: [],
  prioritized_roadmap: [],
  inventory_source: null,
  evidentia_version: "0.10.7",
  notes: null,
};

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("GapExportControl", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let downloadSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    downloadSpy = vi
      .spyOn(downloadLib, "triggerBlobDownload")
      .mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders all engine-supported format options", () => {
    render(<GapExportControl report={REPORT} />);
    const select = screen.getByLabelText("Export format") as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toEqual([
      "json",
      "oscal-ar",
      "sarif",
      "ocsf",
      "ocsf-detection",
      "cyclonedx-vex",
      "csv",
      "markdown",
    ]);
  });

  it("posts the selected format + report and triggers a download", async () => {
    const user = userEvent.setup();
    const blob = new Blob(["[]"], { type: "application/sarif+json" });
    // A lightweight response stub (not `new Response(blob, …)`): jsdom reads a
    // Response body from a Blob via `Blob.stream()`, which jsdom does not
    // implement, emitting a noisy console error. The exporter only needs `ok`,
    // `headers.get(…)`, and `blob()`.
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({
        "Content-Type": "application/sarif+json",
        "Content-Disposition": 'attachment; filename="Acme-Corp.sarif"',
      }),
      blob: async () => blob,
    } as unknown as Response);

    render(<GapExportControl report={REPORT} />);
    await user.selectOptions(screen.getByLabelText("Export format"), "sarif");
    await user.click(screen.getByRole("button", { name: /download/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/gap/export");
    expect(init?.method).toBe("POST");
    const sentBody = JSON.parse(init?.body as string);
    expect(sentBody.format).toBe("sarif");
    expect(sentBody.report.id).toBe("report-1");

    await waitFor(() =>
      expect(downloadSpy).toHaveBeenCalledWith(
        expect.any(Blob),
        "Acme-Corp.sarif",
      ),
    );
    // No error surfaced.
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("surfaces the API error detail and does not download", async () => {
    const user = userEvent.setup();
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          detail: {
            error: "feature_unavailable",
            message:
              "Format 'ocsf' is unavailable: ocsf extra missing. Install the server's [ocsf] extra.",
          },
        },
        400,
      ),
    );

    render(<GapExportControl report={REPORT} />);
    await user.selectOptions(screen.getByLabelText("Export format"), "ocsf");
    await user.click(screen.getByRole("button", { name: /download/i }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("ocsf extra");
    expect(downloadSpy).not.toHaveBeenCalled();
  });
});
