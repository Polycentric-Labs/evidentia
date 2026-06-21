import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { SecurityFinding } from "@/lib/api";
import { CollectPage } from "@/routes/CollectPage";

// Mock the typed API client. Keep the real `ApiError` export intact so the
// page's `error instanceof ApiError` narrowing still behaves. `api.health` MUST
// be mocked — the §4(c) auth-gate reads it.
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      health: vi.fn(),
      collectAws: vi.fn(),
      collectGithub: vi.fn(),
      collectOkta: vi.fn(),
      collectSql: vi.fn(),
      collectDatabricks: vi.fn(),
      collectSnowflake: vi.fn(),
      collectVanta: vi.fn(),
      collectDrata: vi.fn(),
      collectBitsight: vi.fn(),
      collectSecurityscorecard: vi.fn(),
      collectOcsf: vi.fn(),
      collectConvert: vi.fn(),
      collectorsStatus: vi.fn(),
    },
  };
});

const healthMock = vi.mocked(api.health);
const collectGithubMock = vi.mocked(api.collectGithub);
const collectOcsfMock = vi.mocked(api.collectOcsf);
const collectConvertMock = vi.mocked(api.collectConvert);
const collectorsStatusMock = vi.mocked(api.collectorsStatus);

const FINDING: SecurityFinding = {
  id: "f-1",
  title: "Public S3 bucket",
  description: "Bucket allows public read.",
  severity: "high",
  source_system: "aws-security-hub",
  compliance_status: "fail",
  status: "active",
};

function healthValue(authConfigured: boolean) {
  return {
    status: "ok",
    version: "0.10.12",
    auth_configured: authConfigured,
  };
}

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("CollectPage", () => {
  beforeEach(() => {
    healthMock.mockReset();
    collectGithubMock.mockReset();
    collectOcsfMock.mockReset();
    collectConvertMock.mockReset();
    collectorsStatusMock.mockReset();
    // Default: collectors-status query resolves to an empty object so the
    // Status tab (rendered lazily) never rejects in unrelated tests.
    collectorsStatusMock.mockResolvedValue({});
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading", async () => {
    healthMock.mockResolvedValue(healthValue(true));

    renderWithClient(<CollectPage />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Collect" }),
    ).toBeInTheDocument();
  });

  it("disables the Run button and shows the gate note when auth is not configured", async () => {
    healthMock.mockResolvedValue(healthValue(false));

    renderWithClient(<CollectPage />);

    // The §4(c) note renders.
    expect(
      await screen.findByText(/collectors make credentialed external calls/i),
    ).toBeInTheDocument();

    // The credentialed Run button is disabled.
    const runButton = screen.getByRole("button", { name: /run collector/i });
    expect(runButton).toBeDisabled();
  });

  it("runs the matching collect* method when authed (GitHub)", async () => {
    const user = userEvent.setup();
    healthMock.mockResolvedValue(healthValue(true));
    collectGithubMock.mockResolvedValue([FINDING]);

    renderWithClient(<CollectPage />);

    // Wait until the auth query resolves and the Run button enables.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /run collector/i }),
      ).toBeEnabled(),
    );

    // Default selected collector is the first (AWS). Switch to GitHub.
    const picker = screen.getByRole("radiogroup", { name: "Collector" });
    await user.click(within(picker).getByRole("radio", { name: "GitHub" }));

    await user.type(screen.getByLabelText("Repository"), "octocat/hello");

    // Run -> confirmation step -> confirm.
    await user.click(screen.getByRole("button", { name: /run collector/i }));
    await user.click(
      await screen.findByRole("button", { name: /confirm — run collector/i }),
    );

    await waitFor(() => expect(collectGithubMock).toHaveBeenCalledTimes(1));
    expect(collectGithubMock).toHaveBeenCalledWith({ repo: "octocat/hello" });

    // The returned finding renders.
    expect(await screen.findByText("Public S3 bucket")).toBeInTheDocument();
    expect(screen.getByText(/1 finding returned/i)).toBeInTheDocument();
  });

  it("defaults the OCSF block_private_ips guard ON", async () => {
    const user = userEvent.setup();
    healthMock.mockResolvedValue(healthValue(true));

    renderWithClient(<CollectPage />);

    // Move to the OCSF tab.
    await user.click(screen.getByRole("tab", { name: /ocsf ingest/i }));
    // Switch to URL mode so the guard checkbox is visible.
    const modeGroup = await screen.findByRole("radiogroup", {
      name: "OCSF input mode",
    });
    await user.click(within(modeGroup).getByRole("radio", { name: "URL" }));

    const checkbox = (await screen.findByLabelText(
      /block private ips/i,
    )) as HTMLInputElement;
    expect(checkbox).toBeChecked();
  });

  it("submits OCSF inline content with block_private_ips defaulted ON for URL mode", async () => {
    const user = userEvent.setup();
    healthMock.mockResolvedValue(healthValue(true));
    collectOcsfMock.mockResolvedValue([FINDING]);

    renderWithClient(<CollectPage />);

    await user.click(screen.getByRole("tab", { name: /ocsf ingest/i }));

    // Inline-content mode (the default) is local-only — submit a JSON array.
    const textarea = await screen.findByLabelText("OCSF JSON");
    fireEvent.change(textarea, {
      target: { value: '[{ "class_uid": 2003 }]' },
    });

    await user.click(screen.getByRole("button", { name: /ingest ocsf/i }));

    await waitFor(() => expect(collectOcsfMock).toHaveBeenCalledTimes(1));
    expect(collectOcsfMock).toHaveBeenCalledWith({
      content: [{ class_uid: 2003 }],
    });
  });

  it("calls collectConvert from the Convert tab (local, not auth-gated)", async () => {
    const user = userEvent.setup();
    // Auth OFF — Convert is local-only and must stay enabled.
    healthMock.mockResolvedValue(healthValue(false));
    collectConvertMock.mockResolvedValue([{ class_uid: 2003 }]);

    renderWithClient(<CollectPage />);

    await user.click(screen.getByRole("tab", { name: /convert/i }));

    const textarea = await screen.findByLabelText("Findings JSON");
    fireEvent.change(textarea, {
      target: { value: '[{ "title": "x", "severity": "low" }]' },
    });

    const convertButton = screen.getByRole("button", { name: /^convert$/i });
    expect(convertButton).toBeEnabled();
    await user.click(convertButton);

    await waitFor(() => expect(collectConvertMock).toHaveBeenCalledTimes(1));
    expect(collectConvertMock).toHaveBeenCalledWith({
      content: [{ title: "x", severity: "low" }],
      to_format: "ocsf",
    });
  });
});
