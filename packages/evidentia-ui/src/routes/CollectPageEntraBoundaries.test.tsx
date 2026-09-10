import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import {
  DEMO_ENTRA_M365_PARTIAL,
  DEMO_ENTRA_M365_UNAVAILABLE,
} from "@/lib/demo/fixtures";
import { CollectPage } from "@/routes/CollectPage";
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, health: vi.fn(), collectEntraM365: vi.fn() },
  };
});
const health = vi.mocked(api.health);
const collect = vi.mocked(api.collectEntraM365);
const clients: QueryClient[] = [];
const LIMIT = 4_194_304;
const verified = (auth = true) => ({
  status: "ok",
  version: "synthetic",
  auth_configured: auth,
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
async function openForm() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  clients.push(client);
  render(
    <QueryClientProvider client={client}>
      <CollectPage />
    </QueryClientProvider>,
  );
  await userEvent.click(screen.getByRole("tab", { name: "Entra/M365" }));
  fireEvent.change(screen.getByLabelText("Tenant label"), {
    target: { value: "synthetic-review" },
  });
  await waitFor(() => expect(health).toHaveBeenCalled());
}
async function dlpOnly() {
  for (const checkbox of screen.getAllByRole("checkbox")) {
    if (checkbox !== screen.getByRole("checkbox", { name: "DLP export" }))
      await userEvent.click(checkbox);
  }
}
function submit() {
  const form = screen.getByLabelText("Tenant label").closest("form");
  if (!form) throw new Error("Missing form");
  fireEvent.submit(form);
}
function fileOf(
  content: string | Uint8Array<ArrayBuffer>,
  reader?: Promise<ArrayBuffer>,
) {
  const bytes =
    typeof content === "string" ? new TextEncoder().encode(content) : content;
  const file = new File([bytes], "synthetic.json", {
    type: "application/json",
  });
  const read = vi.fn().mockReturnValue(reader ?? Promise.resolve(bytes.buffer));
  Object.defineProperty(file, "arrayBuffer", { value: read });
  return { file, read };
}
async function upload(file: File) {
  await userEvent.upload(screen.getByLabelText("DLP JSON export"), file);
}
beforeEach(() => {
  health.mockReset().mockResolvedValue(verified());
  collect
    .mockReset()
    .mockResolvedValue(structuredClone(DEMO_ENTRA_M365_UNAVAILABLE));
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("Unexpected network");
    }),
  );
});
afterEach(() => {
  cleanup();
  for (const client of clients.splice(0)) client.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
describe("Entra/M365 auth and upload boundaries", () => {
  it.each([false, new Error("synthetic refresh refusal")])(
    "rechecks the current response and sends no Graph POST: %s",
    async (outcome) => {
      await openForm();
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Collect Entra/M365" }),
        ).toBeEnabled(),
      );
      const pending = deferred<ReturnType<typeof verified>>();
      health.mockReturnValueOnce(pending.promise);
      submit();
      await waitFor(() => expect(health).toHaveBeenCalledTimes(2));
      expect(collect).not.toHaveBeenCalled();
      await act(async () => {
        if (outcome instanceof Error) pending.reject(outcome);
        else pending.resolve(verified(outcome));
      });
      expect(
        await screen.findByText(
          /Graph collection requires current API authentication/,
        ),
      ).toBeInTheDocument();
      expect(collect).not.toHaveBeenCalled();
    },
  );

  it("DLP-only does not require a successful health request or trigger a refresh", async () => {
    health.mockRejectedValue(new Error("synthetic health unavailable"));
    await openForm();
    await dlpOnly();
    const before = health.mock.calls.length;
    submit();
    await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
    expect(health).toHaveBeenCalledTimes(before);
    expect(collect.mock.calls[0][0]).toEqual({
      tenant_label: "synthetic-review",
      capabilities: ["dlp-export"],
      lookback_days: 30,
      max_items: 10000,
      max_pages: 100,
    });
  });

  it.each(["resolve", "reject"] as const)(
    "a stale file %s cannot replace the latest selection",
    async (settlement) => {
      await openForm();
      await dlpOnly();
      const old = deferred<ArrayBuffer>();
      await upload(fileOf("old", old.promise).file);
      submit();
      expect(collect).not.toHaveBeenCalled();
      await upload(fileOf('{"new":"selected"}').file);
      await waitFor(() =>
        expect(screen.getByLabelText("DLP export format")).toBeEnabled(),
      );
      await act(async () => {
        if (settlement === "resolve")
          old.resolve(new TextEncoder().encode("old").buffer);
        else old.reject(new Error("old"));
      });
      submit();
      await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
      expect(collect.mock.calls[0][0].dlp_content).toBe('{"new":"selected"}');
      expect(screen.queryByText(/export must be valid UTF-8/)).toBeNull();
    },
  );

  it("deselection invalidates a pending read even if DLP is selected again", async () => {
    await openForm();
    await dlpOnly();
    const pending = deferred<ArrayBuffer>();
    await upload(fileOf("old", pending.promise).file);
    const dlp = screen.getByRole("checkbox", { name: "DLP export" });
    await userEvent.click(dlp);
    await userEvent.click(dlp);
    await act(async () =>
      pending.resolve(new TextEncoder().encode("old").buffer),
    );
    submit();
    await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
    expect(collect.mock.calls[0][0]).not.toHaveProperty("dlp_content");
    expect(collect.mock.calls[0][0]).not.toHaveProperty("dlp_format");
  });

  it("clearing the file invalidates a late failed read", async () => {
    await openForm();
    await dlpOnly();
    const pending = deferred<ArrayBuffer>();
    await upload(fileOf("old", pending.promise).file);
    fireEvent.change(screen.getByLabelText("DLP JSON export"), {
      target: { files: [] },
    });
    await act(async () => pending.reject(new Error("old")));
    submit();
    await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
    expect(collect.mock.calls[0][0]).not.toHaveProperty("dlp_content");
    expect(screen.queryByText(/export must be valid UTF-8/)).toBeNull();
  });

  it.each(["ascii", "multibyte"])(
    "accepts exactly 4 MiB of %s UTF-8 without changing text",
    async (kind) => {
      await openForm();
      await dlpOnly();
      const text =
        kind === "ascii"
          ? '"' + "a".repeat(LIMIT - 2) + '"'
          : '"' + "\u00e9".repeat((LIMIT - 2) / 2) + '"';
      expect(new TextEncoder().encode(text)).toHaveLength(LIMIT);
      await upload(fileOf(text).file);
      await waitFor(() =>
        expect(screen.getByLabelText("DLP export format")).toBeEnabled(),
      );
      submit();
      await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
      expect(collect.mock.calls[0][0].dlp_content).toBe(text);
    },
  );

  it("refuses a reported-small file if the actual buffer exceeds 4 MiB", async () => {
    await openForm();
    await dlpOnly();
    await upload(
      fileOf("small", Promise.resolve(new Uint8Array(LIMIT + 1).buffer)).file,
    );
    expect(
      await screen.findByText(/export must be valid UTF-8 JSON within 4 MiB/),
    ).toBeInTheDocument();
    submit();
    expect(collect).not.toHaveBeenCalled();
  });

  it.each([
    [0xc3, 0x28],
    [0xe2, 0x82],
    [0xed, 0xa0, 0x80],
    [0xc0, 0x80],
  ])("refuses invalid UTF-8 bytes %s before POST", async (...bytes) => {
    await openForm();
    await dlpOnly();
    await upload(fileOf(new Uint8Array(bytes)).file);
    expect(
      await screen.findByText(/export must be valid UTF-8/),
    ).toBeInTheDocument();
    submit();
    expect(collect).not.toHaveBeenCalled();
  });

  it.each([0, 1])(
    "enforces the exact encoded 8 MiB request boundary plus %s byte",
    async (extra) => {
      await openForm();
      const target = 8_388_608 + extra;
      const expectedBody = {
        tenant_label: "synthetic-review",
        capabilities: [
          "conditional-access",
          "authentication-registration",
          "sign-ins",
          "directory-roles",
          "managed-devices",
          "retention-labels",
          "dlp-export",
          "defender-alerts",
          "defender-incidents",
        ],
        lookback_days: 30,
        max_items: 10000,
        max_pages: 100,
        dlp_content: "",
        dlp_format: "evidentia-dlp-v1",
      };
      const overhead = new TextEncoder().encode(
        JSON.stringify(expectedBody),
      ).byteLength;
      const pairs = Math.floor((target - overhead - 4) / 4);
      const remainder = target - overhead - 4 - pairs * 4;
      const text =
        '"' +
        String.fromCharCode(92).repeat(pairs * 2) +
        "a".repeat(remainder) +
        '"';
      expect(() => JSON.parse(text)).not.toThrow();
      expect(new TextEncoder().encode(text).byteLength).toBeLessThanOrEqual(
        LIMIT,
      );
      expectedBody.dlp_content = text;
      expect(
        new TextEncoder().encode(JSON.stringify(expectedBody)).byteLength,
      ).toBe(target);
      await upload(fileOf(text).file);
      await waitFor(() =>
        expect(screen.getByLabelText("DLP export format")).toBeEnabled(),
      );
      const before = health.mock.calls.length;
      submit();
      if (extra === 0) {
        await waitFor(() => expect(collect).toHaveBeenCalledTimes(1));
        expect(health).toHaveBeenCalledTimes(before + 1);
        expect(collect.mock.calls[0][0]).toEqual(expectedBody);
        expect(
          new TextEncoder().encode(JSON.stringify(collect.mock.calls[0][0]))
            .byteLength,
        ).toBe(target);
      } else {
        expect(
          await screen.findByText(/encoded request exceeds the 8 MiB/),
        ).toBeInTheDocument();
        expect(collect).not.toHaveBeenCalled();
        expect(health).toHaveBeenCalledTimes(before);
      }
    },
  );

  it.each([
    ["Tenant label", " bad"],
    ["Tenant label", "synthetic@tenant"],
    ["Lookback days", "1.5"],
    ["Lookback days", "31"],
    ["Maximum items per capability", "0"],
    ["Maximum pages per capability", "101"],
  ])(
    "form handler rejects invalid %s=%s even on direct submit",
    async (label, value) => {
      await openForm();
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
      submit();
      await act(async () => Promise.resolve());
      expect(collect).not.toHaveBeenCalled();
    },
  );
});
describe("Entra/M365 result preservation", () => {
  it("renders only 100 cards and 10 source observations but downloads the full object", async () => {
    const result = structuredClone(DEMO_ENTRA_M365_PARTIAL);
    const first = "2026-09-09T00:00:00.0000001000001Z";
    const last = "2026-09-09T00:00:00.9999999999999Z";
    result.capabilities[2].observed_first = first;
    result.capabilities[2].observed_last = last;
    result.findings = Array.from({ length: 103 }, (_, index) => ({
      ...structuredClone(result.findings[0]),
      id: `synthetic-${index}`,
      title: `Unique finding ${index}`,
      raw_data: {
        exact_time: "2026-09-09T00:00:00.000000000001Z",
        ordinal: index,
      },
    }));
    collect.mockResolvedValue(result);
    let blob: Blob | undefined;
    const create = vi.fn((value: Blob) => {
      blob = value;
      return "blob:synthetic-review";
    });
    const revoke = vi.fn();
    vi.stubGlobal(
      "URL",
      Object.assign(class extends URL {}, {
        createObjectURL: create,
        revokeObjectURL: revoke,
      }),
    );
    const clicked = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    await openForm();
    submit();
    const region = await screen.findByLabelText("Entra/M365 result");
    expect(region.textContent).toContain(first);
    expect(region.textContent).toContain(last);
    expect(within(region).getByText("Unique finding 99")).toBeInTheDocument();
    expect(within(region).queryByText("Unique finding 100")).toBeNull();
    expect(
      region.querySelectorAll('[aria-label="Collector findings"] li'),
    ).toHaveLength(100);
    const source = Array.from(region.querySelectorAll("details")).find((item) =>
      item.textContent?.includes("Source observations"),
    );
    const shown = JSON.parse(
      source?.querySelector("pre")?.textContent ?? "null",
    );
    expect(shown).toHaveLength(10);
    await userEvent.click(
      within(region).getByRole("button", { name: "Download full result JSON" }),
    );
    expect(clicked).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledTimes(1);
    expect(revoke).toHaveBeenCalledWith("blob:synthetic-review");
    expect(
      document.querySelector('a[download="entra-m365-result.json"]'),
    ).toBeNull();
    const serialized = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () =>
        reject(new Error("Synthetic download read failed"));
      if (!blob) throw new Error("Missing download blob");
      reader.readAsText(blob);
    });
    expect(JSON.parse(serialized)).toEqual(result);
    expect(serialized).toContain("2026-09-09T00:00:00.000000000001Z");
  });

  it("preserves the result and removes the temporary link when download click fails", async () => {
    const create = vi.fn(() => "blob:synthetic-review");
    const revoke = vi.fn();
    vi.stubGlobal(
      "URL",
      Object.assign(class extends URL {}, {
        createObjectURL: create,
        revokeObjectURL: revoke,
      }),
    );
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {
      throw new Error("Synthetic refusal");
    });
    await openForm();
    submit();
    const region = await screen.findByLabelText("Entra/M365 result");
    await userEvent.click(
      within(region).getByRole("button", { name: "Download full result JSON" }),
    );
    expect(
      await screen.findByText(/result could not be downloaded/),
    ).toBeInTheDocument();
    expect(within(region).getAllByLabelText(/capability result$/)).toHaveLength(
      9,
    );
    expect(revoke).toHaveBeenCalledWith("blob:synthetic-review");
    expect(
      document.querySelector('a[download="entra-m365-result.json"]'),
    ).toBeNull();
  });
});
