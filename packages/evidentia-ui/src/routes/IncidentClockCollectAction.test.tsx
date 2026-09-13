import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { api } from "@/lib/api";
import {
  incidentDemoCases,
  incidentDemoResponse,
} from "@/lib/demo/incident-clock-fixtures";
import type { IncidentProvider } from "@/lib/incident-clock";
import { IncidentClockCollectAction } from "./IncidentClockCollectAction";

vi.mock("@/lib/demo", () => ({ IS_DEMO: false }));
vi.mock("@/lib/api", () => ({ api: { collectIncidentClock: vi.fn() } }));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});
const button = () =>
  screen.getByRole("button", { name: "Collect incident clock" });
function fill(provider: IncidentProvider = "servicenow") {
  const sample = incidentDemoCases(provider)[0];
  const request = sample.request;
  fireEvent.change(screen.getByLabelText("Incident provider"), {
    target: { value: provider },
  });
  for (const [label, value] of [
    ["Authorized profile alias", request.profile_alias],
    ["Workflow clock alias", request.clock_alias],
    [
      provider === "servicenow"
        ? "ServiceNow record sys_id"
        : provider === "jira"
          ? "Jira issue ID"
          : "PagerDuty incident ID",
      request.record_id,
    ],
  ])
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  if (request.provider === "pagerduty") {
    fireEvent.change(screen.getByLabelText("Log interval since"), {
      target: { value: request.since },
    });
    fireEvent.change(screen.getByLabelText("Log interval until"), {
      target: { value: request.until },
    });
  }
  return incidentDemoResponse(request, sample.name);
}

test.each(["servicenow", "jira", "pagerduty"] as const)(
  "fresh authorization precedes the exact %s request",
  async (provider) => {
    const order: string[] = [];
    render(
      <IncidentClockCollectAction
        freshAuth
        verifyAuth={async () => {
          order.push("auth");
          return true;
        }}
      />,
    );
    const response = fill(provider);
    vi.mocked(api.collectIncidentClock).mockImplementation(async () => {
      order.push("post");
      return response;
    });
    fireEvent.click(button());
    await screen.findByRole("region", { name: "Incident clock result" });
    expect(order).toEqual(["auth", "post"]);
    expect(api.collectIncidentClock).toHaveBeenCalledWith(
      response.result.request,
      "",
    );
    for (const text of [
      "Source completeness",
      "Clock state",
      "Elapsed seconds",
      "Workflow meaning and mapping",
      "Start selection",
      "End selection",
    ])
      expect(screen.getByText(text)).toBeInTheDocument();
  },
);

test("invalid forms and absent current authentication perform no collection", () => {
  const verify = vi.fn();
  const view = render(
    <IncidentClockCollectAction freshAuth verifyAuth={verify} />,
  );
  expect(button()).toBeDisabled();
  fill();
  view.rerender(
    <IncidentClockCollectAction freshAuth={false} verifyAuth={verify} />,
  );
  expect(button()).toBeDisabled();
  fireEvent.click(button());
  expect(verify).not.toHaveBeenCalled();
  expect(api.collectIncidentClock).not.toHaveBeenCalled();
});

test.each([false, "reject"])(
  "refused or failed auth suppresses provider work (%s)",
  async (state) => {
    const verify =
      state === false
        ? vi.fn().mockResolvedValue(false)
        : vi.fn().mockRejectedValue(new Error("Synthetic auth detail"));
    render(<IncidentClockCollectAction freshAuth verifyAuth={verify} />);
    fill();
    fireEvent.click(button());
    await screen.findByRole("alert");
    expect(api.collectIncidentClock).not.toHaveBeenCalled();
    expect(screen.queryByText("Synthetic auth detail")).toBeNull();
  },
);

test.each([false, true])(
  "input changes discard stale authorization (reject=%s)",
  async (reject) => {
    let resolve!: (value: boolean) => void;
    let refuse!: (reason: Error) => void;
    const verify = () =>
      new Promise<boolean>((yes, no) => {
        resolve = yes;
        refuse = no;
      });
    render(<IncidentClockCollectAction freshAuth verifyAuth={verify} />);
    fill();
    fireEvent.click(button());
    fireEvent.change(screen.getByLabelText("Workflow clock alias"), {
      target: { value: "changed" },
    });
    await act(async () => {
      if (reject) refuse(new Error("Stale auth detail"));
      else resolve(true);
    });
    expect(api.collectIncidentClock).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).toBeNull();
  },
);

test.each([false, true])(
  "input changes discard stale provider completion (reject=%s)",
  async (reject) => {
    let resolve!: (value: ReturnType<typeof incidentDemoResponse>) => void;
    let refuse!: (reason: Error) => void;
    vi.mocked(api.collectIncidentClock).mockImplementation(
      () =>
        new Promise((yes, no) => {
          resolve = yes;
          refuse = no;
        }),
    );
    render(
      <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
    );
    const response = fill();
    fireEvent.click(button());
    await waitFor(() =>
      expect(api.collectIncidentClock).toHaveBeenCalledOnce(),
    );
    fireEvent.change(screen.getByLabelText("Authorized profile alias"), {
      target: { value: "changed" },
    });
    await act(async () => {
      if (reject) refuse(new Error("Stale provider detail"));
      else resolve(response);
    });
    expect(
      screen.queryByRole("region", { name: "Incident clock result" }),
    ).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  },
);

test("unmounting while authorization is pending prevents collection", async () => {
  let resolve!: (value: boolean) => void;
  const view = render(
    <IncidentClockCollectAction
      freshAuth
      verifyAuth={() =>
        new Promise((yes) => {
          resolve = yes;
        })
      }
    />,
  );
  fill();
  fireEvent.click(button());
  view.unmount();
  await act(async () => resolve(true));
  expect(api.collectIncidentClock).not.toHaveBeenCalled();
});

test("repeated clicks use one active authorization and collection", async () => {
  let resolve!: (value: boolean) => void;
  const verify = vi.fn(
    () =>
      new Promise<boolean>((yes) => {
        resolve = yes;
      }),
  );
  render(<IncidentClockCollectAction freshAuth verifyAuth={verify} />);
  const response = fill();
  vi.mocked(api.collectIncidentClock).mockResolvedValue(response);
  fireEvent.click(button());
  fireEvent.click(screen.getByRole("button", { name: "Collecting..." }));
  await act(async () => resolve(true));
  await screen.findByRole("region", { name: "Incident clock result" });
  expect(verify).toHaveBeenCalledOnce();
  expect(api.collectIncidentClock).toHaveBeenCalledOnce();
});

test("download preserves the entire original JSON and a fixed provider filename", async () => {
  let downloaded: Blob | null = null;
  let filename = "";
  vi.stubGlobal(
    "URL",
    class extends URL {
      static createObjectURL(value: Blob) {
        downloaded = value;
        return "blob:synthetic-incident";
      }
      static revokeObjectURL = vi.fn();
    },
  );
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    filename = this.download;
  });
  render(
    <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
  );
  const response = fill();
  vi.mocked(api.collectIncidentClock).mockResolvedValue(response);
  fireEvent.click(button());
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Download full incident clock JSON",
    }),
  );
  expect(await (downloaded as unknown as Blob).text()).toBe(response.rawJson);
  expect(filename).toBe("incident-clock-servicenow.json");
  expect(URL.revokeObjectURL).toHaveBeenCalledOnce();
});

test("revalidates a supplied raw result against the original request", async () => {
  render(
    <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill();
  const other = incidentDemoCases("jira")[0];
  vi.mocked(api.collectIncidentClock).mockResolvedValue(
    incidentDemoResponse(other.request, other.name),
  );
  fireEvent.click(button());
  await screen.findByRole("alert");
  expect(
    screen.queryByRole("region", { name: "Incident clock result" }),
  ).toBeNull();
});

test("Jira occurrence selection requires a native ID and bounded integer item index together", () => {
  render(
    <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill("jira");
  expect(button()).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Start history ID"), {
    target: { value: "H1" },
  });
  expect(button()).toBeDisabled();
  for (const value of ["-1", "256", "0.0", "1e0", "00"]) {
    fireEvent.change(screen.getByLabelText("Start item index (0 to 255)"), {
      target: { value },
    });
    expect(button()).toBeDisabled();
  }
  fireEvent.change(screen.getByLabelText("Start item index (0 to 255)"), {
    target: { value: "0" },
  });
  expect(button()).toBeEnabled();
});

test("PagerDuty interval validation preserves native precision and rejects naive or overlong intervals", () => {
  render(
    <IncidentClockCollectAction freshAuth verifyAuth={async () => true} />,
  );
  fill("pagerduty");
  expect(button()).toBeEnabled();
  for (const value of [
    "2024-01-01T00:00:00",
    "2026-01-01T00:00:00Z",
    "2023-12-31T00:00:00Z",
  ]) {
    fireEvent.change(screen.getByLabelText("Log interval until"), {
      target: { value },
    });
    expect(button()).toBeDisabled();
  }
  fireEvent.change(screen.getByLabelText("Log interval until"), {
    target: { value: "2024-01-01T00:00:00.000000001Z" },
  });
  expect(button()).toBeEnabled();
});
