import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { GapTable } from "@/components/gap/GapTable";
import type { ControlGap } from "@/types/api";

// Column order in GapTable.tsx: Framework(0), Control(1), Title(2),
// Severity(3), Effort(4), Priority(5), Status(6). Tests below index into a
// row's cells by that fixed position rather than re-deriving it from the
// header text.
const CONTROL_CELL = 1;
const SEVERITY_CELL = 3;

function gap(overrides: Partial<ControlGap> = {}): ControlGap {
  return {
    id: "gap-1",
    framework: "nist-800-53-mod",
    control_id: "AC-2",
    control_title: "Account Management",
    control_description: "Baseline control description for tests.",
    control_family: "Access Control",
    gap_severity: "high",
    implementation_status: "missing",
    gap_description: "Gap description for tests.",
    status: "open",
    equivalent_controls_in_inventory: [],
    cross_framework_value: [],
    remediation_guidance: "Remediation guidance for tests.",
    implementation_effort: "medium",
    priority_score: 5,
    jira_issue_key: null,
    servicenow_ticket_id: null,
    created_at: "2026-01-01T00:00:00Z",
    remediated_at: null,
    assigned_to: null,
    tags: [],
    ...overrides,
  };
}

const GAPS: ControlGap[] = [
  gap({
    id: "gap-ac-2",
    control_id: "AC-2",
    control_title: "Account Management",
    gap_severity: "high",
    priority_score: 9.1,
  }),
  gap({
    id: "gap-cm-6",
    control_id: "CM-6",
    control_title: "Configuration Settings",
    gap_severity: "critical",
    priority_score: 5.5,
  }),
  gap({
    id: "gap-ir-4",
    control_id: "IR-4",
    control_title: "Incident Handling",
    gap_severity: "low",
    priority_score: 7.3,
  }),
  gap({
    id: "gap-sc-7",
    control_id: "SC-7",
    control_title: "Boundary Protection",
    gap_severity: "medium",
    priority_score: 1.2,
  }),
];

function bodyRows(container: HTMLElement): HTMLElement[] {
  return within(container.querySelector("tbody")!).getAllByRole("row");
}

describe("GapTable", () => {
  it("renders one row per gap in priority-descending order by default", () => {
    const { container } = render(<GapTable gaps={GAPS} />);

    const rows = bodyRows(container);
    expect(rows).toHaveLength(4);
    const controlIds = rows.map(
      (row) => within(row).getAllByRole("cell")[CONTROL_CELL].textContent,
    );
    expect(controlIds).toEqual(["AC-2", "IR-4", "CM-6", "SC-7"]);
    expect(screen.getByText("4 of 4 rows")).toBeInTheDocument();
  });

  it("filters rows with the global filter and shows the empty state for no matches", async () => {
    const user = userEvent.setup();
    const { container } = render(<GapTable gaps={GAPS} />);
    const filterInput = screen.getByLabelText("Filter gaps");

    await user.type(filterInput, "ac-");
    expect(screen.getByText("1 of 4 rows")).toBeInTheDocument();
    const filteredRows = bodyRows(container);
    expect(filteredRows).toHaveLength(1);
    expect(
      within(filteredRows[0]).getAllByRole("cell")[CONTROL_CELL].textContent,
    ).toBe("AC-2");

    await user.clear(filterInput);
    await user.type(filterInput, "no-such-control");
    expect(
      screen.getByText("No gaps match the current filter."),
    ).toBeInTheDocument();
    expect(screen.getByText("0 of 4 rows")).toBeInTheDocument();
  });

  it("sorts by severity rank ascending on header click, descending on a second click", async () => {
    const user = userEvent.setup();
    const { container } = render(<GapTable gaps={GAPS} />);
    const severityHeader = screen.getByRole("columnheader", {
      name: "Severity",
    });

    await user.click(severityHeader);
    const ascending = bodyRows(container).map(
      (row) => within(row).getAllByRole("cell")[SEVERITY_CELL].textContent,
    );
    expect(ascending).toEqual(["low", "medium", "high", "critical"]);

    await user.click(severityHeader);
    const descending = bodyRows(container).map(
      (row) => within(row).getAllByRole("cell")[SEVERITY_CELL].textContent,
    );
    expect(descending).toEqual(["critical", "high", "medium", "low"]);
  });

  it("defaults to compact density and switches to comfortable on Comfy", async () => {
    const user = userEvent.setup();
    const { container } = render(<GapTable gaps={GAPS} />);
    const tableWrap = container.querySelector(".table-wrap");

    expect(screen.getByRole("radio", { name: "Compact" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    expect(tableWrap).toHaveAttribute("data-density", "compact");

    await user.click(screen.getByRole("radio", { name: "Comfy" }));
    expect(tableWrap).toHaveAttribute("data-density", "comfortable");
  });
});
