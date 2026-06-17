import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MetricCard } from "@/components/common/console";
import { Badge } from "@/components/ui/badge";

describe("MetricCard", () => {
  it("renders a block-level value (a Badge <div>) without an invalid DOM-nesting warning", () => {
    // The FDA demo's "Total gaps" card passes a `<Badge>` (which renders a
    // `<div>`) as the value. React logs a `validateDOMNesting` /
    // "cannot be a descendant of <p>" error when a block element is nested
    // inside a `<p>`, so the metric-value wrapper must be a `<div>`.
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const { getByText } = render(
      <MetricCard label="Total gaps" value={<Badge variant="critical">3 critical</Badge>} />,
    );

    expect(getByText("3 critical")).toBeInTheDocument();

    const nestingWarning = errorSpy.mock.calls.find((args) =>
      args.some((arg) => /descendant of|validateDOMNesting/i.test(String(arg))),
    );
    expect(nestingWarning).toBeUndefined();

    errorSpy.mockRestore();
  });
});
