import { afterEach, expect, it, vi } from "vitest";

import { api } from "@/lib/api";

import { DEMO_ENTRA_M365_PARTIAL } from "@/lib/demo/fixtures";

afterEach(() => vi.unstubAllGlobals());

it("preserves sub-microsecond source timestamps across JSON fetch parsing", async () => {
  const value = structuredClone(DEMO_ENTRA_M365_PARTIAL);
  const exact = "2026-09-09T23:59:59.12345678901234567890123456789Z";
  value.capabilities[2].observed_first = exact;
  value.capabilities[2].observed_last = exact;
  value.findings[0].raw_data = { source: { createdDateTime: exact } };
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValue(new Response(JSON.stringify(value), { status: 200 })),
  );
  expect(
    await api.collectEntraM365({ tenant_label: "synthetic-review" }),
  ).toEqual(value);
});
