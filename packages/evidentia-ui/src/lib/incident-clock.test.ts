import { describe, expect, test, vi } from "vitest";
import {
  INCIDENT_FIXTURES,
  incidentDemoCases,
} from "@/lib/demo/incident-clock-fixtures";
import {
  INCIDENT_REQUEST_BYTES,
  INCIDENT_RESULT_BYTES,
  boundedIncidentPreview,
  incidentInstant,
  parseIncidentJson,
  parseIncidentRequest,
  parseIncidentResponse,
  snapshotIncidentRequest,
} from "./incident-clock";

const fixture = INCIDENT_FIXTURES[0];
const selected = JSON.parse(fixture.raw).request;

test.each(INCIDENT_FIXTURES)(
  "preserves the full issued synthetic wire: $name",
  (item) => {
    const request = JSON.parse(item.raw).request;
    const response = parseIncidentResponse(item.raw, request);
    expect(response.rawJson).toBe(item.raw);
    expect(response.result.request).toEqual(snapshotIncidentRequest(request));
    expect(Object.isFrozen(response.result)).toBe(true);
    expect(Object.isFrozen(response.result.events)).toBe(true);
  },
);

test("the request snapshot is detached and rejects callbacks and extra configuration", () => {
  const request = { ...selected };
  const snapshot = snapshotIncidentRequest(request);
  request.profile_alias = "other";
  expect(snapshot.profile_alias).toBe(selected.profile_alias);
  const getter = vi.fn(() => selected.profile_alias);
  const custom = { ...selected };
  Object.defineProperty(custom, "profile_alias", {
    get: getter,
    enumerable: true,
  });
  expect(() => snapshotIncidentRequest(custom)).toThrow();
  expect(getter).not.toHaveBeenCalled();
  for (const extra of [
    { origin: "https://example.org" },
    { credential: "unaccepted" },
    { start_occurrence: { field: "u_start" } },
  ])
    expect(() => snapshotIncidentRequest({ ...selected, ...extra })).toThrow();
});

test.each(["", "_profile", "two words", "x\n", "é", "x".repeat(65)])(
  "rejects invalid alias %j",
  (alias) => {
    expect(() =>
      snapshotIncidentRequest({ ...selected, profile_alias: alias }),
    ).toThrow();
  },
);

test.each([
  '{"a":1,"a":2}',
  '{"a":1,"\\u0061":2}',
  '{"a":NaN}',
  '{"a":1.0}',
  '{"a":1e0}',
  '{"a":9007199254740993}',
  '{"a":"\\ud800"}',
  "\ufeff{}",
  "{} trailing",
  '{"a":[1,]}',
])("rejects invalid or lossy native JSON %s", (raw) => {
  expect(() => parseIncidentJson(raw)).toThrow();
});

test("actual UTF-8 request and result bytes define inclusive boundaries", () => {
  const raw = JSON.stringify(selected);
  expect(
    parseIncidentRequest(raw + " ".repeat(INCIDENT_REQUEST_BYTES - raw.length)),
  ).toEqual(selected);
  expect(() =>
    parseIncidentRequest(
      raw + " ".repeat(INCIDENT_REQUEST_BYTES + 1 - raw.length),
    ),
  ).toThrow();
  const exact =
    fixture.raw +
    " ".repeat(
      INCIDENT_RESULT_BYTES - new TextEncoder().encode(fixture.raw).length,
    );
  expect(parseIncidentResponse(exact, selected).rawJson).toBe(exact);
  expect(() => parseIncidentResponse(exact + " ", selected)).toThrow();
});

test.each([
  ["1970-01-01T00:00:00Z", "pagerduty", 0n, 0],
  ["1969-12-31T23:59:59.9Z", "jira", -1n, 1],
  ["2024-01-01T00:00:00.000000001Z", "jira", 1704067200000000001n, 9],
  ["2024-01-01T01:00:00+0100", "jira", 1704067200n, 0],
  ["2024-01-01 00:00:00", "servicenow", 1704067200n, 0],
] as const)(
  "uses exact native instant %s",
  (literal, provider, ticks, scale) => {
    expect(incidentInstant(literal, provider)).toEqual({ ticks, scale });
  },
);

test.each([
  "2024-02-30T00:00:00Z",
  "0000-01-01T00:00:00Z",
  "2024-01-01T00:00:60Z",
  "2024-01-01T24:00:00Z",
  "2024-01-01T00:00:00-00:00",
  "2024-01-01T00:00:00+24:00",
  "2024-01-01T00:00:00Z\n",
])("refuses unsupported timestamp %s", (literal) => {
  expect(() => incidentInstant(literal, "pagerduty")).toThrow();
});

test("retains two thousand fraction digits and exact interval comparisons", () => {
  const literal = "2024-01-01T00:00:00." + "0".repeat(1999) + "1Z";
  const observed = incidentInstant(literal, "pagerduty");
  expect(observed.scale).toBe(2000);
  expect(observed.ticks).toBe(1704067200n * 10n ** 2000n + 1n);
  const example = incidentDemoCases("pagerduty")[0].request;
  expect(() =>
    snapshotIncidentRequest({
      ...example,
      since: literal,
      until: "2024-01-01T00:00:00Z",
    }),
  ).toThrow();
  expect(() =>
    snapshotIncidentRequest({
      ...example,
      since: "2024-01-01T00:00:00Z",
      until: "2025-01-01T00:00:00.000000001Z",
    }),
  ).toThrow();
});

describe("source and clock disagreement", () => {
  test.each([
    "record",
    "profile",
    "clock-alias",
    "elapsed",
    "source",
    "event-time",
    "event-reference",
    "event-match",
    "counts",
    "manifest",
    "summary",
    "duplicate-event",
    "duplicate-read",
    "body-hash",
  ])("refuses %s", (mode) => {
    const result = JSON.parse(fixture.raw);
    if (mode === "record") result.record.record_id = "2".repeat(32);
    if (mode === "profile") result.request.profile_alias = "other";
    if (mode === "clock-alias") result.definition.clock_alias = "other";
    if (mode === "elapsed") result.clock.elapsed_seconds = "2";
    if (mode === "source") result.source_state = "incomplete";
    if (mode === "event-time")
      result.events[0].timestamp.value = "2025-01-01 00:00:00";
    if (mode === "event-reference")
      result.events[0].read_id = "read-" + "f".repeat(64);
    if (mode === "event-match") result.events[0].matches = ["end"];
    if (mode === "counts") result.source_reads[0].admitted_events = 1;
    if (mode === "manifest") result.manifest.total_findings = 0;
    if (mode === "summary") result.findings[0].raw_data.elapsed_seconds = "2";
    if (mode === "duplicate-event") result.events.push(result.events[0]);
    if (mode === "duplicate-read")
      result.source_reads.push(result.source_reads[0]);
    if (mode === "body-hash") result.source_reads[0].body_complete = false;
    expect(() =>
      parseIncidentResponse(JSON.stringify(result), selected),
    ).toThrow();
  });
});

test("presentation previews use byte bounds without splitting Unicode", () => {
  expect(boundedIncidentPreview("é".repeat(10), 5)).toBe("éé");
  expect(boundedIncidentPreview("sample", 10)).toBe("sample");
});

test.each(["missing-clock-diagnostic", "wrong-warning", "invented-error"])(
  "refuses causal and manifest disagreement: %s",
  (kind) => {
    const item = INCIDENT_FIXTURES.find(
      (item) => item.name === "servicenow-unresolved",
    )!;
    const value = JSON.parse(item.raw);
    if (kind === "missing-clock-diagnostic") {
      value.diagnostics = [];
      for (const read of value.source_reads) read.diagnostic_codes = [];
    }
    if (kind === "wrong-warning")
      value.manifest.warnings = [
        "selected_scope_only",
        "workflow_mapping_only",
        "credential_expiry_unknown",
      ];
    if (kind === "invented-error")
      value.manifest.errors = ["incomplete_source"];
    expect(() =>
      parseIncidentResponse(JSON.stringify(value), value.request),
    ).toThrow();
  },
);
test("refuses a Jira event outside the configured fields even if it matches neither endpoint", () => {
  const item = INCIDENT_FIXTURES.find((item) => item.name === "jira-complete")!;
  const value = JSON.parse(item.raw);
  value.events[0].native_fields.fieldId.value = "unselected";
  value.events[0].matches = [];
  expect(() =>
    parseIncidentResponse(JSON.stringify(value), value.request),
  ).toThrow();
});
test("refuses publisher event types outside the supported PagerDuty schema", () => {
  const item = INCIDENT_FIXTURES.find(
    (item) => item.name === "pagerduty-complete",
  )!;
  const value = JSON.parse(item.raw);
  value.events[0].native_fields.type.value = "future_log_entry";
  value.events[0].matches = [];
  expect(() =>
    parseIncidentResponse(JSON.stringify(value), value.request),
  ).toThrow();
});

describe("native source-read counts", () => {
  test.each([
    ["servicenow", 0],
    ["servicenow", 2],
    ["jira", 0],
    ["jira", 2],
    ["pagerduty", 0],
    ["pagerduty", 2],
  ] as const)("refuses %s admitted record count %s", (provider, count) => {
    const result = JSON.parse(
      INCIDENT_FIXTURES.find((item) => item.name === provider + "-complete")!
        .raw,
    );
    result.source_reads.find(
      (read: { kind: string }) => read.kind === "record",
    ).received_records = count;
    expect(() =>
      parseIncidentResponse(JSON.stringify(result), result.request),
    ).toThrow();
  });

  test.each([0, 10001])("refuses unreceived body count %s", (count) => {
    const result = JSON.parse(
      INCIDENT_FIXTURES.find((item) => item.name === "jira-incomplete")!.raw,
    );
    result.source_reads.at(-1).received_records = count;
    expect(() =>
      parseIncidentResponse(JSON.stringify(result), result.request),
    ).toThrow();
  });

  test.each([null, 0])(
    "requires a null count for invalid JSON: %s",
    (count) => {
      const result = JSON.parse(
        INCIDENT_FIXTURES.find((item) => item.name === "jira-incomplete")!.raw,
      );
      Object.assign(result.source_reads.at(-1), {
        http_status: 200,
        body_complete: true,
        body_bytes: 1,
        wire_bytes: 129,
        body_sha256:
          "021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96",
        received_records: count,
        diagnostic_codes: ["invalid_json"],
      });
      result.diagnostics[0].code = "invalid_json";
      result.manifest.errors = ["invalid_json"];
      const raw = JSON.stringify(result);
      if (count === null)
        expect(parseIncidentResponse(raw, result.request).rawJson).toBe(raw);
      else expect(() => parseIncidentResponse(raw, result.request)).toThrow();
    },
  );
});

describe("native version grammar in composed string schemas", () => {
  test.each(["servicenow", "jira", "pagerduty"])(
    "rejects invalid native versions for %s",
    (provider) => {
      const sample = INCIDENT_FIXTURES.find(
        (item) => item.name === provider + "-complete",
      )!;
      for (const version of ["release", "1 release", "1.0\n"]) {
        const result = JSON.parse(sample.raw, (key, value) =>
          key === "collector_version" || key === "evidentia_version"
            ? version
            : value,
        );
        expect(() =>
          parseIncidentResponse(JSON.stringify(result), result.request),
        ).toThrow();
      }
    },
  );
});
