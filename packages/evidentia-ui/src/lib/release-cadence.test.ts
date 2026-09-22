import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { RELEASE_DEMO_FIXTURES } from "./demo/release-cadence-fixtures";
import {
  parseReleasePollResponse,
  parseReleaseSeriesResponse,
  parseReleaseJson,
  snapshotReleasePollRequest,
  snapshotReleaseSeriesRequest,
  ReleaseResponseError,
} from "./release-cadence";
beforeEach(async () =>
  vi.stubGlobal(
    "crypto",
    (await vi.importActual<{ webcrypto: Crypto }>("node:crypto")).webcrypto,
  ),
);
afterEach(() => vi.unstubAllGlobals());
const compact = (value: unknown): string =>
  JSON.stringify(value, (_key, item) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(
          Object.keys(item)
            .sort()
            .map((k) => [k, item[k]]),
        )
      : item,
  ).replace(
    /[\u007f-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
const fixture = (id: string) =>
  RELEASE_DEMO_FIXTURES.find((row) => row.id === id)!;
test.each(RELEASE_DEMO_FIXTURES)(
  "$id preserves the exact actual synthetic API wire and closed request",
  async (entry) => {
    const parsed = await (
      entry.kind === "poll"
        ? parseReleasePollResponse
        : parseReleaseSeriesResponse
    )(entry.rawJson, entry.request);
    expect(parsed.rawJson).toBe(entry.rawJson);
    expect(parsed.result.request).toEqual(entry.request);
    expect(Object.isFrozen(parsed.result)).toBe(true);
    for (const [key, answer] of Object.entries(entry.expected)) {
      let value: unknown = parsed.result;
      for (const part of key.split("."))
        value = Reflect.get(value as object, part);
      expect(value).toEqual(answer);
    }
  },
);
test.each([
  '{"x":1,"x":2}',
  '{"x":NaN}',
  '{"x":1.2}',
  '{"x":-0}',
  '{"x":9007199254740992}',
  "[1,]",
  '{"x":"\\ud800"}',
  "\ufeff{}",
  "{} trailing",
  "{",
])("strict parser refuses %s", (raw) =>
  expect(() => parseReleaseJson(raw)).toThrow(ReleaseResponseError),
);
test("native ingress refuses getters, prototypes, sparse arrays and shared mutable authority without invoking callbacks", () => {
  const req = fixture("poll-empty").request,
    callback = vi.fn(() => "Example");
  const accessor = { ...req };
  Object.defineProperty(accessor, "owner", { get: callback, enumerable: true });
  expect(() => snapshotReleasePollRequest(accessor)).toThrow();
  expect(callback).not.toHaveBeenCalled();
  expect(() =>
    snapshotReleasePollRequest(Object.assign(Object.create({}), req)),
  ).toThrow();
  expect(() =>
    snapshotReleasePollRequest({ ...req, toJSON: callback }),
  ).toThrow();
  expect(callback).not.toHaveBeenCalled();
  const shared = {};
  expect(() =>
    snapshotReleasePollRequest({ ...req, x: shared, y: shared }),
  ).toThrow();
  const cycle: { x?: unknown } = {};
  cycle.x = cycle;
  expect(() => snapshotReleasePollRequest(cycle)).toThrow();
});
test.each(["bad/name", "owner\n", "-owner", "owner-", ""])(
  "request owner %s is refused before I/O",
  (owner) =>
    expect(() =>
      snapshotReleasePollRequest({ ...fixture("poll-empty").request, owner }),
    ).toThrow(),
);
test.each([".", "..", "bad/name", "repo\n", ""])(
  "request repository %s is refused before I/O",
  (repository) =>
    expect(() =>
      snapshotReleasePollRequest({
        ...fixture("poll-empty").request,
        repository,
      }),
    ).toThrow(),
);
test("request snapshot is detached and frozen", () => {
  const req: { owner: string; [key: string]: unknown } = {
    ...fixture("poll-empty").request,
  };
  const got = snapshotReleasePollRequest(req);
  req.owner = "Changed";
  expect(got.owner).toBe("Example");
  expect(Object.isFrozen(got)).toBe(true);
});
test.each([
  "2000-02-30T00:00:00Z",
  "0000-01-01T00:00:00Z",
  "2000-01-01t00:00:00Z",
  "2000-01-01T00:00:00.1234567Z",
])("series window rejects invalid exact UTC %s", (window_start) =>
  expect(() =>
    snapshotReleaseSeriesRequest({
      ...fixture("series-two").request,
      window_start,
    }),
  ).toThrow(),
);
const pollMutations: [
  string,
  (value: ReturnType<typeof JSON.parse>) => void,
][] = [
  ["request hash", (v) => (v.request_sha256 = "0".repeat(64))],
  ["source profile", (v) => (v.scope.source_profile = "other")],
  ["owner binding", (v) => (v.scope.canonical_owner = "other")],
  ["channel binding", (v) => (v.scope.channel = "all_published")],
  [
    "clock ordering",
    (v) => (v.clocks.started_at = "2002-01-01T00:00:00.000000Z"),
  ],
  ["calendar", (v) => (v.clocks.completed_at = "2001-02-30T00:00:00.000000Z")],
  ["page ordinal", (v) => (v.pages[0].page_ordinal = 2)],
  ["admission status", (v) => (v.pages[0].http_status = 201)],
  ["raw hash presence", (v) => (v.pages[0].raw_body_sha256 = null)],
  [
    "link absence hash",
    (v) => (v.pages[0].link_values_sha256 = "0".repeat(64)),
  ],
  ["link position", (v) => (v.pages[0].next_page = 2)],
  ["row start", (v) => (v.pages[0].row_start = 1)],
  ["row count", (v) => (v.pages[0].row_count = 2)],
  ["row metadata", (v) => (v.rows[0].metadata.row_index = 1)],
  [
    "source digest",
    (v) => (v.rows[0].metadata.selected_facts_sha256 = "0".repeat(64)),
  ],
  [
    "source classification",
    (v) => (v.rows[0].metadata.source_time.classification = "absent"),
  ],
  [
    "source instant",
    (v) =>
      (v.rows[0].metadata.source_time.normalized_utc =
        "2000-01-02T00:00:00.000000Z"),
  ],
  [
    "draft eligible",
    (v) => (v.rows[1].metadata.initial_publication_eligible = true),
  ],
  ["prerelease reasons", (v) => (v.rows[2].metadata.eligibility_reasons = [])],
  ["UUID", (v) => (v.events[0].event_id = v.events[1].event_id)],
  ["representative", (v) => (v.events[0].representative_row_index = 1)],
  ["occurrences", (v) => (v.events[0].occurrence_count = 2)],
  ["event row link", (v) => (v.rows[0].metadata.event_index = 1)],
  ["unobserved comparison", (v) => (v.events[0].known_observation_count = 0)],
  ["counter", (v) => (v.counters.rows_admitted = 2)],
  ["byte counter", (v) => v.counters.selected_ccompact_bytes_admitted++],
  ["implicit save", (v) => (v.persistence.requested = true)],
  ["discovery read", (v) => (v.discovery.passes = 1)],
  ["outcome count", (v) => (v.persistence.outcome_counts.created = 1)],
  ["terminal reason", (v) => (v.terminal_reason = "timeout")],
  ["extra field", (v) => (v.unknown = true)],
  ["selected optional null", (v) => (v.rows[0].selected.immutable = null)],
  ["absent becomes null", (v) => (v.rows[0].selected.updated_at = null)],
  [
    "native string instead of bool",
    (v) => (v.rows[0].selected.draft = "false"),
  ],
];
test.each(pollMutations)("poll rejects $0", async (_name, mutate) => {
  const f = fixture("poll-observed"),
    value = JSON.parse(f.rawJson);
  mutate(value);
  await expect(
    parseReleasePollResponse(compact(value), f.request),
  ).rejects.toThrow(ReleaseResponseError);
});
const seriesMutations: [
  string,
  (value: ReturnType<typeof JSON.parse>) => void,
][] = [
  ["request hash", (v) => (v.request_sha256 = "0".repeat(64))],
  ["scope", (v) => (v.scope.canonical_repository = "other")],
  ["future window", (v) => (v.evaluation_at = "1999-01-01T00:00:00.000000Z")],
  [
    "duplicate record",
    (v) => (v.records[1].artifact_id = v.records[0].artifact_id),
  ],
  ["event membership", (v) => (v.records[1].event_index = 0)],
  ["publication index", (v) => (v.events[0].publication_record_index = 1)],
  ["observations", (v) => (v.events[0].observation_count = 1)],
  ["event identity", (v) => (v.events[0].event_id = v.events[1].event_id)],
  [
    "literal source time",
    (v) => (v.events[0].published_at_literal = "2000-01-02T00:00:00Z"),
  ],
  ["window predicate", (v) => (v.events[0].in_window = false)],
  ["eligible reasons", (v) => (v.events[0].reasons = ["prerelease_excluded"])],
  ["gap count", (v) => v.gaps.pop()],
  ["microsecond", (v) => v.gaps[0].elapsed_microseconds++],
  ["gap predicate", (v) => (v.gaps[0].exceeds_allowed = true)],
  ["boundary", (v) => (v.gaps[0].boundary = "between")],
  ["left endpoint", (v) => (v.gaps[0].left_event_index = 0)],
  ["result state", (v) => (v.state = "gapped")],
  ["result reason", (v) => (v.reasons = ["gap_exceeds_allowed"])],
];
test.each(seriesMutations)("series rejects $0", async (_name, mutate) => {
  const f = fixture("series-two"),
    value = JSON.parse(f.rawJson);
  mutate(value);
  await expect(
    parseReleaseSeriesResponse(compact(value), f.request),
  ).rejects.toThrow(ReleaseResponseError);
});
test("duplicate rows require identical native selected facts", async () => {
  const f = fixture("poll-duplicates"),
    value = JSON.parse(f.rawJson);
  value.rows[1].selected.name = "different";
  await expect(
    parseReleasePollResponse(compact(value), f.request),
  ).rejects.toThrow();
});
test("partial traversal does not invent completed eligibility", async () => {
  const f = fixture("poll-partial"),
    value = JSON.parse(f.rawJson);
  value.rows[0].metadata.initial_publication_eligible = true;
  await expect(
    parseReleasePollResponse(compact(value), f.request),
  ).rejects.toThrow();
});
test.each([
  "save_call",
  "local_state",
  "candidate_id",
  "relative_path",
  "candidate_digest",
])("verified save relation %s is enforced", async (key) => {
  const f = fixture("poll-persist"),
    v = JSON.parse(f.rawJson),
    o = v.outcomes[0];
  if (key === "save_call") o.save_call = "not_called";
  if (key === "local_state") o.local_state = "not_attempted";
  if (key === "candidate_id")
    o.candidate_id = "11111111-1111-5111-8111-111111111111";
  if (key === "relative_path")
    o.verified_record.relative_path =
      "11111111-1111-5111-8111-111111111111/v1.json";
  if (key === "candidate_digest")
    o.candidate_selected_facts_sha256 = "0".repeat(64);
  await expect(
    parseReleasePollResponse(compact(v), f.request),
  ).rejects.toThrow();
});
test("response binding snapshots request before hash awaits", async () => {
  const f = fixture("poll-empty"),
    req: { owner: string; [key: string]: unknown } = { ...f.request };
  const pending = parseReleasePollResponse(f.rawJson, req);
  req.owner = "Changed";
  expect((await pending).result.request.owner).toBe("Example");
});

test("validation schemas match the registered OpenAPI semantic projection", async () => {
  const { RELEASE_SCHEMAS } = await import("./release-cadence");
  const openapi = (await import("../../openapi.json")).default;
  const names = Object.keys(RELEASE_SCHEMAS);
  const schemaName = (name: string) => {
    const qualified = "evidentia_core__release_cadence___contracts__" + name;
    return Object.hasOwn(openapi.components.schemas, qualified)
      ? qualified
      : name;
  };
  const referenceName = (ref: string) => {
    for (const name of names) {
      if (
        ref === "#/$defs/" + name ||
        ref === "#/components/schemas/" + schemaName(name)
      )
        return "#/components/schemas/" + name;
    }
    return ref;
  };
  const project = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(project);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value)
          .filter(
            ([key]) =>
              !["title", "description", "examples", "default"].includes(key),
          )
          .map(([key, item]) => [
            key,
            key === "$ref" && typeof item === "string"
              ? referenceName(item)
              : project(item),
          ]),
      );
    return value;
  };
  for (const [name, schema] of Object.entries(RELEASE_SCHEMAS))
    expect(project(schema), name).toEqual(
      project(Reflect.get(openapi.components.schemas, schemaName(name))),
    );
});

// These empty responses keep every request/hash/scope relation coherent, so the
// repository suffix is the only deliberately invalid source-profile fact.
async function responseWithRepository(
  kind: "poll" | "series",
  repository: string,
) {
  const entry = fixture(kind === "poll" ? "poll-empty" : "series-empty");
  const request = { ...entry.request, repository };
  const value = JSON.parse(entry.rawJson) as {
    request: unknown;
    request_sha256: string;
    scope: { canonical_repository: string };
  };
  value.request = request;
  value.scope.canonical_repository = repository.toLowerCase();
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(compact(request)),
  );
  value.request_sha256 = Array.from(new Uint8Array(hash), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return { request, rawJson: compact(value) };
}
for (const kind of ["poll", "series"] as const) {
  const snapshot =
    kind === "poll" ? snapshotReleasePollRequest : snapshotReleaseSeriesRequest;
  const decode =
    kind === "poll" ? parseReleasePollResponse : parseReleaseSeriesResponse;
  test.each(["application.git", "application.GIT"])(
    kind + " request refuses exact case-insensitive .git suffix: %s",
    (repository) => {
      const request = fixture(
        kind === "poll" ? "poll-empty" : "series-empty",
      ).request;
      expect(() => snapshot({ ...request, repository })).toThrow(
        ReleaseResponseError,
      );
    },
  );
  test.each(["application.git", "application.GIT"])(
    kind + " decoded response refuses coherent .git repository: %s",
    async (repository) => {
      const response = await responseWithRepository(kind, repository);
      await expect(decode(response.rawJson, response.request)).rejects.toThrow(
        ReleaseResponseError,
      );
    },
  );
  test.each(["application", "application.git-tools", "application.GIT2"])(
    kind + " keeps admitted nonsuffix repository spelling: %s",
    async (repository) => {
      const response = await responseWithRepository(kind, repository);
      expect(snapshot(response.request).repository).toBe(repository);
      const decoded = await decode(response.rawJson, response.request);
      expect(decoded.rawJson).toBe(response.rawJson);
      expect(decoded.result.request.repository).toBe(repository);
    },
  );
}
