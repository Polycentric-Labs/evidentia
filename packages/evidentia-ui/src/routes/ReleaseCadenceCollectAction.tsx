import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { IS_DEMO } from "@/lib/demo";
import {
  RELEASE_SOURCE_PROFILE,
  ReleaseResponseError,
  releaseFailureMessage,
  parseReleasePollResponse,
  parseReleaseSeriesResponse,
  releasePreview,
  snapshotReleasePollRequest,
  snapshotReleaseSeriesRequest,
  type ReleasePollResponse,
  type ReleaseSeriesResponse,
} from "@/lib/release-cadence";

type AuthProps = {
  freshAuth: boolean;
  authInvalidated?: boolean;
  verifyAuth: () => Promise<boolean>;
};
const PAGE = 20;
function download(raw: string, filename: string) {
  const url = URL.createObjectURL(
    new Blob([raw], { type: "application/json;charset=utf-8" }),
  );
  const anchor = document.createElement("a");
  try {
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}
function Literal({ value }: { value: string | null }) {
  return (
    <span className="whitespace-pre-wrap break-words">
      {value === null ? "null" : releasePreview(value)}
    </span>
  );
}
export function ReleaseOperationPanel({
  kind,
  freshAuth,
  authInvalidated = !freshAuth,
  verifyAuth,
}: AuthProps & { kind: "poll" | "series" }) {
  const [owner, setOwner] = useState(""),
    [repository, setRepository] = useState(""),
    [channel, setChannel] = useState<"full_releases" | "all_published">(
      "full_releases",
    ),
    [persist, setPersist] = useState(false);
  const [start, setStart] = useState(""),
    [end, setEnd] = useState(""),
    [interval, setInterval] = useState("1"),
    [tolerance, setTolerance] = useState("0");
  const [response, setResponse] = useState<
      ReleasePollResponse | ReleaseSeriesResponse | null
    >(null),
    [error, setError] = useState(""),
    [pending, setPending] = useState(false),
    [page, setPage] = useState(0),
    [detailPage, setDetailPage] = useState(0),
    [outcomePage, setOutcomePage] = useState(0);
  const mounted = useRef(true),
    generation = useRef(0),
    active = useRef<AbortController | null>(null),
    invalid = useRef(authInvalidated),
    busy = useRef(false);
  const [previousInvalid, setPreviousInvalid] = useState(authInvalidated);
  if (previousInvalid !== authInvalidated) {
    setPreviousInvalid(authInvalidated);
    if (authInvalidated) {
      setPending(false);
      setResponse(null);
      setError("");
    }
  }
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      active.current?.abort();
    };
  }, []);
  useLayoutEffect(() => {
    invalid.current = authInvalidated;
    if (authInvalidated) {
      generation.current++;
      active.current?.abort();
      busy.current = false;
    }
  }, [authInvalidated]);
  const changed = () => {
    generation.current++;
    active.current?.abort();
    active.current = null;
    busy.current = false;
    setPending(false);
    setError("");
  };
  const loadDemo = async () => {
    changed();
    const token = generation.current;
    try {
      const { RELEASE_DEMO_FIXTURES } =
        await import("@/lib/demo/release-cadence-fixtures");
      if (!mounted.current || generation.current !== token) return;
      const entry = RELEASE_DEMO_FIXTURES.find(
        (row) => row.id === (kind === "poll" ? "poll-observed" : "series-two"),
      )!;
      const req = entry.request;
      setOwner(req.owner);
      setRepository(req.repository);
      setChannel(req.channel);
      if ("persist" in req) setPersist(false);
      if ("window_start" in req) {
        setStart(req.window_start);
        setEnd(req.window_end);
        setInterval(String(req.interval_days));
        setTolerance(String(req.tolerance_days));
      }
    } catch {
      if (mounted.current && generation.current === token)
        setError("The synthetic example is unavailable.");
    }
  };
  const submit = async () => {
    if (busy.current || !freshAuth || authInvalidated) return;
    busy.current = true;
    setPending(true);
    setError("");
    const token = ++generation.current,
      controller = new AbortController();
    active.current = controller;
    const current = () =>
      mounted.current &&
      generation.current === token &&
      !invalid.current &&
      !controller.signal.aborted;
    try {
      const base = {
        source_profile: RELEASE_SOURCE_PROFILE,
        owner,
        repository,
        channel,
      };
      let captured;
      if (kind === "poll")
        captured = snapshotReleasePollRequest({
          ...base,
          schema_version: "release-poll-request-v1",
          persist,
        });
      else {
        if (
          !/^(?:0|[1-9][0-9]{0,3})$/.test(interval) ||
          !/^(?:0|[1-9][0-9]{0,3})$/.test(tolerance)
        )
          throw new ReleaseResponseError();
        captured = snapshotReleaseSeriesRequest({
          ...base,
          schema_version: "release-series-request-v1",
          window_start: start,
          window_end: end,
          interval_days: Number(interval),
          tolerance_days: Number(tolerance),
        });
      }
      if (!(await verifyAuth()) || !current()) {
        if (current())
          setError(
            "Current authentication is required for this release operation.",
          );
        return;
      }
      const received =
        "persist" in captured
          ? await api.collectReleaseCadence(captured, {
              signal: controller.signal,
            })
          : await api.releaseSeries(captured, { signal: controller.signal });
      if (!current()) return;
      const descriptor =
        received && typeof received === "object"
          ? Object.getOwnPropertyDescriptor(received, "rawJson")
          : undefined;
      if (
        !descriptor ||
        !Object.prototype.hasOwnProperty.call(descriptor, "value") ||
        typeof descriptor.value !== "string"
      )
        throw new ReleaseResponseError();
      const accepted =
        "persist" in captured
          ? await parseReleasePollResponse(descriptor.value, captured)
          : await parseReleaseSeriesResponse(descriptor.value, captured);
      if (current()) {
        setResponse(accepted);
        setPage(0);
        setDetailPage(0);
        setOutcomePage(0);
      }
    } catch (caught) {
      if (current()) setError(releaseFailureMessage(caught));
    } finally {
      if (active.current === controller) {
        active.current = null;
        busy.current = false;
        if (mounted.current) setPending(false);
      }
    }
  };
  const result = response?.result,
    poll = result?.schema_version === "release-poll-result-v1" ? result : null,
    series =
      result?.schema_version === "release-series-result-v1" ? result : null;
  const id = "release-" + kind;
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>
          {kind === "poll"
            ? "Observe upstream releases"
            : "Evaluate recorded release spacing"}
        </CardTitle>
        <CardDescription>
          {kind === "poll"
            ? "Observe visible public GitHub release facts. Saving local evidence requires an explicit choice."
            : "Read previously recorded release publications under an explicit interval policy. This operation does not contact GitHub or save records."}{" "}
          Neither operation proves patch installation or compliance.
        </CardDescription>
      </CardHeader>
      <CardContent className="min-w-0 space-y-5">
        {IS_DEMO && (
          <div className="rounded border p-3">
            <p>
              Synthetic examples only. No provider request or evidence save
              occurs in demo mode.
            </p>
            <Button
              variant="outline"
              type="button"
              onClick={() => void loadDemo()}
            >
              Load synthetic release example
            </Button>
          </div>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <Label htmlFor={id + "-owner"}>GitHub owner</Label>
            <Input
              id={id + "-owner"}
              value={owner}
              onChange={(e) => {
                changed();
                setOwner(e.target.value);
              }}
            />
          </div>
          <div>
            <Label htmlFor={id + "-repository"}>GitHub repository</Label>
            <Input
              id={id + "-repository"}
              value={repository}
              onChange={(e) => {
                changed();
                setRepository(e.target.value);
              }}
            />
          </div>
          <div>
            <Label htmlFor={id + "-channel"}>Release channel</Label>
            <select
              id={id + "-channel"}
              className="w-full rounded border bg-background p-2"
              value={channel}
              onChange={(e) => {
                changed();
                setChannel(e.target.value as typeof channel);
              }}
            >
              <option value="full_releases">Full releases</option>
              <option value="all_published">
                All published releases, including prereleases
              </option>
            </select>
          </div>
          {kind === "poll" ? (
            <div>
              <Label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={persist}
                  onChange={(e) => {
                    changed();
                    setPersist(e.target.checked);
                  }}
                />
                Save release evidence locally
              </Label>
              <p className="text-sm text-muted-foreground">
                Off by default. An explicit save requires write permission. If
                an operation is interrupted, inspect its outcome before
                retrying.
              </p>
            </div>
          ) : (
            <>
              <div>
                <Label htmlFor={id + "-start"}>Window start (UTC)</Label>
                <Input
                  id={id + "-start"}
                  value={start}
                  placeholder="2000-01-01T00:00:00.000000Z"
                  onChange={(e) => {
                    changed();
                    setStart(e.target.value);
                  }}
                />
              </div>
              <div>
                <Label htmlFor={id + "-end"}>Window end (UTC)</Label>
                <Input
                  id={id + "-end"}
                  value={end}
                  placeholder="2000-02-01T00:00:00.000000Z"
                  onChange={(e) => {
                    changed();
                    setEnd(e.target.value);
                  }}
                />
              </div>
              <div>
                <Label htmlFor={id + "-interval"}>Interval days</Label>
                <Input
                  id={id + "-interval"}
                  inputMode="numeric"
                  value={interval}
                  onChange={(e) => {
                    changed();
                    setInterval(e.target.value);
                  }}
                />
              </div>
              <div>
                <Label htmlFor={id + "-tolerance"}>Tolerance days</Label>
                <Input
                  id={id + "-tolerance"}
                  inputMode="numeric"
                  value={tolerance}
                  onChange={(e) => {
                    changed();
                    setTolerance(e.target.value);
                  }}
                />
              </div>
            </>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            disabled={!freshAuth || authInvalidated || pending}
            onClick={() => void submit()}
          >
            {pending
              ? "Running release operation..."
              : kind === "poll"
                ? "Observe releases"
                : "Evaluate release spacing"}
          </Button>
          {pending && (
            <Button variant="outline" type="button" onClick={changed}>
              Cancel release operation
            </Button>
          )}
        </div>
        {!freshAuth && (
          <p role="status">
            Current authentication is required before this operation.
          </p>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertTitle>Release operation unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {result && response && (
          <section
            aria-label="Accepted release result"
            className="min-w-0 space-y-4 rounded border p-4"
          >
            <h3 className="font-semibold">Accepted release result</h3>
            <p className="text-sm">
              This result belongs to {result.request.owner}/
              {result.request.repository}, channel {result.request.channel}.
              Editing the form does not change this accepted result.
            </p>
            <p className="text-sm">
              Request SHA-256:{" "}
              <code className="break-all">{result.request_sha256}</code>
            </p>
            <Button
              variant="outline"
              type="button"
              onClick={() =>
                download(
                  response.rawJson,
                  kind === "poll"
                    ? "release-observation.json"
                    : "release-series.json",
                )
              }
            >
              Download complete release JSON
            </Button>
            {poll && (
              <>
                <dl className="grid gap-2 sm:grid-cols-2">
                  <div>
                    <dt>Upstream observation</dt>
                    <dd>{poll.collection_state}</dd>
                  </div>
                  <div>
                    <dt>Local persistence</dt>
                    <dd>{poll.persistence.state}</dd>
                  </div>
                  <div>
                    <dt>Rows and unique events</dt>
                    <dd>
                      {poll.counters.rows_admitted} rows;{" "}
                      {poll.counters.unique_source_events} events
                    </dd>
                  </div>
                  <div>
                    <dt>Save calls and verified creations</dt>
                    <dd>
                      {poll.persistence.attempted_calls} calls;{" "}
                      {poll.persistence.outcome_counts.created} created
                    </dd>
                  </div>
                  <div>
                    <dt>Store discovery</dt>
                    <dd>{poll.discovery.status}</dd>
                  </div>
                  <div>
                    <dt>Observation completed</dt>
                    <dd>{poll.clocks.completed_at}</dd>
                  </div>
                </dl>
                <p>
                  Reasons: {poll.reasons.join(", ") || "none"}. Mirror outcome:{" "}
                  {poll.persistence.mirror_outcome}.
                </p>
                <h4 className="font-medium">Native release facts</h4>
                <p className="text-sm">
                  Source URLs and markup remain inert text. Long previews are
                  truncated; the download retains complete values.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr>
                        <th>Release</th>
                        <th>Native name and tag</th>
                        <th>Publication time</th>
                        <th>Eligibility</th>
                      </tr>
                    </thead>
                    <tbody>
                      {poll.rows
                        .slice(page * PAGE, (page + 1) * PAGE)
                        .map((row) => (
                          <tr key={row.metadata.row_index}>
                            <td>
                              {row.selected.id}
                              <br />
                              <Literal value={row.selected.url} />
                            </td>
                            <td>
                              <Literal value={row.selected.name} />
                              <br />
                              <Literal value={row.selected.tag_name} />
                            </td>
                            <td>
                              <Literal value={row.selected.published_at} />
                              <br />
                              {row.metadata.source_time.classification}
                              <br />
                              {row.metadata.source_time.normalized_utc}
                            </td>
                            <td>
                              {row.metadata.initial_publication_eligible
                                ? "eligible"
                                : "not established or excluded"}
                              <br />
                              {row.metadata.eligibility_reasons.join(", ") ||
                                "none"}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    disabled={page === 0}
                    onClick={() => setPage((p) => p - 1)}
                  >
                    Previous releases
                  </Button>
                  <span>Release page {page + 1}</span>
                  <Button
                    variant="outline"
                    disabled={(page + 1) * PAGE >= poll.rows.length}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next releases
                  </Button>
                </div>
                <h4 className="font-medium">Observed event families</h4>
                <ul
                  className="space-y-2 text-sm"
                  aria-label="Observed event families"
                >
                  {poll.events
                    .slice(detailPage * PAGE, (detailPage + 1) * PAGE)
                    .map((event) => (
                      <li key={event.event_id}>
                        Release {event.release_id}; {event.occurrence_count}{" "}
                        source occurrences; stored state {event.stored_state}.
                        <br />
                        Current compared with the stored publication:{" "}
                        {event.current_vs_parent === null
                          ? "not observed"
                          : event.current_vs_parent.change_codes.join(", ") ||
                            "unchanged"}
                        .
                        <br />
                        Stored observation changes:{" "}
                        {event.stored_union_change_codes.join(", ") ||
                          "none observed"}
                        .
                        <br />
                        Recorded source observations:{" "}
                        {event.known_observation_count ?? "not observed"};
                        full-release exclusion:{" "}
                        {event.blocks_full_releases === null
                          ? "not observed"
                          : String(event.blocks_full_releases)}
                        ; all-published exclusion:{" "}
                        {event.blocks_all_published === null
                          ? "not observed"
                          : String(event.blocks_all_published)}
                        .
                      </li>
                    ))}
                </ul>
                <Button
                  variant="outline"
                  disabled={detailPage === 0}
                  onClick={() => setDetailPage((p) => p - 1)}
                >
                  Previous event families
                </Button>
                <Button
                  variant="outline"
                  disabled={(detailPage + 1) * PAGE >= poll.events.length}
                  onClick={() => setDetailPage((p) => p + 1)}
                >
                  Next event families
                </Button>
                <h4 className="font-medium">Page provenance</h4>
                <ul className="space-y-2 text-sm">
                  {poll.pages.map((item) => (
                    <li key={item.page_index}>
                      Page {item.page_number}:{" "}
                      {item.admitted ? "admitted" : "not admitted"}, HTTP{" "}
                      {item.http_status ?? "unavailable"}, {item.row_count}{" "}
                      rows, link {item.link_state}; raw SHA-256{" "}
                      <code className="break-all">
                        {item.raw_body_sha256 ?? "unavailable"}
                      </code>
                      ; decoded SHA-256{" "}
                      <code className="break-all">
                        {item.decoded_body_sha256 ?? "unavailable"}
                      </code>
                      .
                    </li>
                  ))}
                </ul>
                <h4 className="font-medium">Local save outcomes</h4>
                {poll.outcomes.length === 0 ? (
                  <p>No save outcomes.</p>
                ) : (
                  <>
                    <ul className="space-y-2 text-sm">
                      {poll.outcomes
                        .slice(outcomePage * PAGE, (outcomePage + 1) * PAGE)
                        .map((item, index) => (
                          <li key={outcomePage * PAGE + index}>
                            <code className="break-all">
                              {item.candidate_id}
                            </code>
                            : {item.outcome}; {item.local_state}; call{" "}
                            {item.save_call}; {item.reason ?? "no refusal"}.{" "}
                            {item.verified_record && (
                              <>
                                Verified record{" "}
                                <code>
                                  {item.verified_record.relative_path}
                                </code>
                                .
                              </>
                            )}
                          </li>
                        ))}
                    </ul>
                    <Button
                      variant="outline"
                      disabled={outcomePage === 0}
                      onClick={() => setOutcomePage((p) => p - 1)}
                    >
                      Previous outcomes
                    </Button>
                    <Button
                      variant="outline"
                      disabled={
                        (outcomePage + 1) * PAGE >= poll.outcomes.length
                      }
                      onClick={() => setOutcomePage((p) => p + 1)}
                    >
                      Next outcomes
                    </Button>
                  </>
                )}
              </>
            )}
            {series && (
              <>
                <p>
                  Recorded publication spacing: <strong>{series.state}</strong>.
                  Reasons: {series.reasons.join(", ") || "none"}.
                </p>
                <p>
                  {series.records.length} records; {series.events.length} event
                  families. Store discovery: {series.discovery.status}.
                  Evaluation: {series.evaluation_at}.
                </p>
                <p>
                  Interval {series.request.interval_days} days plus tolerance{" "}
                  {series.request.tolerance_days} days. Exact elapsed
                  microseconds determine each gap; retrieval times do not
                  substitute for publication.
                </p>
                <h4 className="font-medium">Recorded event families</h4>
                <ul className="space-y-2 text-sm">
                  {series.events
                    .slice(page * PAGE, (page + 1) * PAGE)
                    .map((event) => (
                      <li key={event.event_id}>
                        Release {event.release_id}:{" "}
                        <Literal value={event.published_at_literal} />;
                        normalized {event.published_at}; {event.eligibility};{" "}
                        {event.in_window ? "in window" : "outside window"};{" "}
                        {event.observation_count} source observations;{" "}
                        {event.reasons.join(", ") || "no exclusion"}.
                      </li>
                    ))}
                </ul>
                <Button
                  variant="outline"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous events
                </Button>
                <Button
                  variant="outline"
                  disabled={(page + 1) * PAGE >= series.events.length}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next events
                </Button>
                <h4 className="font-medium">Window boundaries and gaps</h4>
                <ul className="space-y-2 text-sm">
                  {series.gaps
                    .slice(detailPage * PAGE, (detailPage + 1) * PAGE)
                    .map((gap, index) => (
                      <li key={detailPage * PAGE + index}>
                        {gap.boundary}: {gap.start_at} to {gap.end_at};{" "}
                        {gap.elapsed_microseconds} microseconds, allowed{" "}
                        {gap.allowed_microseconds};{" "}
                        {gap.exceeds_allowed
                          ? "exceeds allowed spacing"
                          : "within allowed spacing"}
                        .
                      </li>
                    ))}
                </ul>
                <Button
                  variant="outline"
                  disabled={detailPage === 0}
                  onClick={() => setDetailPage((p) => p - 1)}
                >
                  Previous gaps
                </Button>
                <Button
                  variant="outline"
                  disabled={(detailPage + 1) * PAGE >= series.gaps.length}
                  onClick={() => setDetailPage((p) => p + 1)}
                >
                  Next gaps
                </Button>
              </>
            )}
          </section>
        )}
      </CardContent>
    </Card>
  );
}
export function ReleaseCadenceCollectAction(props: AuthProps) {
  return <ReleaseOperationPanel {...props} kind="poll" />;
}
