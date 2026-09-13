import { useEffect, useRef, useState } from "react";
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
import { incidentDemoCases } from "@/lib/demo/incident-clock-fixtures";
import {
  INCIDENT_PROVIDERS,
  boundedIncidentPreview,
  parseIncidentResponse,
  snapshotIncidentRequest,
  type IncidentProvider,
  type IncidentClockRequest,
  type IncidentClockResponse,
} from "@/lib/incident-clock";

const LABELS: Record<IncidentProvider, string> = {
  servicenow: "ServiceNow",
  jira: "Jira Cloud",
  pagerduty: "PagerDuty",
};
type Form = {
  profile: string;
  clock: string;
  record: string;
  since: string;
  until: string;
  startId: string;
  startIndex: string;
  endId: string;
  endIndex: string;
};
const EMPTY: Form = {
  profile: "",
  clock: "",
  record: "",
  since: "",
  until: "",
  startId: "",
  startIndex: "",
  endId: "",
  endIndex: "",
};
function fromRequest(request: IncidentClockRequest): Form {
  const form = {
    ...EMPTY,
    profile: request.profile_alias,
    clock: request.clock_alias,
    record: request.record_id,
  };
  if (request.provider === "pagerduty") {
    form.since = request.since;
    form.until = request.until;
    form.startId = request.start_occurrence?.event_id ?? "";
    form.endId = request.end_occurrence?.event_id ?? "";
  } else if (request.provider === "jira") {
    form.startId = request.start_occurrence?.history_id ?? "";
    form.startIndex = request.start_occurrence
      ? String(request.start_occurrence.item_index)
      : "";
    form.endId = request.end_occurrence?.history_id ?? "";
    form.endIndex = request.end_occurrence
      ? String(request.end_occurrence.item_index)
      : "";
  }
  return form;
}
function buildRequest(
  provider: IncidentProvider,
  form: Form,
): IncidentClockRequest {
  const common = {
    provider,
    profile_alias: form.profile,
    clock_alias: form.clock,
    record_id: form.record,
  };
  if (provider === "servicenow") return snapshotIncidentRequest(common);
  if (provider === "pagerduty")
    return snapshotIncidentRequest({
      ...common,
      since: form.since,
      until: form.until,
      start_occurrence: form.startId ? { event_id: form.startId } : null,
      end_occurrence: form.endId ? { event_id: form.endId } : null,
    });
  const occurrence = (id: string, index: string) => {
    if (!id && !index) return null;
    if (!id || !/^(0|[1-9][0-9]{0,2})$/.test(index) || Number(index) > 255)
      throw new Error("Invalid occurrence");
    return { history_id: id, item_index: Number(index) };
  };
  return snapshotIncidentRequest({
    ...common,
    start_occurrence: occurrence(form.startId, form.startIndex),
    end_occurrence: occurrence(form.endId, form.endIndex),
  });
}
function Preview({ label, value }: { label: string; value: string }) {
  const preview = boundedIncidentPreview(value);
  return (
    <div className="stack-1">
      <h4 className="text-sm font-medium">{label}</h4>
      <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
        {preview}
      </pre>
      {preview !== value && (
        <p className="text-xs muted">
          This preview is limited to 4 KiB. Download the full JSON for the
          complete value.
        </p>
      )}
    </div>
  );
}
function IncidentResult({ response }: { response: IncidentClockResponse }) {
  const [page, setPage] = useState(0);
  const result = response.result;
  const offset = page * 20;
  const events = result.events.slice(offset, offset + 20);
  const diagnostics = new Map<string, number>();
  for (const diagnostic of result.diagnostics)
    diagnostics.set(
      diagnostic.code,
      (diagnostics.get(diagnostic.code) ?? 0) + 1,
    );
  const download = () => {
    const href = URL.createObjectURL(
      new Blob([response.rawJson], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = "incident-clock-" + result.provider + ".json";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  };
  return (
    <section aria-label="Incident clock result" className="stack-4">
      <dl className="grid gap-2 sm:grid-cols-3">
        <div>
          <dt>Source completeness</dt>
          <dd>{result.source_state}</dd>
        </div>
        <div>
          <dt>Clock state</dt>
          <dd>{result.clock.state}</dd>
        </div>
        <div>
          <dt>Elapsed seconds</dt>
          <dd>{result.clock.elapsed_seconds ?? "Unresolved"}</dd>
        </div>
      </dl>
      <p className="text-sm muted">
        This clock measures the configured workflow events in the selected
        source. It does not establish a legal notification deadline or a
        compliance verdict.
      </p>
      <Preview
        label="Selected request"
        value={JSON.stringify(result.request)}
      />
      <Preview
        label="Workflow meaning and mapping"
        value={JSON.stringify(result.definition)}
      />
      <div className="grid gap-4 sm:grid-cols-2">
        <Preview
          label="Start selection"
          value={JSON.stringify(result.clock.start)}
        />
        <Preview
          label="End selection"
          value={JSON.stringify(result.clock.end)}
        />
      </div>
      <Button type="button" variant="outline" onClick={download}>
        Download full incident clock JSON
      </Button>
      <details>
        <summary>
          Source record and read evidence ({result.source_reads.length})
        </summary>
        <Preview label="Source record" value={JSON.stringify(result.record)} />
        <div aria-label="Incident source reads" className="stack-3">
          {result.source_reads.map((read) => (
            <Card key={read.read_id}>
              <CardContent className="stack-2 pt-4">
                <p>
                  {read.ordinal + 1}: {read.template}; {read.state}
                </p>
                <Preview label="Read evidence" value={JSON.stringify(read)} />
              </CardContent>
            </Card>
          ))}
        </div>
      </details>
      <div aria-label="Incident diagnostics">
        <h3 className="text-sm font-medium">Diagnostic counts</h3>
        {diagnostics.size === 0 ? (
          <p>None.</p>
        ) : (
          <ul>
            {[...diagnostics].map(([code, count]) => (
              <li key={code}>
                {code}: {count}
              </li>
            ))}
          </ul>
        )}
      </div>
      <p>
        Showing {events.length ? offset + 1 : 0} to {offset + events.length} of{" "}
        {result.events.length} admitted events.
      </p>
      <div aria-label="Admitted incident events" className="stack-3">
        {events.map((event, index) => (
          <Card key={event.event_id}>
            <CardContent className="stack-2 pt-4">
              <p>
                Event {offset + index + 1}; matches:{" "}
                {event.matches.length
                  ? event.matches.join(", ")
                  : "neither endpoint"}
              </p>
              <Preview
                label="Source occurrence"
                value={JSON.stringify(event.occurrence)}
              />
              <Preview
                label="Native timestamp"
                value={JSON.stringify(event.timestamp)}
              />
              <Preview
                label="Native event fields"
                value={JSON.stringify(event.native_fields)}
              />
              <Preview
                label="Event and source read identity"
                value={JSON.stringify({
                  event_id: event.event_id,
                  read_id: event.read_id,
                })}
              />
            </CardContent>
          </Card>
        ))}
      </div>
      {result.events.length > 20 && (
        <div className="row gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
          >
            Previous events
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={offset + 20 >= result.events.length}
            onClick={() => setPage(page + 1)}
          >
            Next events
          </Button>
        </div>
      )}
    </section>
  );
}

/** Collect one authorized record with its configured workflow clock. */
export function IncidentClockCollectAction({
  freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const initial = IS_DEMO ? incidentDemoCases("servicenow")[0] : undefined;
  const [provider, setProvider] = useState<IncidentProvider>("servicenow");
  const [form, setForm] = useState<Form>(() =>
    initial ? fromRequest(initial.request) : { ...EMPTY },
  );
  const [scenario, setScenario] = useState(initial?.name ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<IncidentClockResponse | null>(null);
  const generation = useRef(0);
  const active = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);
  const invalidate = () => {
    generation.current += 1;
    active.current = false;
    setPending(false);
    setError(null);
    setResponse(null);
  };
  const change = (field: keyof Form, value: string) => {
    invalidate();
    setForm((previous) => ({ ...previous, [field]: value }));
  };
  const example = (name: IncidentProvider, selected: string) => {
    const item = incidentDemoCases(name).find(
      (candidate) => candidate.name === selected,
    );
    setScenario(item?.name ?? "");
    setForm(item ? fromRequest(item.request) : { ...EMPTY });
  };
  let request: IncidentClockRequest | null = null;
  try {
    request = buildRequest(provider, form);
  } catch {
    /* Keep invalid forms disabled. */
  }
  const collect = async () => {
    if (active.current || request === null || (!IS_DEMO && !freshAuth)) return;
    active.current = true;
    setPending(true);
    setResponse(null);
    setError(null);
    const expected = request;
    const ticket = ++generation.current;
    const current = () => mounted.current && generation.current === ticket;
    try {
      if (!IS_DEMO) {
        const approved = await verifyAuth();
        if (!current()) return;
        if (!approved) {
          setError("API read authentication is required before collection.");
          return;
        }
      }
      if (!current()) return;
      const received = await api.collectIncidentClock(expected, scenario);
      if (!current()) return;
      setResponse(parseIncidentResponse(received.rawJson, expected));
    } catch {
      if (current())
        setError(
          "Incident clock collection failed. Check API access, the authorized profile and the selected request.",
        );
    } finally {
      if (current()) {
        active.current = false;
        setPending(false);
      }
    }
  };
  const field = (key: keyof Form, label: string) => (
    <div className="stack-2" key={key}>
      <Label htmlFor={"incident-" + key}>{label}</Label>
      <Input
        id={"incident-" + key}
        value={form[key]}
        autoComplete="off"
        onChange={(event) => change(key, event.target.value)}
      />
    </div>
  );
  return (
    <Card>
      <CardHeader>
        <CardTitle>Incident clock</CardTitle>
        <CardDescription>
          Read one incident or issue and measure the interval between configured
          workflow events.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        {IS_DEMO && (
          <Alert>
            <AlertTitle>Synthetic examples</AlertTitle>
            <AlertDescription>
              These examples use simulated source records. No provider is
              contacted, and the displayed clock does not assess a real
              incident.
            </AlertDescription>
          </Alert>
        )}
        <div className="stack-2">
          <Label htmlFor="incident-provider">Incident provider</Label>
          <select
            id="incident-provider"
            value={provider}
            onChange={(event) => {
              invalidate();
              const selected = event.target.value as IncidentProvider;
              setProvider(selected);
              example(
                selected,
                IS_DEMO ? (incidentDemoCases(selected)[0]?.name ?? "") : "",
              );
            }}
          >
            {INCIDENT_PROVIDERS.map((name) => (
              <option key={name} value={name}>
                {LABELS[name]}
              </option>
            ))}
          </select>
        </div>
        {IS_DEMO && (
          <div className="stack-2">
            <Label htmlFor="incident-example">Synthetic incident example</Label>
            <select
              id="incident-example"
              value={scenario}
              onChange={(event) => {
                invalidate();
                example(provider, event.target.value);
              }}
            >
              {incidentDemoCases(provider).map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          {field("profile", "Authorized profile alias")}
          {field("clock", "Workflow clock alias")}
        </div>
        {field(
          "record",
          provider === "servicenow"
            ? "ServiceNow record sys_id"
            : provider === "jira"
              ? "Jira issue ID"
              : "PagerDuty incident ID",
        )}
        <p className="text-sm muted">
          The selected profile determines the provider connection, permitted
          records and workflow mapping. Use aliases supplied by the operator.
        </p>
        {provider === "pagerduty" && (
          <div className="stack-3">
            <p>
              Enter a timezone-aware source interval of at most 366 days. Keep
              the original timestamp precision.
            </p>
            {field("since", "Log interval since")}
            {field("until", "Log interval until")}
          </div>
        )}
        {provider !== "servicenow" && (
          <details>
            <summary>Choose exact event occurrences (optional)</summary>
            <p className="text-sm muted">
              An ambiguous endpoint stays unresolved until an admitted matching
              occurrence is selected.
            </p>
            <div className="grid gap-4 sm:grid-cols-2">
              {field(
                "startId",
                provider === "jira" ? "Start history ID" : "Start log event ID",
              )}
              {provider === "jira" &&
                field("startIndex", "Start item index (0 to 255)")}
              {field(
                "endId",
                provider === "jira" ? "End history ID" : "End log event ID",
              )}
              {provider === "jira" &&
                field("endIndex", "End item index (0 to 255)")}
            </div>
          </details>
        )}
        {!IS_DEMO && !freshAuth && (
          <p role="note">
            API read authentication must be configured and current before
            collection.
          </p>
        )}
        <Button
          type="button"
          disabled={pending || request === null || (!IS_DEMO && !freshAuth)}
          onClick={() => void collect()}
        >
          {pending
            ? "Collecting..."
            : IS_DEMO
              ? "View synthetic incident example"
              : "Collect incident clock"}
        </Button>
        {error && (
          <Alert variant="destructive" role="alert">
            <AlertTitle>Collection unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {response && (
          <IncidentResult key={response.result.run_id} response={response} />
        )}
      </CardContent>
    </Card>
  );
}
