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
import { registryDemoCases } from "@/lib/demo/registry-fixtures";
import {
  REGISTRY_NAMES,
  boundedRegistryPreview,
  buildRegistryRequest,
  indexRegistryJson,
  parseRegistryResponse,
  type RegistryName,
  type RegistryRequest,
  type RegistryResponse,
} from "@/lib/registry";

const LABELS: Record<RegistryName, string> = {
  tls: "TLS certificate",
  rdap: "RDAP domain",
  "sam-entity": "SAM entity",
  "sam-exclusions": "SAM exclusions",
  gleif: "GLEIF legal entity",
  fedramp: "FedRAMP product",
  cmvp: "CMVP certificate",
  "fcc-covered-list": "FCC Covered List",
  incommon: "InCommon metadata",
  "ssl-labs": "SSL Labs (live disabled)",
  "security-txt": "security.txt",
};
const FIELDS: Record<RegistryName, readonly { key: string; label: string }[]> =
  {
    tls: [{ key: "hostname", label: "Hostname" }],
    rdap: [{ key: "domain", label: "Domain" }],
    "sam-entity": [{ key: "uei", label: "Unique Entity ID (UEI)" }],
    "sam-exclusions": [{ key: "uei", label: "Unique Entity ID (UEI)" }],
    gleif: [{ key: "lei", label: "Legal Entity Identifier (LEI)" }],
    fedramp: [{ key: "product_id", label: "FedRAMP product ID" }],
    cmvp: [{ key: "certificate_number", label: "CMVP certificate number" }],
    "fcc-covered-list": [
      { key: "organization_name", label: "Organization name" },
    ],
    incommon: [{ key: "entity_id", label: "InCommon entity ID" }],
    "ssl-labs": [
      { key: "hostname", label: "Hostname" },
      { key: "endpoint_ip", label: "Endpoint IP" },
    ],
    "security-txt": [{ key: "hostname", label: "Hostname" }],
  };
const byteSize = (value: string) => new TextEncoder().encode(value).length;

function Preview({ label, value }: { label: string; value: string }) {
  const preview = boundedRegistryPreview(value);
  return (
    <div className="stack-1">
      <h4 className="text-sm font-medium">{label}</h4>
      <pre className="overflow-auto whitespace-pre-wrap break-all text-xs">
        {preview}
      </pre>
      {preview !== value && (
        <p className="text-xs muted">
          Showing {byteSize(preview).toLocaleString()} of{" "}
          {byteSize(value).toLocaleString()} UTF-8 bytes. The full JSON download
          includes the complete value.
        </p>
      )}
    </div>
  );
}

function RegistryResult({ response }: { response: RegistryResponse }) {
  const [page, setPage] = useState(0);
  const result = response.result;
  const start = page * 20;
  const shown = result.observations.slice(start, start + 20);
  const counts = new Map<string, number>();
  for (const diagnostic of result.diagnostics)
    counts.set(diagnostic.code, (counts.get(diagnostic.code) ?? 0) + 1);
  const download = () => {
    const href = URL.createObjectURL(
      new Blob([response.rawJson], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `registry-${result.registry}.json`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  };
  return (
    <section aria-label="Registry result" className="stack-4">
      <dl className="grid gap-2 sm:grid-cols-3">
        <div>
          <dt>Lookup outcome</dt>
          <dd>{result.lookup_outcome}</dd>
        </div>
        <div>
          <dt>Traversal status</dt>
          <dd>{result.collection_status}</dd>
        </div>
        <div>
          <dt>Freshness</dt>
          <dd>{result.freshness}</dd>
        </div>
      </dl>
      <p className="text-sm muted">
        These observations describe the selected source query. They do not
        establish organizational compliance or complete source coverage.
      </p>
      <p>
        {result.observations.length} candidate observations;{" "}
        {result.diagnostics.length} diagnostics.
      </p>
      <Button type="button" variant="outline" onClick={download}>
        Download full registry JSON
      </Button>
      <div aria-label="Source reads" className="stack-3">
        {result.source_reads.map((read) => (
          <Card key={read.read_id}>
            <CardContent className="stack-2 pt-4">
              <p>
                {read.method}: {read.template}
              </p>
              <p className="text-sm">
                Status: {read.status}; freshness: {read.freshness}
              </p>
              <Preview
                label="Retrieval time"
                value={JSON.stringify(read.retrieved_at)}
              />
              <Preview
                label="Selected source scope"
                value={JSON.stringify(read.query_scope)}
              />
              <p className="text-sm">
                Transport verification: {String(read.transport_verified)};
                source signature: {read.source_signature}; cache:{" "}
                {read.cache_state}
              </p>
              <Preview
                label="Publisher date"
                value={JSON.stringify(read.publisher_date)}
              />
              <Preview
                label="Publisher version"
                value={JSON.stringify(read.publisher_version)}
              />
            </CardContent>
          </Card>
        ))}
      </div>
      <div aria-label="Registry diagnostics">
        <h3 className="text-sm font-medium">Diagnostic counts</h3>
        {counts.size === 0 ? (
          <p>None.</p>
        ) : (
          <ul>
            {[...counts].map(([code, count]) => (
              <li key={code}>
                {code}: {count}
              </li>
            ))}
          </ul>
        )}
      </div>
      <p>
        Showing {shown.length === 0 ? 0 : start + 1} to {start + shown.length}{" "}
        of {result.observations.length} observations. Each visible field is
        limited to 16 KiB.
      </p>
      <div className="stack-3" aria-label="Candidate observations">
        {shown.map((observation, offset) => {
          const index = start + offset;
          const raw = response.observationJson[index];
          const spans = indexRegistryJson(raw);
          const field = (name: string) =>
            spans.get("value:" + JSON.stringify([name])) ?? "(absent)";
          return (
            <Card key={observation.observation_id}>
              <CardContent className="stack-3 pt-4">
                <p className="text-sm">
                  Candidate {index + 1}; match basis: {observation.match_basis}
                </p>
                <Preview
                  label="Candidate identity"
                  value={field("source_identity")}
                />
                <Preview label="Source dates" value={field("source_times")} />
                <Preview label="Source trust" value={field("trust")} />
                <Preview
                  label="Interpretation and limits"
                  value={field("interpretation")}
                />
                <Preview
                  label="Selected field coverage"
                  value={field("field_coverage")}
                />
                <Preview
                  label="Selected native source fields"
                  value={response.nativeFieldsJson[index]}
                />
              </CardContent>
            </Card>
          );
        })}
      </div>
      {result.observations.length > 20 && (
        <div className="row gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
          >
            Previous candidates
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={start + 20 >= result.observations.length}
            onClick={() => setPage(page + 1)}
          >
            Next candidates
          </Button>
        </div>
      )}
    </section>
  );
}

/** Collect a finite public registry query after fresh read authorization. */
export function RegistryCollectAction({
  freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const initial = IS_DEMO ? registryDemoCases("tls")[0] : undefined;
  const [registry, setRegistry] = useState<RegistryName>("tls");
  const [target, setTarget] = useState<Record<string, string>>(() =>
    initial ? { ...initial.request.target } : {},
  );
  const [scope, setScope] = useState(initial?.request.scope_label ?? "");
  const [samKind, setSamKind] = useState("uei");
  const [scenario, setScenario] = useState(initial?.name ?? "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<RegistryResponse | null>(null);
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
  const loadExample = (name: RegistryName, selected: string) => {
    const example = registryDemoCases(name).find(
      (item) => item.name === selected,
    );
    setScenario(example?.name ?? "");
    setTarget(example ? { ...example.request.target } : {});
    setScope(example?.request.scope_label ?? "");
    setSamKind(
      example && "organization_name" in example.request.target
        ? "organization_name"
        : "uei",
    );
  };
  let request: RegistryRequest | null = null;
  try {
    request = buildRegistryRequest(
      registry,
      registry === "fcc-covered-list"
        ? { ...target, query_scope: "named_organization_entries" }
        : target,
      scope,
    );
  } catch {
    /* Keep invalid forms disabled. */
  }
  const fields =
    registry === "sam-exclusions" && samKind === "organization_name"
      ? [{ key: "organization_name", label: "Organization name" }]
      : FIELDS[registry];
  const disabled = registry === "ssl-labs" && !IS_DEMO;
  const collect = async () => {
    if (
      active.current ||
      request === null ||
      disabled ||
      (!IS_DEMO && !freshAuth)
    )
      return;
    active.current = true;
    setPending(true);
    setResponse(null);
    setError(null);
    const expected = request;
    const ticket = ++generation.current;
    const current = () => mounted.current && ticket === generation.current;
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
      const received = await api.collectRegistry(expected, scenario);
      if (!current()) return;
      setResponse(parseRegistryResponse(received.rawJson, expected));
    } catch {
      if (current())
        setError(
          "Registry collection failed. Check API access and the selected request.",
        );
    } finally {
      if (current()) {
        active.current = false;
        setPending(false);
      }
    }
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Public registries</CardTitle>
        <CardDescription>
          Look up one selected identity and retain its source, traversal and
          freshness evidence.
        </CardDescription>
      </CardHeader>
      <CardContent className="stack-4">
        {IS_DEMO && (
          <Alert>
            <AlertTitle>Synthetic examples</AlertTitle>
            <AlertDescription>
              These examples use simulated source responses and test trust
              settings. No provider is contacted, and no result is an assessment
              of a real organization.
            </AlertDescription>
          </Alert>
        )}
        <div className="stack-2">
          <Label htmlFor="registry-selector">Registry</Label>
          <select
            id="registry-selector"
            value={registry}
            onChange={(event) => {
              invalidate();
              const name = event.target.value as RegistryName;
              setRegistry(name);
              loadExample(
                name,
                IS_DEMO ? (registryDemoCases(name)[0]?.name ?? "") : "",
              );
            }}
          >
            {REGISTRY_NAMES.map((name) => (
              <option key={name} value={name}>
                {LABELS[name]}
              </option>
            ))}
          </select>
        </div>
        {IS_DEMO && (
          <div className="stack-2">
            <Label htmlFor="registry-example">Synthetic example</Label>
            <select
              id="registry-example"
              value={scenario}
              onChange={(event) => {
                invalidate();
                loadExample(registry, event.target.value);
              }}
            >
              {registryDemoCases(registry).map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                </option>
              ))}
            </select>
          </div>
        )}
        {registry === "sam-exclusions" && (
          <div className="stack-2">
            <Label htmlFor="registry-sam-kind">SAM identifier type</Label>
            <select
              id="registry-sam-kind"
              value={samKind}
              onChange={(event) => {
                invalidate();
                setSamKind(event.target.value);
                setTarget({});
              }}
            >
              <option value="uei">Unique Entity ID</option>
              <option value="organization_name">Organization name</option>
            </select>
          </div>
        )}
        {fields.map((field) => (
          <div className="stack-2" key={field.key}>
            <Label htmlFor={`registry-${field.key}`}>{field.label}</Label>
            <Input
              id={`registry-${field.key}`}
              value={target[field.key] ?? ""}
              autoComplete="off"
              onChange={(event) => {
                invalidate();
                setTarget({ ...target, [field.key]: event.target.value });
              }}
            />
          </div>
        ))}
        <div className="stack-2">
          <Label htmlFor="registry-scope">Scope label (optional)</Label>
          <Input
            id="registry-scope"
            value={scope}
            onChange={(event) => {
              invalidate();
              setScope(event.target.value);
            }}
          />
        </div>
        {registry === "fcc-covered-list" && (
          <p className="text-sm muted">
            This query matches named organization entries. Category, affiliate
            and conditional applicability are not assessed.
          </p>
        )}
        {registry === "sam-entity" && (
          <p className="text-sm muted">
            SAM entity results retain partial traversal status because the
            selected response does not prove the end of the source.
          </p>
        )}
        {disabled && (
          <Alert>
            <AlertTitle>SSL Labs live collection is disabled</AlertTitle>
            <AlertDescription>
              No assessment, cache lookup or registration request will be sent.
            </AlertDescription>
          </Alert>
        )}
        {!IS_DEMO && !freshAuth && (
          <p role="note">
            API read authentication must be configured and current before
            collection.
          </p>
        )}
        <Button
          type="button"
          disabled={
            pending || disabled || request === null || (!IS_DEMO && !freshAuth)
          }
          onClick={() => void collect()}
        >
          {pending
            ? "Collecting..."
            : IS_DEMO
              ? "View synthetic registry example"
              : "Collect registry"}
        </Button>
        {error && (
          <Alert variant="destructive" role="alert">
            <AlertTitle>Collection unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {response && (
          <RegistryResult key={response.result.run_id} response={response} />
        )}
      </CardContent>
    </Card>
  );
}
