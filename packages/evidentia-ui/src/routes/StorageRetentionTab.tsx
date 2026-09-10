import { useEffect, useRef, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { api, ApiError, type StorageRetentionCollectResult } from "@/lib/api";
import { IS_DEMO } from "@/lib/demo";
import {
  buildStorageRetentionRequest,
  parseStorageRetentionResponse,
  snapshotStorageRetentionRequest,
  StorageRetentionResponseError,
  type StorageRetentionResponse,
  STORAGE_S3_REGIONS,
  type StorageProvider,
  type StorageTargetDraft,
} from "@/lib/storage-retention";

const INITIAL_TARGET: StorageTargetDraft = { bucket: "", region: "us-east-1" };
const DEMO_TARGET: StorageTargetDraft = {
  subscription_id: "11111111-2222-4333-8444-555555555555",
  resource_group: "Synthetic_Group",
  account: "syntheticstore",
  container: "synthetic-container",
};
const PROVIDER_HINTS: Record<StorageProvider, string> = {
  s3: "Read Object Lock defaults and versioning for each selected bucket. Use its actual region; owner expectation is optional and is not independently verified.",
  azure:
    "Read the selected account, blob service and container configuration using ARM 2026-04-01. Container WORM can apply when blob-service versioning is disabled.",
  gcs: "Read each selected bucket's retention, lock and versioning configuration. Quoted retention periods remain in source seconds.",
};
function errorText(error: unknown): string {
  if (error instanceof StorageRetentionResponseError) return error.message;
  if (error instanceof ApiError) {
    if (error.status === 401)
      return "API authentication is required. Check the deployment's access configuration.";
    if (error.status === 403)
      return "Read access was denied for this collection.";
    if ([400, 413, 415, 422].includes(error.status))
      return "The storage request is invalid or exceeds the accepted limits.";
    if (error.status === 503)
      return "Storage collection is unavailable in this installation.";
  }
  return "Storage collection failed. Check the API's availability and try again.";
}

export function StorageRetentionTab({
  freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const [provider, setProvider] = useState<StorageProvider>(
    IS_DEMO ? "azure" : "s3",
  );
  const [scopeLabel, setScopeLabel] = useState(IS_DEMO ? "synthetic-demo" : "");
  const [targets, setTargets] = useState<StorageTargetDraft[]>(() => [
    { ...(IS_DEMO ? DEMO_TARGET : INITIAL_TARGET) },
  ]);
  const [result, setResult] = useState<StorageRetentionResponse>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const generation = useRef(0);
  useEffect(
    () => () => {
      ++generation.current;
    },
    [],
  );
  const clearResult = () => {
    setResult(undefined);
    setError(undefined);
  };
  const updateTarget = (
    index: number,
    key: keyof StorageTargetDraft,
    value: string,
  ) => {
    if (running.current) return;
    clearResult();
    setTargets((current) =>
      current.map((target, n) =>
        n === index ? { ...target, [key]: value } : target,
      ),
    );
  };
  const submit = async () => {
    if (running.current || (!IS_DEMO && !freshAuth)) return;
    clearResult();
    let body;
    try {
      body = buildStorageRetentionRequest(provider, scopeLabel, targets);
    } catch (failure) {
      setError(
        failure instanceof Error
          ? failure.message
          : "The storage request is invalid.",
      );
      return;
    }
    const expected = snapshotStorageRetentionRequest(body);
    running.current = true;
    setBusy(true);
    const active = ++generation.current;
    try {
      if (!IS_DEMO) {
        let authenticated = false;
        try {
          authenticated = await verifyAuth();
        } catch {
          /* Treat a failed health read as unconfirmed authentication. */
        }
        if (generation.current !== active) return;
        if (!authenticated) {
          setError(
            "Current API authentication could not be confirmed. No collection was started.",
          );
          return;
        }
      }
      const response = await api.collectStorageRetention(body);
      if (generation.current === active)
        setResult(parseStorageRetentionResponse(response.rawJson, expected));
    } catch (failure) {
      if (generation.current === active) setError(errorText(failure));
    } finally {
      if (generation.current === active) {
        running.current = false;
        setBusy(false);
      }
    }
  };
  const textField = (
    index: number,
    key: keyof StorageTargetDraft,
    label: string,
    maxLength: number,
    hint?: string,
  ) => {
    const id = `storage-${index}-${key}`;
    return (
      <div className="stack-2" key={key}>
        <Label htmlFor={id}>
          {label} {index + 1}
        </Label>
        <Input
          id={id}
          value={targets[index][key] ?? ""}
          maxLength={maxLength}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={hint ? `${id}-hint` : undefined}
          onChange={(event) => updateTarget(index, key, event.target.value)}
        />
        {hint && (
          <p id={`${id}-hint`} className="text-xs muted">
            {hint}
          </p>
        )}
      </div>
    );
  };
  return (
    <section className="stack-6" aria-label="Storage retention collection">
      <Card>
        <CardHeader>
          <CardTitle>Storage retention configuration</CardTitle>
          <CardDescription>
            Read configuration for 1 to 20 operator-selected resources from one
            provider. This does not assess object enforcement, recordset
            completeness or compliance.
          </CardDescription>
        </CardHeader>
        <CardContent className="stack-4">
          {IS_DEMO && (
            <Alert role="note">
              <AlertTitle>Synthetic storage example</AlertTitle>
              <AlertDescription>
                No cloud account is queried. This fixed partial result includes
                a denied read and conflicting hold metadata.
              </AlertDescription>
            </Alert>
          )}
          {!IS_DEMO && !freshAuth && (
            <Alert role="status">
              <AlertTitle>API authentication required</AlertTitle>
              <AlertDescription>
                Live collection is disabled until current API health confirms
                authentication is configured. The API also enforces read
                permissions.
              </AlertDescription>
            </Alert>
          )}
          <form
            className="stack-4"
            aria-label="Storage retention request"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <fieldset className="stack-4" disabled={busy || IS_DEMO}>
              <legend className="sr-only">Selected storage resources</legend>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="stack-2">
                  <Label htmlFor="storage-provider">Storage provider</Label>
                  <select
                    id="storage-provider"
                    className="input"
                    value={provider}
                    onChange={(event) => {
                      if (running.current) return;
                      const next = event.target.value;
                      if (next !== "s3" && next !== "azure" && next !== "gcs")
                        return;
                      clearResult();
                      setProvider(next);
                      setTargets([
                        { ...(next === "s3" ? INITIAL_TARGET : {}) },
                      ]);
                    }}
                  >
                    <option value="s3">Amazon S3</option>
                    <option value="azure">Azure Blob Storage</option>
                    <option value="gcs">Google Cloud Storage</option>
                  </select>
                </div>
                <div className="stack-2">
                  <Label htmlFor="storage-scope">Scope label</Label>
                  <Input
                    id="storage-scope"
                    value={scopeLabel}
                    maxLength={64}
                    autoComplete="off"
                    spellCheck={false}
                    aria-describedby="storage-scope-hint"
                    onChange={(event) => {
                      if (!running.current) {
                        clearResult();
                        setScopeLabel(event.target.value);
                      }
                    }}
                  />
                  <p id="storage-scope-hint" className="text-xs muted">
                    Nonsecret operator alias, up to 64 ASCII letters, digits,
                    underscores, dots or hyphens; start with a letter or digit.
                  </p>
                </div>
              </div>
              <p className="text-sm muted">{PROVIDER_HINTS[provider]}</p>
              {targets.map((_target, index) => (
                <fieldset key={index} className="stack-4 rounded-lg border p-4">
                  <legend className="px-2 font-medium">
                    Target {index + 1}
                  </legend>
                  <div className="grid gap-4 sm:grid-cols-2">
                    {provider === "azure" ? (
                      <>
                        {textField(
                          index,
                          "subscription_id",
                          "Subscription ID",
                          36,
                          "Hyphenated subscription UUID.",
                        )}
                        {textField(
                          index,
                          "resource_group",
                          "Resource group",
                          90,
                          "ASCII letters, digits, underscore, parentheses, dot or hyphen; no final dot.",
                        )}
                        {textField(
                          index,
                          "account",
                          "Storage account",
                          24,
                          "3 to 24 lowercase letters or digits.",
                        )}
                        {textField(
                          index,
                          "container",
                          "Container",
                          63,
                          "3 to 63 lowercase letters, digits or hyphens; no consecutive hyphens.",
                        )}
                      </>
                    ) : (
                      textField(
                        index,
                        "bucket",
                        "Bucket",
                        provider === "s3" ? 63 : 222,
                        "Bucket name only. No URL, object path or query.",
                      )
                    )}
                    {provider === "s3" && (
                      <>
                        <div className="stack-2">
                          <Label htmlFor={`storage-${index}-region`}>
                            Region {index + 1}
                          </Label>
                          <select
                            id={`storage-${index}-region`}
                            className="input"
                            value={targets[index].region ?? "us-east-1"}
                            onChange={(event) =>
                              updateTarget(index, "region", event.target.value)
                            }
                          >
                            {STORAGE_S3_REGIONS.map((region) => (
                              <option key={region} value={region}>
                                {region}
                              </option>
                            ))}
                          </select>
                        </div>
                        {textField(
                          index,
                          "expected_owner",
                          "Expected owner",
                          12,
                          "Optional 12-digit account expectation. Leave empty to omit it.",
                        )}
                      </>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={targets.length === 1}
                    onClick={() => {
                      if (!running.current) {
                        clearResult();
                        setTargets((current) =>
                          current.filter((_item, n) => n !== index),
                        );
                      }
                    }}
                  >
                    Remove target {index + 1}
                  </Button>
                </fieldset>
              ))}
              <Button
                type="button"
                variant="outline"
                disabled={targets.length >= 20}
                onClick={() => {
                  if (!running.current && targets.length < 20) {
                    clearResult();
                    setTargets((current) => [
                      ...current,
                      { ...(provider === "s3" ? INITIAL_TARGET : {}) },
                    ]);
                  }
                }}
              >
                Add target
              </Button>
            </fieldset>
            <p className="text-sm muted">
              Credentials are configured on the API server. No bucket
              enumeration or object reads are performed. Requests are limited to
              64 KiB; bounded source reads may return partial or unavailable
              evidence.
            </p>
            <div className="flex flex-wrap gap-3">
              <Button type="submit" disabled={busy || (!IS_DEMO && !freshAuth)}>
                {busy
                  ? "Collecting storage configuration"
                  : IS_DEMO
                    ? "Show synthetic storage result"
                    : "Collect storage configuration"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => {
                  if (running.current) return;
                  ++generation.current;
                  clearResult();
                  setProvider(IS_DEMO ? "azure" : "s3");
                  setScopeLabel(IS_DEMO ? "synthetic-demo" : "");
                  setTargets([{ ...(IS_DEMO ? DEMO_TARGET : INITIAL_TARGET) }]);
                }}
              >
                Reset storage form
              </Button>
            </div>
          </form>
          {busy && (
            <p role="status">
              Collecting storage configuration. Each planned read will retain
              its outcome.
            </p>
          )}
          {error && (
            <Alert variant="destructive">
              <AlertTitle>Collection could not finish</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
      {result && (
        <StorageResult key={result.result.manifest.run_id} response={result} />
      )}
    </section>
  );
}

function JsonDisclosure({
  label,
  value,
  raw,
}: {
  label: string;
  value?: unknown;
  raw?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="rounded border p-3"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer font-medium">{label}</summary>
      {open && (
        <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
          <code>{raw ?? JSON.stringify(value, null, 2)}</code>
        </pre>
      )}
    </details>
  );
}
function Diagnostics({
  items,
}: {
  items: StorageRetentionCollectResult["diagnostics"];
}) {
  return items.length ? (
    <ul className="list-inside list-disc text-sm">
      {items.map((item, index) => (
        <li key={index}>
          {item.code}
          {item.http_status == null ? "" : ` (HTTP ${item.http_status})`}
        </li>
      ))}
    </ul>
  ) : (
    <p className="text-sm muted">No diagnostics at this level.</p>
  );
}
function StorageResult({ response }: { response: StorageRetentionResponse }) {
  const result = response.result;
  const [downloadError, setDownloadError] = useState(false);
  const download = () => {
    let url: string | undefined;
    let anchor: HTMLAnchorElement | undefined;
    try {
      url = URL.createObjectURL(
        new Blob([response.rawJson], {
          type: "application/json",
        }),
      );
      anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "storage-retention-result.json";
      document.body.append(anchor);
      anchor.click();
      setDownloadError(false);
    } catch {
      setDownloadError(true);
    } finally {
      anchor?.remove();
      if (url) URL.revokeObjectURL(url);
    }
  };
  return (
    <section className="stack-6" aria-label="Storage retention result">
      <Alert
        role="status"
        variant={result.status === "complete" ? "default" : "destructive"}
      >
        <AlertTitle>
          {result.status === "complete"
            ? "Selected configuration reads complete"
            : `Collection incomplete: ${result.status}`}
        </AlertTitle>
        <AlertDescription>
          Object enforcement and recordset completeness were not assessed.
          Configuration applies only to the selected resources; it does not
          establish compliance.
        </AlertDescription>
      </Alert>
      <div className="stack-2 text-sm">
        <p>
          Provider: {result.provider}. Scope label: {result.scope_label}.
          Identity basis: {result.identity_basis}. Authenticated resource
          ownership is unverified.
        </p>
        <p>
          Selected resources: {result.requested_resources}; attempted:{" "}
          {result.attempted_resources}. Planned reads:{" "}
          {result.planned_components}; attempted: {result.attempted_components};
          complete: {result.completed_components}. Findings retained:{" "}
          {result.findings.length}.
        </p>
        <p className="break-all font-mono text-xs">
          Run: {result.manifest.run_id}. Collection interval:{" "}
          {result.started_at} to {result.finished_at}.
        </p>
        <Diagnostics items={result.diagnostics} />
        <Button type="button" variant="outline" onClick={download}>
          Download full storage result JSON
        </Button>
        {downloadError && (
          <p role="alert">
            The JSON download could not be created. The result remains available
            below.
          </p>
        )}
      </div>
      {result.resources.map((resource, resourceIndex) => (
        <Card key={resource.canonical_resource_id}>
          <CardHeader>
            <CardTitle className="break-all text-base">
              {resource.canonical_resource_id}
            </CardTitle>
            <CardDescription>
              Resource collection state: {resource.status}
            </CardDescription>
          </CardHeader>
          <CardContent className="stack-4">
            <JsonDisclosure label="Selected target" value={resource.target} />
            {resource.components.map((component, componentIndex) => (
              <section
                key={component.component_id}
                className="stack-3 rounded-lg border p-4"
                aria-label={`${component.component_id} result`}
              >
                <div className="flex flex-wrap items-center gap-3">
                  <h3 className="font-medium">{component.component_id}</h3>
                  <Badge variant="secondary">{component.status}</Badge>
                </div>
                <p className="text-xs muted">
                  Attempts: {component.attempts}; raw bytes:{" "}
                  {component.raw_bytes}; decoded bytes:{" "}
                  {component.decoded_bytes}; HTTP:{" "}
                  {component.http_status ?? "not received"}.
                </p>
                <p className="break-all font-mono text-xs">
                  Observed: {component.started_at ?? "not started"} to{" "}
                  {component.finished_at ?? "not finished"}.
                </p>
                <Diagnostics items={component.diagnostics} />
                {component.projection ? (
                  <>
                    <p className="text-sm">
                      Native scope: {component.projection.native_scope}. Source
                      API: {component.projection.api_version}.
                    </p>
                    <p className="break-all font-mono text-xs">
                      Source ETag:{" "}
                      {component.projection.source_etag == null
                        ? "not returned"
                        : JSON.stringify(component.projection.source_etag)}
                      . Metageneration:{" "}
                      {component.projection.source_metageneration == null
                        ? "not returned"
                        : JSON.stringify(
                            component.projection.source_metageneration,
                          )}
                      .
                    </p>
                    <p className="text-xs muted">
                      Native fields and the full JSON download preserve the
                      received JSON text, including numeric values and timestamp
                      text. Omitted keys are absent from the selected
                      projection; null, empty text and false remain distinct.
                    </p>
                    <JsonDisclosure
                      label="Native configuration fields"
                      raw={
                        response.nativeFieldsJson[resourceIndex][
                          componentIndex
                        ] ?? undefined
                      }
                    />
                  </>
                ) : (
                  <p>No configuration evidence admitted for this read.</p>
                )}
              </section>
            ))}
          </CardContent>
        </Card>
      ))}
      <JsonDisclosure
        label="Full result, including manifest and findings"
        raw={response.rawJson}
      />
    </section>
  );
}
