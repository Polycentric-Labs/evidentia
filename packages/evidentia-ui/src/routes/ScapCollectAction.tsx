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
import { SCAP_DEMO_CASES, scapDemoSource } from "@/lib/demo/scap-fixtures";
import {
  SCAP_ASSERTION_BYTES,
  SCAP_PROFILES,
  SCAP_SOURCE_BYTES,
  boundedScapPreview,
  parseScapAssertion,
  parseScapResponse,
  prepareScapUpload,
  type ScapCompletionAssertion,
  type ScapProfile,
  type ScapResponse,
} from "@/lib/scap";

const PAGE = 20;
const failureText =
  "SCAP collection did not complete. Check the selected file, profile, assessment index and optional assertion, then try again.";
function Preview({ value }: { value: unknown }) {
  return (
    <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words rounded bg-muted p-2 text-xs">
      {boundedScapPreview(value)}
    </pre>
  );
}
function download(raw: string, name: string) {
  const url = URL.createObjectURL(
    new Blob([raw], { type: "application/json;charset=utf-8" }),
  );
  const anchor = document.createElement("a");
  try {
    anchor.href = url;
    anchor.download = name;
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}
async function readFile(file: File, limit: number): Promise<ArrayBuffer> {
  if (file.size < 1 || file.size > limit)
    throw new Error("Invalid local file size");
  const raw = await file.arrayBuffer();
  if (raw.byteLength !== file.size || raw.byteLength > limit)
    throw new Error("Invalid local file read");
  return raw;
}
function SourceValue({
  response,
  reference,
}: {
  response: ScapResponse;
  reference: {
    node_index: number;
    slot: string;
    attribute_index: number | null;
  };
}) {
  const node = response.result.native_document.nodes[reference.node_index];
  if (node.kind !== "element") return null;
  let value = node.text ?? "";
  if (reference.slot === "attribute_value")
    value = node.attributes[reference.attribute_index!].value;
  else if (reference.slot === "element_simple_content")
    value += node.children
      .map((index) => response.result.native_document.nodes[index].tail ?? "")
      .join("");
  return <Preview value={value} />;
}
export function ScapCollectAction({
  freshAuth,
  authInvalidated = !freshAuth,
  verifyAuth,
}: {
  freshAuth: boolean;
  authInvalidated?: boolean;
  verifyAuth: () => Promise<boolean>;
}) {
  const [profile, setProfile] = useState<ScapProfile>("xccdf-1.2-results");
  const [index, setIndex] = useState("0");
  const [cadence, setCadence] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [sidecar, setSidecar] = useState<File | null>(null);
  const [useAssertion, setUseAssertion] = useState(false);
  const [scenario, setScenario] = useState("xccdf-qualified");
  const [demo, setDemo] = useState<ReturnType<typeof scapDemoSource> | null>(
    null,
  );
  const [response, setResponse] = useState<ScapResponse | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [page, setPage] = useState(0);
  const [timePage, setTimePage] = useState(0);
  const [nodePage, setNodePage] = useState(0);
  const generation = useRef(0),
    mounted = useRef(true),
    busy = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (authInvalidated) generation.current++;
  }, [authInvalidated]);
  const changed = () => {
    generation.current++;
    setError("");
  };
  const loadDemo = () => {
    changed();
    const chosen = scapDemoSource(scenario);
    setDemo(chosen);
    setFile(null);
    setSidecar(null);
    setProfile(chosen.request.source_profile);
    setIndex(String(chosen.request.assessment_index));
    setCadence(chosen.request.cadence_slug ?? "");
    setUseAssertion(chosen.request.completion_assertion !== null);
  };
  const collect = async () => {
    if (busy.current || !freshAuth) return;
    busy.current = true;
    setPending(true);
    setError("");
    const token = ++generation.current;
    const current = () => mounted.current && token === generation.current;
    try {
      if (
        !/^(?:0|[1-9][0-9]{0,2})$/.test(index) ||
        Number(index) > 255 ||
        (!file && !demo)
      )
        throw new Error("Invalid selection");
      const raw = demo ? demo.raw : await readFile(file!, SCAP_SOURCE_BYTES);
      let claim: ScapCompletionAssertion | null = null;
      if (useAssertion) {
        if (profile === "xccdf-1.2-results")
          throw new Error("Assertion requires OVAL");
        if (demo) claim = demo.request.completion_assertion;
        else {
          if (!sidecar) throw new Error("Select assertion sidecar");
          const bytes = await readFile(sidecar, SCAP_ASSERTION_BYTES);
          claim = parseScapAssertion(
            new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
              bytes,
            ),
          );
        }
        if (claim === null) throw new Error("Select assertion sidecar");
      }
      const request = {
        source_profile: profile,
        assessment_index: Number(index),
        cadence_slug: cadence === "" ? null : cadence,
        completion_assertion: claim,
      };
      const prepared = await prepareScapUpload(raw, request);
      if (!current()) return;
      if (!(await verifyAuth()) || !current()) {
        if (current())
          setError(
            "Current authentication is required to collect SCAP evidence.",
          );
        return;
      }
      const received = await api.collectScap(
        prepared.body,
        request,
        demo ? scenario : "",
      );
      // Revalidate the exact wire with this action's captured source, including
      // when a runtime API adapter or a demo implementation returns the value.
      const accepted = await parseScapResponse(
        received.rawJson,
        prepared.expected,
      );
      if (current()) {
        setResponse(accepted);
        setPage(0);
        setTimePage(0);
        setNodePage(0);
      }
    } catch {
      if (current()) setError(failureText);
    } finally {
      busy.current = false;
      if (mounted.current) setPending(false);
    }
  };
  const r = response?.result;
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Import a local SCAP assessment</CardTitle>
        <CardDescription>
          Choose a supported XML result profile and assessment occurrence.
          Collection preserves native observations and does not run a scanner,
          follow source URLs or save evidence automatically.
        </CardDescription>
      </CardHeader>
      <CardContent className="min-w-0 space-y-5">
        {IS_DEMO && (
          <div className="space-y-2 rounded border p-3">
            <Label htmlFor="scap-demo">Synthetic SCAP example</Label>
            <select
              id="scap-demo"
              className="w-full rounded border bg-background p-2"
              value={scenario}
              onChange={(event) => {
                changed();
                setScenario(event.target.value);
                setDemo(null);
              }}
            >
              {SCAP_DEMO_CASES.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
            <Button type="button" variant="outline" onClick={loadDemo}>
              Load synthetic example
            </Button>
            <p className="text-sm text-muted-foreground">
              Demo collection accepts only the loaded synthetic source and its
              explicit request.
            </p>
          </div>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="scap-profile">SCAP source profile</Label>
            <select
              id="scap-profile"
              className="w-full rounded border bg-background p-2"
              value={profile}
              onChange={(event) => {
                changed();
                setProfile(event.target.value as ScapProfile);
                setDemo(null);
                if (event.target.value === "xccdf-1.2-results") {
                  setUseAssertion(false);
                  setSidecar(null);
                }
              }}
            >
              {SCAP_PROFILES.map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="scap-index">Assessment index (zero-based)</Label>
            <Input
              id="scap-index"
              value={index}
              inputMode="numeric"
              onChange={(event) => {
                changed();
                setIndex(event.target.value);
              }}
            />
            <p className="text-xs text-muted-foreground">
              Select one occurrence from 0 through 255. The profile and index
              are never inferred from the filename.
            </p>
          </div>
          <div className="min-w-0 space-y-2">
            <Label htmlFor="scap-file">Local SCAP XML file</Label>
            <Input
              id="scap-file"
              type="file"
              accept=".xml,application/xml,text/xml"
              onChange={(event) => {
                changed();
                setFile(event.target.files?.[0] ?? null);
                setDemo(null);
              }}
            />
            <p className="text-xs text-muted-foreground">
              At most 8 MiB. Exact file bytes are uploaded after your collection
              action.
            </p>
            {demo && (
              <p className="text-sm">
                Loaded synthetic bytes: {demo.raw.byteLength}
              </p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="scap-cadence">Cadence slug (optional)</Label>
            <Input
              id="scap-cadence"
              value={cadence}
              onChange={(event) => {
                changed();
                setCadence(event.target.value);
              }}
            />
            <p className="text-xs text-muted-foreground">
              Use an existing cadence. Import time never substitutes for
              assessment completion.
            </p>
          </div>
        </div>
        {profile !== "xccdf-1.2-results" && (
          <div className="space-y-3 rounded border p-3">
            <Label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={useAssertion}
                onChange={(event) => {
                  changed();
                  setUseAssertion(event.target.checked);
                }}
              />
              Use an OVAL completion assertion sidecar
            </Label>
            <p className="text-sm text-muted-foreground">
              The six-field JSON must bind this file hash, profile and index.
              Completion is operator asserted; the API records the authenticated
              actor. It does not attest to source authenticity.
            </p>
            {useAssertion && (
              <div className="space-y-2">
                <Label htmlFor="scap-assertion">
                  Local OVAL assertion JSON (at most 2 KiB)
                </Label>
                <Input
                  id="scap-assertion"
                  type="file"
                  accept=".json,application/json"
                  onChange={(event) => {
                    changed();
                    setSidecar(event.target.files?.[0] ?? null);
                    setDemo(null);
                  }}
                />
              </div>
            )}
          </div>
        )}
        <Button
          type="button"
          disabled={pending || !freshAuth}
          onClick={() => void collect()}
        >
          {pending ? "Collecting SCAP..." : "Collect SCAP"}
        </Button>
        {!freshAuth && (
          <p role="status" className="text-sm">
            Current authentication is required before collection.
          </p>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertTitle>SCAP collection unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {r && response && (
          <section
            aria-label="SCAP collection result"
            className="min-w-0 space-y-5 rounded border p-4"
          >
            <h3 className="font-semibold">Imported SCAP observations</h3>
            <p className="text-sm">
              One informational summary finding. Native results below do not
              establish vulnerability, compliance, scanner population
              completeness or source authenticity.
            </p>
            <dl className="grid min-w-0 gap-3 sm:grid-cols-2">
              <div>
                <dt className="font-medium">Source profile and SHA-256</dt>
                <dd>
                  <Preview
                    value={{
                      profile: r.source.profile,
                      sha256: r.source.sha256,
                      bytes: r.source.bytes,
                    }}
                  />
                </dd>
              </div>
              <div>
                <dt className="font-medium">Selected and unselected scope</dt>
                <dd>
                  <Preview
                    value={{
                      selection: r.assessment.selection,
                      visible_units: r.assessment.coverage.visible_unit_count,
                      unselected_units:
                        r.assessment.coverage.unselected_unit_count,
                      selected_outcomes:
                        r.assessment.coverage.selected_outcome_count,
                      visible_outcomes:
                        r.assessment.coverage.visible_outcome_count,
                    }}
                  />
                </dd>
              </div>
              <div>
                <dt className="font-medium">Completion and actor provenance</dt>
                <dd>
                  <Preview value={r.completion} />
                </dd>
              </div>
              <div>
                <dt className="font-medium">
                  Artifact availability and cadence
                </dt>
                <dd>
                  <Preview
                    value={{
                      artifact: r.artifact_availability,
                      cadence: r.cadence,
                    }}
                  />
                </dd>
              </div>
              <div>
                <dt className="font-medium">Import observation time</dt>
                <dd>
                  <Preview value={r.imported_at} />
                </dd>
              </div>
              <div>
                <dt className="font-medium">Coverage limits</dt>
                <dd>
                  <Preview value={r.assessment.coverage} />
                </dd>
              </div>
            </dl>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => download(response.rawJson, "scap-result.json")}
              >
                Download full SCAP result
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={response.artifactRawJson === null}
                onClick={() => {
                  if (response.artifactRawJson !== null)
                    download(response.artifactRawJson, "scap-evidence.json");
                }}
              >
                Download evidence artifact
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Downloads retain the complete validated values. Nothing has been
              saved to the evidence store.
            </p>
            <section aria-label="Native SCAP outcomes">
              <h4 className="font-medium">Native outcome observations</h4>
              <p className="text-sm">
                {r.assessment.outcomes.length} outcomes; rows{" "}
                {r.assessment.outcomes.length ? page * PAGE + 1 : 0} through{" "}
                {Math.min((page + 1) * PAGE, r.assessment.outcomes.length)}.
              </p>
              <div className="max-w-full overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr>
                      <th>Node</th>
                      <th>Level</th>
                      <th>Native result</th>
                      <th>Original literal</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.assessment.outcomes
                      .slice(page * PAGE, (page + 1) * PAGE)
                      .map((item) => (
                        <tr key={item.node_index}>
                          <td>{item.node_index}</td>
                          <td>{item.level}</td>
                          <td>{item.native_result}</td>
                          <td>
                            <SourceValue
                              response={response}
                              reference={item.value_ref}
                            />
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  disabled={page === 0}
                  onClick={() => setPage(page - 1)}
                >
                  Previous outcomes
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={(page + 1) * PAGE >= r.assessment.outcomes.length}
                  onClick={() => setPage(page + 1)}
                >
                  Next outcomes
                </Button>
              </div>
            </section>
            <section aria-label="SCAP time roles">
              <h4 className="font-medium">Source times and roles</h4>
              {r.assessment.times
                .slice(timePage * PAGE, (timePage + 1) * PAGE)
                .map((item, offset) => (
                  <div
                    className="my-2 rounded border p-2"
                    key={timePage * PAGE + offset}
                  >
                    <Preview
                      value={{
                        role: item.role,
                        scope: item.scope,
                        scope_node_index: item.scope_node_index,
                        normalization: item.normalization,
                      }}
                    />
                    <SourceValue
                      response={response}
                      reference={item.value_ref}
                    />
                  </div>
                ))}
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  disabled={timePage === 0}
                  onClick={() => setTimePage(timePage - 1)}
                >
                  Previous times
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={(timePage + 1) * PAGE >= r.assessment.times.length}
                  onClick={() => setTimePage(timePage + 1)}
                >
                  Next times
                </Button>
              </div>
            </section>
            <details>
              <summary>Native source graph (inert text)</summary>
              <p className="text-xs">
                Each preview is bounded. All declarations, node fields and
                source order remain in the full download.
              </p>
              <Preview
                value={{
                  declaration: r.native_document.declaration,
                  text: r.native_document.text,
                  children: r.native_document.children,
                }}
              />
              {r.native_document.nodes
                .slice(nodePage * PAGE, (nodePage + 1) * PAGE)
                .map((node, offset) => (
                  <div key={nodePage * PAGE + offset}>
                    <p className="text-xs">Node {nodePage * PAGE + offset}</p>
                    <Preview value={node} />
                  </div>
                ))}
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  disabled={nodePage === 0}
                  onClick={() => setNodePage(nodePage - 1)}
                >
                  Previous nodes
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  disabled={
                    (nodePage + 1) * PAGE >= r.native_document.nodes.length
                  }
                  onClick={() => setNodePage(nodePage + 1)}
                >
                  Next nodes
                </Button>
              </div>
            </details>
            <section aria-label="SCAP diagnostics">
              <h4 className="font-medium">Qualification and limits</h4>
              <ul className="list-disc pl-5 text-sm">
                {r.diagnostics.map((item) => (
                  <li key={item.code}>{item.message}</li>
                ))}
              </ul>
            </section>
          </section>
        )}
      </CardContent>
    </Card>
  );
}
