import { useQuery } from "@tanstack/react-query";
import { useCallback, useId, useLayoutEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { api } from "@/lib/api";
import { IS_DEMO } from "@/lib/demo";
import {
  bindNativeControl,
  createNativeSelection,
  nativeBundleDownload,
  nativeDocumentDownload,
  nativePreview,
  nativeRefText,
  occurrencePage,
  type NativeBundle,
  type NativeRequest,
  type ValueRef,
  type CatalogNativeOccurrence,
} from "@/lib/catalog-native";
import type { CatalogControl, CatalogSourceRow } from "@/types/catalog";

const NOTICE_DATES = [
  ["approved_on", "Approved"],
  ["published_on", "Published"],
  ["order_effective_on", "Order effective"],
  ["effective_on", "Applicable"],
  ["inactive_on", "Inactive"],
] as const;

function SourceReference({ value, label }: { value: string; label: string }) {
  let clickable = false;
  try {
    const url = new URL(value);
    clickable =
      /^https?:\/\//i.test(value) &&
      (url.protocol === "https:" || url.protocol === "http:") &&
      !url.username &&
      !url.password &&
      !/[\u0000-\u0020\u007f]/.test(value);
  } catch {
    // Catalog sources can be repository names or other non-URL references.
  }
  return clickable ? (
    <a href={value} target="_blank" rel="noopener noreferrer">
      {label}
    </a>
  ) : (
    <span>{value || "Not provided"}</span>
  );
}

function SourceValue({ value }: { value: CatalogSourceRow["source_id"] }) {
  if (value === null) return <span className="muted">Blank (null)</span>;
  if (value === "") return <span className="muted">Empty text ("")</span>;
  const kind =
    typeof value === "string"
      ? /^\s+$/.test(value)
        ? "whitespace-only text"
        : "text"
      : typeof value;
  return (
    <>
      <span style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {typeof value === "boolean" ? String(value) : value}
      </span>
      <span className="muted"> ({kind})</span>
    </>
  );
}

function SourceRowDetail({
  row,
  controlId,
}: {
  row: CatalogSourceRow;
  controlId: string;
}) {
  const resolved = row.resolved_values ?? {};
  const columns = [
    ...new Set([...Object.keys(row.values), ...Object.keys(resolved)]),
  ];
  const provenance = Object.entries(row.provenance ?? {});
  return (
    <article
      aria-label={`${controlId}, source row ${row.row}`}
      className="stack-3"
    >
      <h3 className="base">
        {controlId}: source row {row.row}
      </h3>
      <dl className="stack-2">
        <div>
          <dt className="muted">Sheet</dt>
          <dd>
            <SourceValue value={row.sheet} />
          </dd>
        </div>
        <div>
          <dt className="muted">Physical row</dt>
          <dd>{row.row}</dd>
        </div>
        <div>
          <dt className="muted">Row kind</dt>
          <dd>{row.kind}</dd>
        </div>
        <div>
          <dt className="muted">Original identifier</dt>
          <dd>
            <SourceValue value={row.source_id} />
          </dd>
        </div>
        <div>
          <dt className="muted">Source number format</dt>
          <dd>
            {row.source_id_format == null ? (
              "Not provided"
            ) : (
              <SourceValue value={row.source_id_format} />
            )}
          </dd>
        </div>
        <div>
          <dt className="muted">Interpreted identifier</dt>
          <dd>
            {row.interpreted_id == null ? (
              "Not provided"
            ) : (
              <SourceValue value={row.interpreted_id} />
            )}
          </dd>
        </div>
        <div>
          <dt className="muted">Source SHA-256 (claimed)</dt>
          <dd>
            <code style={{ overflowWrap: "anywhere" }}>
              {row.source_sha256}
            </code>
          </dd>
        </div>
      </dl>
      {columns.length > 0 ? (
        <div className="table-wrap">
          <table className="tbl">
            <caption className="sr-only">Source cells</caption>
            <thead>
              <tr>
                <th scope="col">Column</th>
                <th scope="col">Original cell</th>
                <th scope="col">Merge-anchor value</th>
              </tr>
            </thead>
            <tbody>
              {columns.map((column) => (
                <tr key={column}>
                  <th
                    scope="row"
                    style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                  >
                    {column}
                  </th>
                  <td>
                    {Object.hasOwn(row.values, column) ? (
                      <SourceValue value={row.values[column]} />
                    ) : (
                      "Column not retained"
                    )}
                  </td>
                  <td>
                    {Object.hasOwn(resolved, column) ? (
                      <SourceValue value={resolved[column]} />
                    ) : (
                      "No merge projection"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">No source columns retained.</p>
      )}
      <div className="stack-2">
        <h4 className="base">Provenance</h4>
        {provenance.length > 0 ? (
          <dl className="stack-2">
            {provenance.map(([key, value]) => (
              <div key={key}>
                <dt
                  className="muted"
                  style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                >
                  {key}
                </dt>
                <dd
                  style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                >
                  {key === "source_url" && value !== "" ? (
                    <SourceReference value={value} label={value} />
                  ) : (
                    <SourceValue value={value} />
                  )}
                </dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="muted">No provenance provided.</p>
        )}
      </div>
    </article>
  );
}

function sourceRowCount(control: CatalogControl): number {
  return (
    (control.source_rows?.length ?? 0) +
    control.enhancements.reduce(
      (count, enhancement) => count + sourceRowCount(enhancement),
      0,
    )
  );
}

function SourceRowsContent({ control }: { control: CatalogControl }) {
  return (
    <>
      {control.source_rows?.map((row, index) => (
        <SourceRowDetail
          key={`${row.sheet}:${row.row}:${index}`}
          row={row}
          controlId={control.id}
        />
      ))}
      {control.enhancements.map((enhancement) => (
        <SourceRowsContent key={enhancement.id} control={enhancement} />
      ))}
    </>
  );
}

function ControlSourceRows({ control }: { control: CatalogControl }) {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();
  const count = sourceRowCount(control);
  if (count === 0) return null;
  return (
    <CardContent className="pt-0 text-sm stack-3">
      <Button
        variant="outline"
        size="sm"
        aria-label={`Source rows for ${control.id} (${count})`}
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => setExpanded(!expanded)}
      >
        Source rows ({count})
      </Button>
      {expanded && (
        <section
          id={panelId}
          aria-label={`Source rows for ${control.id}`}
          className="stack-6"
        >
          <p className="muted">
            Source evidence does not add assessed controls. Original cells and
            reviewed merge-anchor values are shown separately. Row properties do
            not determine applicability.
          </p>
          <SourceRowsContent control={control} />
        </section>
      )}
    </CardContent>
  );
}

function NativeText({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const preview = nativePreview(text);
  return (
    <div>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {expanded ? text : preview.text}
      </pre>
      {preview.truncated && (
        <Button
          variant="outline"
          size="sm"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Collapse source text" : "Expand source text"}
        </Button>
      )}
    </div>
  );
}

function NativeSpan({
  bundle,
  reference,
}: {
  bundle: NativeBundle;
  reference: ValueRef;
}) {
  return (
    <div>
      <p className="text-xs muted">
        Document {reference.document_index}, bytes {reference.byte_start} to{" "}
        {reference.byte_end} ({reference.kind})
      </p>
      <NativeText text={nativeRefText(bundle, reference)} />
    </div>
  );
}

function NativeOccurrence({
  bundle,
  occurrence,
}: {
  bundle: NativeBundle;
  occurrence: CatalogNativeOccurrence;
}) {
  return (
    <article
      className="stack-3"
      aria-label={"Native occurrence " + occurrence.index}
    >
      <h3>
        Occurrence {occurrence.index}: {occurrence.kind}
      </h3>
      <p>
        Parent:{" "}
        {occurrence.parent_index === null ? "none" : occurrence.parent_index}.
        Source order: {occurrence.sibling_ordinal}.
      </p>
      <NativeSpan bundle={bundle} reference={occurrence.source} />
      <dl>
        {occurrence.fields.map((field, index) => (
          <div key={index}>
            <dt>{field.name}</dt>
            <dd>
              <NativeSpan bundle={bundle} reference={field.value} />
            </dd>
          </div>
        ))}
      </dl>
      <dl>
        {occurrence.selections.map((selection, index) => (
          <div key={index}>
            <dt>{selection.role}</dt>
            <dd>
              {selection.value.state === "absent" ? (
                "Absent"
              ) : (
                <>
                  <p>
                    {selection.value.state === "native_null"
                      ? "Native null"
                      : "Present"}
                  </p>
                  {selection.value.refs.map((reference, refIndex) => (
                    <NativeSpan
                      key={refIndex}
                      bundle={bundle}
                      reference={reference}
                    />
                  ))}
                </>
              )}
            </dd>
          </div>
        ))}
      </dl>
    </article>
  );
}

export function NativeSourcePanel({
  catalog,
  authGeneration,
}: {
  catalog: import("@/types/catalog").ControlCatalog;
  authGeneration: string;
}) {
  const bundle = catalog.native_source;
  const [selected, setSelected] = useState(
    bundle?.data.control_bindings[0]?.control_id ?? "",
  );
  const [page, setPage] = useState(0);
  const [selection] = useState(createNativeSelection);
  const [running, setRunning] = useState<{
    ticket: ReturnType<typeof selection.begin>;
    auth: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [last, setLast] = useState<{
    bundle: NativeBundle;
    control: string;
    auth: string;
    signal: AbortSignal;
  } | null>(null);
  const epoch = useRef(0);
  const pending =
    running !== null &&
    !running.ticket.signal.aborted &&
    running.auth === authGeneration &&
    running.ticket.framework === catalog.framework_id &&
    running.ticket.bundle === bundle?.bundle_sha256 &&
    running.ticket.selection === selected;
  const invalidate = useCallback(() => {
    selection.invalidate();
    setRunning(null);
    setLast((prior) => (prior ? { ...prior } : prior));
  }, [selection]);
  useLayoutEffect(() => {
    const changed = () => invalidate();
    window.addEventListener("focus", changed);
    window.addEventListener("storage", changed);
    return () => {
      selection.invalidate();
      window.removeEventListener("focus", changed);
      window.removeEventListener("storage", changed);
    };
  }, [
    selection,
    invalidate,
    catalog.framework_id,
    bundle?.bundle_sha256,
    selected,
    authGeneration,
  ]);
  if (!bundle) return null;
  const load = async () => {
    if (IS_DEMO || pending || !selected) return;
    const ticket = selection.begin(
      catalog.framework_id,
      bundle.bundle_sha256,
      selected,
      ++epoch.current,
    );
    const current = () => !ticket.signal.aborted;
    setRunning({ ticket, auth: authGeneration });
    setError(null);
    try {
      const received = await api.getCatalogNative(
        {
          framework_id: catalog.framework_id as NativeRequest["framework_id"],
          bundle_sha256: bundle.bundle_sha256,
        },
        ticket.signal,
      );
      if (!current() || !selection.accept(ticket, received)) return;
      setLast({
        bundle: received,
        control: selected,
        auth: authGeneration,
        signal: ticket.signal,
      });
      setPage(0);
    } catch {
      if (current())
        setError(
          "Native source could not be verified. The last verified result is retained.",
        );
    } finally {
      if (current()) setRunning(null);
    }
  };
  const activeDownload =
    !IS_DEMO &&
    last !== null &&
    !last.signal.aborted &&
    last.bundle.data.catalog_id === catalog.framework_id &&
    last.bundle.bundle_sha256 === bundle.bundle_sha256 &&
    last.control === selected &&
    last.auth === authGeneration;
  const download = (documentIndex?: number) => {
    if (!activeDownload || !last || last.signal.aborted) return;
    const value =
      documentIndex === undefined
        ? nativeBundleDownload(last.bundle)
        : nativeDocumentDownload(last.bundle, documentIndex);
    const filename =
      documentIndex === undefined
        ? last.bundle.data.catalog_id + "-native.json"
        : last.bundle.data.documents[documentIndex].binding.source_key + ".txt";
    const object = URL.createObjectURL(
      new Blob([new Uint8Array(value)], {
        type:
          documentIndex === undefined
            ? "application/json"
            : "text/plain;charset=utf-8",
      }),
    );
    try {
      const link = document.createElement("a");
      link.href = object;
      link.download = filename;
      link.click();
    } finally {
      URL.revokeObjectURL(object);
    }
  };
  let bound: CatalogNativeOccurrence | null = null;
  if (last) {
    const binding = last.bundle.data.control_bindings.find(
      (row) => row.control_id === last.control,
    )!;
    bound = bindNativeControl(last.bundle, last.control, {
      bundle_sha256: last.bundle.bundle_sha256,
      occurrence_index: binding.occurrence_index,
    });
  }
  const pages = last ? Math.ceil(last.bundle.data.occurrences.length / 20) : 0;
  return (
    <section className="stack-3" aria-label="Native catalog source">
      <h2 className="h2">Native source</h2>
      <p>
        Source text is displayed literally. It does not run commands, load
        images, or open source links.
      </p>
      {IS_DEMO && (
        <p>
          Native source retrieval and downloads are unavailable in the demo.
        </p>
      )}
      <label>
        Source control{" "}
        <select
          value={selected}
          disabled={IS_DEMO}
          onChange={(event) => {
            invalidate();
            setSelected(event.target.value);
          }}
        >
          {bundle.data.control_bindings.map((row) => (
            <option key={row.control_id} value={row.control_id}>
              {row.control_id}
            </option>
          ))}
        </select>
      </label>
      <div className="row gap-2">
        <Button
          disabled={IS_DEMO || pending || !selected}
          onClick={() => void load()}
        >
          {pending ? "Verifying source..." : "Load native source"}
        </Button>
        <Button variant="outline" disabled={!pending} onClick={invalidate}>
          Cancel source request
        </Button>
      </div>
      {error && <p role="alert">{error}</p>}
      {last && (
        <div className="stack-3">
          <p>
            Last verified source: {last.bundle.data.catalog_id}, control{" "}
            {last.control}. Bundle SHA-256:{" "}
            <code>{last.bundle.bundle_sha256}</code>
          </p>
          <Button disabled={!activeDownload} onClick={() => download()}>
            Download native bundle
          </Button>
          <ul>
            {last.bundle.data.documents.map((document, index) => (
              <li key={index}>
                <code>{document.binding.upstream_path}</code> (
                {document.binding.raw_bytes} bytes). SHA-256:{" "}
                <code>{document.binding.raw_sha256}</code>{" "}
                <Button
                  disabled={!activeDownload}
                  variant="outline"
                  onClick={() => download(index)}
                >
                  Download source document {index + 1}
                </Button>
              </li>
            ))}
          </ul>
          {bound && (
            <details>
              <summary>Selected control and its source context</summary>
              <NativeOccurrence bundle={last.bundle} occurrence={bound} />
              {(() => {
                const parents: CatalogNativeOccurrence[] = [];
                let parent = bound.parent_index;
                while (parent !== null) {
                  const row = last.bundle.data.occurrences[parent];
                  parents.push(row);
                  parent = row.parent_index;
                }
                return parents
                  .reverse()
                  .map((row) => (
                    <NativeOccurrence
                      key={row.index}
                      bundle={last.bundle}
                      occurrence={row}
                    />
                  ));
              })()}
            </details>
          )}
          <p>
            Source occurrences, page {page + 1} of {pages}.
          </p>
          <div className="row gap-2">
            <Button
              variant="outline"
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
            >
              Previous occurrences
            </Button>
            <Button
              variant="outline"
              disabled={page + 1 >= pages}
              onClick={() => setPage(page + 1)}
            >
              Next occurrences
            </Button>
          </div>
          {occurrencePage(last.bundle, page).map((row) => (
            <NativeOccurrence
              key={last.bundle.bundle_sha256 + ":" + row.index}
              bundle={last.bundle}
              occurrence={row}
            />
          ))}
        </div>
      )}
    </section>
  );
}

export function FrameworkDetailPage() {
  const { id } = useParams<{ id: string }>();
  const query = useQuery({
    queryKey: ["framework", id],
    queryFn: ({ signal }) => api.getFramework(id ?? "", signal),
    enabled: Boolean(id),
  });
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
    enabled: !IS_DEMO,
  });
  const authGeneration =
    health.status + ":" + health.dataUpdatedAt + ":" + health.errorUpdatedAt;

  if (!id) {
    return (
      <div className="stack-4">
        <Card className="border-dest">
          <CardHeader>
            <CardTitle className="base">No framework ID</CardTitle>
            <CardDescription>No framework ID in URL.</CardDescription>
          </CardHeader>
        </Card>
        <Button asChild variant="outline">
          <Link to="/frameworks">Back to frameworks</Link>
        </Button>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="stack-4">
        <Card className="border-dest">
          <CardHeader>
            <CardTitle className="base">Framework not found</CardTitle>
            <CardDescription>
              Could not load framework <code className="kbd">{id}</code>.
            </CardDescription>
          </CardHeader>
        </Card>
        <Button asChild variant="outline">
          <Link to="/frameworks">Back to frameworks</Link>
        </Button>
      </div>
    );
  }

  if (!query.data) {
    return (
      <div className="stack-6">
        <header className="stack-2">
          <div className="skel" style={{ height: "1.5rem", width: "14rem" }} />
          <div className="skel" style={{ height: "2.25rem", width: "20rem" }} />
          <div className="skel" style={{ height: "1.25rem", width: "16rem" }} />
        </header>
        <section className="stack-3">
          <div className="skel" style={{ height: "1.5rem", width: "8rem" }} />
          <ul className="reset stack-2">
            {[0, 1, 2].map((i) => (
              <li key={i} className="reset">
                <Card>
                  <CardHeader className="pb-3 stack-2">
                    <div
                      className="skel"
                      style={{ height: "1.25rem", width: "6rem" }}
                    />
                    <div
                      className="skel"
                      style={{ height: "1rem", width: "18rem" }}
                    />
                  </CardHeader>
                </Card>
              </li>
            ))}
          </ul>
        </section>
      </div>
    );
  }

  const catalog = query.data;

  return (
    <div className="stack-6">
      <header className="stack-2">
        <div className="row gap-2 wrap">
          <Badge variant="outline">Tier {catalog.tier ?? "?"}</Badge>
          <Badge variant="secondary">{catalog.category}</Badge>
          <Badge
            variant={catalog.status === "retired" ? "destructive" : "outline"}
          >
            {catalog.status || "status unknown"}
          </Badge>
          {catalog.placeholder && (
            <Badge variant="destructive">placeholder</Badge>
          )}
          {catalog.license_required && <Badge>license required</Badge>}
        </div>
        <h1 className="page-title">{catalog.framework_name}</h1>
        <p className="page-sub">
          <code className="kbd">{catalog.framework_id}</code> &middot; version{" "}
          {catalog.version} &middot; {catalog.controls.length} top-level
          controls ({catalog.families.length} families)
        </p>
      </header>

      <section aria-label="Catalog context">
        <Card>
          <CardHeader>
            <CardTitle className="base">Catalog context</CardTitle>
            {catalog.notes && (
              <CardDescription>{catalog.notes}</CardDescription>
            )}
          </CardHeader>
          <CardContent className="pt-0 text-sm stack-2">
            <dl className="stack-2">
              <div>
                <dt className="muted">Source checked</dt>
                <dd>{catalog.verified_on || "Unknown"}</dd>
              </div>
              {catalog.superseded_by && (
                <div>
                  <dt className="muted">Successor</dt>
                  <dd>
                    <Link
                      to={`/frameworks/${encodeURIComponent(catalog.superseded_by)}`}
                    >
                      {catalog.superseded_by}
                    </Link>
                  </dd>
                </div>
              )}
              <div>
                <dt className="muted">Source</dt>
                <dd>
                  <SourceReference
                    value={catalog.source}
                    label="Catalog source"
                  />
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </section>

      {Object.keys(catalog.audit_contexts ?? {}).length > 0 && (
        <section aria-label="Audit contexts" className="stack-3">
          <h2 className="h2">Audit contexts</h2>
          <p className="text-sm muted">
            Unlisted CSA audit versions are unknown.
          </p>
          {Object.entries(catalog.audit_contexts ?? {}).map(
            ([jurisdiction, context]) => (
              <article key={jurisdiction} aria-label={jurisdiction}>
                <Card>
                  <CardHeader>
                    <CardTitle className="base">{jurisdiction}</CardTitle>
                    <CardDescription>{context.authority}</CardDescription>
                  </CardHeader>
                  <CardContent className="pt-0 text-sm stack-2">
                    <dl className="stack-2">
                      <div>
                        <dt className="muted">Audit version</dt>
                        <dd>{context.version}</dd>
                      </div>
                      <div>
                        <dt className="muted">Source checked</dt>
                        <dd>{context.verified_on}</dd>
                      </div>
                      <div>
                        <dt className="muted">Source valid through</dt>
                        <dd>{context.valid_through || "Unknown"}</dd>
                      </div>
                      <div>
                        <dt className="muted">Source</dt>
                        <dd>
                          <SourceReference
                            value={context.source_url}
                            label="Audit source"
                          />
                        </dd>
                      </div>
                    </dl>
                    {context.notes && <p>{context.notes}</p>}
                  </CardContent>
                </Card>
              </article>
            ),
          )}
        </section>
      )}

      {(catalog.publication_notices?.length ?? 0) > 0 && (
        <section aria-label="Publication notices" className="stack-3">
          <h2 className="h2">Publication notices</h2>
          <p className="text-sm muted">
            Publication records are outside the assessed controls and do not
            activate automatically.
          </p>
          {catalog.publication_notices?.map((notice) => (
            <article key={notice.id} aria-label={notice.id}>
              <Card>
                <CardHeader className="stack-2">
                  <div className="row gap-2 wrap">
                    <CardTitle className="base mono">{notice.id}</CardTitle>
                    <Badge variant="outline">{notice.status}</Badge>
                  </div>
                  <CardDescription>{notice.title}</CardDescription>
                </CardHeader>
                <CardContent className="pt-0 text-sm stack-2">
                  <dl className="stack-2">
                    {NOTICE_DATES.map(([field, label]) => (
                      <div key={field}>
                        <dt className="muted">{label}</dt>
                        <dd>{notice[field] || "Unknown"}</dd>
                      </div>
                    ))}
                    {notice.superseded_by && (
                      <div>
                        <dt className="muted">Successor designator</dt>
                        <dd>{notice.superseded_by}</dd>
                      </div>
                    )}
                    <div>
                      <dt className="muted">Source</dt>
                      <dd>
                        <SourceReference
                          value={notice.source_url}
                          label="Publication source"
                        />
                      </dd>
                    </div>
                  </dl>
                  {notice.notes && <p>{notice.notes}</p>}
                </CardContent>
              </Card>
            </article>
          ))}
        </section>
      )}

      {catalog.license_terms && (
        <Card>
          <CardHeader>
            <CardTitle className="base">License</CardTitle>
            <CardDescription>{catalog.license_terms}</CardDescription>
          </CardHeader>
        </Card>
      )}

      <NativeSourcePanel
        key={catalog.framework_id}
        catalog={catalog}
        authGeneration={authGeneration}
      />

      <section aria-labelledby="controls-list" className="stack-3">
        <h2 id="controls-list" className="h2">
          Controls
        </h2>
        <ul className="reset stack-2">
          {catalog.controls.map((ctrl) => (
            <li key={ctrl.id} className="reset">
              <Card>
                <CardHeader className="pb-3 stack-2">
                  <div
                    className="row-between gap-4"
                    style={{ alignItems: "flex-start" }}
                  >
                    <CardTitle className="base mono">{ctrl.id}</CardTitle>
                    <div className="row gap-2 wrap">
                      {ctrl.family && (
                        <Badge variant="outline">{ctrl.family}</Badge>
                      )}
                      {ctrl.priority && (
                        <Badge variant="secondary">
                          Priority: {ctrl.priority}
                        </Badge>
                      )}
                      {ctrl.withdrawn && (
                        <Badge variant="secondary">withdrawn</Badge>
                      )}
                    </div>
                  </div>
                  <CardDescription>{ctrl.title}</CardDescription>
                </CardHeader>
                {ctrl.description && !ctrl.placeholder && (
                  <CardContent className="pt-0 text-sm muted">
                    {ctrl.description.length > 300
                      ? `${ctrl.description.slice(0, 300)}...`
                      : ctrl.description}
                  </CardContent>
                )}
                {ctrl.placeholder && (
                  <CardContent className="pt-0 text-sm muted">
                    <span style={{ fontStyle: "italic" }}>
                      Placeholder control. Supply your licensed copy via{" "}
                      <code className="kbd">evidentia catalog import</code>.
                    </span>
                  </CardContent>
                )}
                {Object.keys(ctrl.properties ?? {}).length > 0 && (
                  <CardContent className="pt-0 text-sm">
                    <dl className="stack-2">
                      {Object.entries(ctrl.properties ?? {}).map(
                        ([key, value]) => (
                          <div key={key}>
                            <dt className="muted">{key}</dt>
                            <dd>
                              {key === "source_url" ? (
                                <SourceReference
                                  value={value}
                                  label="Control source"
                                />
                              ) : (
                                value
                              )}
                            </dd>
                          </div>
                        ),
                      )}
                    </dl>
                  </CardContent>
                )}
                <ControlSourceRows control={ctrl} />
              </Card>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
