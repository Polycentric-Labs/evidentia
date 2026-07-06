import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

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
import { Textarea } from "@/components/ui/textarea";
import {
  api,
  ApiError,
  extractApiErrorMessage,
  type CatalogCrosswalkResponse,
  type CatalogImportPayload,
} from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * Catalog management console (`/catalog`).
 *
 * This is the WRITE / management surface for the control-catalog store —
 * distinct from the read-only Frameworks browser (`/frameworks`). It wraps
 * the five catalog tooling endpoints the API exposes:
 *
 *   1. Crosswalk — resolve control↔control mappings between two frameworks
 *      (`GET /api/catalog/crosswalk`).
 *   2. Where — show where a framework id resolves from
 *      (`GET /api/catalog/where`): bundled vs user import, on-disk path,
 *      whether a user import shadows a bundled catalog, and its tier.
 *   3. License-info — the redistribution license + tier for a framework
 *      (`GET /api/catalog/license-info/{id}`).
 *   4. Import — register a user catalog from inline content
 *      (`POST /api/catalog/import`). The catalog is sent INLINE (never a
 *      server-side path) so the API never reads an operator-chosen file.
 *   5. Remove — delete a user import (`DELETE /api/catalog/{id}`); bundled
 *      catalogs can't be removed and a missing user import 404s.
 *
 * Each section is an independent form-driven mutation with its own
 * loading / error / empty states.
 */

const FORMAT_OPTIONS: [string, string][] = [
  ["json", "JSON"],
  ["yaml", "YAML"],
];

const TIER_OPTIONS: [string, string][] = [
  ["A", "A"],
  ["B", "B"],
  ["C", "C"],
  ["D", "D"],
];

/** Render the `{status, payload}` of an ApiError as a readable string. */
function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.payload && typeof error.payload === "object") {
      const detail = extractApiErrorMessage(error.payload);
      if (detail) return detail;
      return JSON.stringify(error.payload);
    }
    return error.message;
  }
  return String(error);
}

export function CatalogPage() {
  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">Catalog</h1>
        <p className="page-sub">
          Manage the control-catalog store: cross-walk mappings, resolve where
          a framework comes from, inspect license terms, and import or remove
          user catalogs.
        </p>
      </header>

      <CrosswalkSection />
      <WhereSection />
      <LicenseInfoSection />
      <ImportSection />
      <RemoveSection />
    </div>
  );
}

// ── 1. Crosswalk ─────────────────────────────────────────────────────────

function CrosswalkSection() {
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [control, setControl] = useState("");

  const mutation = useMutation({
    mutationFn: (params: { source: string; target: string; control: string }) =>
      api.catalogCrosswalk(params),
  });

  const canSubmit =
    source.trim().length > 0 &&
    target.trim().length > 0 &&
    control.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate({
      source: source.trim(),
      target: target.trim(),
      control: control.trim(),
    });
  };

  return (
    <section className="stack-3" aria-label="Crosswalk lookup">
      <h2 className="section-num">Crosswalk lookup</h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Resolve a control crosswalk</CardTitle>
          <CardDescription>
            Find how a control in the source framework maps into the target
            framework.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="stack-5"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="crosswalk-source">Source framework</Label>
                <Input
                  id="crosswalk-source"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="nist-800-53"
                  required
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="crosswalk-target">Target framework</Label>
                <Input
                  id="crosswalk-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="soc2-tsc"
                  required
                />
              </div>
            </div>
            <div className="stack-2">
              <Label htmlFor="crosswalk-control">Control id</Label>
              <Input
                id="crosswalk-control"
                value={control}
                onChange={(e) => setControl(e.target.value)}
                placeholder="AC-2"
                required
                style={{ maxWidth: "16rem" }}
              />
            </div>
            <div className="row-between border-t pt-4">
              <p className="text-xs muted">
                Returns the resolved mapping rows for the control.
              </p>
              <Button type="submit" disabled={!canSubmit}>
                {mutation.isPending ? "Resolving..." : "Look up crosswalk"}
              </Button>
            </div>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not resolve crosswalk</AlertTitle>
              <AlertDescription>{errorMessage(mutation.error)}</AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <CrosswalkResult result={mutation.data} />
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function CrosswalkResult({ result }: { result: CatalogCrosswalkResponse }) {
  if (result.total === 0 || result.mappings.length === 0) {
    return (
      <div className="empty-state mt-4">
        No mappings from <code className="kbd">{result.source}</code> to{" "}
        <code className="kbd">{result.target}</code> for{" "}
        <code className="kbd">{result.control}</code>.
      </div>
    );
  }
  return (
    <div className="stack-2 mt-4">
      <div className="row gap-2 wrap">
        <Badge variant="outline">{result.source}</Badge>
        <span aria-hidden="true">&rarr;</span>
        <Badge variant="outline">{result.target}</Badge>
        <Badge variant="secondary">
          {result.total} mapping{result.total === 1 ? "" : "s"}
        </Badge>
      </div>
      <ul className="reset stack-2">
        {result.mappings.map((mapping, idx) => (
          <li key={idx} className="reset">
            <Card>
              <CardContent className="text-xs" style={{ padding: "0.75rem" }}>
                <pre className="mono" style={{ whiteSpace: "pre-wrap", margin: 0 }}>
                  {JSON.stringify(mapping, null, 2)}
                </pre>
              </CardContent>
            </Card>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── 2. Where ─────────────────────────────────────────────────────────────

function WhereSection() {
  const [frameworkId, setFrameworkId] = useState("");

  const mutation = useMutation({
    mutationFn: (id: string) => api.catalogWhere(id),
  });

  const canSubmit = frameworkId.trim().length > 0 && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate(frameworkId.trim());
  };

  const data = mutation.data ?? {};
  const field = (key: string) => {
    const value = data[key];
    if (value === undefined || value === null) return null;
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  };

  return (
    <section className="stack-3" aria-label="Where lookup">
      <h2 className="section-num">Where</h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Resolve where a framework lives</CardTitle>
          <CardDescription>
            Show the source (bundled vs user import), on-disk path, whether the
            catalog is shadowed, and its tier.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="row gap-3 wrap"
            style={{ alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="stack-2" style={{ flex: "1 1 16rem" }}>
              <Label htmlFor="where-framework">Framework id</Label>
              <Input
                id="where-framework"
                value={frameworkId}
                onChange={(e) => setFrameworkId(e.target.value)}
                placeholder="nist-800-53"
                required
              />
            </div>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Resolving..." : "Where"}
            </Button>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not resolve framework</AlertTitle>
              <AlertDescription>{errorMessage(mutation.error)}</AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <dl className="stack-2 mt-4 text-sm">
              <WhereRow label="Source" value={field("source")} />
              <WhereRow label="Path" value={field("path")} mono />
              <WhereRow label="Shadowed" value={field("shadowed")} />
              <WhereRow label="Tier" value={field("tier")} />
            </dl>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

function WhereRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <div className="row gap-2 wrap">
      <dt className="text-xs faint" style={{ minWidth: "6rem" }}>
        {label}
      </dt>
      <dd className="reset">
        {value === null ? (
          <span className="dim">—</span>
        ) : mono ? (
          <code className="kbd">{value}</code>
        ) : (
          <span>{value}</span>
        )}
      </dd>
    </div>
  );
}

// ── 3. License info ──────────────────────────────────────────────────────

function LicenseInfoSection() {
  const [frameworkId, setFrameworkId] = useState("");

  const mutation = useMutation({
    mutationFn: (id: string) => api.catalogLicenseInfo(id),
  });

  const canSubmit = frameworkId.trim().length > 0 && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate(frameworkId.trim());
  };

  const data = mutation.data ?? {};
  const field = (key: string) => {
    const value = data[key];
    if (value === undefined || value === null) return null;
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  };

  return (
    <section className="stack-3" aria-label="License info lookup">
      <h2 className="section-num">License info</h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Inspect license terms</CardTitle>
          <CardDescription>
            Show the redistribution license, tier, and source URL for a
            framework's catalog.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="row gap-3 wrap"
            style={{ alignItems: "flex-end" }}
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="stack-2" style={{ flex: "1 1 16rem" }}>
              <Label htmlFor="license-framework">Framework id</Label>
              <Input
                id="license-framework"
                value={frameworkId}
                onChange={(e) => setFrameworkId(e.target.value)}
                placeholder="iso-27001"
                required
              />
            </div>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? "Loading..." : "License info"}
            </Button>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not load license info</AlertTitle>
              <AlertDescription>{errorMessage(mutation.error)}</AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <dl className="stack-2 mt-4 text-sm">
              <WhereRow label="License" value={field("license")} />
              <WhereRow label="Tier" value={field("tier")} />
              <WhereRow label="URL" value={field("url")} mono />
            </dl>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

// ── 4. Import ────────────────────────────────────────────────────────────

const EMPTY_IMPORT = {
  framework_id: "",
  content: "",
  format: "json",
  name: "",
  tier: "C",
  license_terms: "",
  force: false,
};

function ImportSection() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({ ...EMPTY_IMPORT });

  const mutation = useMutation({
    mutationFn: (payload: CatalogImportPayload) => api.catalogImport(payload),
    onSuccess: () => {
      // A new user import changes what the Frameworks browser resolves.
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      setForm({ ...EMPTY_IMPORT });
    },
  });

  const canSubmit =
    form.framework_id.trim().length > 0 &&
    form.content.trim().length > 0 &&
    !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate({
      framework_id: form.framework_id.trim(),
      content: form.content,
      format: form.format,
      tier: form.tier,
      force: form.force,
      name: form.name.trim() ? form.name.trim() : null,
      license_terms: form.license_terms.trim()
        ? form.license_terms.trim()
        : null,
    });
  };

  return (
    <section className="stack-3" aria-label="Import catalog">
      <h2 className="section-num">Import</h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Import a user catalog</CardTitle>
          <CardDescription>
            Register a catalog from inline content. The framework id is
            authoritative for the on-disk filename and overrides any id inside
            the content.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="stack-5"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="import-framework">Framework id</Label>
                <Input
                  id="import-framework"
                  value={form.framework_id}
                  onChange={(e) =>
                    setForm({ ...form, framework_id: e.target.value })
                  }
                  placeholder="my-custom-framework"
                  required
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="import-name">Name (optional)</Label>
                <Input
                  id="import-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="My Custom Framework"
                />
              </div>
            </div>

            <div className="stack-2">
              <Label htmlFor="import-content">Catalog content</Label>
              <Textarea
                id="import-content"
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
                placeholder="Paste the catalog JSON or YAML here…"
                rows={8}
                required
                className="mono text-xs"
              />
            </div>

            <div className="stack-2">
              <span className="text-sm font-medium leading-none">Format</span>
              <div
                className="row wrap gap-2"
                role="radiogroup"
                aria-label="Content format"
              >
                {FORMAT_OPTIONS.map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    role="radio"
                    aria-checked={form.format === value}
                    onClick={() => setForm({ ...form, format: value })}
                    className={cn("pill", form.format === value && "on")}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="stack-2">
              <span className="text-sm font-medium leading-none">Tier</span>
              <div
                className="row wrap gap-2"
                role="radiogroup"
                aria-label="Redistribution tier"
              >
                {TIER_OPTIONS.map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    role="radio"
                    aria-checked={form.tier === value}
                    onClick={() => setForm({ ...form, tier: value })}
                    className={cn("pill", form.tier === value && "on")}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="stack-2">
              <Label htmlFor="import-license">License terms (optional)</Label>
              <Input
                id="import-license"
                value={form.license_terms}
                onChange={(e) =>
                  setForm({ ...form, license_terms: e.target.value })
                }
                placeholder="Source + redistribution statement"
              />
            </div>

            <div className="row gap-2" style={{ alignItems: "center" }}>
              <input
                id="import-force"
                type="checkbox"
                checked={form.force}
                onChange={(e) => setForm({ ...form, force: e.target.checked })}
              />
              <Label htmlFor="import-force">
                Force — overwrite an existing user import with the same id
              </Label>
            </div>

            <div className="row-between border-t pt-4">
              <p className="text-xs muted">
                Framework id + content are required. Content is sent inline.
              </p>
              <Button type="submit" disabled={!canSubmit}>
                {mutation.isPending ? "Importing..." : "Import catalog"}
              </Button>
            </div>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>
                {mutation.error instanceof ApiError &&
                mutation.error.status === 400
                  ? "Import rejected (400)"
                  : "Could not import catalog"}
              </AlertTitle>
              <AlertDescription>{errorMessage(mutation.error)}</AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <Alert className="mt-4">
              <AlertTitle>Catalog imported</AlertTitle>
              <AlertDescription>
                <pre
                  className="mono text-xs"
                  style={{ whiteSpace: "pre-wrap", margin: 0 }}
                >
                  {JSON.stringify(mutation.data, null, 2)}
                </pre>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </section>
  );
}

// ── 5. Remove ────────────────────────────────────────────────────────────

function RemoveSection() {
  const queryClient = useQueryClient();
  const [frameworkId, setFrameworkId] = useState("");
  const [confirm, setConfirm] = useState(false);

  const mutation = useMutation({
    mutationFn: (id: string) => api.catalogRemove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      setFrameworkId("");
      setConfirm(false);
    },
  });

  const canSubmit =
    frameworkId.trim().length > 0 && confirm && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate(frameworkId.trim());
  };

  const notFound =
    mutation.error instanceof ApiError && mutation.error.status === 404;

  return (
    <section className="stack-3" aria-label="Remove catalog">
      <h2 className="section-num">Remove</h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Remove a user catalog</CardTitle>
          <CardDescription>
            Delete a user import. Bundled catalogs can't be removed; a missing
            user import returns 404.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="stack-5"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <div className="stack-2" style={{ maxWidth: "20rem" }}>
              <Label htmlFor="remove-framework">Framework id</Label>
              <Input
                id="remove-framework"
                value={frameworkId}
                onChange={(e) => setFrameworkId(e.target.value)}
                placeholder="my-custom-framework"
                required
              />
            </div>

            <div className="row gap-2" style={{ alignItems: "center" }}>
              <input
                id="remove-confirm"
                type="checkbox"
                checked={confirm}
                onChange={(e) => setConfirm(e.target.checked)}
              />
              <Label htmlFor="remove-confirm">
                I understand this permanently deletes the user import.
              </Label>
            </div>

            <div className="row-between border-t pt-4">
              <p className="text-xs muted">Requires the confirmation above.</p>
              <Button type="submit" variant="destructive" disabled={!canSubmit}>
                {mutation.isPending ? "Removing..." : "Remove catalog"}
              </Button>
            </div>
          </form>

          {mutation.isError && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not remove catalog</AlertTitle>
              <AlertDescription>
                {notFound
                  ? "No user import for that id — there is nothing to remove, or it is a bundled catalog that can't be removed."
                  : errorMessage(mutation.error)}
              </AlertDescription>
            </Alert>
          )}

          {mutation.isSuccess && (
            <Alert className="mt-4">
              <AlertTitle>Catalog removed</AlertTitle>
              <AlertDescription>
                The user import was deleted.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </section>
  );
}
