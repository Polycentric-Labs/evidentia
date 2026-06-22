import { useMutation } from "@tanstack/react-query";
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
import { api, ApiError, type OscalVerifyRequest } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * OSCAL Assessment-Result VERIFY console (`/oscal`).
 *
 * READ-ONLY counterpart to the CLI chain-of-custody check
 * (`evidentia oscal verify`). Posts an operator-supplied AR document inline
 * to `POST /api/oscal/verify` and renders the structured verdict: an overall
 * valid/invalid badge, per-check rows (digests / signature / Sigstore — the
 * Sigstore leg shows "skipped (offline)" in air-gapped mode), and the
 * back-matter `digest_checks[]` table (expected vs actual SHA-256).
 *
 * This console NEVER signs. Signing
 * (`evidentia gap analyze --sign-with-gpg / --sign-with-sigstore`) is an
 * air-gap CLI operation by design; the GUI only ever VERIFIES.
 *
 * The verify result is typed loosely (`Record<string, unknown>`) in the
 * client because the server returns a free-form dict with no dedicated
 * response schema, so every field is read defensively below.
 */

// ── defensive readers over the loose Record<string, unknown> verdict ──────

type Verdict = Record<string, unknown>;

function readBool(v: Verdict, key: string): boolean | null {
  const raw = v[key];
  return typeof raw === "boolean" ? raw : null;
}

function readString(v: Verdict, key: string): string | null {
  const raw = v[key];
  return typeof raw === "string" ? raw : null;
}

function readStringArray(v: Verdict, key: string): string[] {
  const raw = v[key];
  if (!Array.isArray(raw)) return [];
  return raw.filter((item): item is string => typeof item === "string");
}

interface DigestCheckRow {
  resource_uuid: string | null;
  title: string | null;
  expected_digest: string | null;
  actual_digest: string | null;
  valid: boolean | null;
}

function readDigestChecks(v: Verdict): DigestCheckRow[] {
  const raw = v["digest_checks"];
  if (!Array.isArray(raw)) return [];
  return raw.map((entry): DigestCheckRow => {
    const row = (entry ?? {}) as Record<string, unknown>;
    return {
      resource_uuid: readString(row, "resource_uuid"),
      title: readString(row, "title"),
      expected_digest: readString(row, "expected_digest"),
      actual_digest: readString(row, "actual_digest"),
      valid: readBool(row, "valid"),
    };
  });
}

/** Surface an ApiError payload (or any error) as readable text. */
function apiErrorText(error: unknown): string {
  if (error instanceof ApiError) {
    // The router returns a plain `{detail: "..."}` for 400 (unparseable AR /
    // both-or-neither identity violation) and a structured body for 422.
    const payload = error.payload;
    if (payload && typeof payload === "object" && "detail" in payload) {
      const detail = (payload as { detail: unknown }).detail;
      if (typeof detail === "string") return detail;
    }
    if (payload != null) return JSON.stringify(payload);
    return error.message;
  }
  return String(error);
}

/** Render a tri-state per-check row (true / false / null = "not checked"). */
function CheckRow({
  label,
  value,
  overrideText,
}: {
  label: string;
  value: boolean | null;
  /** When set, render this text + a neutral pill instead of the bool verdict. */
  overrideText?: string;
}) {
  let text: string;
  let variant: "low" | "critical" | "outline";
  if (overrideText != null) {
    text = overrideText;
    variant = "outline";
  } else if (value === true) {
    text = "valid";
    variant = "low";
  } else if (value === false) {
    text = "invalid";
    variant = "critical";
  } else {
    text = "not checked";
    variant = "outline";
  }
  return (
    <li className="row-between text-sm" style={{ gap: "0.75rem" }}>
      <span>{label}</span>
      <Badge variant={variant}>{text}</Badge>
    </li>
  );
}

export function OscalVerifyPage() {
  const [content, setContent] = useState("");
  const [identity, setIdentity] = useState("");
  const [issuer, setIssuer] = useState("");

  const mutation = useMutation({
    mutationFn: (body: OscalVerifyRequest) => api.oscalVerify(body),
  });

  // Both-or-neither identity pinning (cosign model) — mirror the server guard
  // client-side so the operator gets the constraint before the round-trip.
  const identityTrim = identity.trim();
  const issuerTrim = issuer.trim();
  const identityIncomplete =
    (identityTrim.length > 0) !== (issuerTrim.length > 0);

  const canSubmit =
    content.trim().length > 0 && !identityIncomplete && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    const body: OscalVerifyRequest = {
      content,
      ...(identityTrim.length > 0
        ? {
            expected_sigstore_identity: identityTrim,
            expected_sigstore_issuer: issuerTrim,
          }
        : {}),
    };
    mutation.mutate(body);
  };

  const verdict = mutation.data ?? null;

  return (
    <div className="stack-6">
      <header>
        <h1 className="page-title">OSCAL Verify</h1>
        <p className="page-sub">
          Verify the chain-of-custody of an OSCAL Assessment Result —
          back-matter SHA-256 digests, detached GPG signature, and the
          Sigstore/Rekor identity leg. Read-only.
        </p>
      </header>

      <Alert>
        <AlertTitle>This console verifies — it never signs.</AlertTitle>
        <AlertDescription>
          Signing an Assessment Result is an air-gap CLI operation
          (<code className="kbd">evidentia gap analyze --sign-with-gpg</code> /{" "}
          <code className="kbd">--sign-with-sigstore</code>). This page only ever
          checks an Assessment Result you already hold; a tampered document is a
          negative verdict, not an error.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="base">Assessment Result</CardTitle>
          <CardDescription>
            Paste the OSCAL Assessment Result JSON document. Identity pinning is
            optional and both-or-neither — supply both the expected Sigstore
            identity and its issuer, or leave both blank.
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
            <div className="stack-2">
              <Label htmlFor="oscal-content">
                OSCAL Assessment Result (JSON)
              </Label>
              <Textarea
                id="oscal-content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={12}
                className="mono"
                placeholder={'{\n  "assessment-results": { "uuid": "..." }\n}'}
              />
            </div>

            <div className="grid grid-2">
              <div className="stack-2">
                <Label htmlFor="oscal-identity">
                  Expected Sigstore identity (optional)
                </Label>
                <Input
                  id="oscal-identity"
                  value={identity}
                  onChange={(e) => setIdentity(e.target.value)}
                  placeholder="release@example.com"
                />
              </div>
              <div className="stack-2">
                <Label htmlFor="oscal-issuer">
                  Expected Sigstore issuer (optional)
                </Label>
                <Input
                  id="oscal-issuer"
                  value={issuer}
                  onChange={(e) => setIssuer(e.target.value)}
                  placeholder="https://token.actions.githubusercontent.com"
                />
              </div>
            </div>

            {identityIncomplete && (
              <p
                id="oscal-identity-hint"
                role="alert"
                className="text-xs text-destructive"
              >
                Provide both the expected identity and issuer, or leave both
                blank (cosign both-or-neither model).
              </p>
            )}

            <div className="row-between border-t pt-4">
              <p className="text-xs muted">
                Inline document only — no server path, no persistence, no
                signing.
              </p>
              <Button
                type="submit"
                disabled={!canSubmit}
                aria-describedby="oscal-identity-hint"
              >
                {mutation.isPending ? "Verifying..." : "Verify"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {mutation.isPending && (
        <Card aria-label="Verifying">
          <CardContent className="card-body" style={{ padding: "1.5rem" }}>
            <div className="skel" style={{ height: "6rem" }} />
            <p className="mt-3 text-xs muted" role="status" aria-live="polite">
              Verifying the Assessment Result…
            </p>
          </CardContent>
        </Card>
      )}

      {mutation.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not verify the Assessment Result</AlertTitle>
          <AlertDescription>{apiErrorText(mutation.error)}</AlertDescription>
        </Alert>
      )}

      {verdict && <VerdictPanel verdict={verdict} />}
    </div>
  );
}

/** Render the structured verify verdict (defensive over the loose dict). */
function VerdictPanel({ verdict }: { verdict: Verdict }) {
  const overallValid = readBool(verdict, "overall_valid");
  const digestsValid = readBool(verdict, "digests_valid");
  const signatureValid = readBool(verdict, "signature_valid");
  const offline = readBool(verdict, "offline") === true;
  const sigstoreValid = readBool(verdict, "sigstore_signature_valid");
  const sigstoreStatus = readString(verdict, "sigstore_status");

  const errors = readStringArray(verdict, "errors");
  const warnings = readStringArray(verdict, "warnings");
  const digestChecks = readDigestChecks(verdict);

  return (
    <section className="stack-4" aria-label="Verification verdict">
      <Card className={cn(overallValid === false && "border-dest")}>
        <CardHeader className="row-between">
          <CardTitle className="base">Verdict</CardTitle>
          <Badge variant={overallValid ? "low" : "critical"}>
            {overallValid ? "Valid" : "Invalid"}
          </Badge>
        </CardHeader>
        <CardContent className="stack-4">
          <ul className="reset stack-2">
            <CheckRow label="Back-matter digests" value={digestsValid} />
            <CheckRow label="Detached signature" value={signatureValid} />
            <CheckRow
              label="Sigstore / Rekor identity"
              value={sigstoreValid}
              overrideText={
                offline
                  ? "skipped (offline)"
                  : sigstoreStatus ?? undefined
              }
            />
          </ul>

          {errors.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>Errors</AlertTitle>
              <AlertDescription>
                <ul className="reset stack-1">
                  {errors.map((err, i) => (
                    <li key={i} className="text-xs">
                      {err}
                    </li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}

          {warnings.length > 0 && (
            <Alert>
              <AlertTitle>Warnings</AlertTitle>
              <AlertDescription>
                <ul className="reset stack-1">
                  {warnings.map((warn, i) => (
                    <li key={i} className="text-xs">
                      {warn}
                    </li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      <section className="stack-3" aria-label="Digest checks">
        <h2 className="section-num">Back-matter digest checks</h2>
        {digestChecks.length === 0 ? (
          <div className="empty-state">
            No back-matter resources to check in this document.
          </div>
        ) : (
          <Card>
            <CardContent className="card-body" style={{ padding: "1.5rem" }}>
              <ul className="reset stack-3">
                {digestChecks.map((row, i) => (
                  <li
                    key={row.resource_uuid ?? i}
                    className="stack-1 text-xs"
                    style={
                      i > 0
                        ? {
                            borderTop: "1px solid var(--border)",
                            paddingTop: "0.75rem",
                          }
                        : undefined
                    }
                  >
                    <div className="row-between" style={{ gap: "0.75rem" }}>
                      <span className="font-medium">
                        {row.title ?? row.resource_uuid ?? "(resource)"}
                      </span>
                      <Badge variant={row.valid ? "low" : "critical"}>
                        {row.valid ? "match" : "mismatch"}
                      </Badge>
                    </div>
                    <div className="muted">
                      Expected:{" "}
                      <code className="kbd mono">
                        {row.expected_digest ?? "—"}
                      </code>
                    </div>
                    <div className="muted">
                      Actual:{" "}
                      <code className="kbd mono">
                        {row.actual_digest ?? "—"}
                      </code>
                    </div>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </section>
    </section>
  );
}
