import {
  BadgeCheck,
  Check,
  FileSignature,
  Minus,
  ShieldCheck,
  ShieldX,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Presentational pieces for a signed OSCAL evidence artifact and its
 * verification summary. Shared by the FDA 524B demo (`FdaDemoPage`) and the
 * OSCAL emit/verify console view. Presentation only — no data fetching and no
 * real cryptography; the demo renders pre-computed, illustrative values.
 */

export interface SignedArtifactCardProps {
  filename: string;
  framework: string;
  /** SHA-256 over the assessment payload. */
  sha256: string;
  /** ULID run identifier. */
  runId: string;
  signedAt: string;
  signer: string;
  /** Sigstore Rekor transparency-log index. */
  rekorLogIndex: string;
  /** Show the "Verified ✓" badge (default true). */
  verified?: boolean;
  /** Status-line label (default "Tamper-evident"). */
  statusLabel?: string;
  /** Disclaimer / context note rendered under the field grid. */
  note?: ReactNode;
}

export function SignedArtifactCard({
  filename,
  framework,
  sha256,
  runId,
  signedAt,
  signer,
  rekorLogIndex,
  verified = true,
  statusLabel = "Tamper-evident",
  note,
}: SignedArtifactCardProps) {
  return (
    <Card className="fda-artifact-card card-accent-top">
      <CardContent className="fda-artifact-body">
        <div className="fda-artifact-head">
          <div className="fda-artifact-file">
            <FileSignature className="fda-artifact-file-ic" aria-hidden />
            <div className="stack-2">
              <p className="fda-artifact-filename mono">{filename}</p>
              <p className="muted fda-artifact-fw">
                Framework: <span className="kbd">{framework}</span>
              </p>
            </div>
          </div>
          {verified && (
            <span className="fda-verified" role="status">
              <BadgeCheck className="fda-verified-ic" aria-hidden />
              Verified ✓
            </span>
          )}
        </div>

        <dl className="fda-artifact-grid">
          <ArtifactField label="SHA-256" mono title={sha256}>
            {middleTruncate(sha256, 14, 12)}
          </ArtifactField>
          <ArtifactField label="Run ID (ULID)" mono>
            {runId}
          </ArtifactField>
          <ArtifactField label="Signed at">{formatSignedAt(signedAt)}</ArtifactField>
          <ArtifactField label="Signer">{signer}</ArtifactField>
          <ArtifactField label="Rekor log index" mono>
            {rekorLogIndex}
          </ArtifactField>
          <ArtifactField label="Status">
            <span className="fda-artifact-status">
              <ShieldCheck className="fda-inline-ic" aria-hidden /> {statusLabel}
            </span>
          </ArtifactField>
        </dl>

        {note != null && <p className="fda-artifact-note muted">{note}</p>}
      </CardContent>
    </Card>
  );
}

function ArtifactField({
  label,
  children,
  mono = false,
  title,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="fda-field box">
      <dt className="fda-field-label">{label}</dt>
      <dd
        className={mono ? "fda-field-value mono" : "fda-field-value"}
        title={title}
      >
        {children}
      </dd>
    </div>
  );
}

/** Middle-truncate a long string (e.g. a SHA-256) for compact display. */
function middleTruncate(value: string, head: number, tail: number): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Render an ISO timestamp as a stable, readable UTC string. */
function formatSignedAt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z")}`;
}

// ── Verification panel ───────────────────────────────────────────────────────

export type VerificationStatus = "verified" | "not-applicable" | "failed";

export interface VerificationCheck {
  id: string;
  label: string;
  status: VerificationStatus;
  detail: ReactNode;
}

const STATUS_ICON: Record<
  VerificationStatus,
  { icon: LucideIcon; cls: string; aria: string }
> = {
  verified: { icon: Check, cls: "ok", aria: "verified" },
  "not-applicable": { icon: Minus, cls: "na", aria: "not applicable" },
  failed: { icon: ShieldX, cls: "bad", aria: "failed" },
};

/** Read-only list of integrity / signature verification checks. */
export function VerificationPanel({ checks }: { checks: VerificationCheck[] }) {
  return (
    <dl className="verify-list">
      {checks.map((c) => {
        const s = STATUS_ICON[c.status];
        const Icon = s.icon;
        return (
          <div key={c.id} className="verify-row">
            <Icon className={cn("verify-ic", s.cls)} aria-label={s.aria} />
            <div className="verify-body">
              <dt className="verify-label">{c.label}</dt>
              <dd className="verify-detail">{c.detail}</dd>
            </div>
          </div>
        );
      })}
    </dl>
  );
}
