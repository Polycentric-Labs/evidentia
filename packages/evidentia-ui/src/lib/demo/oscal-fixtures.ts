import type {
  SignedArtifactCardProps,
  VerificationCheck,
} from "@/components/common/signed-artifact";
import { FDA_SIGNED_ARTIFACT } from "@/lib/demo/fda-fixtures";

/** A back-matter resource: an embedded finding with its integrity hash. */
export interface OscalBackMatterResource {
  uuid: string;
  title: string;
  mediaType: string;
  sha256: string;
}

/** The demo OSCAL Assessment Results envelope, summarised for display. */
export interface DemoOscalAssessmentResults {
  /** OSCAL document title (`metadata.title`). */
  title: string;
  /** OSCAL schema version (`metadata.oscal-version`). */
  oscalVersion: string;
  /** Framework analysed. */
  framework: string;
  /** ISO timestamp (`metadata.last-modified`). */
  generatedAt: string;
  categoriesRequired: number;
  categoriesSatisfied: number;
  openGaps: number;
  observations: number;
  /** `back-matter.resources[]` — embedded findings, each integrity-hashed. */
  resources: OscalBackMatterResource[];
  /** The signed artifact (filename, digest, signer, Rekor index). */
  artifact: SignedArtifactCardProps;
  /** Read-only verification checks rendered in the verify panel. */
  checks: VerificationCheck[];
}

/**
 * Illustrative emitted-and-signed OSCAL Assessment Results from the FDA 524B
 * demo run. Mirrors `examples/fda-524b-DEMO-example-assessment.oscal.json`.
 * Synthetic, pre-signed values — nothing here is cryptographically live.
 */
export const DEMO_OSCAL_AR: DemoOscalAssessmentResults = {
  title:
    "Gap Analysis: Northwind MedTech (illustrative) · FDA Section 524B Appendix 1",
  oscalVersion: "1.2.1",
  framework: "fda-524b-appendix1",
  generatedAt: FDA_SIGNED_ARTIFACT.signedAt,
  categoriesRequired: 8,
  categoriesSatisfied: 3,
  openGaps: 5,
  observations: 8,
  resources: [
    {
      uuid: "f5240b00-0001-4000-8000-000000000001",
      title: "Finding — Cybersecurity bill of materials (SBOM) absent",
      mediaType: "application/json",
      sha256:
        "3b1c8e7a9d2f40516273849a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192",
    },
    {
      uuid: "f5240b00-0001-4000-8000-000000000002",
      title: "Finding — No coordinated vulnerability disclosure process",
      mediaType: "application/json",
      sha256:
        "7e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3",
    },
    {
      uuid: "f5240b00-0001-4000-8000-000000000003",
      title: "Finding — Security update mechanism undocumented",
      mediaType: "application/json",
      sha256:
        "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
    },
  ],
  artifact: FDA_SIGNED_ARTIFACT,
  checks: [
    {
      id: "digest",
      label: "Back-matter resource digests (SHA-256)",
      status: "verified",
      detail:
        "Every embedded finding hashes to its recorded SHA-256, so the evidence is tamper-evident — re-running the analysis on the same inputs reproduces the same digests.",
    },
    {
      id: "sigstore",
      label: "Sigstore keyless signature",
      status: "verified",
      detail:
        "Fulcio certificate identity confirmed for the signer; the detached bundle binds the signature to the document digest.",
    },
    {
      id: "rekor",
      label: "Rekor transparency-log inclusion",
      status: "verified",
      detail: `Inclusion proof present at log index ${FDA_SIGNED_ARTIFACT.rekorLogIndex}.`,
    },
    {
      id: "gpg",
      label: "GPG detached signature",
      status: "not-applicable",
      detail:
        "Not used — this artifact takes the Sigstore keyless path. The air-gap path signs the same envelope with `gap analyze --sign-with-gpg`.",
    },
  ],
};
