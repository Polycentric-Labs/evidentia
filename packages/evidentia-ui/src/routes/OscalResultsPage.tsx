import { FileJson, ShieldCheck } from "lucide-react";

import { MetricCard } from "@/components/common/console";
import {
  SignedArtifactCard,
  VerificationPanel,
} from "@/components/common/signed-artifact";
import { Card, CardContent } from "@/components/ui/card";
import { DEMO_OSCAL_AR } from "@/lib/demo/oscal-fixtures";

/**
 * OSCAL emit/verify console view (read-mostly). Shows a gap run's emitted OSCAL
 * Assessment Results — the document summary, its integrity-hashed back-matter
 * resources, the signed artifact, and a verification panel — reusing the FDA
 * demo's signed-artifact components. Demo-gated and fixture-backed; wiring the
 * live emit/verify against a real run is the v0.10.12 parity work.
 */
export function OscalResultsPage() {
  const ar = DEMO_OSCAL_AR;
  const coverage = Math.round(
    (ar.categoriesSatisfied / ar.categoriesRequired) * 100,
  );

  return (
    <section className="stack-8">
      <header className="stack-2">
        <h1 className="h2-lg">OSCAL Assessment Results — emit &amp; verify</h1>
        <p className="muted">
          Every gap run can emit an OSCAL Assessment Results envelope and sign
          it. This view shows the emitted document, its tamper-evident
          back-matter, and how the signature verifies — the same artifact a CLI
          run produces with{" "}
          <span className="kbd">
            gap analyze --format oscal-ar --sign-with-sigstore
          </span>
          .
        </p>
      </header>

      {/* 1 — the emitted document */}
      <section className="stack-5" aria-labelledby="oscal-doc-heading">
        <p className="section-num">
          <span className="sn-badge">01</span> Emitted document
        </p>
        <h2 id="oscal-doc-heading" className="h2-lg">
          {ar.title}
        </h2>

        <div className="grid-3">
          <MetricCard
            icon={ShieldCheck}
            label="Coverage"
            value={`${coverage}%`}
            bar={coverage}
            description={`${ar.categoriesSatisfied} / ${ar.categoriesRequired} categories satisfied`}
          />
          <MetricCard
            icon={FileJson}
            label="OSCAL version"
            value={ar.oscalVersion}
            description={`Framework: ${ar.framework}`}
          />
          <MetricCard
            label="Open gaps"
            value={ar.openGaps}
            description={`${ar.observations} observations recorded`}
          />
        </div>

        <Card>
          <CardContent
            className="stack-2"
            style={{ padding: "var(--card-pad)" }}
          >
            <p className="muted">
              Back-matter resources — each embedded finding is integrity-hashed
              (SHA-256), so the evidence is reproducible and tamper-evident.
            </p>
            <ul className="oscal-resource-list">
              {ar.resources.map((r) => (
                <li key={r.uuid} className="oscal-resource">
                  <span className="oscal-resource-title">{r.title}</span>
                  <span className="oscal-resource-hash mono" title={r.sha256}>
                    sha256:{r.sha256}
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </section>

      {/* 2 — the signed artifact */}
      <section className="stack-5" aria-labelledby="oscal-artifact-heading">
        <p className="section-num">
          <span className="sn-badge">02</span> Signed artifact
        </p>
        <h2 id="oscal-artifact-heading" className="h2-lg">
          A signed, reproducible evidence artifact
        </h2>
        <SignedArtifactCard
          {...ar.artifact}
          note={
            <>
              Real deployments sign keylessly via Sigstore (Fulcio&nbsp;+ Rekor
              transparency log); this is a pre-signed illustration with a test
              key.
            </>
          }
        />
      </section>

      {/* 3 — verification */}
      <section className="stack-5" aria-labelledby="oscal-verify-heading">
        <p className="section-num">
          <span className="sn-badge">03</span> Verification
        </p>
        <h2 id="oscal-verify-heading" className="h2-lg">
          How the artifact verifies
        </h2>
        <Card>
          <CardContent style={{ padding: "var(--card-pad)" }}>
            <VerificationPanel checks={ar.checks} />
          </CardContent>
        </Card>
        <p className="muted">
          This is an illustrative verification of a pre-signed demo artifact. In
          a real deployment,{" "}
          <span className="kbd">evidentia oscal verify --require-signature</span>{" "}
          performs these checks end-to-end (digests + GPG or Sigstore + Rekor
          inclusion).
        </p>
      </section>
    </section>
  );
}
