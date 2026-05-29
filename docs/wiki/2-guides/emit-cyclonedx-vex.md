# Emit CycloneDX VEX for supply-chain workflows

`evidentia gap analyze --format cyclonedx-vex` renders a gap report as a
CycloneDX 1.6 VEX (Vulnerability Exploitability eXchange) document. VEX lets you
communicate the *analysis state* of each finding to supply-chain tooling —
Dependency-Track and other CycloneDX-aware consumers read this surface directly.

This format slots into the same CycloneDX toolchain Evidentia already uses for
its release SBOM, so VEX is an additive artifact over an existing supply-chain
stack rather than a new format to bolt on.

## Why VEX

Federal and regulatory supply-chain mandates (Executive Order 14028 and the 2026
SEC supply-chain enforcement wave among them) are driving CycloneDX VEX adoption.
VEX answers the question a raw vulnerability list cannot: *for this finding, what
is our analysis state* — is it being worked, accepted, not applicable, resolved?
Emitting your gap report as VEX puts that judgment into a machine-readable,
standards-conformant document your downstream tooling can act on.

## Prerequisites

- Evidentia installed, plus a control inventory (see
  [Run a gap analysis](run-gap-analysis.md)).
- A CycloneDX-aware consumer if you intend to ingest the output (for example
  Dependency-Track). The emit itself needs no extra install.

## Step 1 — Emit the VEX document

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --format=cyclonedx-vex \
  --output=gap-vex.cdx.json
```

`cyclonedx-vex` is a first-class `--format` value. The output is a CycloneDX 1.6
document in which each `ControlGap` becomes one `vulnerability` entry. The entry's
analysis `state` is derived from the gap's `implementation_status` and its
`GapStatus` — so a gap you have marked remediated, accepted, or not applicable
carries that state into the VEX record.

## Step 2 — Compose with your SBOM

Evidentia's release workflow ships an SBOM (`evidentia-sbom.cdx.json`), and the
VEX document is the companion analysis surface. Because both are CycloneDX, you
compose them with standard CycloneDX tooling rather than anything
Evidentia-specific — for example, uploading the SBOM and the VEX together to
Dependency-Track, or merging them with the CycloneDX CLI for distribution to a
downstream consumer.

The general shape:

```bash
# Illustrative — use your CycloneDX tool of choice to associate the
# VEX analysis with the SBOM's component inventory.
cyclonedx merge --input-files evidentia-sbom.cdx.json gap-vex.cdx.json \
  --output-file combined.cdx.json
```

(The exact `cyclonedx` invocation depends on which CycloneDX CLI/version you use;
the point is that the VEX document is portable, standards-conformant input to it.)

## What's next

- **CI-gate the same gaps**: [Emit SARIF](emit-sarif.md) for Code Scanning.
- **SIEM ingest**: [Emit OCSF Detection](emit-ocsf-detection.md).
- **Verify Evidentia's own supply-chain artifacts**: the release SBOM, PEP 740
  attestations, and cosign signatures are covered in
  [Project → Verification](../6-project/verification.md).

## Got stuck?

- A consumer rejects the file: confirm it supports CycloneDX 1.6 and that you are
  feeding it the `--output` file (not the console summary).
- The analysis states look wrong: they are derived from each gap's
  `implementation_status` + `status` (GapStatus). Update the gap statuses (for
  example via [Manage POA&M](manage-poam.md)) and re-emit.
- Need the full flag list: [CLI reference → `evidentia gap analyze`](../4-reference/cli.md).
