# 2. Guides

Task-oriented how-tos. Each page solves a specific operational need.

## Pages in this section

- **[Run gap analysis](run-gap-analysis.md)** — full CLI walkthrough: catalog selection, evidence-dir conventions, output formats, framework crosswalks, partial-coverage handling, faithfulness threshold.

- **[Ingest OCSF](ingest-ocsf.md)** — ingest OCSF Detection Finding output from Prowler / AWS Security Hub / etc.; the `--block-private-ips` SSRF mitigation; the v0.10.1 trust-unmapped contract.

- **[Emit SARIF](emit-sarif.md)** — SARIF 2.1.0 output for CI gates; GitHub Code Scanning ingestion; severity mapping rationale.

- **[Emit OCSF Detection](emit-ocsf-detection.md)** — OCSF Detection Finding class_uid 2004 emit; SIEM ingestion; sample queries.

- **[Emit CycloneDX VEX](emit-cyclonedx-vex.md)** — CycloneDX 1.6 VEX statements; supply-chain composition with the release-time SBOM via standard CycloneDX merge.

- **[Manage POA&M](manage-poam.md)** — POA&M data model + 5-state lifecycle; CLI verbs; OSCAL POA&M emit; integration patterns (Jira, ServiceNow, etc.).

- **[CONMON deployment](conmon-deployment.md)** — CONMON cadence library + CLI; 7 bundled federal cadences; daemon vs read-only deployment patterns.

- **[Sign and verify evidence](sign-and-verify-evidence.md)** — signing + verifying evidence and MCP tool output (`SignedToolOutput` Sigstore keyless) and OSCAL documents (GPG detached); the verification recipe; the append-only / WORM evidence store. (CIMD is the separate OAuth client-scope mechanism, not a signing primitive.)

- **[Air-gapped install](air-gapped-install.md)** — wheelhouse pattern + offline catalog updates; GPG-only fallback for environments without Sigstore reach.

- **[CI integration](ci-integration.md)** — GitHub Actions sample workflow (gap analysis on PR + SARIF upload); GitLab CI sample; Jenkins sample.

- **[OSPS self-assessment](osps-self-assessment.md)** — walk through [`OSPS-CONFORMANCE.md`](../../../OSPS-CONFORMANCE.md) + the `verify-osps-conformance.yml` CI gate; how to fork the pattern for your own project.

## How to use this section

Jump directly to the page that solves your problem. Each guide is self-contained; cross-references to [Concepts](../3-concepts/) point at the "why" if you need depth.

> **Stub status:** as of v0.10.7, only the section index exists; individual guide pages are stubs to be filled in over upcoming cycles. See the v0.10.7+ ROADMAP for fill-in cadence.
