# 2. Guides

Task-oriented how-tos. Each page solves a specific operational need.

## Pages in this section

- **[Run gap analysis](run-gap-analysis.md)** — full CLI walkthrough: catalog selection, evidence-dir conventions, output formats, framework crosswalks, partial-coverage handling, faithfulness threshold.

- **[Ingest OCSF](ingest-ocsf.md)** — ingest OCSF Detection Finding output from Prowler / AWS Security Hub / etc.; the `--block-private-ips` SSRF mitigation; the v0.10.1 trust-unmapped contract.

- **[Emit SARIF](emit-sarif.md)** — SARIF 2.1.0 output for CI gates; GitHub Code Scanning ingestion; severity mapping rationale.

- **[Emit OCSF Detection](emit-ocsf-detection.md)** — OCSF Detection Finding class_uid 2004 emit; SIEM ingestion; sample queries.

- **[Emit CycloneDX VEX](emit-cyclonedx-vex.md)** — CycloneDX 1.6 VEX statements; supply-chain composition with the release-time SBOM via standard CycloneDX merge.

- **[Manage POA&M](manage-poam.md)** — POA&M data model + 5-state lifecycle; CLI verbs; OSCAL POA&M emit; integration patterns (Jira, ServiceNow, etc.).

- **[Generate and quantify risk](generate-and-quantify-risk.md)** — qualitative NIST SP 800-30 risk statements (LLM-backed) + deterministic FAIR / Monte-Carlo quantification (`risk generate` / `risk quantify`).

- **[Explain a control](explain-controls.md)** — stream a plain-English explanation of any control (what it means, why it matters, what to do) in the web console; LLM-backed with on-disk caching (`explain`).

- **[Manage third-party risk](manage-third-party-risk.md)** — vendor inventory, concentration-risk reporting, and CAIQ / SIG due-diligence questionnaires (`tprm`), plus the in-browser TPRM screen for browsing, filtering, and adding vendors.

- **[Manage model risk](manage-model-risk.md)** — SR 11-7 / OCC 2026-13a model inventory, model documentation, and validation reports (`model-risk`).

- **[Governance metrics and workflows](governance-metrics-and-workflows.md)** — KRI / KPI / KGI metrics, Effective Challenge, Three-Lines reporting, and process-as-code workflows (`governance`).

- **[AI governance](ai-governance.md)** — EU AI Act risk-tier classification + NIST AI RMF system inventory, FIPS-199 + OMB impact leveling (`ai-gov`).

- **[CONMON deployment](conmon-deployment.md)** — CONMON cadence library + CLI; 7 bundled federal cadences; daemon vs read-only deployment patterns.

- **[Sign and verify evidence](sign-and-verify-evidence.md)** — signing + verifying evidence and MCP tool output (`SignedToolOutput` Sigstore keyless) and OSCAL documents (GPG detached); the verification recipe; the append-only / WORM evidence store. (CIMD is the separate OAuth client-scope mechanism, not a signing primitive.)

- **[Air-gapped install](air-gapped-install.md)** — wheelhouse pattern + offline catalog updates; GPG-only fallback for environments without Sigstore reach.

- **[CI integration](ci-integration.md)** — GitHub Actions sample workflow (gap analysis on PR + SARIF upload); GitLab CI sample; Jenkins sample.

- **[OSPS self-assessment](osps-self-assessment.md)** — walk through [`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md) + the `verify-osps-conformance.yml` CI gate; how to fork the pattern for your own project.

- **[MCP client setup](mcp-client-setup.md)** — run the Evidentia MCP server and wire its 14 tools into Claude Desktop / Claude Code (`mcp`).

- **[Serve the web UI](serve-the-web-ui.md)** — launch the local browser UI for gap analysis + the 8-format gap-export control (`evidentia serve`).

- **[Run evidence collectors](run-collectors.md)** — gather findings from AWS, GitHub, Okta, SQL databases, Snowflake, and more (`collect`); credentials stay server-side, with the `--block-private-ips` SSRF guard and the console's auth-gated run buttons.

- **[Browse and manage catalogs](manage-catalogs.md)** — list, inspect, crosswalk, import, and remove framework catalogs (`catalog`); the bundled-vs-user-imported split and per-catalog license tiers.

- **[Track evidence lineage](track-evidence-lineage.md)** — append-only, WORM-enforced evidence-artifact versioning (`evidence save` / `history` / `show`); distinct from the signing chain.

- **[Manage audit retention](manage-retention.md)** — per-record retention metadata, the WORM extend-only lock, legal holds, and the active → preserved → expired → purged lifecycle (`retention`).

- **[Emit a traceability matrix](emit-traceability-matrix.md)** — emit a signed OSCAL Profile mapping controls to threats (`traceability emit`); plus the read-only console view.

- **[Push to integrations](push-to-integrations.md)** — push gaps to Jira / ServiceNow and publish to Tableau / Power BI (`integrations`); credentials server-side, with an external-push confirmation step.

## How to use this section

Jump directly to the page that solves your problem. Each guide is self-contained; cross-references to [Concepts](../3-concepts/index.md) point at the "why" if you need depth.

All twenty-five guide pages above are live. New guides land here as new operational surfaces ship; see the [ROADMAP](../6-project/roadmap.md) for the forward cadence.
