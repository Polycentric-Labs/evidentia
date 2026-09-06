<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/evidentia-banner-dark.png">
  <img src="docs/brand/evidentia-banner-light.png" alt="Evidentia — open-source compliance-as-code, OSCAL-native" width="820">
</picture>

<p>
  <strong>Open-source compliance-as-code</strong> — gap analysis, evidence collection, OSCAL emit.
  <br>
  Apache-2.0 · Python 3.12+
</p>

<p>
  <a href="#quickstart-60-seconds"><img src="https://img.shields.io/badge/Get%20Started-1D58A5?style=for-the-badge" alt="Get Started"></a>
  <a href="https://github.com/Polycentric-Labs/evidentia/wiki"><img src="https://img.shields.io/badge/Documentation-0E1B25?style=for-the-badge" alt="Documentation"></a>
  <a href="https://pypi.org/project/evidentia/"><img src="https://img.shields.io/badge/PyPI-15478A?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI"></a>
</p>

<p>
  <a href="https://pypi.org/project/evidentia/"><img src="https://img.shields.io/pypi/v/evidentia.svg" alt="PyPI version"></a>
  <a href="https://github.com/Polycentric-Labs/evidentia/actions/workflows/test.yml"><img src="https://github.com/Polycentric-Labs/evidentia/actions/workflows/test.yml/badge.svg?branch=main" alt="tests"></a>
  <a href="https://codecov.io/gh/Polycentric-Labs/evidentia"><img src="https://codecov.io/gh/Polycentric-Labs/evidentia/branch/main/graph/badge.svg" alt="codecov"></a>
  <a href="docs/parity-coverage.md"><img src="https://img.shields.io/badge/CLI%E2%86%94GUI%20parity-100%25-brightgreen.svg" alt="CLI↔GUI parity"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/python-3.12+-1D58A5.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License: Apache 2.0">
  <a href="https://www.bestpractices.dev/projects/12724"><img src="https://www.bestpractices.dev/projects/12724/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Polycentric-Labs/evidentia"><img src="https://api.scorecard.dev/projects/github.com/Polycentric-Labs/evidentia/badge" alt="OpenSSF Scorecard"></a>
</p>

<p>
  <a href="CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/Contributor%20Covenant-2.1-1D58A5.svg" alt="Code of Conduct"></a>
</p>

</div>

---

## What is Evidentia?

Evidentia turns compliance from a spreadsheet problem into a software problem. It ingests NIST OSCAL catalogs, runs gap analysis against your evidence, and emits OSCAL Assessment Results, SARIF for CI gates, OCSF Compliance + Detection Findings for SIEMs, and CycloneDX VEX for supply-chain workflows — all from a Python library, CLI, or REST API.

Built for compliance engineers, GRC teams, and CISOs who want to:

- Ship audit-grade evidence with cryptographic provenance (Sigstore + PEP 740 + SLSA Provenance v1).
- Map controls across frameworks via **97 bundled catalogs** (NIST 800-53 Rev 5, FedRAMP + FedRAMP CR26 KSIs and provider-facing Requirements, CMMC 2.0, ISO 27001, CSF 2.0, EU AI Act, DORA, NIS2, GDPR, OpenSSF OSPS Baseline, the full FFIEC stack, and all 15 comprehensive US state privacy laws).
- Drive AI agents (Claude Desktop, Claude Code, Copilot CLI) deterministically via MCP tools with signed output envelopes.

## Install

```bash
pip install evidentia
```

For the full workspace (AI risk-statements, REST API, all collectors, MCP server):

```bash
pip install 'evidentia[ai,api,collectors,mcp]'
```

Container: `docker pull ghcr.io/polycentric-labs/evidentia:v0.12.1` (cosign keyless OIDC + SLSA Provenance v1 verified).

See the [Getting Started wiki section](https://github.com/Polycentric-Labs/evidentia/wiki/Getting-Started) for air-gapped install, virtualenv setup, and full extras matrix.

## Quickstart (60 Seconds)

`evidentia gap analyze` is inventory-driven: `--inventory` is the file of controls you *have*; `--frameworks` is the catalogs to measure *against*. A ready-to-run sample inventory ships inside the wheel.

```bash
# 1. List bundled framework catalogs
evidentia catalog list

# 2. Locate the bundled sample inventory (maps to nist-800-53-rev5-moderate)
SAMPLE=$(python -c "import importlib.resources as r; print(r.files('evidentia.examples')/'sample-inventory.yaml')")

# 3. Run gap analysis against a framework
evidentia gap analyze \
  --inventory "$SAMPLE" --frameworks nist-800-53-rev5-moderate \
  --output gap-report.json

# 4. Emit OSCAL Assessment Results
evidentia gap analyze \
  --inventory "$SAMPLE" --frameworks nist-800-53-rev5-moderate \
  --output assessment-results.json --format oscal-ar
```

Full 5-minute walk-through: [Quickstart wiki page](https://github.com/Polycentric-Labs/evidentia/wiki/Quickstart).

### Live Demo

See it first, no install — a self-hosted [asciinema](https://asciinema.org/) recording of the exact `doctor → catalog list → gap analyze → oscal verify` sequence on the Meridian Financial sample, plus a clickable, backend-free demo console:

[**▶ Watch the CLI demo**](https://demo.evidentiagrc.com/#/demo) · [**Click through the demo console**](https://demo.evidentiagrc.com/)

## Features

- **OSCAL-native end-to-end** — Ingest NIST OSCAL catalogs (Catalog 1.2.1); emit OSCAL Assessment Results + Plan-of-Action-and-Milestones (POA&M) on the established FedRAMP Rev 5 package rail.
- **FedRAMP CR26 machine-readable SDR emission** — `evidentia conmon ksi` emits the CR26 Security Decision Record `keySecurityIndicators` block (10 families / 46 KSIs) conformant to FedRAMP's official 2026-06-24 schemas (vendored at pinned upstream SHAs, drift-watched weekly) — the first production-grade open-source emitter of the CR26 SDR format.
- **Cryptographic evidence chain** — Sigstore keyless signing on Assessment Results; PEP 740 attestations on every published wheel; SLSA Provenance v1 on the container; CycloneDX 1.7 SBOM on every GitHub Release.
- **97 framework catalogs + 16 crosswalks** — NIST 800-53 Rev 5 (full 1,196 controls + Low/Moderate/High/Privacy baselines), CSF 2.0, FedRAMP (Rev 5 baselines + CR26 Key Security Indicators + the 180 provider-facing CR26 Requirements), CMMC 2.0 L1/L2, OpenSSF OSPS Baseline (Maturity 1/2/3 + first public OSCAL serialization), ISO 27001:2022, EU AI Act, DORA, NIS2, GDPR, all 15 US state privacy laws, full FFIEC IT Examination Handbook, OCC Bulletin 2026-13a / FRB SR 26-02. Plus 16 inter-framework crosswalks.
- **14 evidence collectors** — AWS, GitHub (including v0.10.6 OSPS conformance helpers), Postgres, MySQL, Oracle, SQLite, MS-SQL, Snowflake, Databricks, Okta, Vanta, Drata, BitSight, SecurityScorecard. All OCSF-aligned with `compliance_status` field.
- **OCSF-aligned findings** — OCSF Compliance Finding (class_uid 2003) via `--format ocsf`; OCSF Detection Finding (class_uid 2004) via `--format ocsf-detection`. SARIF 2.1.0 for CI gates via `--format sarif`. CycloneDX 1.6 VEX via `--format cyclonedx-vex`.
- **14 MCP tools** — Drive Evidentia from Claude Desktop, Claude Code, or any MCP host. Append-only tool contract per [`docs/api-stability.md`](docs/api-stability.md) (NORMATIVE). Signed output envelopes (CIMD) per [`docs/evidence-integrity.md`](docs/evidence-integrity.md).
- **OSPS Baseline conformance** — First public open-source project to ship a machine-readable per-control OSPS Baseline conformance attestation ([`OSPS-CONFORMANCE.md`](docs/OSPS-CONFORMANCE.md)) with a CI gate that re-validates every evidence link on push/PR/cron.

## What's in the Box

| Surface | Count |
|---|---|
| Workspace packages | 9 (8 Python on PyPI + 1 TypeScript/Vite frontend) |
| Framework catalogs | 97 |
| Inter-framework crosswalks | 16 |
| Evidence collectors | 14 |
| MCP tools | 14 |
| OSCAL serializations | 1 (OpenSSF OSPS Baseline; more on the roadmap) |
| Test suite | 5,000+ tests; mypy strict; ruff clean |

## Documentation

- [**Wiki**](https://github.com/Polycentric-Labs/evidentia/wiki) — Getting Started, Guides, Concepts, Reference, Compliance, Project meta (auto-synced from `docs/wiki/` on every push to main)
- [`docs/api-stability.md`](docs/api-stability.md) — append-only contract; what's frozen vs evolving
- [`docs/architecture/`](docs/architecture/) — system design + extension points
- [`OSPS-CONFORMANCE.md`](docs/OSPS-CONFORMANCE.md) — OpenSSF OSPS Baseline self-attestation + CI gate
- [`docs/verification.md`](docs/verification.md) — consumer-side recipes for PEP 740 + cosign + osv-scanner + SLSA Provenance v1
- [`EOL.md`](docs/EOL.md) — version support windows + cessation comms policy
- [`docs/engineering-practices.md`](docs/engineering-practices.md) — how Evidentia is built, tested, and shipped: the safeguard stack and the candid failures that shaped it

## Recent Releases

**v0.12.1 (2026-09-05)** — *Container rebuild on a fresh hardened base (day-N CVE response), carrying the v0.13 cycle's opening batch*. **Python 3.14 support** (closes #212): `requires-python` lifted to `>=3.12,<3.15` across the workspace after litellm 1.98.x raised its own ceiling (the documented removal trigger), with 3.13/3.14 trove classifiers and 3.14 pytest legs on all three OSes.

**v0.12.0 (2026-08-22)** — *Pre-1.0 hardening — the project's promises become enforceable*. **`conmon ksi` now emits the SDR's `fedRampRequirements` block (SDR-CSO-FRR); new `fedramp-frr-2026` catalog, 97 bundled catalogs.** The v0.12 plan gated the "FRR statements" extra on a cheapness re-verify against the post-08-14 schema set.

**v0.11.2 (2026-08-17)** — *Day-N dependency sweep on a fresh hardened base*. **README brand refresh**, a Polycentric Labs family visual identity: a light/dark `<picture>` banner and purpose-tiered, federal-blue-accented badges, from the new Evidentia brand kit committed under `docs/brand/`.

Full release history: [`CHANGELOG.md`](CHANGELOG.md) | [GitHub Releases](https://github.com/Polycentric-Labs/evidentia/releases)

## Community & Governance

- [`GOVERNANCE.md`](GOVERNANCE.md) — project governance + decision-making
- [`CONTRIBUTING.md`](.github/CONTRIBUTING.md) — how to contribute (issues, PRs, catalogs)
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy (private via [GHSA](https://github.com/Polycentric-Labs/evidentia/security/advisories/new))
- [Code of Conduct](.github/CODE_OF_CONDUCT.md)
- [FAQ (wiki)](https://github.com/Polycentric-Labs/evidentia/wiki/Project) — frequent operator questions

## AI Assistance

This project was developed alongside AI platforms.

Custom infrastructure and integrations built in-house.

Details, including the tools used: [`docs/ai-assistance.md`](docs/ai-assistance.md).

## License

[Apache-2.0](LICENSE) — embeddable in commercial products without copyleft.
