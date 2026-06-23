<div align="center">

<img src="packages/evidentia-ui/public/evidentia-og-2400x1260.png" alt="Evidentia — open-source compliance-as-code, OSCAL-native" width="780">

<p>
  <strong>Open-source compliance-as-code</strong> — gap analysis, evidence collection, OSCAL emit.
  <br>
  Apache-2.0 · Python 3.12+
</p>

<p>
  <a href="#quickstart-60-seconds"><img src="https://img.shields.io/badge/Get%20Started-2563EB?style=for-the-badge" alt="Get Started"></a>
  <a href="https://github.com/Polycentric-Labs/evidentia/wiki"><img src="https://img.shields.io/badge/Documentation-1E293B?style=for-the-badge" alt="Documentation"></a>
  <a href="https://pypi.org/project/evidentia/"><img src="https://img.shields.io/badge/PyPI-3775A9?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI"></a>
</p>

<p>
  <a href="https://github.com/Polycentric-Labs/evidentia/actions/workflows/test.yml"><img src="https://github.com/Polycentric-Labs/evidentia/actions/workflows/test.yml/badge.svg?branch=main" alt="tests"></a>
  <a href="https://codecov.io/gh/Polycentric-Labs/evidentia"><img src="https://codecov.io/gh/Polycentric-Labs/evidentia/branch/main/graph/badge.svg" alt="codecov"></a>
  <a href="https://pypi.org/project/evidentia/"><img src="https://img.shields.io/pypi/v/evidentia.svg" alt="PyPI version"></a>
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green.svg" alt="License: Apache 2.0">
  <a href="CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg" alt="Code of Conduct"></a>
  <a href="https://www.bestpractices.dev/projects/12724"><img src="https://www.bestpractices.dev/projects/12724/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Polycentric-Labs/evidentia"><img src="https://api.scorecard.dev/projects/github.com/Polycentric-Labs/evidentia/badge" alt="OpenSSF Scorecard"></a>
  <a href="docs/parity-coverage.md"><img src="https://img.shields.io/badge/CLI%E2%86%94GUI%20parity-98%25-brightgreen.svg" alt="CLI↔GUI parity"></a>
</p>

</div>

---

## What is Evidentia?

Evidentia turns compliance from a spreadsheet problem into a software problem. It ingests NIST OSCAL catalogs, runs gap analysis against your evidence, and emits OSCAL Assessment Results, SARIF for CI gates, OCSF Compliance + Detection Findings for SIEMs, and CycloneDX VEX for supply-chain workflows — all from a Python library, CLI, or REST API.

Built for compliance engineers, GRC teams, and CISOs who want to:

- Ship audit-grade evidence with cryptographic provenance (Sigstore + PEP 740 + SLSA Provenance v1).
- Map controls across frameworks via **95 bundled catalogs** (NIST 800-53 Rev 5, FedRAMP, CMMC 2.0, ISO 27001, CSF 2.0, EU AI Act, DORA, NIS2, GDPR, OpenSSF OSPS Baseline, the full FFIEC stack, and all 15 comprehensive US state privacy laws).
- Drive AI agents (Claude Desktop, Claude Code, Cursor, Copilot CLI) deterministically via MCP tools with signed output envelopes.

## Install

```bash
pip install evidentia
```

For the full workspace (AI risk-statements, REST API, all collectors, MCP server):

```bash
pip install 'evidentia[ai,api,collectors,mcp]'
```

Container: `docker pull ghcr.io/polycentric-labs/evidentia:v0.10.13` (cosign keyless OIDC + SLSA Provenance v1 verified).

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

- **OSCAL-native end-to-end** — Ingest NIST OSCAL catalogs (Catalog 1.2.1); emit OSCAL Assessment Results + Plan-of-Action-and-Milestones (POA&M). Ready for FedRAMP 20x machine-readable submissions.
- **Cryptographic evidence chain** — Sigstore keyless signing on Assessment Results; PEP 740 attestations on every published wheel; SLSA Provenance v1 on the container; CycloneDX 1.6 SBOM on every GitHub Release.
- **95 framework catalogs + 15 crosswalks** — NIST 800-53 Rev 5 (full 1,196 controls + Low/Moderate/High/Privacy baselines), CSF 2.0, FedRAMP, CMMC 2.0 L1/L2, OpenSSF OSPS Baseline (Maturity 1/2/3 + first public OSCAL serialization), ISO 27001:2022, EU AI Act, DORA, NIS2, GDPR, all 15 US state privacy laws, full FFIEC IT Examination Handbook, OCC Bulletin 2026-13a / FRB SR 26-02. Plus 15 inter-framework crosswalks.
- **14 evidence collectors** — AWS, GitHub (including v0.10.6 OSPS conformance helpers), Postgres, MySQL, Oracle, SQLite, MS-SQL, Snowflake, Databricks, Okta, Vanta, Drata, BitSight, SecurityScorecard. All OCSF-aligned with `compliance_status` field.
- **OCSF-aligned findings** — OCSF Compliance Finding (class_uid 2003) via `--format ocsf`; OCSF Detection Finding (class_uid 2004) via `--format ocsf-detection`. SARIF 2.1.0 for CI gates via `--format sarif`. CycloneDX 1.6 VEX via `--format cyclonedx-vex`.
- **13 MCP tools** — Drive Evidentia from Claude Desktop, Claude Code, Cursor, or any MCP host. Append-only tool contract per [`docs/api-stability.md`](docs/api-stability.md) (NORMATIVE). Signed output envelopes (CIMD) per [`docs/evidence-integrity.md`](docs/evidence-integrity.md).
- **OSPS Baseline conformance** — First public open-source project to ship a machine-readable per-control OSPS Baseline conformance attestation ([`OSPS-CONFORMANCE.md`](OSPS-CONFORMANCE.md)) with a CI gate that re-validates every evidence link on push/PR/cron.

## What's in the Box

| Surface | Count |
|---|---|
| Workspace packages | 9 (8 Python on PyPI + 1 TypeScript/Vite frontend) |
| Framework catalogs | 95 |
| Inter-framework crosswalks | 15 |
| Evidence collectors | 14 |
| MCP tools | 13 |
| OSCAL serializations | 1 (OpenSSF OSPS Baseline; more on the v0.11+ roadmap) |
| Test suite | 4,000+ tests; mypy strict; ruff clean |

## Documentation

- [**Wiki**](https://github.com/Polycentric-Labs/evidentia/wiki) — Getting Started, Guides, Concepts, Reference, Compliance, Project meta (auto-synced from `docs/wiki/` on every push to main)
- [`docs/api-stability.md`](docs/api-stability.md) — append-only contract; what's frozen vs evolving
- [`docs/architecture/`](docs/architecture/) — system design + extension points
- [`OSPS-CONFORMANCE.md`](OSPS-CONFORMANCE.md) — OpenSSF OSPS Baseline self-attestation + CI gate
- [`docs/verification.md`](docs/verification.md) — consumer-side recipes for PEP 740 + cosign + osv-scanner + SLSA Provenance v1
- [`EOL.md`](EOL.md) — version support windows + cessation comms policy

## Recent Releases

**v0.10.13 (2026-06-23)** — *Patch — restore the container base to Python 3.13*. **Container base reverted to `python:3.13-slim`** after a Dependabot bump (#83) to `python:3.14-slim` broke `release.yml`'s container build.

**v0.10.12 (2026-06-23)** — *full CLI↔GUI parity build-out + the OMB M-25-21 AI-governance migration*. **OMB M-25-21 "high-impact AI" model**, the AI-governance module now reflects current federal guidance; **Full CLI↔GUI parity build-out**, the local web console grows to **22 consoles at ~98% CLI↔GUI parity** (up from ~13% in v0.10.11), with matched REST endpoints for every new console.

**v0.10.11 (2026-06-17)** — *public demo completion + signed traceability + hygiene*. **Signed Control↔Threat Traceability Matrix**, a new `evidentia traceability emit` verb produces a Sigstore-signable OSCAL profile mapping controls to the threats they mitigate; **OSCAL emit/verify console view**.

Full release history: [`CHANGELOG.md`](CHANGELOG.md) | [GitHub Releases](https://github.com/Polycentric-Labs/evidentia/releases)

## Community & Governance

- [`GOVERNANCE.md`](GOVERNANCE.md) — project governance + decision-making
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute (issues, PRs, catalogs)
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy (private via [GHSA](https://github.com/Polycentric-Labs/evidentia/security/advisories/new))
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [FAQ (wiki)](https://github.com/Polycentric-Labs/evidentia/wiki/Project) — frequent operator questions

## AI Assistance

This project was developed alongside AI platforms.

AI models and tools used: Claude, Codex, Cursor, LangChain, Ollama (and other local models), OpenRouter (incl. Gemini, GPT, etc.), Perplexity.

Custom-built infrastructure and integrations for each.

## License

[Apache-2.0](LICENSE) — embeddable in commercial products without copyleft.
