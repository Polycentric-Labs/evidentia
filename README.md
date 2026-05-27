# Evidentia

> **Open-source compliance-as-code: gap analysis, evidence collection, OSCAL emit.** Apache-2.0. Python 3.12+.

[![tests](https://github.com/polycentric-labs/evidentia/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/polycentric-labs/evidentia/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/polycentric-labs/evidentia/branch/main/graph/badge.svg)](https://codecov.io/gh/polycentric-labs/evidentia)
[![PyPI version](https://img.shields.io/pypi/v/evidentia.svg)](https://pypi.org/project/evidentia/)
![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12724/badge?v=silver)](https://www.bestpractices.dev/projects/12724)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Polycentric-Labs/evidentia/badge)](https://scorecard.dev/viewer/?uri=github.com/Polycentric-Labs/evidentia)

---

## What is Evidentia?

Evidentia turns compliance from a spreadsheet problem into a software problem. It ingests NIST OSCAL catalogs, runs gap analysis against your evidence, and emits OSCAL Assessment Results, SARIF for CI gates, OCSF Compliance + Detection Findings for SIEMs, and CycloneDX VEX for supply-chain workflows — all from a Python library, CLI, or REST API.

Built for compliance engineers, GRC teams, and CISOs who want to:

- Ship audit-grade evidence with cryptographic provenance (Sigstore + PEP 740 + SLSA Provenance v1).
- Map controls across frameworks via **92 bundled catalogs** (NIST 800-53 Rev 5, FedRAMP, CMMC 2.0, ISO 27001, CSF 2.0, EU AI Act, DORA, NIS2, GDPR, OpenSSF OSPS Baseline, the full FFIEC stack, and all 15 comprehensive US state privacy laws).
- Drive AI agents (Claude Desktop, Claude Code, Cursor, Copilot CLI) deterministically via MCP tools with signed output envelopes.

## Install

```bash
pip install evidentia
```

For the full workspace (AI risk-statements, REST API, all collectors, MCP server):

```bash
pip install 'evidentia[ai,api,collectors,mcp]'
```

Container: `docker pull ghcr.io/polycentric-labs/evidentia:v0.10.6` (cosign keyless OIDC + SLSA Provenance v1 verified).

See the [Getting Started wiki section](https://github.com/Polycentric-Labs/evidentia/wiki/Getting-Started) for air-gapped install, virtualenv setup, and full extras matrix.

## Quickstart (60 seconds)

```bash
# 1. List bundled framework catalogs
evidentia catalog list

# 2. Run gap analysis against a framework
evidentia gap analyze --framework=nist-800-53-rev5 --evidence-dir=./evidence/

# 3. Emit OSCAL Assessment Results
evidentia gap analyze --framework=nist-800-53-rev5 --evidence-dir=./evidence/ --format=oscal > assessment-results.json
```

Full 5-minute walk-through: [Quickstart wiki page](https://github.com/Polycentric-Labs/evidentia/wiki/Quickstart).

## Features

- **OSCAL-native end-to-end** — Ingest NIST OSCAL catalogs (Catalog 1.2.1); emit OSCAL Assessment Results + Plan-of-Action-and-Milestones (POA&M). Ready for FedRAMP 20x machine-readable submissions.
- **Cryptographic evidence chain** — Sigstore keyless signing on Assessment Results; PEP 740 attestations on every published wheel; SLSA Provenance v1 on the container; CycloneDX 1.6 SBOM on every GitHub Release.
- **92 framework catalogs + 13 crosswalks** — NIST 800-53 Rev 5 (full 1,196 controls + Low/Moderate/High/Privacy baselines), CSF 2.0, FedRAMP, CMMC 2.0 L1/L2, OpenSSF OSPS Baseline (Maturity 1/2/3 + first public OSCAL serialization), ISO 27001:2022, EU AI Act, DORA, NIS2, GDPR, all 15 US state privacy laws, full FFIEC IT Examination Handbook, OCC Bulletin 2026-13a / FRB SR 26-02. Plus 13 inter-framework crosswalks.
- **14 evidence collectors** — AWS, GitHub (including v0.10.6 OSPS conformance helpers), Postgres, MySQL, Oracle, SQLite, MS-SQL, Snowflake, Databricks, Okta, Vanta, Drata, BitSight, SecurityScorecard. All OCSF-aligned with `compliance_status` field.
- **OCSF-aligned findings** — OCSF Compliance Finding (class_uid 2003) via `--format ocsf`; OCSF Detection Finding (class_uid 2004) via `--format ocsf-detection`. SARIF 2.1.0 for CI gates via `--format sarif`. CycloneDX 1.6 VEX via `--format cyclonedx-vex`.
- **13 MCP tools** — Drive Evidentia from Claude Desktop, Claude Code, Cursor, or any MCP host. Append-only tool contract per [`docs/api-stability.md`](docs/api-stability.md) (NORMATIVE). Signed output envelopes (CIMD) per [`docs/evidence-integrity.md`](docs/evidence-integrity.md).
- **OSPS Baseline conformance** — First public open-source project shipping self-attestation against the OpenSSF OSPS Baseline ([`OSPS-CONFORMANCE.md`](OSPS-CONFORMANCE.md)) with a CI gate that re-validates every evidence link on push/PR/cron.

## What's in the box

| Surface | Count |
|---|---|
| Workspace packages | 9 (8 Python on PyPI + 1 TypeScript/Vite frontend) |
| Framework catalogs | 92 |
| Inter-framework crosswalks | 13 |
| Evidence collectors | 14 |
| MCP tools | 13 |
| OSCAL serializations | 1 (OpenSSF OSPS Baseline; more on the v0.11+ roadmap) |
| Test suite | 3,536 tests (mypy strict 0/0 across 279 source files; ruff clean) |
| Consecutive PROCEED-CLEAN releases | 19 (v0.7.x → v0.10.x line) |

## Documentation

- [**Wiki**](https://github.com/Polycentric-Labs/evidentia/wiki) — Getting Started, Guides, Concepts, Reference, Compliance, Project meta (auto-synced from `docs/wiki/` on every push to main)
- [`docs/api-stability.md`](docs/api-stability.md) — append-only contract; what's frozen vs evolving
- [`docs/architecture/`](docs/architecture/) — system design + extension points
- [`OSPS-CONFORMANCE.md`](OSPS-CONFORMANCE.md) — OpenSSF OSPS Baseline self-attestation + CI gate
- [`docs/verification.md`](docs/verification.md) — consumer-side recipes for PEP 740 + cosign + osv-scanner + SLSA Provenance v1
- [`EOL.md`](EOL.md) — version support windows + cessation comms policy

## Recent releases

**v0.10.6 (2026-05-27)** — *OSS first-mover artifacts + downstream OSPS crosswalks + hygiene*. OSPS Baseline 3-catalog bundle + first public OSCAL Catalog 1.2.1 serialization. `OSPS-CONFORMANCE.md` self-attestation + `verify-osps-conformance.yml` CI gate. 5 OSPS-Baseline crosswalks (NIST SSDF, CSF 2.0, EU CRA, PCI DSS 4.0, NIST 800-161). GitHub OSPS collector extension (16 populate-helpers). `SECURITY.md` refresh + `EOL.md` + `docs/verification.md`. Scorecard restoration to 6.5+ via `verify-changelog.yml` SHA pins. OSCAL upstream PR to [oscal-club/awesome-oscal#59](https://github.com/oscal-club/awesome-oscal/pull/59). **19th consecutive PROCEED-CLEAN ship.**

**v0.10.5 (2026-05-26)** — *OCSF Detection Finding + CycloneDX VEX + evidentia-eval extraction*. `evidentia gap analyze --format ocsf-detection` (SIEM-target counterpart to v0.10.0's SARIF). `evidentia gap analyze --format cyclonedx-vex` (supply-chain VEX statements). `evidentia-eval` extracted to a standalone workspace package (the 8th Python package; lazy-import contract preserves air-gap install posture). Collector idempotency hardening via UUID v5 deterministic IDs. **3,443 tests.**

**v0.10.4 (2026-05-24)** — *OCSF symmetry loop close + CHANGELOG pre-tag CI gate*. `evidentia gap analyze --format ocsf` (Compliance Finding 2003; symmetric counterpart to v0.10.0 SARIF + v0.10.1 OCSF ingest). 13th MCP tool `verify_signed_artifact` (append-only). `verify-changelog.yml` pre-tag CI gate (lesson from the v0.10.3 move-tag re-fire). **3,370 tests; 17th consecutive PROCEED-CLEAN.**

Full release history: [`CHANGELOG.md`](CHANGELOG.md) | [GitHub Releases](https://github.com/Polycentric-Labs/evidentia/releases)

## Community + governance

- [`GOVERNANCE.md`](GOVERNANCE.md) — project governance + decision-making
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute (issues, PRs, catalogs)
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy (private via [GHSA](https://github.com/Polycentric-Labs/evidentia/security/advisories/new))
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [FAQ (wiki)](https://github.com/Polycentric-Labs/evidentia/wiki/Project) — frequent operator questions

## AI assistance

This project was developed alongside AI platforms.

Models used: Claude Opus 4.6, Claude Opus 4.7, Sonar Deep Research

## License

[Apache-2.0](LICENSE) — embeddable in commercial products without copyleft.
