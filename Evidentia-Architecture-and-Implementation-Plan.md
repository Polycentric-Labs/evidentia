# Evidentia: Architecture & Implementation Plan

**Version:** 1.0.0-draft  
**Date:** April 5, 2026  
**Status:** Definitive — Single Source of Truth  
**Audience:** Senior Engineers, Technical Leads, Contributors  
**License:** Apache 2.0  

> **Implementation status as of 2026-04-29:** v0.7.2 (the
> "supply-chain polish + documentation refresh" release) is the latest
> shipped version. v0.7.3 is in flight (composite action hardening +
> docs polish + audit cleanup). All phases through Phase 2
> (collectors) are SHIPPED. Phase 3 (AI evidence validation) baseline
> is hardened in v0.7.1 — see "Updates since v0.7.0" below. v0.8.0
> ships the AI moat features (DFAH determinism harness, PRT mode,
> MCP server, plugin-contract scaffolding) per
> [`docs/v0.8.0-plan.md`](docs/v0.8.0-plan.md). See
> [`docs/v0.7.3-plan.md`](docs/v0.7.3-plan.md) for the next-release
> scope and [`docs/positioning-and-value.md`](docs/positioning-and-value.md)
> + [`docs/capability-matrix.md`](docs/capability-matrix.md) for
> current competitive positioning and capability test matrix. This
> architecture plan remains the canonical design reference; the
> supplements carry status + forward direction.

---

> ## Updates since v0.7.0
>
> The body of this document describes the v0.7.0 design baseline.
> Subsequent releases extended specific subsystems without changing
> the document's structure. This section is the canonical
> what-changed callout so readers don't need to walk the per-release
> CHANGELOG to understand the current shape.
>
> ### v0.7.1 — AI features enterprise-grade hardening
>
> Brought `evidentia-ai` (`risk_statements/` + `explain/`) up to the
> v0.7.0 collector-pattern enterprise grade. Substantive additions
> to §7.2 (AI Risk Statement Generator) + the as-yet-unwritten §9.1
> (AI evidence validator):
>
> - **`GenerationContext`** Pydantic model in
>   `evidentia_core.audit.provenance` (sibling of `CollectionContext`).
>   Captures per-output AI provenance: `model`, `temperature`,
>   `prompt_hash` (SHA-256 of the rendered prompt), `run_id` (ULID),
>   `generated_at` (RFC 3339 UTC), `attempts`,
>   `instructor_max_retries`, `credential_identity`,
>   `evidentia_version`. Optional field on `RiskStatement` and
>   `PlainEnglishExplanation` (default `None` for v0.7.x backward
>   compat; will tighten to required in v0.8 with deprecation cycle).
> - **9 new `EventAction` entries** under the `evidentia.ai.*`
>   namespace (`AI_RISK_GENERATED`, `AI_RISK_FAILED`, `AI_RISK_RETRY`,
>   `AI_EXPLAIN_GENERATED`, `AI_EXPLAIN_FAILED`, `AI_EXPLAIN_RETRY`,
>   `AI_EXPLAIN_CACHE_HIT`, `AI_RISK_BATCH_COMPLETED`,
>   `AI_EXPLAIN_BATCH_COMPLETED`).
> - **Typed exception hierarchy** in `evidentia_ai.exceptions`:
>   `EvidentiaAIError` (parent), `LLMUnavailableError`,
>   `LLMValidationError`, `RiskStatementError`,
>   `RiskGenerationFailed`, `ExplainError`, `ExplainGenerationFailed`.
>   Closes the v0.7.0 BLOCKER B3 carry-over for both AI subsystems.
> - **Bounded retry against shared `LLM_TRANSIENT_EXCEPTIONS`** via
>   the new `with_retry_async` decorator and
>   `build_retrying`/`build_async_retrying` factory functions in
>   `evidentia_core.audit.retry`. Stacks cleanly on top of
>   Instructor's `max_retries` (which handles validation retries).
> - **Audit-trail correlation** — every `AI_*` event carries
>   `run_id` so SIEM queries can attribute retry storms,
>   regenerations, and final outputs to the same batch.
> - **Best-effort operator identity** via
>   `evidentia_ai.client.get_operator_identity()` — closes the
>   NIST AU-3 "Identity" gap for AI-derived artifacts.
>
> ### v0.7.2 — supply-chain visibility + dev-loop ergonomics
>
> No source-architecture changes. Adds:
>
> - **OpenSSF Scorecard weekly workflow**
>   (`.github/workflows/scorecard.yml`) publishing to
>   `securityscorecards.dev`.
> - **Version-controlled IDE config** —
>   `.vscode/{settings,launch,tasks,extensions}.json` + `.cursorrules`
>   + `.editorconfig` + the `docs/ide-setup.md` walkthrough.
> - **`.gitignore` `.local/`** scratch-directory convention for
>   per-developer working notes.
> - **Catalog-drift false-positive fix** —
>   `yaml.safe_dump(width=200)` byte-stable manifest emit +
>   `--ignore-all-space` workflow guard.
>
> ### v0.7.3 — composite action hardening + docs polish (in flight)
>
> No source-architecture changes. Adds:
>
> - **SHA-pinning** all third-party `uses:` refs across the composite
>   action + every workflow file. Closes OpenSSF Scorecard
>   "Pinned-Dependencies".
> - **Composite action E2E smoke test**
>   (`.github/workflows/action-smoke-test.yml`) catches future
>   action.yml ↔ CLI drift.
> - **SLSA L3 build provenance** via
>   `actions/attest-build-provenance@v2` in `release.yml`. Closes
>   enterprise-grade H2 + restores `gh attestation verify` as a
>   working verifier alongside the PEP 740 path.
> - **Pre-commit hooks** (`.pre-commit-config.yaml`) + **dev
>   container** (`.devcontainer/devcontainer.json`) — closes the two
>   outstanding promises in `docs/ide-setup.md`.
> - **Forward plans** — `docs/v0.8.0-plan.md` (the AI moat) +
>   `docs/sigstore-quickstart.md` (signing walkthrough) +
>   `docs/release-checklist.md` Step 9 verifier-note refresh.
>
> ### Future direction (v0.8.0+)
>
> See [`docs/v0.8.0-plan.md`](docs/v0.8.0-plan.md). The
> `evidentia-ai` package gains a new `eval/` submodule (DFAH
> determinism harness), `risk_statements/` gains a `--emit-trace`
> mode (Policy Reasoning Traces with structured clause citations
> per claim), a new `evidentia-mcp` workspace package exposes the
> library surface to AI agents under the Model Context Protocol,
> and `evidentia_core.plugins.{auth,storage,marketplace}`
> formalises the extension surface for out-of-tree authors. v0.9.0
> reserves the federal-compliance theme (POA&M, CONMON cycle
> calendar) per domain-expert input.

---

> **"Bridge the gap between your controls and your frameworks."**

This document is the exhaustive, authoritative architecture and implementation plan for **Evidentia** — an open-source Governance, Risk, and Compliance (GRC) tool. It contains every decision, rationale, data model, code structure, API endpoint design, integration contract, and phased implementation plan required to begin building immediately. No external design document is needed.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Principles](#2-design-principles)
3. [Technology Stack](#3-technology-stack)
4. [Repository Structure](#4-repository-structure)
5. [Complete Data Models](#5-complete-data-models)
6. [OSCAL Catalog Loading & Cross-Framework Mapping Engine](#6-oscal-catalog-loading--cross-framework-mapping-engine)
7. [Phase 1 MVP: Control Gap Analyzer + AI Risk Statement Generator](#7-phase-1-mvp-control-gap-analyzer--ai-risk-statement-generator)
8. [Phase 2: Evidence Collection Agents](#8-phase-2-evidence-collection-agents)
9. [Phase 3: Evidence Validator + Integration Outputs](#9-phase-3-evidence-validator--integration-outputs)
10. [REST API Design (FastAPI)](#10-rest-api-design-fastapi)
11. [CLI Command Reference](#11-cli-command-reference)
12. [Configuration File Reference](#12-configuration-file-reference)
13. [Dockerfile & Container Strategy](#13-dockerfile--container-strategy)
14. [Phased Implementation Roadmap](#14-phased-implementation-roadmap)
15. [Open-Source Ecosystem Integration Strategy](#15-open-source-ecosystem-integration-strategy)
16. [Security & Credential Handling](#16-security--credential-handling)
17. [Testing Strategy](#17-testing-strategy)
18. [Naming, Branding & Community Strategy](#18-naming-branding--community-strategy)
19. [Appendix A: Bundled Framework Data](#appendix-a-bundled-framework-data)
20. [Appendix B: Known Risks & Mitigations](#appendix-b-known-risks--mitigations)
21. [Appendix C: Minimum Viable IaC for Self-Hosting](#appendix-c-minimum-viable-iac-for-self-hosting)
22. [Appendix D: Storage Backend Abstraction Layer](#appendix-d-storage-backend-abstraction-layer)
23. [Appendix E: OSCAL Output Mapping Specification](#appendix-e-oscal-output-mapping-specification)
24. [Appendix F: Error Handling & Observability](#appendix-f-error-handling--observability)
25. [Appendix G: Contributor Guide Architecture](#appendix-g-contributor-guide-architecture)

---


## 1. Executive Summary

Evidentia is an open-source, Python-first GRC tool that provides five core capabilities:

1. **Control Gap Analysis** — Compare an organization's current control inventory against one or more compliance frameworks (NIST 800-53, SOC 2, ISO 27001, CIS Controls, CMMC, PCI DSS) and produce a prioritized gap report with cross-framework efficiency opportunities.
2. **AI Risk Statement Generation** — Given a gap report and system context, generate NIST SP 800-30-compliant risk statements with structured threat/vulnerability/impact analysis and remediation recommendations using any LLM provider.
3. **Automated Evidence Collection** — Continuously collect compliance evidence from cloud providers (AWS, Azure, GCP), identity providers (Okta), source control (GitHub), and map evidence artifacts to specific framework controls.
4. **AI Evidence Validation** — Assess collected evidence for sufficiency, relevance, currency, and completeness using LLM-powered analysis (including vision models for screenshots and PDFs).
5. **Integration Outputs** — Push gaps as tickets to Jira or ServiceNow, export reports as OSCAL Assessment Results, CSV, Markdown, or JSON for auditor tooling.

### Why Evidentia Exists

Existing open-source GRC tools fall into two camps: full-platform solutions (CISO Assistant, Eramba) that require deployment infrastructure and database setup, or point tools that solve one narrow problem. Evidentia occupies the middle ground — a **composable Python library** that a security engineer can `pip install` and start using in five minutes, scaling from single-developer CLI usage to team-wide REST API deployment without architecture changes.

### Core Value Proposition

- **One control implementation satisfies multiple framework requirements.** Evidentia's cross-framework mapping engine makes this visible and actionable.
- **Evidence collection is automated, mapped, and validated.** Not just collected — assessed for audit readiness.
- **Every output is auditor-friendly.** Timestamped, source-attributed, versioned, OSCAL-compatible.
- **Zero-to-productive in under 5 minutes.** No database, no Kubernetes, no config files required for basic use.

---


## 2. Design Principles

Every architectural and implementation decision in this document traces back to one or more of the following ten principles. They are non-negotiable constraints, not aspirational goals.

### Principle 1: Composable, Not Monolithic

Each of the five core capabilities is independently installable and usable. A user can `pip install evidentia-core` and use only the gap analyzer without pulling in AI dependencies, evidence collectors, or integration clients. The package structure enforces this:

| Package | Depends On | Provides |
|---|---|---|
| `evidentia-core` | pydantic, pyyaml, oscal-pydantic | Data models, catalog loading, gap analysis engine |
| `evidentia-ai` | evidentia-core, litellm, instructor | Risk statement generator, evidence validator, narrative generator |
| `evidentia-collectors` | evidentia-core, boto3, PyGithub, etc. | Evidence collection agents |
| `evidentia-integrations` | evidentia-core, jira, servicenow-api | Jira and ServiceNow output clients |
| `evidentia` (meta-package) | All of the above + typer, fastapi | CLI, REST API, and full installation |

**Rationale:** GRC tools are adopted incrementally. A security engineer evaluating the tool wants to try gap analysis first, not install AWS SDK dependencies they don't need. Composability also reduces the attack surface — teams that don't use AI features never install LLM libraries.

### Principle 2: Library-First, CLI-Second, REST API-Third

The Python library is the canonical interface. The CLI is a thin wrapper around the library. The REST API is a thin wrapper around the CLI logic (which calls the library). This layered architecture ensures:

- **Behavior consistency:** All three interfaces produce identical outputs for identical inputs.
- **Testability:** Unit tests exercise the library directly. Integration tests exercise the CLI. API tests are thin because the API delegates to the library.
- **Embeddability:** Security teams can import Evidentia into their existing Python automation, CI/CD pipelines, or Jupyter notebooks without running a server.

```
┌─────────────────────────────────────────┐
│            REST API (FastAPI)            │  Layer 3: HTTP interface
│      Pydantic request/response models   │
├─────────────────────────────────────────┤
│              CLI (Typer)                 │  Layer 2: Terminal interface
│         Rich-formatted output           │
├─────────────────────────────────────────┤
│        Python Library (Core)            │  Layer 1: Canonical interface
│  Pydantic models, business logic, I/O   │
└─────────────────────────────────────────┘
```

### Principle 3: OSCAL as the Exchange Standard

All internal data models map cleanly to OSCAL (Open Security Controls Assessment Language) concepts:

| Evidentia Concept | OSCAL Equivalent |
|---|---|
| `ControlCatalog` | `catalog` |
| `ControlInventory` | `component-definition` |
| `GapAnalysisReport` | `assessment-results` |
| `EvidenceArtifact` | `observation` within `assessment-results` |
| `RiskStatement` | `risk` within `assessment-results` |
| Framework crosswalk | `profile` with `import` and `modify` |

Output is always OSCAL-compatible, even if input is not. When a user provides a CSV inventory, Evidentia normalizes it to internal Pydantic models that can serialize to OSCAL JSON at any point.

**Rationale:** OSCAL is a NIST-published, machine-readable standard for security control information. Government agencies (FedRAMP), defense contractors (CMMC), and an increasing number of private-sector organizations require OSCAL-formatted artifacts. By using OSCAL as the internal exchange format, Evidentia outputs are directly consumable by the OSCAL ecosystem (OSCAL CLI, Trestle, Lula, GovReady).

### Principle 4: No Database Required for Core Use

Default operation uses structured YAML and JSON files. Everything is git-friendly — control inventories, gap reports, evidence bundles, and risk statements are stored as human-readable files that can be version-controlled, diff'd, and reviewed in pull requests.

```
.evidentia/
├── inventories/
│   └── 2026-04-05_controls.yaml
├── reports/
│   └── 2026-04-05_gap-analysis.json
├── evidence/
│   ├── 2026-04-05_aws-config.json
│   ├── 2026-04-05_github-repos.json
│   └── 2026-04-05_okta-iam.json
├── risks/
│   └── 2026-04-05_risk-statements.json
└── validated/
    └── 2026-04-05_validated-bundle.json
```

Optional persistence backends for team use:
- **SQLite:** Single-file database for local persistence with query capabilities. No server process.
- **PostgreSQL:** Full relational database for multi-user team deployments with concurrent access, RBAC, and audit logging.

The storage backend is selected via `evidentia.yaml` and abstracted behind a `StorageBackend` interface so all business logic is storage-agnostic.

### Principle 5: LLM-Agnostic

All AI features use LiteLLM (unified interface to 100+ LLM providers) and Instructor (structured output extraction using Pydantic models). The model is configurable at three levels:

1. **Environment variable:** `EVIDENTIA_LLM_MODEL=gpt-4o`
2. **Config file:** `llm.model: "claude-sonnet-4-20250514"` in `evidentia.yaml`
3. **Per-call override:** `--model ollama/llama3.3` on CLI commands

Supported providers (via LiteLLM):
- OpenAI (GPT-4o, GPT-4o-mini)
- Anthropic (Claude Sonnet, Claude Haiku)
- Google (Gemini 1.5 Pro, Gemini Flash)
- Azure OpenAI (any deployed model)
- AWS Bedrock (Claude, Titan)
- Ollama (any local model — Llama 3.3, Mistral, Qwen, etc.)
- Any OpenAI-compatible endpoint (vLLM, LiteLLM Proxy, etc.)

**Rationale:** Enterprise customers have existing LLM contracts and data residency requirements. A GRC tool that only works with OpenAI is a non-starter for organizations using Azure OpenAI or running local models for data sovereignty.

### Principle 6: Framework-Agnostic Internal Model

Evidentia does not model each framework as a separate system. Instead, it uses a unified control model where one `ControlImplementation` can map to requirements across multiple frameworks simultaneously. The cross-framework mapping engine (powered by NIST-published crosswalks) answers questions like:

- "If I implement NIST AC-2 (Account Management), which SOC 2, ISO 27001, and CIS Controls requirements does that also satisfy?"
- "What is the minimum set of controls I need to implement to achieve compliance with NIST 800-53 Moderate AND SOC 2 AND ISO 27001?"

This cross-framework efficiency is a first-class concept, surfaced in gap reports as "efficiency opportunities" — controls that satisfy three or more framework requirements simultaneously.

### Principle 7: Reliability Over Breadth

Evidentia ships with fewer, more reliable integrations rather than 200 fragile connectors. Each collector includes:

- **Connection health monitoring:** `check_connection()` verifies connectivity, authentication, and permissions before attempting collection.
- **Retry logic:** Exponential backoff with jitter for transient failures. Configurable max retries.
- **Connection status reporting:** The `/health` endpoint and `collect check-connections` CLI command report the real-time status of every configured collector.
- **Graceful degradation:** If one collector fails, others continue. The report notes which collectors succeeded and which failed.
- **Rate limiting:** Respect API rate limits for each integration (GitHub, Okta, AWS).

**Initial collectors (Phase 2):** AWS (Config, Security Hub, IAM, CloudTrail, Audit Manager), GitHub (repos, actions), Okta (IAM, MFA, policies).  
**Secondary collectors (Phase 2 late):** Azure (Policy, Defender, Entra ID), GCP (Security Command Center, Org Policy).

### Principle 8: Portable Deployment

Three supported deployment modes, all from the same codebase:

| Mode | Command | Use Case |
|---|---|---|
| **pip install** | `pip install evidentia` | Developer workstation, CI/CD pipelines, Python scripts |
| **Docker** | `docker run ghcr.io/evidentia/evidentia:latest` | Server deployment, team use |
| **Homebrew** (future) | `brew install evidentia` | macOS developer convenience |

No Kubernetes required. No Helm charts. No Terraform modules. A single Docker container with a mounted config file and environment variables is the production deployment model.

### Principle 9: Auditor-Friendly Output

Every output artifact includes:

| Field | Purpose |
|---|---|
| `id` | Unique identifier (UUID v4) for traceability |
| `created_at` / `generated_at` | ISO 8601 timestamp |
| `created_by` / `generated_by` | Source attribution (collector name, user email, or "evidentia-ai") |
| `version` | Evidentia version that generated the output |
| `content_hash` | SHA-256 hash for tamper detection (evidence artifacts) |
| `source_system` | Origin system (e.g., "aws-config", "github", "manual-upload") |

Export formats: JSON (default), CSV (for spreadsheet users), Markdown (for documentation), OSCAL Assessment Results (for government/defense audits).

### Principle 10: Progressive Enhancement

Evidentia works with zero configuration for basic operations:

```bash
# Zero-config usage: analyze a control inventory against default frameworks
evidentia gap analyze --inventory my-controls.yaml

# Add one config option: specify frameworks
evidentia gap analyze --inventory my-controls.yaml --frameworks soc2-tsc,iso27001-2022

# Add AI: generate risk statements (requires LLM API key)
export OPENAI_API_KEY=sk-...
evidentia risk generate --context system-context.yaml --gaps report.json

# Add evidence collection (requires cloud credentials)
export AWS_ACCESS_KEY_ID=...
evidentia collect run --collectors aws --frameworks nist-800-53-mod

# Add integrations (requires Jira credentials)
export JIRA_SERVER=https://my-company.atlassian.net
evidentia gap push-jira --report report.json --project SEC
```

Complexity is always opt-in. A `evidentia.yaml` config file is only needed when the user wants persistent configuration.

---


## 3. Technology Stack

All technology choices are confirmed and final. Each choice includes rationale.

| Layer | Technology | Version | Rationale |
|---|---|---|---|
| **Language** | Python 3.12+ | 3.12+ | f-strings, type hints (PEP 695), `tomllib` in stdlib, broad ecosystem for security tooling |
| **Project management** | uv (Astral) | latest | 10-100x faster than pip/poetry; native workspace (monorepo) support; single lockfile across packages; replaces pip, pip-tools, poetry, and virtualenv |
| **CLI framework** | Typer | 0.14+ | FastAPI-style CLI declaration using type hints; built-in Rich integration for styled terminal output; auto-generated `--help`; shell completion |
| **Terminal rendering** | Rich | 13+ | Tables, progress bars, syntax highlighting, panels, markdown rendering in terminal |
| **REST API** | FastAPI + Uvicorn | 0.115+ / 0.30+ | Async-first, auto-generated OpenAPI docs, Pydantic v2 native, high performance |
| **Data models** | Pydantic v2 | 2.9+ | Runtime validation, JSON/YAML serialization, schema generation, Settings management |
| **AI interface** | LiteLLM | 1.50+ | Unified API for 100+ LLM providers; handles auth, retries, fallbacks, cost tracking |
| **Structured AI output** | Instructor | 1.7+ | Extracts Pydantic model instances from LLM responses; auto-retry on validation failure; supports function calling and JSON mode |
| **OSCAL models** | oscal-pydantic | 2023.3+ | Pydantic models matching NIST OSCAL specification; serialization to/from OSCAL JSON; maintained by Credentive Security |
| **OSCAL content** | usnistgov/oscal-content | latest | Official NIST-published OSCAL catalogs and profiles in JSON/XML/YAML; public domain |
| **Testing** | pytest + pytest-asyncio + pytest-httpx | latest | Industry standard; async test support; HTTP mocking for API tests |
| **Integration testing** | testcontainers-python | latest | Spin up PostgreSQL, mock services in Docker for integration tests |
| **AI test recording** | pytest-recording (VCR.py) | latest | Record and replay LLM API responses to avoid expensive calls in CI |
| **Linting / formatting** | Ruff | latest | Replaces flake8, isort, black; 10-100x faster; configured in pyproject.toml |
| **Type checking** | mypy | latest | Static type analysis for all packages; strict mode enabled |
| **Packaging** | hatchling | latest | PEP 517 build backend; works with uv; supports dynamic versioning |
| **Docker** | Multi-stage build | Python 3.12-slim | Minimal image size; non-root user; health check included |
| **CI/CD** | GitHub Actions | N/A | Lint, typecheck, test on push; build + publish to PyPI on tag; Docker push on tag |
| **Configuration** | Pydantic Settings | 2.9+ | Environment variable + YAML file loading with validation and type coercion |
| **Cloud: AWS** | boto3 | 1.35+ | Official AWS SDK; Config, Security Hub, IAM, CloudTrail, Audit Manager |
| **Cloud: Azure** | azure-mgmt-* | latest | Official Azure SDK; Policy, Defender, Entra ID |
| **Cloud: GCP** | google-cloud-* | latest | Official GCP SDK; Security Command Center, Org Policy |
| **GitHub** | PyGithub | 2.5+ | Full GitHub API v3 coverage; repos, branch protection, secret scanning |
| **Okta** | okta-sdk-python | 2.0+ | Official Okta SDK; users, policies, factors, lifecycle events |
| **Jira** | jira (PyPI) | 3.8+ | Mature Python Jira client; issue creation, search, transition |
| **ServiceNow** | servicenow-api (PyPI) | latest | ServiceNow REST API client; table operations, incident/task management |
| **Cloud query (optional)** | Steampipe | latest | SQL interface to cloud APIs; invoked via subprocess; alternative to direct SDK calls |

### Dependency Graph

```
evidentia (meta-package)
├── evidentia-core
│   ├── pydantic >= 2.9
│   ├── pyyaml >= 6.0
│   ├── oscal-pydantic >= 2023.3
│   ├── python-dateutil >= 2.9
│   └── thefuzz >= 0.22  (fuzzy string matching for control IDs)
├── evidentia-ai
│   ├── evidentia-core
│   ├── litellm >= 1.50
│   └── instructor >= 1.7
├── evidentia-collectors
│   ├── evidentia-core
│   ├── boto3 >= 1.35
│   ├── azure-mgmt-resource >= 23.0
│   ├── azure-mgmt-security >= 6.0
│   ├── azure-identity >= 1.17
│   ├── google-cloud-securitycenter >= 1.35
│   ├── google-cloud-resource-manager >= 1.12
│   ├── PyGithub >= 2.5
│   ├── okta >= 2.0
│   ├── aiohttp >= 3.10 (async HTTP for collectors)
│   └── apscheduler >= 3.10 (scheduled collection)
├── evidentia-integrations
│   ├── evidentia-core
│   ├── jira >= 3.8
│   └── servicenow-api >= 0.1
├── typer[all] >= 0.14   (CLI)
├── rich >= 13.0         (terminal rendering)
├── fastapi >= 0.115     (REST API)
├── uvicorn[standard] >= 0.30  (ASGI server)
└── python-multipart >= 0.0.9  (file upload in API)
```

---


## 4. Repository Structure

The repository is a uv workspace monorepo. Each package under `packages/` is an independently installable Python package with its own `pyproject.toml`. The root `pyproject.toml` defines the workspace and shared development dependencies.

```
evidentia/                        # Root monorepo
├── pyproject.toml                   # Root workspace pyproject (uv workspace)
├── uv.lock                          # Single lockfile for all packages
├── README.md                        # Project README (see §18 for structure)
├── CONTRIBUTING.md                  # Contributor guide
├── LICENSE                          # Apache 2.0
├── CHANGELOG.md                     # Keep-a-changelog format
├── .pre-commit-config.yaml          # Pre-commit hooks (ruff, mypy)
├── .gitignore
├── docker/
│   ├── Dockerfile                   # Multi-stage production build
│   └── docker-compose.yml           # Local development and self-hosting
├── .github/
│   └── workflows/
│       ├── ci.yml                   # lint, typecheck, test on push/PR
│       ├── release.yml              # build + publish to PyPI on tag
│       └── docker.yml               # build + push Docker image on tag
├── packages/
│   ├── evidentia-core/          # Core library (no AI, no integrations)
│   │   ├── pyproject.toml
│   │   └── src/evidentia_core/
│   │       ├── __init__.py
│   │       ├── py.typed             # PEP 561 marker for type checking
│   │       ├── models/              # Pydantic data models
│   │       │   ├── __init__.py
│   │       │   ├── control.py       # ControlImplementation, ControlInventory
│   │       │   ├── evidence.py      # EvidenceArtifact, EvidenceBundle
│   │       │   ├── risk.py          # RiskStatement, RiskLevel
│   │       │   ├── gap.py           # ControlGap, GapAnalysisReport
│   │       │   ├── finding.py       # SecurityFinding (from collectors)
│   │       │   ├── catalog.py       # CatalogControl, ControlCatalog, FrameworkMapping
│   │       │   └── common.py        # Shared types: enums, mixins, base classes
│   │       ├── catalogs/            # OSCAL catalog loaders & cross-mapping engine
│   │       │   ├── __init__.py
│   │       │   ├── loader.py        # Load OSCAL JSON → ControlCatalog
│   │       │   ├── crosswalk.py     # Cross-framework mapping engine
│   │       │   ├── registry.py      # Framework registry & discovery
│   │       │   └── data/            # Bundled OSCAL JSON catalogs + mappings
│   │       │       ├── nist-800-53-rev5.json
│   │       │       ├── nist-800-53-mod.json    # Moderate baseline profile
│   │       │       ├── nist-800-53-high.json   # High baseline profile
│   │       │       ├── nist-csf-2.0.json
│   │       │       ├── cis-controls-v8.json
│   │       │       ├── soc2-tsc.json
│   │       │       ├── iso27001-2022.json
│   │       │       ├── cmmc-2-level2.json
│   │       │       ├── pci-dss-4.json
│   │       │       └── mappings/
│   │       │           ├── nist-800-53-to-soc2-tsc.json
│   │       │           ├── nist-800-53-to-iso27001.json
│   │       │           ├── nist-800-53-to-cis-v8.json
│   │       │           ├── nist-800-53-to-cmmc2.json
│   │       │           ├── nist-800-53-to-pci-dss-4.json
│   │       │           └── nist-800-53-to-csf2.json
│   │       ├── gap_analyzer/        # Gap analysis engine
│   │       │   ├── __init__.py
│   │       │   ├── analyzer.py      # Core GapAnalyzer class
│   │       │   ├── inventory.py     # Multi-format inventory parser
│   │       │   ├── normalizer.py    # Control ID normalization & fuzzy matching
│   │       │   ├── prioritizer.py   # Gap priority scoring algorithm
│   │       │   ├── efficiency.py    # Cross-framework efficiency opportunity detection
│   │       │   └── reporter.py      # Output formatters (JSON, CSV, Markdown, OSCAL)
│   │       ├── storage/             # Storage backend abstraction
│   │       │   ├── __init__.py
│   │       │   ├── base.py          # Abstract StorageBackend interface
│   │       │   ├── file_backend.py  # YAML/JSON file storage (default)
│   │       │   ├── sqlite_backend.py # SQLite storage
│   │       │   └── postgres_backend.py # PostgreSQL storage
│   │       ├── oscal/               # OSCAL I/O utilities
│   │       │   ├── __init__.py
│   │       │   ├── exporter.py      # Export to OSCAL Assessment Results
│   │       │   ├── importer.py      # Import from OSCAL component definitions
│   │       │   └── mapper.py        # Map internal models ↔ OSCAL models
│   │       └── utils/
│   │           ├── __init__.py
│   │           ├── hashing.py       # SHA-256 content hashing
│   │           ├── timestamps.py    # ISO 8601 utilities
│   │           └── version.py       # Version info
│   ├── evidentia-ai/            # AI features (risk statements, evidence validation)
│   │   ├── pyproject.toml
│   │   └── src/evidentia_ai/
│   │       ├── __init__.py
│   │       ├── py.typed
│   │       ├── client.py            # LiteLLM + Instructor client setup
│   │       ├── risk_statements/     # Risk statement generator
│   │       │   ├── __init__.py
│   │       │   ├── generator.py     # RiskStatementGenerator class
│   │       │   ├── prompts.py       # System prompts for risk generation
│   │       │   └── templates.py     # Context formatting templates
│   │       ├── evidence_validator/  # Evidence quality validation
│   │       │   ├── __init__.py
│   │       │   ├── validator.py     # EvidenceValidator class
│   │       │   ├── prompts.py       # Validation prompts per framework
│   │       │   └── vision.py        # Vision model handler for images/PDFs
│   │       └── narrative/           # SSP/control narrative generator
│   │           ├── __init__.py
│   │           ├── generator.py     # NarrativeGenerator class
│   │           └── prompts.py       # Narrative generation prompts
│   ├── evidentia-collectors/    # Evidence collection agents
│   │   ├── pyproject.toml
│   │   └── src/evidentia_collectors/
│   │       ├── __init__.py
│   │       ├── py.typed
│   │       ├── base.py              # Abstract BaseCollector class
│   │       ├── health.py            # ConnectionStatus model, health monitoring
│   │       ├── registry.py          # Collector discovery and registration
│   │       ├── retry.py             # Exponential backoff with jitter
│   │       ├── rate_limit.py        # Rate limiter for API calls
│   │       ├── aws/
│   │       │   ├── __init__.py
│   │       │   ├── config.py        # AWS Config compliance rules
│   │       │   ├── security_hub.py  # Security Hub findings
│   │       │   ├── iam.py           # IAM policy, MFA, credential reports
│   │       │   ├── cloudtrail.py    # CloudTrail logging verification
│   │       │   ├── audit_manager.py # AWS Audit Manager bridge
│   │       │   └── mappings.py      # AWS Config rule → NIST control mapping table
│   │       ├── azure/
│   │       │   ├── __init__.py
│   │       │   ├── policy.py        # Azure Policy compliance state
│   │       │   ├── defender.py      # Defender for Cloud security posture
│   │       │   └── entra.py         # Entra ID (formerly AAD) identity controls
│   │       ├── gcp/
│   │       │   ├── __init__.py
│   │       │   ├── scc.py           # Security Command Center findings
│   │       │   └── org_policy.py    # Organization Policy constraints
│   │       ├── github/
│   │       │   ├── __init__.py
│   │       │   ├── repos.py         # Branch protection, secrets, CODEOWNERS
│   │       │   └── actions.py       # CI/CD pipeline compliance checks
│   │       ├── okta/
│   │       │   ├── __init__.py
│   │       │   └── iam.py           # MFA, passwords, user lifecycle, access reviews
│   │       └── scheduled.py         # APScheduler-based collection scheduler
│   ├── evidentia-integrations/  # Output integrations (Jira, ServiceNow)
│   │   ├── pyproject.toml
│   │   └── src/evidentia_integrations/
│   │       ├── __init__.py
│   │       ├── py.typed
│   │       ├── base.py              # Abstract BaseIntegration class
│   │       ├── jira/
│   │       │   ├── __init__.py
│   │       │   ├── client.py        # JiraIntegration class
│   │       │   └── formatters.py    # Gap → Jira issue formatting
│   │       └── servicenow/
│   │           ├── __init__.py
│   │           ├── client.py        # ServiceNowIntegration class
│   │           └── formatters.py    # Gap → ServiceNow record formatting
│   └── evidentia/               # Meta-package: installs everything + CLI + API
│       ├── pyproject.toml
│       └── src/evidentia/
│           ├── __init__.py
│           ├── py.typed
│           ├── cli/                  # Typer CLI application
│           │   ├── __init__.py
│           │   ├── main.py           # Root Typer app + entry point
│           │   ├── gap.py            # `evidentia gap` subcommands
│           │   ├── risk.py           # `evidentia risk` subcommands
│           │   ├── collect.py        # `evidentia collect` subcommands
│           │   ├── validate.py       # `evidentia validate` subcommands
│           │   ├── push.py           # `evidentia gap push-jira/push-servicenow`
│           │   ├── catalog.py        # `evidentia catalog` subcommands
│           │   ├── export.py         # `evidentia export` subcommands
│           │   ├── serve.py          # `evidentia serve` (start API server)
│           │   ├── init.py           # `evidentia init` (project scaffolding)
│           │   └── formatters.py     # Rich output formatting helpers
│           ├── api/                  # FastAPI REST API
│           │   ├── __init__.py
│           │   ├── main.py           # FastAPI app factory
│           │   ├── dependencies.py   # Dependency injection (config, storage, etc.)
│           │   ├── routers/
│           │   │   ├── __init__.py
│           │   │   ├── gaps.py       # /api/v1/gaps/* endpoints
│           │   │   ├── risks.py      # /api/v1/risks/* endpoints
│           │   │   ├── evidence.py   # /api/v1/evidence/* endpoints
│           │   │   ├── collectors.py # /api/v1/collectors/* endpoints
│           │   │   ├── catalogs.py   # /api/v1/catalogs/* endpoints
│           │   │   └── health.py     # /health endpoint
│           │   ├── middleware.py      # CORS, request ID, timing middleware
│           │   ├── auth.py           # Optional API key authentication
│           │   └── errors.py         # Standardized error response models
│           └── config.py             # Pydantic Settings configuration loader
├── tests/
│   ├── conftest.py                   # Shared fixtures
│   ├── unit/
│   │   ├── test_models/              # Pydantic model validation tests
│   │   │   ├── test_control.py
│   │   │   ├── test_evidence.py
│   │   │   ├── test_risk.py
│   │   │   └── test_gap.py
│   │   ├── test_catalogs/            # Catalog loading and crosswalk tests
│   │   │   ├── test_loader.py
│   │   │   ├── test_crosswalk.py
│   │   │   └── test_registry.py
│   │   ├── test_gap_analyzer/        # Gap analysis engine tests
│   │   │   ├── test_analyzer.py
│   │   │   ├── test_inventory.py
│   │   │   ├── test_normalizer.py
│   │   │   ├── test_prioritizer.py
│   │   │   └── test_efficiency.py
│   │   ├── test_ai/                  # AI module tests
│   │   │   ├── test_risk_generator.py
│   │   │   └── test_evidence_validator.py
│   │   └── test_storage/
│   │       ├── test_file_backend.py
│   │       └── test_sqlite_backend.py
│   ├── integration/
│   │   ├── test_cli/                 # End-to-end CLI tests
│   │   │   ├── test_gap_commands.py
│   │   │   ├── test_risk_commands.py
│   │   │   └── test_catalog_commands.py
│   │   ├── test_api/                 # FastAPI endpoint tests
│   │   │   ├── test_gap_endpoints.py
│   │   │   ├── test_risk_endpoints.py
│   │   │   └── test_health.py
│   │   ├── test_collectors/          # Collector integration tests (mocked)
│   │   │   ├── test_aws_collector.py
│   │   │   ├── test_github_collector.py
│   │   │   └── test_okta_collector.py
│   │   └── test_integrations/        # Jira/ServiceNow integration tests (mocked)
│   │       ├── test_jira.py
│   │       └── test_servicenow.py
│   └── fixtures/
│       ├── sample-inventory.yaml      # Evidentia YAML format
│       ├── sample-inventory.csv       # CSV format
│       ├── sample-inventory-oscal.json # OSCAL component definition
│       ├── sample-system-context.yaml  # System context for risk generation
│       ├── sample-gap-report.json      # Pre-computed gap report
│       └── sample-evidence-bundle.json # Pre-collected evidence bundle
└── docs/
    ├── mkdocs.yml                    # MkDocs configuration
    ├── index.md                      # Documentation home
    ├── getting-started.md            # Quickstart guide
    ├── installation.md               # Detailed installation options
    ├── configuration.md              # Complete config reference
    ├── cli-reference.md              # CLI command documentation
    ├── api-reference.md              # REST API documentation
    ├── frameworks.md                 # Supported framework details
    ├── collectors.md                 # Evidence collector documentation
    ├── oscal-guide.md                # OSCAL integration guide
    ├── contributing.md               # Developer contribution guide
    └── architecture.md               # Link to this document
```

### Root pyproject.toml

```toml
[project]
name = "evidentia-workspace"
version = "0.1.0"
requires-python = ">=3.12"

[tool.uv.workspace]
members = [
    "packages/evidentia-core",
    "packages/evidentia-ai",
    "packages/evidentia-collectors",
    "packages/evidentia-integrations",
    "packages/evidentia",
]

[tool.uv]
dev-dependencies = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "pytest-httpx>=0.32",
    "pytest-cov>=5.0",
    "pytest-recording>=0.13",  # VCR.py wrapper for LLM response recording
    "testcontainers>=4.8",
    "moto[all]>=5.0",          # AWS mock
    "responses>=0.25",         # HTTP mock
    "ruff>=0.7",
    "mypy>=1.12",
    "pre-commit>=4.0",
]

[tool.ruff]
target-version = "py312"
line-length = 120

[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "UP",  # pyupgrade
    "RUF", # ruff-specific
    "SIM", # flake8-simplify
    "TCH", # flake8-type-checking
]

[tool.mypy]
python_version = "3.12"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "ai: marks tests that call LLM APIs (expensive)",
]
```

### Package pyproject.toml: evidentia-core

```toml
[project]
name = "evidentia-core"
version = "0.1.0"
description = "Core data models, catalog loading, and gap analysis engine for Evidentia GRC tool"
readme = "README.md"
license = {text = "Apache-2.0"}
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.9",
    "pydantic-settings>=2.6",
    "pyyaml>=6.0",
    "oscal-pydantic>=2023.3",
    "python-dateutil>=2.9",
    "thefuzz[speedup]>=0.22",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/evidentia_core"]
```

### Package pyproject.toml: evidentia (meta-package)

```toml
[project]
name = "evidentia"
version = "0.1.0"
description = "Open-source GRC tool: gap analysis, risk statements, evidence collection, and compliance automation"
readme = "README.md"
license = {text = "Apache-2.0"}
requires-python = ">=3.12"
keywords = ["grc", "compliance", "governance", "risk", "oscal", "nist", "soc2", "iso27001"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "evidentia-core",
    "evidentia-ai",
    "evidentia-collectors",
    "evidentia-integrations",
    "typer[all]>=0.14",
    "rich>=13.0",
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "python-multipart>=0.0.9",
]

[project.scripts]
evidentia = "evidentia.cli.main:app"
cb = "evidentia.cli.main:app"

[project.urls]
Homepage = "https://github.com/polycentric-labs/evidentia"
Documentation = "https://evidentia.dev"
Repository = "https://github.com/polycentric-labs/evidentia"
Changelog = "https://github.com/polycentric-labs/evidentia/blob/main/CHANGELOG.md"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/evidentia"]

[tool.uv.sources]
evidentia-core = { workspace = true }
evidentia-ai = { workspace = true }
evidentia-collectors = { workspace = true }
evidentia-integrations = { workspace = true }
```

---


## 5. Complete Data Models

All internal data is represented as Pydantic v2 models. These models serve triple duty: runtime validation, JSON/YAML serialization, and OpenAPI schema generation for the REST API.

### 5.1 Common Types (evidentia_core/models/common.py)

```python
"""Shared types, enums, and base classes used across all Evidentia models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(timezone.utc)


def new_id() -> str:
    """Generate a new UUID v4 string."""
    return str(uuid4())


class EvidentiaModel(BaseModel):
    """Base model for all Evidentia objects.
    
    Provides consistent serialization settings:
    - Enums serialize to their string values
    - Datetimes serialize to ISO 8601
    - Extra fields are forbidden (strict schema)
    """
    model_config = ConfigDict(
        use_enum_values=True,
        json_encoders={datetime: lambda v: v.isoformat()},
        extra="forbid",
        str_strip_whitespace=True,
    )


class Severity(str, Enum):
    """Universal severity levels used across gaps, risks, and findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FrameworkId(str, Enum):
    """Canonical framework identifiers used throughout Evidentia."""
    NIST_800_53_REV5 = "nist-800-53-rev5"
    NIST_800_53_MOD = "nist-800-53-mod"
    NIST_800_53_HIGH = "nist-800-53-high"
    NIST_CSF_2 = "nist-csf-2.0"
    SOC2_TSC = "soc2-tsc"
    ISO_27001_2022 = "iso27001-2022"
    CIS_CONTROLS_V8 = "cis-controls-v8"
    CMMC_2_LEVEL2 = "cmmc-2-level2"
    PCI_DSS_4 = "pci-dss-4"


class ControlMapping(EvidentiaModel):
    """Maps an entity (evidence, risk, gap) to a specific framework control."""
    framework: str = Field(
        description="Framework identifier, e.g. 'nist-800-53-rev5', 'soc2-tsc'"
    )
    control_id: str = Field(
        description="Control identifier within the framework, e.g. 'AC-2', 'CC6.1'"
    )
    control_title: Optional[str] = Field(
        default=None,
        description="Human-readable control title"
    )

    def __str__(self) -> str:
        return f"{self.framework}:{self.control_id}"
```

### 5.2 Control Model (evidentia_core/models/control.py)

```python
"""Control implementation and inventory models.

Represents an organization's current state of control implementation.
This is the input to gap analysis — "what do we have today?"
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, utc_now


class ControlStatus(str, Enum):
    """Implementation status of a control within an organization."""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class ControlImplementation(EvidentiaModel):
    """Represents a single control as implemented by the organization.
    
    This is not a catalog control (what the framework requires) but an
    organizational control (what the org actually does). The gap analyzer
    compares these against catalog controls to find gaps.
    
    Example:
        ControlImplementation(
            id="AC-2",
            title="Account Management",
            status=ControlStatus.IMPLEMENTED,
            implementation_notes="Managed via Okta with automated provisioning/deprovisioning.",
            responsible_roles=["IT Security", "HR"],
            evidence_references=["evidence/okta-user-lifecycle-2026-04.json"],
            owner="ciso@acme.com",
            tags=["identity", "access-control"]
        )
    """
    id: str = Field(
        description="Organization-defined control ID, typically matching framework IDs. "
                    "E.g. 'AC-2', 'CC6.1', 'A.9.2.1'"
    )
    title: Optional[str] = Field(
        default=None,
        description="Human-readable control title"
    )
    description: Optional[str] = Field(
        default=None,
        description="Description of how the organization implements this control"
    )
    status: ControlStatus = Field(
        description="Current implementation status"
    )
    implementation_notes: Optional[str] = Field(
        default=None,
        description="Free-text notes on implementation details, compensating controls, "
                    "or planned improvements"
    )
    responsible_roles: list[str] = Field(
        default_factory=list,
        description="Roles or teams responsible for this control. "
                    "E.g. ['IT Security', 'DevOps', 'HR']"
    )
    evidence_references: list[str] = Field(
        default_factory=list,
        description="Paths, URIs, or IDs pointing to supporting evidence artifacts"
    )
    last_assessed: Optional[datetime] = Field(
        default=None,
        description="When this control was last assessed or validated"
    )
    owner: Optional[str] = Field(
        default=None,
        description="Email or name of the control owner"
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Frameworks this control is claimed to satisfy. "
                    "E.g. ['nist-800-53-mod', 'soc2-tsc']"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary tags for filtering and organization"
    )


class ControlInventory(EvidentiaModel):
    """An organization's complete control inventory.
    
    This is the primary input to gap analysis. It can be loaded from:
    - Evidentia YAML format (preferred)
    - CSV with header mapping
    - OSCAL component definition JSON
    - CISO Assistant JSON export
    """
    organization: str = Field(
        description="Organization name, used in report headers"
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        description="When this inventory was created"
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        description="When this inventory was last updated"
    )
    controls: list[ControlImplementation] = Field(
        description="List of all control implementations"
    )
    source_format: str = Field(
        default="evidentia",
        description="Format of the source data: 'evidentia', 'oscal', 'csv', 'ciso-assistant'"
    )
    source_file: Optional[str] = Field(
        default=None,
        description="Path to the source file this inventory was loaded from"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Additional metadata from the source format"
    )

    @property
    def implemented_count(self) -> int:
        """Count of fully implemented controls."""
        return sum(
            1 for c in self.controls 
            if c.status == ControlStatus.IMPLEMENTED
        )

    @property
    def total_count(self) -> int:
        """Total number of controls in inventory."""
        return len(self.controls)
    
    def get_control(self, control_id: str) -> Optional[ControlImplementation]:
        """Look up a control by ID (case-insensitive, whitespace-normalized)."""
        normalized = control_id.strip().upper().replace(" ", "-")
        for control in self.controls:
            if control.id.strip().upper().replace(" ", "-") == normalized:
                return control
        return None
```

### 5.3 Evidence Model (evidentia_core/models/evidence.py)

```python
"""Evidence artifact and bundle models.

Represents compliance evidence collected from systems or uploaded manually.
Evidence is the proof that a control is implemented and operating effectively.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import Field, field_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    ControlMapping,
    new_id,
    utc_now,
)


class EvidenceType(str, Enum):
    """Classification of evidence artifacts by type."""
    CONFIGURATION = "configuration"       # System configuration exports (e.g., AWS Config rules)
    LOG = "log"                           # Audit logs, access logs
    SCREENSHOT = "screenshot"             # UI screenshots (analyzed via vision models)
    POLICY_DOCUMENT = "policy_document"   # Written policies, procedures
    AUDIT_REPORT = "audit_report"         # Prior audit reports, attestations
    API_RESPONSE = "api_response"         # Raw API responses from systems
    TEST_RESULT = "test_result"           # Penetration test results, scan reports
    ATTESTATION = "attestation"           # Signed attestation documents
    REPOSITORY_METADATA = "repository_metadata"  # Git repo configuration data
    IDENTITY_DATA = "identity_data"       # IdP exports (Okta, Entra ID)


class EvidenceSufficiency(str, Enum):
    """AI-assessed sufficiency of evidence for a control."""
    SUFFICIENT = "sufficient"       # Evidence fully demonstrates control compliance
    PARTIAL = "partial"             # Evidence partially demonstrates compliance; gaps exist
    INSUFFICIENT = "insufficient"   # Evidence does not demonstrate compliance
    STALE = "stale"                 # Evidence was sufficient but is now past its freshness window
    UNKNOWN = "unknown"             # Not yet assessed


class EvidenceArtifact(EvidentiaModel):
    """A single piece of compliance evidence.
    
    An artifact represents one discrete piece of proof that a control is
    implemented and operating effectively. Artifacts are collected by
    collectors (automated) or uploaded manually.
    
    Every artifact includes:
    - Source attribution (which system, which collector)
    - Timestamp (when collected)
    - Content hash (for tamper detection)
    - Control mappings (which controls this evidence supports)
    - Sufficiency assessment (set by AI validator or human reviewer)
    
    Example:
        EvidenceArtifact(
            title="AWS Config: S3 Bucket Encryption Check",
            evidence_type=EvidenceType.CONFIGURATION,
            source_system="aws-config",
            collected_by="evidentia-collectors/aws",
            content={
                "rule_name": "s3-bucket-server-side-encryption-enabled",
                "compliance_type": "COMPLIANT",
                "region": "us-east-1",
                "account_id": "123456789012",
                "evaluated_resources": 47,
                "non_compliant_resources": 0
            },
            control_mappings=[
                ControlMapping(framework="nist-800-53-mod", control_id="SC-28",
                               control_title="Protection of Information at Rest"),
                ControlMapping(framework="pci-dss-4", control_id="3.5.1",
                               control_title="PAN is secured with strong cryptography")
            ]
        )
    """
    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4)"
    )
    title: str = Field(
        description="Human-readable title describing what this evidence shows"
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed description of the evidence content and context"
    )
    evidence_type: EvidenceType = Field(
        description="Classification of this evidence artifact"
    )
    source_system: str = Field(
        description="System that produced this evidence. "
                    "E.g. 'aws-config', 'github', 'okta', 'manual-upload'"
    )
    collected_at: datetime = Field(
        default_factory=utc_now,
        description="When this evidence was collected (UTC)"
    )
    collected_by: str = Field(
        description="Collector name or user email that produced this evidence"
    )
    # Content
    content: Optional[Any] = Field(
        default=None,
        description="The actual evidence content. JSON for API responses, text for logs, "
                    "base64 for images. Large content should use file_path instead."
    )
    content_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of content for tamper detection. "
                    "Computed automatically on serialization if content is present."
    )
    content_format: str = Field(
        default="json",
        description="Format of the content field: 'json', 'text', 'base64', 'html'"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Path to the evidence file if stored on disk (for large artifacts)"
    )
    file_size_bytes: Optional[int] = Field(
        default=None,
        description="Size of the evidence file in bytes"
    )
    # Control mappings
    control_mappings: list[ControlMapping] = Field(
        default_factory=list,
        description="Controls that this evidence supports, across one or more frameworks"
    )
    # Validation (populated by evidence validator)
    sufficiency: EvidenceSufficiency = Field(
        default=EvidenceSufficiency.UNKNOWN,
        description="AI-assessed sufficiency of this evidence for its mapped controls"
    )
    sufficiency_rationale: Optional[str] = Field(
        default=None,
        description="Explanation of the sufficiency assessment"
    )
    missing_elements: list[str] = Field(
        default_factory=list,
        description="List of elements that would be needed to make this evidence sufficient"
    )
    validator_confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Validator's confidence in the sufficiency assessment (0.0–1.0)"
    )
    validated_at: Optional[datetime] = Field(
        default=None,
        description="When the sufficiency assessment was performed"
    )
    validated_by: Optional[str] = Field(
        default=None,
        description="Model or person that performed the validation"
    )
    # Staleness
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When this evidence becomes stale. Configurable per framework."
    )
    # Metadata
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary tags for filtering"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Collector-specific metadata (region, account ID, org name, etc.)"
    )

    @field_validator("content_hash", mode="before")
    @classmethod
    def compute_content_hash_if_missing(cls, v: Optional[str], info) -> Optional[str]:
        """Content hash is computed lazily — not in the validator to avoid
        circular dependency. Call artifact.compute_hash() after creation."""
        return v

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of content for tamper detection."""
        import hashlib
        import json
        if self.content is not None:
            content_str = json.dumps(self.content, sort_keys=True, default=str)
            self.content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        elif self.file_path:
            h = hashlib.sha256()
            with open(self.file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self.content_hash = h.hexdigest()
        return self.content_hash or ""

    @property
    def is_stale(self) -> bool:
        """Check if this evidence has passed its expiration date."""
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at


class EvidenceBundle(EvidentiaModel):
    """A collection of evidence artifacts for an assessment scope.
    
    Bundles group evidence artifacts by assessment (e.g., "SOC 2 Type II 2026")
    and provide metadata about the overall evidence package.
    """
    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4)"
    )
    title: str = Field(
        description="Bundle title, e.g. 'SOC 2 Type II Evidence — Q1 2026'"
    )
    assessment_scope: str = Field(
        description="What this bundle covers, e.g. 'SOC 2 Type II 2026'"
    )
    frameworks: list[str] = Field(
        description="Frameworks this evidence bundle supports"
    )
    artifacts: list[EvidenceArtifact] = Field(
        default_factory=list,
        description="Evidence artifacts in this bundle"
    )
    created_at: datetime = Field(
        default_factory=utc_now
    )
    created_by: str = Field(
        description="User or process that created this bundle"
    )
    valid_until: Optional[datetime] = Field(
        default=None,
        description="When this bundle expires (e.g., end of audit period)"
    )
    notes: Optional[str] = Field(
        default=None,
        description="Free-text notes about this evidence bundle"
    )
    evidentia_version: str = Field(
        default="0.1.0",
        description="Version of Evidentia that generated this bundle"
    )

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def sufficient_count(self) -> int:
        return sum(1 for a in self.artifacts if a.sufficiency == EvidenceSufficiency.SUFFICIENT)

    @property
    def stale_count(self) -> int:
        return sum(1 for a in self.artifacts if a.is_stale)

    @property
    def coverage_by_control(self) -> dict[str, list[EvidenceArtifact]]:
        """Group artifacts by control mapping for coverage analysis."""
        coverage: dict[str, list[EvidenceArtifact]] = {}
        for artifact in self.artifacts:
            for mapping in artifact.control_mappings:
                key = f"{mapping.framework}:{mapping.control_id}"
                coverage.setdefault(key, []).append(artifact)
        return coverage
```

### 5.4 Risk Statement Model (evidentia_core/models/risk.py)

```python
"""Risk statement models following NIST SP 800-30 structure.

Risk statements are generated by the AI module based on identified gaps
and system context. Each statement includes structured threat analysis,
likelihood/impact ratings, and remediation recommendations.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, new_id, utc_now


class RiskLevel(str, Enum):
    """Overall risk level (derived from likelihood × impact)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class LikelihoodRating(str, Enum):
    """Likelihood that a threat event will occur (NIST SP 800-30 scale)."""
    VERY_HIGH = "very_high"     # Almost certain (>90%)
    HIGH = "high"               # Highly likely (70-90%)
    MODERATE = "moderate"       # Somewhat likely (30-70%)
    LOW = "low"                 # Unlikely (10-30%)
    VERY_LOW = "very_low"       # Negligible (<10%)


class ImpactRating(str, Enum):
    """Impact if the threat event occurs (NIST SP 800-30 scale)."""
    VERY_HIGH = "very_high"     # Catastrophic impact to mission/business
    HIGH = "high"               # Severe impact, significant degradation
    MODERATE = "moderate"       # Serious impact, notable degradation
    LOW = "low"                 # Limited impact, minor degradation
    VERY_LOW = "very_low"       # Negligible impact


class RiskTreatment(str, Enum):
    """Risk treatment decision."""
    MITIGATE = "mitigate"       # Implement controls to reduce risk
    ACCEPT = "accept"           # Accept the risk with documented rationale
    TRANSFER = "transfer"       # Transfer via insurance or outsourcing
    AVOID = "avoid"             # Eliminate the activity causing the risk
    PENDING = "pending"         # Awaiting review


class RiskStatement(EvidentiaModel):
    """A structured risk statement following NIST SP 800-30 Rev 1 format.
    
    Generated by the AI risk statement generator, each risk statement
    decomposes a control gap into its threat components and provides
    actionable remediation guidance.
    
    The structure follows the NIST risk equation:
    Risk = Likelihood(Threat × Vulnerability) × Impact
    
    Example:
        RiskStatement(
            asset="Customer Data Platform — Amazon Redshift data warehouse",
            threat_source="External threat actor (financial motivation)",
            threat_event="Exfiltrate customer PII including payment card data "
                         "from unencrypted Redshift cluster",
            vulnerability="Amazon Redshift cluster in us-east-1 does not enforce "
                          "encryption at rest (SC-28 gap identified)",
            likelihood=LikelihoodRating.HIGH,
            likelihood_rationale="Redshift contains PCI-scoped data accessible from "
                                  "the application VPC. Encryption at rest is a basic "
                                  "control whose absence is easily discoverable.",
            impact=ImpactRating.VERY_HIGH,
            impact_rationale="Breach would expose 50,000 customer payment records, "
                              "triggering PCI DSS incident notification, potential fines "
                              "of $50-500K, and reputational damage.",
            risk_level=RiskLevel.CRITICAL,
            risk_description="...",
            recommended_controls=["SC-28", "SC-28(1)", "AU-6"],
            remediation_priority=1
        )
    """
    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4)"
    )
    # ── Core NIST SP 800-30 risk statement components ──────────────────
    asset: str = Field(
        description="The system, data, function, or process at risk. "
                    "Be specific: include system name, data type, and location."
    )
    threat_source: str = Field(
        description="Who or what could exploit the vulnerability. "
                    "E.g. 'External threat actor (financial motivation)', "
                    "'Insider threat (disgruntled employee)', 'Misconfiguration'"
    )
    threat_event: str = Field(
        description="What the threat source would do. Use specific, "
                    "technical language. E.g. 'Exfiltrate customer PII via "
                    "unencrypted S3 bucket with public access enabled'"
    )
    vulnerability: str = Field(
        description="The specific weakness that enables the threat. "
                    "Directly tied to the control gap. E.g. 'S3 bucket in "
                    "us-east-1 lacks server-side encryption and Block Public Access'"
    )
    predisposing_conditions: list[str] = Field(
        default_factory=list,
        description="Environmental factors that increase likelihood. "
                    "E.g. ['Public-facing application', 'Multi-tenant architecture', "
                    "'Previous security incidents in sector']"
    )
    # ── Ratings ────────────────────────────────────────────────────────
    likelihood: LikelihoodRating = Field(
        description="Likelihood that the threat event will occur"
    )
    likelihood_rationale: str = Field(
        description="Specific explanation for the likelihood rating. "
                    "Must reference concrete factors, not vague statements."
    )
    impact: ImpactRating = Field(
        description="Impact if the threat event occurs"
    )
    impact_rationale: str = Field(
        description="Specific explanation for the impact rating. "
                    "Must reference data types, record counts, regulatory "
                    "consequences, and business impact."
    )
    risk_level: RiskLevel = Field(
        description="Overall risk level derived from likelihood × impact "
                    "using the NIST SP 800-30 risk matrix"
    )
    risk_description: str = Field(
        description="Full prose risk statement combining all components. "
                    "Written for executive and auditor audiences."
    )
    # ── Remediation ────────────────────────────────────────────────────
    recommended_controls: list[str] = Field(
        description="NIST 800-53 control IDs that would mitigate this risk. "
                    "E.g. ['SC-28', 'SC-28(1)', 'AU-6']"
    )
    remediation_priority: int = Field(
        ge=1,
        le=5,
        description="1 = most urgent, 5 = least urgent. Based on risk level, "
                    "implementation effort, and cross-framework value."
    )
    remediation_steps: list[str] = Field(
        default_factory=list,
        description="Ordered list of specific remediation actions"
    )
    estimated_remediation_effort: Optional[str] = Field(
        default=None,
        description="Estimated effort: 'hours', 'days', 'weeks', 'months'"
    )
    # ── Treatment ──────────────────────────────────────────────────────
    treatment: RiskTreatment = Field(
        default=RiskTreatment.PENDING,
        description="Risk treatment decision"
    )
    treatment_rationale: Optional[str] = Field(
        default=None,
        description="Rationale for the treatment decision (required if accepted)"
    )
    # ── Lifecycle ──────────────────────────────────────────────────────
    generated_by: str = Field(
        default="evidentia-ai",
        description="'evidentia-ai' for generated, or user email for manual"
    )
    generated_at: datetime = Field(
        default_factory=utc_now,
        description="When this risk statement was generated"
    )
    model_used: Optional[str] = Field(
        default=None,
        description="LLM model used for generation, e.g. 'gpt-4o'"
    )
    reviewed_by: Optional[str] = Field(
        default=None,
        description="Email of the person who reviewed this risk statement"
    )
    reviewed_at: Optional[datetime] = Field(
        default=None,
        description="When the risk statement was reviewed"
    )
    accepted: bool = Field(
        default=False,
        description="Whether this risk statement has been accepted by a reviewer"
    )
    # ── Mappings ───────────────────────────────────────────────────────
    source_gap_id: Optional[str] = Field(
        default=None,
        description="ID of the ControlGap that triggered this risk statement"
    )
    framework_mappings: list[str] = Field(
        default_factory=list,
        description="Framework control IDs this risk maps to. "
                    "E.g. ['nist-800-53-mod:SC-28', 'pci-dss-4:3.5.1']"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary tags for filtering and grouping"
    )


class RiskRegister(EvidentiaModel):
    """A collection of risk statements for an organization/system.
    
    Serves as the output of the risk statement generator and the
    persistent risk register for ongoing risk management.
    """
    id: str = Field(default_factory=new_id)
    organization: str
    system_name: str
    generated_at: datetime = Field(default_factory=utc_now)
    risks: list[RiskStatement] = Field(default_factory=list)
    evidentia_version: str = Field(default="0.1.0")

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.risks if r.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.risks if r.risk_level == RiskLevel.HIGH)

    @property
    def accepted_count(self) -> int:
        return sum(1 for r in self.risks if r.accepted)

    @property
    def pending_review_count(self) -> int:
        return sum(1 for r in self.risks if not r.reviewed_by)
```

### 5.5 Gap Model (evidentia_core/models/gap.py)

```python
"""Control gap analysis models.

Represents the difference between what a framework requires and what
an organization has implemented. The gap analyzer produces these models
as its primary output.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, new_id, utc_now


class GapSeverity(str, Enum):
    """Severity of a control gap based on framework requirement and implementation state."""
    CRITICAL = "critical"       # Required by framework, no implementation or compensating control
    HIGH = "high"               # Required by framework, partially addressed
    MEDIUM = "medium"           # Recommended control, not implemented
    LOW = "low"                 # Optional/advisory control, not implemented
    INFORMATIONAL = "informational"  # Noted for completeness, no action required


class ImplementationEffort(str, Enum):
    """Estimated effort to remediate a gap."""
    LOW = "low"            # < 1 week of engineering effort
    MEDIUM = "medium"      # 1–4 weeks
    HIGH = "high"          # 1–3 months
    VERY_HIGH = "very_high"  # 3+ months


class GapStatus(str, Enum):
    """Current status of gap remediation."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"       # Risk accepted — gap will not be closed
    NOT_APPLICABLE = "not_applicable"


class ControlGap(EvidentiaModel):
    """A single control gap identified by the gap analyzer.
    
    Represents a framework requirement that the organization has not
    fully implemented. Each gap includes:
    - The framework requirement (what's needed)
    - The gap description (what's missing)
    - Cross-framework value (what else gets satisfied if this is fixed)
    - Remediation guidance (how to fix it)
    - Priority scoring (what to fix first)
    """
    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4)"
    )
    # ── Framework requirement ──────────────────────────────────────────
    framework: str = Field(
        description="Framework ID, e.g. 'nist-800-53-mod', 'soc2-tsc'"
    )
    control_id: str = Field(
        description="Control ID within the framework, e.g. 'AC-2', 'CC6.1'"
    )
    control_title: str = Field(
        description="Human-readable control title from the catalog"
    )
    control_description: str = Field(
        description="Full control description from the catalog"
    )
    control_family: Optional[str] = Field(
        default=None,
        description="Control family or category, e.g. 'Access Control', 'Logical and Physical Access Controls'"
    )
    # ── Gap details ────────────────────────────────────────────────────
    gap_severity: GapSeverity = Field(
        description="Severity based on requirement level and implementation state"
    )
    implementation_status: str = Field(
        description="Current state: 'missing' (no implementation), 'partial' (incomplete), "
                    "'planned' (scheduled but not started), 'not_applicable'"
    )
    gap_description: str = Field(
        description="Specific description of what is missing or incomplete"
    )
    status: GapStatus = Field(
        default=GapStatus.OPEN,
        description="Current remediation status"
    )
    # ── Cross-framework analysis ───────────────────────────────────────
    equivalent_controls_in_inventory: list[str] = Field(
        default_factory=list,
        description="Organization control IDs that partially satisfy this requirement. "
                    "E.g. the org has AC-2 partially implemented — listed here."
    )
    cross_framework_value: list[str] = Field(
        default_factory=list,
        description="Other framework:control_id pairs that this gap also satisfies. "
                    "E.g. implementing NIST AC-2 also satisfies SOC 2 CC6.1 and ISO A.9.2.1. "
                    "Format: ['soc2-tsc:CC6.1', 'iso27001-2022:A.9.2.1']"
    )
    # ── Remediation ────────────────────────────────────────────────────
    remediation_guidance: str = Field(
        description="Actionable remediation guidance for this gap"
    )
    implementation_effort: ImplementationEffort = Field(
        description="Estimated engineering effort to close this gap"
    )
    priority_score: float = Field(
        default=0.0,
        description="Computed priority score (higher = more urgent). "
                    "Formula: severity_weight × (1 + 0.2 × cross_framework_count) × (1 / effort_weight)"
    )
    # ── Ticket tracking ────────────────────────────────────────────────
    jira_issue_key: Optional[str] = Field(
        default=None,
        description="Jira issue key if pushed, e.g. 'SEC-123'"
    )
    servicenow_ticket_id: Optional[str] = Field(
        default=None,
        description="ServiceNow record sys_id if pushed"
    )
    # ── Lifecycle ──────────────────────────────────────────────────────
    created_at: datetime = Field(
        default_factory=utc_now
    )
    remediated_at: Optional[datetime] = Field(
        default=None,
        description="When this gap was marked as remediated"
    )
    assigned_to: Optional[str] = Field(
        default=None,
        description="Email of the person assigned to remediate this gap"
    )
    tags: list[str] = Field(
        default_factory=list
    )


class EfficiencyOpportunity(EvidentiaModel):
    """A control that satisfies multiple framework requirements simultaneously.
    
    These are high-value implementation targets — implementing one control
    closes gaps across multiple frameworks.
    """
    control_id: str = Field(
        description="The NIST 800-53 control ID (used as the canonical reference)"
    )
    control_title: str = Field(
        description="Human-readable control title"
    )
    frameworks_satisfied: list[str] = Field(
        description="List of framework:control_id pairs this satisfies. "
                    "E.g. ['nist-800-53-mod:AC-2', 'soc2-tsc:CC6.1', 'iso27001-2022:A.9.2.1']"
    )
    framework_count: int = Field(
        description="Number of distinct frameworks satisfied"
    )
    total_gaps_closed: int = Field(
        description="Total number of gap entries that would be closed by implementing this control"
    )
    implementation_effort: ImplementationEffort = Field(
        description="Estimated effort to implement"
    )
    value_score: float = Field(
        description="Efficiency value score = total_gaps_closed / effort_weight"
    )


class GapAnalysisReport(EvidentiaModel):
    """Complete gap analysis report.
    
    The primary output of the gap analyzer. Contains all identified gaps,
    efficiency opportunities, and a prioritized remediation roadmap.
    """
    id: str = Field(default_factory=new_id)
    organization: str = Field(
        description="Organization name from the control inventory"
    )
    frameworks_analyzed: list[str] = Field(
        description="Framework IDs that were analyzed"
    )
    analyzed_at: datetime = Field(
        default_factory=utc_now
    )
    # ── Summary statistics ─────────────────────────────────────────────
    total_controls_required: int = Field(
        description="Total unique controls required across all analyzed frameworks"
    )
    total_controls_in_inventory: int = Field(
        description="Total controls in the organization's inventory"
    )
    total_gaps: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    informational_gaps: int = Field(default=0)
    coverage_percentage: float = Field(
        description="Percentage of required controls that are fully implemented. "
                    "Formula: (required - gaps) / required × 100"
    )
    # ── Detail ─────────────────────────────────────────────────────────
    gaps: list[ControlGap] = Field(
        description="All identified gaps, sorted by priority_score descending"
    )
    efficiency_opportunities: list[EfficiencyOpportunity] = Field(
        default_factory=list,
        description="Controls that satisfy 3+ framework requirements simultaneously"
    )
    prioritized_roadmap: list[str] = Field(
        default_factory=list,
        description="Ordered list of gap IDs by descending priority_score"
    )
    # ── Metadata ───────────────────────────────────────────────────────
    inventory_source: Optional[str] = Field(
        default=None,
        description="Path to the inventory file used"
    )
    evidentia_version: str = Field(default="0.1.0")
    notes: Optional[str] = Field(default=None)
```

### 5.6 Catalog Models (evidentia_core/models/catalog.py)

```python
"""Framework catalog models.

Represents the controls required by a compliance framework. These are
loaded from bundled OSCAL JSON catalogs and used as the "target state"
in gap analysis.
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel


class CatalogControl(EvidentiaModel):
    """A single control from a framework catalog."""
    id: str = Field(description="Control ID, e.g. 'AC-2', 'CC6.1'")
    title: str = Field(description="Control title")
    description: str = Field(description="Full control description")
    family: Optional[str] = Field(default=None, description="Control family/group")
    class_: Optional[str] = Field(
        default=None,
        alias="class",
        description="Control class: 'technical', 'operational', 'management'"
    )
    priority: Optional[str] = Field(
        default=None,
        description="NIST priority: 'P1' (most critical) through 'P3'"
    )
    baseline_impact: list[str] = Field(
        default_factory=list,
        description="Baselines this control belongs to: ['low', 'moderate', 'high']"
    )
    enhancements: list[CatalogControl] = Field(
        default_factory=list,
        description="Control enhancements (sub-controls)"
    )
    related_controls: list[str] = Field(
        default_factory=list,
        description="IDs of related controls within the same framework"
    )
    assessment_objectives: list[str] = Field(
        default_factory=list,
        description="Assessment objectives from SP 800-53A"
    )
    parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Organization-defined parameters and their default values"
    )


class ControlCatalog(EvidentiaModel):
    """A complete framework catalog containing all controls.
    
    Loaded from bundled OSCAL JSON files. Provides indexed access
    to controls by ID and family.
    """
    framework_id: str = Field(
        description="Canonical framework ID, e.g. 'nist-800-53-rev5'"
    )
    framework_name: str = Field(
        description="Human-readable name, e.g. 'NIST SP 800-53 Revision 5'"
    )
    version: str = Field(
        description="Framework version, e.g. 'Rev 5', '2022', 'v8'"
    )
    source: str = Field(
        description="Source of the catalog data, e.g. 'usnistgov/oscal-content'"
    )
    controls: list[CatalogControl] = Field(
        description="All controls in this catalog"
    )
    families: list[str] = Field(
        default_factory=list,
        description="List of control families in this catalog"
    )

    # ── Index for fast lookup ──────────────────────────────────────────
    _index: dict[str, CatalogControl] = {}

    def model_post_init(self, __context) -> None:
        """Build control index after initialization."""
        self._index = {}
        for control in self.controls:
            self._index[control.id.upper()] = control
            for enhancement in control.enhancements:
                self._index[enhancement.id.upper()] = enhancement

    def get_control(self, control_id: str) -> Optional[CatalogControl]:
        """Look up a control by ID (case-insensitive)."""
        return self._index.get(control_id.strip().upper())

    def get_family(self, family: str) -> list[CatalogControl]:
        """Get all controls in a family."""
        return [c for c in self.controls if c.family == family]

    @property
    def control_count(self) -> int:
        """Total number of controls (including enhancements)."""
        return len(self._index)


class FrameworkMapping(EvidentiaModel):
    """A single mapping entry between two frameworks' controls."""
    source_control_id: str
    source_control_title: Optional[str] = None
    target_control_id: str
    target_control_title: Optional[str] = None
    relationship: str = Field(
        description="Mapping relationship: 'equivalent', 'related', 'partial', 'superset'"
    )
    notes: Optional[str] = Field(
        default=None,
        description="Notes about this mapping relationship"
    )


class CrosswalkDefinition(EvidentiaModel):
    """A complete crosswalk between two frameworks.
    
    Loaded from bundled JSON files in catalogs/data/mappings/.
    """
    source_framework: str
    target_framework: str
    version: str
    generated_at: str
    source: str = Field(
        description="Authority source for this crosswalk. "
                    "E.g. 'NIST SP 800-53 Rev5 Appendix H', 'AICPA crosswalk'"
    )
    mappings: list[FrameworkMapping]

    def get_target_controls(self, source_control_id: str) -> list[FrameworkMapping]:
        """Get all target controls mapped from a source control."""
        return [
            m for m in self.mappings 
            if m.source_control_id.upper() == source_control_id.strip().upper()
        ]

    def get_source_controls(self, target_control_id: str) -> list[FrameworkMapping]:
        """Get all source controls mapped to a target control (reverse lookup)."""
        return [
            m for m in self.mappings 
            if m.target_control_id.upper() == target_control_id.strip().upper()
        ]
```

### 5.7 Finding Model (evidentia_core/models/finding.py)

```python
"""Security finding model for collector outputs.

Collectors produce findings (raw security observations from systems).
Findings are then mapped to evidence artifacts with control mappings.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, Severity, new_id, utc_now


class FindingStatus(str, Enum):
    """Status of a security finding."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class SecurityFinding(EvidentiaModel):
    """A security finding from an evidence collector.
    
    Findings are the raw output of collectors — they represent a single
    observation about a system's security posture. Findings are then
    transformed into EvidenceArtifacts with control mappings.
    """
    id: str = Field(default_factory=new_id)
    title: str
    description: str
    severity: Severity
    status: FindingStatus = Field(default=FindingStatus.ACTIVE)
    # Source
    source_system: str = Field(description="E.g. 'aws-security-hub', 'github'")
    source_finding_id: Optional[str] = Field(
        default=None,
        description="Original finding ID in the source system"
    )
    # Resource
    resource_type: Optional[str] = Field(
        default=None,
        description="E.g. 'AWS::S3::Bucket', 'GitHub::Repository'"
    )
    resource_id: Optional[str] = Field(
        default=None,
        description="Resource identifier in the source system"
    )
    resource_region: Optional[str] = Field(default=None)
    resource_account: Optional[str] = Field(default=None)
    # Control mappings
    control_ids: list[str] = Field(
        default_factory=list,
        description="NIST 800-53 control IDs this finding relates to"
    )
    # Raw data
    raw_data: Optional[Any] = Field(
        default=None,
        description="Original finding data from the source system"
    )
    # Timestamps
    first_observed: datetime = Field(default_factory=utc_now)
    last_observed: datetime = Field(default_factory=utc_now)
    resolved_at: Optional[datetime] = Field(default=None)
```

### 5.8 System Context Model (evidentia_ai/risk_statements/templates.py)

```python
"""System context model — the user-provided description of their environment.

Used by the AI risk statement generator to produce contextually relevant
risk statements. Loaded from a YAML file (system-context.yaml).
"""

from __future__ import annotations

from typing import Optional

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel


class SystemComponent(EvidentiaModel):
    """A component of the system being assessed."""
    name: str = Field(description="Component name, e.g. 'Web Application'")
    type: str = Field(description="Component type: 'web_app', 'api', 'database', 'network', 'identity_provider', 'ci_cd'")
    technology: str = Field(description="Technology stack, e.g. 'React + Node.js', 'Amazon Redshift'")
    data_handled: list[str] = Field(
        default_factory=list,
        description="Types of data this component processes, e.g. ['PII', 'PCI-CDE']"
    )
    location: Optional[str] = Field(
        default=None,
        description="Hosting location, e.g. 'AWS us-east-1', 'On-premises datacenter'"
    )
    notes: Optional[str] = Field(default=None)


class SystemContext(EvidentiaModel):
    """Complete system context for risk statement generation.
    
    Provided by the user in a system-context.yaml file. Describes the
    organization, system, data, hosting, components, threat actors,
    existing controls, and risk tolerance.
    
    This context is included in the LLM prompt to generate risk statements
    that are specific to the user's environment.
    """
    organization: str = Field(
        description="Organization name"
    )
    system_name: str = Field(
        description="Name of the system being assessed"
    )
    system_description: str = Field(
        description="Free-text description of the system's purpose, scope, and architecture"
    )
    data_classification: list[str] = Field(
        default_factory=list,
        description="Types of data processed: 'PII', 'PHI', 'PCI-CDE', 'CUI', 'public'"
    )
    hosting: str = Field(
        description="Hosting environment description, e.g. 'AWS (us-east-1, eu-west-1)'"
    )
    components: list[SystemComponent] = Field(
        default_factory=list,
        description="System components with their technology stacks"
    )
    threat_actors: list[str] = Field(
        default_factory=list,
        description="Relevant threat actor categories. "
                    "E.g. ['External threat actors (financial)', 'Nation-state', 'Insider']"
    )
    existing_controls: list[str] = Field(
        default_factory=list,
        description="Control IDs already implemented (used for context in risk generation)"
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Target compliance frameworks"
    )
    risk_tolerance: str = Field(
        default="medium",
        description="Organization's risk tolerance: 'low', 'medium', 'high'"
    )
    regulatory_requirements: list[str] = Field(
        default_factory=list,
        description="Applicable regulations: 'HIPAA', 'PCI DSS', 'GDPR', 'CCPA', 'ITAR'"
    )
    annual_revenue: Optional[str] = Field(
        default=None,
        description="Annual revenue range (used for impact assessment)"
    )
    employee_count: Optional[int] = Field(
        default=None,
        description="Number of employees"
    )
    customer_count: Optional[int] = Field(
        default=None,
        description="Number of customers/users"
    )
    notes: Optional[str] = Field(default=None)
```

---


## 6. OSCAL Catalog Loading & Cross-Framework Mapping Engine

The catalog system is the foundation of Evidentia. It provides indexed access to framework controls and bidirectional cross-framework mappings.

### 6.1 Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    Framework Registry                        │
│  Discovers available catalogs and crosswalks at startup      │
├──────────────┬───────────────────────────────────────────────┤
│              │                                               │
│  Catalog     │         Crosswalk Engine                      │
│  Loader      │   ┌─────────────────────────────┐            │
│              │   │  Bidirectional Mapping Graph  │            │
│  OSCAL JSON  │   │                               │            │
│  → Pydantic  │   │  NIST AC-2 ←→ SOC2 CC6.1    │            │
│  → Index     │   │  NIST AC-2 ←→ ISO A.9.2.1   │            │
│              │   │  NIST AC-2 ←→ CIS 5.3       │            │
│              │   │  ...                          │            │
│              │   └─────────────────────────────┘            │
└──────────────┴───────────────────────────────────────────────┘
```

### 6.2 Catalog Loader (evidentia_core/catalogs/loader.py)

```python
"""OSCAL catalog loader.

Loads NIST-published OSCAL JSON catalogs from bundled data files
and parses them into indexed ControlCatalog objects.

Supported catalog formats:
- OSCAL Catalog JSON (NIST 800-53, CSF 2.0)
- Evidentia framework JSON (SOC 2, ISO 27001, CIS, CMMC, PCI DSS)
"""

from __future__ import annotations

import json
import logging
from importlib import resources
from pathlib import Path
from typing import Optional

from evidentia_core.models.catalog import (
    CatalogControl,
    ControlCatalog,
)

logger = logging.getLogger(__name__)

# Path to bundled data directory
DATA_DIR = Path(__file__).parent / "data"


def load_oscal_catalog(catalog_path: Path) -> ControlCatalog:
    """Load an OSCAL Catalog JSON file into a ControlCatalog.
    
    Parses the OSCAL catalog structure:
    {
        "catalog": {
            "uuid": "...",
            "metadata": {...},
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                    "controls": [
                        {
                            "id": "ac-1",
                            "title": "Policy and Procedures",
                            "parts": [...],
                            "controls": [...]  # enhancements
                        }
                    ]
                }
            ]
        }
    }
    """
    with open(catalog_path, "r") as f:
        data = json.load(f)

    catalog_data = data.get("catalog", data)
    metadata = catalog_data.get("metadata", {})
    
    controls: list[CatalogControl] = []
    families: list[str] = []

    for group in catalog_data.get("groups", []):
        family_title = group.get("title", "")
        families.append(family_title)

        for oscal_control in group.get("controls", []):
            control = _parse_oscal_control(oscal_control, family_title)
            controls.append(control)

    framework_id = _detect_framework_id(catalog_path, metadata)
    framework_name = metadata.get("title", catalog_path.stem)
    version = metadata.get("version", "unknown")

    catalog = ControlCatalog(
        framework_id=framework_id,
        framework_name=framework_name,
        version=version,
        source=f"OSCAL: {catalog_path.name}",
        controls=controls,
        families=families,
    )

    logger.info(
        f"Loaded catalog '{framework_name}': "
        f"{catalog.control_count} controls in {len(families)} families"
    )
    return catalog


def _parse_oscal_control(
    oscal_control: dict,
    family: str,
) -> CatalogControl:
    """Parse a single OSCAL control into a CatalogControl."""
    control_id = oscal_control.get("id", "").upper()
    title = oscal_control.get("title", "")
    
    # Extract description from parts
    description = ""
    for part in oscal_control.get("parts", []):
        if part.get("name") == "statement":
            description = _extract_prose(part)
            break
    
    # Extract assessment objectives
    objectives: list[str] = []
    for part in oscal_control.get("parts", []):
        if part.get("name") == "assessment-objective":
            objectives.append(_extract_prose(part))

    # Parse enhancements (nested controls)
    enhancements: list[CatalogControl] = []
    for sub_control in oscal_control.get("controls", []):
        enhancement = _parse_oscal_control(sub_control, family)
        enhancements.append(enhancement)

    # Extract priority from properties
    priority = None
    for prop in oscal_control.get("props", []):
        if prop.get("name") == "priority":
            priority = prop.get("value")

    # Extract baseline impact from properties
    baseline_impact: list[str] = []
    for prop in oscal_control.get("props", []):
        if prop.get("name") == "baseline" or prop.get("name") == "impact":
            baseline_impact.append(prop.get("value", ""))

    # Extract related controls from links
    related: list[str] = []
    for link in oscal_control.get("links", []):
        if link.get("rel") == "related":
            related.append(link.get("href", "").replace("#", "").upper())
    
    # Extract parameters
    parameters: dict[str, str] = {}
    for param in oscal_control.get("params", []):
        param_id = param.get("id", "")
        default_value = ""
        if "select" in param:
            choices = param["select"].get("choice", [])
            default_value = " | ".join(choices) if choices else ""
        elif "guidelines" in param:
            default_value = param["guidelines"][0].get("prose", "")
        parameters[param_id] = default_value

    return CatalogControl(
        id=control_id,
        title=title,
        description=description,
        family=family,
        priority=priority,
        baseline_impact=baseline_impact,
        enhancements=enhancements,
        related_controls=related,
        assessment_objectives=objectives,
        parameters=parameters,
    )


def _extract_prose(part: dict) -> str:
    """Recursively extract prose text from an OSCAL part."""
    prose = part.get("prose", "")
    for sub_part in part.get("parts", []):
        sub_prose = _extract_prose(sub_part)
        if sub_prose:
            prose += "\n" + sub_prose
    return prose.strip()


def _detect_framework_id(path: Path, metadata: dict) -> str:
    """Detect the framework ID from the file path or metadata."""
    stem = path.stem.lower()
    if "800-53" in stem and "rev5" in stem:
        return "nist-800-53-rev5"
    if "800-53" in stem and "mod" in stem:
        return "nist-800-53-mod"
    if "800-53" in stem and "high" in stem:
        return "nist-800-53-high"
    if "csf" in stem and "2.0" in stem:
        return "nist-csf-2.0"
    # Fallback: use the filename stem
    return stem


def load_evidentia_catalog(catalog_path: Path) -> ControlCatalog:
    """Load a Evidentia-format framework catalog.
    
    Used for frameworks that don't have OSCAL catalogs published by NIST
    (SOC 2, ISO 27001, CIS, CMMC, PCI DSS). These are stored as
    Evidentia JSON format with a simplified structure.
    """
    with open(catalog_path, "r") as f:
        data = json.load(f)

    controls = [CatalogControl(**c) for c in data.get("controls", [])]
    
    return ControlCatalog(
        framework_id=data["framework_id"],
        framework_name=data["framework_name"],
        version=data.get("version", "1.0"),
        source=data.get("source", f"Evidentia: {catalog_path.name}"),
        controls=controls,
        families=data.get("families", []),
    )


def load_catalog(framework_id: str, custom_path: Optional[Path] = None) -> ControlCatalog:
    """Load a catalog by framework ID.
    
    First checks for a custom path, then looks in the bundled data directory.
    Auto-detects format (OSCAL vs Evidentia) based on file contents.
    """
    if custom_path:
        path = custom_path
    else:
        # Map framework ID to bundled file
        framework_files = {
            "nist-800-53-rev5": "nist-800-53-rev5.json",
            "nist-800-53-mod": "nist-800-53-mod.json",
            "nist-800-53-high": "nist-800-53-high.json",
            "nist-csf-2.0": "nist-csf-2.0.json",
            "soc2-tsc": "soc2-tsc.json",
            "iso27001-2022": "iso27001-2022.json",
            "cis-controls-v8": "cis-controls-v8.json",
            "cmmc-2-level2": "cmmc-2-level2.json",
            "pci-dss-4": "pci-dss-4.json",
        }
        filename = framework_files.get(framework_id)
        if not filename:
            raise ValueError(
                f"Unknown framework '{framework_id}'. "
                f"Available: {', '.join(framework_files.keys())}"
            )
        path = DATA_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Catalog file not found: {path}")

    with open(path, "r") as f:
        data = json.load(f)

    # Auto-detect format
    if "catalog" in data:
        return load_oscal_catalog(path)
    else:
        return load_evidentia_catalog(path)
```

### 6.3 Crosswalk Engine (evidentia_core/catalogs/crosswalk.py)

```python
"""Cross-framework mapping engine.

Loads crosswalk definitions and provides bidirectional mapping between
framework controls. The mapping graph is built at startup and cached
for fast lookups during gap analysis.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from evidentia_core.models.catalog import (
    CrosswalkDefinition,
    FrameworkMapping,
)

logger = logging.getLogger(__name__)

MAPPINGS_DIR = Path(__file__).parent / "data" / "mappings"


class CrosswalkEngine:
    """Bidirectional cross-framework control mapping engine.
    
    Loads all available crosswalk definitions and builds an in-memory
    mapping graph for fast lookups.
    
    Usage:
        engine = CrosswalkEngine()
        engine.load_all()
        
        # Forward: NIST → SOC 2
        soc2_controls = engine.get_mapped_controls(
            source_framework="nist-800-53-rev5",
            source_control_id="AC-2",
            target_framework="soc2-tsc"
        )
        # Returns: [FrameworkMapping(target_control_id="CC6.1", ...)]
        
        # Reverse: SOC 2 → NIST
        nist_controls = engine.get_mapped_controls(
            source_framework="soc2-tsc",
            source_control_id="CC6.1",
            target_framework="nist-800-53-rev5"
        )
        # Returns: [FrameworkMapping(target_control_id="AC-2", ...), ...]
        
        # All targets for a control
        all_targets = engine.get_all_mapped_controls(
            framework="nist-800-53-rev5",
            control_id="AC-2"
        )
        # Returns: {"soc2-tsc": [...], "iso27001-2022": [...], ...}
    """

    def __init__(self, mappings_dir: Optional[Path] = None):
        self._dir = mappings_dir or MAPPINGS_DIR
        # Forward index: (source_fw, source_ctl, target_fw) → [FrameworkMapping]
        self._forward: dict[tuple[str, str, str], list[FrameworkMapping]] = {}
        # Reverse index: (target_fw, target_ctl, source_fw) → [FrameworkMapping]
        self._reverse: dict[tuple[str, str, str], list[FrameworkMapping]] = {}
        # All loaded crosswalks
        self._crosswalks: list[CrosswalkDefinition] = []

    def load_all(self) -> None:
        """Load all crosswalk JSON files from the mappings directory."""
        if not self._dir.exists():
            logger.warning(f"Mappings directory not found: {self._dir}")
            return

        for json_file in sorted(self._dir.glob("*.json")):
            self.load_crosswalk(json_file)

        logger.info(
            f"Loaded {len(self._crosswalks)} crosswalks with "
            f"{sum(len(c.mappings) for c in self._crosswalks)} total mappings"
        )

    def load_crosswalk(self, path: Path) -> CrosswalkDefinition:
        """Load a single crosswalk definition and index it."""
        with open(path, "r") as f:
            data = json.load(f)

        crosswalk = CrosswalkDefinition(**data)
        self._crosswalks.append(crosswalk)

        # Build forward and reverse indexes
        for mapping in crosswalk.mappings:
            src_key = (
                crosswalk.source_framework,
                mapping.source_control_id.upper(),
                crosswalk.target_framework,
            )
            self._forward.setdefault(src_key, []).append(mapping)

            # Reverse mapping (swap source/target)
            rev_mapping = FrameworkMapping(
                source_control_id=mapping.target_control_id,
                source_control_title=mapping.target_control_title,
                target_control_id=mapping.source_control_id,
                target_control_title=mapping.source_control_title,
                relationship=mapping.relationship,
                notes=mapping.notes,
            )
            rev_key = (
                crosswalk.target_framework,
                mapping.target_control_id.upper(),
                crosswalk.source_framework,
            )
            self._reverse.setdefault(rev_key, []).append(rev_mapping)

        return crosswalk

    def get_mapped_controls(
        self,
        source_framework: str,
        source_control_id: str,
        target_framework: str,
    ) -> list[FrameworkMapping]:
        """Get controls in target_framework that map from source_control_id.
        
        Checks both forward and reverse indexes.
        """
        ctl = source_control_id.strip().upper()
        
        # Check forward index
        forward_key = (source_framework, ctl, target_framework)
        forward_results = self._forward.get(forward_key, [])
        
        # Check reverse index
        reverse_key = (source_framework, ctl, target_framework)
        reverse_results = self._reverse.get(reverse_key, [])
        
        # Deduplicate by target_control_id
        seen: set[str] = set()
        results: list[FrameworkMapping] = []
        for m in forward_results + reverse_results:
            if m.target_control_id.upper() not in seen:
                seen.add(m.target_control_id.upper())
                results.append(m)
        
        return results

    def get_all_mapped_controls(
        self,
        framework: str,
        control_id: str,
    ) -> dict[str, list[FrameworkMapping]]:
        """Get all controls across ALL frameworks that map to/from this control.
        
        Returns a dict keyed by target framework ID.
        """
        ctl = control_id.strip().upper()
        results: dict[str, list[FrameworkMapping]] = {}

        # Check all forward entries for this source
        for (src_fw, src_ctl, tgt_fw), mappings in self._forward.items():
            if src_fw == framework and src_ctl == ctl:
                results.setdefault(tgt_fw, []).extend(mappings)

        # Check all reverse entries
        for (src_fw, src_ctl, tgt_fw), mappings in self._reverse.items():
            if src_fw == framework and src_ctl == ctl:
                results.setdefault(tgt_fw, []).extend(mappings)

        return results

    def get_cross_framework_value(
        self,
        framework: str,
        control_id: str,
    ) -> list[str]:
        """Get a flat list of 'framework:control_id' pairs that this control maps to.
        
        Used for gap prioritization — controls that satisfy more frameworks
        are higher value to implement.
        """
        all_mappings = self.get_all_mapped_controls(framework, control_id)
        result: list[str] = []
        for target_fw, mappings in all_mappings.items():
            for m in mappings:
                result.append(f"{target_fw}:{m.target_control_id}")
        return result

    @property
    def available_frameworks(self) -> set[str]:
        """All framework IDs that appear in loaded crosswalks."""
        frameworks: set[str] = set()
        for crosswalk in self._crosswalks:
            frameworks.add(crosswalk.source_framework)
            frameworks.add(crosswalk.target_framework)
        return frameworks
```

### 6.4 Crosswalk JSON Format

All crosswalk files follow this structure:

```json
{
  "source_framework": "nist-800-53-rev5",
  "target_framework": "soc2-tsc-2017",
  "version": "1.0",
  "generated_at": "2026-04-05",
  "source": "AICPA Trust Services Criteria to NIST Cybersecurity Framework Mapping (2017), supplemented by NIST SP 800-53 Rev5 Appendix H",
  "mappings": [
    {
      "source_control_id": "AC-1",
      "source_control_title": "Policy and Procedures",
      "target_control_id": "CC1.1",
      "target_control_title": "COSO Principle 1: Demonstrates Commitment to Integrity and Ethical Values",
      "relationship": "related",
      "notes": "AC-1 addresses policy development and dissemination; CC1.1 addresses ethical values at the organizational level. Partial overlap on governance aspects."
    },
    {
      "source_control_id": "AC-2",
      "source_control_title": "Account Management",
      "target_control_id": "CC6.1",
      "target_control_title": "Logical and Physical Access Controls — Security Software, Infrastructure, and Architectures",
      "relationship": "related",
      "notes": "AC-2 covers user account lifecycle management; CC6.1 addresses logical access controls broadly including authentication and authorization."
    },
    {
      "source_control_id": "AC-2",
      "source_control_title": "Account Management",
      "target_control_id": "CC6.2",
      "target_control_title": "Logical and Physical Access Controls — User Authentication",
      "relationship": "related",
      "notes": "AC-2 user provisioning/deprovisioning supports CC6.2 registration and authorization requirements."
    }
  ]
}
```

**Relationship types:**

| Relationship | Meaning |
|---|---|
| `equivalent` | Source and target controls have essentially the same requirements |
| `related` | Controls address the same security domain but with different scope or specificity |
| `partial` | Source control partially addresses target requirement (or vice versa) |
| `superset` | Source control fully encompasses the target requirement plus additional requirements |

### 6.5 Framework Registry (evidentia_core/catalogs/registry.py)

```python
"""Framework registry — discovers and caches available catalogs and crosswalks.

Singleton that initializes at first use and provides the central access
point for all catalog and crosswalk operations.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from evidentia_core.catalogs.crosswalk import CrosswalkEngine
from evidentia_core.catalogs.loader import load_catalog
from evidentia_core.models.catalog import ControlCatalog

logger = logging.getLogger(__name__)


class FrameworkRegistry:
    """Central registry for framework catalogs and cross-framework mappings.
    
    Lazily loads catalogs on first access. Caches all loaded catalogs
    in memory for the lifetime of the process.
    
    Usage:
        registry = FrameworkRegistry()
        
        # List available frameworks
        registry.list_frameworks()
        # ['nist-800-53-rev5', 'nist-800-53-mod', 'soc2-tsc', ...]
        
        # Get a catalog
        catalog = registry.get_catalog("nist-800-53-mod")
        
        # Get a specific control
        control = registry.get_control("nist-800-53-mod", "AC-2")
        
        # Get cross-framework mappings
        mappings = registry.crosswalk.get_mapped_controls(
            "nist-800-53-rev5", "AC-2", "soc2-tsc"
        )
    """

    _instance: Optional[FrameworkRegistry] = None

    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = data_dir or Path(__file__).parent / "data"
        self._catalogs: dict[str, ControlCatalog] = {}
        self._crosswalk_engine = CrosswalkEngine(
            mappings_dir=self._data_dir / "mappings"
        )
        self._crosswalk_loaded = False

    @classmethod
    def get_instance(cls) -> FrameworkRegistry:
        """Get or create the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def crosswalk(self) -> CrosswalkEngine:
        """Access the crosswalk engine (lazy-loaded)."""
        if not self._crosswalk_loaded:
            self._crosswalk_engine.load_all()
            self._crosswalk_loaded = True
        return self._crosswalk_engine

    def list_frameworks(self) -> list[dict[str, str]]:
        """List all available framework IDs with metadata."""
        framework_metadata = {
            "nist-800-53-rev5": {"name": "NIST SP 800-53 Rev 5 (Full)", "controls": "~1189"},
            "nist-800-53-mod": {"name": "NIST SP 800-53 Rev 5 Moderate Baseline", "controls": "~323"},
            "nist-800-53-high": {"name": "NIST SP 800-53 Rev 5 High Baseline", "controls": "~421"},
            "nist-csf-2.0": {"name": "NIST Cybersecurity Framework 2.0", "controls": "~106"},
            "soc2-tsc": {"name": "SOC 2 Trust Services Criteria 2017", "controls": "~60"},
            "iso27001-2022": {"name": "ISO/IEC 27001:2022 Annex A", "controls": "93"},
            "cis-controls-v8": {"name": "CIS Controls v8", "controls": "153"},
            "cmmc-2-level2": {"name": "CMMC 2.0 Level 2", "controls": "110"},
            "pci-dss-4": {"name": "PCI DSS 4.0", "controls": "~285"},
        }
        return [
            {"id": fw_id, **meta}
            for fw_id, meta in framework_metadata.items()
        ]

    def get_catalog(self, framework_id: str) -> ControlCatalog:
        """Get a catalog by framework ID (cached)."""
        if framework_id not in self._catalogs:
            self._catalogs[framework_id] = load_catalog(framework_id)
        return self._catalogs[framework_id]

    def get_control(self, framework_id: str, control_id: str):
        """Get a specific control from a framework catalog."""
        catalog = self.get_catalog(framework_id)
        return catalog.get_control(control_id)
```

---


## 7. Phase 1 MVP: Control Gap Analyzer + AI Risk Statement Generator

### 7.1 Gap Analyzer

#### 7.1.1 Multi-Format Inventory Parser (evidentia_core/gap_analyzer/inventory.py)

```python
"""Multi-format control inventory parser.

Supports four input formats with auto-detection:
1. Evidentia YAML (preferred)
2. CSV with fuzzy header matching
3. OSCAL component definition JSON
4. CISO Assistant JSON export

Detection logic:
1. Check file extension (.yaml/.yml → YAML, .csv → CSV, .json → JSON)
2. If JSON: check for "component-definition" key → OSCAL
3. If JSON: check for "ciso_assistant" or "framework" key → CISO Assistant
4. If YAML: check for "controls:" key → Evidentia
5. If CSV: map columns with fuzzy matching on standard header names
"""

from __future__ import annotations

import csv
import json
import logging
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml
from thefuzz import fuzz

from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)

logger = logging.getLogger(__name__)

# Known CSV column names and their canonical mappings
CSV_COLUMN_ALIASES = {
    "control_id": ["control_id", "control id", "id", "control", "ctrl_id", "ctrl", "requirement_id", "requirement"],
    "title": ["title", "control_title", "control title", "name", "control_name"],
    "status": ["status", "implementation_status", "implementation status", "state", "impl_status"],
    "description": ["description", "notes", "implementation_notes", "details", "comments"],
    "owner": ["owner", "control_owner", "responsible", "assignee", "responsible_party"],
}

# Status aliases for fuzzy matching
STATUS_ALIASES = {
    "implemented": ControlStatus.IMPLEMENTED,
    "fully implemented": ControlStatus.IMPLEMENTED,
    "complete": ControlStatus.IMPLEMENTED,
    "yes": ControlStatus.IMPLEMENTED,
    "partial": ControlStatus.PARTIALLY_IMPLEMENTED,
    "partially implemented": ControlStatus.PARTIALLY_IMPLEMENTED,
    "in progress": ControlStatus.PARTIALLY_IMPLEMENTED,
    "planned": ControlStatus.PLANNED,
    "scheduled": ControlStatus.PLANNED,
    "not implemented": ControlStatus.NOT_IMPLEMENTED,
    "missing": ControlStatus.NOT_IMPLEMENTED,
    "no": ControlStatus.NOT_IMPLEMENTED,
    "not applicable": ControlStatus.NOT_APPLICABLE,
    "n/a": ControlStatus.NOT_APPLICABLE,
    "na": ControlStatus.NOT_APPLICABLE,
}


def load_inventory(path: str | Path) -> ControlInventory:
    """Load a control inventory from any supported format.
    
    Auto-detects format based on file extension and content structure.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {path}")

    suffix = path.suffix.lower()
    content = path.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        return _parse_evidentia_yaml(content, str(path))
    elif suffix == ".csv":
        return _parse_csv(content, str(path))
    elif suffix == ".json":
        return _parse_json(content, str(path))
    else:
        raise ValueError(
            f"Unsupported file extension '{suffix}'. "
            f"Supported: .yaml, .yml, .json, .csv"
        )


def _parse_json(content: str, source_path: str) -> ControlInventory:
    """Parse a JSON inventory — auto-detect OSCAL vs CISO Assistant vs Evidentia."""
    data = json.loads(content)

    if "component-definition" in data:
        return _parse_oscal_component_definition(data, source_path)
    elif "ciso_assistant" in data or (
        isinstance(data, dict) and "framework" in data and "assessments" in data
    ):
        return _parse_ciso_assistant(data, source_path)
    elif "controls" in data:
        # Evidentia JSON format (same structure as YAML)
        return _parse_evidentia_dict(data, source_path, "evidentia-json")
    else:
        raise ValueError(
            "Unrecognized JSON format. Expected one of: "
            "OSCAL component-definition, CISO Assistant export, "
            "or Evidentia format with 'controls' key."
        )


def _parse_evidentia_yaml(content: str, source_path: str) -> ControlInventory:
    """Parse Evidentia YAML format."""
    data = yaml.safe_load(content)
    if not isinstance(data, dict) or "controls" not in data:
        raise ValueError(
            "Invalid Evidentia YAML: expected a mapping with 'controls' key"
        )
    return _parse_evidentia_dict(data, source_path, "evidentia")


def _parse_evidentia_dict(
    data: dict, source_path: str, format_name: str
) -> ControlInventory:
    """Parse a Evidentia-format dict (from YAML or JSON)."""
    controls: list[ControlImplementation] = []
    for item in data.get("controls", []):
        status_str = item.get("status", "not_implemented").lower().strip()
        status = STATUS_ALIASES.get(status_str, ControlStatus.NOT_IMPLEMENTED)
        
        controls.append(ControlImplementation(
            id=str(item["id"]).strip(),
            title=item.get("title"),
            description=item.get("description"),
            status=status,
            implementation_notes=item.get("implementation_notes") or item.get("notes"),
            responsible_roles=item.get("responsible_roles", []),
            evidence_references=item.get("evidence_references", []),
            owner=item.get("owner"),
            frameworks=item.get("frameworks", []),
            tags=item.get("tags", []),
        ))

    return ControlInventory(
        organization=data.get("organization", "Unknown Organization"),
        controls=controls,
        source_format=format_name,
        source_file=source_path,
    )


def _parse_csv(content: str, source_path: str) -> ControlInventory:
    """Parse CSV with fuzzy header matching."""
    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        raise ValueError("CSV file has no headers")

    # Map CSV headers to canonical names using fuzzy matching
    header_map: dict[str, str] = {}
    for canonical, aliases in CSV_COLUMN_ALIASES.items():
        best_match: Optional[str] = None
        best_score = 0
        for csv_header in reader.fieldnames:
            for alias in aliases:
                score = fuzz.ratio(csv_header.lower().strip(), alias.lower())
                if score > best_score and score >= 70:  # 70% minimum match
                    best_score = score
                    best_match = csv_header
        if best_match:
            header_map[canonical] = best_match

    if "control_id" not in header_map:
        raise ValueError(
            f"CSV must have a control ID column. "
            f"Found headers: {reader.fieldnames}. "
            f"Expected one of: {CSV_COLUMN_ALIASES['control_id']}"
        )

    controls: list[ControlImplementation] = []
    for row in reader:
        control_id = row.get(header_map["control_id"], "").strip()
        if not control_id:
            continue

        status_str = row.get(header_map.get("status", ""), "not_implemented").lower().strip()
        status = STATUS_ALIASES.get(status_str, ControlStatus.NOT_IMPLEMENTED)

        controls.append(ControlImplementation(
            id=control_id,
            title=row.get(header_map.get("title", ""), None) or None,
            description=row.get(header_map.get("description", ""), None) or None,
            status=status,
            owner=row.get(header_map.get("owner", ""), None) or None,
        ))

    logger.info(
        f"Parsed CSV inventory: {len(controls)} controls from {source_path}"
    )
    return ControlInventory(
        organization="Unknown Organization (from CSV)",
        controls=controls,
        source_format="csv",
        source_file=source_path,
    )


def _parse_oscal_component_definition(data: dict, source_path: str) -> ControlInventory:
    """Parse an OSCAL component-definition JSON into a ControlInventory."""
    comp_def = data["component-definition"]
    metadata = comp_def.get("metadata", {})

    controls: list[ControlImplementation] = []
    for component in comp_def.get("components", []):
        for ctrl_impl in component.get("control-implementations", []):
            for impl_req in ctrl_impl.get("implemented-requirements", []):
                control_id = impl_req.get("control-id", "").upper()
                
                # Determine status from OSCAL properties
                status = ControlStatus.IMPLEMENTED
                for prop in impl_req.get("props", []):
                    if prop.get("name") == "implementation-status":
                        oscal_status = prop.get("value", "").lower()
                        if "partial" in oscal_status:
                            status = ControlStatus.PARTIALLY_IMPLEMENTED
                        elif "planned" in oscal_status:
                            status = ControlStatus.PLANNED
                        elif "not" in oscal_status:
                            status = ControlStatus.NOT_IMPLEMENTED

                description = ""
                for statement in impl_req.get("statements", []):
                    description += statement.get("description", "") + "\n"

                controls.append(ControlImplementation(
                    id=control_id,
                    title=None,  # OSCAL doesn't include title in component-definition
                    description=description.strip() or None,
                    status=status,
                ))

    return ControlInventory(
        organization=metadata.get("title", "Unknown Organization"),
        controls=controls,
        source_format="oscal",
        source_file=source_path,
    )


def _parse_ciso_assistant(data: dict, source_path: str) -> ControlInventory:
    """Parse a CISO Assistant JSON export into a ControlInventory."""
    controls: list[ControlImplementation] = []
    
    for assessment in data.get("assessments", data.get("compliance_assessments", [])):
        for req in assessment.get("requirements", []):
            control_id = req.get("ref_id", req.get("urn", "")).strip()
            if not control_id:
                continue

            status_value = req.get("status", "").lower()
            status_map = {
                "compliant": ControlStatus.IMPLEMENTED,
                "partially_compliant": ControlStatus.PARTIALLY_IMPLEMENTED,
                "non_compliant": ControlStatus.NOT_IMPLEMENTED,
                "not_applicable": ControlStatus.NOT_APPLICABLE,
            }
            status = status_map.get(status_value, ControlStatus.NOT_IMPLEMENTED)

            controls.append(ControlImplementation(
                id=control_id,
                title=req.get("name"),
                description=req.get("description"),
                status=status,
                implementation_notes=req.get("observation"),
            ))

    return ControlInventory(
        organization=data.get("organization", {}).get("name", "Unknown Organization"),
        controls=controls,
        source_format="ciso-assistant",
        source_file=source_path,
    )
```

#### 7.1.2 Control ID Normalizer (evidentia_core/gap_analyzer/normalizer.py)

```python
"""Control ID normalization and fuzzy matching.

Handles the many ways people write control IDs:
- "AC-2" vs "AC2" vs "ac-2" vs "Access Control 2"
- "CC6.1" vs "CC 6.1" vs "cc6.1"
- "A.9.2.1" vs "A9.2.1" vs "ISO A.9.2.1"
"""

from __future__ import annotations

import re
from typing import Optional

from thefuzz import fuzz, process

from evidentia_core.models.catalog import ControlCatalog


def normalize_control_id(raw_id: str) -> str:
    """Normalize a control ID to a canonical form.
    
    Rules:
    1. Strip whitespace and convert to uppercase
    2. Remove common prefixes: "NIST ", "ISO ", "CIS ", "SOC2 "
    3. Ensure hyphen separators for NIST-style IDs: "AC2" → "AC-2"
    4. Preserve dot separators for ISO/SOC2 style: "CC6.1" stays "CC6.1"
    """
    result = raw_id.strip().upper()
    
    # Remove common prefixes
    for prefix in ["NIST ", "ISO ", "CIS ", "SOC2 ", "SOC 2 ", "PCI ", "CMMC "]:
        if result.startswith(prefix):
            result = result[len(prefix):]
    
    # Handle NIST-style IDs: ensure hyphen between family prefix and number
    # Match patterns like "AC2" → "AC-2", "AU12" → "AU-12"
    nist_pattern = re.compile(r'^([A-Z]{2,3})(\d+)(.*)$')
    match = nist_pattern.match(result.replace("-", "").replace(" ", ""))
    if match and not re.search(r'\.', result):
        family = match.group(1)
        number = match.group(2)
        suffix = match.group(3)
        # Handle enhancement notation: "AC-2(1)" 
        if suffix.startswith("("):
            result = f"{family}-{number}{suffix}"
        elif suffix:
            result = f"{family}-{number}-{suffix}" if suffix.isdigit() else f"{family}-{number}{suffix}"
        else:
            result = f"{family}-{number}"
    
    return result


def find_best_match(
    user_control_id: str,
    catalog: ControlCatalog,
    threshold: int = 75,
) -> Optional[str]:
    """Find the best matching control ID in a catalog using fuzzy matching.
    
    Steps:
    1. Try exact match (after normalization)
    2. Try fuzzy matching on control IDs
    3. Try fuzzy matching on control titles (for natural language input)
    
    Returns the matched catalog control ID, or None if no match found.
    """
    normalized = normalize_control_id(user_control_id)
    
    # 1. Exact match
    exact = catalog.get_control(normalized)
    if exact:
        return exact.id
    
    # 2. Fuzzy match on control IDs
    all_ids = [c.id for c in catalog.controls]
    for c in catalog.controls:
        all_ids.extend(e.id for e in c.enhancements)
    
    id_match = process.extractOne(
        normalized, all_ids, scorer=fuzz.ratio
    )
    if id_match and id_match[1] >= threshold:
        return id_match[0]
    
    # 3. Fuzzy match on titles (for inputs like "Account Management")
    title_map = {}
    for c in catalog.controls:
        title_map[c.title] = c.id
        for e in c.enhancements:
            title_map[e.title] = e.id
    
    title_match = process.extractOne(
        user_control_id, list(title_map.keys()), scorer=fuzz.ratio
    )
    if title_match and title_match[1] >= threshold:
        return title_map[title_match[0]]
    
    return None
```

#### 7.1.3 Gap Analysis Engine (evidentia_core/gap_analyzer/analyzer.py)

```python
"""Core gap analysis engine.

Compares an organization's control inventory against one or more framework
catalogs and produces a prioritized gap report with cross-framework
efficiency opportunities.

Algorithm:
1. Load target framework catalog(s)
2. Build required control set (union of all controls from selected frameworks)
3. Normalize user inventory control IDs to catalog control IDs
4. Identify gaps (required controls not in inventory or partially implemented)
5. Assess partial coverage
6. Calculate cross-framework value for each gap
7. Compute priority scores
8. Detect efficiency opportunities (controls satisfying 3+ frameworks)
9. Generate prioritized roadmap
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer.normalizer import find_best_match, normalize_control_id
from evidentia_core.models.catalog import CatalogControl
from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)
from evidentia_core.models.gap import (
    ControlGap,
    EfficiencyOpportunity,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)

logger = logging.getLogger(__name__)

# ── Scoring weights ────────────────────────────────────────────────────
SEVERITY_WEIGHT: dict[GapSeverity, float] = {
    GapSeverity.CRITICAL: 4.0,
    GapSeverity.HIGH: 3.0,
    GapSeverity.MEDIUM: 2.0,
    GapSeverity.LOW: 1.0,
    GapSeverity.INFORMATIONAL: 0.5,
}

EFFORT_WEIGHT: dict[ImplementationEffort, float] = {
    ImplementationEffort.LOW: 1.0,
    ImplementationEffort.MEDIUM: 2.0,
    ImplementationEffort.HIGH: 4.0,
    ImplementationEffort.VERY_HIGH: 8.0,
}


class GapAnalyzer:
    """The core gap analysis engine.
    
    Usage:
        analyzer = GapAnalyzer()
        report = analyzer.analyze(
            inventory=my_inventory,
            frameworks=["nist-800-53-mod", "soc2-tsc"],
            show_efficiency=True,
        )
    """

    def __init__(self, registry: Optional[FrameworkRegistry] = None):
        self.registry = registry or FrameworkRegistry.get_instance()

    def analyze(
        self,
        inventory: ControlInventory,
        frameworks: list[str],
        show_efficiency: bool = True,
        min_efficiency_frameworks: int = 3,
    ) -> GapAnalysisReport:
        """Run gap analysis against specified frameworks.
        
        Args:
            inventory: Organization's control inventory
            frameworks: List of framework IDs to analyze against
            show_efficiency: Whether to compute efficiency opportunities
            min_efficiency_frameworks: Minimum number of frameworks a control
                must satisfy to be flagged as an efficiency opportunity
        """
        logger.info(
            f"Starting gap analysis for {inventory.organization}: "
            f"{len(inventory.controls)} controls vs {frameworks}"
        )

        # Step 1: Load catalogs
        catalogs = {fw: self.registry.get_catalog(fw) for fw in frameworks}
        
        # Step 2: Build required control set
        required_controls = self._build_required_set(catalogs)
        
        # Step 3: Normalize inventory
        inventory_map = self._normalize_inventory(inventory, catalogs)
        
        # Step 4-5: Identify gaps
        gaps = self._identify_gaps(
            required_controls, inventory_map, inventory, catalogs
        )
        
        # Step 6: Calculate cross-framework value
        self._calculate_cross_framework_value(gaps)
        
        # Step 7: Compute priority scores
        for gap in gaps:
            gap.priority_score = self._compute_priority(gap)
        
        # Sort by priority (descending)
        gaps.sort(key=lambda g: g.priority_score, reverse=True)
        
        # Step 8: Detect efficiency opportunities
        efficiency = []
        if show_efficiency:
            efficiency = self._detect_efficiency_opportunities(
                gaps, min_frameworks=min_efficiency_frameworks
            )
        
        # Step 9: Build report
        severity_counts = self._count_severities(gaps)
        total_required = len(required_controls)
        total_gaps = len(gaps)
        coverage = ((total_required - total_gaps) / total_required * 100) if total_required > 0 else 100.0

        report = GapAnalysisReport(
            organization=inventory.organization,
            frameworks_analyzed=frameworks,
            total_controls_required=total_required,
            total_controls_in_inventory=len(inventory.controls),
            total_gaps=total_gaps,
            critical_gaps=severity_counts.get(GapSeverity.CRITICAL, 0),
            high_gaps=severity_counts.get(GapSeverity.HIGH, 0),
            medium_gaps=severity_counts.get(GapSeverity.MEDIUM, 0),
            low_gaps=severity_counts.get(GapSeverity.LOW, 0),
            informational_gaps=severity_counts.get(GapSeverity.INFORMATIONAL, 0),
            coverage_percentage=round(coverage, 1),
            gaps=gaps,
            efficiency_opportunities=efficiency,
            prioritized_roadmap=[g.id for g in gaps],
            inventory_source=inventory.source_file,
        )

        logger.info(
            f"Gap analysis complete: {total_gaps} gaps found, "
            f"{coverage:.1f}% coverage, "
            f"{len(efficiency)} efficiency opportunities"
        )
        return report

    def _build_required_set(
        self, catalogs: dict[str, "ControlCatalog"]
    ) -> dict[str, list[tuple[str, CatalogControl]]]:
        """Build the set of required controls across all frameworks.
        
        Returns: {canonical_control_id: [(framework_id, CatalogControl), ...]}
        This allows tracking which frameworks require each control.
        """
        from evidentia_core.models.catalog import ControlCatalog
        
        required: dict[str, list[tuple[str, CatalogControl]]] = defaultdict(list)
        
        for fw_id, catalog in catalogs.items():
            for control in catalog.controls:
                key = f"{fw_id}:{control.id}"
                required[key].append((fw_id, control))
                # Include enhancements as separate requirements
                for enhancement in control.enhancements:
                    enh_key = f"{fw_id}:{enhancement.id}"
                    required[enh_key].append((fw_id, enhancement))
        
        return required

    def _normalize_inventory(
        self,
        inventory: ControlInventory,
        catalogs: dict,
    ) -> dict[str, ControlImplementation]:
        """Normalize inventory control IDs and build a lookup map.
        
        For each inventory control, attempt to match it to each catalog's
        controls using normalization and fuzzy matching.
        
        Returns: {framework:control_id: ControlImplementation}
        """
        inv_map: dict[str, ControlImplementation] = {}
        
        for impl in inventory.controls:
            for fw_id, catalog in catalogs.items():
                matched_id = find_best_match(impl.id, catalog)
                if matched_id:
                    key = f"{fw_id}:{matched_id}"
                    inv_map[key] = impl
        
        return inv_map

    def _identify_gaps(
        self,
        required: dict[str, list[tuple[str, CatalogControl]]],
        inventory_map: dict[str, ControlImplementation],
        inventory: ControlInventory,
        catalogs: dict,
    ) -> list[ControlGap]:
        """Identify gaps between required controls and inventory."""
        gaps: list[ControlGap] = []

        for req_key, fw_controls in required.items():
            impl = inventory_map.get(req_key)
            fw_id, catalog_control = fw_controls[0]

            if impl is None:
                # Control is completely missing
                gaps.append(ControlGap(
                    framework=fw_id,
                    control_id=catalog_control.id,
                    control_title=catalog_control.title,
                    control_description=catalog_control.description,
                    control_family=catalog_control.family,
                    gap_severity=GapSeverity.CRITICAL,
                    implementation_status="missing",
                    gap_description=(
                        f"Control {catalog_control.id} ({catalog_control.title}) "
                        f"is required by {fw_id} but is not present in the "
                        f"organization's control inventory."
                    ),
                    remediation_guidance=self._generate_remediation_guidance(
                        catalog_control
                    ),
                    implementation_effort=self._estimate_effort(catalog_control),
                ))
            elif impl.status == ControlStatus.PARTIALLY_IMPLEMENTED:
                gaps.append(ControlGap(
                    framework=fw_id,
                    control_id=catalog_control.id,
                    control_title=catalog_control.title,
                    control_description=catalog_control.description,
                    control_family=catalog_control.family,
                    gap_severity=GapSeverity.HIGH,
                    implementation_status="partial",
                    gap_description=(
                        f"Control {catalog_control.id} ({catalog_control.title}) "
                        f"is partially implemented. "
                        f"Notes: {impl.implementation_notes or 'No details provided.'}"
                    ),
                    equivalent_controls_in_inventory=[impl.id],
                    remediation_guidance=self._generate_remediation_guidance(
                        catalog_control, partial=True
                    ),
                    implementation_effort=ImplementationEffort.MEDIUM,
                ))
            elif impl.status == ControlStatus.PLANNED:
                gaps.append(ControlGap(
                    framework=fw_id,
                    control_id=catalog_control.id,
                    control_title=catalog_control.title,
                    control_description=catalog_control.description,
                    control_family=catalog_control.family,
                    gap_severity=GapSeverity.MEDIUM,
                    implementation_status="planned",
                    gap_description=(
                        f"Control {catalog_control.id} ({catalog_control.title}) "
                        f"is planned but not yet implemented."
                    ),
                    equivalent_controls_in_inventory=[impl.id],
                    remediation_guidance=(
                        f"Execute the planned implementation for {catalog_control.id}. "
                        f"Ensure implementation addresses all assessment objectives."
                    ),
                    implementation_effort=ImplementationEffort.LOW,
                ))
            # IMPLEMENTED and NOT_APPLICABLE are not gaps

        return gaps

    def _calculate_cross_framework_value(self, gaps: list[ControlGap]) -> None:
        """For each gap, determine which other frameworks would also benefit."""
        crosswalk = self.registry.crosswalk
        
        for gap in gaps:
            # Get all cross-framework mappings for this control
            cross_value = crosswalk.get_cross_framework_value(
                gap.framework, gap.control_id
            )
            gap.cross_framework_value = cross_value

    def _compute_priority(self, gap: ControlGap) -> float:
        """Compute priority score for a gap.
        
        Formula:
            priority = severity_weight × (1 + 0.2 × cross_framework_count) × (1 / effort_weight)
        
        Higher score = higher priority (fix first).
        """
        severity_w = SEVERITY_WEIGHT.get(gap.gap_severity, 1.0)
        cross_fw_bonus = 1 + 0.2 * len(gap.cross_framework_value)
        effort_w = EFFORT_WEIGHT.get(gap.implementation_effort, 2.0)
        
        return round(severity_w * cross_fw_bonus * (1 / effort_w), 3)

    def _detect_efficiency_opportunities(
        self,
        gaps: list[ControlGap],
        min_frameworks: int = 3,
    ) -> list[EfficiencyOpportunity]:
        """Detect controls that satisfy multiple framework requirements.
        
        Groups gaps by their base control ID (e.g., AC-2 across NIST, SOC2, ISO)
        and identifies controls that appear in min_frameworks or more.
        """
        crosswalk = self.registry.crosswalk
        
        # Group gaps by normalized control concept
        control_groups: dict[str, list[ControlGap]] = defaultdict(list)
        for gap in gaps:
            # Use the control ID as the grouping key
            control_groups[gap.control_id].append(gap)
        
        opportunities: list[EfficiencyOpportunity] = []
        
        for control_id, gap_group in control_groups.items():
            # Count distinct frameworks
            frameworks = set(g.framework for g in gap_group)
            
            # Add cross-framework mappings
            all_satisfied: list[str] = []
            for g in gap_group:
                all_satisfied.append(f"{g.framework}:{g.control_id}")
                all_satisfied.extend(g.cross_framework_value)
            
            unique_frameworks = set(s.split(":")[0] for s in all_satisfied)
            
            if len(unique_frameworks) >= min_frameworks:
                # Pick the most common effort level
                effort = max(
                    gap_group, key=lambda g: SEVERITY_WEIGHT.get(g.gap_severity, 0)
                ).implementation_effort
                
                effort_w = EFFORT_WEIGHT.get(effort, 2.0)
                value_score = len(set(all_satisfied)) / effort_w
                
                opportunities.append(EfficiencyOpportunity(
                    control_id=control_id,
                    control_title=gap_group[0].control_title,
                    frameworks_satisfied=sorted(set(all_satisfied)),
                    framework_count=len(unique_frameworks),
                    total_gaps_closed=len(gap_group),
                    implementation_effort=effort,
                    value_score=round(value_score, 2),
                ))
        
        # Sort by value score descending
        opportunities.sort(key=lambda o: o.value_score, reverse=True)
        return opportunities

    def _generate_remediation_guidance(
        self,
        control: CatalogControl,
        partial: bool = False,
    ) -> str:
        """Generate remediation guidance for a gap."""
        if partial:
            return (
                f"Complete the implementation of {control.id} ({control.title}). "
                f"Review the control description and assessment objectives to identify "
                f"which aspects are not yet covered. Key requirements:\n"
                f"{control.description[:500]}"
            )
        return (
            f"Implement {control.id} ({control.title}) to meet the following requirement:\n"
            f"{control.description[:500]}\n\n"
            f"Consider: existing tools, processes, or compensating controls that may "
            f"partially address this requirement."
        )

    def _estimate_effort(self, control: CatalogControl) -> ImplementationEffort:
        """Estimate implementation effort based on control characteristics."""
        # Heuristic: controls with many enhancements or assessment objectives
        # tend to be more complex
        complexity_score = len(control.enhancements) + len(control.assessment_objectives)
        
        if complexity_score >= 10:
            return ImplementationEffort.VERY_HIGH
        elif complexity_score >= 5:
            return ImplementationEffort.HIGH
        elif complexity_score >= 2:
            return ImplementationEffort.MEDIUM
        else:
            return ImplementationEffort.LOW

    @staticmethod
    def _count_severities(gaps: list[ControlGap]) -> dict[GapSeverity, int]:
        counts: dict[GapSeverity, int] = {}
        for gap in gaps:
            counts[gap.gap_severity] = counts.get(gap.gap_severity, 0) + 1
        return counts
```

#### 7.1.4 Output Formatters (evidentia_core/gap_analyzer/reporter.py)

```python
"""Gap analysis report output formatters.

Supports: JSON, CSV, Markdown, OSCAL Assessment Results.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Literal

from evidentia_core.models.gap import GapAnalysisReport


OutputFormat = Literal["json", "csv", "markdown", "oscal-ar"]


def export_report(
    report: GapAnalysisReport,
    output_path: str | Path,
    format: OutputFormat = "json",
) -> Path:
    """Export a gap analysis report in the specified format."""
    path = Path(output_path)
    
    if format == "json":
        return _export_json(report, path)
    elif format == "csv":
        return _export_csv(report, path)
    elif format == "markdown":
        return _export_markdown(report, path)
    elif format == "oscal-ar":
        return _export_oscal_ar(report, path)
    else:
        raise ValueError(f"Unsupported format: {format}")


def _export_json(report: GapAnalysisReport, path: Path) -> Path:
    """Export as JSON."""
    path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return path


def _export_csv(report: GapAnalysisReport, path: Path) -> Path:
    """Export gaps as CSV (one row per gap)."""
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "gap_id", "framework", "control_id", "control_title",
        "gap_severity", "implementation_status", "gap_description",
        "cross_framework_value", "remediation_guidance",
        "implementation_effort", "priority_score",
        "jira_issue_key", "servicenow_ticket_id",
    ])
    
    for gap in report.gaps:
        writer.writerow([
            gap.id, gap.framework, gap.control_id, gap.control_title,
            gap.gap_severity, gap.implementation_status, gap.gap_description,
            "; ".join(gap.cross_framework_value),
            gap.remediation_guidance, gap.implementation_effort,
            gap.priority_score,
            gap.jira_issue_key or "", gap.servicenow_ticket_id or "",
        ])
    
    path.write_text(output.getvalue(), encoding="utf-8")
    return path


def _export_markdown(report: GapAnalysisReport, path: Path) -> Path:
    """Export as Markdown report."""
    lines: list[str] = []
    
    lines.append(f"# Gap Analysis Report: {report.organization}")
    lines.append(f"")
    lines.append(f"**Date:** {report.analyzed_at.isoformat()}")
    lines.append(f"**Frameworks:** {', '.join(report.frameworks_analyzed)}")
    lines.append(f"**Evidentia Version:** {report.evidentia_version}")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Total Controls Required | {report.total_controls_required} |")
    lines.append(f"| Controls in Inventory | {report.total_controls_in_inventory} |")
    lines.append(f"| Total Gaps | {report.total_gaps} |")
    lines.append(f"| Critical | {report.critical_gaps} |")
    lines.append(f"| High | {report.high_gaps} |")
    lines.append(f"| Medium | {report.medium_gaps} |")
    lines.append(f"| Low | {report.low_gaps} |")
    lines.append(f"| Coverage | {report.coverage_percentage}% |")
    lines.append(f"")
    
    lines.append(f"## Gaps (Prioritized)")
    lines.append(f"")
    lines.append(f"| # | Framework | Control | Severity | Status | Effort | Priority | Cross-FW Value |")
    lines.append(f"|---|---|---|---|---|---|---|---|")
    
    for i, gap in enumerate(report.gaps, 1):
        cross_fw = len(gap.cross_framework_value)
        lines.append(
            f"| {i} | {gap.framework} | {gap.control_id} — {gap.control_title} | "
            f"{gap.gap_severity} | {gap.implementation_status} | "
            f"{gap.implementation_effort} | {gap.priority_score} | "
            f"{cross_fw} frameworks |"
        )
    
    if report.efficiency_opportunities:
        lines.append(f"")
        lines.append(f"## Efficiency Opportunities")
        lines.append(f"")
        lines.append(f"Controls that satisfy 3+ framework requirements simultaneously:")
        lines.append(f"")
        lines.append(f"| Control | Title | Frameworks | Gaps Closed | Effort | Value Score |")
        lines.append(f"|---|---|---|---|---|---|")
        for opp in report.efficiency_opportunities:
            lines.append(
                f"| {opp.control_id} | {opp.control_title} | "
                f"{opp.framework_count} | {opp.total_gaps_closed} | "
                f"{opp.implementation_effort} | {opp.value_score} |"
            )
    
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _export_oscal_ar(report: GapAnalysisReport, path: Path) -> Path:
    """Export as OSCAL Assessment Results JSON.
    
    Maps Evidentia gap report to OSCAL assessment-results structure:
    - Each gap → observation + finding
    - Risk statements → risk entries
    - Evidence → observations with evidence references
    """
    from evidentia_core.oscal.exporter import gap_report_to_oscal_ar
    
    oscal_ar = gap_report_to_oscal_ar(report)
    path.write_text(
        json.dumps(oscal_ar, indent=2, default=str),
        encoding="utf-8",
    )
    return path
```

### 7.2 AI Risk Statement Generator

#### 7.2.1 LLM Client Setup (evidentia_ai/client.py)

```python
"""LiteLLM + Instructor client setup.

Provides a configured Instructor client that works with any LLM provider
supported by LiteLLM. Model selection is determined by (in priority order):
1. Explicit model parameter
2. EVIDENTIA_LLM_MODEL environment variable
3. llm.model in evidentia.yaml
4. Default: "gpt-4o"
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import instructor
import litellm


# Suppress LiteLLM's verbose logging by default
litellm.suppress_debug_info = True


def get_default_model() -> str:
    """Get the default model from environment or config."""
    return os.environ.get("EVIDENTIA_LLM_MODEL", "gpt-4o")


def get_temperature() -> float:
    """Get the default temperature from environment or config."""
    return float(os.environ.get("EVIDENTIA_LLM_TEMPERATURE", "0.1"))


@lru_cache(maxsize=1)
def get_instructor_client(
    model: Optional[str] = None,
) -> instructor.Instructor:
    """Get a configured Instructor client.
    
    Uses `instructor.from_litellm` for provider-agnostic LLM access.
    The same client works with OpenAI, Anthropic, Google, Ollama, etc.
    """
    return instructor.from_litellm(litellm.completion)


@lru_cache(maxsize=1)
def get_async_instructor_client(
    model: Optional[str] = None,
) -> instructor.AsyncInstructor:
    """Get an async Instructor client for concurrent operations."""
    return instructor.from_litellm(litellm.acompletion)
```

#### 7.2.2 Risk Statement Prompts (evidentia_ai/risk_statements/prompts.py)

```python
"""System prompts for risk statement generation.

These prompts are carefully engineered to produce NIST SP 800-30-compliant
risk statements with specific, measurable language.
"""

RISK_STATEMENT_SYSTEM_PROMPT = """\
You are an expert cybersecurity risk analyst specializing in NIST Risk Management \
Framework (RMF) risk assessments. You produce risk statements following the \
structure defined in NIST SP 800-30 Revision 1, "Guide for Conducting Risk Assessments."

Your task is to generate a structured risk statement for a specific control gap \
identified during a gap analysis. The risk statement must be:

1. **Specific and measurable.** Never use vague language like "potential impact" or \
"may cause harm." Instead, reference specific data types, record counts, system names, \
regulatory consequences, and dollar amounts where possible.

2. **Structured per NIST SP 800-30.** Every risk statement must decompose into:
   - **Asset**: The specific system, data, or function at risk
   - **Threat source**: Who or what could exploit the vulnerability
   - **Threat event**: What they would do (specific technical action)
   - **Vulnerability**: The weakness that enables the threat (tied to the control gap)
   - **Predisposing conditions**: Environmental factors that increase likelihood
   - **Likelihood**: Rated on a 5-point scale with specific rationale
   - **Impact**: Rated on a 5-point scale with specific rationale
   - **Risk level**: Derived from likelihood × impact per NIST risk matrix

3. **Actionable.** Include specific NIST 800-53 control IDs that would mitigate the risk, \
and ordered remediation steps.

4. **Honest about uncertainty.** If the system context doesn't provide enough information \
to make a precise assessment, say so in the rationale rather than fabricating specifics.

NIST SP 800-30 Risk Matrix (for determining risk_level from likelihood × impact):
- Very High × Very High/High = Critical
- High × Very High/High = Critical
- High × Moderate = High
- Moderate × Very High/High = High
- Moderate × Moderate = Medium
- Low × Very High/High = Medium
- Low × Moderate/Low = Low
- Very Low × any = Low (or Informational)

CRITICAL RULES:
- Only reference NIST 800-53 control IDs that actually exist. Do not fabricate control IDs.
- Rate likelihood and impact independently — do not conflate them.
- The vulnerability field MUST directly reference the control gap provided.
- remediation_priority: 1 = most urgent, 5 = least urgent.
"""

RISK_CONTEXT_TEMPLATE = """\
## System Context
Organization: {organization}
System: {system_name}
Description: {system_description}
Data Classification: {data_classification}
Hosting: {hosting}
Risk Tolerance: {risk_tolerance}

## System Components
{components_text}

## Relevant Threat Actors
{threat_actors_text}

## Existing Controls Already Implemented
{existing_controls_text}

## Control Gap to Assess
Framework: {gap_framework}
Control ID: {gap_control_id}
Control Title: {gap_control_title}
Control Description: {gap_control_description}
Gap Severity: {gap_severity}
Gap Description: {gap_description}
Implementation Status: {gap_implementation_status}
Cross-Framework Value: This control also satisfies requirements in: {cross_framework_value}

Generate a NIST SP 800-30 compliant risk statement for this specific gap, \
considering the system context, data classification, hosting environment, \
and threat actors described above.
"""
```

#### 7.2.3 Risk Statement Generator (evidentia_ai/risk_statements/generator.py)

```python
"""Risk statement generator using LiteLLM + Instructor.

Generates NIST SP 800-30-compliant risk statements from control gaps
and system context. Uses Instructor for structured output extraction —
the LLM response is validated against the RiskStatement Pydantic model.
"""

from __future__ import annotations

import logging
from typing import Optional

import instructor
import litellm

from evidentia_ai.client import get_default_model, get_instructor_client, get_temperature
from evidentia_ai.risk_statements.prompts import (
    RISK_CONTEXT_TEMPLATE,
    RISK_STATEMENT_SYSTEM_PROMPT,
)
from evidentia_core.models.gap import ControlGap
from evidentia_core.models.risk import RiskStatement

logger = logging.getLogger(__name__)


# Import SystemContext here to avoid circular imports at module level
from evidentia_ai.risk_statements.templates import SystemContext


def _build_risk_context(gap: ControlGap, context: SystemContext) -> str:
    """Build the user prompt with full risk context."""
    components_text = ""
    for comp in context.components:
        components_text += (
            f"- {comp.name} ({comp.type}): {comp.technology}"
        )
        if comp.data_handled:
            components_text += f" — handles: {', '.join(comp.data_handled)}"
        if comp.location:
            components_text += f" — location: {comp.location}"
        components_text += "\n"

    threat_actors_text = "\n".join(f"- {t}" for t in context.threat_actors) or "Not specified"
    existing_controls_text = ", ".join(context.existing_controls) or "None specified"
    cross_fw_text = ", ".join(gap.cross_framework_value) or "None"

    return RISK_CONTEXT_TEMPLATE.format(
        organization=context.organization,
        system_name=context.system_name,
        system_description=context.system_description,
        data_classification=", ".join(context.data_classification),
        hosting=context.hosting,
        risk_tolerance=context.risk_tolerance,
        components_text=components_text.strip(),
        threat_actors_text=threat_actors_text,
        existing_controls_text=existing_controls_text,
        gap_framework=gap.framework,
        gap_control_id=gap.control_id,
        gap_control_title=gap.control_title,
        gap_control_description=gap.gap_description,
        gap_severity=gap.gap_severity,
        gap_description=gap.gap_description,
        gap_implementation_status=gap.implementation_status,
        cross_framework_value=cross_fw_text,
    )


class RiskStatementGenerator:
    """Generates risk statements from control gaps using LLMs.
    
    Usage:
        generator = RiskStatementGenerator(model="gpt-4o")
        
        # Single gap
        risk = generator.generate(gap=my_gap, system_context=my_context)
        
        # Batch
        risks = generator.generate_batch(
            gaps=report.gaps[:10],
            system_context=my_context,
            max_concurrent=5,
        )
    """

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_retries: int = 3,
    ):
        self.model = model or get_default_model()
        self.temperature = temperature if temperature is not None else get_temperature()
        self.max_retries = max_retries
        self.client = get_instructor_client()

    def generate(
        self,
        gap: ControlGap,
        system_context: SystemContext,
    ) -> RiskStatement:
        """Generate a single risk statement for a control gap.
        
        Uses Instructor to extract a validated RiskStatement from the LLM response.
        If the LLM returns invalid JSON, Instructor automatically retries up to
        max_retries times.
        """
        user_prompt = _build_risk_context(gap, system_context)

        logger.info(
            f"Generating risk statement for {gap.framework}:{gap.control_id} "
            f"using model={self.model}"
        )

        risk: RiskStatement = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": RISK_STATEMENT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_model=RiskStatement,
            max_retries=self.max_retries,
            temperature=self.temperature,
        )

        # Enrich with metadata
        risk.source_gap_id = gap.id
        risk.model_used = self.model
        risk.framework_mappings = [
            f"{gap.framework}:{gap.control_id}"
        ] + gap.cross_framework_value

        logger.info(
            f"Generated risk statement: level={risk.risk_level}, "
            f"priority={risk.remediation_priority}"
        )
        return risk

    def generate_batch(
        self,
        gaps: list[ControlGap],
        system_context: SystemContext,
        max_concurrent: int = 5,
        on_progress: Optional[callable] = None,
    ) -> list[RiskStatement]:
        """Generate risk statements for multiple gaps.
        
        Processes sequentially (sync version). For async batch processing,
        use generate_batch_async.
        
        Args:
            gaps: Control gaps to generate risk statements for
            system_context: System context for the organization
            max_concurrent: Not used in sync version (reserved for async)
            on_progress: Optional callback(current, total) for progress reporting
        """
        results: list[RiskStatement] = []
        total = len(gaps)

        for i, gap in enumerate(gaps):
            try:
                risk = self.generate(gap, system_context)
                results.append(risk)
            except Exception as e:
                logger.error(
                    f"Failed to generate risk for {gap.control_id}: {e}"
                )
                # Continue with remaining gaps
                continue
            
            if on_progress:
                on_progress(i + 1, total)

        logger.info(
            f"Batch complete: {len(results)}/{total} risk statements generated"
        )
        return results

    async def generate_async(
        self,
        gap: ControlGap,
        system_context: SystemContext,
    ) -> RiskStatement:
        """Async version of generate() for concurrent batch processing."""
        from evidentia_ai.client import get_async_instructor_client

        client = get_async_instructor_client()
        user_prompt = _build_risk_context(gap, system_context)

        risk: RiskStatement = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": RISK_STATEMENT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_model=RiskStatement,
            max_retries=self.max_retries,
            temperature=self.temperature,
        )

        risk.source_gap_id = gap.id
        risk.model_used = self.model
        risk.framework_mappings = [
            f"{gap.framework}:{gap.control_id}"
        ] + gap.cross_framework_value

        return risk

    async def generate_batch_async(
        self,
        gaps: list[ControlGap],
        system_context: SystemContext,
        max_concurrent: int = 5,
    ) -> list[RiskStatement]:
        """Async batch generation with concurrency control."""
        import asyncio

        semaphore = asyncio.Semaphore(max_concurrent)
        results: list[RiskStatement] = []

        async def _generate_one(gap: ControlGap) -> Optional[RiskStatement]:
            async with semaphore:
                try:
                    return await self.generate_async(gap, system_context)
                except Exception as e:
                    logger.error(f"Failed: {gap.control_id}: {e}")
                    return None

        tasks = [_generate_one(g) for g in gaps]
        raw_results = await asyncio.gather(*tasks)
        results = [r for r in raw_results if r is not None]

        logger.info(f"Async batch: {len(results)}/{len(gaps)} generated")
        return results
```

---


## 8. Phase 2: Evidence Collection Agents

### 8.1 Base Collector Architecture

```python
# evidentia_collectors/base.py
"""Abstract base class for all evidence collectors.

Every collector must implement:
- check_connection(): Verify connectivity, authentication, and permissions
- collect(): Collect evidence artifacts for specified controls
- get_supported_controls(): Declare which controls this collector can provide evidence for

Collectors are async-first. The collection framework manages scheduling,
retries, and health monitoring.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from evidentia_core.models.common import EvidentiaModel, utc_now
from evidentia_core.models.evidence import EvidenceArtifact


class ConnectionStatus(EvidentiaModel):
    """Result of a collector connection health check."""
    collector: str = ""
    display_name: str = ""
    connected: bool = False
    authenticated: bool = False
    permissions_ok: bool = False
    missing_permissions: list[str] = []
    error_message: Optional[str] = None
    last_checked: datetime = utc_now()
    next_check: Optional[datetime] = None
    latency_ms: Optional[float] = None


class CollectionResult(EvidentiaModel):
    """Result of a single collection run."""
    collector: str
    started_at: datetime
    completed_at: datetime
    success: bool
    artifacts_collected: int
    errors: list[str] = []
    warnings: list[str] = []
    artifacts: list[EvidenceArtifact] = []


class BaseCollector(ABC):
    """Abstract base class for evidence collectors.
    
    Subclasses must set:
    - name: Machine-readable collector name (e.g., "aws-config")
    - display_name: Human-readable name (e.g., "AWS Config")
    
    Subclasses must implement:
    - check_connection()
    - collect()
    - get_supported_controls()
    """
    name: str = ""
    display_name: str = ""

    @abstractmethod
    async def check_connection(self) -> ConnectionStatus:
        """Test connectivity, authentication, and required permissions.
        
        Returns a ConnectionStatus with:
        - connected: Can we reach the service?
        - authenticated: Are the credentials valid?
        - permissions_ok: Do we have the required permissions?
        - missing_permissions: List of permissions we need but don't have
        """
        ...

    @abstractmethod
    async def collect(
        self,
        control_ids: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
    ) -> list[EvidenceArtifact]:
        """Collect evidence artifacts.
        
        Args:
            control_ids: Specific controls to collect evidence for.
                         If None, collect evidence for all supported controls.
            frameworks: Filter to controls relevant to these frameworks.
        
        Returns:
            List of EvidenceArtifact objects with control_mappings populated.
        """
        ...

    @abstractmethod
    def get_supported_controls(self) -> list[str]:
        """Return list of NIST 800-53 control IDs this collector can provide evidence for.
        
        Uses NIST 800-53 as the canonical reference. Cross-framework mapping
        is handled by the framework registry.
        """
        ...

    async def run(
        self,
        control_ids: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
    ) -> CollectionResult:
        """Execute a full collection run with error handling and timing.
        
        This is the main entry point called by the scheduler and CLI.
        It wraps collect() with timing, error handling, and result packaging.
        """
        started = utc_now()
        errors: list[str] = []
        warnings: list[str] = []
        artifacts: list[EvidenceArtifact] = []

        try:
            # Check connection first
            status = await self.check_connection()
            if not status.connected:
                return CollectionResult(
                    collector=self.name,
                    started_at=started,
                    completed_at=utc_now(),
                    success=False,
                    artifacts_collected=0,
                    errors=[f"Connection failed: {status.error_message}"],
                )
            
            if not status.permissions_ok:
                warnings.append(
                    f"Missing permissions: {', '.join(status.missing_permissions)}"
                )

            # Collect
            artifacts = await self.collect(control_ids, frameworks)
            
            # Compute content hashes
            for artifact in artifacts:
                artifact.compute_hash()

        except Exception as e:
            errors.append(f"{type(e).__name__}: {str(e)}")

        return CollectionResult(
            collector=self.name,
            started_at=started,
            completed_at=utc_now(),
            success=len(errors) == 0,
            artifacts_collected=len(artifacts),
            errors=errors,
            warnings=warnings,
            artifacts=artifacts,
        )
```

### 8.2 Retry and Rate Limiting

```python
# evidentia_collectors/retry.py
"""Exponential backoff with jitter for collector API calls."""

from __future__ import annotations

import asyncio
import logging
import random
from functools import wraps
from typing import TypeVar, Callable

logger = logging.getLogger(__name__)

T = TypeVar("T")


def async_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retryable_exceptions: tuple = (Exception,),
):
    """Decorator for async functions with exponential backoff and jitter.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay cap in seconds
        exponential_base: Base for exponential calculation
        retryable_exceptions: Tuple of exception types to retry on
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        # Exponential backoff with full jitter
                        delay = min(
                            base_delay * (exponential_base ** attempt),
                            max_delay,
                        )
                        jittered_delay = random.uniform(0, delay)
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): "
                            f"{e}. Retrying in {jittered_delay:.1f}s"
                        )
                        await asyncio.sleep(jittered_delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {e}"
                        )
            raise last_exception
        return wrapper
    return decorator
```

```python
# evidentia_collectors/rate_limit.py
"""Rate limiter for collector API calls."""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Token bucket rate limiter for API calls.
    
    Usage:
        limiter = RateLimiter(calls_per_second=10)
        async with limiter:
            await make_api_call()
    """
    
    def __init__(self, calls_per_second: float = 10.0):
        self._rate = calls_per_second
        self._tokens = calls_per_second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._rate,
                self._tokens + elapsed * self._rate,
            )
            self._last_refill = now

            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def __aexit__(self, *args):
        pass
```

### 8.3 AWS Collector (evidentia_collectors/aws/config.py)

```python
"""AWS Config compliance evidence collector.

Collects compliance rule results from AWS Config and maps them to
NIST 800-53 controls using AWS's built-in control mapping.

Required IAM permissions:
- config:DescribeComplianceByConfigRule
- config:GetComplianceDetailsByConfigRule
- config:DescribeConfigRules
"""

from __future__ import annotations

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from evidentia_collectors.base import BaseCollector, ConnectionStatus
from evidentia_collectors.retry import async_retry
from evidentia_collectors.aws.mappings import AWS_CONFIG_TO_NIST
from evidentia_core.models.common import ControlMapping, utc_now
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

logger = logging.getLogger(__name__)


class AWSConfigCollector(BaseCollector):
    """Collects compliance evidence from AWS Config rules."""
    
    name = "aws-config"
    display_name = "AWS Config"

    def __init__(
        self,
        regions: list[str] | None = None,
        profile_name: str | None = None,
    ):
        self.regions = regions or ["us-east-1"]
        self.profile_name = profile_name

    def _get_client(self, service: str, region: str):
        """Create a boto3 client for the specified service and region."""
        session = boto3.Session(
            profile_name=self.profile_name,
            region_name=region,
        )
        return session.client(service)

    async def check_connection(self) -> ConnectionStatus:
        """Verify AWS credentials and Config permissions."""
        try:
            client = self._get_client("config", self.regions[0])
            # Test API access
            client.describe_compliance_by_config_rule(Limit=1)
            
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=True,
                authenticated=True,
                permissions_ok=True,
                last_checked=utc_now(),
            )
        except NoCredentialsError:
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=False,
                authenticated=False,
                error_message="No AWS credentials found. Set AWS_ACCESS_KEY_ID and "
                              "AWS_SECRET_ACCESS_KEY, or configure an IAM role.",
                last_checked=utc_now(),
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDeniedException":
                return ConnectionStatus(
                    collector=self.name,
                    display_name=self.display_name,
                    connected=True,
                    authenticated=True,
                    permissions_ok=False,
                    missing_permissions=[
                        "config:DescribeComplianceByConfigRule",
                        "config:GetComplianceDetailsByConfigRule",
                    ],
                    error_message=f"Access denied: {e}",
                    last_checked=utc_now(),
                )
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=False,
                error_message=f"AWS API error: {error_code} — {e}",
                last_checked=utc_now(),
            )

    async def collect(
        self,
        control_ids: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
    ) -> list[EvidenceArtifact]:
        """Collect compliance evidence from AWS Config across all configured regions."""
        artifacts: list[EvidenceArtifact] = []

        for region in self.regions:
            logger.info(f"Collecting from AWS Config in {region}")
            try:
                region_artifacts = await self._collect_region(region, control_ids)
                artifacts.extend(region_artifacts)
            except Exception as e:
                logger.error(f"Failed to collect from {region}: {e}")
                continue

        logger.info(
            f"AWS Config collection complete: {len(artifacts)} artifacts "
            f"from {len(self.regions)} regions"
        )
        return artifacts

    async def _collect_region(
        self,
        region: str,
        control_ids: Optional[list[str]] = None,
    ) -> list[EvidenceArtifact]:
        """Collect from a single AWS region."""
        client = self._get_client("config", region)
        artifacts: list[EvidenceArtifact] = []

        # Get all Config rule compliance summaries
        paginator = client.get_paginator("describe_compliance_by_config_rule")
        
        for page in paginator.paginate():
            for rule_result in page.get("ComplianceByConfigRules", []):
                rule_name = rule_result["ConfigRuleName"]
                compliance_type = rule_result["Compliance"]["ComplianceType"]
                
                # Map AWS Config rule to NIST controls
                nist_controls = AWS_CONFIG_TO_NIST.get(rule_name, [])
                
                # Filter by requested control IDs if specified
                if control_ids:
                    nist_controls = [
                        c for c in nist_controls 
                        if c in control_ids
                    ]
                    if not nist_controls:
                        continue
                
                # Get non-compliant resources for failed rules
                non_compliant_resources = []
                if compliance_type in ("NON_COMPLIANT",):
                    try:
                        detail_response = client.get_compliance_details_by_config_rule(
                            ConfigRuleName=rule_name,
                            ComplianceTypes=["NON_COMPLIANT"],
                            Limit=100,
                        )
                        non_compliant_resources = [
                            {
                                "resource_type": r["EvaluationResultIdentifier"][
                                    "EvaluationResultQualifier"
                                ]["ResourceType"],
                                "resource_id": r["EvaluationResultIdentifier"][
                                    "EvaluationResultQualifier"
                                ]["ResourceId"],
                            }
                            for r in detail_response.get("EvaluationResults", [])
                        ]
                    except ClientError:
                        pass
                
                # Build control mappings
                mappings = [
                    ControlMapping(
                        framework="nist-800-53-rev5",
                        control_id=ctrl_id,
                    )
                    for ctrl_id in nist_controls
                ]
                
                # Create evidence artifact
                artifact = EvidenceArtifact(
                    title=f"AWS Config Rule: {rule_name}",
                    description=(
                        f"Compliance status for AWS Config rule '{rule_name}' "
                        f"in region {region}"
                    ),
                    evidence_type=EvidenceType.CONFIGURATION,
                    source_system="aws-config",
                    collected_by=f"evidentia-collectors/{self.name}",
                    content={
                        "rule_name": rule_name,
                        "compliance_type": compliance_type,
                        "region": region,
                        "account_id": self._get_account_id(region),
                        "non_compliant_resources": non_compliant_resources,
                        "non_compliant_count": len(non_compliant_resources),
                    },
                    control_mappings=mappings,
                    metadata={
                        "aws_region": region,
                        "config_rule": rule_name,
                    },
                )
                artifacts.append(artifact)

        return artifacts

    def _get_account_id(self, region: str) -> str:
        """Get the AWS account ID."""
        try:
            sts = self._get_client("sts", region)
            return sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def get_supported_controls(self) -> list[str]:
        """Return all NIST 800-53 controls that AWS Config rules map to."""
        all_controls: set[str] = set()
        for controls in AWS_CONFIG_TO_NIST.values():
            all_controls.update(controls)
        return sorted(all_controls)
```

### 8.4 AWS Config Rule to NIST 800-53 Mapping Table

```python
# evidentia_collectors/aws/mappings.py
"""AWS Config rule name → NIST 800-53 control ID mapping.

Based on AWS's published Config Conformance Pack mappings for
NIST 800-53 Rev 5. See:
https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_5.html
"""

AWS_CONFIG_TO_NIST: dict[str, list[str]] = {
    # Access Control (AC)
    "iam-password-policy": ["AC-2", "IA-5"],
    "iam-user-mfa-enabled": ["AC-2", "IA-2", "IA-2(1)"],
    "mfa-enabled-for-iam-console-access": ["AC-2", "IA-2", "IA-2(1)"],
    "root-account-mfa-enabled": ["AC-2", "AC-6(1)", "IA-2(1)"],
    "iam-root-access-key-check": ["AC-2", "AC-6(1)"],
    "iam-user-unused-credentials-check": ["AC-2", "AC-2(3)"],
    "iam-user-no-policies-check": ["AC-2", "AC-6"],
    "iam-group-has-users-check": ["AC-2"],
    "iam-policy-no-statements-with-admin-access": ["AC-6", "AC-6(1)"],
    "iam-policy-no-statements-with-full-access": ["AC-6"],
    
    # Audit and Accountability (AU)
    "cloud-trail-cloud-watch-logs-enabled": ["AU-6", "AU-6(1)", "AU-12"],
    "cloudtrail-enabled": ["AU-2", "AU-3", "AU-12"],
    "cloudtrail-s3-dataevents-enabled": ["AU-2", "AU-3", "AU-12"],
    "multi-region-cloudtrail-enabled": ["AU-2", "AU-12"],
    "cloudtrail-log-file-validation-enabled": ["AU-9"],
    "cloud-trail-encryption-enabled": ["AU-9"],
    "cloudwatch-alarm-action-check": ["AU-6"],
    "cloudwatch-log-group-encrypted": ["AU-9"],
    "cw-loggroup-retention-period-check": ["AU-11"],
    
    # Configuration Management (CM)
    "ec2-instance-managed-by-systems-manager": ["CM-2", "CM-7", "CM-8"],
    "ec2-managedinstance-patch-compliance-status-check": ["CM-3", "SI-2"],
    "ec2-stopped-instance": ["CM-2"],
    "ec2-instances-in-vpc": ["CM-7", "SC-7"],
    "ec2-ebs-encryption-by-default": ["SC-28", "SC-28(1)"],
    
    # Identification and Authentication (IA)
    "iam-customer-policy-blocked-kms-actions": ["IA-5"],
    "access-keys-rotated": ["IA-5", "IA-5(1)"],
    
    # System and Communications Protection (SC)
    "alb-http-to-https-redirection-check": ["SC-8", "SC-8(1)"],
    "elb-tls-https-listeners-only": ["SC-8", "SC-8(1)"],
    "s3-bucket-ssl-requests-only": ["SC-8", "SC-8(1)"],
    "s3-bucket-server-side-encryption-enabled": ["SC-28", "SC-28(1)"],
    "s3-default-encryption-kms": ["SC-28", "SC-28(1)"],
    "rds-storage-encrypted": ["SC-28", "SC-28(1)"],
    "encrypted-volumes": ["SC-28", "SC-28(1)"],
    "redshift-cluster-configuration-check": ["SC-28"],
    "vpc-flow-logs-enabled": ["AU-2", "AU-12", "SC-7"],
    "vpc-sg-open-only-to-authorized-ports": ["SC-7", "SC-7(5)"],
    "restricted-ssh": ["SC-7", "SC-7(5)"],
    "s3-bucket-public-read-prohibited": ["SC-7", "AC-3"],
    "s3-bucket-public-write-prohibited": ["SC-7", "AC-3"],
    "rds-instance-public-access-check": ["SC-7", "AC-3"],
    
    # System and Information Integrity (SI)
    "guardduty-enabled-centralized": ["SI-4", "SI-4(5)"],
    "securityhub-enabled": ["SI-4"],
    "rds-instance-deletion-protection-enabled": ["SI-12"],
    "s3-bucket-versioning-enabled": ["SI-12"],
    "dynamodb-pitr-enabled": ["SI-12"],
    
    # Contingency Planning (CP)
    "rds-multi-az-support": ["CP-10"],
    "s3-bucket-replication-enabled": ["CP-9"],
    "db-instance-backup-enabled": ["CP-9"],
    "dynamodb-in-backup-plan": ["CP-9"],
    "ebs-in-backup-plan": ["CP-9"],
}
```

### 8.5 GitHub Collector (evidentia_collectors/github/repos.py)

```python
"""GitHub repository compliance evidence collector.

Collects repository security configuration data from GitHub and maps
it to NIST 800-53 controls.

Required GitHub permissions:
- repo:read (for private repos)
- read:org (for organization-level queries)
"""

from __future__ import annotations

import logging
from typing import Optional

from github import Github, GithubException

from evidentia_collectors.base import BaseCollector, ConnectionStatus
from evidentia_core.models.common import ControlMapping, utc_now
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

logger = logging.getLogger(__name__)


class GitHubCollector(BaseCollector):
    """Collects compliance evidence from GitHub repositories."""
    
    name = "github"
    display_name = "GitHub"
    
    # Controls this collector provides evidence for
    SUPPORTED_CONTROLS = [
        "CM-2",   # Baseline Configuration (branch protection)
        "CM-3",   # Configuration Change Control (PR reviews)
        "CM-7",   # Least Functionality (repository visibility)
        "SA-11",  # Developer Testing (CI/CD checks)
        "SA-15",  # Development Process (CODEOWNERS, branch rules)
        "SI-2",   # Flaw Remediation (Dependabot)
        "SI-7",   # Software Integrity (signed commits)
        "SC-28",  # Protection of Information at Rest (secret scanning)
    ]

    def __init__(
        self,
        token: Optional[str] = None,
        organizations: list[str] | None = None,
        base_url: Optional[str] = None,  # For GitHub Enterprise
    ):
        import os
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.organizations = organizations or []
        self.base_url = base_url
        self._client: Optional[Github] = None

    @property
    def client(self) -> Github:
        if self._client is None:
            kwargs = {"login_or_token": self.token}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = Github(**kwargs)
        return self._client

    async def check_connection(self) -> ConnectionStatus:
        try:
            user = self.client.get_user()
            _ = user.login  # Force API call
            
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=True,
                authenticated=True,
                permissions_ok=True,
                last_checked=utc_now(),
            )
        except GithubException as e:
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=True,
                authenticated=False,
                error_message=f"GitHub authentication failed: {e}",
                last_checked=utc_now(),
            )
        except Exception as e:
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=False,
                error_message=str(e),
                last_checked=utc_now(),
            )

    async def collect(
        self,
        control_ids: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
    ) -> list[EvidenceArtifact]:
        artifacts: list[EvidenceArtifact] = []

        for org_name in self.organizations:
            try:
                org = self.client.get_organization(org_name)
                repos = list(org.get_repos(type="all"))
                
                logger.info(f"Scanning {len(repos)} repos in {org_name}")
                
                for repo in repos:
                    try:
                        repo_artifacts = self._collect_repo(repo, org_name)
                        artifacts.extend(repo_artifacts)
                    except GithubException as e:
                        logger.warning(f"Skipping {repo.full_name}: {e}")
                        continue
                        
            except GithubException as e:
                logger.error(f"Failed to access org {org_name}: {e}")

        return artifacts

    def _collect_repo(self, repo, org_name: str) -> list[EvidenceArtifact]:
        """Collect all security evidence from a single repository."""
        artifacts: list[EvidenceArtifact] = []
        
        # 1. Branch protection rules
        try:
            default_branch = repo.get_branch(repo.default_branch)
            protection = default_branch.get_protection()
            
            bp_data = {
                "repo": repo.full_name,
                "branch": repo.default_branch,
                "enforce_admins": protection.enforce_admins.enabled if protection.enforce_admins else False,
                "required_pull_request_reviews": protection.required_pull_request_reviews is not None,
                "required_reviews_count": (
                    protection.required_pull_request_reviews.required_approving_review_count
                    if protection.required_pull_request_reviews else 0
                ),
                "required_status_checks": protection.required_status_checks is not None,
                "require_signed_commits": getattr(protection, 'required_signatures', False),
                "dismiss_stale_reviews": (
                    protection.required_pull_request_reviews.dismiss_stale_reviews
                    if protection.required_pull_request_reviews else False
                ),
            }
            
            artifacts.append(EvidenceArtifact(
                title=f"Branch Protection: {repo.full_name}/{repo.default_branch}",
                evidence_type=EvidenceType.CONFIGURATION,
                source_system="github",
                collected_by=f"evidentia-collectors/{self.name}",
                content=bp_data,
                control_mappings=[
                    ControlMapping(framework="nist-800-53-rev5", control_id="CM-2"),
                    ControlMapping(framework="nist-800-53-rev5", control_id="CM-3"),
                    ControlMapping(framework="nist-800-53-rev5", control_id="SA-15"),
                ],
                metadata={"organization": org_name, "repo": repo.full_name},
            ))
        except GithubException:
            # Branch protection not configured — this IS evidence (of a gap)
            artifacts.append(EvidenceArtifact(
                title=f"Branch Protection Missing: {repo.full_name}",
                evidence_type=EvidenceType.CONFIGURATION,
                source_system="github",
                collected_by=f"evidentia-collectors/{self.name}",
                content={
                    "repo": repo.full_name,
                    "branch": repo.default_branch,
                    "branch_protection_enabled": False,
                },
                control_mappings=[
                    ControlMapping(framework="nist-800-53-rev5", control_id="CM-2"),
                    ControlMapping(framework="nist-800-53-rev5", control_id="CM-3"),
                ],
                metadata={"organization": org_name, "repo": repo.full_name},
            ))

        # 2. Repository visibility and security settings
        repo_security = {
            "repo": repo.full_name,
            "visibility": "private" if repo.private else "public",
            "has_vulnerability_alerts": repo.get_vulnerability_alert(),
            "has_wiki": repo.has_wiki,
            "archived": repo.archived,
            "default_branch": repo.default_branch,
        }
        
        # Check for CODEOWNERS
        try:
            repo.get_contents("CODEOWNERS")
            repo_security["has_codeowners"] = True
        except GithubException:
            try:
                repo.get_contents(".github/CODEOWNERS")
                repo_security["has_codeowners"] = True
            except GithubException:
                repo_security["has_codeowners"] = False

        artifacts.append(EvidenceArtifact(
            title=f"Repository Security Settings: {repo.full_name}",
            evidence_type=EvidenceType.REPOSITORY_METADATA,
            source_system="github",
            collected_by=f"evidentia-collectors/{self.name}",
            content=repo_security,
            control_mappings=[
                ControlMapping(framework="nist-800-53-rev5", control_id="CM-7"),
                ControlMapping(framework="nist-800-53-rev5", control_id="SA-15"),
                ControlMapping(framework="nist-800-53-rev5", control_id="SI-2"),
            ],
            metadata={"organization": org_name, "repo": repo.full_name},
        ))

        return artifacts

    def get_supported_controls(self) -> list[str]:
        return self.SUPPORTED_CONTROLS
```

### 8.6 Okta Collector (evidentia_collectors/okta/iam.py)

```python
"""Okta identity and access management evidence collector.

Collects MFA enrollment, password policies, user lifecycle data,
and access review status from Okta.

Required Okta permissions (read-only API token):
- okta.policies.read
- okta.users.read
- okta.factors.read
- okta.groups.read
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from evidentia_collectors.base import BaseCollector, ConnectionStatus
from evidentia_core.models.common import ControlMapping, utc_now
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

logger = logging.getLogger(__name__)


class OktaCollector(BaseCollector):
    """Collects identity compliance evidence from Okta."""
    
    name = "okta"
    display_name = "Okta"
    
    SUPPORTED_CONTROLS = [
        "AC-2",   # Account Management
        "AC-2(3)", # Disable Accounts
        "AC-7",   # Unsuccessful Logon Attempts
        "IA-2",   # Identification and Authentication
        "IA-2(1)", # Multi-Factor Authentication
        "IA-5",   # Authenticator Management
        "IA-5(1)", # Password-Based Authentication
        "PS-4",   # Personnel Termination
    ]

    def __init__(
        self,
        domain: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        self.domain = domain or os.environ.get("OKTA_DOMAIN", "")
        self.api_token = api_token or os.environ.get("OKTA_API_TOKEN", "")

    def _get_client(self):
        """Create Okta SDK client."""
        from okta.client import Client as OktaClient
        config = {
            "orgUrl": f"https://{self.domain}",
            "token": self.api_token,
        }
        return OktaClient(config)

    async def check_connection(self) -> ConnectionStatus:
        try:
            client = self._get_client()
            users, _, err = await client.list_users({"limit": "1"})
            
            if err:
                return ConnectionStatus(
                    collector=self.name,
                    display_name=self.display_name,
                    connected=True,
                    authenticated=False,
                    error_message=str(err),
                    last_checked=utc_now(),
                )
            
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=True,
                authenticated=True,
                permissions_ok=True,
                last_checked=utc_now(),
            )
        except Exception as e:
            return ConnectionStatus(
                collector=self.name,
                display_name=self.display_name,
                connected=False,
                error_message=str(e),
                last_checked=utc_now(),
            )

    async def collect(
        self,
        control_ids: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
    ) -> list[EvidenceArtifact]:
        artifacts: list[EvidenceArtifact] = []
        client = self._get_client()

        # 1. Password Policy
        try:
            policies, _, _ = await client.list_policies({"type": "PASSWORD"})
            for policy in (policies or []):
                policy_data = {
                    "policy_name": policy.name,
                    "status": policy.status,
                    "min_length": getattr(policy.settings, 'password', {}).get('complexity', {}).get('minLength', 'N/A'),
                    "require_lowercase": True,  # Parse from policy settings
                    "require_uppercase": True,
                    "require_number": True,
                    "require_symbol": True,
                    "max_age_days": getattr(policy.settings, 'password', {}).get('age', {}).get('maxAgeDays', 'N/A'),
                    "min_age_minutes": getattr(policy.settings, 'password', {}).get('age', {}).get('minAgeMinutes', 'N/A'),
                    "history_count": getattr(policy.settings, 'password', {}).get('age', {}).get('historyCount', 'N/A'),
                }
                
                artifacts.append(EvidenceArtifact(
                    title=f"Okta Password Policy: {policy.name}",
                    evidence_type=EvidenceType.CONFIGURATION,
                    source_system="okta",
                    collected_by=f"evidentia-collectors/{self.name}",
                    content=policy_data,
                    control_mappings=[
                        ControlMapping(framework="nist-800-53-rev5", control_id="IA-5"),
                        ControlMapping(framework="nist-800-53-rev5", control_id="IA-5(1)"),
                    ],
                    metadata={"okta_domain": self.domain},
                ))
        except Exception as e:
            logger.error(f"Failed to collect password policies: {e}")

        # 2. MFA Enrollment Policy
        try:
            policies, _, _ = await client.list_policies({"type": "MFA_ENROLL"})
            for policy in (policies or []):
                artifacts.append(EvidenceArtifact(
                    title=f"Okta MFA Policy: {policy.name}",
                    evidence_type=EvidenceType.CONFIGURATION,
                    source_system="okta",
                    collected_by=f"evidentia-collectors/{self.name}",
                    content={
                        "policy_name": policy.name,
                        "status": policy.status,
                        "factors": "parsed from policy settings",
                    },
                    control_mappings=[
                        ControlMapping(framework="nist-800-53-rev5", control_id="IA-2"),
                        ControlMapping(framework="nist-800-53-rev5", control_id="IA-2(1)"),
                    ],
                    metadata={"okta_domain": self.domain},
                ))
        except Exception as e:
            logger.error(f"Failed to collect MFA policies: {e}")

        # 3. Inactive Users (Account Management evidence)
        try:
            from datetime import datetime, timedelta
            cutoff = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            inactive_users, _, _ = await client.list_users({
                "filter": f'lastLogin lt "{cutoff}"',
                "limit": "200",
            })
            
            inactive_count = len(inactive_users) if inactive_users else 0
            artifacts.append(EvidenceArtifact(
                title="Okta Inactive Users (90+ days)",
                evidence_type=EvidenceType.IDENTITY_DATA,
                source_system="okta",
                collected_by=f"evidentia-collectors/{self.name}",
                content={
                    "inactive_user_count": inactive_count,
                    "threshold_days": 90,
                    "checked_at": utc_now().isoformat(),
                },
                control_mappings=[
                    ControlMapping(framework="nist-800-53-rev5", control_id="AC-2"),
                    ControlMapping(framework="nist-800-53-rev5", control_id="AC-2(3)"),
                ],
                metadata={"okta_domain": self.domain},
            ))
        except Exception as e:
            logger.error(f"Failed to collect inactive users: {e}")

        return artifacts

    def get_supported_controls(self) -> list[str]:
        return self.SUPPORTED_CONTROLS
```

### 8.7 Scheduled Collection (evidentia_collectors/scheduled.py)

```python
"""Evidence collection scheduler using APScheduler.

Manages periodic evidence collection based on cron expressions
defined in evidentia.yaml.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from evidentia_collectors.base import BaseCollector, CollectionResult
from evidentia_collectors.registry import get_enabled_collectors
from evidentia_core.models.common import utc_now

logger = logging.getLogger(__name__)


class CollectionScheduler:
    """Manages scheduled evidence collection.
    
    Usage:
        scheduler = CollectionScheduler(
            cron="0 2 * * *",  # Daily at 2am UTC
            collectors=["aws", "github", "okta"],
            output_dir="./evidence",
        )
        await scheduler.start()
    """

    def __init__(
        self,
        cron: str = "0 2 * * *",
        collectors: Optional[list[str]] = None,
        frameworks: Optional[list[str]] = None,
        output_dir: str = "./evidence",
        git_commit: bool = False,
    ):
        self.cron = cron
        self.collector_names = collectors or []
        self.frameworks = frameworks
        self.output_dir = output_dir
        self.git_commit = git_commit
        self._scheduler = AsyncIOScheduler()
        self._last_run: Optional[datetime] = None
        self._last_result: Optional[dict] = None

    async def start(self) -> None:
        """Start the collection scheduler."""
        trigger = CronTrigger.from_crontab(self.cron)
        self._scheduler.add_job(
            self._run_collection,
            trigger=trigger,
            id="evidence_collection",
            name="Evidentia Evidence Collection",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(f"Collection scheduler started: cron='{self.cron}'")

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._scheduler.shutdown()
        logger.info("Collection scheduler stopped")

    async def _run_collection(self) -> None:
        """Execute a collection run for all configured collectors."""
        logger.info("Starting scheduled collection run")
        self._last_run = utc_now()
        
        collectors = get_enabled_collectors(self.collector_names)
        results: dict[str, CollectionResult] = {}

        for collector in collectors:
            try:
                result = await collector.run(frameworks=self.frameworks)
                results[collector.name] = result
                logger.info(
                    f"  {collector.name}: {result.artifacts_collected} artifacts"
                )
            except Exception as e:
                logger.error(f"  {collector.name}: FAILED — {e}")

        self._last_result = {
            name: {
                "success": r.success,
                "artifacts": r.artifacts_collected,
                "errors": r.errors,
            }
            for name, r in results.items()
        }

        # Save evidence bundle
        all_artifacts = []
        for r in results.values():
            all_artifacts.extend(r.artifacts)

        if all_artifacts:
            from evidentia_core.models.evidence import EvidenceBundle
            bundle = EvidenceBundle(
                title=f"Scheduled Collection — {utc_now().strftime('%Y-%m-%d')}",
                assessment_scope="Continuous Monitoring",
                frameworks=self.frameworks or [],
                artifacts=all_artifacts,
                created_by="evidentia-scheduler",
            )
            # Save to output directory
            import json
            from pathlib import Path
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            bundle_file = output_path / f"bundle-{utc_now().strftime('%Y%m%d-%H%M%S')}.json"
            bundle_file.write_text(bundle.model_dump_json(indent=2))
            logger.info(f"Saved evidence bundle: {bundle_file}")

            if self.git_commit:
                import subprocess
                try:
                    subprocess.run(["git", "add", str(bundle_file)], check=True, cwd=self.output_dir)
                    subprocess.run(
                        ["git", "commit", "-m", f"chore(evidence): scheduled collection {utc_now().date()}"],
                        check=True, cwd=self.output_dir,
                    )
                    logger.info("Auto-committed evidence to git")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Git commit failed: {e}")

    @property
    def status(self) -> dict:
        return {
            "running": self._scheduler.running,
            "cron": self.cron,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "last_result": self._last_result,
            "next_run": str(self._scheduler.get_jobs()[0].next_run_time)
            if self._scheduler.get_jobs() else None,
        }
```

---


## 9. Phase 3: Evidence Validator + Integration Outputs

### 9.1 Evidence Validator (evidentia_ai/evidence_validator/validator.py)

```python
"""AI-powered evidence sufficiency validator.

Assesses collected evidence for:
1. Relevance: Does the evidence relate to the claimed control?
2. Sufficiency: Does it demonstrate compliance?
3. Currency: Is it within the acceptable freshness window?
4. Completeness: Are all required elements present?
5. Authenticity signals: Does it appear to be genuine?

Supports text/JSON evidence (via LLM text analysis) and image evidence
(screenshots, PDFs — via LLM vision capabilities).
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import instructor
import litellm

from evidentia_ai.client import get_default_model, get_instructor_client, get_temperature
from evidentia_core.models.common import ControlMapping, utc_now
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceSufficiency

logger = logging.getLogger(__name__)


# Staleness thresholds (days) per framework — overridable in config
DEFAULT_STALENESS_DAYS: dict[str, int] = {
    "soc2-tsc": 90,
    "pci-dss-4": 90,
    "iso27001-2022": 365,
    "nist-800-53-mod": 365,
    "nist-800-53-rev5": 365,
    "nist-800-53-high": 365,
    "cis-controls-v8": 180,
    "cmmc-2-level2": 365,
}


EVIDENCE_VALIDATION_PROMPT = """\
You are an expert compliance auditor validating evidence artifacts for \
regulatory compliance. Assess the following evidence artifact and determine \
whether it is sufficient to demonstrate compliance with the specified control.

Your assessment must evaluate:

1. **Relevance** (0-100): Does this evidence directly relate to the control requirement?
   - 90-100: Directly demonstrates the control
   - 70-89: Strongly related but doesn't cover all aspects
   - 50-69: Partially relevant
   - Below 50: Tangentially or not relevant

2. **Sufficiency** (sufficient/partial/insufficient):
   - sufficient: An auditor would accept this as evidence of compliance
   - partial: Shows some implementation but missing key elements
   - insufficient: Does not demonstrate compliance

3. **Completeness**: What specific elements are present vs. missing?

4. **Authenticity**: Does this appear to be a genuine system export?

Be specific. Reference exact fields, values, and configuration settings \
in your assessment. Do not make vague statements.

## Evidence Artifact
Title: {title}
Source System: {source_system}
Evidence Type: {evidence_type}
Collected At: {collected_at}
Content Format: {content_format}

## Evidence Content
{content}

## Control Being Assessed
Framework: {framework}
Control ID: {control_id}
Control Title: {control_title}

## Assessment
"""


class ValidationResult(EvidentiaModel):
    """Structured output from the evidence validator."""
    sufficiency: EvidenceSufficiency
    sufficiency_rationale: str
    relevance_score: float = Field(ge=0.0, le=100.0)
    missing_elements: list[str]
    authenticity_assessment: str
    recommendations: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


from evidentia_core.models.common import EvidentiaModel
from pydantic import Field


class EvidenceValidator:
    """AI-powered evidence sufficiency validator.
    
    Usage:
        validator = EvidenceValidator(model="gpt-4o")
        
        # Validate a single artifact
        validated = validator.validate(
            artifact=my_artifact,
            control=ControlMapping(framework="soc2-tsc", control_id="CC6.1")
        )
        
        # Validate with image (screenshot/PDF)
        validated = validator.validate_file(
            file_path="screenshot.png",
            control=ControlMapping(framework="soc2-tsc", control_id="CC6.1")
        )
    """

    def __init__(
        self,
        model: Optional[str] = None,
        staleness_overrides: Optional[dict[str, int]] = None,
    ):
        self.model = model or get_default_model()
        self.staleness_days = {**DEFAULT_STALENESS_DAYS, **(staleness_overrides or {})}
        self.client = get_instructor_client()

    def validate(
        self,
        artifact: EvidenceArtifact,
        control: Optional[ControlMapping] = None,
    ) -> EvidenceArtifact:
        """Validate a single evidence artifact.
        
        Performs staleness check (rule-based) and AI quality assessment.
        Mutates and returns the artifact with sufficiency fields populated.
        """
        # If no specific control provided, use the first mapping
        if control is None and artifact.control_mappings:
            control = artifact.control_mappings[0]
        elif control is None:
            artifact.sufficiency = EvidenceSufficiency.UNKNOWN
            artifact.sufficiency_rationale = "No control mapping specified for validation."
            return artifact

        # Step 1: Staleness check (rule-based, no LLM needed)
        framework = control.framework
        max_age = self.staleness_days.get(framework, 365)
        age = (utc_now() - artifact.collected_at).days
        
        if age > max_age:
            artifact.sufficiency = EvidenceSufficiency.STALE
            artifact.sufficiency_rationale = (
                f"Evidence is {age} days old, exceeding the {max_age}-day "
                f"freshness requirement for {framework}."
            )
            artifact.validated_at = utc_now()
            artifact.validated_by = "evidentia-ai/staleness-check"
            return artifact

        # Step 2: AI quality assessment
        import json
        content_str = ""
        if artifact.content is not None:
            if isinstance(artifact.content, (dict, list)):
                content_str = json.dumps(artifact.content, indent=2, default=str)
            else:
                content_str = str(artifact.content)
        elif artifact.file_path:
            content_str = f"[File: {artifact.file_path}]"
        
        # Truncate very large content
        if len(content_str) > 8000:
            content_str = content_str[:8000] + "\n... [truncated]"

        prompt = EVIDENCE_VALIDATION_PROMPT.format(
            title=artifact.title,
            source_system=artifact.source_system,
            evidence_type=artifact.evidence_type,
            collected_at=artifact.collected_at.isoformat(),
            content_format=artifact.content_format,
            content=content_str,
            framework=control.framework,
            control_id=control.control_id,
            control_title=control.control_title or "",
        )

        try:
            result: ValidationResult = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_model=ValidationResult,
                max_retries=2,
                temperature=0.1,
            )

            artifact.sufficiency = result.sufficiency
            artifact.sufficiency_rationale = result.sufficiency_rationale
            artifact.missing_elements = result.missing_elements
            artifact.validator_confidence = result.confidence
            artifact.validated_at = utc_now()
            artifact.validated_by = f"evidentia-ai/{self.model}"

        except Exception as e:
            logger.error(f"Validation failed for {artifact.id}: {e}")
            artifact.sufficiency = EvidenceSufficiency.UNKNOWN
            artifact.sufficiency_rationale = f"Validation failed: {e}"

        return artifact

    def validate_file(
        self,
        file_path: str | Path,
        control: ControlMapping,
        model: Optional[str] = None,
    ) -> EvidenceArtifact:
        """Validate a file (screenshot, PDF, document) as evidence.
        
        Uses LLM vision capabilities for image files.
        """
        path = Path(file_path)
        vision_model = model or self.model

        # Determine content type
        suffix = path.suffix.lower()
        is_image = suffix in (".png", ".jpg", ".jpeg", ".gif", ".webp")
        is_pdf = suffix == ".pdf"

        if is_image:
            return self._validate_image(path, control, vision_model)
        elif is_pdf:
            return self._validate_pdf(path, control, vision_model)
        else:
            # Text-based file
            content = path.read_text(encoding="utf-8", errors="replace")
            artifact = EvidenceArtifact(
                title=f"File: {path.name}",
                evidence_type=EvidenceType.POLICY_DOCUMENT,
                source_system="manual-upload",
                collected_by="manual",
                content=content[:10000],
                content_format="text",
                file_path=str(path),
                control_mappings=[control],
            )
            return self.validate(artifact, control)

    def _validate_image(
        self,
        path: Path,
        control: ControlMapping,
        model: str,
    ) -> EvidenceArtifact:
        """Validate an image file using LLM vision."""
        from evidentia_core.models.evidence import EvidenceType
        
        # Read and encode image
        image_data = base64.b64encode(path.read_bytes()).decode("utf-8")
        mime_type = "image/png" if path.suffix == ".png" else "image/jpeg"

        prompt = (
            f"Analyze this screenshot as compliance evidence for "
            f"{control.framework} control {control.control_id} "
            f"({control.control_title or 'N/A'}). "
            f"Assess relevance, sufficiency, and authenticity."
        )

        try:
            result: ValidationResult = self.client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:{mime_type};base64,{image_data}"
                                },
                            },
                        ],
                    }
                ],
                response_model=ValidationResult,
                max_retries=2,
            )
        except Exception as e:
            result = ValidationResult(
                sufficiency=EvidenceSufficiency.UNKNOWN,
                sufficiency_rationale=f"Vision validation failed: {e}",
                relevance_score=0.0,
                missing_elements=[],
                authenticity_assessment="Unable to assess",
                recommendations=[],
                confidence=0.0,
            )

        artifact = EvidenceArtifact(
            title=f"Screenshot: {path.name}",
            evidence_type=EvidenceType.SCREENSHOT,
            source_system="manual-upload",
            collected_by="manual",
            content_format="image",
            file_path=str(path),
            control_mappings=[control],
            sufficiency=result.sufficiency,
            sufficiency_rationale=result.sufficiency_rationale,
            missing_elements=result.missing_elements,
            validator_confidence=result.confidence,
            validated_at=utc_now(),
            validated_by=f"evidentia-ai/{model}",
        )
        artifact.compute_hash()
        return artifact

    def _validate_pdf(
        self,
        path: Path,
        control: ControlMapping,
        model: str,
    ) -> EvidenceArtifact:
        """Validate a PDF file — extract text and validate."""
        # For PDF validation, extract text first, then validate as text
        # In a production implementation, use pymupdf or pdfplumber
        from evidentia_core.models.evidence import EvidenceType
        
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(str(path))
            text = ""
            for page in doc:
                text += page.get_text()
            doc.close()
        except ImportError:
            text = "[PDF text extraction not available — install pymupdf]"

        artifact = EvidenceArtifact(
            title=f"PDF Document: {path.name}",
            evidence_type=EvidenceType.POLICY_DOCUMENT,
            source_system="manual-upload",
            collected_by="manual",
            content=text[:10000],
            content_format="text",
            file_path=str(path),
            control_mappings=[control],
        )
        return self.validate(artifact, control)
```

### 9.2 Jira Integration (evidentia_integrations/jira/client.py)

```python
"""Jira integration for pushing gap reports as issues.

Creates Jira issues from gap analysis results with:
- Structured descriptions with remediation guidance
- Priority mapping from gap severity
- Labels for filtering and tracking
- Idempotency (won't create duplicate issues)
- Dry-run mode for preview
"""

from __future__ import annotations

import logging
from typing import Optional

from jira import JIRA, JIRAError

from evidentia_core.models.gap import ControlGap, GapAnalysisReport, GapSeverity

logger = logging.getLogger(__name__)

# Gap severity → Jira priority mapping
SEVERITY_TO_JIRA_PRIORITY: dict[GapSeverity, str] = {
    GapSeverity.CRITICAL: "Highest",
    GapSeverity.HIGH: "High",
    GapSeverity.MEDIUM: "Medium",
    GapSeverity.LOW: "Low",
    GapSeverity.INFORMATIONAL: "Lowest",
}


def format_gap_description(gap: ControlGap) -> str:
    """Format a gap as Jira wiki markup description."""
    cross_fw = ", ".join(gap.cross_framework_value) if gap.cross_framework_value else "None"
    
    return f"""\
h3. Control Requirement

*Framework:* {gap.framework}
*Control ID:* {gap.control_id}
*Control Title:* {gap.control_title}
*Control Family:* {gap.control_family or 'N/A'}

{gap.control_description}

h3. Gap Description

*Status:* {gap.implementation_status}
*Severity:* {gap.gap_severity}

{gap.gap_description}

h3. Cross-Framework Value

Implementing this control also satisfies requirements in: {cross_fw}

h3. Remediation Guidance

{gap.remediation_guidance}

h3. Estimated Effort

{gap.implementation_effort}

h3. Metadata

*Gap ID:* {{monospace:{gap.id}}}
*Priority Score:* {gap.priority_score}
*Generated by:* Evidentia v0.1.0 on {gap.created_at.strftime('%Y-%m-%d')}
"""


class JiraIntegration:
    """Push gap analysis results to Jira as issues.
    
    Usage:
        jira = JiraIntegration(
            server="https://my-company.atlassian.net",
            email="grc@my-company.com",
            token="...",
            project_key="SEC",
        )
        
        results = jira.create_gap_issues(
            report=gap_report,
            only_severity=["critical", "high"],
            dry_run=True,  # Preview first
        )
    """

    def __init__(
        self,
        server: str,
        email: Optional[str] = None,
        token: Optional[str] = None,
        project_key: str = "",
        issue_type: str = "Task",
        label_prefix: str = "evidentia",
    ):
        auth_kwargs = {}
        if email and token:
            auth_kwargs = {"basic_auth": (email, token)}
        elif token:
            auth_kwargs = {"token_auth": token}
        
        self.client = JIRA(server=server, **auth_kwargs)
        self.project_key = project_key
        self.issue_type = issue_type
        self.label_prefix = label_prefix

    def create_gap_issues(
        self,
        report: GapAnalysisReport,
        only_severity: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> list[dict]:
        """Create one Jira issue per gap.
        
        Args:
            report: The gap analysis report
            only_severity: Filter to these severities (e.g., ["critical", "high"])
            dry_run: If True, return issue previews without creating them
        
        Returns:
            List of {gap_id, jira_key, status, summary} dicts
        """
        results: list[dict] = []

        for gap in report.gaps:
            # Filter by severity
            if only_severity and gap.gap_severity not in only_severity:
                continue

            # Idempotency: check if issue already exists
            if gap.jira_issue_key:
                results.append({
                    "gap_id": gap.id,
                    "jira_key": gap.jira_issue_key,
                    "status": "already_exists",
                    "summary": f"[existing] {gap.control_id}",
                })
                continue

            # Check for existing issue by label search
            existing = self._find_existing_issue(gap)
            if existing:
                gap.jira_issue_key = existing
                results.append({
                    "gap_id": gap.id,
                    "jira_key": existing,
                    "status": "already_exists",
                    "summary": f"[found existing] {gap.control_id}",
                })
                continue

            # Build issue data
            summary = (
                f"[Evidentia] {gap.framework} Gap: "
                f"{gap.control_id} — {gap.control_title}"
            )
            if len(summary) > 255:
                summary = summary[:252] + "..."

            description = format_gap_description(gap)

            labels = [
                self.label_prefix,
                "grc-gap",
                gap.framework,
                gap.gap_severity,
            ]

            priority = SEVERITY_TO_JIRA_PRIORITY.get(
                gap.gap_severity, "Medium"
            )

            issue_data = {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.issue_type},
                "labels": labels,
                "priority": {"name": priority},
            }

            if dry_run:
                results.append({
                    "gap_id": gap.id,
                    "jira_key": "[DRY RUN]",
                    "status": "would_create",
                    "summary": summary,
                    "issue_data": issue_data,
                })
            else:
                try:
                    issue = self.client.create_issue(fields=issue_data)
                    gap.jira_issue_key = issue.key
                    results.append({
                        "gap_id": gap.id,
                        "jira_key": issue.key,
                        "status": "created",
                        "summary": summary,
                    })
                    logger.info(f"Created Jira issue {issue.key} for {gap.control_id}")
                except JIRAError as e:
                    results.append({
                        "gap_id": gap.id,
                        "jira_key": None,
                        "status": "failed",
                        "summary": summary,
                        "error": str(e),
                    })
                    logger.error(f"Failed to create issue for {gap.control_id}: {e}")

        created = sum(1 for r in results if r["status"] == "created")
        skipped = sum(1 for r in results if r["status"] == "already_exists")
        logger.info(
            f"Jira push complete: {created} created, {skipped} already existed"
        )
        return results

    def _find_existing_issue(self, gap: ControlGap) -> Optional[str]:
        """Search for an existing issue for this gap using labels."""
        jql = (
            f'project = "{self.project_key}" AND '
            f'labels = "{self.label_prefix}" AND '
            f'summary ~ "{gap.control_id}"'
        )
        try:
            issues = self.client.search_issues(jql, maxResults=1)
            if issues:
                return issues[0].key
        except JIRAError:
            pass
        return None

    def update_gap_status_from_jira(
        self, gap: ControlGap
    ) -> Optional[str]:
        """Sync Jira issue status back to gap.
        
        Returns the Jira issue status string, or None if not found.
        """
        if not gap.jira_issue_key:
            return None
        try:
            issue = self.client.issue(gap.jira_issue_key)
            return str(issue.fields.status)
        except JIRAError:
            return None
```

### 9.3 ServiceNow Integration (evidentia_integrations/servicenow/client.py)

```python
"""ServiceNow integration for pushing gap reports as records.

Creates ServiceNow records (incidents, tasks, or compliance tasks)
from gap analysis results.
"""

from __future__ import annotations

import logging
from typing import Optional

from evidentia_core.models.gap import ControlGap, GapAnalysisReport, GapSeverity

logger = logging.getLogger(__name__)

# Gap severity → ServiceNow impact/urgency mapping
SEVERITY_TO_SNOW_IMPACT: dict[GapSeverity, str] = {
    GapSeverity.CRITICAL: "1",  # High
    GapSeverity.HIGH: "2",      # Medium
    GapSeverity.MEDIUM: "2",    # Medium
    GapSeverity.LOW: "3",       # Low
    GapSeverity.INFORMATIONAL: "3",
}


class ServiceNowIntegration:
    """Push gap analysis results to ServiceNow.
    
    Supports creating records in any table:
    - incident (default)
    - sc_task (service catalog tasks)
    - sn_risk_risk (risk management)
    - sn_compliance_task (compliance tasks — GRC module)
    """

    def __init__(
        self,
        instance_url: str,
        username: str,
        password: str,
        table: str = "incident",
        assignment_group: Optional[str] = None,
    ):
        import requests
        self.instance_url = instance_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self.table = table
        self.assignment_group = assignment_group

    def create_gap_records(
        self,
        report: GapAnalysisReport,
        only_severity: Optional[list[str]] = None,
        dry_run: bool = False,
    ) -> list[dict]:
        """Create ServiceNow records for each gap."""
        results: list[dict] = []

        for gap in report.gaps:
            if only_severity and gap.gap_severity not in only_severity:
                continue

            if gap.servicenow_ticket_id:
                results.append({
                    "gap_id": gap.id,
                    "sys_id": gap.servicenow_ticket_id,
                    "status": "already_exists",
                })
                continue

            record_data = {
                "short_description": (
                    f"[Evidentia] {gap.framework} Gap: "
                    f"{gap.control_id} — {gap.control_title}"
                )[:160],
                "description": self._format_description(gap),
                "impact": SEVERITY_TO_SNOW_IMPACT.get(gap.gap_severity, "2"),
                "urgency": SEVERITY_TO_SNOW_IMPACT.get(gap.gap_severity, "2"),
                "category": "Compliance",
                "subcategory": gap.framework,
            }

            if self.assignment_group:
                record_data["assignment_group"] = self.assignment_group

            if dry_run:
                results.append({
                    "gap_id": gap.id,
                    "sys_id": "[DRY RUN]",
                    "status": "would_create",
                    "record_data": record_data,
                })
            else:
                try:
                    url = f"{self.instance_url}/api/now/table/{self.table}"
                    response = self.session.post(url, json=record_data)
                    response.raise_for_status()
                    sys_id = response.json()["result"]["sys_id"]
                    
                    gap.servicenow_ticket_id = sys_id
                    results.append({
                        "gap_id": gap.id,
                        "sys_id": sys_id,
                        "status": "created",
                    })
                    logger.info(f"Created ServiceNow record {sys_id} for {gap.control_id}")
                except Exception as e:
                    results.append({
                        "gap_id": gap.id,
                        "sys_id": None,
                        "status": "failed",
                        "error": str(e),
                    })

        return results

    @staticmethod
    def _format_description(gap: ControlGap) -> str:
        """Format gap as ServiceNow description (plain text)."""
        cross_fw = ", ".join(gap.cross_framework_value) if gap.cross_framework_value else "None"
        return f"""\
CONTROL REQUIREMENT
Framework: {gap.framework}
Control ID: {gap.control_id}
Control Title: {gap.control_title}

{gap.control_description}

GAP DESCRIPTION
Status: {gap.implementation_status}
Severity: {gap.gap_severity}

{gap.gap_description}

CROSS-FRAMEWORK VALUE
{cross_fw}

REMEDIATION GUIDANCE
{gap.remediation_guidance}

ESTIMATED EFFORT: {gap.implementation_effort}

Generated by Evidentia v0.1.0 | Gap ID: {gap.id}
"""
```

---


## 10. REST API Design (FastAPI)

Base URL: `http://localhost:8743/api/v1`

The REST API is a thin wrapper around the Python library. Every endpoint delegates to library functions and returns Pydantic models serialized as JSON.

### 10.1 API Application Factory (evidentia/api/main.py)

```python
"""FastAPI application factory for Evidentia REST API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from evidentia.api.routers import catalogs, collectors, evidence, gaps, health, risks
from evidentia.api.middleware import RequestIdMiddleware, TimingMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup: pre-load catalog registry
    from evidentia_core.catalogs.registry import FrameworkRegistry
    registry = FrameworkRegistry.get_instance()
    _ = registry.crosswalk  # Trigger lazy loading
    yield
    # Shutdown: nothing to clean up for file-based storage


def create_app() -> FastAPI:
    app = FastAPI(
        title="Evidentia API",
        description="Open-source GRC tool: gap analysis, risk statements, evidence collection",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(TimingMiddleware)

    # Routers
    app.include_router(health.router)
    app.include_router(gaps.router, prefix="/api/v1")
    app.include_router(risks.router, prefix="/api/v1")
    app.include_router(evidence.router, prefix="/api/v1")
    app.include_router(collectors.router, prefix="/api/v1")
    app.include_router(catalogs.router, prefix="/api/v1")

    return app
```

### 10.2 Endpoint Specifications

#### Health & Status

```
GET /health
```

Response `200 OK`:
```json
{
  "status": "ok",
  "version": "0.1.0",
  "timestamp": "2026-04-05T19:22:00Z",
  "catalogs_loaded": 9,
  "storage_backend": "file",
  "collectors": [
    {
      "name": "aws-config",
      "display_name": "AWS Config",
      "connected": true,
      "last_collected": "2026-04-05T02:00:00Z"
    },
    {
      "name": "github",
      "display_name": "GitHub",
      "connected": true,
      "last_collected": "2026-04-05T02:00:00Z"
    },
    {
      "name": "okta",
      "display_name": "Okta",
      "connected": false,
      "last_collected": null
    }
  ]
}
```

#### Gap Analysis

```
POST /api/v1/gaps/analyze
Content-Type: application/json
```

Request body:
```json
{
  "inventory": {
    "organization": "Acme Corp",
    "controls": [
      {
        "id": "AC-2",
        "title": "Account Management",
        "status": "implemented",
        "implementation_notes": "Managed via Okta",
        "responsible_roles": ["IT Security"],
        "owner": "ciso@acme.com"
      },
      {
        "id": "AC-3",
        "title": "Access Enforcement",
        "status": "partially_implemented",
        "implementation_notes": "RBAC in app layer, but no network segmentation"
      }
    ]
  },
  "frameworks": ["nist-800-53-mod", "soc2-tsc"],
  "options": {
    "show_efficiency": true,
    "min_efficiency_frameworks": 3
  }
}
```

Alternative — reference an inventory file by URL:
```json
{
  "inventory_url": "https://raw.githubusercontent.com/acme/compliance/main/controls.yaml",
  "frameworks": ["nist-800-53-mod"],
  "options": {}
}
```

Response `200 OK`:
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "organization": "Acme Corp",
  "frameworks_analyzed": ["nist-800-53-mod", "soc2-tsc"],
  "analyzed_at": "2026-04-05T19:22:00Z",
  "total_controls_required": 383,
  "total_controls_in_inventory": 2,
  "total_gaps": 381,
  "critical_gaps": 320,
  "high_gaps": 1,
  "medium_gaps": 0,
  "low_gaps": 60,
  "informational_gaps": 0,
  "coverage_percentage": 0.5,
  "gaps": [
    {
      "id": "a1b2c3d4-...",
      "framework": "nist-800-53-mod",
      "control_id": "AC-1",
      "control_title": "Policy and Procedures",
      "control_description": "...",
      "gap_severity": "critical",
      "implementation_status": "missing",
      "gap_description": "Control AC-1 is required by nist-800-53-mod but is not present...",
      "cross_framework_value": ["soc2-tsc:CC1.1", "iso27001-2022:A.5.1"],
      "remediation_guidance": "Implement AC-1...",
      "implementation_effort": "medium",
      "priority_score": 4.8,
      "jira_issue_key": null,
      "servicenow_ticket_id": null
    }
  ],
  "efficiency_opportunities": [
    {
      "control_id": "AC-2",
      "control_title": "Account Management",
      "frameworks_satisfied": ["nist-800-53-mod:AC-2", "soc2-tsc:CC6.1", "iso27001-2022:A.9.2.1"],
      "framework_count": 3,
      "total_gaps_closed": 3,
      "implementation_effort": "medium",
      "value_score": 1.5
    }
  ],
  "prioritized_roadmap": ["a1b2c3d4-...", "e5f6g7h8-..."]
}
```

```
GET /api/v1/gaps/reports
```

Response `200 OK`:
```json
{
  "reports": [
    {
      "id": "f47ac10b-...",
      "organization": "Acme Corp",
      "frameworks_analyzed": ["nist-800-53-mod", "soc2-tsc"],
      "analyzed_at": "2026-04-05T19:22:00Z",
      "total_gaps": 381,
      "coverage_percentage": 0.5
    }
  ]
}
```

```
GET /api/v1/gaps/reports/{report_id}
```

Response: Full `GapAnalysisReport` JSON.

```
POST /api/v1/gaps/reports/{report_id}/push-to-jira
Content-Type: application/json
```

Request:
```json
{
  "project_key": "SEC",
  "only_severity": ["critical", "high"],
  "issue_type": "Task",
  "dry_run": false
}
```

Response `200 OK`:
```json
{
  "results": [
    {"gap_id": "a1b2c3d4-...", "jira_key": "SEC-123", "status": "created"},
    {"gap_id": "e5f6g7h8-...", "jira_key": "SEC-124", "status": "created"}
  ],
  "created": 2,
  "already_existed": 0,
  "failed": 0
}
```

```
POST /api/v1/gaps/reports/{report_id}/push-to-servicenow
Content-Type: application/json
```

Request:
```json
{
  "table": "sn_compliance_task",
  "assignment_group": "GRC Team",
  "only_severity": ["critical", "high"],
  "dry_run": false
}
```

#### Risk Statements

```
POST /api/v1/risks/generate
Content-Type: application/json
```

Request:
```json
{
  "system_context": {
    "organization": "Acme Corp",
    "system_name": "Customer Data Platform",
    "system_description": "Cloud-native data platform on AWS...",
    "data_classification": ["PII", "PCI-DSS-CDE"],
    "hosting": "AWS (us-east-1, eu-west-1)",
    "components": [
      {"name": "Web Application", "type": "web_app", "technology": "React + Node.js"},
      {"name": "Data Warehouse", "type": "database", "technology": "Amazon Redshift"}
    ],
    "threat_actors": ["External threat actors (financial)", "Insider threat"],
    "existing_controls": ["AC-2", "IA-2", "SC-8"],
    "frameworks": ["nist-800-53-mod", "pci-dss-4"],
    "risk_tolerance": "medium"
  },
  "gaps": ["a1b2c3d4-..."],
  "model": "gpt-4o",
  "options": {
    "max_concurrent": 5
  }
}
```

Alternative — reference a gap report:
```json
{
  "system_context": {...},
  "gap_report_id": "f47ac10b-...",
  "model": "gpt-4o"
}
```

Response `200 OK`:
```json
{
  "risks": [
    {
      "id": "r1s2k3-...",
      "asset": "Customer Data Platform — Amazon Redshift data warehouse",
      "threat_source": "External threat actor (financial motivation)",
      "threat_event": "Exfiltrate customer PII...",
      "vulnerability": "No access control policy (AC-1) governing...",
      "likelihood": "high",
      "likelihood_rationale": "...",
      "impact": "very_high",
      "impact_rationale": "...",
      "risk_level": "critical",
      "risk_description": "...",
      "recommended_controls": ["AC-1", "AC-1(1)", "PL-1"],
      "remediation_priority": 1,
      "remediation_steps": ["Draft access control policy...", "..."],
      "generated_by": "evidentia-ai",
      "model_used": "gpt-4o"
    }
  ],
  "total_generated": 1,
  "model_used": "gpt-4o"
}
```

```
GET /api/v1/risks/{risk_id}
```

Response: Single `RiskStatement` JSON.

```
PUT /api/v1/risks/{risk_id}/review
Content-Type: application/json
```

Request:
```json
{
  "reviewer_email": "ciso@acme.com",
  "accepted": true,
  "treatment": "mitigate",
  "treatment_rationale": "Will implement AC-1 as part of Q2 roadmap"
}
```

#### Evidence Collection

```
GET /api/v1/collectors
```

Response `200 OK`:
```json
{
  "collectors": [
    {
      "name": "aws-config",
      "display_name": "AWS Config",
      "connected": true,
      "authenticated": true,
      "permissions_ok": true,
      "last_checked": "2026-04-05T19:00:00Z",
      "supported_controls": ["AC-2", "AC-6", "AU-2", "AU-3", "..."]
    },
    {
      "name": "github",
      "display_name": "GitHub",
      "connected": true,
      "authenticated": true,
      "permissions_ok": true,
      "supported_controls": ["CM-2", "CM-3", "CM-7", "SA-11", "..."]
    }
  ]
}
```

```
POST /api/v1/collectors/{collector_name}/check
```

Response `200 OK`: `ConnectionStatus` JSON.

```
POST /api/v1/evidence/collect
Content-Type: application/json
```

Request:
```json
{
  "collectors": ["aws", "github"],
  "frameworks": ["soc2-tsc"],
  "control_ids": null,
  "dry_run": false
}
```

Response `202 Accepted`:
```json
{
  "job_id": "j1o2b3-...",
  "status": "running",
  "collectors": ["aws-config", "github"],
  "started_at": "2026-04-05T19:22:00Z"
}
```

```
GET /api/v1/evidence/jobs/{job_id}
```

Response `200 OK`:
```json
{
  "job_id": "j1o2b3-...",
  "status": "completed",
  "started_at": "2026-04-05T19:22:00Z",
  "completed_at": "2026-04-05T19:22:45Z",
  "results": {
    "aws-config": {"success": true, "artifacts_collected": 52, "errors": []},
    "github": {"success": true, "artifacts_collected": 24, "errors": []}
  },
  "total_artifacts": 76,
  "bundle_id": "b1u2n3-..."
}
```

```
GET /api/v1/evidence/bundles
GET /api/v1/evidence/bundles/{bundle_id}
```

#### Evidence Validation

```
POST /api/v1/evidence/validate
Content-Type: multipart/form-data
```

Fields:
- `file`: The evidence file (screenshot, PDF, JSON, text)
- `control_id`: Control ID (e.g., "CC6.1")
- `framework`: Framework ID (e.g., "soc2-tsc")
- `model`: (optional) LLM model to use for validation

Response `200 OK`:
```json
{
  "artifact": {
    "id": "e1v2-...",
    "title": "Screenshot: mfa-settings.png",
    "evidence_type": "screenshot",
    "sufficiency": "partial",
    "sufficiency_rationale": "The screenshot shows MFA is enabled for admin accounts, but does not demonstrate MFA enforcement for all user accounts as required by CC6.1.",
    "missing_elements": [
      "Evidence of MFA enforcement for all user types (not just admins)",
      "MFA enrollment completion rate",
      "Policy document requiring MFA for all access"
    ],
    "validator_confidence": 0.85,
    "validated_at": "2026-04-05T19:22:00Z",
    "validated_by": "evidentia-ai/gpt-4o"
  }
}
```

#### Catalogs

```
GET /api/v1/catalogs
```

Response `200 OK`:
```json
{
  "catalogs": [
    {"id": "nist-800-53-rev5", "name": "NIST SP 800-53 Rev 5 (Full)", "controls": "~1189"},
    {"id": "nist-800-53-mod", "name": "NIST SP 800-53 Rev 5 Moderate", "controls": "~323"},
    {"id": "soc2-tsc", "name": "SOC 2 Trust Services Criteria 2017", "controls": "~60"}
  ]
}
```

```
GET /api/v1/catalogs/{framework_id}/controls
GET /api/v1/catalogs/{framework_id}/controls/{control_id}
```

```
GET /api/v1/catalogs/crosswalk?source=nist-800-53-rev5&target=soc2-tsc&control=AC-2
```

Response `200 OK`:
```json
{
  "source_framework": "nist-800-53-rev5",
  "source_control_id": "AC-2",
  "target_framework": "soc2-tsc",
  "mappings": [
    {
      "target_control_id": "CC6.1",
      "target_control_title": "Logical and Physical Access Controls...",
      "relationship": "related",
      "notes": "AC-2 covers user account lifecycle..."
    },
    {
      "target_control_id": "CC6.2",
      "target_control_title": "User Authentication...",
      "relationship": "related"
    }
  ]
}
```

### 10.3 Error Responses

All errors follow a consistent structure:

```json
{
  "error": {
    "code": "INVENTORY_PARSE_ERROR",
    "message": "Failed to parse inventory file: CSV has no 'control_id' column",
    "details": {
      "file": "controls.csv",
      "found_headers": ["ctrl", "name", "done"]
    },
    "request_id": "req-abc123",
    "timestamp": "2026-04-05T19:22:00Z"
  }
}
```

Error codes:

| Code | HTTP Status | Description |
|---|---|---|
| `INVENTORY_PARSE_ERROR` | 400 | Failed to parse inventory input |
| `FRAMEWORK_NOT_FOUND` | 404 | Requested framework ID not recognized |
| `CONTROL_NOT_FOUND` | 404 | Control ID not found in framework catalog |
| `REPORT_NOT_FOUND` | 404 | Gap report or risk statement not found |
| `COLLECTOR_NOT_CONFIGURED` | 400 | Collector not enabled or configured |
| `COLLECTOR_CONNECTION_FAILED` | 502 | Collector failed to connect to upstream service |
| `LLM_GENERATION_FAILED` | 502 | LLM API call failed after retries |
| `JIRA_PUSH_FAILED` | 502 | Failed to create Jira issues |
| `SERVICENOW_PUSH_FAILED` | 502 | Failed to create ServiceNow records |
| `VALIDATION_ERROR` | 422 | Pydantic validation error (malformed request body) |
| `AUTH_REQUIRED` | 401 | API key required but not provided |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

### 10.4 Authentication (Optional)

When `api.require_auth: true` in config:

```
GET /api/v1/gaps/reports
Authorization: Bearer <EVIDENTIA_API_KEY>
```

Missing or invalid key returns `401`:
```json
{
  "error": {
    "code": "AUTH_REQUIRED",
    "message": "Valid API key required. Set EVIDENTIA_API_KEY and pass via Authorization header."
  }
}
```

---


## 11. CLI Command Reference

All CLI commands use Typer with Rich for styled terminal output. The CLI is a thin wrapper around the Python library.

```bash
# ── Installation ────────────────────────────────────────────────────
pip install evidentia            # Full install (all packages)
pip install evidentia-core       # Core only (gap analysis, no AI)
docker run -it ghcr.io/evidentia/evidentia:latest

# ── Project Initialization ──────────────────────────────────────────
evidentia init
# Creates:
#   evidentia.yaml       — config file with defaults
#   my-controls.yaml         — template control inventory
#   system-context.yaml      — template system context (for risk generation)
#   .evidentia/          — local storage directory

evidentia init --frameworks nist-800-53-mod,soc2-tsc
# Pre-populates config with specified frameworks

# ── Catalog Exploration ─────────────────────────────────────────────
evidentia catalog list
# ┌──────────────────┬──────────────────────────────────────┬────────┐
# │ Framework ID     │ Name                                 │ Ctrls  │
# ├──────────────────┼──────────────────────────────────────┼────────┤
# │ nist-800-53-mod  │ NIST SP 800-53 Rev 5 Moderate       │ ~323   │
# │ soc2-tsc         │ SOC 2 Trust Services Criteria 2017   │ ~60    │
# │ iso27001-2022    │ ISO/IEC 27001:2022 Annex A           │ 93     │
# │ ...              │ ...                                  │ ...    │
# └──────────────────┴──────────────────────────────────────┴────────┘

evidentia catalog show nist-800-53-mod
# Lists all controls in the framework with ID, title, and family

evidentia catalog show nist-800-53-mod --control AC-2
# Shows full control detail: description, enhancements, assessment objectives

evidentia catalog crosswalk \
  --source nist-800-53-mod \
  --target soc2-tsc \
  --control AC-2
# Shows:
# AC-2 (Account Management) maps to:
#   → CC6.1 (Logical and Physical Access Controls) [related]
#   → CC6.2 (User Authentication) [related]
#   → CC6.3 (Access Removal) [related]

# ── Gap Analysis ────────────────────────────────────────────────────
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-mod,soc2-tsc \
  --output report.json \
  --format json

evidentia gap analyze \
  --inventory controls.csv \
  --frameworks nist-800-53-mod \
  --format markdown \
  --output gap-report.md \
  --show-efficiency-opportunities

# Output formats: json, csv, markdown, oscal-ar
# --show-efficiency-opportunities: include cross-framework efficiency analysis

# ── Push Gaps to Jira ───────────────────────────────────────────────
evidentia gap push-jira \
  --report report.json \
  --project SEC \
  --severity critical,high \
  --dry-run
# Outputs preview of issues that would be created

evidentia gap push-jira \
  --report report.json \
  --project SEC \
  --severity critical,high
# Creates Jira issues for critical and high severity gaps

# ── Push Gaps to ServiceNow ─────────────────────────────────────────
evidentia gap push-servicenow \
  --report report.json \
  --table sn_compliance_task \
  --group "GRC Team" \
  --severity critical,high

# ── Risk Statement Generation ───────────────────────────────────────
evidentia risk generate \
  --context system-context.yaml \
  --gaps report.json \
  --model gpt-4o \
  --output risks.json

evidentia risk generate \
  --context system-context.yaml \
  --gap-id a1b2c3d4-... \
  --model claude-sonnet-4-20250514

evidentia risk generate \
  --context system-context.yaml \
  --gaps report.json \
  --model ollama/llama3.3 \
  --output risks.json
# Works with local Ollama models — no API key required

# ── Evidence Collection ─────────────────────────────────────────────
evidentia collect check-connections
# ┌──────────────┬──────────────────┬────────┬────────────────┬──────┐
# │ Collector    │ Display Name     │ Status │ Authenticated  │ Perm │
# ├──────────────┼──────────────────┼────────┼────────────────┼──────┤
# │ aws-config   │ AWS Config       │ ✓      │ ✓              │ ✓    │
# │ github       │ GitHub           │ ✓      │ ✓              │ ✓    │
# │ okta         │ Okta             │ ✗      │ ✗              │ —    │
# └──────────────┴──────────────────┴────────┴────────────────┴──────┘

evidentia collect run \
  --collectors aws,github \
  --frameworks soc2-tsc \
  --output ./evidence/

evidentia collect run --all  # Run all enabled collectors

evidentia collect schedule start    # Start background scheduler
evidentia collect schedule status   # Check scheduler status  
evidentia collect schedule stop     # Stop scheduler

# ── Evidence Validation ─────────────────────────────────────────────
evidentia validate \
  --evidence ./evidence/bundle-20260405.json \
  --model gpt-4o \
  --output validated-bundle.json

evidentia validate \
  --file screenshot.png \
  --control CC6.1 \
  --framework soc2-tsc \
  --model gpt-4o

evidentia validate \
  --file policy-document.pdf \
  --control AC-1 \
  --framework nist-800-53-mod

# ── REST API Server ─────────────────────────────────────────────────
evidentia serve
# Starts API server at http://localhost:8743

evidentia serve \
  --host 0.0.0.0 \
  --port 8743 \
  --reload            # Dev mode: auto-reload on code changes

# ── Export ──────────────────────────────────────────────────────────
evidentia export \
  --report report.json \
  --format oscal-ar \
  --output assessment-results.json

evidentia export \
  --report report.json \
  --format csv \
  --output gaps.csv

# ── Version and Diagnostics ─────────────────────────────────────────
evidentia version
# Evidentia v0.1.0 (Python 3.12.4, uv 0.4.x)

evidentia doctor
# Checks:
#   ✓ Python 3.12+ detected
#   ✓ evidentia-core installed
#   ✓ evidentia-ai installed
#   ✓ OSCAL catalogs loaded (9 frameworks)
#   ✓ Crosswalk mappings loaded (6 crosswalks, 2,847 mappings)
#   ⚠ No LLM API key detected (set OPENAI_API_KEY for AI features)
#   ✗ AWS credentials not configured
#   ✗ GitHub token not configured
```

---

## 12. Configuration File Reference

```yaml
# evidentia.yaml — complete configuration reference
# All values shown are defaults unless noted otherwise.
# Environment variables take precedence over config file values.

# ── Schema Version ──────────────────────────────────────────────────
version: "1"

# ── LLM Configuration ──────────────────────────────────────────────
# Uses LiteLLM — supports any provider: OpenAI, Anthropic, Google, Azure, Ollama, etc.
# API keys loaded from environment variables:
#   OPENAI_API_KEY, ANTHROPIC_API_KEY, AZURE_OPENAI_API_KEY,
#   GOOGLE_API_KEY, etc.
# For Ollama (local, no API key): set model to "ollama/llama3.3"
llm:
  model: "gpt-4o"                    # Override: EVIDENTIA_LLM_MODEL env var
  # base_url: "http://localhost:11434"  # For Ollama or custom endpoints
  temperature: 0.1                    # Low for deterministic outputs
  max_retries: 3                      # Instructor retry count on validation failure
  # max_tokens: 4096                  # Optional: limit response length

# ── Storage Configuration ───────────────────────────────────────────
storage:
  type: "file"                        # "file" | "sqlite" | "postgresql"
  path: "./.evidentia"            # For file-based storage
  # For SQLite:
  # type: "sqlite"
  # path: "sqlite:///evidentia.db"
  # For PostgreSQL:
  # type: "postgresql"
  # path: "postgresql://user:pass@localhost:5432/evidentia"

# ── Default Frameworks ──────────────────────────────────────────────
frameworks:
  default:
    - nist-800-53-mod                 # NIST 800-53 Rev5 Moderate baseline
    - soc2-tsc                        # SOC 2 Trust Services Criteria
  # Additional frameworks to load at startup (improves first-query latency):
  preload:
    - iso27001-2022
    - cis-controls-v8

# ── Evidence Collectors ─────────────────────────────────────────────
collectors:
  aws:
    enabled: false
    # Auth: from environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    # or IAM role (preferred for production)
    regions: ["us-east-1"]
    include_security_hub: true
    include_iam: true
    include_cloudtrail: true
    include_audit_manager: false

  azure:
    enabled: false
    # Auth: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    subscription_ids: []

  gcp:
    enabled: false
    # Auth: GOOGLE_APPLICATION_CREDENTIALS (path to service account JSON)
    project_ids: []

  github:
    enabled: false
    # Auth: GITHUB_TOKEN environment variable
    organizations: []
    include_actions: true
    # base_url: "https://github.example.com/api/v3"  # For GitHub Enterprise

  okta:
    enabled: false
    domain: ""                        # e.g. "my-company.okta.com"
    # Auth: OKTA_API_TOKEN environment variable

# ── Integration Outputs ─────────────────────────────────────────────
integrations:
  jira:
    enabled: false
    server: ""                        # e.g. "https://my-company.atlassian.net"
    # Auth: JIRA_EMAIL + JIRA_API_TOKEN environment variables
    default_project: ""               # Jira project key, e.g. "SEC"
    issue_type: "Task"
    label_prefix: "evidentia"

  servicenow:
    enabled: false
    instance_url: ""                  # e.g. "https://my-company.service-now.com"
    # Auth: SERVICENOW_USERNAME + SERVICENOW_PASSWORD environment variables
    default_table: "sn_compliance_task"
    assignment_group: ""

# ── Evidence Validation ─────────────────────────────────────────────
validation:
  enabled: true
  staleness_thresholds:               # Maximum evidence age in days per framework
    soc2-tsc: 90
    pci-dss-4: 90
    iso27001-2022: 365
    nist-800-53-mod: 365
    nist-800-53-high: 365
    cis-controls-v8: 180
    cmmc-2-level2: 365

# ── Collection Schedule ─────────────────────────────────────────────
schedule:
  enabled: false
  cron: "0 2 * * *"                   # Daily at 2:00 AM UTC
  git_commit: false                   # Auto-commit evidence bundles to git
  notify_on_failure: ""               # Email or Slack webhook URL (optional)

# ── REST API Server ─────────────────────────────────────────────────
api:
  host: "0.0.0.0"
  port: 8743
  require_auth: false                 # Set true for production
  api_key: ""                         # Override: EVIDENTIA_API_KEY env var
  cors_origins: ["*"]                 # Restrict in production
  workers: 1                          # Uvicorn workers (increase for production)

# ── Logging ─────────────────────────────────────────────────────────
logging:
  level: "INFO"                       # DEBUG, INFO, WARNING, ERROR
  format: "rich"                      # "rich" (terminal), "json" (structured)
  file: null                          # Optional: path to log file
```

---

## 13. Dockerfile & Container Strategy

### 13.1 Multi-Stage Dockerfile

```dockerfile
# ============================================================
# Evidentia Dockerfile — Multi-stage production build
# ============================================================

# Stage 1: Build
FROM python:3.12-slim AS builder

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy workspace definition and lockfile first (for layer caching)
COPY pyproject.toml uv.lock ./

# Copy all package pyproject.toml files (for dependency resolution)
COPY packages/evidentia-core/pyproject.toml packages/evidentia-core/
COPY packages/evidentia-ai/pyproject.toml packages/evidentia-ai/
COPY packages/evidentia-collectors/pyproject.toml packages/evidentia-collectors/
COPY packages/evidentia-integrations/pyproject.toml packages/evidentia-integrations/
COPY packages/evidentia/pyproject.toml packages/evidentia/

# Install dependencies (cached if pyproject.toml files haven't changed)
RUN uv sync --frozen --no-install-workspace --no-dev

# Copy source code
COPY packages/ ./packages/

# Install workspace packages in non-editable mode
RUN uv sync --frozen --no-editable --no-dev

# ────────────────────────────────────────────────────────────
# Stage 2: Runtime
FROM python:3.12-slim AS runtime

WORKDIR /app

# Minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Copy bundled catalog data (included in evidentia-core package)
# This is already in .venv/lib but keeping explicit for clarity

# Create non-root user
RUN useradd --create-home --shell /bin/bash evidentia \
    && mkdir -p /app/.evidentia /app/evidence \
    && chown -R evidentia:evidentia /app

USER evidentia

# Default: start API server
EXPOSE 8743

CMD ["evidentia", "serve", "--host", "0.0.0.0", "--port", "8743"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8743/health || exit 1

# Labels
LABEL org.opencontainers.image.title="Evidentia"
LABEL org.opencontainers.image.description="Open-source GRC tool"
LABEL org.opencontainers.image.source="https://github.com/polycentric-labs/evidentia"
LABEL org.opencontainers.image.licenses="Apache-2.0"
```

### 13.2 Docker Compose (docker/docker-compose.yml)

```yaml
# docker-compose.yml — Evidentia self-hosting
version: "3.8"

services:
  evidentia:
    image: ghcr.io/evidentia/evidentia:latest
    # Or build locally:
    # build:
    #   context: ..
    #   dockerfile: docker/Dockerfile
    restart: unless-stopped
    ports:
      - "8743:8743"
    volumes:
      - ./evidentia.yaml:/app/evidentia.yaml:ro
      - evidence-data:/app/evidence
      - cb-data:/app/.evidentia
    environment:
      # ── LLM (at least one required for AI features) ──
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      # ── Cloud collectors (optional) ──
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}
      - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
      - GITHUB_TOKEN=${GITHUB_TOKEN:-}
      - OKTA_API_TOKEN=${OKTA_API_TOKEN:-}
      - OKTA_DOMAIN=${OKTA_DOMAIN:-}
      # ── Azure (optional) ──
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID:-}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET:-}
      - AZURE_TENANT_ID=${AZURE_TENANT_ID:-}
      # ── GCP (optional) ──
      - GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS:-}
      # ── Integration outputs (optional) ──
      - JIRA_SERVER=${JIRA_SERVER:-}
      - JIRA_EMAIL=${JIRA_EMAIL:-}
      - JIRA_API_TOKEN=${JIRA_API_TOKEN:-}
      - SERVICENOW_INSTANCE=${SERVICENOW_INSTANCE:-}
      - SERVICENOW_USERNAME=${SERVICENOW_USERNAME:-}
      - SERVICENOW_PASSWORD=${SERVICENOW_PASSWORD:-}
      # ── Evidentia API auth (optional) ──
      - EVIDENTIA_API_KEY=${EVIDENTIA_API_KEY:-}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8743/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  evidence-data:
  cb-data:
```

### 13.3 GitHub Actions CI/CD

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint-and-typecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v3
      - name: Set up Python
        run: uv python install 3.12
      - name: Install dependencies
        run: uv sync --all-packages
      - name: Lint
        run: uv run ruff check .
      - name: Format check
        run: uv run ruff format --check .
      - name: Type check
        run: uv run mypy packages/

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v3
      - name: Set up Python ${{ matrix.python }}
        run: uv python install ${{ matrix.python }}
      - name: Install dependencies
        run: uv sync --all-packages
      - name: Run tests
        run: uv run pytest tests/ -v --cov=packages --cov-report=xml -m "not ai"
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: coverage.xml

  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -f docker/Dockerfile -t evidentia:test .
      - name: Test Docker image
        run: |
          docker run -d --name cb-test -p 8743:8743 evidentia:test
          sleep 5
          curl -f http://localhost:8743/health
          docker stop cb-test
```

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ["v*"]

jobs:
  publish-pypi:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # For trusted publishing
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v3
      - name: Build packages
        run: |
          for pkg in evidentia-core evidentia-ai evidentia-collectors evidentia-integrations evidentia; do
            uv build --package $pkg
          done
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

  publish-docker:
    runs-on: ubuntu-latest
    permissions:
      packages: write
    steps:
      - uses: actions/checkout@v4
      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          file: docker/Dockerfile
          push: true
          tags: |
            ghcr.io/evidentia/evidentia:${{ github.ref_name }}
            ghcr.io/evidentia/evidentia:latest
```

---


## 14. Phased Implementation Roadmap

### Phase 1: Core Gap Analyzer + Risk Statement Generator (Weeks 1–16)

#### Week 1–2: Project Scaffolding

| Task | Detail | Acceptance Criteria |
|---|---|---|
| Initialize uv workspace | Create root `pyproject.toml` with workspace members; set up `uv.lock` | `uv sync` succeeds from root |
| Create all 5 package skeletons | `evidentia-core`, `-ai`, `-collectors`, `-integrations`, `evidentia` | Each package has `pyproject.toml`, `src/` dir, `__init__.py`, `py.typed` |
| GitHub Actions CI | Lint (ruff), typecheck (mypy), test (pytest) on push/PR | CI runs green on empty test suite |
| Pre-commit hooks | ruff check, ruff format, mypy | `pre-commit run --all-files` passes |
| Docker build pipeline | Multi-stage Dockerfile builds successfully | `docker build` succeeds; container starts and responds on `/health` |
| Branch protection | Require PR reviews, status checks | Direct push to `main` blocked |
| Initial documentation | README.md with project description, license, architecture overview | README renders correctly on GitHub |

#### Week 3–4: OSCAL Catalog Integration

| Task | Detail | Acceptance Criteria |
|---|---|---|
| Download NIST 800-53 Rev5 OSCAL JSON | From `usnistgov/oscal-content` repo | File bundled in `evidentia-core/src/evidentia_core/catalogs/data/` |
| Build `CatalogLoader` class | Parse OSCAL catalog JSON into `ControlCatalog` Pydantic model | All 1,007+ controls parsed; indexed by ID |
| Build NIST 800-53 Moderate profile loader | Parse OSCAL profile to extract Moderate baseline control IDs | ~323 controls in Moderate baseline |
| Build `CrosswalkLoader` | Load crosswalk JSON files into `CrosswalkDefinition` models | Bidirectional lookup works |
| Create crosswalk JSON files | NIST 800-53 ↔ SOC 2 TSC, ISO 27001, CIS v8, CMMC 2.0, PCI DSS 4.0, CSF 2.0 | 6 crosswalk files with source citations |
| Build `FrameworkRegistry` | Singleton that lazy-loads catalogs and crosswalks | `registry.get_catalog("nist-800-53-mod")` returns valid catalog |
| Unit tests | Test catalog loading, crosswalk lookups, bidirectional mapping | >90% coverage on `catalogs/` module |
| `evidentia catalog list` | CLI command listing available frameworks | Table output with Rich |
| `evidentia catalog show` | CLI command showing controls in a framework | Shows control detail for specified framework/control |
| `evidentia catalog crosswalk` | CLI command showing cross-framework mappings | Shows mappings for specified source→target→control |

#### Week 5–6: Control Inventory Parser

| Task | Detail | Acceptance Criteria |
|---|---|---|
| `ControlInventory` Pydantic model | With all fields from §5.2 | Model validates sample data; serializes to JSON/YAML |
| Evidentia YAML parser | Parse preferred YAML format | Sample `my-controls.yaml` loads correctly |
| CSV parser with fuzzy headers | Map common column name variations | `control_id`, `ctrl`, `id`, `requirement` all recognized |
| OSCAL component-definition parser | Parse OSCAL component definition JSON | Official OSCAL examples parse correctly |
| CISO Assistant export parser | Parse CISO Assistant JSON export format | Test with sample CISO Assistant export |
| Auto-detection logic | Detect format from file extension and content | `.yaml`, `.csv`, `.json` (OSCAL, CISO, CB) all auto-detected |
| `normalize_control_id()` function | Handle `AC-2`, `AC2`, `ac-2`, `Access Control 2` | All variations normalize to `AC-2` |
| `find_best_match()` function | Fuzzy match user control IDs to catalog IDs | Threshold of 75% similarity |
| Unit tests for all parsers | Test with sample files in `tests/fixtures/` | Each format loads and produces correct `ControlInventory` |

#### Week 7–9: Gap Analysis Engine

| Task | Detail | Acceptance Criteria |
|---|---|---|
| `GapAnalyzer.analyze()` method | Core gap analysis algorithm from §7.1.3 | Produces `GapAnalysisReport` from inventory + frameworks |
| Required control set builder | Union of controls from selected frameworks | Deduplicates cross-framework overlaps |
| Inventory normalization | Map user control IDs to catalog IDs using fuzzy matching | 90%+ correct mapping on realistic inventories |
| Gap identification | Missing = critical, partial = high, planned = medium | Correct severity assignment |
| Cross-framework value calculation | For each gap, determine multi-framework value | `cross_framework_value` populated correctly |
| Priority scoring | Formula: severity × (1 + 0.2 × cross_fw) × (1 / effort) | Scores ranked correctly |
| Efficiency opportunity detection | Controls satisfying 3+ frameworks flagged | Opportunities sorted by value score |
| JSON output formatter | Export `GapAnalysisReport` as JSON | Valid JSON matching schema |
| CSV output formatter | One row per gap | Headers match specification |
| Markdown output formatter | Rich table with summary statistics | Readable in GitHub/GitLab |
| OSCAL Assessment Results exporter | Map gap report to OSCAL AR structure | Valid OSCAL JSON |
| `evidentia gap analyze` CLI | End-to-end CLI command | Accepts all flags from §11 |
| Integration test | Real OSCAL catalog + sample inventory → gap report | Report structure matches schema |
| Performance benchmark | 500-control inventory vs NIST 800-53 Moderate | < 2 seconds |

#### Week 10–12: AI Risk Statement Generator

| Task | Detail | Acceptance Criteria |
|---|---|---|
| LiteLLM + Instructor client setup | `evidentia_ai/client.py` | `get_instructor_client()` returns configured client |
| `RISK_STATEMENT_SYSTEM_PROMPT` | NIST SP 800-30 compliant prompt | Reviewed by domain expert |
| `SystemContext` model + YAML parser | Load `system-context.yaml` | All fields from §5.8 validated |
| Context builder | Format gap + system context into prompt | Template populated correctly |
| `RiskStatementGenerator.generate()` | Single risk statement generation | Returns valid `RiskStatement` |
| `generate_batch()` | Sequential batch generation | Generates N risk statements with progress |
| `generate_batch_async()` | Concurrent batch with semaphore | Respects `max_concurrent` |
| Model agnosticism test | Test with GPT-4o, Claude Sonnet, Ollama/Llama3 | All three produce valid `RiskStatement` |
| Retry handling | Invalid JSON from LLM triggers Instructor retry | Up to 3 retries; eventual success logged |
| `evidentia risk generate` CLI | End-to-end CLI command | Accepts `--context`, `--gaps`, `--model`, `--output` |
| VCR.py test recordings | Record LLM responses for CI replay | Tests run without real API calls in CI |
| Performance benchmark | Single risk statement generation time | < 15 seconds with GPT-4o |

#### Week 13–14: Jira + ServiceNow Integrations

| Task | Detail | Acceptance Criteria |
|---|---|---|
| `JiraIntegration` class | Create issues from gap reports | Issues created with correct fields |
| Jira issue template | Summary, description, labels, priority | Matches specification in §9.2 |
| Idempotency check | Search for existing issues before creating | No duplicate issues |
| Dry-run mode | Preview issues without creating | Returns `"would_create"` results |
| `ServiceNowIntegration` class | Create records in configurable table | Records created in specified table |
| Severity → priority mapping | Gap severity maps to Jira/ServiceNow priority | Correct mapping per specification |
| `evidentia gap push-jira` CLI | End-to-end CLI command | Accepts `--report`, `--project`, `--severity`, `--dry-run` |
| `evidentia gap push-servicenow` CLI | End-to-end CLI command | Accepts `--report`, `--table`, `--group`, `--severity` |
| Integration tests (mocked) | Mock Jira/ServiceNow APIs | Verify correct API calls |

#### Week 15–16: REST API + Docker + v0.1.0 Release

| Task | Detail | Acceptance Criteria |
|---|---|---|
| FastAPI application | All Phase 1 endpoints from §10 | OpenAPI docs at `/docs` |
| Gap analysis endpoints | POST `/gaps/analyze`, GET `/gaps/reports`, etc. | Correct request/response shapes |
| Risk statement endpoints | POST `/risks/generate`, GET `/risks/{id}`, etc. | Correct request/response shapes |
| Catalog endpoints | GET `/catalogs`, `/catalogs/{id}/controls`, `/catalogs/crosswalk` | Correct responses |
| Health endpoint | GET `/health` | Returns status, version, collector info |
| Error handling middleware | Consistent error response format | All errors match §10.3 |
| Optional API key auth | `Authorization: Bearer <key>` when enabled | 401 on missing/invalid key |
| `evidentia serve` CLI | Start API server | Server starts on configured port |
| Docker image | Multi-stage build | Image < 500MB; starts in < 5s |
| PyPI packages | All 5 packages published | `pip install evidentia` works |
| Documentation | getting-started.md, configuration.md, CLI reference | Covers all Phase 1 features |
| v0.1.0 tag | GitHub release with changelog | All CI checks pass |

### Phase 2: Evidence Collection Agents (Weeks 17–28)

#### Week 17–18: Base Collector Framework

- Build `BaseCollector` abstract class, `ConnectionStatus`, `CollectionResult` models
- Build `async_retry` decorator with exponential backoff
- Build `RateLimiter` token bucket implementation
- Build collector registry for discovery and instantiation
- Build evidence storage layer (file-based locker pattern)
- `evidentia collect check-connections` CLI command
- Unit tests for base framework

#### Week 19–21: AWS Collector

- `AWSConfigCollector` — Config rule compliance results
- `AWSSecurityHubCollector` — Security Hub findings with NIST mappings
- `AWSIAMCollector` — Password policy, MFA status, credential reports
- `AWSCloudTrailCollector` — Trail configuration verification
- `AWSAuditManagerCollector` — Bridge to existing Audit Manager assessments
- Bundle AWS Config rule → NIST 800-53 mapping table (60+ rules)
- Integration tests using `moto` (AWS mock library)
- `evidentia collect run --collectors aws`

#### Week 22–23: GitHub Collector

- `GitHubCollector` — Branch protection, secret scanning, CODEOWNERS, Dependabot, visibility
- `GitHubActionsCollector` — CI/CD pipeline compliance checks
- Control mapping table (CM-*, SA-*, SI-* controls)
- Integration tests using `responses` library
- `evidentia collect run --collectors github`

#### Week 24–25: Okta Collector

- `OktaCollector` — MFA enrollment, password policies, inactive users, lifecycle events
- Control mapping table (IA-*, AC-*, PS-* controls)
- Integration tests
- `evidentia collect run --collectors okta`

#### Week 26–27: Azure + GCP Collectors

- Azure: Policy compliance, Defender for Cloud, Entra ID
- GCP: Security Command Center, Organization Policy
- These are secondary priority — functional but fewer control mappings than AWS
- Integration tests

#### Week 28: Scheduler + Evidence Bundle Export

- `CollectionScheduler` using APScheduler
- OSCAL Assessment Results export from `EvidenceBundle`
- Auto-commit evidence to git (optional)
- `evidentia collect schedule start/status/stop`
- `evidentia export --format oscal-ar`
- Publish v0.2.0

### Phase 3: Evidence Validator + Polish (Weeks 29–36)

#### Week 29–31: Evidence Validator

- `EvidenceValidator` class with text and vision analysis
- Framework-specific validation prompts (SOC 2, NIST, ISO 27001)
- Staleness rules (configurable per framework)
- Image validation using LLM vision (screenshots, PDFs)
- `evidentia validate` CLI command
- `POST /evidence/validate` API endpoint

#### Week 32–34: Dashboard + Management Reporting

- Lightweight HTML dashboard (single file, no build step)
- Collector connection status widget
- Evidence collection history
- Gap coverage trend chart (using Chart.js)
- Export dashboard as PDF
- Served at `http://localhost:8743/dashboard`

#### Week 35–36: v1.0.0 Release

- Comprehensive test suite (target 80%+ coverage)
- MkDocs documentation site
- Security hardening (API auth, input validation, secrets scanning)
- Performance optimization (async collection, parallel gap analysis)
- Publish v1.0.0 to PyPI and GHCR
- Blog post and community announcement

---


## 15. Open-Source Ecosystem Integration Strategy

### What to Build On (Do Not Rebuild)

| Existing Tool/Library | How Evidentia Uses It | Relationship |
|---|---|---|
| **NIST OSCAL catalogs** (`usnistgov/oscal-content`) | Bundled as data files — the authoritative control catalog source for NIST frameworks | Data dependency (public domain) |
| **oscal-pydantic** (PyPI) | Pydantic models for OSCAL data types — used for OSCAL I/O, avoids rebuilding OSCAL schema | Library dependency |
| **LiteLLM** | Unified LLM interface — all AI calls route through this for provider agnosticism | Library dependency |
| **Instructor** | Structured output extraction — enforces Pydantic schema on LLM responses with auto-retry | Library dependency |
| **Steampipe** (optional) | Can invoke via subprocess for cloud infrastructure SQL queries as an alternative to direct SDK clients | Optional integration |
| **Cloud Custodian** (optional) | Can read Cloud Custodian policy check outputs as evidence artifacts | Optional evidence source |
| **Auditree** (IBM) | Architectural inspiration for the fetcher/check/locker evidence pattern; Evidentia's evidence locker is spiritually similar | Design inspiration |
| **CISO Assistant** | Evidentia accepts CISO Assistant JSON exports as inventory input; future: push gap data back via CISO Assistant API | Input/output integration |
| **`jira`** Python library | Direct dependency for Jira Cloud/Server integration | Library dependency |
| **`servicenow-api`** Python library | Direct dependency for ServiceNow integration | Library dependency |
| **boto3, azure-mgmt-\*, google-cloud-\*** | Direct dependencies for respective cloud evidence collectors | Library dependencies |
| **PyGithub** | Direct dependency for GitHub repository evidence collection | Library dependency |
| **okta-sdk-python** | Direct dependency for Okta identity evidence collection | Library dependency |

### What NOT to Rebuild

| Capability | Existing Tool | Why Not |
|---|---|---|
| Full GRC platform UI | CISO Assistant | Already well-built; Evidentia focuses on library/CLI/API, not UI |
| Framework content authoring | OSCAL CLI | NIST maintains this; no reason to duplicate |
| SIEM/SOAR workflows | Admyral, Tines | Different problem domain |
| Full risk management platform | SimpleRisk, Eramba | Evidentia generates risk statements, not manages the full risk lifecycle |
| Policy-as-code engine | OPA, Cloud Custodian | Evidentia consumes their outputs as evidence, doesn't replace them |
| Vulnerability scanning | Trivy, Grype, Nuclei | Evidentia maps scan results to controls, doesn't perform scanning |

### Evidentia's Unique Position

Evidentia is the **translation layer** between:

```
Raw Infrastructure Data          →  Evidentia  →  Audit-Ready Evidence
(AWS Config, GitHub, Okta)          (maps, validates,    (OSCAL, Jira tickets,
                                     generates risks)     gap reports, PDFs)
```

No existing open-source tool occupies this specific niche with a library-first, OSCAL-native approach.

---

## 16. Security & Credential Handling

### Credential Flow

All credentials are loaded from environment variables exclusively. The `evidentia.yaml` config file documents which environment variables are needed but never stores actual credential values.

```
┌─────────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│ Environment Variables│───→│ Pydantic Settings    │───→│ Connector Client │
│ (set by user or CI) │    │ (validates, types)    │    │ (boto3, PyGithub)│
└─────────────────────┘    └──────────────────────┘    └──────────────────┘

OPENAI_API_KEY=sk-... ──→ config.llm.api_key ──→ LiteLLM
AWS_ACCESS_KEY_ID=... ──→ boto3 (auto-discovers from environment)
GITHUB_TOKEN=ghp_... ──→ config.github.token ──→ PyGithub
```

### Required Environment Variables by Feature

| Feature | Required Variables | Optional Variables |
|---|---|---|
| **Gap Analysis** (core) | None | None |
| **Risk Generation** (AI) | One of: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` | `EVIDENTIA_LLM_MODEL` |
| **AWS Collector** | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (or IAM role) | `AWS_DEFAULT_REGION` |
| **Azure Collector** | `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID` | `AZURE_SUBSCRIPTION_ID` |
| **GCP Collector** | `GOOGLE_APPLICATION_CREDENTIALS` | — |
| **GitHub Collector** | `GITHUB_TOKEN` | — |
| **Okta Collector** | `OKTA_API_TOKEN` + `OKTA_DOMAIN` | — |
| **Jira Integration** | `JIRA_SERVER` + `JIRA_EMAIL` + `JIRA_API_TOKEN` | — |
| **ServiceNow Integration** | `SERVICENOW_INSTANCE` + `SERVICENOW_USERNAME` + `SERVICENOW_PASSWORD` | — |
| **REST API Auth** | — | `EVIDENTIA_API_KEY` |
| **Ollama (Local LLM)** | None (set model to `ollama/llama3.3`) | `EVIDENTIA_LLM_MODEL` |

### IAM Permissions Required per Collector

**AWS Config Collector** — Minimum IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "config:DescribeComplianceByConfigRule",
        "config:GetComplianceDetailsByConfigRule",
        "config:DescribeConfigRules",
        "securityhub:GetFindings",
        "securityhub:BatchGetSecurityControls",
        "iam:GetAccountPasswordPolicy",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**GitHub Collector** — Token scopes:
- `repo` (read access to private repos — required for branch protection rules)
- `read:org` (organization membership and settings)
- For public repos only: `public_repo` scope is sufficient

**Okta Collector** — API token with read-only scopes:
- `okta.policies.read`
- `okta.users.read`
- `okta.factors.read`
- `okta.groups.read`
- `okta.logs.read` (optional, for lifecycle events)

### Security Best Practices Enforced

1. **No credentials in config files:** `evidentia.yaml` contains zero secrets. All secrets flow through environment variables.
2. **No credential logging:** All logging sanitizes credential values. API keys are never printed, even at DEBUG level.
3. **Least privilege documentation:** README documents the minimum permissions needed for each collector.
4. **Content hashing:** All evidence artifacts include SHA-256 content hashes for tamper detection.
5. **Non-root Docker user:** Container runs as `evidentia` user, not root.
6. **Input validation:** All API inputs validated by Pydantic before processing. Extra fields rejected (`extra="forbid"`).
7. **Rate limiting awareness:** Collectors respect upstream API rate limits to avoid account lockout.
8. **HTTPS enforcement:** When API auth is enabled, documentation recommends running behind a TLS-terminating reverse proxy.

---

## 17. Testing Strategy

### Test Pyramid

```
                ┌─────────┐
                │   E2E   │  ← Docker-based full stack tests (few, slow)
               ┌┤         ├┐
              ┌┤│         │├┐
             ┌┤││         │││
            ┌┤│││   API   │├┤  ← FastAPI endpoint tests
           ┌┤│││├─────────┤│├┐
          ┌┤│││││   CLI   │├││┤  ← Typer CLI command tests
         ┌┤│││││├─────────┤││├┐
        ┌┤│││││││   Intg  ├┤│├┤  ← Integration tests (mocked externals)
       ┌┤│││││││├─────────┤├│├┤┐
      ┌┤│││││││││  Unit   ├┤├│├┤  ← Pydantic models, business logic (many, fast)
      └┴┴┴┴┴┴┴┴┴┴─────────┴┴┴┴┴┘
```

### Unit Tests

| Module | What to Test | Test Count (est.) |
|---|---|---|
| `models/*` | Pydantic validation, serialization, deserialization, edge cases | 50+ |
| `catalogs/loader.py` | Parse all bundled OSCAL catalogs; handle malformed JSON | 15+ |
| `catalogs/crosswalk.py` | Bidirectional lookup; missing entries; normalization | 20+ |
| `catalogs/registry.py` | Framework discovery; lazy loading; caching | 10+ |
| `gap_analyzer/inventory.py` | YAML, CSV, OSCAL, CISO Assistant parsing; auto-detection; edge cases | 25+ |
| `gap_analyzer/normalizer.py` | Control ID normalization; fuzzy matching; threshold behavior | 20+ |
| `gap_analyzer/analyzer.py` | Full gap analysis with known inputs → known outputs | 15+ |
| `gap_analyzer/prioritizer.py` | Priority scoring formula; all severity/effort combinations | 10+ |
| `gap_analyzer/efficiency.py` | Efficiency opportunity detection with varying framework counts | 10+ |
| `gap_analyzer/reporter.py` | JSON, CSV, Markdown, OSCAL-AR output formats | 8+ |
| `storage/*` | File backend CRUD; SQLite backend CRUD | 15+ |

### Integration Tests (Mocked External Services)

| Test | Mock Library | What It Verifies |
|---|---|---|
| AWS collector | `moto` | Correct AWS API calls; Config rule → control mapping; multi-region |
| GitHub collector | `responses` | Branch protection parsing; CODEOWNERS detection; visibility checks |
| Okta collector | `responses` | MFA policy parsing; password policy extraction; inactive user detection |
| Jira integration | `responses` | Issue creation payload; idempotency; dry-run mode |
| ServiceNow integration | `responses` | Record creation payload; table selection; severity mapping |
| CLI gap analysis | `typer.testing.CliRunner` | End-to-end `evidentia gap analyze` with fixture data |
| CLI risk generation | `typer.testing.CliRunner` + VCR.py | End-to-end `evidentia risk generate` with recorded LLM response |
| API endpoints | `httpx` + `pytest-httpx` | All endpoints return correct status codes and response shapes |

### AI Tests (Special Considerations)

```python
# tests/unit/test_ai/test_risk_generator.py
"""Tests for risk statement generation.

Strategy:
1. Record LLM responses using pytest-recording (VCR.py) during development
2. Replay recorded responses in CI (no real API calls, no cost)
3. Validate that Instructor always produces valid RiskStatement
4. Test with multiple model configurations
"""

import pytest
from evidentia_ai.risk_statements.generator import RiskStatementGenerator
from evidentia_core.models.gap import ControlGap, GapSeverity, ImplementationEffort
from evidentia_core.models.risk import RiskLevel, RiskStatement


@pytest.fixture
def sample_gap() -> ControlGap:
    return ControlGap(
        framework="nist-800-53-mod",
        control_id="SC-28",
        control_title="Protection of Information at Rest",
        control_description="Protect the confidentiality and integrity of information at rest.",
        gap_severity=GapSeverity.CRITICAL,
        implementation_status="missing",
        gap_description="No encryption at rest configured for data warehouses.",
        remediation_guidance="Enable encryption at rest for all data stores.",
        implementation_effort=ImplementationEffort.MEDIUM,
        cross_framework_value=["pci-dss-4:3.5.1", "soc2-tsc:CC6.7"],
    )


@pytest.fixture
def sample_context():
    from evidentia_ai.risk_statements.templates import SystemContext, SystemComponent
    return SystemContext(
        organization="Acme Corp",
        system_name="Customer Data Platform",
        system_description="Cloud-native data platform on AWS processing customer PII.",
        data_classification=["PII", "PCI-CDE"],
        hosting="AWS (us-east-1)",
        components=[
            SystemComponent(
                name="Data Warehouse", type="database",
                technology="Amazon Redshift",
                data_handled=["PII", "PCI-CDE"],
            )
        ],
        threat_actors=["External threat actors (financial)"],
        existing_controls=["AC-2", "IA-2"],
        frameworks=["nist-800-53-mod"],
        risk_tolerance="medium",
    )


@pytest.mark.ai
@pytest.mark.vcr  # Record/replay LLM response
def test_generate_risk_statement(sample_gap, sample_context):
    generator = RiskStatementGenerator(model="gpt-4o")
    risk = generator.generate(gap=sample_gap, system_context=sample_context)

    # Validate output is a valid RiskStatement
    assert isinstance(risk, RiskStatement)
    assert risk.risk_level in [e.value for e in RiskLevel]
    assert risk.remediation_priority >= 1
    assert risk.remediation_priority <= 5
    assert len(risk.recommended_controls) > 0
    assert risk.source_gap_id == sample_gap.id
    assert risk.model_used == "gpt-4o"
    # Verify the vulnerability references the actual gap
    assert "SC-28" in risk.vulnerability or "encryption" in risk.vulnerability.lower()


@pytest.mark.ai
@pytest.mark.vcr
def test_generate_batch(sample_gap, sample_context):
    generator = RiskStatementGenerator(model="gpt-4o")
    results = generator.generate_batch(
        gaps=[sample_gap],
        system_context=sample_context,
    )
    assert len(results) == 1
    assert all(isinstance(r, RiskStatement) for r in results)
```

### Performance Benchmarks

| Operation | Target | Measurement Method |
|---|---|---|
| Gap analysis (500 controls vs Moderate) | < 2 seconds | `pytest-benchmark` fixture |
| Risk statement generation (single, GPT-4o) | < 15 seconds | Wall clock, recorded response |
| AWS evidence collection (100 rules, 2 regions) | < 30 seconds | `moto`-mocked, async |
| Catalog loading (all 9 frameworks) | < 1 second | Cold start measurement |
| Crosswalk loading (all 6 crosswalks) | < 500ms | Cold start measurement |
| API response (GET /health) | < 50ms | `pytest-httpx` |
| API response (POST /gaps/analyze, small inventory) | < 3 seconds | `pytest-httpx` |

### Coverage Targets

| Package | Target | Rationale |
|---|---|---|
| `evidentia-core` | 90% | Core business logic — must be thoroughly tested |
| `evidentia-ai` | 70% | LLM calls are recorded/replayed; prompt logic tested via output validation |
| `evidentia-collectors` | 75% | Mocked external services; focus on parsing and mapping |
| `evidentia-integrations` | 80% | Mocked Jira/ServiceNow; verify payload construction |
| `evidentia` (CLI/API) | 70% | Integration-level tests cover most paths |

---


## 18. Naming, Branding & Community Strategy

### Project Identity

| Attribute | Value |
|---|---|
| **Project name** | Evidentia |
| **PyPI package** | `evidentia` (meta), `evidentia-core`, `evidentia-ai`, `evidentia-collectors`, `evidentia-integrations` |
| **Docker image** | `ghcr.io/evidentia/evidentia` |
| **GitHub org/repo** | `polycentric-labs/evidentia` |
| **CLI command** | `evidentia` (primary), `cb` (alias) |
| **Config file** | `evidentia.yaml` |
| **License** | Apache 2.0 (OSI approved, enterprise-friendly, no copyleft) |
| **Tagline** | "Bridge the gap between your controls and your frameworks." |
| **Website** | `evidentia.dev` (future) |

### README Structure

1. **One-line description** + tagline
2. **Three bullet points** — what it does
3. **Quick install** — `pip install evidentia`
4. **60-second demo GIF** — gap analysis on a sample inventory with Rich-formatted terminal output
5. **Features table** — 5 core capabilities with status badges (GA / Beta / Planned)
6. **Installation** — pip, Docker, Homebrew (future)
7. **Quick start** — 5 commands from zero to gap report
8. **Configuration** — link to docs/configuration.md
9. **CLI reference** — link to docs/cli-reference.md
10. **API reference** — link to docs/api-reference.md
11. **Architecture** — link to this document
12. **Contributing** — link to CONTRIBUTING.md
13. **License** — Apache 2.0

### Community Launch Plan

| Week | Action | Target |
|---|---|---|
| Week 16 | v0.1.0 release | Post on r/netsec, r/grc, r/cybersecurity; LinkedIn post |
| Week 20 | Blog: "Automating SOC 2 Gap Analysis with Evidentia" | Medium, dev.to, company blog |
| Week 24 | Blog: "OSCAL for Normal People" using Evidentia | Target OSCAL community; present at OSCAL monthly workshop |
| Week 28 | v0.2.0 release (evidence collectors) | Post on r/aws, r/devops; Steampipe community |
| Week 32 | Blog: "AI-Powered Evidence Validation" | Target GRC analyst audience |
| Week 36 | v1.0.0 launch | ProductHunt, Hacker News "Show HN", CISO Assistant community, tweet thread |

### GitHub Star Targets

- Month 3: 200 stars
- Month 6: 500 stars
- Month 12: 1,500+ stars

### SEO and Discoverability

- GitHub topics: `grc`, `compliance`, `governance`, `risk-management`, `oscal`, `nist`, `soc2`, `iso27001`, `security`, `audit`
- PyPI keywords: same as above
- README includes "awesome-security" badge and links
- Submit to awesome-security, awesome-compliance, awesome-python lists

---

## Appendix A: Bundled Framework Data

### Catalog Data Files

| Framework | File | Source | Controls | Crosswalk File |
|---|---|---|---|---|
| NIST SP 800-53 Rev 5 (Full) | `nist-800-53-rev5.json` | `usnistgov/oscal-content` (public domain) | ~1,189 | N/A (primary hub) |
| NIST SP 800-53 Rev 5 Moderate | `nist-800-53-mod.json` | `usnistgov/oscal-content` profile filter | ~323 | N/A (primary hub) |
| NIST SP 800-53 Rev 5 High | `nist-800-53-high.json` | `usnistgov/oscal-content` profile filter | ~421 | N/A (primary hub) |
| NIST CSF 2.0 | `nist-csf-2.0.json` | NIST IR 8286 | ~106 subcategories | `nist-800-53-to-csf2.json` |
| SOC 2 TSC 2017 | `soc2-tsc.json` | Custom (from AICPA published crosswalk) | ~60 TSC points | `nist-800-53-to-soc2-tsc.json` |
| ISO 27001:2022 Annex A | `iso27001-2022.json` | Custom (from NIST SP 800-53 Rev5 Appendix H crosswalk) | 93 controls | `nist-800-53-to-iso27001.json` |
| CIS Controls v8 | `cis-controls-v8.json` | Custom (from CIS published mapping to NIST) | 153 safeguards | `nist-800-53-to-cis-v8.json` |
| CMMC 2.0 Level 2 | `cmmc-2-level2.json` | Custom (derived from NIST SP 800-171 → 800-53 mapping) | 110 practices | `nist-800-53-to-cmmc2.json` |
| PCI DSS 4.0 | `pci-dss-4.json` | Custom (from PCI SSC published mapping) | ~285 requirements | `nist-800-53-to-pci-dss-4.json` |

### Legal and Licensing Notes

- **NIST publications** (800-53, CSF, IR 8286): Public domain. No licensing restrictions. Freely distributable.
- **SOC 2 TSC**: The Trust Services Criteria are published by AICPA. Evidentia represents SOC 2 as an OSCAL profile mapping to NIST 800-53 controls rather than reproducing copyrighted TSC text verbatim. Control IDs (CC6.1, etc.) and titles are factual and not copyrightable.
- **ISO 27001:2022**: ISO standards are copyrighted. Evidentia represents ISO 27001 Annex A as an OSCAL profile pointing to NIST 800-53 controls. Control IDs (A.5.1, etc.) and short titles are factual references. Full control text is not reproduced.
- **CIS Controls v8**: Published under Creative Commons Attribution-NonCommercial-NoDerivatives (CC BY-NC-ND). Evidentia references CIS control IDs and titles (factual) and maps them to NIST. Full safeguard text is not reproduced in the bundled data.
- **CMMC 2.0**: Based on NIST SP 800-171 (public domain). CMMC practice identifiers are public.
- **PCI DSS 4.0**: Published by PCI SSC. Evidentia references requirement IDs and short descriptions. Full requirement text is not reproduced.

### Crosswalk Authoritative Sources

| Crosswalk | Primary Source |
|---|---|
| NIST 800-53 ↔ SOC 2 TSC | AICPA "Mapping of AICPA Trust Services Criteria to NIST Cybersecurity Framework" + NIST SP 800-53 Appendix H |
| NIST 800-53 ↔ ISO 27001 | NIST SP 800-53 Rev 5 Appendix H (Table H-4) |
| NIST 800-53 ↔ CIS Controls v8 | CIS Controls v8 Mapping to NIST 800-53 (published by CIS) |
| NIST 800-53 ↔ CMMC 2.0 | NIST SP 800-171 → NIST SP 800-53 mapping (Appendix D) + CMMC ↔ 800-171 |
| NIST 800-53 ↔ PCI DSS 4.0 | PCI SSC published mapping + NIST 800-53 Appendix H |
| NIST 800-53 ↔ CSF 2.0 | NIST CSF 2.0 Reference Tool mappings (published by NIST) |

---

## Appendix B: Known Risks & Mitigations

| # | Risk | Likelihood | Impact | Mitigation Strategy |
|---|---|---|---|---|
| 1 | **Framework crosswalk inaccuracy** — Mappings between frameworks may be incomplete or incorrect | Medium | High | Use only NIST-published and AICPA/CIS/PCI SSC-published crosswalks as primary sources. Document all sources. Include disclaimer that cross-framework mappings are advisory and require human review. Allow users to override mappings. |
| 2 | **LLM hallucination in risk statements** — AI generates fabricated control IDs, inaccurate technical details, or misleading risk ratings | Medium | Medium | Instructor enforces Pydantic schema validation. Low temperature (0.1). System prompt explicitly prohibits fabricated control IDs. Include mandatory human review step in workflow. Log model used and prompt for auditability. |
| 3 | **API credential exposure** — Credentials could be leaked through logs, error messages, or config files | Low | Critical | Credentials only from environment variables, never from config files. All logging sanitizes credential values. Docker runs as non-root user. Document least-privilege IAM policies. |
| 4 | **Integration breaking on upstream API changes** — Cloud provider, Jira, ServiceNow, or Okta APIs change | High | Medium | Pin integration library versions. Add integration health monitoring (`check_connection`). Version-aware connector design. Monitor upstream changelogs. Graceful degradation when one collector fails. |
| 5 | **Legal issues with framework content** — Reproducing copyrighted framework text | Low | High | Only use NIST-published OSCAL content (public domain). Represent commercial frameworks as OSCAL profiles pointing to NIST controls. Do not reproduce copyrighted text. Reference factual control IDs and titles only. |
| 6 | **Community not adopting** — Project fails to gain traction | Medium | High | Focus on GitHub SEO, clear README with demo GIF, working zero-config experience. Integrate with CISO Assistant (existing community). Blog series targeting GRC practitioners. Present at OSCAL workshops. |
| 7 | **OSCAL specification changes** — NIST updates OSCAL schema | Low | Medium | Depend on `oscal-pydantic` library (maintained by Credentive Security). Monitor OSCAL release notes. Abstract OSCAL I/O behind internal models. |
| 8 | **Performance degradation at scale** — Gap analysis or evidence collection slows with large inventories | Low | Medium | Profile critical paths. Use async I/O for collectors. Index catalogs in memory. Benchmark on every release. Target: <2s for 500-control gap analysis. |
| 9 | **LLM provider outage** — Primary LLM provider (OpenAI, Anthropic) is unavailable | Medium | Low | LiteLLM supports fallback models. Users can configure backup model. Core features (gap analysis) work without LLM. AI features degrade gracefully. |
| 10 | **Supply chain vulnerability** — Dependency with known CVE | Medium | Medium | Dependabot enabled. Regular `uv lock --upgrade`. Pin major versions. Minimal dependency surface. |

---

## Appendix C: Minimum Viable IaC for Self-Hosting

### Docker Compose (Production-Ready)

```yaml
# docker-compose.prod.yml
# Self-hosting Evidentia with HTTPS via Caddy reverse proxy
version: "3.8"

services:
  evidentia:
    image: ghcr.io/evidentia/evidentia:latest
    restart: unless-stopped
    expose:
      - "8743"
    volumes:
      - ./evidentia.yaml:/app/evidentia.yaml:ro
      - evidence-data:/app/evidence
      - cb-data:/app/.evidentia
    env_file:
      - .env  # All credentials in .env file (git-ignored)
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8743/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config

volumes:
  evidence-data:
  cb-data:
  caddy-data:
  caddy-config:
```

### Caddyfile (Automatic HTTPS)

```
# Caddyfile — automatic HTTPS with Caddy
evidentia.example.com {
    reverse_proxy evidentia:8743
    
    # Optional: basic auth at the reverse proxy level
    # basicauth /api/* {
    #     admin $2a$14$... # caddy hash-password
    # }
}
```

### `.env` File Template

```bash
# .env — credentials for docker-compose (git-ignored!)

# LLM (at least one required for AI features)
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...

# Cloud collectors (optional — enable what you use)
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AWS_DEFAULT_REGION=us-east-1

# GITHUB_TOKEN=ghp_...

# OKTA_API_TOKEN=
# OKTA_DOMAIN=my-company.okta.com

# Integration outputs (optional)
# JIRA_SERVER=https://my-company.atlassian.net
# JIRA_EMAIL=grc@my-company.com
# JIRA_API_TOKEN=

# SERVICENOW_INSTANCE=my-company.service-now.com
# SERVICENOW_USERNAME=admin
# SERVICENOW_PASSWORD=

# Evidentia API auth
EVIDENTIA_API_KEY=your-secure-api-key-here
```

### PostgreSQL (Optional — Team Use)

```yaml
# Add to docker-compose.prod.yml for PostgreSQL backend
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: evidentia
      POSTGRES_USER: evidentia
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U evidentia"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

Update `evidentia.yaml`:
```yaml
storage:
  type: "postgresql"
  path: "postgresql://evidentia:changeme@postgres:5432/evidentia"
```

---

## Appendix D: Storage Backend Abstraction Layer

### Interface Definition (evidentia_core/storage/base.py)

```python
"""Abstract storage backend interface.

All storage operations go through this interface, making the application
storage-agnostic. Implementations exist for:
- File-based (YAML/JSON files — default, git-friendly)
- SQLite (single-file database — local persistence)
- PostgreSQL (full relational — team use)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from evidentia_core.models.evidence import EvidenceBundle
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskRegister


class StorageBackend(ABC):
    """Abstract interface for Evidentia storage backends."""

    # ── Gap Reports ────────────────────────────────────────────────
    @abstractmethod
    async def save_gap_report(self, report: GapAnalysisReport) -> str:
        """Save a gap analysis report. Returns the report ID."""
        ...

    @abstractmethod
    async def get_gap_report(self, report_id: str) -> Optional[GapAnalysisReport]:
        """Retrieve a gap report by ID."""
        ...

    @abstractmethod
    async def list_gap_reports(
        self, limit: int = 50, offset: int = 0
    ) -> list[GapAnalysisReport]:
        """List gap reports, newest first."""
        ...

    # ── Risk Registers ─────────────────────────────────────────────
    @abstractmethod
    async def save_risk_register(self, register: RiskRegister) -> str:
        """Save a risk register. Returns the register ID."""
        ...

    @abstractmethod
    async def get_risk_register(self, register_id: str) -> Optional[RiskRegister]:
        """Retrieve a risk register by ID."""
        ...

    # ── Evidence Bundles ───────────────────────────────────────────
    @abstractmethod
    async def save_evidence_bundle(self, bundle: EvidenceBundle) -> str:
        """Save an evidence bundle. Returns the bundle ID."""
        ...

    @abstractmethod
    async def get_evidence_bundle(self, bundle_id: str) -> Optional[EvidenceBundle]:
        """Retrieve an evidence bundle by ID."""
        ...

    @abstractmethod
    async def list_evidence_bundles(
        self, limit: int = 50, offset: int = 0
    ) -> list[EvidenceBundle]:
        """List evidence bundles, newest first."""
        ...
```

### File Backend Implementation (evidentia_core/storage/file_backend.py)

```python
"""File-based storage backend.

Stores all data as JSON files in a directory structure:
.evidentia/
├── reports/
│   └── {report_id}.json
├── risks/
│   └── {register_id}.json
└── evidence/
    └── {bundle_id}.json

All files are human-readable, git-friendly, and version-controllable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from evidentia_core.models.evidence import EvidenceBundle
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.risk import RiskRegister
from evidentia_core.storage.base import StorageBackend


class FileBackend(StorageBackend):
    """File-based storage using JSON files."""

    def __init__(self, base_dir: str = ".evidentia"):
        self.base = Path(base_dir)
        self.reports_dir = self.base / "reports"
        self.risks_dir = self.base / "risks"
        self.evidence_dir = self.base / "evidence"
        
        # Create directories
        for d in [self.reports_dir, self.risks_dir, self.evidence_dir]:
            d.mkdir(parents=True, exist_ok=True)

    async def save_gap_report(self, report: GapAnalysisReport) -> str:
        path = self.reports_dir / f"{report.id}.json"
        path.write_text(report.model_dump_json(indent=2))
        return report.id

    async def get_gap_report(self, report_id: str) -> Optional[GapAnalysisReport]:
        path = self.reports_dir / f"{report_id}.json"
        if not path.exists():
            return None
        return GapAnalysisReport.model_validate_json(path.read_text())

    async def list_gap_reports(
        self, limit: int = 50, offset: int = 0
    ) -> list[GapAnalysisReport]:
        files = sorted(self.reports_dir.glob("*.json"), reverse=True)
        results = []
        for f in files[offset:offset + limit]:
            try:
                results.append(GapAnalysisReport.model_validate_json(f.read_text()))
            except Exception:
                continue
        return results

    async def save_risk_register(self, register: RiskRegister) -> str:
        path = self.risks_dir / f"{register.id}.json"
        path.write_text(register.model_dump_json(indent=2))
        return register.id

    async def get_risk_register(self, register_id: str) -> Optional[RiskRegister]:
        path = self.risks_dir / f"{register_id}.json"
        if not path.exists():
            return None
        return RiskRegister.model_validate_json(path.read_text())

    async def save_evidence_bundle(self, bundle: EvidenceBundle) -> str:
        path = self.evidence_dir / f"{bundle.id}.json"
        path.write_text(bundle.model_dump_json(indent=2))
        return bundle.id

    async def get_evidence_bundle(self, bundle_id: str) -> Optional[EvidenceBundle]:
        path = self.evidence_dir / f"{bundle_id}.json"
        if not path.exists():
            return None
        return EvidenceBundle.model_validate_json(path.read_text())

    async def list_evidence_bundles(
        self, limit: int = 50, offset: int = 0
    ) -> list[EvidenceBundle]:
        files = sorted(self.evidence_dir.glob("*.json"), reverse=True)
        results = []
        for f in files[offset:offset + limit]:
            try:
                results.append(EvidenceBundle.model_validate_json(f.read_text()))
            except Exception:
                continue
        return results
```

---

## Appendix E: OSCAL Output Mapping Specification

### Gap Report → OSCAL Assessment Results

Evidentia's gap reports map to OSCAL `assessment-results` as follows:

| Evidentia Concept | OSCAL Assessment Results Element |
|---|---|
| `GapAnalysisReport` | Root `assessment-results` object |
| `GapAnalysisReport.organization` | `metadata.title` |
| `GapAnalysisReport.analyzed_at` | `metadata.last-modified` |
| `GapAnalysisReport.frameworks_analyzed` | `import-ap` references |
| Each `ControlGap` | `result.finding` within `results` |
| `ControlGap.control_id` | `finding.target.target-id` |
| `ControlGap.gap_severity` | `finding.target.status` + custom property |
| `ControlGap.gap_description` | `finding.description` |
| `ControlGap.remediation_guidance` | `finding.response` (remediation) |
| Each `RiskStatement` | `result.risk` within `results` |
| `RiskStatement.risk_level` | `risk.status` |
| `RiskStatement.risk_description` | `risk.description` |
| Each `EvidenceArtifact` | `result.observation` within `results` |
| `EvidenceArtifact.content` | `observation.relevant-evidence` |

### Exporter Implementation (evidentia_core/oscal/exporter.py)

```python
"""Export Evidentia data to OSCAL Assessment Results format."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from evidentia_core.models.gap import GapAnalysisReport


def gap_report_to_oscal_ar(report: GapAnalysisReport) -> dict:
    """Convert a GapAnalysisReport to OSCAL Assessment Results JSON."""
    
    findings = []
    for gap in report.gaps:
        finding = {
            "uuid": str(uuid4()),
            "title": f"{gap.control_id} — {gap.control_title}",
            "description": gap.gap_description,
            "target": {
                "type": "control-id",
                "target-id": gap.control_id,
                "status": {
                    "state": _map_gap_status(gap.implementation_status),
                },
            },
            "props": [
                {"name": "gap-severity", "value": gap.gap_severity, "ns": "https://evidentia.dev"},
                {"name": "priority-score", "value": str(gap.priority_score), "ns": "https://evidentia.dev"},
                {"name": "implementation-effort", "value": gap.implementation_effort, "ns": "https://evidentia.dev"},
            ],
            "related-observations": [],
        }
        
        if gap.remediation_guidance:
            finding["response"] = {
                "uuid": str(uuid4()),
                "lifecycle": "recommendation",
                "description": gap.remediation_guidance,
            }
        
        findings.append(finding)

    oscal_ar = {
        "assessment-results": {
            "uuid": str(uuid4()),
            "metadata": {
                "title": f"Gap Analysis: {report.organization}",
                "last-modified": report.analyzed_at.isoformat(),
                "version": report.evidentia_version,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "tool", "value": "Evidentia"},
                    {"name": "tool-version", "value": report.evidentia_version},
                ],
            },
            "results": [
                {
                    "uuid": str(uuid4()),
                    "title": f"Gap Analysis Results — {', '.join(report.frameworks_analyzed)}",
                    "description": (
                        f"Automated gap analysis of {report.organization}'s control inventory "
                        f"against {', '.join(report.frameworks_analyzed)}. "
                        f"Coverage: {report.coverage_percentage}%. "
                        f"Total gaps: {report.total_gaps}."
                    ),
                    "start": report.analyzed_at.isoformat(),
                    "findings": findings,
                    "props": [
                        {"name": "total-controls-required", "value": str(report.total_controls_required)},
                        {"name": "total-gaps", "value": str(report.total_gaps)},
                        {"name": "coverage-percentage", "value": str(report.coverage_percentage)},
                        {"name": "critical-gaps", "value": str(report.critical_gaps)},
                        {"name": "high-gaps", "value": str(report.high_gaps)},
                    ],
                }
            ],
        }
    }

    return oscal_ar


def _map_gap_status(status: str) -> str:
    """Map Evidentia implementation status to OSCAL finding status."""
    mapping = {
        "missing": "not-satisfied",
        "partial": "not-satisfied",
        "planned": "not-satisfied",
        "not_applicable": "not-applicable",
    }
    return mapping.get(status, "not-satisfied")
```

---

## Appendix F: Error Handling & Observability

### Structured Logging

All Evidentia components use Python's standard `logging` module with structured output. In JSON log mode (for production), every log entry includes:

```json
{
  "timestamp": "2026-04-05T19:22:00.123Z",
  "level": "INFO",
  "logger": "evidentia_core.gap_analyzer.analyzer",
  "message": "Gap analysis complete",
  "extra": {
    "organization": "Acme Corp",
    "frameworks": ["nist-800-53-mod", "soc2-tsc"],
    "total_gaps": 42,
    "coverage_pct": 87.3,
    "duration_ms": 1234
  }
}
```

### Error Classification

Errors are classified into three categories:

1. **User errors** (4xx in API, helpful messages in CLI): Invalid input, missing config, unsupported format. Always include actionable fix instructions.
2. **Integration errors** (5xx/warnings): Upstream service unreachable, authentication failure, rate limit. Include retry information and fallback options.
3. **Internal errors** (5xx): Bugs in Evidentia. Include stack trace in logs (not in user-facing output). Create GitHub issue template with reproduction steps.

### Health Monitoring

The `/health` endpoint (and `evidentia doctor` CLI) performs:

1. **Self-check:** Package versions, catalog loading, crosswalk integrity
2. **Collector health:** For each enabled collector, call `check_connection()` with a 10-second timeout
3. **Storage health:** Verify read/write access to storage backend
4. **LLM health:** If AI features configured, perform a minimal test call (optional, skipped by default to avoid cost)

Response includes degraded state reporting:
```json
{
  "status": "degraded",
  "version": "0.1.0",
  "issues": [
    {"component": "aws-config", "severity": "warning", "message": "Access denied — missing config:DescribeComplianceByConfigRule permission"}
  ]
}
```

---

## Appendix G: Contributor Guide Architecture

### How to Add a New Collector

1. Create a new directory under `packages/evidentia-collectors/src/evidentia_collectors/`:
   ```
   my_service/
   ├── __init__.py
   └── collector.py
   ```

2. Implement the `BaseCollector` interface:
   ```python
   from evidentia_collectors.base import BaseCollector, ConnectionStatus
   
   class MyServiceCollector(BaseCollector):
       name = "my-service"
       display_name = "My Service"
       
       async def check_connection(self) -> ConnectionStatus: ...
       async def collect(self, ...) -> list[EvidenceArtifact]: ...
       def get_supported_controls(self) -> list[str]: ...
   ```

3. Register the collector in `evidentia_collectors/registry.py`

4. Add the collector to `evidentia.yaml` schema in `evidentia/config.py`

5. Write tests using `responses` or `moto` for mocking

6. Document required credentials and IAM permissions in the collector's docstring

### How to Add a New Framework

1. Create the catalog JSON file in `evidentia_core/catalogs/data/`:
   - Use OSCAL format if available from NIST
   - Use Evidentia JSON format if no OSCAL source exists

2. Create the crosswalk JSON file in `evidentia_core/catalogs/data/mappings/`:
   - Document the authoritative source for the mapping
   - Use NIST 800-53 as the source framework (all crosswalks go through NIST)

3. Add the framework to `FrameworkRegistry.list_frameworks()` metadata

4. Add the framework ID to the `FrameworkId` enum in `common.py`

5. Write unit tests verifying catalog loading and crosswalk integrity

6. Update the bundled framework data table in this document

### How to Add a New Output Integration

1. Create a new directory under `packages/evidentia-integrations/src/evidentia_integrations/`:
   ```
   my_output/
   ├── __init__.py
   ├── client.py
   └── formatters.py
   ```

2. Implement the client with:
   - Constructor taking credentials from environment variables
   - `create_gap_issues()` or equivalent method
   - Dry-run mode support
   - Idempotency (don't create duplicates)

3. Add CLI command in `evidentia/cli/push.py`

4. Add API endpoint in `evidentia/api/routers/gaps.py`

5. Document required credentials in the integration's docstring

---

*End of Document*

**Evidentia Architecture & Implementation Plan v1.0.0-draft**  
**April 5, 2026**  
**Apache 2.0 License**
