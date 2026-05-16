# Evidentia security assurance case

> Composed from three companion documents per the OpenSSF Best
> Practices Silver-tier `assurance_case` criterion. This file is
> the canonical entry-point — auditors and successors should read
> this first, then drill into the three constituent documents for
> evidence depth.
>
> Reviewed at every release per
> [`docs/release-checklist.md`](release-checklist.md) Step 5.

## What this document is

An "assurance case" is a structured argument that the system
satisfies its security claims, supported by evidence. The OpenSSF
Silver-tier criterion text:

> The project MUST provide an assurance case that justifies why
> its security requirements are met. The assurance case MUST
> include: a description of the threat model, clear identification
> of trust boundaries, an argument that secure design principles
> have been applied, and an argument that common implementation
> security weaknesses have been countered.

Evidentia composes its assurance case across three documents:

1. **Threat model** — [`docs/threat-model.md`](threat-model.md) —
   the system's attack surface inventory, trust boundaries, and
   in-scope / out-of-scope definitions.
2. **Per-release security review** —
   [`docs/security-review-v0.7.9.md`](security-review-v0.7.9.md)
   (latest) — applies CVSS / CWE / EPSS classification to the
   active surface and demonstrates that secure-design principles
   have been applied + common implementation weaknesses
   countered.
3. **Accepted-findings registry** —
   [`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md) —
   documents residual-risk acceptance with explicit rationale per
   accepted finding.

This document stitches the three together into the OpenSSF-
prescribed structure. Each of the three is independently useful;
this file is the auditor's reading guide.

## Threat model description

[`docs/threat-model.md`](threat-model.md) inventories Evidentia's
attack surface across **5 surface tiers** and **~58 named
surfaces** (post-v0.7.9 ship). The document carries three
sections that satisfy the OpenSSF "description of the threat
model + trust boundaries + in-scope / out-of-scope" requirement:

| Threat-model section | What it provides |
|---|---|
| `## Trust boundaries` | Named trust boundaries: User ↔ CLI / User ↔ REST API / User ↔ Web UI / REST API ↔ LLM provider / REST API ↔ cloud-provider collectors / Build CI ↔ PyPI (OIDC Trusted Publisher) / Build CI ↔ Sigstore (keyless OIDC) / Build CI ↔ ghcr.io (cosign keyless OIDC) |
| `## In scope` / `## Out of scope` | Explicit in-scope (the operator's local Evidentia install, REST endpoints they explicitly bind to a network interface, the GitHub Actions release pipeline, the published artifacts on PyPI + ghcr.io + the GitHub Release SBOM) and out-of-scope (the operator's host OS, the operator's network, the LLM provider's hosted inference, downstream consumers' integration code) declarations |
| `## v0.7.x attack-surface deltas` | Per-release attack-surface diff so a successor or auditor can read the cumulative picture incrementally rather than reverse-engineering it from `git log` |

The v0.7.9 ship adds 12 new surfaces (TPRM module + 4 vendor-
risk-collector quartet + OSCAL TPRM emit) inventoried in the
threat-model's
[v0.7.9 section](threat-model.md#v079-attack-surface-delta-shipped-2026-05-04-at-tag-v079).

## Argument: secure design principles applied

[`docs/security-review-v0.7.9.md`](security-review-v0.7.9.md)
demonstrates the application of six established secure-design
principles:

| Principle | How v0.7.9 applies it |
|---|---|
| **Least privilege** | GitHub Actions workflows default to `permissions: contents: read`, with per-job elevation (`contents: write` only on `publish-pypi` + `publish-container`); collector API tokens scoped to read-only (Vanta `vendors:read`, Drata vendor-inventory only, BitSight + SSC at the operator's API-key scope). |
| **Fail-safe defaults** | Pydantic `extra="forbid"` rejects unknown fields by default; offline mode is default-on for the AI module unless explicitly opted-in; security-headers middleware defaults OFF on localhost binds + auto-ON on non-loopback (operator opted into network exposure). |
| **Complete mediation** | Every external input passes through Pydantic validation OR the `validate_within()` path-traversal sanitizer before reaching business logic; vendor inventory validates UUID-shape IDs at the storage layer; manual `HTTPException(400, ...)` per the v0.7.8 F-V08-DAST-3 invariant ensures runtime body errors are mediated through the API's typed error schema. |
| **Separation of privilege** | Sigstore keyless OIDC + Trusted Publisher OIDC (no long-lived secrets to compromise); vendor-risk-collector tokens never flow through CLI args or REST request bodies (env-var only); release workflow's job split ensures publish-pypi and publish-container can be revoked independently. |
| **Defense in depth** | ruff + mypy strict + CodeQL + osv-scanner + Scorecard + manual `/security-review` per release. The /pre-release-review v4 skill mandates `/security-review` invocations at three step boundaries (Step 3, Step 4, Step 6.C). v0.7.9 ran 4 Continuous-variant runs + 1 final Pre-tag run, each surfacing distinct findings. CSV-injection defenses (CWE-1236) on TPRM concentration-report + DD-questionnaire CSV/XLSX render paths. |
| **Allowlist input validation** | Pydantic schemas enumerate accepted shapes; everything else rejected. CLI subcommands enumerate `Literal[]` choices for type / criticality_tier / regulatory_classification etc.; questionnaire formats enumerated via `QuestionnaireFormat` enum. |

Each principle is supported by code references to specific
locations in
[`docs/security-review-v0.7.9.md`](security-review-v0.7.9.md).

## Argument: common implementation weaknesses countered

The per-release security review systematically identifies + closes
common implementation weaknesses by CWE category. v0.7.9-cycle
specific closures:

| CWE | Weakness class | Where countered |
|---|---|---|
| CWE-22 (path traversal) | OSCAL artifact path inputs, vendor-store IDs, SQLite collector paths | `evidentia_core.security.paths.validate_within`; UUID-shape validation in `vendor_store`; mandatory `safe_root` on the SQLite collector REST surface (closed in v0.7.7 P0.5 S1) |
| CWE-78 (OS command injection) | subprocess calls in release-pipeline + git-helper paths | All subprocess calls use `shell=False` + argv-list invocation; no shell interpolation of operator-controlled strings |
| CWE-89 (SQL injection) | Snowflake INFORMATION_SCHEMA queries (defensive even though Snowflake doesn't allow `"` in identifiers by convention) | `_quote_snowflake_identifier()` static helper escapes literal `"` per Snowflake's documented double-up convention (v0.7.9 carry-over fix) |
| CWE-117 (log injection) | New collectors + integrations (v0.7.8 + v0.7.9) | `%r` format on user-controlled values in `_log` calls (v0.7.8 P0.5 S2); _scrub continues to redact secret-shaped patterns |
| CWE-200 (info disclosure) | Stack-trace + URI quoting on error paths | F-002 / F-003 (v0.7.7) closed stack-trace exposure on REST error paths; collectors return `type(e).__name__` driver-class-name only, never the raw exception body |
| CWE-209 (error-message disclosure) | Same as CWE-200 | Same closure |
| CWE-319 (cleartext transmission) | BitSight pagination cross-host + scheme-downgrade attacker model | Cross-host guard refuses to follow `next` URLs pointing off-host; v0.7.9 Continuous F-V09-S1 fix added scheme-downgrade refusal so a malicious upstream `http://...` `next` URL doesn't leak the HTTP Basic auth header over cleartext HTTP |
| CWE-502 (deserialization of untrusted data) | Questionnaire ingest path; YAML / JSON / XLSX inputs | `json.loads` (safe) / `yaml.safe_load` (safe) / `csv.reader` (safe) / `openpyxl.load_workbook(data_only=True)` (no formula evaluation; no VBA macro execution per openpyxl's documented behavior). No `pickle.loads` / `yaml.unsafe_load` anywhere in the codebase. |
| CWE-697 (incorrect comparison) | Drata + SSC pagination payload-key fall-through | Continuous H-2 fix: explicit-key priority `if "data" in data and isinstance(data["data"], list)` instead of `data.get("data") or data.get("results") or []` (the falsy-`[]` fall-through pattern) |
| CWE-770 (resource exhaustion) | Power BI 1MB per-batch byte limit | Continuous F-V08-CR-MEDIUM Power BI fix: `push_rows()` bisects batches whose serialized JSON exceeds 950 KB headroom |
| CWE-835 (loop with unreachable exit) | Vanta + Drata + SSC pagination loops | Stuck-cursor guards (Continuous H-1 + H-3 fixes); monotonic-increase guard for SSC where `page_count` metadata is missing |
| CWE-1188 (insecure default) | SIG BYO XLSX template column-write order | Continuous H-5 fix: prefer column C over column B when writing vendor-metadata responses (real-world Shared Assessments templates put instructions in column B) |
| CWE-693 (protection mechanism failure) | HTTP response security headers | F-V08-DAST-2 closure via new `SecurityHeadersMiddleware` + `--security-headers` flag |
| CWE-1236 (CSV injection) | DD-questionnaire CSV + XLSX render; concentration-report CSV | `_csv_safe()` OWASP single-quote prefix on every operator-supplied user-content cell (vendor name, fourth-party names, region, relationship_owner, regulatory_classification, question_text, notes) |

The v0.7.9-cycle aggregate finding count: **18 HIGH + 1 LOW
security all inline-fixed** + 4 v0.7.8-carry-over MEDIUM
inline-fixed + 17 MEDIUM/LOW deferred to v0.7.10 with explicit
rationale + **0 unfixed findings at v0.7.9 ship**.

The full per-finding mapping with CVSS estimates, CWE references,
EPSS likelihood, and disposition + commit links is in
[`docs/security-review-v0.7.9.md` §Findings — bug-bucket
table](security-review-v0.7.9.md#findings--bug-bucket-table).

## Argument: residual risk explicitly accepted

[`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md)
documents the small set of static-analysis / supply-chain findings
that have been knowingly accepted instead of fixed, with rationale
per finding. The doc is reviewed at every release per
release-checklist.md Step 5. v0.7.9 review confirmed all prior
acceptances remain valid and added no net-new entries beyond the
existing categories (CodeQL `py/path-injection` false positives
on `validate_within` + Scorecard `Token-Permissions` accepts on
the release-workflow `contents: write` declarations + Scorecard
`Pinned-Dependencies` accept on the Dockerfile `==X.Y.Z` pin).

## Continuity assurance

The assurance case includes operational continuity per the
OpenSSF Silver-tier `access_continuity` MUST criterion. The
project's continuity plan is documented separately in
[`docs/access-continuity.md`](access-continuity.md). Key
elements:

- Sigstore keyless OIDC + Trusted Publisher OIDC means **no
  offline private signing keys exist** that could be lost with
  the maintainer.
- Operational SLA: the project commits to resuming normal
  operations (issues / PRs / releases) within 7 calendar days of
  confirmation of loss of support.
- Documented step-by-step recovery procedure (GitHub Support
  ticket OR fork-and-redirect; PyPI project-owner-role transfer
  ticket; GHCR + cosign re-bind via successor's repo write
  access).
- Named successor + emergency contact maintained in the
  maintainer's encrypted password manager + will / estate
  documents (kept private to avoid social-engineering risk).

## Compliance framework cross-mapping

The assurance case satisfies (in addition to the OpenSSF Silver
`assurance_case` criterion):

- **NIST SSDF v1.1**: PS.3.1 (protect releases from unauthorized
  changes), RV.1.1 (identify + confirm vulnerabilities prior to
  release), RV.1.3 (analyze vulnerabilities + identify root
  causes)
- **SLSA Level 3**: build provenance, build platform isolation
- **ISO 27001:2022**: Annex A 8.25 (secure development lifecycle),
  8.28 (secure coding)
- **SOC 2 Type II**: CC7.1 (vulnerability management), CC8.1
  (change management)
- **DORA (EU 2022/2554)**: Article 9(4) (operational resilience
  testing), Article 28(7) (third-party risk register —
  materially advanced by the v0.7.9 TPRM module)
- **CISA Secure by Design Pledge**: pillars 4 (security patches),
  6 (vulnerability disclosure), 7 (CVE handling)

The full per-control mapping is in
[`docs/security-review-v0.7.9.md` §Compliance framework
mapping](security-review-v0.7.9.md#compliance-framework-mapping).

## How to verify this assurance case

An auditor or successor verifying the assurance case should:

1. Read this document end-to-end (the entry point).
2. Open [`docs/threat-model.md`](threat-model.md) and verify the
   trust-boundaries + in-scope / out-of-scope sections match the
   reality of the deployed code.
3. Open
   [`docs/security-review-v0.7.9.md`](security-review-v0.7.9.md)
   and spot-check 2-3 of the cited CWE-counter rows against the
   referenced commits.
4. Open
   [`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md)
   and verify each accepted finding's rationale against the GitHub
   code-scanning alert queue at
   [`https://github.com/polycentric-labs/evidentia/security/code-scanning`](https://github.com/polycentric-labs/evidentia/security/code-scanning).
5. Open [`docs/access-continuity.md`](access-continuity.md) and
   verify the operational SLA + recovery procedure are concrete
   + executable.
6. Run the Step-7 post-tag verification commands (PEP 740 verify,
   cosign verify, osv-scanner --sbom, docker run smoke,
   Scorecard delta) against the most recent release tag to
   confirm the secure-release infrastructure is operational.

If any verification step fails, file an issue on
[`https://github.com/polycentric-labs/evidentia/issues`](https://github.com/polycentric-labs/evidentia/issues)
or contact the maintainer per
[`SECURITY.md`](../SECURITY.md).

## Plan maintenance

This document is updated:

- At every release (Step 5 of release-checklist.md) — the
  cited security-review-v*.md filename rolls forward to the
  current release.
- When the threat model changes materially (new attack-surface
  delta added; trust boundaries restructured; in-scope /
  out-of-scope re-drawn).
- When a new CWE category is added to the "common implementation
  weaknesses countered" table — typically once per release-cycle
  finding.
- When the accepted-findings registry adds or removes an entry.
- When the access-continuity plan changes structurally.

---

*Created 2026-05-04 for v0.7.9 P0.6 OpenSSF Silver-tier prep.
Satisfies the `assurance_case` MUST criterion. Companion to
[`docs/threat-model.md`](threat-model.md) +
[`docs/security-review-v0.7.9.md`](security-review-v0.7.9.md) +
[`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md) +
[`docs/access-continuity.md`](access-continuity.md). Reviewed at
every release; full review on a quarterly cadence.*
