# Enterprise-grade credibility checklist (v0.7.0)

Evidentia's v0.7.0 release is explicitly targeted at the quality bar
that Big-4 audit firms (Deloitte, PwC, KPMG, EY), FedRAMP Third-Party
Assessor Organizations (3PAOs), and senior GRC officers at regulated
companies would consider production-grade for evidence collection.

This checklist synthesizes requirements from:

- **AICPA** Trust Services Principles (SOC 2 Type II)
- **NIST** SP 800-53 Rev 5 (AU-3 audit content, SR-3 supply chain, SI-2 flaw remediation)
- **NIST** SP 800-218 SSDF v1.1 (PO.3, PW.4, RV.2)
- **FedRAMP** Rev 5 baseline + Continuous Monitoring Playbook
- **CISA** EO 14028 secure software development attestation
- **SSAE 18** AT-C 320 attestation standards
- **AWS** Audit Manager NIST 800-53 Rev 5 framework
- **AWS** Security Hub NIST SP 800-53 Rev 5 standard
- **GitHub** Well-Architected "Implementing the NIST SSDF with GitHub"

Priority tiers:

- **BLOCKER** — gap would fail audit adoption
- **HIGH** — strong enterprise expectation; acceptable with documented remediation plan
- **MEDIUM** — desirable, often documented as "on the roadmap"
- **LOW** — nice-to-have

## BLOCKER items

| # | Item | v0.7.0 status |
|---|---|---|
| B1 | Evidence integrity: SHA-256 digest + cryptographic signature on every finding | ✅ GPG (v0.7.0 initial) + Sigstore/Rekor (v0.7.0 enterprise) |
| B2 | RFC 3339 UTC timestamps on every finding | ✅ `CollectionContext.collected_at` + NIST AU-3 content |
| B3 | No bare `except` in evidence-generation code | ✅ Typed catches + structured log emission in AWS + GitHub collectors. **v0.7.1**: extended to AI features (`risk_statements/`, `explain/`) via the typed `EvidentiaAIError` hierarchy in `evidentia_ai.exceptions` (closes the v0.7.0 HIGH carry-over). |
| B4 | No floating dependencies in lock file | ✅ `pyproject.toml` uses pinned minors; `uv.lock` committed |
| B5 | Completeness attestation per collection run | ✅ `CollectionManifest` with `empty_categories` + `is_complete` + per-resource-type `CoverageCount` |
| B6 | Air-gapped signed evidence path | ✅ GPG works in air-gap; Sigstore refuses and routes operators to GPG |
| B7 | CI enforces OSCAL schema validation | ✅ `compliance-trestle>=4.0` round-trip in `tests/unit/test_oscal/test_trestle_conformance.py`; covers `Extra.forbid` unknown-field detection that NIST's JSON Schema doesn't catch |
| B8 | No sensitive data in logs | ✅ Regex-based secret scrubber in `evidentia_core.audit.logger._scrub` |
| B9 | NIST-approved crypto algorithms | ✅ SHA-256, Ed25519 (via Sigstore), GPG RSA-2048+ |
| B10 | Bounded retry + exponential backoff | ✅ `@with_retry` in AWS + GitHub + Dependabot + Access Analyzer collectors. **v0.7.1**: extended to AI features via `build_retrying`/`build_async_retrying` in `risk_statements/` and `explain/` (sync + async) against the shared `LLM_TRANSIENT_EXCEPTIONS` set (LiteLLM `RateLimitError`/`APIConnectionError`/`Timeout`/`InternalServerError`/`ServiceUnavailableError`/`BadGatewayError`). |

## HIGH items

| # | Item | v0.7.0 status |
|---|---|---|
| H1 | Test coverage ≥ 80% line, ≥ 70% branch | ✅ 862 tests passing; coverage documented in CI |
| H2 | SLSA L2+ reproducible builds + SBOM | ✅ CycloneDX SBOM on release (v0.7.0 Commit 7); SLSA L3 planned for v0.7.x |
| H3 | OSCAL Assessment Results output | ✅ `gap_report_to_oscal_ar` ships since v0.2; v0.7.0 adds back-matter resources with digests |
| H4 | RFC 3161 timestamp authority or Sigstore/Rekor | ✅ Sigstore/Rekor integrated (v0.7.0) |
| H5 | Collector metadata on every finding | ✅ `CollectionContext` (collector_id, collector_version, run_id, credential_identity, source_system_id, filter_applied, pagination_context) |
| H6 | No silent failures; structured logs for every error | ✅ Typed catches + `evidentia.collect.failed` ECS events |
| H7 | Supply-chain security: signed releases + SBOM + Trusted Publisher | ⚠️ SBOM done (v0.7.0); PyPI Trusted Publisher OIDC planned for post-v0.7.0 (operator-blocking on PyPI UI clicks for 12 packages) |
| H8 | Immutable evidence storage + audit trail | ⚠️ Operator responsibility; docs recommend S3 + MFA Delete / git-backed stores |
| H9 | Machine-readable structured logging | ✅ ECS 8.11 + NIST AU-3 + OpenTelemetry via `--json-logs` |
| H10 | Pagination continuation tokens in evidence | ✅ `PaginationContext` on `CollectionContext` + Dependabot collector 100-page safety cap |
| H11 | Atomic collection transactions | ✅ Manifest marks partial runs `is_complete=False` with `incomplete_reason`; findings always carry run_id so partial runs are identifiable |
| H12 | Configuration change audit trail | ✅ `evidentia.config.*` events |
| H13 | Anti-tamper evidence store | ⚠️ Operator responsibility; docs guidance in `docs/evidence-integrity.md` (planned) |
| H14 | Documentation: collection method, limitations, scope | ✅ Every collector has docstring covering scope + blind-spot disclosures (Access Analyzer ships 5 explicit blind-spot entries) |
| H15 | SECURITY.md + responsible disclosure | ⚠️ Present; last-updated stamp to be refreshed at release |

## MEDIUM items

| # | Item | v0.7.0 status |
|---|---|---|
| M1 | Mutation testing ≥ 65% | ❌ Not currently run in CI; planned for v0.8 |
| M2 | Air-gapped deployment mode | ✅ `--offline` flag refuses network egress; GPG signing works offline |
| M3 | Multi-cloud + SaaS support | ⚠️ AWS + GitHub in v0.7.0; Okta, Azure, GCP planned |
| M4 | Performance benchmarks | ⚠️ Not documented; ad-hoc testing on 10k-resource sample |
| M5 | Dry-run mode | ✅ `dry_run=True` kwarg on all collectors; `--dry-run` CLI flag |
| M6 | Custom OSCAL finding fields | ✅ `back-matter.resources[].props[]` with Evidentia-namespaced prop extensions |
| M7 | run_id + idempotency | ✅ ULID run_id on every collection; findings carry it |
| M8 | Prometheus metrics | ❌ Not currently exposed; planned for v0.8 |
| M9 | Public roadmap + regular releases | ✅ `docs/ROADMAP.md`; monthly release cadence |
| M10 | Backward compatibility + deprecation policy | ✅ semver + `control_ids` kwarg still accepted; `legacy-pre-v0.7.0` CollectionContext marker for un-upgraded code |

## LOW items

| # | Item | v0.7.0 status |
|---|---|---|
| L1 | Container image (Docker Hub / ECR / ghcr) | ✅ Published to `ghcr.io/polycentric-labs/evidentia` per release with cosign keyless OIDC signing + SLSA L3 build provenance attestation against the image digest (v0.7.5+). Verifiable via `cosign verify ghcr.io/polycentric-labs/evidentia:vX.Y.Z` (PEP 740-equivalent for OCI) and `gh attestation verify oci://ghcr.io/polycentric-labs/evidentia:vX.Y.Z` (SLSA path). Repo-root `Dockerfile` + CI smoke test on every Dockerfile-touching PR (`.github/workflows/container-build.yml`) provides an early-warning signal independent of release cadence. |
| L2 | SLA documentation | ❌ Not currently documented |
| L3 | Terraform / CloudFormation templates | ❌ Not currently provided |
| L4 | Pre-built compliance profile library | ⚠️ 82 frameworks bundled (v0.2+); not OSCAL Profile format |
| L5 | Evidence diff / comparison tool | ⚠️ `evidentia gap diff` exists for gap reports; not for evidence-level diff |

## Scoring

Using the enterprise-grade scoring rubric:

- **BLOCKER**: **10/10** ✅ (all closed for v0.7.0)
- **HIGH**: 12/15 ✅; 3 with documented remediation plan (H7 OIDC + PEP 740 attestations also closing in v0.7.0)
- **MEDIUM**: 6/10 ✅; 4 deferred
- **LOW**: 2/5 ✅ (L1 closed in v0.7.5)

> Static-analysis findings that have been knowingly accepted instead
> of fixed (e.g., CodeQL false positives on the `validate_within`
> sanitizer, OpenSSF Scorecard `Token-Permissions` accepts on
> release-write permissions) are documented per-finding in
> [`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md).
>
> Performance benchmark numbers (gap-analysis throughput, catalog
> load, UI bundle size, test-suite runtime) with hardware baselines
> + reproducibility recipe live at
> [`docs/benchmarks.md`](benchmarks.md). Closes M4. Updated each
> release as the surface stabilizes.
>
> Public threat model — external input surfaces, sanitization
> layers, and acknowledged gaps — lives at
> [`docs/threat-model.md`](threat-model.md). Reviewed each release;
> full deep-pass walk on every minor + quarterly cadence. Satisfies
> pre-release-review v4 G5 (threat-model existence gate) for the
> v0.8.0 minor.

**v0.7.0 classification: Enterprise-ready, BLOCKER-complete (L3 on
the research's capability-maturity scale).** This is the first
fully-featured enterprise GRC release with all 10 BLOCKER items
satisfied. Operators evaluating Evidentia against competitive
commercial tools (Vanta, Drata, Secureframe) should see technical
parity on audit-integrity, supply-chain transparency, and scope.

The supply-chain hardening narrative is end-to-end:
- **Build provenance**: GitHub Actions workflow with OIDC identity
- **Signed publish**: PyPI Trusted Publisher (OIDC, no long-lived tokens)
- **Per-artifact attestations**: PEP 740 Sigstore attestations on every wheel + sdist, logged to Rekor
- **Container image provenance**: ghcr.io publish with cosign keyless signing + `actions/attest-build-provenance` SLSA L3 build provenance against the image digest (v0.7.5+); independent verification via `cosign verify` (Fulcio identity binding) AND `gh attestation verify oci://...` (SLSA predicate)
- **Software bill of materials**: CycloneDX SBOM attached to every GitHub Release
- **Schema conformance**: `compliance-trestle` round-trip in CI
- **Evidence integrity**: SHA-256 digests + GPG signatures (air-gap) or Sigstore bundles (online) on every AR

## Adoption path

A regulated company evaluating Evidentia for production evidence use
should follow this sequence:

1. **Install with the Sigstore extra**: `pip install 'evidentia-core[sigstore]'`.
2. **Configure air-gap posture** if applicable: set `--offline`
   globally; validate with `evidentia doctor --check-air-gap`.
3. **Pin a single OIDC identity** for Sigstore signing (GitHub
   Actions workflow token, workload identity, or explicit token).
4. **Enable `--json-logs`** and route to your SIEM.
5. **Bind** `evidentia collect` runs to a GRC-scoped IAM role
   (AWS) or fine-grained PAT (GitHub) — principle of least privilege.
6. **Run the baseline collection** and verify every finding carries
   a real (not `legacy-pre-v0.7.0`) `CollectionContext`.
7. **Verify the signed AR** end-to-end with `evidentia oscal verify
   --require-signature` before submitting to auditors.
