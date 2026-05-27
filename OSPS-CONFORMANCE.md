# OSPS Baseline Conformance Statement — Evidentia

> **As of 2026-05-27** (UTC), [Polycentric-Labs/evidentia](https://github.com/Polycentric-Labs/evidentia)
> self-attests conformance with **OSPS Baseline v2026.02.19 Maturity 2**
> (with partial Maturity 3 coverage). This is a self-assessment; no
> third-party audit has been conducted.
>
> **Method**: each control in the OSPS Baseline upstream YAML files
> (commit
> [`ac6bbec8aecf51dce41f62712745f7949ab6bdeb`](https://github.com/ossf/security-baseline/tree/ac6bbec8aecf51dce41f62712745f7949ab6bdeb/baseline))
> was walked against Evidentia's release pipeline + repo state on
> 2026-05-27. Per-control evidence pointers below. Walk methodology +
> JSONL working note documented in `docs/v0.10.6-implementation-plan.md`
> §Task 3.1.
>
> **First-mover claim**: `gh api search/code "filename:OSPS-CONFORMANCE.md"`
> returned `total_count: 0` at 2026-05-27. Evidentia is the first public
> open-source project to ship this artifact in this form (machine-readable
> per-control conformance attestation cross-referenced to upstream
> OSPS Baseline IDs, paired with a CI gate that re-validates every
> claimed-PASS evidence link on every push).

## Conformance summary

The walk covers **64 active assessment-requirements** across 41
top-level controls. (1 assessment-requirement — `OSPS-BR-01.02` — is
marked `state: Retired` upstream and is excluded.)

| Maturity | PASS / Total | Conformance |
|---|---|---|
| Maturity 1 | **24 / 24** | **100%** |
| Maturity 2 | **39 / 41** | **95%** |
| Maturity 3 | **55 / 62** | **89%** |

**Per-family breakdown:**

| Family | PASS | HONEST_GAP | FAIL | Total |
|---|---|---|---|---|
| OSPS-AC (Access Control) | 4 | 2 | 0 | 6 |
| OSPS-BR (Build and Release) | 12 | 0 | 0 | 12 |
| OSPS-DO (Documentation) | 8 | 0 | 0 | 8 |
| OSPS-GV (Governance) | 5 | 1 | 0 | 6 |
| OSPS-LE (Legal) | 4 | 1 | 0 | 5 |
| OSPS-QA (Quality) | 12 | 1 | 0 | 13 |
| OSPS-SA (Security Assessment) | 4 | 0 | 0 | 4 |
| OSPS-VM (Vulnerability Management) | 8 | 2 | 0 | 10 |
| **Total** | **57** | **7** | **0** | **64** |

**Zero FAIL verdicts.** All non-PASS verdicts are documented as
HONEST_GAP with concrete resolution paths (see §Honest gaps below).

## Per-control evidence

Each row references the upstream OSPS Baseline assessment-requirement
ID. Evidence links resolve to Evidentia's `Polycentric-Labs/evidentia`
repository at `main` HEAD. The
[`.github/workflows/verify-osps-conformance.yml`](.github/workflows/verify-osps-conformance.yml)
CI gate re-validates every claimed-PASS evidence link on every push
to `main` (HTTP 200 check via `gh api`).

### OSPS-AC (Access Control)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-AC-01.01 | Use MFA for Sensitive Actions | ✅ PASS | [GOVERNANCE.md](https://github.com/Polycentric-Labs/evidentia/blob/main/GOVERNANCE.md) |
| OSPS-AC-02.01 | Restrict Collaborator Permissions | ✅ PASS | [GOVERNANCE.md](https://github.com/Polycentric-Labs/evidentia/blob/main/GOVERNANCE.md) |
| OSPS-AC-03.01 | Protect the Primary Branch from Accidental Modification | ✅ PASS | [release.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/release.yml) |
| OSPS-AC-03.02 | Protect the Primary Branch from Accidental Modification (deletion) | ✅ PASS | [release.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/release.yml) |
| OSPS-AC-04.01 | Enforce Least Privilege on CI/CD Pipelines (default-deny) | ⚠ HONEST_GAP | (see Honest gaps below) |
| OSPS-AC-04.02 | Enforce Least Privilege on CI/CD Pipelines (per-job minimum) | ⚠ HONEST_GAP | (see Honest gaps below) |

### OSPS-BR (Build and Release)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-BR-01.01 | Prevent Untrusted Input When Building & Releasing (metadata sanitization) | ✅ PASS | [release.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/release.yml) |
| OSPS-BR-01.03 | Prevent Untrusted Input When Building & Releasing (untrusted code isolation) | ✅ PASS | [release.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/release.yml) |
| OSPS-BR-01.04 | Prevent Untrusted Input (trusted collaborator input) | ✅ PASS | [release.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/release.yml) |
| OSPS-BR-02.01 | Assign Unique Version Identifiers (release identifier) | ✅ PASS | [v0.10.5](https://github.com/Polycentric-Labs/evidentia/releases/tag/v0.10.5) |
| OSPS-BR-02.02 | Assign Unique Version Identifiers (per-asset) | ✅ PASS | [v0.10.5](https://github.com/Polycentric-Labs/evidentia/releases/tag/v0.10.5) |
| OSPS-BR-03.01 | Use Encrypted Channels (project channels) | ✅ PASS | [README.md](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md) |
| OSPS-BR-03.02 | Use Encrypted Channels (distribution AITM-protection) | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-BR-04.01 | Publish Change Log With Release | ✅ PASS | [CHANGELOG.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CHANGELOG.md) |
| OSPS-BR-05.01 | Use Standardized Dependency Management Tools | ✅ PASS | [pyproject.toml](https://github.com/Polycentric-Labs/evidentia/blob/main/pyproject.toml) |
| OSPS-BR-06.01 | Include Signatures and Hashes With Release | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-BR-07.01 | Secure Secrets and Credentials (prevent commit) | ✅ PASS | [secret_scanning.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/secret_scanning.yml) |
| OSPS-BR-07.02 | Secure Secrets and Credentials (rotation policy) | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |

### OSPS-DO (Documentation)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-DO-01.01 | Publish User Guides for Basic Functionality | ✅ PASS | [README.md](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md) |
| OSPS-DO-02.01 | Provide Mechanisms for Reporting Defects | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-DO-03.01 | Publish Provenance Verification Instructions (integrity/authenticity) | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-DO-03.02 | Publish Provenance Verification Instructions (signer identity) | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-DO-04.01 | Publish Support Scope and Duration | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-DO-05.01 | Document Security Update Scope and Duration | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-DO-06.01 | Publish Dependency Management Policy | ✅ PASS | [dependabot.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/dependabot.yml) |
| OSPS-DO-07.01 | Provide Instructions on How to Build From Source | ✅ PASS | [README.md](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md) |

### OSPS-GV (Governance)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-GV-01.01 | Publish Project Roles and Responsibilities (member list) | ✅ PASS | [GOVERNANCE.md](https://github.com/Polycentric-Labs/evidentia/blob/main/GOVERNANCE.md) |
| OSPS-GV-01.02 | Publish Project Roles and Responsibilities (role descriptions) | ✅ PASS | [GOVERNANCE.md](https://github.com/Polycentric-Labs/evidentia/blob/main/GOVERNANCE.md) |
| OSPS-GV-02.01 | Provide Public Discussion Mechanisms | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-GV-03.01 | Publish Contribution Guide (process) | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-GV-03.02 | Publish Contribution Guide (acceptance requirements) | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-GV-04.01 | Require Formal Review of Permission Grants | ⚠ HONEST_GAP | (see Honest gaps below) |

### OSPS-LE (Legal)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-LE-01.01 | Require Code Contributors to Assert Right to Commit | ⚠ HONEST_GAP | (see Honest gaps below) |
| OSPS-LE-02.01 | Ensure Project Licenses are Fully Open Source (source) | ✅ PASS | [LICENSE](https://github.com/Polycentric-Labs/evidentia/blob/main/LICENSE) |
| OSPS-LE-02.02 | Ensure Project Licenses are Fully Open Source (release assets) | ✅ PASS | [LICENSE](https://github.com/Polycentric-Labs/evidentia/blob/main/LICENSE) |
| OSPS-LE-03.01 | Maintain and Release Licenses in a Well Known Location (source) | ✅ PASS | [LICENSE](https://github.com/Polycentric-Labs/evidentia/blob/main/LICENSE) |
| OSPS-LE-03.02 | Maintain and Release Licenses in a Well Known Location (release assets) | ✅ PASS | [LICENSE](https://github.com/Polycentric-Labs/evidentia/blob/main/LICENSE) |

### OSPS-QA (Quality)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-QA-01.01 | Publish Source Code and Change History (public read) | ✅ PASS | [evidentia](https://github.com/Polycentric-Labs/evidentia) |
| OSPS-QA-01.02 | Publish Source Code and Change History (git history) | ✅ PASS | [main](https://github.com/Polycentric-Labs/evidentia/commits/main) |
| OSPS-QA-02.01 | Publish Software Dependencies (dependency list) | ✅ PASS | [pyproject.toml](https://github.com/Polycentric-Labs/evidentia/blob/main/pyproject.toml) |
| OSPS-QA-02.02 | Publish Software Dependencies (SBOM) | ✅ PASS | [v0.10.5](https://github.com/Polycentric-Labs/evidentia/releases/tag/v0.10.5) |
| OSPS-QA-03.01 | Address Pass/Fail Checks Before Accepting Changes | ✅ PASS | [test.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/test.yml) |
| OSPS-QA-04.01 | Enforce Security Requirements on All Codebases (codebase list) | ✅ PASS | [README.md](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md) |
| OSPS-QA-04.02 | Enforce Security Requirements on All Codebases (multi-repo equality) | ✅ PASS | [README.md](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md) |
| OSPS-QA-05.01 | Prevent Executables in the Codebase (no generated executables) | ✅ PASS | [.gitignore](https://github.com/Polycentric-Labs/evidentia/blob/main/.gitignore) |
| OSPS-QA-05.02 | Prevent Executables in the Codebase (no unreviewable binaries) | ✅ PASS | [.gitignore](https://github.com/Polycentric-Labs/evidentia/blob/main/.gitignore) |
| OSPS-QA-06.01 | Use Automated Testing in CI/CD Pipelines (run on commit) | ✅ PASS | [test.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/test.yml) |
| OSPS-QA-06.02 | Use Automated Testing in CI/CD Pipelines (test policy doc) | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-QA-06.03 | Use Automated Testing in CI/CD Pipelines (test-update policy) | ✅ PASS | [CONTRIBUTING.md](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md) |
| OSPS-QA-07.01 | Require Merge Approvals (two-person review) | ⚠ HONEST_GAP | (see Honest gaps below) |

### OSPS-SA (Security Assessment)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-SA-01.01 | Publish Design Descriptions of System Actors and Actions | ✅ PASS | [Evidentia-Architecture-and-Implementation-Plan.md](https://github.com/Polycentric-Labs/evidentia/blob/main/Evidentia-Architecture-and-Implementation-Plan.md) |
| OSPS-SA-02.01 | Publish External Interface Descriptions | ✅ PASS | [api-stability.md](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/api-stability.md) |
| OSPS-SA-03.01 | Maintain a Project Security Assessment | ✅ PASS | [threat-model.md](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/threat-model.md) |
| OSPS-SA-03.02 | Maintain a Project Security Assessment (threat model + attack surface) | ✅ PASS | [threat-model.md](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/threat-model.md) |

### OSPS-VM (Vulnerability Management)

| Control | Title | Verdict | Evidence |
|---|---|---|---|
| OSPS-VM-01.01 | Publish Coordinated Vulnerability Disclosure Policy | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-VM-02.01 | Publish Contacts and Process for Reporting Vulnerabilities | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-VM-03.01 | Maintain Private Vulnerability Reporting Process | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-VM-04.01 | Publish Discovered Vulnerabilities | ✅ PASS | [advisories](https://github.com/Polycentric-Labs/evidentia/security/advisories) |
| OSPS-VM-04.02 | Publish Discovered Vulnerabilities (VEX for non-affecting deps) | ⚠ HONEST_GAP | (see Honest gaps below) |
| OSPS-VM-05.01 | Publish and Enforce a Dependency Remediation Policy (SCA threshold) | ✅ PASS | [SECURITY.md](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md) |
| OSPS-VM-05.02 | Publish and Enforce a Dependency Remediation Policy (pre-release SCA) | ✅ PASS | [release-checklist.md](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/release-checklist.md) |
| OSPS-VM-05.03 | Publish and Enforce a Dependency Remediation Policy (block in CI) | ⚠ HONEST_GAP | (see Honest gaps below) |
| OSPS-VM-06.01 | Publish and Enforce an Application Security Testing Policy (SAST threshold) | ✅ PASS | [codeql.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/codeql.yml) |
| OSPS-VM-06.02 | Publish and Enforce an Application Security Testing Policy (block in CI) | ✅ PASS | [codeql.yml](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/codeql.yml) |

## Honest gaps (Maturity 2 + Maturity 3)

The following 7 assessment-requirements are declared as **HONEST_GAP**.
Each gap has a documented resolution path. The first four are
**structurally unreachable in Evidentia's current single-maintainer
posture** — they require ≥2 unassociated contributors and are tied
to the SOC 2 Type I program's segregation-of-duties + additional-governance
milestone (see [`docs/v1.0-transition.md`](docs/v1.0-transition.md)).

| Control | Applicability | Reason | Resolution path |
|---|---|---|---|
| OSPS-AC-04.01 | M2, M3 | Explicit CI/CD permissions audit not yet automated. `release.yml` declares top-level `permissions: contents: read` but other workflows have not been fully audited for default-deny posture. | **v0.10.7 CI gate** — scoped in `docs/v0.10.6-plan.md` §2.E; C7 ships the advisory-mode audit script ahead of the v0.10.7 enforcing gate. |
| OSPS-AC-04.02 | M3 | Per-job least-privilege not yet enforced across all workflows. | **v0.10.7 CI gate** — same workflow-permissions audit as 04.01. |
| OSPS-GV-04.01 | M3 | Formal permission-grant review requires ≥2 unassociated contributors. Single-maintainer project — no reviewer for the maintainer's own permission grants. | **SOC 2 Type I program + second-maintainer onboarding** per `docs/v1.0-transition.md`. Tracked at v1.1+ (post-second-maintainer). |
| OSPS-QA-07.01 | M3 | Two-person merge approval requires ≥2 unassociated contributors. The maintainer is the only reviewer for the maintainer's own PRs. | **SOC 2 Type I program + second-maintainer onboarding** per `docs/v1.0-transition.md`. Tracked at v1.1+ (post-second-maintainer). |
| OSPS-LE-01.01 | M2, M3 | DCO sign-off not yet enforced. Per upstream OSPS-LE-01.01 recommendation, GitHub ToS arguably satisfies (all contributors accept GitHub's contribution-terms clause), but explicit DCO sign-off is the stronger interpretation. Single-maintainer; all commits to date are by the maintainer. | **`.github/workflows/dco.yml` + `Signed-off-by:` trailers** enabled in the same PR that onboards the second contributor (per `GOVERNANCE.md` §Becoming a contributor). |
| OSPS-VM-04.02 | M3 | VEX documents not yet emitted for non-affecting upstream advisories. Per-release `docs/security-review-vX.Y.Z.md` artifacts narrate non-applicability prose-style for upstream-only vulnerabilities, but no formal CycloneDX-VEX or CSAF-VEX artifact is produced. | **`evidentia vex emit` CLI verb** scoped for **v0.11.x**. The existing per-release security-review prose is the human-readable equivalent in the interim. |
| OSPS-VM-05.03 | M3 | `osv-scanner` is run pre-tag locally (manual gate per `docs/release-checklist.md` Step 7) but is NOT yet integrated as a CI-blocking workflow on pull-request. Dependabot security_updates blocks merging via branch protection when a CVE auto-PR is filed, but there is no programmatic SCA-violation block on arbitrary PRs. | **`verify-osv-scan.yml` workflow** scoped for **v0.10.7** per `docs/v0.10.6-plan.md` §11 backlog. |

## Re-validation

This conformance claim is re-validated automatically on every push to
`main` by
[`.github/workflows/verify-osps-conformance.yml`](.github/workflows/verify-osps-conformance.yml).
Every claimed-PASS evidence link in the per-control evidence tables
above is checked via `gh api` for HTTP 200. The workflow also runs:

- **on pull_request to main** — catches regression PRs that would
  break a claimed-PASS link before the PR can merge.
- **on a weekly cron** (Monday 03:00 UTC) — catches link-rot from
  out-of-band repo changes (e.g., a file rename that doesn't go
  through PR review).

If any evidence link 404s, the workflow fails and this doc MUST be
updated (either fix the link, restore the missing file, or downgrade
the verdict to HONEST_GAP with a documented resolution path) before
the next release.

The machine-readable companion at
`.local/pre-release-review/osps-conformance.yaml` (gitignored per the
integration plan's standing operator-deep-dive deferral; the CI gate
re-derives the data from this MD file on each run, and the YAML
companion exists for skill-side tooling that wants structured access
to the same attestation).

A separate schema validator at
[`scripts/validate_osps_conformance_yaml.py`](scripts/validate_osps_conformance_yaml.py)
checks the YAML companion's schema when it's present (CI emits a
warning when it's absent, since it's gitignored and won't exist on
fresh clones — that's expected).

## Versioning + change log

| Date | Version | Change |
|---|---|---|
| 2026-05-27 | v0.10.6 (Phase 3 / commit C3) | Initial publication. 64 active assessment-requirements walked; 57 PASS / 7 HONEST_GAP / 0 FAIL. Maturity 2 conformance at 95% (39/41), partial Maturity 3 at 89% (55/62). |

## Cross-references

- Upstream OSPS Baseline: [`ossf/security-baseline@ac6bbec`](https://github.com/ossf/security-baseline/tree/ac6bbec8aecf51dce41f62712745f7949ab6bdeb/baseline)
  (the pinned commit walked for this attestation).
- Catalog format: the same OSPS Baseline shipped as 3 Evidentia
  framework catalogs at
  [`packages/evidentia-core/src/evidentia_core/catalogs/data/international/osps-baseline-m{1,2,3}.yaml`](packages/evidentia-core/src/evidentia_core/catalogs/data/international/)
  (added in v0.10.6 Phase 1 / commit C1).
- OSCAL conversion: machine-readable OSCAL Catalog v1.2.0 of the
  OSPS Baseline at
  [`packages/evidentia-core/src/evidentia_core/catalogs/data/international/osps-baseline.oscal.json`](packages/evidentia-core/src/evidentia_core/catalogs/data/international/osps-baseline.oscal.json)
  (added in v0.10.6 Phase 1 / commit C1).
- SOC 2 Type I + second-maintainer onboarding milestones:
  [`docs/v1.0-transition.md`](docs/v1.0-transition.md).
- Security policy (CVD + GHSA Private Vulnerability Reporting):
  [`SECURITY.md`](SECURITY.md) + [`.well-known/security.txt`](.well-known/security.txt).
- Project governance (roles, contribution process, DCO posture):
  [`GOVERNANCE.md`](GOVERNANCE.md).
- Threat model (workflow guards for the verify-osps-conformance.yml
  surface): [`docs/threat-model.md`](docs/threat-model.md) §"v0.10.6
  attack-surface delta".

---

*Maintained by the Evidentia maintainers under the OSPS Baseline
project methodology. License-compatible reuse of the upstream OSPS
Baseline IDs + control text is permitted under Apache-2.0 (matching
[`ossf/security-baseline`](https://github.com/ossf/security-baseline)'s
LICENSE).*
