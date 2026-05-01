# Accepted security-tooling findings

> Companion to [`docs/enterprise-grade.md`](enterprise-grade.md).
> Documents the small set of static-analysis / supply-chain
> findings that we have **knowingly accepted** instead of fixing,
> with rationale per finding so an external auditor can read the
> closed-as-accepted alerts without a workflow run id.

The bar for acceptance is high: each finding here represents a
case where (a) the tool's recommended remediation conflicts with a
different security or operational requirement, OR (b) the tool's
flow analysis doesn't recognize a project-internal sanitizer that
already addresses the underlying class. Each entry is dated, links
to the GitHub Security alert, and is reviewed against
[`docs/release-checklist.md`](release-checklist.md) Step 5 every
release.

---

## CodeQL `py/path-injection` false positives

CodeQL's Python path-injection query flags any code path where an
externally-influenced string flows into a `Path()` constructor or
`open()`/`read_text()`/etc. without recognizing custom validators.
Evidentia's [`evidentia_core.security.paths.validate_within`](../packages/evidentia-core/src/evidentia_core/security/paths.py)
helper IS such a sanitizer — landed in v0.7.5 as the S1 path-
injection containment work. CodeQL's default-setup query suite
doesn't carry a model for it, so flow analysis treats it as a
no-op, and any code path that includes a `Path()` operation
downstream of `validate_within` re-flags.

Long-term fix (deferred to v0.7.7 unless reprioritized): migrate
from GitHub's default CodeQL setup to an advanced workflow with a
custom QL pack declaring `validate_within` as a `BarrierGuard` /
`Sanitizer` for the `py/path-injection` configuration. See [GitHub
docs on extending CodeQL data flow](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning).

| Alert | Path | Why CodeQL flags it | Why it's actually safe |
|---|---|---|---|
| **#73** | `packages/evidentia-core/src/evidentia_core/security/paths.py:91` | `candidate.resolve(strict=False)` accepts an externally-influenced Path. | This IS the sanitizer. The next two lines re-resolve the safe-root and assert `is_relative_to`. Every callsite of this function is downstream-safe by construction. |
| **#72** | `packages/evidentia-core/src/evidentia_core/gap_store.py:185` | `path.read_text(encoding="utf-8")` reads from a user-controlled path key. | The `path` variable is the return value of `validate_within(candidate, store)` on line 181, which raised `PathTraversalError` if the resolved candidate sat outside the gap-store directory. Read is on a guaranteed-safe path. |
| **#71** | `packages/evidentia-core/src/evidentia_core/gap_store.py:182` | `path.is_file()` check on a user-controlled path. | Same `validate_within` upstream as #72. The `is_file()` check itself doesn't read content; even if it did, the path is sanitized. |

**Action**: dismiss as `false_positive` with the above rationale via
`gh api repos/allenfbyrd/evidentia/code-scanning/alerts/<n> -X PATCH`.
Each dismissal is publish-authority gated.

---

## OpenSSF Scorecard `Token-Permissions` accepts

GitHub Actions OpenSSF Scorecard scores any job that declares
`contents: write` (or other write permissions) at job level as a
risk, recommending zero-write or step-level grants. Evidentia's
release jobs need write permissions for legitimate reasons that
can't be reduced without losing functionality.

| Alert | Workflow | Permission | Why it's needed |
|---|---|---|---|
| **#75** | `.github/workflows/release.yml:211` | `contents: write` on `publish-container` job | The job's final step uses `softprops/action-gh-release` to **append** the container-image section (digest + cosign verify one-liner + SLSA verify one-liner) to the GitHub Release notes that `publish-pypi` created. Append requires write access to the Release. Same pattern as #29/#30 below. |
| **#30** | `.github/workflows/release.yml` | `contents: write` on `publish-pypi` job | Attaches the CycloneDX SBOM + (v0.7.5+) appends container section. Same `softprops/action-gh-release` flow. |
| **#29** | `.github/workflows/release.yml:22` | `contents: write` (workflow-level) | Identical rationale. |

**Mitigations in place** (so the permission isn't a security
weakening):

- All three jobs run only on tag pushes (`push: tags: v*`), not on
  PRs from forks or untrusted contributors.
- The repo has only one writer (Allen). Branch ruleset enforcement
  + admin-bypass review is tracked in v0.7.6 P0.8 GE3.
- Trusted Publisher OIDC handles PyPI publish; no long-lived tokens.
- The `softprops/action-gh-release` SHA is pinned; v0.7.5 ship
  validated via cosign + SLSA L3 verification end-to-end.

**Action**: dismiss as `won't_fix` with the above mitigations
listed in the dismissal comment.

---

## OpenSSF Scorecard `Pinned-Dependencies` accept

| Alert | File:Line | Pin form | Why Scorecard flags it | Why it's accepted |
|---|---|---|---|---|
| **#74** | `Dockerfile:62` (`pip install evidentia[gui]==0.7.5`) | Exact-version pin (`==X.Y.Z`) | Scorecard wants `--hash=sha256:<digest>` style cryptographic pin | The `evidentia==X.Y.Z` wheel on PyPI is signed with PEP 740 attestations + SLSA L3 build provenance; verification runs in the docker build's pre-PyPI propagation wait step (`pip index versions`) and again post-image via `pypi-attestations verify pypi`. The end-to-end chain is more rigorous than `--hash=sha256:` alone. |

Other `apt-get install` floating-version pins in the Dockerfile are
intentional and already documented in-line per the v0.7.5 S5
work — those alerts have already been suppressed in code-scanning.

**Action**: dismiss #74 as `won't_fix` with the above rationale.

---

## Review cadence

This document is reviewed at every release per the release-checklist
Step 5 acceptance bullet "Code-scanning open-alert count stays at
the prior baseline OR every new HIGH is documented here as
accepted." If a new HIGH appears that isn't covered here, the
release ship is gated until the alert is either fixed, accepted in
this doc with rationale, or dismissed via the GitHub UI.

---

*Last reviewed: v0.7.6 cycle. Created in v0.7.6 to capture the 5
NEW HIGH alerts that surfaced post-v0.7.5 push (3 CodeQL false
positives on `validate_within` + 1 Scorecard `contents: write`
finding on the new `publish-container` job + 1 Scorecard `==X.Y.Z`
pin finding on the Dockerfile).*
