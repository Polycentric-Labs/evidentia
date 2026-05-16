# Evidentia release checklist

> Step-6 deliverable from the v0.7.0 comprehensive pre-tag review
> (compiled 2026-04-25). Comprehensive per-release update list to
> ensure future consistency and uniformity in accordance with best
> GRC and DevSecOps practice. Run this checklist for every release —
> patch, minor, or major.
>
> **This checklist is self-referential** — Step 0 below is "review
> and update this checklist itself" so it stays current as the
> project evolves.
>
> Cross-link to: [testing-playbook.md](testing-playbook.md) (the
> operational test loop), [enterprise-grade.md](enterprise-grade.md)
> (the quality bar), [capability-matrix.md](capability-matrix.md)
> (last release's test snapshot), [v0.7.2-plan.md](v0.7.2-plan.md)
> (the next release's scope), [v0.7.1-plan.md](v0.7.1-plan.md)
> (the prior release's scope, SHIPPED 2026-04-26).

---

## Step 0 — Review this checklist

Before doing anything else: **scan this document end-to-end** and
update any item that is now stale (new package added, new doc
created, new workflow added, etc.). A stale checklist gives you
false confidence; an honest checklist catches real bugs.

If the project has changed materially since the last release (new
package, new collector, new top-level config, new workflow), add
the corresponding new checklist items here.

---

## Step 1 — Pre-release scope confirmation

Before writing any code for a release:

- [ ] Read `docs/<X.Y.Z>-plan.md` (or `docs/ROADMAP.md` if no plan
      doc exists for this release). Confirm scope is locked.
- [ ] Verify any required design decisions for this release are
      decided (e.g., v0.7.1 had 4 design decisions D1-D4).
- [ ] Confirm any deferred items from the prior release's
      `capability-matrix.md` HIGH bucket are scheduled or explicitly
      re-deferred.
- [ ] Open a release tracking issue on GitHub describing scope.

---

## Step 2 — Version bumps + dependency pins

For every release (patch / minor / major):

- [ ] Bump `version = "X.Y.Z"` in **all 7** pyproject.toml files:
  - `pyproject.toml` (workspace root)
  - `packages/evidentia/pyproject.toml`
  - `packages/evidentia-core/pyproject.toml`
  - `packages/evidentia-ai/pyproject.toml`
  - `packages/evidentia-collectors/pyproject.toml`
  - `packages/evidentia-integrations/pyproject.toml`
  - `packages/evidentia-api/pyproject.toml`
- [ ] Bump `"version": "X.Y.Z"` in `packages/evidentia-ui/package.json`.
- [ ] **Bump inter-package dep pins** atomically. Pattern:
      `>=PREV.0,<X.0` → `>=X.0,<NEXT.0` across:
  - `packages/evidentia/pyproject.toml` (5 pins: evidentia-core,
    -ai, -collectors, -integrations, -api in `[gui]` extra)
  - `packages/evidentia-api/pyproject.toml` (2 pins: -core, -ai)
  - `packages/evidentia-ai/pyproject.toml` (1 pin: -core)
  - `packages/evidentia-collectors/pyproject.toml` (1 pin: -core)
  - `packages/evidentia-integrations/pyproject.toml` (1 pin: -core)
- [ ] **Why this matters**: Step 3 of the v0.7.0 review caught a real
      bug where `version = "..."` was bumped but inter-package pins
      were not, producing a within-release version mismatch for raw
      pip users (commit `25ccca8`).
- [ ] Run `uv sync --all-extras --all-packages` to regenerate `uv.lock`.
- [ ] Verify with `git diff packages/*/pyproject.toml` that 9 pin
      lines changed (not just 7 version lines).

---

## Step 3 — CHANGELOG

- [ ] Rename `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] Add a fresh `## [Unreleased]` block above with
      `_No changes yet on the vX.Y.Z+1 development branch._`.
- [ ] Write a 2-3 paragraph release-summary block at the top of the
      new entry. Include test count (`uv run pytest -q | tail -1`),
      headline features, and a cross-link to any deliverable docs
      from a pre-tag review (e.g., positioning-and-value.md,
      capability-matrix.md, vX.Y.Z+1-plan.md).
- [ ] Add a "Deferred to vX.Y.Z+1" section if applicable, with
      design rationale.
- [ ] Verify CHANGELOG renders cleanly in Markdown preview.

---

## Step 4 — Documentation refresh

- [ ] Update `docs/ROADMAP.md`:
  - Mark this release as SHIPPED with a 1-paragraph summary.
  - Add a "vX.Y.Z+1 — NEXT" section pointing at
    `docs/<next-version>-plan.md`.
  - Update the `**Last updated:**` line in the header.
- [ ] Update `docs/enterprise-grade.md` if any BLOCKER / HIGH /
      MEDIUM / LOW items moved status. Refresh the BLOCKER score.
- [ ] Verify `README.md` "Current status" section reflects the new
      version. Update version-callout banners.
- [ ] If a `docs/positioning-and-value.md` re-sync is due (quarterly
      cadence — see [`MEMORY.md` pointer](pointer_evidentia_positioning_and_value.md)):
  - Re-run the 7 research streams per the recipe in MEMORY.md
  - Snapshot the prior version as `docs/positioning-and-value-YYYY-Q[N].md`
  - Promote new synthesis to canonical `docs/positioning-and-value.md`
  - Update the version-history table in the doc
- [ ] Update `docs/log-schema.md` if any new `EventAction` entries
      were added in this release.
- [ ] If new CLI commands or REST endpoints were added, update the
      counts and command lists in:
  - `README.md` §3.4 (REST endpoint count) + §"Typer + Rich CLI"
  - `docs/capability-matrix.md` §Surface tier 7 / 8
- [ ] If the OpenSSF Best Practices badge tier changed in this
      release cycle (Passing → Silver, Silver → Gold), verify the
      [README badge embed](../README.md) renders the correct tier
      and add a CHANGELOG entry under "Added" or "Changed"
      referencing the new tier. Roadmap:
      [`docs/openssf-best-practices-badge.md`](openssf-best-practices-badge.md).

---

## Step 5 — Test gate

Run from a clean worktree:

```bash
uv sync --all-extras --all-packages
uv run --no-sync ruff check
uv run --no-sync python -m mypy \
  packages/evidentia-core packages/evidentia-collectors \
  packages/evidentia-api packages/evidentia-ai \
  packages/evidentia-integrations packages/evidentia
uv run --no-sync python -m pytest -q --cov=packages
uv build --all-packages
uvx twine check dist/*
```

**For releases that touch `Dockerfile` or
`.github/workflows/container-build.yml`** — also run a local
Docker build BEFORE tag. The tag-triggered `release.yml` doesn't
exercise the Dockerfile, and the PR-triggered
`container-build.yml` only fires after push-to-main with
Dockerfile changes — meaning a broken `Dockerfile` will only
surface in CI AFTER the tag has shipped. Added to the checklist
in v0.7.4 after the v0.7.3 ship surfaced exactly this gap (3
wrong CLI invocations in the Dockerfile + smoke-test workflow
that the pre-tag gates didn't catch).

```bash
docker build -t evidentia:rc .
docker run --rm evidentia:rc version          # expect "Evidentia vX.Y.Z"
docker run --rm evidentia:rc catalog list     # expect framework table
docker rmi evidentia:rc
```

Acceptance:

- [ ] ruff: `All checks passed!`
- [ ] mypy: `Success: no issues found in N source files`
- [ ] pytest: ≥ 857 passed (the v0.7.0 baseline; will grow over
      time), ≤ 8 skipped, 16 benign Tier-C warnings
- [ ] `uv build --all-packages`: 6 evidentia-* wheels + sdists at the
      new version (no shim wheels)
- [ ] `uvx twine check dist/*`: every distribution PASSED
- [ ] (If Dockerfile / container-build.yml touched) local
      `docker build` succeeds; in-image `evidentia version` and
      `evidentia catalog list` return expected output
- [ ] (v0.7.5+) Dockerfile pin updated to current release version
      (`pip install evidentia[gui]==X.Y.Z`); local `docker build` AND
      in-image HEALTHCHECK against `/api/health` (NOT `/health` —
      the SPA fallback would mask a broken API) succeed

---

## Step 5.5 — Doc consistency sweep (v0.7.12+)

Per Allen's 2026-05-04 directive ("ensure documentation is
comprehensively updated for consistency across the board, and
that each release triggers another internally consistent
documentation update"), every release MUST run a doc-consistency
sweep before the tag. This is the in-repo public-facing
counterpart to the pre-release-review v4 skill's per-step
`references/doc-consistency-checklist.md`.

Cross-doc invariants to verify (pre-tag):

- [ ] **Test count** consistent across README, CHANGELOG, recent
      docs: bump to current release's pytest count
- [ ] **Source-file count** consistent ("across N source files")
- [ ] **Bundled catalog count** consistent (canonical via
      `evidentia_core.catalogs.registry.FRAMEWORK_METADATA` —
      currently 89 post-v0.7.9)
- [ ] **Package count** consistent (6 Python wheels at PyPI:
      evidentia + evidentia-core + evidentia-ai +
      evidentia-collectors + evidentia-integrations + evidentia-api;
      evidentia-ui is a Vite project, NOT a Python wheel)
- [ ] **Latest version references** match the current release
      (no straggler "v0.7.X" where X is one or more behind)
- [ ] **Cross-doc links resolve** — every `[link](other.md)`
      points at an existing file
- [ ] **Feature-claim consistency** — same feature described
      same way across README + docs/positioning-and-value.md +
      docs/capability-matrix.md
- [ ] **Capability-matrix freshness** — surfaces tested count +
      revalidation date current
- [ ] **threat-model.md delta** — append a v{X.Y.Z}-delta sub-
      section covering any new public surface
- [ ] **enterprise-grade.md** — every BLOCKER / HIGH / MEDIUM /
      LOW row reflects current shipped state
- [ ] **ROADMAP.md** — current release marked SHIPPED; next
      release promoted to NEXT
- [ ] **AI-assistance acknowledgment** in README — Allen's
      per-release manual update; flag if missing

Apply via Grep/Edit; commit as a single
`docs(consistency):` commit per release.

---

## Step 6 — Inconsistency scour

Per the testing-playbook 3-pass scour pattern:

```bash
# Pass 1: stale name references (must only appear in CHANGELOG /
# RENAMED.md / scripts/_create_shim_packages.py / scripts/_rename_content.py)
grep -ri "controlbridge"

# Pass 2: prior-version mentions (must only appear in CHANGELOG
# entries documenting prior versions)
grep -ri "PREV.X.Y"
grep -ri "X.Y-1.0"

# Pass 3: current-version coverage (should appear in 7 pyproject.toml
# + package.json + CHANGELOG + ROADMAP + enterprise-grade.md +
# capability-matrix.md as the current release)
grep -ri "X.Y.Z"

# Email leak audit (must return zero hits)
git log --all --format="%ae" | sort -u | grep "@allenfbyrd.com$" || echo "OK: zero non-noreply emails"
```

- [ ] Zero stale-name hits outside expected files.
- [ ] Prior-version mentions only in historical CHANGELOG entries.
- [ ] Current-version mentioned consistently across all sources.
- [ ] No real email addresses in commit history (only noreply forms).

---

## Step 7 — External repo + service review

```bash
gh repo view polycentric-labs/evidentia --json name,description,isArchived,defaultBranchRef
gh secret list --env pypi --repo polycentric-labs/evidentia
gh api repos/polycentric-labs/evidentia/environments/pypi --jq '{name, url, deployment_branch_policy}'
gh api repos/polycentric-labs/evidentia/branches/main/protection --jq '{required_status_checks, required_pull_request_reviews, enforce_admins, allow_force_pushes, allow_deletions}'
gh search commits --author-email allen@allenfbyrd.com --owner polycentric-labs  # zero hits
```

- [ ] Repo About description is current (no stale "Previously: ..." text).
- [ ] PyPI environment exists.
- [ ] PyPI Trusted Publisher entries exist for all 6 published packages
      (verify via `https://pypi.org/manage/project/<name>/settings/publishing/`).
- [ ] Zero `allen@allenfbyrd.com` commits across all owned repos.
- [ ] **Branch protection on `main` still active** (added in v0.7.2
      post-audit hardening). Required status checks include the test
      matrix + ruff + mypy + scorecard. `allow_force_pushes` and
      `allow_deletions` both `false`. If protection has been
      accidentally removed, re-apply per the rule documented in
      [`SECURITY.md`](../SECURITY.md) before tagging.
- [ ] **`pypi` environment branch policy correct**: with branch
      protection in place,
      `deployment_branch_policy.custom_branch_policies` should be
      `true` and the policy should include both `main` and `v*`
      (the tag-triggered release path needs to deploy from a tag,
      not just a branch). If only `main` is allowed, tag pushes will
      block at the deployment-protection gate.
- [ ] **Dependabot review** — check the open Dependabot PR queue
      (`gh pr list --label dependencies --state open`). For the
      week-of-ship batch, either roll the PRs in (security updates +
      low-risk patch bumps) or defer them to the next release with
      a documented reason. Don't ship next to a security advisory
      that has an open auto-PR.
- [ ] **SECURITY.md vulnerability-coordination flow** — confirm
      `SECURITY.md` is current: SLA still accurate (3 business days
      initial / 10 business days triage), 90-day disclosure timeline
      still applies, supported-versions table reflects the
      single-supported-patch policy as of this release. If a CVE
      shipped between releases, ensure its handling is documented.

---

## Step 8 — Tag and push (the irreversible step)

**STOP for explicit user approval before proceeding.** Surface a
comprehensive pre-tag overview including:

- Commit list since the prior release tag
- Test results (passed / skipped / warnings)
- Build artifacts (6 wheels + 6 sdists at new version)
- Scour findings (zero stale references)
- External services state (PyPI publishers, GitHub repo)
- Known deferrals (HIGH-bucket items deferred to next release)

After explicit approval:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z — <one-line summary>"
git push origin main          # if main has unpushed commits
git push origin vX.Y.Z         # the tag triggers release.yml
gh run watch                   # monitor the release workflow
```

If the release.yml workflow fails:

- For OIDC bootstrap issues (per-package PyPI Trusted Publisher
  registration mismatch), check the per-package
  `https://pypi.org/manage/project/<name>/settings/publishing/`
  page; correct the entry; re-trigger via re-pushing the tag (delete
  and re-push, or push a new patch tag).
- For SBOM / attestation issues, fix the workflow YAML, push the
  fix, push a new tag (don't reuse the failed tag).
- For partial publishes (some wheels published, others 403), fix
  the failing publisher then re-run; `skip-existing: true` in
  `release.yml` makes retries idempotent.

---

## Step 9 — Post-release verification

Within 30 minutes of `release.yml` reporting success:

- [ ] PyPI: each of the 6 packages shows version X.Y.Z at
      `https://pypi.org/project/<name>/`.
- [ ] **Codecov badge** registers ≥80% coverage (post-v0.7.12 fix:
      coverage.xml emits repo-relative paths via `[tool.coverage.run]
      relative_files = true` so Codecov's path matcher resolves
      against the GitHub tree).

### Step 9.5 — Release notes audit (v0.7.12+)

Per Allen's 2026-05-04 directive ("review all release notes for
missing entries and update accordingly, commit that practice to
memory for each release as well"), every release MUST audit the
GitHub Release body for completeness post-tag.

For the just-tagged release `vX.Y.Z`, verify the release body
contains:

- [ ] Body present (not auto-generated empty default)
- [ ] CHANGELOG `[X.Y.Z]` block content matches the release body
      (or release body summarizes correctly)
- [ ] Container image stanza (post-v0.7.5; the Dockerfile-
      published releases) — `ghcr.io/polycentric-labs/evidentia:vX.Y.Z`
      with image digest
- [ ] PEP 740 verification stanza — pypi-attestations verify
      command line that an operator can copy-paste
- [ ] Cosign verify stanza for the container (post-v0.7.5)
- [ ] CycloneDX SBOM noted as a release asset
- [ ] Step 7 post-tag verification snapshot (v4 pre-release-
      review skill output)
- [ ] Hot-fix mention if applicable (e.g., v0.7.4 fixed the
      v0.7.3 Dockerfile invocation; v0.7.7.1 fixed v0.7.7's
      container-pin drift)

Per the publishing-authority protocol in `~/.claude/CLAUDE.md`,
any `gh release edit` on a published release is a public-surface
mutation and requires explicit per-action approval — surface
the diff before mutating.

For prior releases (v0.7.0 → previous-X.Y.Z), the same audit
runs once per cycle to catch any historical gaps. v0.7.12
introduced this practice retroactively.

### Step 9.6 — Other PyPI checks

- [ ] PyPI per-file pages show the "Provenance" / PEP 740 attestation
      section with the GitHub Actions workflow URL + commit SHA.
- [ ] PyPI per-file pages show the "Provenance" / PEP 740 attestation
      section with the GitHub Actions workflow URL + commit SHA.
- [ ] **Verify PEP 740 publish attestations (PyPI path)** — primary
      verifier for the per-file Sigstore-signed PEP 740 attestation
      that PyPA's publish action uploads alongside each wheel/sdist:
      ```bash
      uvx pypi-attestations verify pypi \
          --repository https://github.com/polycentric-labs/evidentia \
          "pypi:evidentia_core-X.Y.Z-py3-none-any.whl"
      ```
      Repeat for the other 5 wheels. Expect `OK: <wheel>`.
      `gh attestation verify` does NOT validate this — it defaults
      to the SLSA provenance v1 predicate, while PEP 740 publish
      attestations use `https://docs.pypi.org/attestations/publish/v1`.
      Use the SLSA-path verifier below for `gh attestation verify`.
- [ ] **Verify SLSA L3 build provenance (GitHub path)** — secondary
      verifier covering the build-provenance attestation that
      `actions/attest-build-provenance` stores under the repo's
      Attestations endpoint (added in v0.7.3 S3 per
      [`docs/v0.7.3-plan.md`](v0.7.3-plan.md)):
      ```bash
      gh attestation verify dist/evidentia_core-X.Y.Z-py3-none-any.whl \
          -R Polycentric-Labs/evidentia
      ```
      Expect `Loaded digest sha256:... ` and `OK`. The same command
      also validates the CycloneDX SBOM's attestation
      (`gh attestation verify evidentia-sbom.cdx.json -R Polycentric-Labs/evidentia`).
      Pre-v0.7.3 releases (v0.7.0/v0.7.1/v0.7.2) return HTTP 404
      because they emit only the PEP 740 publish predicate; only
      v0.7.3+ releases carry the SLSA build-provenance predicate
      that `gh attestation verify` looks for.
- [ ] CycloneDX SBOM attached to the GitHub Release.
- [ ] CHANGELOG entry renders correctly on GitHub.
- [ ] `pip install evidentia==X.Y.Z` from a clean venv succeeds; CLI
      commands work end-to-end. Also verify `pip install "evidentia[gui]==X.Y.Z"`
      pulls in `evidentia_api` (the `[gui]` extra; required to import
      the FastAPI surface).
- [ ] **(v0.7.5+) Container image published to ghcr.io** — pulls
      successfully and the in-image CLI works:
      ```bash
      docker pull ghcr.io/polycentric-labs/evidentia:vX.Y.Z
      docker run --rm ghcr.io/polycentric-labs/evidentia:vX.Y.Z version
      docker run --rm ghcr.io/polycentric-labs/evidentia:vX.Y.Z catalog list | head -5
      ```
- [ ] **(v0.7.5+) Verify cosign keyless signature on the image** —
      validates the OIDC identity binding (release.yml@refs/tags/v*):
      ```bash
      cosign verify ghcr.io/polycentric-labs/evidentia:vX.Y.Z \
          --certificate-identity-regexp 'https://github\.com/Polycentric-Labs/evidentia/\.github/workflows/release\.yml@refs/tags/v.*' \
          --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
      ```
      Expect "Verified OK" + the certificate identity URL printed.
- [ ] **(v0.7.5+) Verify SLSA build provenance on the image digest**
      — independent of cosign, validates the build-provenance predicate:
      ```bash
      gh attestation verify oci://ghcr.io/polycentric-labs/evidentia:vX.Y.Z \
          -R Polycentric-Labs/evidentia
      ```
      Expect "verified" + the workflow run id matching the release.
- [ ] **(v0.7.5+) Tag and `:latest` resolve to same digest** — sanity
      check the rolling-pointer is up to date:
      ```bash
      docker buildx imagetools inspect ghcr.io/polycentric-labs/evidentia:vX.Y.Z --raw | grep -i digest
      docker buildx imagetools inspect ghcr.io/polycentric-labs/evidentia:latest --raw | grep -i digest
      # both should print the same sha256:... line
      ```

---

## Step 10 — Post-release housekeeping

Within 1-3 days:

- [ ] Update MEMORY.md pointer entries for the shipped version.
- [ ] Archive any merged feature branches.
- [ ] Open GitHub issues for any known follow-ups discovered during
      the release process.
- [ ] If this is the first release after a major review, update
      `docs/capability-matrix.md` with any new bug findings + their
      resolution status.
- [ ] Outreach (per `docs/positioning-and-value.md` §12.5):
  - Tweet / Substack post / LinkedIn announcement
  - Engage 1-2 of the top-4-to-pitch voices (Mike Privette,
    AJ Yawn, Greg Elin, FedRAMP team)
  - Submit to OSCAL Plugfest if not already done
  - Open issue on `oscal-compass/community` for new interop
    scenarios if applicable
- [ ] Optional manual PyPI yank operations (e.g., yank shim wheels
      from prior versions if a contract specified yank at a future
      version — we did this for v0.5.1 controlbridge-* shims at v0.7.0).

---

## Step 11 — Quarterly cadence (independent of releases)

Run quarterly regardless of release schedule:

- [ ] Re-sync `docs/positioning-and-value.md` per the
      [`research_resync_automation_pattern.md`](pointer_research_resync_automation_pattern.md)
      MEMORY pointer. Snapshot to dated file; review diff; promote
      to canonical.
- [ ] Refresh `docs/enterprise-grade.md` if standards have evolved
      (NIST SSDF v1.X, FedRAMP RFC-NNNN, EU regulation enforcement
      timelines).
- [ ] Run `gh attestation verify` against a recent release to confirm
      the Sigstore / Rekor chain still validates.
- [ ] Verify Dependabot has been keeping `actions` and Python deps
      current. Apply security-only PRs immediately; batch other
      updates monthly.
- [ ] Check OpenSSF Scorecard score (after v0.7.1 ships the
      Scorecard workflow). Address any regressions.

---

## DevSecOps + GRC alignment

This checklist explicitly aligns with:

- **NIST SSDF v1.1** (PO.3 Implement Supporting Toolchains, PW.4 Reuse
  Existing, RV.2 Identify and Mitigate Vulnerabilities)
- **OpenSSF Scorecard** (Pinned-Dependencies, SBOM, Signed-Releases,
  Security-Policy)
- **CISA Secure by Design Pledge** (signed software, transparency)
- **PEP 740** (Index-Hosted Attestations for Python Package Index)
- **SLSA L3** (build provenance with isolated builders, target for
  v0.7.2 per `docs/v0.7.2-plan.md` item S3 — deferred from v0.7.1
  when that release narrowed to P0-only AI features hardening)

The 11 steps map to GRC release-management discipline:

| Step | GRC discipline |
|---|---|
| 0 (this checklist) | Continuous control monitoring (CCM) |
| 1 (scope) | Change management |
| 2-4 (versions/CHANGELOG/docs) | Configuration management baseline |
| 5 (test gate) | Verification & validation |
| 6 (scour) | Configuration audit |
| 7 (external review) | Third-party access management |
| 8 (tag/push) | Approved change deployment |
| 9 (verification) | Release verification |
| 10 (housekeeping) | Post-implementation review |
| 11 (quarterly) | Continuous monitoring |

---

## Future automation candidates

Items currently manual that could be scripted/automated:

- **Step 2 (version bumps)**: a generalized `_bump_version.py` script
  parameterized by current and target versions, handling all 7
  pyproject.toml + package.json + 9 inter-package pins atomically.
  See deprecation header on the existing one-shot
  `scripts/_bump_version.py`.
- **Step 6 (scour)**: a `scripts/_release_scour.sh` script running the
  three grep passes + the email-leak audit.
- **Step 7 (external review)**: a `scripts/_release_external_check.sh`
  script wrapping the gh API calls.
- **Step 11 (quarterly research re-sync)**: per
  `pointer_research_resync_automation_pattern.md`, can run as a
  CronCreate-scheduled session or a GitHub Action workflow.

---

*End of release-checklist.md. Cross-link from MEMORY.md so future
Claude sessions auto-load this checklist when a release is being
prepared. Step 0 self-reference ensures the checklist itself is
maintained.*
