# Evidentia release checklist

> Step-6 deliverable from the v0.7.0 comprehensive pre-tag review
> (compiled 2026-04-25). Comprehensive per-release update list to
> ensure future consistency and uniformity in accordance with best
> GRC and DevSecOps practice. Run this checklist for every release -
> patch, minor, or major.
>
> **This checklist is self-referential** - Step 0 below is "review
> and update this checklist itself" so it stays current as the
> project evolves.
>
> Cross-link to: [testing-playbook.md](testing-playbook.md) (the
> operational test loop), [enterprise-grade.md](enterprise-grade.md)
> (the quality bar), [capability-matrix.md](capability-matrix.md)
> (last release's test snapshot), [ROADMAP.md](ROADMAP.md) (the
> current dev cycle and its scope; the top PLANNED entry links the
> active `docs/releases/plans/v<x>-plan.md` when one exists for the cycle).

---

## Step 0 - Review this checklist

Before doing anything else: **scan this document end-to-end** and
update any item that is now stale (new package added, new doc
created, new workflow added, etc.). A stale checklist gives you
false confidence; an honest checklist catches real bugs.

If the project has changed materially since the last release (new
package, new collector, new top-level config, new workflow), add
the corresponding new checklist items here.

**Last self-update**: 2026-09-20. Reconciled package counts, publisher readiness,
container validation, protected delivery and immutable-tag recovery for v0.13.

---

## Step 1 - Pre-release scope confirmation

Before writing any code for a release:

- [ ] Read `docs/releases/plans/v<X.Y>-plan.md` (or `docs/ROADMAP.md` if no plan
      doc exists for this release). Confirm scope is locked.
- [ ] Verify any required design decisions for this release are
      decided (e.g., v0.7.1 had 4 design decisions D1-D4).
- [ ] Confirm any deferred items from the prior release's
      `capability-matrix.md` HIGH bucket are scheduled or explicitly
      re-deferred.
- [ ] Prepare a release tracking issue if needed; create it only with publication authority.

---

## Step 2 - Version bumps + dependency pins

For every release (patch / minor / major):

- [ ] Bump `version = "X.Y.Z"` in **all 9** pyproject.toml files (the workspace root and eight packages):
  - `pyproject.toml` (workspace root)
  - `packages/evidentia/pyproject.toml`
  - `packages/evidentia-core/pyproject.toml`
  - `packages/evidentia-ai/pyproject.toml`
  - `packages/evidentia-collectors/pyproject.toml`
  - `packages/evidentia-integrations/pyproject.toml`
  - `packages/evidentia-api/pyproject.toml`
  - `packages/evidentia-mcp/pyproject.toml`
  - `packages/evidentia-eval/pyproject.toml`
- [ ] Bump `"version": "X.Y.Z"` in `packages/evidentia-ui/package.json`.
- [ ] **Bump inter-package dependency constraints** using the canonical
      version manifest. Inspect every Evidentia dependency in package manifests,
      including extras, and preserve the intended compatibility upper bounds.
      Verify that a clean install resolves the release packages together.
- [ ] **Why this matters**: Step 3 of the v0.7.0 review caught a real
      bug where `version = "..."` was bumped but inter-package pins
      were not, producing a within-release version mismatch for raw
      pip users (commit `25ccca8`).
- [ ] Use `scripts/bump_version.py --to X.Y.Z --dry-run` to inspect the
      canonical version manifest, then apply the reviewed version change.
- [ ] Regenerate and review `uv.lock` and the npm lock in an isolated checkout.
      Verify every workspace version and inter-package constraint. Reuse qualified
      dependencies only within their recorded scope.
- [ ] Run `scripts/check_version_consistency.py` and inspect the complete diff.
- [ ] **At Pydantic major-version upgrades** (v0.9.5 F-V94-S11 INFO):
      audit the AI-gov idempotency body-hash. The hash is computed
      via `hashlib.sha256(json.dumps(model.model_dump(mode="json"),
      sort_keys=True))` in `evidentia_api.routers.ai_gov`. Pydantic
      changes the canonical form across some majors (e.g., default
      datetime serializer, enum dump shape), which would make
      previously-stored idempotency keys produce different hashes
      and silently appear as "different body" → 409 Conflict on
      legitimate replays after upgrade. Mitigation: at the
      Pydantic-upgrade commit, snapshot the existing idempotency
      store via `mv _idempotency.json _idempotency.pre-pydantic-N.json`
      so the new key/hash mapping starts fresh + the prior state is
      preserved for audit. Document the version transition in the
      CHANGELOG.

---

## Step 2.A - Pre-publish credential readiness check (LL-V105-1)

> Added v0.10.6 per the v0.10.5 partial-publish lesson-learned
> (LL-V105-1). For every release that introduces a new PyPI-published
> workspace package, the pending publisher MUST be configured on PyPI
> BEFORE tagging. A configured pending publisher can create its project on the
> first successful authorized upload.

For every release:

- [ ] Identify any workspace packages new to this release:

  ```bash
  diff <(git ls-tree HEAD packages/ --name-only) <(git ls-tree <prev-tag> packages/ --name-only)
  ```

- [ ] For each new package, check whether it exists on PyPI:

  ```bash
  for pkg in $new_packages; do
    curl -sI "https://pypi.org/pypi/${pkg}/json" -o /dev/null -w "${pkg}: %{http_code}\n"
  done
  ```

- [ ] If any package returns 404, the release MUST NOT tag until a pending publisher is configured at:
  https://pypi.org/manage/account/publishing/
  Configure with: PyPI Project Name = `<package>`, Owner = `Polycentric-Labs`,
  Repository name = `evidentia`, Workflow name = `release.yml`,
  Environment name = `pypi`.
- [ ] For an existing project, verify its Trusted Publisher configuration. For a
      new project, verify the pending publisher in the authorized owner account.
      HTTP 404 alone neither proves nor disproves pending-publisher readiness.
      A pending publisher does not reserve the project name. See the
      [PyPI pending-publisher documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

**Failure mode this prevents**: partial PyPI publish chain halt. v0.10.5's
publish step bailed at `evidentia-eval-0.10.5-py3-none-any.whl` because
no pending publisher existed for the new package, leaving 3 of 8
packages unpublished. Recovery required PyPI dashboard work + workflow
re-run. See `.local/pre-release-review/lessons-learned.yaml` LL-V105-1.

---

## Step 3 - CHANGELOG

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

## Step 4 - Documentation refresh

- [ ] Update `docs/ROADMAP.md`:
  - Prepare the release summary and mark it ready for tag approval once verified.
    Mark it SHIPPED only after publication and post-release verification.
  - Add a "vX.Y.Z+1 - NEXT" section pointing at
    `docs/releases/plans/v<next-version>-plan.md`.
  - Update the `**Last updated:**` line in the header.
- [ ] Update `docs/enterprise-grade.md` if any BLOCKER / HIGH /
      MEDIUM / LOW items moved status. Refresh the BLOCKER score.
- [ ] Verify `README.md` "Current status" section reflects the new
      version. Update version-callout banners.
- [ ] If a `docs/positioning-and-value.md` re-sync is due (quarterly
      cadence - see the `evidentia_positioning_and_value` MEMORY entry):
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

## Step 5 - Test gate

Run from a clean worktree:

```bash
uv sync --all-extras --all-packages
uv run --no-sync ruff check
uv run --no-sync ruff format --check .
uv run --no-sync python -m mypy \
  packages/evidentia-core packages/evidentia-collectors \
  packages/evidentia-api packages/evidentia-ai \
  packages/evidentia-integrations packages/evidentia \
  packages/evidentia-mcp packages/evidentia-eval
uv run --no-sync python -m pytest -q --cov=packages
uv build --all-packages
uvx twine check dist/*
# v0.9.9 - supply-chain gate. Generates the CycloneDX SBOM and scans
# it with osv-scanner: surfaces transitive + DISPUTED advisories the
# Dependabot alert feed suppresses. Requires osv-scanner on PATH (the
# pinned v2.4.0 binary from github.com/google/osv-scanner/releases, or
# `brew install osv-scanner`). This is the SAME shared script CI's
# `osv-scan` job runs - gate and CI stay in lockstep by construction.
uv run --no-sync python scripts/run_osv_scan.py
# v0.10.7 - workflow least-privilege gate. Fails (exit 2) if any
# .github/workflows/*.yml grants a top-level `write` scope without a
# `# JUSTIFIED: <reason>` comment on the line above its `permissions:`
# key. JUSTIFIED workflows (issue-opening bot, PR-comment smoke tests)
# are accepted exceptions. Same `--strict` check CI's
# `verify-workflow-perms.yml` job runs - gate and CI stay in lockstep.
uv run --no-sync python scripts/audit_workflow_permissions.py --strict
```

**For releases that touch the container or release dependency closure**,
validate the container before tag approval. The current `release.yml` builds
and checks wheels, SBOMs and a container from local wheels before either
publish job. The required container smoke workflow also runs for PRs and
merge groups, using its step-level relevance policy.

Use the reviewed release preflight in Step 5.6 when authorized, or the
equivalent isolated local build and smoke checks. Check the exact platform,
version, non-root user and `/api/health` response. Preserve failed attempts.
Container execution and any workflow dispatch still require their applicable
authority; this checklist does not grant it.

Acceptance:

- [ ] ruff: `All checks passed!`
- [ ] ruff format: `N files already formatted`, no `Would reformat` line
- [ ] mypy: `Success: no issues found in N source files`
- [ ] Record current pytest totals, failures, skips, warnings and platform
      scope. Every required suite must pass; explain each skip and preserve
      any exact owner-approved exception. Historical counts are not acceptance.
- [ ] `uv build --all-packages`: 8 evidentia-* wheels + sdists at the
      new version (no shim wheels)
- [ ] `uvx twine check dist/*`: every distribution PASSED
- [ ] (v0.9.9+) `scripts/run_osv_scan.py`: `PASS: osv-scanner found no
      un-allowlisted vulnerabilities`. Accepted findings live in
      `osv-scanner.toml`, each with a reason + an `ignoreUntil`
      re-validation date. CI's `osv-scan` job runs the identical
      shared script (gate-fidelity: CI and this checklist run one
      check, not two).
- [ ] (v0.10.7+) `scripts/audit_workflow_permissions.py --strict`:
      exit 0 (`STRICT: PASS`). Any workflow with a top-level `write`
      scope must carry a `# JUSTIFIED: <reason>` comment above its
      `permissions:` key, else the gate fails. CI's
      `verify-workflow-perms.yml` job runs the identical `--strict`
      check (gate-fidelity: CI and this checklist run one check).
- [ ] (If Dockerfile / container-build.yml touched) local
      `docker build` succeeds; in-image `evidentia version` and
      `evidentia catalog list` return expected output
- [ ] (v0.7.5+) Dockerfile pin updated to current release version
      (`pip install evidentia[gui]==X.Y.Z`); local `docker build` AND
      in-image HEALTHCHECK against `/api/health` (NOT `/health` -
      the SPA fallback would mask a broken API) succeed

---

## Step 5.5 - Doc consistency sweep (v0.7.12+)

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
- [ ] **Bundled catalog count** consistent with the current registry and
      verified CLI/API output. Do not reuse a historical count.
- [ ] **Package count** consistent: eight Python distributions, evidentia,
      evidentia-core, evidentia-ai, evidentia-collectors, evidentia-integrations,
      evidentia-api, evidentia-mcp and evidentia-eval. The workspace root is
      virtual; evidentia-ui is a Vite project, not a Python distribution.
- [ ] **Latest version references** match the current release
      (no straggler "v0.7.X" where X is one or more behind)
- [ ] **Cross-doc links resolve** - each relative Markdown link
      points at an existing file
- [ ] **Feature-claim consistency** - same feature described
      same way across README + docs/positioning-and-value.md +
      docs/capability-matrix.md
- [ ] **Capability-matrix freshness** - surfaces tested count +
      revalidation date current
- [ ] **Claim-bearing deltas are verifier-sourced (G28 inversion;
      added 2026-07-19)** - every NEW claim-bearing sentence in the
      capability-matrix / threat-model deltas is written FROM a
      `doc-runtime-verifier` PASS (or an equivalently exercised
      behavior), BEFORE the release-prep commit - never drafted from
      memory during release-prep. Rationale: all three v0.11.0
      self-inflicted doc overclaims (F-V0110-4/6/7), and prior cycles'
      G28 findings, were introduced at release-prep time from memory.
      Scope: claim-bearing prose only (mechanisms, gates, active
      behavior); CHANGELOG narrative is exempt.
- [ ] **threat-model.md delta** - append a v{X.Y.Z}-delta sub-
      section covering any new public surface
- [ ] **enterprise-grade.md** - every BLOCKER / HIGH / MEDIUM /
      LOW row reflects current shipped state
- [ ] **ROADMAP.md** reflects the actual release boundary. Mark the release
      SHIPPED after verified publication, and then promote the next release.
- [ ] **AI-assistance acknowledgment** in README - Allen's
      per-release manual update; flag if missing

Apply via Grep/Edit; commit as a single
`docs(consistency):` commit per release.

---

## Step 5.6 - Release preflight dry-run (optional pre-tag validation, v0.10.17+)

For a higher-fidelity pre-tag check than the local Step-5 gate - especially
when `release.yml`, the `Dockerfile`, or the dependency closure changed - run
the **release preflight**: a `workflow_dispatch` on `release.yml` that executes
the FULL pre-publish path on a runner (the SSOT gate suite + wheels + per-package
SBOMs + the reproducible-build double-build + the container-built-FROM-LOCAL-WHEELS
and all the image smoke tests) **without publishing anything**. It catches the
classes that historically surfaced only at tag time - a base/dep regression, a
`uvx` exit-127, a `pip-compile` hash mismatch (the v0.10.14 / v0.10.15 ghost-tag
failures).

```bash
# After explicit dispatch approval, run on the verified release candidate:
gh workflow run release.yml --ref main
# then watch it:
gh run watch "$(gh run list --workflow release.yml --event workflow_dispatch \
  --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Publish-safe by construction: `tag-guard` and both publish jobs require
`github.event_name == 'push'`, so a dispatch - even one selected on a `v*` tag
ref - yields `publishable=false` and `publish-pypi` / `publish-container` SKIP.
The `pypi` / `ghcr` deployment environments are independently restricted to `v*`
**tag** refs (with required reviewers), a second, platform-level belt.

Acceptance:

- [ ] The preflight dispatch run is GREEN through `build` (gate + build +
      reproducible-build check + container smoke all pass)
- [ ] `publish-pypi` and `publish-container` show **skipped** - confirm nothing
      published on the dispatch

---

## Step 6 - Inconsistency scour

Per the testing-playbook 3-pass scour pattern:

```bash
# Pass 1: stale name references (must only appear in CHANGELOG /
# docs/archive/RENAMED.md / scripts/_create_shim_packages.py / scripts/_rename_content.py)
grep -ri "controlbridge"

# Pass 2: prior-version mentions (must only appear in CHANGELOG
# entries documenting prior versions)
grep -ri "PREV.X.Y"
grep -ri "X.Y-1.0"

# Pass 3: current-version coverage (should appear in 9 pyproject.toml
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

## Step 7 - External repo + service review

```bash
gh repo view polycentric-labs/evidentia --json name,description,isArchived,defaultBranchRef
gh secret list --env pypi --repo polycentric-labs/evidentia
gh api repos/polycentric-labs/evidentia/environments/pypi --jq '{name, url, deployment_branch_policy}'
gh api repos/Polycentric-Labs/evidentia/rulesets --jq '.[] | {id, name, target, enforcement}'   # main PR-flow ruleset + org baseline
gh search commits --author-email allen@allenfbyrd.com --owner polycentric-labs  # zero hits
```

- [ ] **Repo About description is managed as code** (no stale
      "Previously: ..." text). The source of truth is
      [`.github/repo-description.txt`](../.github/repo-description.txt)
      (single line, no version literal - so it is NOT part of per-version
      bumping; `.github/**` is in the `frozen` list of
      [`scripts/version_tracked_files.yaml`](../scripts/version_tracked_files.yaml),
      so `check_version_consistency.py` does not flag it). Re-assert the
      live GitHub About from the tracked file each release so the two
      cannot silently drift:

      ```bash
      gh repo edit Polycentric-Labs/evidentia \
        --description "$(cat .github/repo-description.txt)"
      ```

      This is a **Tier-4 action requiring Allen's approval** (it mutates
      public GitHub state) - surface the exact command and wait for
      explicit approval before running it. If the About copy itself needs
      to change, edit `.github/repo-description.txt` first (in its own
      commit), then re-assert from the file.
- [ ] PyPI environment exists.
- [ ] PyPI Trusted Publisher entries exist for all eight published packages
      (verify via `https://pypi.org/manage/project/<name>/settings/publishing/`).
- [ ] Zero `allen@allenfbyrd.com` commits across all owned repos.
- [ ] **`main` PR-flow ruleset still active** (v0.10.14). Confirm the
      repository ruleset `main - PR flow (required checks + merge queue)` is
      `enforcement: active` with `bypass_actors: []`, a `pull_request` rule, a
      `required_status_checks` rule listing the full meaningful set, a
      `merge_queue` rule (`merge_method: SQUASH`), and
      `required_linear_history`. The org `polycentric-labs-default-branch-baseline`
      ruleset additionally enforces signatures / non-FF / deletion. Classic
      branch protection was intentionally removed (the ruleset is the single
      source of truth). If protection has changed or weakened, stop release
      preparation, document the discrepancy and obtain explicit authority
      before changing protections.
- [ ] **`pypi` environment branch policy correct**: with branch
      protection in place,
      `deployment_branch_policy.custom_branch_policies` should be
      `true`, with the approved `v*` tag policy and required reviewer.
      The release publish jobs use tag refs; do not add a `main` branch
      policy as a workaround. Verify both `pypi` and `ghcr` environments.
- [ ] **Dependabot review** - check the open Dependabot PR queue
      (`gh pr list --label dependencies --state open`). Resolve in-scope updates
      through signed commits, required checks and the protected merge queue.
      Any deferral must be documented and consistent with the owner-approved
      release scope. Keep unresolved security advisories visible at the gate.
- [ ] **Security vulnerability-coordination flow**: confirm
      [`.github/SECURITY.md`](../.github/SECURITY.md) is current: SLA still accurate (3 business days
      initial / 10 business days triage), 90-day disclosure timeline
      still applies, supported-versions table reflects the
      single-supported-patch policy as of this release. If a CVE
      shipped between releases, ensure its handling is documented.

### Repo secret rotation (v0.9.4 P4.6)

Credential rotation is an owner-operated, separately approved action. Keep
secret values out of chat, tool arguments and captured output. If the owner
rotates `CODECOV_TOKEN` (or another repo secret), use one of these two forms - `gh secret set` does NOT
have a `--body-file` flag (common mis-recall; only `-b/--body
string`, `-f/--env-file file`, or stdin work):

```bash
# Option A - dotenv format (file has KEY=value lines)
gh secret set -R polycentric-labs/evidentia \
    -f C:\Users\allen\.secrets\codecov-polycentric-labs-evidentia.env

# Option B - stdin pipe (file has bare value only)
Get-Content C:\Users\allen\.secrets\codecov-token-raw.txt \
  | gh secret set CODECOV_TOKEN -R polycentric-labs/evidentia
```

After rotation, the Codecov badge cache may take ~15-30 min to
clear (Fastly edge). Operators can append `?v=<release-tag>` to
the README badge URL to bust the cache (same workaround as v0.8.2
`?v=silver` for the OpenSSF tier upgrade).

---

## Step 8 - Tag and push (the irreversible step)

**STOP for explicit user approval before proceeding.** Surface a
comprehensive pre-tag overview including:

- Commit list since the prior release tag
- Test results (passed / skipped / warnings)
- Build artifacts (eight wheels and eight sdists at the new version)
- Scour findings (zero stale references)
- External services state (PyPI publishers, GitHub repo)
- Known deferrals (HIGH-bucket items deferred to next release)

After explicit approval:

```bash
git tag -s vX.Y.Z <verified-main-commit> -m "Release vX.Y.Z: <one-line summary>"
git verify-tag vX.Y.Z
git push origin refs/tags/vX.Y.Z  # the approved tag triggers release.yml
gh run watch                   # monitor the release workflow
```

> **v0.10.17+ - deployment approval gate.** The `pypi` and `ghcr` deployment
> environments carry **required reviewers** (Allen; self-review allowed), so
> after the tag push the `release.yml` run PAUSES at `publish-pypi` (and again at
> `publish-container`) awaiting an "Approve deployment" click in the Actions run
> UI - the Tier-4 per-publish approval enforced by the platform, not just by
> discipline. Approve each once the preceding jobs are green. These environments
> are also restricted to `v*` **tag** refs and are consumed ONLY by `release.yml`;
> do not re-add a branch policy or point another workflow at them without
> re-checking this guard (a `custom_branch_policies:true` environment with zero
> matching policies blocks ALL deployments → a wheels-only half-release).

If the release.yml workflow fails:

- For OIDC bootstrap issues (per-package PyPI Trusted Publisher
  registration mismatch), check the per-package
  `https://pypi.org/manage/project/<name>/settings/publishing/`
  page. Prepare the correction and obtain the required authority.
  Preserve the existing immutable tag; never delete, move or force-push it.
  Follow [release rollback](runbooks/release-rollback.md) for approved recovery.
- For SBOM / attestation issues, fix the workflow YAML, push the
  fix through the protected queue, then obtain approval for a forward patch
  release. Keep the failed tag and its evidence.
- For partial publishes (some wheels published, others 403), fix
  the failing publisher only with explicit authority. Reconcile which artifacts
  were published before selecting the approved recovery. `skip-existing: true`
  skips existing files; it does not make every release step idempotent.

### PR flow via merge queue (v0.10.14 - the "never ship a failed test" flip)

As of v0.10.14, `main` is governed by a **repository ruleset** that makes the
full CI matrix gate **before** a change lands, not after. This reverses the
prior direct-push pattern, under which admin pushes bypassed the required
checks (`enforce_admins: false`), so the full matrix only ran post-merge / at
release - the structural root cause of the v0.10.12 layered failures (a
`python:3.14` base regression + a dead container smoke test surfaced only after
the PyPI publish).

The ruleset on `main` (created via `gh api repos/.../rulesets`) enforces:

- **Require a pull request before merging** - 0 required approvals (solo
  maintainer; a PR is still mandatory). `bypass_actors: []` - **no one
  bypasses, including admins**.
- **Require status checks** - the full meaningful set: the 3-OS `pytest`
  matrix + `pytest no-extras`, `ruff`, `mypy`, `frontend (typecheck + build)`,
  `docker/requirements drift`, `openapi schema drift`, `osv-scanner (SBOM)`,
  `staleness guards …`, `gitleaks …`, `Analyze (python/js/actions)`,
  `CLI<->GUI parity`, `verify-conformance-evidence`,
  `Audit workflow permissions (strict)`, and the container `Build + smoke test`.
- **Merge queue** (`merge_method: SQUASH`) - re-tests the prospective `main` +
  PR merge so two individually-green PRs can't break `main`. SQUASH is the only
  method compatible with `required_signatures` + `required_linear_history`
  (`merge` breaks linearity; `rebase` produces commits GitHub cannot sign, which
  would fail the signature rule). Every workflow producing a required check
  carries the `merge_group:` trigger, or the queue stalls waiting for a
  conclusion that never arrives. Paths-filtered workflows are **not** required -
  they do not run on `merge_group` (GitHub does not expand the queue-branch
  diff), so requiring one would hang the queue; the container smoke test avoids
  this by always running and early-exiting on a step-level relevance check
  rather than an `on.paths` filter.
- **required_linear_history + required_signatures + non_fast_forward** (the org
  `polycentric-labs-default-branch-baseline` ruleset also enforces signatures /
  non-FF / deletion org-wide).

The classic branch protection was removed so the ruleset is the single source
of truth.

How to ship a change now - code, docs, **and** releases all go through a PR:

```bash
git checkout -b <branch>
# ... make changes ...   (signed commits authored solely by Allen)
git push origin <branch>
gh pr create --base main --head <branch> --title "..." --body "..."
# wait for the required checks to go green, then add to the merge queue:
gh pr merge <PR#> --squash --auto     # or "Merge when ready" in the UI
# the queue re-tests main+PR and squash-merges (GitHub-signed) when green
```

A direct `git push origin main` now **fails** by design (the ruleset requires a
PR). Tagging a release is unchanged - `git tag -s vX.Y.Z && git push origin
vX.Y.Z` fires `release.yml`; the tag is pushed to its own ref, not to `main`.
Each `git push`, `gh pr merge`, and tag push remains a Tier-4 action requiring
explicit approval per the global publishing-authority protocol.

---

## Step 9 - Post-release verification

Within 30 minutes of `release.yml` reporting success:

- [ ] PyPI: each of the eight packages shows version X.Y.Z at
      `https://pypi.org/project/<name>/`.
- [ ] **Codecov badge** registers ≥80% coverage (post-v0.7.12 fix:
      coverage.xml emits repo-relative paths via `[tool.coverage.run]
      relative_files = true` so Codecov's path matcher resolves
      against the GitHub tree).

### Step 9.5 - Release notes audit (v0.7.12+)

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
      published releases) - `ghcr.io/polycentric-labs/evidentia:vX.Y.Z`
      with image digest
- [ ] PEP 740 verification stanza - pypi-attestations verify
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
mutation and requires explicit per-action approval - surface
the diff before mutating.

For prior releases (v0.7.0 → previous-X.Y.Z), the same audit
runs once per cycle to catch any historical gaps. v0.7.12
introduced this practice retroactively.

### Step 9.6 - Other PyPI checks

- [ ] PyPI per-file pages show the "Provenance" / PEP 740 attestation
      section with the GitHub Actions workflow URL + commit SHA.
- [ ] **Verify PEP 740 publish attestations (PyPI path)** - primary
      verifier for the per-file Sigstore-signed PEP 740 attestation
      that PyPA's publish action uploads alongside each wheel/sdist:
      ```bash
      uvx pypi-attestations verify pypi \
          --repository https://github.com/polycentric-labs/evidentia \
          "pypi:evidentia_core-X.Y.Z-py3-none-any.whl"
      ```
      Repeat for the other seven wheels and the source distributions.
      Record each exact filename, digest, publisher identity and result.
      `gh attestation verify` does NOT validate this - it defaults
      to the SLSA provenance v1 predicate, while PEP 740 publish
      attestations use `https://docs.pypi.org/attestations/publish/v1`.
      Use the SLSA-path verifier below for `gh attestation verify`.
- [ ] **Verify SLSA build provenance (GitHub path)** - secondary
      verifier covering the build-provenance attestation that
      `actions/attest-build-provenance` stores under the repo's
      Attestations endpoint (added in v0.7.3 S3 per
      [`v0.7.3-plan.md`](releases/plans/v0.7.3-plan.md)):
      ```bash
      gh attestation verify dist/evidentia_core-X.Y.Z-py3-none-any.whl \
          -R Polycentric-Labs/evidentia
      ```
      Expect `Loaded digest sha256:...` and `OK`. The same command
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
- [ ] **(v0.7.5+) Container image published to ghcr.io** - pulls
      successfully and the in-image CLI works:
      ```bash
      docker pull ghcr.io/polycentric-labs/evidentia:vX.Y.Z
      docker run --rm ghcr.io/polycentric-labs/evidentia:vX.Y.Z version
      docker run --rm ghcr.io/polycentric-labs/evidentia:vX.Y.Z catalog list | head -5
      ```
- [ ] **(v0.9.3+) GHCR package visibility is PUBLIC** - the first
      container push to a new GitHub org defaults to **private**
      visibility. This bit us at v0.9.1 (org migration to
      Polycentric-Labs) and again at v0.9.2. One-time manual fix:
      1. Go to `https://github.com/orgs/Polycentric-Labs/packages/container/evidentia/settings`
      2. Scroll to "Danger Zone" → "Change package visibility"
      3. Select "Public" → confirm by typing the package name
      4. Verify: `docker pull ghcr.io/polycentric-labs/evidentia:vX.Y.Z`
         succeeds from an unauthenticated context (e.g., incognito
         `docker pull` without `gh auth setup-git`).
      After the one-time flip, subsequent pushes to the same package
      inherit public visibility. Only re-check if the org is
      recreated or the package is deleted and re-pushed.
- [ ] **(v0.7.5+) Verify cosign keyless signature on the image** -
      validates the OIDC identity binding (release.yml@refs/tags/v*):
      ```bash
      cosign verify ghcr.io/polycentric-labs/evidentia:vX.Y.Z \
          --certificate-identity-regexp \
          'https://github\.com/Polycentric-Labs/evidentia/\.github/workflows/release\.yml@refs/tags/v.*' \
          --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
      ```
      Expect "Verified OK" + the certificate identity URL printed.
- [ ] **(v0.7.5+) Verify SLSA build provenance on the image digest**
      - independent of cosign, validates the build-provenance predicate:
      ```bash
      gh attestation verify oci://ghcr.io/polycentric-labs/evidentia:vX.Y.Z \
          -R Polycentric-Labs/evidentia
      ```
      Expect "verified" + the workflow run id matching the release.
- [ ] **(v0.7.5+) Tag and `:latest` resolve to same digest** - sanity
      check the rolling-pointer is up to date:
      ```bash
      docker buildx imagetools inspect ghcr.io/polycentric-labs/evidentia:vX.Y.Z --raw | grep -i digest
      docker buildx imagetools inspect ghcr.io/polycentric-labs/evidentia:latest --raw | grep -i digest
      # both should print the same sha256:... line
      ```

---

## Step 10 - Post-release housekeeping

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
      version - we did this for v0.5.1 controlbridge-* shims at v0.7.0).

---

## Step 11 - Quarterly cadence (independent of releases)

Run quarterly regardless of release schedule:

- [ ] Re-sync `docs/positioning-and-value.md` per the
      `research_resync_automation_pattern` MEMORY entry. Snapshot to
      dated file; review diff; promote to canonical.
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
  v0.7.2 per `docs/releases/plans/v0.7.2-plan.md` item S3 - deferred from v0.7.1
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

- **Step 2 (version bumps)**: maintain the implemented `scripts/bump_version.py`
  and its `scripts/version_tracked_files.yaml` manifest as package and
  documentation surfaces change. Keep its dry-run and consistency checks.
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
