# Evidentia testing playbook

This playbook codifies the test-and-release workflow for Evidentia
maintainers. It's the operational counterpart to
[`docs/enterprise-grade.md`](enterprise-grade.md), which lists the
quality bar; this document is **how to verify** Evidentia meets it.

Maintain this file alongside each release. The "Per-release update
checklist" below is the minimum maintenance.

## Local development test loop

Run before every commit:

```bash
uv sync --all-extras --all-packages   # incl. sigstore + trestle dev-deps
uv run --no-sync ruff check                   # lint — ENFORCED in CI
uv run --no-sync python -m mypy packages/evidentia-core packages/evidentia-collectors packages/evidentia-api packages/evidentia-ai packages/evidentia-integrations packages/evidentia
uv run --no-sync python -m pytest -q --no-header
```

Expected: ruff lint clean, mypy clean, 849 tests passing (8 skipped,
16 benign Tier-C placeholder catalog warnings) in ~12 seconds on a
warm checkout.

`ruff format` is recommended on new code but not enforced in CI as
of v0.7.0 — much of the pre-existing codebase predates the current
ruff format config. Format-the-world is tracked as a v0.8.0 cleanup
task. For new code, run `uv run --no-sync ruff format <files>` before
committing.

## Pre-release smoke test sequence

Run after the last commit before tagging. This is the operationalized
3-pass scour that closes a release.

### Pass 1 — automated checks

```bash
# Lint / type-check
uv run --no-sync ruff check
uv run --no-sync python -m mypy packages/evidentia-core packages/evidentia-collectors packages/evidentia-api packages/evidentia-ai packages/evidentia-integrations packages/evidentia

# Format new files only (not the whole repo — pre-existing format debt)
uv run --no-sync ruff format <only-files-touched-this-release>

# Tests with coverage
uv run --no-sync python -m pytest -q --cov=packages

# Build all wheels + sdists (excludes shim packages — those are removed)
uv build --all-packages

# PyPI metadata sanity
uvx twine check dist/*
```

Acceptance: zero ruff errors, zero mypy errors, all tests passing,
all 6 wheels produced (no `shim-*` wheels), twine check ✅ on all
distributions.

### Pass 2 — manual codebase review (regex-grep based)

```bash
# Must return zero hits OUTSIDE CHANGELOG.md, RENAMED.md,
# scripts/_create_shim_packages.py
grep -ri "controlbridge"

# Must only appear in CHANGELOG entries documenting v0.6.0 history
grep -ri "0\.6\.0"

# Should appear in 7 pyproject.toml + CHANGELOG + docs as the current release
grep -ri "0\.7\.0"

# evidentia-action@v1 only in migration guides pointing to deprecation
grep -ri "evidentia-action@v1"
```

Plus visual checks:

- `docs/enterprise-grade.md` BLOCKER score: 10/10
- `README.md` opens with v0.7.0 banner (no rename banner)
- `README.md` directory tree: no `shim-controlbridge*/` row
- `CHANGELOG.md` top section: `[0.7.0] - 2026-04-DD` (not Unreleased)

### Pass 3 — external repo + service review

```bash
# Confirm action repo state
gh repo view allenfbyrd/evidentia-action

# Confirm PyPI environment + secrets
gh secret list --env pypi --repo polycentric-labs/evidentia
gh api repos/polycentric-labs/evidentia/environments/pypi

# Confirm zero email leaks
gh search commits --author-email allen@allenfbyrd.com --owner polycentric-labs
```

Plus PyPI publisher check: visit each of 6 packages'
`https://pypi.org/manage/project/<name>/settings/publishing/` page and
confirm Trusted Publisher entries match the workflow claims (Owner,
Repository, Workflow, Environment).

## How to add a new collector + matching test

Use AWS IAM Access Analyzer as the canonical example:
- Collector source: `packages/evidentia-collectors/src/evidentia_collectors/aws/access_analyzer.py`
- Tests: `tests/unit/test_collectors/test_access_analyzer.py`

Pattern:

1. **Define the collector**: subclass the base collector pattern, return
   `list[SecurityFinding]` from a `collect()` method.
2. **OLIR mapping tables**: define module-level `_*_MAPPINGS` dicts
   with `relationship` (subset-of / equivalent-to / etc.) and
   `justification` strings citing authoritative sources (AWS / NIST /
   etc.).
3. **BLIND_SPOTS list**: enumerate what the collector does NOT cover,
   each entry with `id`, `title`, `description`. These thread through
   `gap_report_to_oscal_ar(blind_spots=...)` into the AR back-matter
   for auditor disclosure.
4. **Retry**: wrap network calls with `@with_retry` from
   `evidentia_core.audit.retry`.
5. **Pagination**: add a 100-page safety cap (10k items max) for any
   API that paginates; emit a manifest warning when the cap is hit.
6. **Tests**: use moto for AWS mocking, responses for HTTP mocking.
   Cover empty-result, single-page, multi-page, retry-recovery,
   credential-failure, and BLIND_SPOTS-shape paths.
7. **CollectionContext**: every finding must carry a `CollectionContext`
   identifying the collector + run + credential identity.

## How to validate OSCAL output manually

```bash
# Generate an AR
uv run --no-sync evidentia gap analyze \
  --inventory examples/meridian-fintech/my-controls.yaml \
  --frameworks nist-800-53-mod \
  --output /tmp/ar.json \
  --format oscal-ar

# Schema-validate via trestle (Extra.forbid catches unknown fields)
uv run --no-sync python -c "
import json
from trestle.oscal.assessment_results import Model
ar = json.load(open('/tmp/ar.json'))
parsed = Model.parse_obj(ar)
print(f'AR valid: uuid={parsed.assessment_results.uuid}')
print(f'  results: {len(parsed.assessment_results.results)}')
print(f'  findings: {len(parsed.assessment_results.results[0].findings)}')
"

# Optional: jsonschema fallback against bundled NIST schema
# (if trestle is unavailable in your environment)
# pip install jsonschema
# python -m jsonschema -i /tmp/ar.json oscal_assessment-results_schema.json
```

## Test fixtures index

| Fixture | Location | Covers |
|---|---|---|
| Meridian fintech v2 | `examples/meridian-fintech-v2/` | Realistic SOC 2 + NIST scenario; canonical end-to-end test |
| Acme healthtech | `examples/acme-healthtech/` | HIPAA-focused inventory |
| Northstar systems | `examples/northstar-systems/` | DoD CMMC scenario |
| Sample inventories | `tests/fixtures/` | Per-test minimal yaml/csv/json |

Sample collector outputs (de-identified) live in `tests/fixtures/`
when present; new test data should be added there with a comment
documenting de-identification provenance.

## Per-release update checklist

Run this list at the start of each release branch (e.g. v0.7.1):

- [ ] Bump version in 7 `pyproject.toml` files (workspace root + 6
      published packages)
- [ ] CHANGELOG.md: rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`,
      add a fresh `[Unreleased]` block above
- [ ] `docs/enterprise-grade.md`: refresh BLOCKER / HIGH / MEDIUM /
      LOW status table; bump scoring section with current numbers
- [ ] `docs/ROADMAP.md`: mark current release as SHIPPED, add next
      release scope
- [ ] Run the 3-pass smoke test sequence above
- [ ] Cut an RC tag (`vX.Y.Z-rc1`) before the final tag, especially
      when changing release.yml or PyPI Trusted Publisher claims
- [ ] After RC succeeds: cut `vX.Y.Z` final tag and push
- [ ] Update GitHub repo About text if any rename/repositioning
- [ ] Update `MEMORY.md` (Allen's auto-memory) with release notes
- [ ] Update README "Current status" line + version-callout banners

## Inconsistency-scour checklist (regex commands)

Quick reference for the manual scour pass:

```bash
# Stale references to old project name (must only be in CHANGELOG/RENAMED/scripts)
grep -ri "controlbridge"

# Off-version mentions in current code
grep -ri "0\.6\.0"

# Current version coverage
grep -ri "0\.7\.0"

# Stale action references
grep -ri "evidentia-action@v1"

# Author email scrubbing (must be zero post-audit)
git log --all --format="%ae" | sort -u | grep "allen@allenfbyrd.com" || echo "✓ zero leaks"
```

## Test mode

Set `EVIDENTIA_TEST_MODE=1` to zero out retry backoff in
`@with_retry`-decorated functions. Used by the test suite to keep
retry tests fast. Production should never set this.

## See also

- [`docs/enterprise-grade.md`](enterprise-grade.md) — the quality bar
- [`docs/log-schema.md`](log-schema.md) — ECS / NIST AU-3 / OpenTelemetry
  audit log schema
- [`docs/ROADMAP.md`](ROADMAP.md) — release plan
- [`.github/actions/gap-analysis/README.md`](../.github/actions/gap-analysis/README.md)
  — composite action surface
