# Evidentia gap analysis — composite GitHub Action

Run Evidentia gap analysis on every pull request, post a sticky comment
with the diff vs. the base branch, and gate merge on compliance
regressions. Optionally produce a signed OSCAL Assessment Results
document for downstream auditor consumption.

This is a **composite action** that lives inside the main Evidentia
repo. It supersedes the legacy standalone `allenfbyrd/evidentia-action`
repo (archived as of v0.7.0).

## Usage

### Floating major tag (recommended for non-audit consumers)

```yaml
name: Compliance check
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 2  # baseline cache restore needs HEAD~1 reachable

      - uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
        with:
          inventory: inventory.yaml
          frameworks: nist-800-53-rev5-moderate,soc2-tsc
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### SHA-pinned (recommended for production compliance pipelines)

OpenSSF Scorecard's "Pinned-Dependencies" check requires SHA pins on
every third-party action. For audit-grade pipelines, pin the action by
its 40-char commit SHA and document the version it corresponds to in a
trailing comment. Dependabot will keep both the SHA and the comment in
sync via PRs.

```yaml
- uses: polycentric-labs/evidentia/.github/actions/gap-analysis@<40-char-sha>  # v0.7.0
  with:
    inventory: inventory.yaml
    frameworks: nist-800-53-rev5-moderate,soc2-tsc
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### With OSCAL Assessment Results + Sigstore signing

Signs the AR with Sigstore using the workflow's ambient OIDC identity.
Requires `permissions: id-token: write`. Bundle is uploaded as a workflow
artifact alongside the gap-report.

```yaml
permissions:
  contents: read
  pull-requests: write
  id-token: write  # required for Sigstore OIDC signing

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 2

      - uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
        with:
          inventory: inventory.yaml
          frameworks: nist-800-53-rev5-moderate,soc2-tsc
          github-token: ${{ secrets.GITHUB_TOKEN }}
          emit-oscal-ar: 'true'
          emit-sigstore-bundle: 'true'
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `inventory` | yes | — | Path to control inventory file (YAML/CSV/JSON). |
| `frameworks` | no | from `evidentia.yaml` | Comma-separated framework IDs. |
| `github-token` | yes | — | `GITHUB_TOKEN` with `pull-requests: write`. |
| `evidentia-version` | no | `>=0.7,<0.8` | pip spec for evidentia-core. |
| `python-version` | no | `3.12` | Python interpreter version. |
| `fail-on-regression` | no | `true` | Exit non-zero on opened gaps or severity increases. |
| `emit-oscal-ar` | no | `false` | Also produce OSCAL AR JSON. |
| `emit-sigstore-bundle` | no | `false` | Sign OSCAL AR with Sigstore (requires `id-token: write`). |
| `output-dir` | no | `.evidentia-out` | Output directory under `$GITHUB_WORKSPACE`. |

## Outputs

| Name | Description |
|---|---|
| `gap-report-path` | Absolute path to gap-report.json (current state). |
| `baseline-path` | Absolute path to cached baseline gap-report. |
| `diff-markdown-path` | Absolute path to rendered markdown diff. |
| `oscal-ar-path` | Absolute path to OSCAL AR JSON (empty if not requested). |
| `sigstore-bundle-path` | Absolute path to Sigstore bundle (empty if not requested). |

## How it works

1. **Setup**: installs `evidentia-core` from PyPI at the version specified
   by `evidentia-version`.
2. **Analyze head**: runs `evidentia gap analyze` against the inventory
   for the current PR / push state.
3. **Restore baseline**: pulls the cached gap-report for the base branch
   from `actions/cache`. The cache key includes the inventory file's
   hash so changes to the inventory file invalidate the cache.
4. **Seed baseline**: on the first push to the default branch, seeds the
   baseline from the current head (no diff yet).
5. **Diff**: runs `evidentia gap diff --format markdown` against the
   baseline. Produces a markdown PR-comment body.
6. **Sticky PR comment**: posts (or updates) a sticky comment on the PR
   using `marocchino/sticky-pull-request-comment@v2`. The header
   `evidentia-gap-analysis` is used for idempotent find-or-create.
7. **Gate**: if `fail-on-regression: true`, runs `evidentia gap diff
   --format github --fail-on-regression`, which exits non-zero (failing
   the PR check) when:
   - **Opened** count > 0 (a new gap appeared)
   - **Severity increased** count > 0 (an existing gap got worse)
8. **Artifact upload**: uploads the entire `output-dir/` as a workflow
   artifact, retained for 90 days.

## Migrating from `allenfbyrd/evidentia-action@v1`

The standalone `allenfbyrd/evidentia-action` repo is archived as of
v0.7.0. Existing `uses: allenfbyrd/evidentia-action@v1` references will
continue to resolve (archived repos retain clone access) but will not
receive updates.

### Before (archived, frozen at v1)

```yaml
- uses: allenfbyrd/evidentia-action@v1
  with:
    inventory: inventory.yaml
    frameworks: soc2-tsc
```

### After (consolidated subpath, active development)

```yaml
- uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
  with:
    inventory: inventory.yaml
    frameworks: soc2-tsc
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### New inputs since v1

- `github-token` is now **required** (was implicitly auto-resolved before)
- `emit-oscal-ar` — opt in to OSCAL Assessment Results output
- `emit-sigstore-bundle` — opt in to Sigstore signing of the AR
- `evidentia-version` — pin to a specific evidentia-core version

## Required permissions

```yaml
permissions:
  contents: read         # checkout
  pull-requests: write   # sticky PR comment
  id-token: write        # only if emit-sigstore-bundle: true
```

## Troubleshooting

**"need two gap reports to diff"** — the baseline cache didn't restore
and the current run isn't a push to the default branch. Either run the
workflow manually on `main` once to seed the cache, or commit a
pre-generated baseline file (not recommended — keeps drift-prone state
in version control).

**PR comment has no content** — confirm `pull-requests: write` is in the
workflow's `permissions:` block. GitHub 2023-03 tightened defaults;
without the explicit grant, the comment step silently no-ops.

**Sigstore signing fails with "OIDC token unavailable"** — confirm
`id-token: write` is in the workflow's `permissions:` block. Composite
actions inherit the caller workflow's permissions; you must grant it
at the workflow level, not the action level.

**Stale baseline after a main merge** — `actions/cache` uses cache keys,
not invalidation semantics. After a base-branch push that changes the
baseline, subsequent PRs continue using the stale cache until
`restore-keys` falls through. The cache key includes
`hashFiles(inputs.inventory)`, so changes to the inventory file
automatically invalidate the cache.

## See also

- [Evidentia main README](../../../README.md)
- [Enterprise-grade checklist](../../../docs/enterprise-grade.md)
- [Testing playbook](../../../docs/testing-playbook.md)
- [`evidentia gap diff` CLI reference](../../../docs/github-action/README.md)
