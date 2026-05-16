# Evidentia GitHub Action — compliance-as-code for PRs

v0.7.0 ships a **composite action** at
[`.github/actions/gap-analysis/`](../../.github/actions/gap-analysis/)
that turns every pull request into a compliance check. The standalone
`allenfbyrd/evidentia-action` repo is archived in favor of this
consolidated subpath action.

```yaml
- uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
  with:
    inventory: inventory.yaml
    frameworks: nist-800-53-rev5-moderate,soc2-tsc
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

See the [composite-action README](../../.github/actions/gap-analysis/README.md)
for the full input/output surface, OSCAL AR + Sigstore signing options,
SHA-pinned variants for audit pipelines, and a migration guide from
`evidentia-action@v1`.

---

The rest of this document keeps the v0.3.0 hand-rolled-workflow pattern
for users who prefer a copy-paste workflow over the action wrapper.

v0.3.0 introduced `evidentia gap diff`, which turns every pull
request into a compliance check. This guide shows how to wire it into
GitHub Actions so your PRs block on compliance regressions the same way
they block on failing tests.

## What it does

On every PR:

1. Runs `evidentia gap analyze` against the committed inventory.
2. Compares the result against the `main`-branch baseline.
3. Posts the diff as a PR comment.
4. Fails the check (red ✗) if any new gaps were opened or severities
   increased — so the branch-protection rule "require compliance check
   to pass" actually stops regressions.

No commercial GRC tool does this at the PR level. Hyperproof has
"continuous control monitoring" but it's API-polling, not PR-diff-based.

## Minimal setup

Copy [`workflow-example.yml`](workflow-example.yml) into
`.github/workflows/evidentia.yml` in your repo, commit, and open a
PR.

```yaml
name: Compliance check
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]  # so main-branch pushes refresh the baseline

permissions:
  contents: read
  pull-requests: write  # needed for PR-comment posting

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2  # need HEAD~1 for the 'base' snapshot

      - uses: astral-sh/setup-uv@v3
        with:
          python-version: "3.12"

      - name: Install Evidentia
        run: uv tool install evidentia

      # --- Head (current PR state) ---
      - name: Analyze head (PR branch)
        run: |
          evidentia gap analyze \
            --inventory inventory.yaml \
            --frameworks nist-800-53-rev5-moderate,soc2-tsc \
            --output /tmp/head.json \
            --format json

      # --- Base (main branch state, cached across runs) ---
      - name: Check for main-branch baseline artifact
        id: baseline
        uses: actions/cache@v4
        with:
          path: /tmp/base.json
          key: evidentia-baseline-${{ github.base_ref }}
          restore-keys: |
            evidentia-baseline-main

      - name: Regenerate baseline if missing
        if: steps.baseline.outputs.cache-hit != 'true' && github.event_name == 'push'
        run: |
          evidentia gap analyze \
            --inventory inventory.yaml \
            --frameworks nist-800-53-rev5-moderate,soc2-tsc \
            --output /tmp/base.json \
            --format json

      - name: Gap diff (PR-comment markdown)
        if: github.event_name == 'pull_request'
        id: diff
        run: |
          evidentia gap diff \
            --base /tmp/base.json \
            --head /tmp/head.json \
            --format markdown \
            --output /tmp/diff.md \
            --fail-on-regression

      - name: Post PR comment
        if: always() && github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/diff.md', 'utf8');
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body,
            });
```

## How the exit code works

`evidentia gap diff --fail-on-regression` exits with code 1 if any
of the following is true:

- **Opened** count > 0 (a new gap appeared in head that wasn't in base)
- **Severity increased** count > 0 (an existing gap got worse)

Severity decreases and gap closures do **not** fail the build — those
are good things.

Without `--fail-on-regression`, the command always exits 0 regardless
of diff content. Useful for reporting-only runs.

## Required permissions

- `contents: read` — to check out the repo
- `pull-requests: write` — only needed if you want the PR-comment step
  to post the diff back

## Alternative output formats

If you'd rather surface the diff as GitHub Actions annotations (inline
on the Checks page) instead of a PR comment:

```yaml
      - name: Gap diff (GitHub annotations)
        run: |
          evidentia gap diff \
            --base /tmp/base.json \
            --head /tmp/head.json \
            --format github \
            --fail-on-regression
```

Each opened gap becomes a `::error::` line; each severity increase
becomes a `::warning::`; each closure becomes a `::notice::`. GitHub
surfaces all three inline on the workflow summary page.

## Reusable composite action (v0.7.0+)

v0.7.0 ships the consolidated composite action at
[`.github/actions/gap-analysis/`](../../.github/actions/gap-analysis/).
The full ~80-line workflow above collapses to:

```yaml
      - uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
        with:
          inventory: inventory.yaml
          frameworks: nist-800-53-rev5-moderate,soc2-tsc
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

The composite action handles cache restore, the sticky PR comment via
`marocchino/sticky-pull-request-comment@v2`, regression gating, and
optional OSCAL AR + Sigstore signing.

**Migrating from `allenfbyrd/evidentia-action@v1`**: that standalone repo
is archived as of v0.7.0. See the
[composite-action README's migration guide](../../.github/actions/gap-analysis/README.md#migrating-from-allenfbyrdevidentia-actionv1)
for the diff.

## Troubleshooting

**"need two gap reports to diff"** — the cache didn't restore a baseline
and the current run isn't a push to `main`. Either run the workflow
manually on `main` once to seed the cache, or commit a pre-generated
`/tmp/base.json` to the repo (not recommended — keeps drift-prone
baseline in version control).

**PR comment has no content** — check that `pull-requests: write` is
granted in the workflow's `permissions:` block. GitHub 2023-03 tightened
defaults; without the explicit grant, the comment step silently no-ops.

**Stale baseline after a main merge** — `actions/cache` uses the cache
key, not invalidation semantics. After a main-branch push that changes
the baseline, the cached file is stale until `restore-keys` fails
(happens on the next unique branch). Workaround: add a `cache-key`
input that includes `${{ github.sha }}` for push events.
