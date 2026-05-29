# Your first evidence collection

Gap analysis tells you *what controls a framework expects*. Collectors tell you
*what your real systems actually do* — they pull live configuration from a
source system (GitHub, AWS, Okta, a SQL database, etc.) and emit
`SecurityFinding` records mapped to control families. This guide wires one
collector end-to-end: configure it, run it, inspect the findings, and fold them
into a gap analysis as tamper-evident OSCAL back-matter.

We use the **GitHub** collector because it needs only a personal access token
and a repository you can read — no cloud account required.

## Prerequisites

- Evidentia installed (`pip install evidentia`; verify with `evidentia version`).
- A GitHub repository you can read.
- A GitHub personal access token (classic or fine-grained) with `repo` read
  scope. A token is required for private repos and lifts the API rate limit on
  public ones.

## Step 1 — Configure the token

The GitHub collector reads its token from the `GITHUB_TOKEN` environment
variable by default (you can override with `--token`, but the env var keeps the
secret out of your shell history):

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

> Evidentia's collectors deliberately prefer environment variables / file paths
> for secrets over CLI value flags, so a token never lands in your shell history
> or a process listing.

## Step 2 — Run the collector

`evidentia collect github` takes a `--repo` in `owner/repo` form and writes the
findings JSON to `--output` (or stdout if omitted):

```bash
evidentia collect github \
  --repo octocat/Hello-World \
  --output findings.json
```

The collector inspects branch protection, CODEOWNERS presence, repository
visibility, and (where the token's scope allows) the security posture surface,
then writes a JSON list of `SecurityFinding` objects. You will see a summary on
the console and the full list in `findings.json`:

```
GitHub collection complete for octocat/Hello-World
  Findings: 7   (visibility, branch protection, CODEOWNERS, ...)
  Written:  findings.json
```

(Counts are illustrative — they depend on the repository's configuration.)

## Step 3 — Inspect the findings

Each finding carries a `compliance_status` (`pass` / `fail` / `warning` /
`not_applicable` / `unknown`), a `severity`, and one or more `control_mappings`
that tie the observation to NIST SP 800-53 Rev 5 control IDs (with an OLIR
relationship + a per-mapping justification). Open `findings.json` in your editor,
or pretty-print the first record:

```bash
python -c "import json,sys; d=json.load(open('findings.json')); print(json.dumps(d[0], indent=2))"
```

A branch-protection finding, for example, maps to access-enforcement controls
and records whether the default branch requires reviews before merge.

## Step 4 — Fold the findings into a gap analysis

The payoff: pass the findings to `evidentia gap analyze` with `--format oscal-ar`
and each finding is embedded in the OSCAL Assessment Results back-matter with a
SHA-256 digest, cross-referenced from observations that share a control ID:

```bash
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --findings findings.json \
  --format oscal-ar \
  --output assessment-results.json
```

(Don't have an inventory yet? `evidentia init --preset nist-moderate-starter`
scaffolds `evidentia.yaml` + `my-controls.yaml` you can edit — see the
[Quickstart](quickstart.md).)

The findings are now tamper-evident evidence attached to your assessment: an
auditor can recompute the SHA-256 of each back-matter resource and confirm it
matches the embedded digest. `--findings` is honored **only** with
`--format oscal-ar`; passing it with another format prints a note and ignores
the file.

## Step 5 — (Optional) convert findings to OCSF

If your downstream tooling speaks OCSF, convert the same findings file to an
OCSF Compliance Finding bundle (requires the `[ocsf]` extra,
`pip install "evidentia-core[ocsf]"`):

```bash
evidentia collect convert --input findings.json --format ocsf --output findings.ocsf.json
```

See [Guides → Ingest OCSF](../2-guides/ingest-ocsf.md) for the round-trip and
the SIEM-ingest path.

## What's next

- **Run the full gap workflow**: [Guides → Run a gap analysis](../2-guides/run-gap-analysis.md).
- **Try a cloud collector**: `evidentia collect aws` pulls AWS Config + Security
  Hub findings; see the [CLI reference](../4-reference/cli.md) for the full
  collector matrix (Okta, SQL, Snowflake, Databricks, Vanta, Drata, BitSight,
  SecurityScorecard).
- **Self-assess this repo's open-source posture**: [Guides → OSPS self-assessment](../2-guides/osps-self-assessment.md)
  uses the GitHub collector's OSPS Baseline helpers.

## Troubleshooting

- **`GitHubCollectorError: Could not read repo ...`** — the token cannot see the
  repository (wrong scope, private repo without access, or a typo in
  `--repo owner/repo`). Confirm the token works:
  `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/<owner>/<repo>`.
- **Rate-limit (HTTP 403/429)** — unauthenticated requests are throttled. Set
  `GITHUB_TOKEN` (Step 1) to use the authenticated 5000-req/hour limit.
- **A finding shows `compliance_status: unknown`** — a transient API/5xx error
  on one sub-check. The run still completes; the indeterminate item is flagged
  rather than dropped. Re-run to resolve.
