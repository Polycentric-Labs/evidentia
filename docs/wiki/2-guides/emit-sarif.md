# Emit SARIF for CI gates and Code Scanning

`evidentia gap analyze --format sarif` renders a gap report as a SARIF 2.1.0 log.
SARIF is the format GitHub Code Scanning, GitLab MR security dashboards, and most
SARIF-aware viewers consume natively, so this is the fastest way to surface
compliance gaps inside the same review surface developers already use for SAST
findings.

## Prerequisites

- Evidentia installed, plus a control inventory (see
  [Run a gap analysis](run-gap-analysis.md)).
- For Code Scanning upload: a GitHub repository with the Code Scanning feature
  available, and the `codeql-action/upload-sarif` action (or the
  `gh api` upload endpoint).

## Step 1 — Produce the SARIF file

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --format=sarif \
  --output=gap-results.sarif
```

`sarif` is a first-class `--format` value — no extra install required. The output
is a standalone, schema-valid SARIF 2.1.0 document
(`$schema: https://json.schemastore.org/sarif-2.1.0.json`).

## How gaps map to SARIF

Each distinct control becomes one SARIF `rule` (reportingDescriptor); each
`ControlGap` becomes one `result`. Two design choices make the output behave well
in viewers:

- **Severity mapping.** Evidentia's `GapSeverity` maps to SARIF's fixed
  `level` vocabulary: `critical` and `high` escalate to `error`; `medium` becomes
  `warning`; `low` and `informational` become `note`. This lets a CI gate fail on
  `error`-level results while still recording the lower-severity gaps.
- **Locations.** Compliance gaps are not bound to a source-code line, so each
  result is anchored to the control inventory file (a physical location) *and* the
  control itself (a logical location). Viewers attribute the finding to the
  inventory rather than misattributing it to unrelated source code.

Each result also carries a stable `partialFingerprints` entry, so Code Scanning
can track a given gap across runs (open/fixed/reappeared) instead of treating
every scan as brand-new findings.

## Step 2 — Upload to GitHub Code Scanning

In a GitHub Actions workflow, run the analysis and hand the file to the standard
upload action:

```yaml
# .github/workflows/compliance.yml (excerpt)
- name: Gap analysis (SARIF)
  run: |
    evidentia gap analyze \
      --inventory=my-controls.yaml \
      --frameworks=nist-800-53-rev5-mod \
      --format=sarif \
      --output=gap-results.sarif

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gap-results.sarif
    category: evidentia-gap-analysis
```

The gaps then appear under the repository's **Security → Code scanning** tab,
grouped by control, with the severity levels described above.

> A complete starter workflow (gap analysis on PR plus SARIF upload) is covered
> in the [CI integration](ci-integration.md) guide.

## Step 3 (optional) — Fail the build on a regression

SARIF upload records findings but does not, by itself, fail a job. If you want a
hard gate, pair it with `evidentia gap diff --fail-on-regression`, which exits
non-zero when a PR opens new gaps or increases severities relative to a base
report:

```bash
evidentia gap diff --base=main-report.json --head=pr-report.json \
  --fail-on-regression --format=github
```

The `github` diff format emits Actions workflow annotations; see the
[CLI reference](../4-reference/cli.md) for the full `gap diff` surface.

## What's next

- **Wire the whole pipeline**: [CI integration](ci-integration.md).
- **SIEM instead of Code Scanning**: [Emit OCSF Detection](emit-ocsf-detection.md).
- **Auditor-grade artifact**: emit `--format oscal-ar` and sign it
  ([Run a gap analysis](run-gap-analysis.md#signing-the-oscal-output)).

## Got stuck?

- Upload rejected as invalid SARIF: confirm you used `--format=sarif` and that
  the file is the one written to `--output` (not the console summary).
- No results show up in Code Scanning: check the `category` matches across runs
  and that the workflow has `security-events: write` permission.
- Need the exact severity-to-level table again: it is in the section above and in
  the [CLI reference](../4-reference/cli.md).
