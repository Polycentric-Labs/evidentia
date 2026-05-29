# CI integration

Running `evidentia gap analyze` in CI turns compliance into a check that runs on
every pull request — gaps surface in the same review surface developers already
use, and a regression can fail the build before it merges. This guide gives
copy-pasteable starter configs for **GitHub Actions**, **GitLab CI**, and
**Jenkins**, all built on the same two commands: `gap analyze --format sarif`
(produce findings) and `gap diff --fail-on-regression` (gate the build).

## Prerequisites

- A control inventory committed to the repo (`my-controls.yaml` — see
  [Run a gap analysis](run-gap-analysis.md)). `evidentia init` scaffolds one.
- Python 3.12+ available in the CI runner.

## The two building blocks

**Produce a SARIF log** (no extra install required — `sarif` is a first-class
format):

```bash
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate \
  --format sarif \
  --output gap-results.sarif
```

**Gate on regressions** — `gap diff --fail-on-regression` exits non-zero when a
change opens new gaps or increases severities relative to a base report:

```bash
evidentia gap diff --base base-report.json --head pr-report.json \
  --fail-on-regression --format github
```

The `github` diff format emits Actions workflow annotations; `console`, `json`,
and `markdown` are also available (see the [CLI reference](../4-reference/cli.md)).

## GitHub Actions — gap analysis + SARIF upload on PR

This workflow runs the analysis on every pull request and uploads the SARIF to
Code Scanning, where gaps appear under **Security → Code scanning**, grouped by
control:

```yaml
# .github/workflows/compliance.yml
name: compliance

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  gap-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Evidentia
        run: pip install evidentia

      - name: Gap analysis (SARIF)
        run: |
          evidentia gap analyze \
            --inventory my-controls.yaml \
            --frameworks nist-800-53-rev5-moderate \
            --format sarif \
            --output gap-results.sarif

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gap-results.sarif
          category: evidentia-gap-analysis
```

> SARIF upload *records* findings but does not fail the job by itself. Add a
> `gap diff --fail-on-regression` step (committing a base report, or fetching the
> previous run's report) when you want a hard gate. See
> [Emit SARIF](emit-sarif.md) for the severity-to-`level` mapping and
> fingerprinting details.

## GitLab CI — SARIF artifact + regression gate

GitLab's MR security dashboard ingests SARIF as a `sast` report artifact:

```yaml
# .gitlab-ci.yml
stages: [compliance]

evidentia-gap-analysis:
  stage: compliance
  image: python:3.12-slim
  before_script:
    - pip install evidentia
  script:
    - evidentia gap analyze
        --inventory my-controls.yaml
        --frameworks nist-800-53-rev5-moderate
        --format sarif
        --output gap-results.sarif
  artifacts:
    when: always
    paths:
      - gap-results.sarif
    reports:
      sast: gap-results.sarif
```

To fail a merge request on a compliance regression, add a job that diffs the MR
report against the target branch's report and relies on the non-zero exit:

```yaml
evidentia-regression-gate:
  stage: compliance
  image: python:3.12-slim
  before_script:
    - pip install evidentia
  script:
    # produce the current report, fetch/restore the base report, then:
    - evidentia gap diff --base base-report.json --head pr-report.json
        --fail-on-regression --format markdown
```

## Jenkins — declarative pipeline

```groovy
// Jenkinsfile
pipeline {
  agent any
  stages {
    stage('Compliance gap analysis') {
      steps {
        sh 'python3 -m venv .venv && . .venv/bin/activate && pip install evidentia'
        sh '''
          . .venv/bin/activate
          evidentia gap analyze \
            --inventory my-controls.yaml \
            --frameworks nist-800-53-rev5-moderate \
            --format sarif \
            --output gap-results.sarif
        '''
      }
    }
    stage('Regression gate') {
      steps {
        // Non-zero exit from gap diff fails the stage (sh propagates it).
        sh '''
          . .venv/bin/activate
          evidentia gap diff --base base-report.json --head pr-report.json \
            --fail-on-regression --format console
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'gap-results.sarif', allowEmptyArchive: true
      // Optional: a SARIF/Warnings-NG plugin can render gap-results.sarif.
      recordIssues tools: [sarif(pattern: 'gap-results.sarif')]
    }
  }
}
```

## Offline / self-hosted runners

In an air-gapped CI environment, install from a wheelhouse instead of PyPI and
add the `--offline` global flag to every command (`evidentia --offline gap
analyze ...`). See [Air-gapped install](air-gapped-install.md).

## What's next

- **SARIF details**: [Emit SARIF](emit-sarif.md) — severity mapping,
  fingerprints, Code Scanning specifics.
- **SIEM instead of Code Scanning**: [Emit OCSF Detection](emit-ocsf-detection.md).
- **Self-assess your own repo's OSS posture in CI**:
  [OSPS self-assessment](osps-self-assessment.md).

## Got stuck?

- **SARIF upload rejected as invalid** — confirm you used `--format sarif` and
  uploaded the `--output` file (not the console summary).
- **No results in Code Scanning** — the job needs `security-events: write`
  permission and a stable `category` across runs.
- **The regression gate never fails** — `gap diff` only exits non-zero with
  `--fail-on-regression`, and only when the *head* report has new/worse gaps than
  the *base*. Confirm both report paths are correct.
