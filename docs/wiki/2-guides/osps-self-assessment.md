# OSPS self-assessment

The [OpenSSF Open Source Project Security (OSPS) Baseline](https://baseline.openssf.org/)
is a tiered set of security expectations for open-source projects. Evidentia
ships the OSPS Baseline as a measurable framework *and* uses it on itself: the
repo carries an [`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md)
self-attestation, backed by a CI gate that re-validates every claimed-PASS
evidence link on every push. This guide explains how that pattern works and how
to fork it for your own project — measuring your repo against the Baseline with
Evidentia's GitHub OSPS collector helpers, and standing up the same link-rot CI
gate.

## What ships in the repo

- **`OSPS-CONFORMANCE.md`** — a machine-readable, per-control conformance
  attestation. Each row references an upstream OSPS Baseline assessment-
  requirement ID, a verdict (`PASS` / `HONEST_GAP` / `FAIL`), and an evidence
  link into the repo. Non-PASS verdicts are documented as `HONEST_GAP` with a
  concrete resolution path — never silently omitted.
- **[`.github/workflows/verify-osps-conformance.yml`](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/verify-osps-conformance.yml)**
  — a read-only CI gate. It parses `OSPS-CONFORMANCE.md`, translates each
  evidence link to the GitHub REST endpoint that authoritatively answers "does
  this resource exist on this ref", and probes it via `gh api`. An HTTP 404 on
  any claimed-PASS link fails the workflow, so conformance drift (a deleted or
  renamed evidence file) is caught at PR time rather than discovered by an
  auditor.
- **3 bundled OSPS Baseline catalogs** — one per maturity level, with framework
  IDs `osps-baseline-m1`, `osps-baseline-m2`, `osps-baseline-m3`. Run gap
  analysis against any of them.

## Step 1 — Measure your repo against the Baseline

Two complementary surfaces measure OSPS conformance:

**The OSPS collector helpers** (`evidentia_collectors.github.osps`) observe what
GitHub's REST API can confirm directly — ~16 automatable controls across Access
Control, Build & Release, Documentation, Governance, Legal, Quality, and
Vulnerability Management. Each `populate_osps_*(client, owner, repo)` helper
returns one `SecurityFinding` carrying a `compliance_status` (PASS / FAIL /
WARNING / NOT_APPLICABLE / UNKNOWN) and a `ControlMapping` against
`framework="osps-baseline"` (plus NIST 800-53 crosswalk mappings where natural).
These are a library surface you drive from a small script:

```python
from evidentia_collectors.github.client import GitHubClient
from evidentia_collectors.github import osps

with GitHubClient(token="ghp_...") as client:
    findings = [
        osps.populate_osps_ac_03_01(client, "your-org", "your-repo"),  # branch protection
        osps.populate_osps_vm_02_01(client, "your-org", "your-repo"),  # SECURITY.md
        osps.populate_osps_le_02_01(client, "your-org", "your-repo"),  # OSI/FSF license
        # ... the remaining populate_osps_* helpers
    ]
    for f in findings:
        print(f.source_finding_id, f.compliance_status)
```

A transport/5xx error on one check yields a finding with status `UNKNOWN`
(flagged, not dropped); a genuine absence (e.g. no `SECURITY.md`) is a definitive
`FAIL`.

**Gap analysis against the OSPS catalog** measures your control inventory
against the full Baseline at a chosen maturity level — including the controls
that are *not* observable from the GitHub API (process + policy controls you
attest to in your inventory):

```bash
evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks osps-baseline-m2 \
  --output osps-gap-report.json
```

Use `osps-baseline-m1` / `-m2` / `-m3` to target the maturity level you are
claiming. Confirm the exact catalog with `evidentia catalog show osps-baseline-m2`.

## Step 2 — Write your conformance statement

Model your `OSPS-CONFORMANCE.md` on Evidentia's: one row per upstream assessment-
requirement ID, a verdict, and a clickable evidence link into your repo. Keep
three disciplines:

1. **Pin the upstream baseline commit** you walked against, so the attestation is
   reproducible.
2. **Use `HONEST_GAP`, not omission**, for anything not yet PASS — with the
   concrete path to close it. Zero `FAIL` verdicts is the goal; honest gaps are
   acceptable and auditable.
3. **Make every PASS link resolvable** — the CI gate (Step 3) will enforce this.

## Step 3 — Fork the link-rot CI gate

Copy [`.github/workflows/verify-osps-conformance.yml`](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/verify-osps-conformance.yml)
(and its companion `scripts/verify_osps_conformance.py`) into your repo. The
workflow:

- Runs on **every push and PR to `main`** (deliberately no `paths:` filter, so a
  PR that renames/deletes an evidence-referenced file still triggers it) plus a
  weekly cron to catch out-of-band drift.
- Needs only **read** permissions (`contents: read`, `actions: read`); the
  default `GITHUB_TOKEN` is sufficient for the `gh api` probes.
- Fails on any claimed-PASS link that 404s — your cue to fix the link, restore
  the file, or downgrade the verdict to `HONEST_GAP`.

Adjust the repo owner/name references in the validator to your project, then the
gate keeps your attestation honest automatically.

## Step 4 — (Optional) gate OSPS gaps in CI

Fold the OSPS gap analysis into your CI pipeline the same way as any other
framework — emit SARIF for Code Scanning, or diff against a base report to fail
on regressions:

```bash
evidentia gap analyze --inventory my-controls.yaml \
  --frameworks osps-baseline-m2 --format sarif --output osps.sarif
```

See [CI integration](ci-integration.md) for the full GitHub Actions / GitLab /
Jenkins patterns.

## What's next

- [Compliance → OSPS Baseline mapping](../5-compliance/osps-baseline-mapping.md)
  — the bundled catalogs, OSCAL serialization, and the 5 inter-framework
  crosswalks (to NIST SSDF, CSF 2.0, EU CRA, PCI-DSS 4.0, NIST 800-161).
- [First collection](../1-getting-started/first-collection.md) — the GitHub
  collector basics the OSPS helpers build on.
- [Project → Verification](../6-project/verification.md) — verifying Evidentia's
  own released artifacts (the BR-family evidence behind several PASS verdicts).

## Got stuck?

- **`catalog ID not found`** — the OSPS framework IDs are `osps-baseline-m1`,
  `osps-baseline-m2`, `osps-baseline-m3` (per maturity level). Run
  `evidentia catalog list` to confirm.
- **A `populate_osps_*` finding is `UNKNOWN`** — a transient GitHub API error on
  that sub-check; the run still completes. Re-run, or check the token scope.
- **The CI gate fails on a link you believe is valid** — confirm the file exists
  on the `main` ref and the link path exactly matches; the probe checks existence
  on the referenced ref, not your local working tree.
