# Run a gap analysis

The core Evidentia workflow: compare a control inventory against one or more
framework catalogs and produce a prioritized list of gaps. This guide covers
catalog selection, inventory conventions, every output format, and how partial
coverage is scored.

`evidentia gap analyze` is inventory-driven — you point it at a file describing
the controls your organization *has* (`--inventory`) and the frameworks you want
to be measured *against* (`--frameworks`). It does not crawl an evidence
directory; evidence collection is a separate step that produces a findings JSON
you can optionally fold in (see [below](#folding-in-collector-findings)).

## Prerequisites

- Evidentia installed (`pip install evidentia`; verify with `evidentia version`).
- A control inventory file (YAML, CSV, or JSON). If you do not have one yet,
  `evidentia init --preset soc2-starter` scaffolds an `evidentia.yaml` plus a
  starter `my-controls.yaml` you can edit.

## Step 1 — Pick your frameworks

List what is available and filter by redistribution tier:

```bash
evidentia catalog list --tier=A
```

Tier-A catalogs are production-grade and verbatim-licensed. Note the framework
IDs you care about (for example `nist-800-53-rev5-mod`, `soc2-tsc`). You can
analyze against several at once — Evidentia will also surface cross-framework
efficiency opportunities (one control that closes gaps in 3+ frameworks).

To inspect a single framework before committing:

```bash
evidentia catalog show nist-800-53-rev5-low
```

## Step 2 — Run the analysis

The minimal invocation needs an inventory, a framework list, and an output path:

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod,soc2-tsc \
  --output=gap-report.json
```

`--frameworks` (`-f`) is a comma-separated list. If you omit it, Evidentia falls
back to the `frameworks:` list in your `evidentia.yaml`; if neither is present it
exits with an error. `--inventory` (`-i`) and `--output` (`-o`) are required.

You will see a summary table plus the top 5 priority gaps printed to the
console, and the full report written to `--output`:

```
                 Gap Analysis Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Metric                     ┃     Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Total controls required    │       421 │
│ Total gaps                 │        63 │
│ Critical                   │         4 │
│ High                       │        18 │
│ Medium                     │        29 │
│ Low                        │        12 │
│ Coverage                   │     78.4% │
│ Efficiency opportunities   │         7 │
└────────────────────────────┴───────────┘
```

(Counts above are illustrative.) The report is also snapshotted to a per-user
gap store so `evidentia gap diff` and `evidentia risk generate --gap-id` can
find it without you re-specifying `--gaps`.

## Step 3 — Choose an output format

`--format` controls the shape of the `--output` file. The accepted values are:

| `--format` | What it produces | Typical use |
| --- | --- | --- |
| `json` (default) | The full `GapAnalysisReport` model | Programmatic post-processing, the gap store |
| `csv` | One row per gap | Spreadsheets, quick triage |
| `markdown` | A human-readable report | PR comments, tickets, email |
| `oscal-ar` | NIST OSCAL Assessment Results 1.2.x | Auditor handoff, FedRAMP packages |
| `sarif` | SARIF 2.1.0 log | CI gates, GitHub Code Scanning ([guide](emit-sarif.md)) |
| `ocsf` | OCSF Compliance Finding (class_uid 2003) | OCSF-aware GRC tooling, data lakes |
| `ocsf-detection` | OCSF Detection Finding (class_uid 2004) | SIEM ingest ([guide](emit-ocsf-detection.md)) |
| `cyclonedx-vex` | CycloneDX 1.6 VEX | Supply-chain workflows ([guide](emit-cyclonedx-vex.md)) |

For example, to hand an auditor an OSCAL Assessment Results document:

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --format=oscal-ar \
  --output=assessment-results.json
```

The `ocsf` and `ocsf-detection` formats require the optional `[ocsf]` extra
(`pip install 'evidentia-core[ocsf]'`).

## Understanding partial coverage

Each gap carries an `implementation_status` (`missing`, `partial`, `planned`,
or `not_applicable`) and a `gap_severity`. A control your inventory addresses
only partially still surfaces as a gap — at a lower severity than a fully
missing one — so partial credit is visible rather than silently rounded up.
The summary's coverage percentage counts only *fully* implemented controls; a
partially covered control does not count toward it. See
[Concepts → Data model](../3-concepts/data-model.md) for the exact
`ControlGap` field semantics.

## Folding in collector findings

If you have run an evidence collector (for example `evidentia collect aws
--output findings.json`), you can embed those findings as tamper-evident OSCAL
back-matter resources — but only with `--format oscal-ar`:

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --findings=findings.json \
  --format=oscal-ar \
  --output=assessment-results.json
```

Each finding is hashed (SHA-256) and cross-referenced from observations that
share a control ID. Passing `--findings` with any other format prints a note and
ignores the file. (To convert collector findings to OCSF directly, see
[Ingest OCSF](ingest-ocsf.md) and `evidentia collect convert`.)

## Signing the OSCAL output

For an auditor-defensible chain of custody, sign the `oscal-ar` export. GPG
produces a detached `.asc` signature; Sigstore produces a keyless Rekor bundle:

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --format=oscal-ar \
  --output=assessment-results.json \
  --sign-with-gpg=YOUR_KEY_ID
```

Verify later with `evidentia oscal verify assessment-results.json
--require-signature`. Sigstore signing (`--sign-with-sigstore`) requires the
`[sigstore]` extra and is refused in `--offline` mode (use GPG in air-gapped
environments).

## What's next

- **Track gaps as a remediation plan**: turn the report into POA&M items
  ([Manage POA&M](manage-poam.md)).
- **Gate a pull request**: emit SARIF and upload it to Code Scanning
  ([Emit SARIF](emit-sarif.md)).
- **Compare two runs**: `evidentia gap diff --fail-on-regression` blocks a PR
  that opens new gaps (see the [CLI reference](../4-reference/cli.md)).
- **Browse the full framework set**: [Compliance → Catalog inventory](../5-compliance/catalog-inventory.md).

## Got stuck?

- Full flag reference: [CLI reference → `evidentia gap analyze`](../4-reference/cli.md).
- "No frameworks specified": pass `--frameworks` or add a `frameworks:` list to
  `evidentia.yaml`.
- Catalog ID not found: run `evidentia catalog list` to confirm the exact ID, or
  `evidentia catalog where <id>` to see where it resolves from.
