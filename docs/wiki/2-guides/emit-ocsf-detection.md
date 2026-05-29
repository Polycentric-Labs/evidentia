# Emit OCSF Detection Findings for a SIEM

`evidentia gap analyze --format ocsf-detection` renders a gap report as an array
of OCSF **Detection Finding** records (`class_uid` 2004). This is the
SIEM-targeted OCSF emit: Splunk, Elastic, Microsoft Sentinel, and Datadog all
ingest Detection Finding (2004) natively as production telemetry, so this format
drops compliance gaps straight into the same pipeline as your security events.

## Compliance Finding vs. Detection Finding — which to pick

Evidentia can emit two OCSF classes, and the distinction matters:

| Format | OCSF class | `class_uid` | Best for |
| --- | --- | --- | --- |
| `ocsf` | Compliance Finding | 2003 | OCSF-aware GRC tooling, data-lake landing zones |
| `ocsf-detection` | Detection Finding | 2004 | SIEM ingest (Splunk, Elastic, Sentinel, Datadog) |

Compliance Finding (2003) is the *semantically* correct class for a control
pass/fail verdict, but it is under-adopted by SIEM ingest pipelines. Detection
Finding (2004) is what those pipelines are already wired for. Both emits carry
the same gap data with the same severity mappings — the only structural
difference is the OCSF class. Pick `ocsf-detection` when your destination is a
SIEM; pick `ocsf` when your destination is OCSF-aware GRC tooling or a data lake.

## Prerequisites

- The optional OCSF extra: `pip install 'evidentia-core[ocsf]'`. Without it the
  command exits with a hint to install it.
- A control inventory (see [Run a gap analysis](run-gap-analysis.md)).

## Step 1 — Emit the Detection Finding array

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --format=ocsf-detection \
  --output=gap-detections.json
```

`ocsf-detection` is a first-class `--format` value. The output is a JSON array of
OCSF Detection Finding objects, each validated against the `class_uid` 2004
schema — one finding per gap.

## Step 2 — Ingest into your SIEM

The output is standard OCSF 2004, so the ingest path is whatever your SIEM
already uses for Detection Findings. A few common patterns:

- **Splunk**: route the JSON to an OCSF-aware index (for example via HEC), then
  query the `class_uid=2004` events alongside other detections.
- **Elastic / Microsoft Sentinel / Datadog**: point your existing OCSF ingest
  pipeline at the file or stream; no custom parser is needed because the records
  conform to the published 2004 schema.

Because each gap is a discrete Detection Finding, you can alert, dashboard, and
correlate compliance gaps using the same tooling you use for security events —
for example, surfacing newly opened critical-severity control gaps next to the
day's other high-severity detections.

## Severity mapping

Detection Findings inherit the same severity treatment as the rest of Evidentia's
emits, derived from each gap's `GapSeverity` (`critical` / `high` / `medium` /
`low` / `informational`). The verdict and severity travel with the finding, so
your SIEM's severity-based routing and alerting work without extra mapping on
your side.

## What's next

- **Compliance-class OCSF instead**: drop the `-detection` suffix to emit
  `--format ocsf` (Compliance Finding 2003).
- **Ingest the other direction**: pull third-party OCSF *into* Evidentia with
  [Ingest OCSF](ingest-ocsf.md).
- **The OCSF field map**: [Compliance → OCSF mapping](../5-compliance/ocsf-mapping.md).

## Got stuck?

- "OCSF ingestion needs the optional ocsf extra": run
  `pip install 'evidentia-core[ocsf]'` (the same extra powers ingest and emit).
- Your SIEM rejects the records: confirm it is configured for OCSF
  `class_uid` 2004 (Detection Finding), not 2003 (Compliance Finding) — see the
  table above.
- Need the full flag list: [CLI reference → `evidentia gap analyze`](../4-reference/cli.md).
