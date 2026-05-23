---
description: Ingest Prowler / AWS Security Hub OCSF JSON output, convert to Evidentia SecurityFinding, and crosswalk against a compliance framework (NIST 800-53, SOC 2, FedRAMP, etc.)
---

# Ingest OCSF + Crosswalk

Reads OCSF (Open Cybersecurity Schema Framework) JSON output —
typically from **Prowler** or **AWS Security Hub** — converts it
into Evidentia's normalized `SecurityFinding` model, then optionally
crosswalks the findings against a compliance framework so you see
which controls they affect.

Uses the `collect_ocsf` MCP tool (v0.10.2 — file mode only; URL
ingest is intentionally not exposed at the MCP layer because of the
SSRF surface). Pure read-only.

## Arguments

- `$1` — **OCSF JSON path** (required). Local file containing either
  a single OCSF finding or a JSON array. Both OCSF **Compliance
  Finding** (`class_uid` 2003) and **Detection Finding**
  (`class_uid` 2004 — what Prowler + AWS Security Hub emit) are
  auto-dispatched.
- `$2` — **Framework** (optional). Catalog ID for the crosswalk,
  e.g. `nist-800-53-rev5-moderate`. Omit to skip the crosswalk and
  just convert.
- `$3` — **Output SecurityFinding JSON path** (optional). Where to
  write the converted findings. Default: `evidentia-findings.json`
  in the current directory.

## Instructions

1. Call the **`collect_ocsf`** MCP tool with the user's `$1` input
   path. Capture the resulting list of `SecurityFinding` dicts.
2. Summarize the conversion:
   - Total findings count.
   - Per-`compliance_status` breakdown (`fail` / `warning` /
     `pass` / `unknown`).
   - Per-`source_system` breakdown (e.g., "Prowler", "AWS Security
     Hub").
   - For Detection Findings: note that `compliance_status` was
     **synthesized** from `severity_id` per Evidentia v0.10.1's
     heuristic (CRITICAL/HIGH/MEDIUM → FAIL, LOW → WARNING,
     INFORMATIONAL/UNKNOWN → UNKNOWN) — operators should treat
     these as best-effort until enriched.
3. Write the converted findings list to `$3` (or default) as
   pretty-printed JSON.
4. **If `$2` (framework) is provided**: use the framework name to
   look up which controls the detected findings map to. Use the
   `list_frameworks` + `get_control` MCP tools to fetch control
   metadata if needed. Surface a brief "findings → controls" table.
   For a complete gap analysis, suggest the user follow up with
   `/evidentia:gap-analyze-sarif`.

## Examples

```bash
# Prowler scan -> Evidentia findings (no crosswalk)
/evidentia:ingest-ocsf ./prowler-scan-2026-05.json

# AWS Security Hub findings -> NIST 800-53 crosswalk + JSON output
/evidentia:ingest-ocsf ./security-hub-export.json nist-800-53-rev5-moderate ./findings/aws-2026-05.json

# Cross-walk Prowler against SOC 2
/evidentia:ingest-ocsf ./prowler.json soc2-tsc
```

## Notes

- The MCP tool refuses unsupported OCSF `class_uid` values (anything
  other than 2003 or 2004) — surface the error message to the user
  if it fires; the source tool (Prowler version, Security Hub
  export format) likely needs adjusting.
- The OCSF `unmapped["evidentia"]` block is **ignored** on ingestion
  per the v0.10.1 F-V100-L1 trust-boundary fix — a third-party OCSF
  producer cannot impersonate Evidentia-native fields. See
  [`docs/ocsf-mapping.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/ocsf-mapping.md)
  §5.1 for the rationale.
- For the reverse direction (Evidentia → OCSF), use the
  `evidentia collect convert --format ocsf` CLI verb.
