---
description: Run an Evidentia gap analysis against a control inventory and emit SARIF 2.1.0 — drop the output into a CI gate (GitHub code scanning / GitLab security dashboards / any SARIF viewer)
---

# Gap Analysis → SARIF (CI-gate output)

Runs an Evidentia gap analysis against a local control inventory and
returns the result as a **SARIF 2.1.0** log. SARIF is the standard
input format for GitHub code scanning, GitLab security dashboards,
and IDE SARIF viewers — so a single skill invocation gives you both
the analysis AND the CI-gate artifact in one step.

Uses the `gap_analyze_sarif` Evidentia MCP tool (v0.10.2). Pure
read-only: no API calls, no network, no LLM inference. Pair with
`@github/actions` skills (or any CI-config skill) to wire the
output into a workflow.

## Arguments

- `$1` — **Control inventory path** (required). Filesystem path to a
  YAML / CSV / JSON file. Evidentia's loader auto-detects the format.
- `$2` — **Frameworks** (required). Comma-separated catalog IDs to
  assess against, e.g. `nist-800-53-mod,soc2-tsc,fedramp-mod`.
  Discover available IDs with `/evidentia:list-frameworks` (or via
  the `list_frameworks` MCP tool).
- `$3` — **Output SARIF path** (optional). Where to write the SARIF
  log on disk. Default: `evidentia-gaps.sarif` in the current
  directory.

## Instructions

1. Call the **`gap_analyze_sarif`** MCP tool with the user's inventory
   path + frameworks. Default `show_efficiency=True`.
2. Write the returned dict to the output path (`$3` or the default)
   as pretty-printed JSON.
3. Summarize:
   - Total results count and per-level breakdown
     (`error`/`warning`/`note`).
   - The top 5 highest-priority results (by SARIF level then rule).
   - Stable `partialFingerprints` mean re-running on the same
     inventory produces the same finding IDs — usable directly as
     PR-comment anchors.
4. **CI-wiring suggestion** (optional, only if the user mentions
   CI): show the GitHub Actions snippet for the
   [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
   step that uploads the file. Do NOT modify the user's repo
   without explicit confirmation.

## Examples

```bash
# Single framework against a YAML inventory
/evidentia:gap-analyze-sarif ./controls.yaml nist-800-53-mod

# Cross-framework (NIST + SOC 2) with a custom output path
/evidentia:gap-analyze-sarif ./inventory/meridian-fintech.yaml nist-800-53-mod,soc2-tsc ./compliance.sarif

# FedRAMP-Mod-only against a CSV inventory exported from your GRC
# spreadsheet, with the SARIF written to .github/ for direct upload
/evidentia:gap-analyze-sarif ./gov-controls.csv fedramp-mod ./.github/evidentia-gaps.sarif
```

## Notes

- The SARIF output validates against the official SARIF 2.1.0 schema
  (https://json.schemastore.org/sarif-2.1.0.json).
- `evidentia gap` also accepts `--format sarif` if you prefer to run
  the CLI directly without this skill.
- Severity mapping: Evidentia `critical`/`high` → SARIF `error`;
  `medium` → `warning`; `low`/`informational` → `note`.
