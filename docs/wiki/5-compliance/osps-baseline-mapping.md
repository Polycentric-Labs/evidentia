# OpenSSF OSPS Baseline mapping

Evidentia ships the first publicly-distributed NIST OSCAL Catalog 1.2.1 serialization of the OpenSSF Open Source Project Security Baseline. This page covers what's included, where the upstream lives, and how to use it.

## What's bundled (v0.10.6)

- **3 per-maturity YAML catalogs** at `packages/evidentia-core/src/evidentia_core/catalogs/data/international/osps-baseline-m{1,2,3}.yaml`. Maturity 1 = 25 assessment-requirements (17 top-level controls); Maturity 2 = 42 assessment-requirements (32 top-level controls); Maturity 3 = 63 assessment-requirements (40 top-level controls). Total 41 unique top-level controls across all 3 maturity levels.

- **1 OSCAL Catalog 1.2.1 serialization** at `osps-baseline.oscal.json`. Top-level-control granularity (41 controls). Validates against `compliance-trestle` Pydantic models (re-validated at 4.2.0, 2026-07-10).

- **5 inter-framework crosswalks** at `mappings/osps-baseline_to_{nist-ssdf-800-218,nist-csf-2.0,eu-cra,pci-dss-4.0,nist-800-161}.json`. Rows are keyed at OSPS assessment-requirement level (for example `OSPS-AC-01.01`, not the top-level control `OSPS-AC-01`) and declare `source_framework: osps-baseline`, the `crosswalk_family` all three bundled OSPS catalogs share, so an `osps-baseline-m1`, `-m2` or `-m3` gap analysis resolves through them. Current row counts are on the generated crosswalks reference page: [`docs/wiki/4-reference/crosswalks.md`](../4-reference/crosswalks.md). All carry `provenance: upstream-osps-guidelines` and `verification: self-attested-via-upstream` (auto-extracted from upstream OSPS Baseline `guidelines[]` array at the pinned commit, not independently hand-verified; see verification posture below).

- **16 GitHub OSPS collector helpers** at `packages/evidentia-collectors/src/evidentia_collectors/github/osps.py`. Cover AC + BR + DO + GV + LE + QA + VM family assessment-requirements via GitHub REST API. Each helper emits a `SecurityFinding` with `compliance_status` mapped from the GitHub API observation.

## Upstream pinning

- Source: [`ossf/security-baseline`](https://github.com/ossf/security-baseline) at commit [`ac6bbec8aecf51dce41f62712745f7949ab6bdeb`](https://github.com/ossf/security-baseline/commit/ac6bbec8aecf51dce41f62712745f7949ab6bdeb) (May 12, 2026).
- Catalog version string: `osps-baseline-2026.02.19`.
- License: Apache-2.0 (Evidentia ships verbatim under upstream's Apache-2.0 license per Tier-A redistribution rules).

## Verification posture

Per the v0.10.6 cycle's brainstorm decision (see `docs/v0.10.6-plan.md` §4.5 + §12.1), the 5 OSPS crosswalks ship raw with explicit upstream-attested disclaimer. The `CrosswalkDefinition` schema was extended additively in v0.10.6 with 3 optional fields:

- `provenance: str | None` — e.g., `"upstream-osps-guidelines"`
- `verification: Literal["self-attested-via-upstream", "hand-checked"] | None` — currently `"self-attested-via-upstream"` for all 5 OSPS crosswalks
- `verification_note: str | None` — free-form documentation of the verification posture

**Translation for consumers**: the 5 OSPS crosswalks are mechanical extracts of upstream OSPS Baseline `guidelines[]` references to other frameworks. They are NOT independently SME-verified against (e.g.) the actual text of NIST SSDF SP 800-218 control PO.1.1. Consumers requiring independent verification should plan a hand-check pass. The v0.10.7+ roadmap targets converting `"self-attested-via-upstream"` → `"hand-checked"` once SME review is complete.

## Evidentia's own OSPS Baseline conformance

Evidentia self-attests against the OSPS Baseline at [`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md). The conformance claim is **Maturity 2 + partial Maturity 3** as of v0.10.6. The `verify-osps-conformance.yml` GitHub Actions workflow re-validates every evidence link in the conformance doc on every push, PR, and weekly cron — ensuring the claim stays honest as the codebase evolves.

## How to use the OSPS crosswalks

```python
from evidentia_core.catalogs.crosswalk import CrosswalkEngine, MAPPINGS_DIR

engine = CrosswalkEngine()
cw = engine.load_crosswalk(MAPPINGS_DIR / "osps-baseline_to_nist-ssdf-800-218.json")
print(f"{cw.source_framework} → {cw.target_framework}")
print(f"Verification: {cw.verification}")
print(f"Mappings: {len(cw.mappings)}")
for m in cw.mappings[:3]:
    print(f"  {m.source_control_id} → {m.target_control_id} ({m.relationship})")
```

Output:
```
osps-baseline → nist-ssdf-800-218
Verification: self-attested-via-upstream
Mappings: 226
  OSPS-AC-01.01 → PO.3.2 (related)
  OSPS-AC-01.01 → PS.1.1 (related)
  OSPS-AC-01.01 → PS.2.1 (related)
```

## Running GitHub OSPS conformance checks

```python
from evidentia_collectors.github import GitHubClient
from evidentia_collectors.github.osps import (
    populate_osps_ac_03_01,  # branch protection on default branch
    populate_osps_le_02_01,  # OSI/FSF-recognized SPDX license
    populate_osps_vm_05_03,  # Dependabot enabled
    # ... 13 more
)

with GitHubClient(token="ghp_...") as gh:
    finding = populate_osps_ac_03_01(gh, owner="myorg", repo="myrepo")
    print(f"{finding.title}: {finding.compliance_status.value}")
```

Full list of 16 helpers: see [`evidentia_collectors.github.osps`](../4-reference/api/evidentia-collectors.md) (api reference).

## OSCAL upstream contribution

The OSPS Baseline OSCAL conversion was proposed for inclusion in the canonical `awesome-oscal` list maintained by the OSCAL Club community group: [oscal-club/awesome-oscal#59](https://github.com/oscal-club/awesome-oscal/pull/59).

## Further verification

The five upstream-derived crosswalks retain their `self-attested-via-upstream`
posture. An operator with subject-matter expertise must verify each mapping
before audit use. See the [roadmap](../6-project/roadmap.md) for the open cycle.
