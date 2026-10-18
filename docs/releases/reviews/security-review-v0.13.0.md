# Security review: v0.13.0

**Release**: v0.13.0, release candidate prepared 2026-10-18 on
`chore/v013-candidate-hardening` (PR #401) with the review fixes on
`bugfix/v013-review-findings`; tag pending the owner's approval.
**Review shape**: full `/pre-release-review` (G29). The change adds new
endpoints, new credential paths and new collectors, so the ceremony was Step 1
checks, the 21-row pre-push gate, a per-subsystem review fan-out (eight
reviewers and three functional probers over `v0.12.1..HEAD`: 63 commits,
57 squash-merged PRs, 517 source files), the Step 5 fix batch, the Step 6
overview and, after the tag, the Step 7 verification. Per-run JSON:
`.local/pre-release-review/runs/2026-10-18T10-57-24Z-v0.13.0.json`.

## Cycle scope

Diff = v0.12.1..main. The release carries the v0.13 plan: the cadence evidence
series and day-granular cadences, native catalog sources, SCAP, incident clock,
registry, release cadence, storage and enterprise retention, Entra/M365 and
Google Workspace collectors, the Nessus and Greenbone importers, CycloneDX 1.7
exports, the MCP SDK 2.2 dispatch, text depth and withdrawn controls on every
catalog surface, the FedRAMP SCN writer, and the catalog truth gate. The
candidate hardening (PR #401) fixed the three product-side blockers: the osv
gate failing on the locked closure, two stale container bases, and MAJOR
FedRAMP schema drift.

## Verdict

**PROCEED with the review-findings PR, pending CI on that PR, the release
preflight on main and the owner's tag approval.** Two CRITICAL and eight HIGH
findings were fixed in the cycle; every deferred item is recorded with its
reason in `docs/releases/plans/v0.13.1-plan.md`.

## Summary

- Total findings across the eleven reports: 2 CRITICAL, 8 HIGH, 46 MEDIUM,
  about 60 LOW.
- All CRITICAL fixed pre-tag: yes. All HIGH fixed pre-tag: six of eight in code,
  one (the unexecuted release workflow) by the approved preflight dispatch, one
  (the breadth of RBAC gating) fixed on REST and deferred on the CLI with its
  rationale.
- Origin: both CRITICAL and five of the HIGH predate v0.12.1; the review
  found no CRITICAL regression introduced by v0.13.
- Compliance posture: NIST SSDF PW.4, PW.7 and PW.8 (review before release,
  code review, test); ISO 27001:2022 A.8.28 (secure coding) and A.8.29 (security
  testing); SOC 2 CC7.1 and CC8.1.

## Fix-now items applied in cycle

| Bucket | Finding | Fix |
|---|---|---|
| CRITICAL | `GET`/`PUT /api/config` returned the configuration with `${VAR}` expanded into live server env values, ungated, unbounded (CWE-526) | raw file contents in both responses, `read`/`admin` gates, unknown-key refusal, 1 MiB cap, atomic write |
| CRITICAL | request bodies named the server env var a route reads (`token_env`, `password_env`, `pat_name_env`, `pat_secret_env`, `client_secret_env`) with no constraint, and the routes carried no role gate (CWE-201) | names must match `^[A-Z][A-Z0-9_]{0,63}$` and the integration's prefix; the five pushes and every collect route are gated; strict booleans |
| HIGH | API fell back to the permissive default policy when the policy file could not be loaded (CWE-636) | startup refuses |
| HIGH | `POST /api/risk/generate` took any server path and echoed parser excerpts (CWE-22, CWE-209) | confined to the working directory, fixed message |
| HIGH | Nessus and Greenbone ingest persisted to the WORM store with no role check | `write` gate |
| HIGH | 57 of 89 mutating REST operations ungated while the docs claimed REST was gated | gates by effect class (D8); docs corrected; CLI deferred |
| HIGH | cadence series counted incomplete runs, import-dated artifacts and every version of a lineage (CWE-345) | provenance metadata, lineage counting, `excluded_observations`, as-of anchor |
| HIGH | nine new collectors emitted no audit events (CWE-778) | COLLECT_STARTED, COMPLETED and FAILED from each entry point |
| HIGH | no release.yml change since v0.12.1 had executed | preflight dispatch on main (approved) is a tag precondition |
| HIGH | Okta admin-assignment lookup failure reported PASS with zero admins | UNKNOWN, active finding |
| MEDIUM (26 fixed) | bounds, error handling, format checks, IDN pin, offline alert channels, signing flags, state loaders, CSV neutralisation, Power BI clear, ServiceNow outcome, release toolchain pins, gate fidelity (OSPS probe, docs link classifier, Tier C rows, pre-push filter), provider error text, 422 rendering, middleware path, vLLM key, eval gate semantics | see the CHANGELOG `[0.13.0]` review bullets |

## Deferred (documented dispositions)

Twenty MEDIUM items and the LOW list that need a design decision, a contract
change or a reviewed source capture are in
[`v0.13.1-plan.md`](../plans/v0.13.1-plan.md), each with its evidence pointer.
Two are owner decisions: the registry snapshot refresh (a reviewed source
capture) and the console bearer-token design.

## /security-review invocations

- Invocation 1 (Step 3, branch code review of the candidate hardening):
  8 findings, 5 fixed, 3 skipped with rationale (recorded in the per-run JSON).
- Invocation 2 (Step 4, per-subsystem): eight reviewers (core platform;
  API, CLI, MCP and AI; identity and retention collectors; existing modified
  collectors; clocks and registries; imports, catalogs and exports; release
  pipeline and gates; console) plus three functional probers (API, MCP and
  build; new core surfaces: 88 probes, 61 PASS, 21 WARN, 6 FAIL; new collector
  surfaces: 181 probes, 153 PASS, 11 WARN, 17 FAIL). Reports under the review
  working area.
- Invocation 3 (Step 6.C, full pre-tag): the review-findings PR runs the
  repository's 25 required checks and the 21-row pre-push gate; recorded in
  the per-run JSON when green.

## /code-review auto-fires

- Trigger 1 (new public API: 38 new routes, verbs or models): fired; covered
  by the API and collector partitions.
- Trigger 4 (audit, network_guard, OSCAL signing and verify, security/
  touched): fired; the core partition read those modules in full and found
  them format-only this release apart from the IDN pin key (fixed).

## The 21-row pre-push gate

Rows 1 to 12, 14 to 17, 19 and 20 were recorded PASS on the candidate branch
before PR #401; row 13 (container CVE scan) is delegated to the container
build and the preflight; row 18 (bypass audit) is recorded from the push
output ("no Bypassed rule violations"); row 21 (release workflow first live
run) passed its six static checks in the pipeline review and is satisfied at
runtime by the preflight dispatch. The gate re-runs on the review-findings
push; its output is attached to the per-run JSON.

## Step 7: post-tag verification

Pending the tag. The runner follows `docs/verification.md`: PyPI wheels and
attestations, SLSA provenance, reproducible build, the container signature,
the release SBOM scan, the fresh-install smoke and the GitHub Release assets.

## Cross-references

- [`CHANGELOG.md`](../../../CHANGELOG.md) `[0.13.0]`
- [`capability-matrix.md`](../../capability-matrix.md), the v0.13.0 snapshot
- [`threat-model.md`](../../threat-model.md), the v0.13.0 attack-surface delta
- [`v0.13.1-plan.md`](../plans/v0.13.1-plan.md), the deferrals
- [`release-checklist.md`](../../release-checklist.md)
