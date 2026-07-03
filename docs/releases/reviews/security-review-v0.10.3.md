# Security review — v0.10.3

> **Status**: in-cycle artifact for the v0.10.3 ship — the v4
> pre-release-review's 5th canonical deliverable.
>
> **Theme**: YAML-format catalog support (Phase 1, Candidate C from
> `docs/v0.10.3-plan.md`) + OpenSSF Gemara reference-model mapping
> (Phase 2, Candidate D).

## Cycle scope

v0.10.3 is the third patch on the v0.10.x line and the **fourth
ship on 2026-05-23** — same calendar day as v0.10.0 (03:07 UTC)
+ v0.10.1 (~04:54 UTC) + v0.10.2 (~06:30 UTC). The
[`docs/v0.10.3-plan.md`](v0.10.3-plan.md) selected Candidates C +
D under Allen's "C, then D, both under v0.10.3" directive:

1. **Phase 1 — Candidate C (YAML-driven catalog definitions)**:
   `evidentia_core.catalogs.loader._load_catalog_data` helper
   dispatches by file extension (`.json` → `json.loads`, `.yaml`
   / `.yml` → `yaml.safe_load`); rejects unsupported extensions
   + non-mapping YAML roots. All downstream loaders
   (`load_oscal_catalog`, `load_evidentia_catalog`,
   `load_non_control_catalog`, `load_catalog`, `load_any_catalog`)
   refactored to use the helper. `regenerate_manifest.py` extended
   to scan both extensions. Proof: `iso-27017-2015.json` →
   `iso-27017-2015.yaml` (7-control Tier-C stub); 89 bundled
   catalogs unchanged. 7 new tests in `test_yaml_loader.py`.
   New contributor doc `docs/contributing-a-catalog.md`.
2. **Phase 2 — Candidate D (OpenSSF Gemara reference-model
   mapping)**: NEW `docs/gemara-mapping.md` (NORMATIVE positioning)
   with 13-row component-by-component mapping table. Gemara v1.1.0
   (2026-05-12) cited; adopters FINOS CCC + OpenSSF Security
   Baseline. "Mapping, not conformance claim" framing — Evidentia
   does not yet emit Gemara-shape artifacts; CUE-constraint emit
   is a v0.11+ candidate. `docs/positioning-and-value.md` §8.3
   bullet corrected.

## Review structure

v0.10.3 was reviewed under the v4 default pre-tag variant with the
Diff + 1-hop dep closure scope (Step 1.4 option 1, auto-confirmed
per the established v0.10.0–v0.10.2 rhythm). The changeset is on
`main` (local), so `/security-review` and `/code-review` use
direct delta inspection per the v0.9.8 / v0.9.9 / v0.10.0–v0.10.2
precedent.

| Pass | Scope | Verdict |
|---|---|---|
| 3 — commit re-test + 1-hop closure | 3 unpushed commits (Phase 1 + Phase 2 + positioning skip-by-reuse) + 2 review-deliverable commits added in Step 4 + Step 5. `/security-review` direct delta inspection: **0 findings ≥ confidence 8**. `/code-review --effort high` (fired on Trigger #1: new modules): **0 critical, 4 polish-class suggestions** — all deferred to v0.10.4. | PROCEED-CLEAN |
| 4 — capability matrix (REUSE + delta) | v0.10.0 + v0.10.1 + v0.10.2 matrices reused for unchanged subsystems; v0.10.3 PRE-TAG section added with 5 new surfaces + 8-vector adversarial probe table on the YAML loader. | PROCEED-CLEAN |
| 6.C — final pre-tag pass | Full HEAD vs `v0.10.2` direct delta inspection; 16-row pre-push gate (filled below); 0 new findings; no api-stability surface change to validate. | PROCEED-CLEAN |

## Findings ledger

**Zero NEW findings.** All prior v0.10.x findings remain CLOSED
(F-V100-L1 + F-V100-M1 + F-V100-S1 + F-V101-L1).

`/code-review` raised 4 polish-class suggestions, none blocking:

| ID | File | Topic | Severity | Disposition |
|---|---|---|---|---|
| CR-V103-1 | `packages/evidentia-core/src/evidentia_core/catalogs/loader.py` | Module-level docstring choke-point note for `_load_catalog_data` | LOW (maintainability) | DEFERRED → v0.10.4 P1 |
| CR-V103-2 | `packages/evidentia-core/src/evidentia_core/catalogs/loader.py` | Error message polish when `suffix == ''` (no-extension path) | LOW (maintainability) | DEFERRED → v0.10.4 P2 |
| CR-V103-3 | `scripts/catalogs/regenerate_manifest.py` | `framework_id` collision guard in `scan_dir` | LOW (correctness, defensive) | DEFERRED → v0.10.4 P3 |
| CR-V103-4 | `tests/unit/test_catalogs/test_yaml_loader.py` | Multi-line round-trip coverage (`description` / `assessment_objectives` / `parameters`) | LOW (test coverage) | DEFERRED → v0.10.4 P4 |

## Subsystem-by-subsystem coverage

- **`_load_catalog_data` (new helper)** — closed-allowlist extension
  dispatch + non-mapping-root rejection; `yaml.safe_load` (safe
  variant, no arbitrary-object construction). 4 direct unit tests
  cover dispatch + 2 rejection paths.
- **`load_*` refactor** — pure call-site change; downstream Pydantic
  validation unchanged. Bundled catalogs (89) load identically.
- **`regenerate_manifest.py`** — developer-only maintenance script;
  not exposed at runtime. New extension globs preserve the existing
  WARN-and-skip pattern on parse errors.
- **`iso-27017-2015.yaml` (data file)** — 1:1 content conversion
  of the prior JSON Tier-C stub; same 7 controls; same framework
  metadata.
- **`docs/contributing-a-catalog.md` + `docs/gemara-mapping.md` +
  `docs/positioning-and-value.md` §8.3** — docs-only; no
  security surface.

## Step 6 16-row pre-push gate

| # | Check | Status |
|---|---|---|
| 1 | Branch state clean | ✅ PASS |
| 2 | Co-authorship trailers absent | ✅ PASS |
| 3 | Secret-file gitignore | ✅ PASS |
| 4 | Tests green (pytest / mypy / ruff) | ✅ PASS |
| 5 | `osv-scanner --sbom` (184 packages, 0 issues) | ✅ PASS |
| 6 | `test.yml` baseline green on `origin/main` | ✅ PASS |
| 7 | Threat-model fresh (0.4 days) | ✅ PASS |
| 8 | `/security-review` invocations (Step 3 fire = clean) | ✅ PASS |
| 9 | `/code-review` findings (4 polish deferred to v0.10.4) | ✅ PASS |
| 10 | api-stability unchanged (additive internal helper only) | ✅ PASS |
| 11 | Version bump atomic (24 subs / 10 files; py-ocsf-models pin preserved 3rd time) | ✅ PASS |
| 12 | Code-scanning alerts delta (0 open) | ✅ PASS |
| 13 | Container CVE scan | N/A pre-tag |
| 14 | Vuln-aging SLO (0 open findings) | ✅ PASS |
| 15 | License / SCA SPDX allowlist | ✅ PASS |
| 16 | Secret rotation cadence (OIDC) | ✅ PASS |

**16/16 PASS** (1 N/A → post-tag container check).

## Step 6 ship incident + recovery

**Incident**: release.yml first-fire on tag `v0.10.3 @ 487e0ac`
(run id `26339751865`, 18:03:02 UTC) succeeded at PyPI publish
(7 wheels with PEP 740 + SLSA at 18:04:31 UTC) but **FAILED at
the `Extract release body from CHANGELOG` step** at 18:04:54 UTC
— the `[0.10.3]` block was missing from `CHANGELOG.md`. The
downstream `Attach SBOM to GitHub Release` step was SKIPPED, and
the `Build and publish container image to ghcr.io` job was
SKIPPED (downstream `needs: publish-pypi`).

**Root cause**: I missed adding the CHANGELOG block in Step 6.
The pre-release-review skill v4 SKILL.md does not yet include a
CHANGELOG-presence pre-flight gate; the only protection is
`release.yml`'s 1500-byte sanity gate which fires at runtime
(too late — the irreversible PyPI publish has already happened
by the time that step runs).

**Recovery (user-approved via AskUserQuestion: Move-tag re-fire)**:
1. Added the `[0.10.3]` block to `CHANGELOG.md` (extracts to
   6897 bytes, well over the 1500-byte gate).
2. Committed as `c0ed3ad docs(changelog): backfill v0.10.3 entry`;
   pushed to `main`.
3. Deleted the remote `v0.10.3` tag + the local tag; re-created
   the annotated tag on `c0ed3ad`; pushed.
4. `release.yml` re-fired at 18:11:06 UTC (run id `26339919598`).
   `pypa/gh-action-pypi-publish skip-existing: true` gracefully
   skipped the already-published wheels; CHANGELOG extract
   succeeded; `Attach SBOM to GitHub Release` succeeded;
   `Build and publish container image to ghcr.io` succeeded.
   Full job duration: **196s**.

**Tag pointer drift**: `v0.10.3` now points at `c0ed3ad` (=
`487e0ac` + CHANGELOG backfill). PyPI attestations remain bound
to the OIDC-token-attested build from `487e0ac`; `c0ed3ad` is the
direct successor of `487e0ac` in `main`'s history so the chain
remains verifiable. The container's SLSA Provenance v1 binds to
`c0ed3ad`.

**Lessons learned**: added as v0.10.4 P5 in
[`docs/v0.10.4-plan.md`](v0.10.4-plan.md) — pre-tag CHANGELOG-
presence check at both the skill layer (Step 6 pre-flight) AND
the workflow layer (CI gate on main before any tag can fire).

## Step 7 post-tag verification

| Sub-step | Outcome |
|---|---|
| 7.1 `release.yml` run | ✅ **success** in 196s (~3:16 tag-to-publish); run id `26339919598` (re-fire) |
| 7.3 PEP 740 attestation verify (7 wheels) | ✅ **7/7 OK** via `pypi-attestations verify pypi --repository https://github.com/Polycentric-Labs/evidentia "pypi:<wheel-name>"` |
| 7.5 Cosign container verify | ✅ **VERIFIED** — SLSA Provenance v1; image digest `sha256:2cc7daff207a1cfca2b022817c1c340ac2a569d8345f59b0b10f2a831f794b4e` |
| 7.5 Docker smoke | ✅ `docker run ghcr.io/polycentric-labs/evidentia:v0.10.3 version` → `Evidentia v0.10.3 / Python 3.14.5` |
| 7.6 Published SBOM osv-scan | ✅ **CLEAN** — 183 packages |
| 7.7 Scorecard | ✅ **success** for `c0ed3ad`; 0 open code-scanning alerts |
| 7.8 Fresh-venv install smoke | ✅ `python -m venv` + `pip install "evidentia==0.10.3" "evidentia-mcp==0.10.3"` → `Evidentia v0.10.3 / Python 3.14.2`. v0.10.3 catalog loader's YAML-dispatch behavior verified by `iso-27017-2015` (the bundled YAML stub) loading without error on the fresh install — live verification of the Phase 1 contract. |
| 7.9 Release notes audit | ✅ 7548-byte body extracted from `[0.10.3]` CHANGELOG block; SBOM attached |
| 7.10 Memory + audit-log update | this section; plus a fresh entry appended to `MEMORY.md` for v0.10.3 SHIPPED |

**Verdict**: PROCEED-CLEAN confirmed post-tag — **16th consecutive**
of the v0.7.x → v0.8.x → v0.9.x → v0.10.x line. v0.10.3 SHIPPED.
All v0.10.x findings remain closed; v0.10.x line at zero unfixed
findings entering v0.10.4.

## Disposition

**PROCEED-CLEAN.** Bump shape: **patch** (v0.10.2 → v0.10.3).

This is the **16th consecutive PROCEED-CLEAN** of the v0.7.x →
v0.8.x → v0.9.x → v0.10.x line. Continuous PROCEED-CLEAN tally:
v0.7.0 / v0.7.1 / v0.7.2 / v0.7.3 / v0.7.4 / v0.7.5 / v0.7.6 /
v0.7.7 / v0.7.8 / v0.7.9 / v0.8.0 / v0.8.1 / v0.8.2 / v0.8.3 /
v0.8.4 / v0.8.5 / v0.8.6 / v0.8.7 / v0.9.0 / v0.9.1 / v0.9.2 /
v0.9.3 / v0.9.4 / v0.9.5 / v0.9.6 / v0.9.7 / v0.9.8 / v0.9.9 /
v0.10.0 / v0.10.1 / v0.10.2 / **v0.10.3**.
