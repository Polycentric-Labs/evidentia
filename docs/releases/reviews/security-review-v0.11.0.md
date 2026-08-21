# Security review — v0.11.0

> **Status**: post-ship artifact for the v0.11.0 release — generated
> 2026-07-18 from the pre-tag per-run JSON
> (`.local/pre-release-review/runs/2026-07-17T02-40-00Z-v0.11.0.json`)
> plus the Step 7 post-tag verification results.
>
> **Theme**: the federal wave — FedRAMP CR26 Security Decision Record
> emission (`evidentia conmon ksi`, 10 families / 46 KSIs against the
> upstream 1.0.0-graduated schemas), OMB M-25-21 minimum-practice
> tracking (`ai-gov set-practice` + CAIO waiver objects), and OMB
> M-25-22 acquisition lifecycle (`ai-gov acquisition
> register|list|show|set-phase`, six §4 phases).
>
> **Variant**: pre-tag FULL per the G29 right-sizing rubric — the
> release adds new externally-reachable federal surfaces (CR26 SDR
> emitter + M-25-21/22 API+CLI + a file-backed store), so the full
> ceremony applied. Steps 3–4 ran as a fan-out of five per-subsystem
> security reviewers (fedramp-emitter / ai-gov-core / api-surface /
> cli-surface / workflows-and-docs) followed by adversarial
> verification of every finding.

## Cycle scope

v0.11.0 is the first release of the v0.11 cycle, tagged 2026-07-18
(annotated tag `d260eab` → commit `828a7f9`). The review covered the
full `v0.10.18..HEAD` delta: PR #194 (KSI emit + `fedramp-ksi-2026`
catalog + vendored CR26 schemas), PR #195 (M-25-21 practices), PR #196
(M-25-22 acquisitions), PR #197 (claim-accuracy sweep), PR #198 (CR26
schema re-vendor at the upstream SDR 1.0.0 graduation, pins
`@ae0dc43e`), and the release-prep commit (PR #199). PRs #200/#201
(verify-recipes sentinel fixes) landed after the review, before the
tag; PR #202 (About-text DSSE parenthetical) landed post-tag.

## Verdict

**CHANGES-REQUIRED → RESOLVED pre-tag.** The Step 3–4 fan-out surfaced
20 unique findings. 1 BLOCKER + 7 fix-now items were fixed on
`release/v0.11.0-prep` with a regression test each; 8 lower-severity
items were deferred to v0.12 with documented dispositions. The full
gate battery re-ran green post-fix; the tag was cut the following day.

## The BLOCKER (caught pre-tag)

| ID | CWE | Finding |
|---|---|---|
| F-V0110-B1 | CWE-471 | `ai-gov set-high-impact` (both API and CLI handlers) rebuilt `OMBHighImpactAssessment` from only determination/bases/rationale, resetting `practices` to `{}` — silently destroying all recorded M-25-21 practice status **and CAIO waiver provenance** on any bases/rationale amendment, contradicting the model's own retention docstring. Introduced by the v0.11 delta (the `practices` field was added but never merged forward). Reproduced live. |

**Fix**: both handlers now carry `practices=dict(prior.practices)`
forward when the entry already has an assessment. Regression tests:
`test_re_determination_preserves_recorded_practices` (CLI) +
`test_set_high_impact_preserves_recorded_practices` (API).

## Fix-now items applied in cycle

| ID | CWE | Severity | Finding | Fix |
|---|---|---|---|---|
| F-V0110-1 | CWE-694 | major | Duplicate KSI indicator keys in the status YAML were last-wins-merged, silently dropping earlier blocks from the federal SDR | Duplicate-key-rejecting SafeLoader subclass on the `ksi` status-file load (exit 2); `test_duplicate_indicator_key_rejected` |
| F-V0110-2 | CWE-223 | major | A state-file anchor keyed by a slug matching no bundled cadence silently omitted its dates from the SDR | `ksi` now warns on state-file slugs resolving to no known cadence; `test_unknown_state_file_slug_warns` |
| F-V0110-3 | CWE-770/1284 | major | `PracticeWaiver.issued_by` + `AIAcquisition.linked_system_id` + `RegisterAcquisitionRequest.linked_system_id` lacked `max_length` while every sibling was bounded (stored-amplification vector) | `max_length=256` on all three sites; two bounding tests |
| F-V0110-4 | CWE-1059/G28 | major | Threat-model delta claimed the new API mirrors inherit the idempotency-key body-hash mechanism; they do not (self-inflicted in release-prep) | Corrected: mechanism NOT on the v0.11 mutating routes; retry-dedup is a tracked v0.12 item |
| F-V0110-5 | CWE-755 | minor | `conmon ksi --out` to a missing/unwritable path dumped a raw pathlib traceback; write was non-atomic | Atomic write (tmp + `os.replace`) with clean error + `Exit(1)`; `test_unwritable_out_path_exits_1` |
| F-V0110-6 | G28 | minor | Capability-matrix row overclaimed a standing `gen_fedramp_ksi.py --check` CI drift gate (it runs on demand) | Reworded to the verified behavior |
| F-V0110-7 | G28 | minor | Capability-matrix row overclaimed active CAIO waiver-clock evaluation (helpers exist, wired to no runtime surface) | Reworded; runtime surfacing is a v0.12 item |

## Deferred to v0.12 (documented dispositions)

| CWE | Location | Finding |
|---|---|---|
| CWE-393 | `cli/conmon.py` | `conmon ksi` exits 1 (not 2) on a malformed `--state-file`, vs the fedramp-ksi.md exit-code contract (fix touches the shared `_load_last_completed_map` helper) |
| CWE-799 | `routers/ai_gov.py` | `POST /api/ai-gov/acquisitions` lacks the `X-Idempotency-Key` retry-dedup its sibling `/register` carries (design gap, documented in threat-model) |
| CWE-20 | `fedramp/ksi.py` | No `FormatChecker` on the `Draft202012Validator` (`format: uri` unenforced on operator-supplied provenance URIs) |
| CWE-345 | `fedramp/schemas/UPSTREAM.json` | No CI gate verifies the LOCAL vendored schema copies against their recorded sha256 (the sentinel checks live-upstream only) → v0.12 fragility-watches |
| CWE-1059 | `omb_m_25_21.py` | `waiver_certification_due` / `waiver_omb_report_overdue` helpers wired to no CLI/API/MCP surface → v0.12 GUI/verb pass |
| CWE-362 | `acquisition_store.py` | `save()` fixed per-record temp filename (concurrent-save race; pre-existing single-writer-localhost pattern, not a v0.11 regression) |
| CWE-345 | `fedramp-schema-watch.yml` | Tracking-issue selection matches by title across all authors → v0.12 CI hardening |
| CWE-117 | `check_fedramp_upstream_drift.py` | Upstream-controlled strings interpolated into `drift-findings.md` without newline neutralization (flows into a gh issue body; bounded blast radius) → v0.12 CI hardening |

## 3× validation

1. **Gate battery** — GREEN: ruff, mypy (292 files), docs-health
   `--strict` 0 FAIL, doc-counts, parity 93.4%, version-consistency,
   roadmap-currency (A4 clean), mirrors `--check`,
   changelog-vs-commits advisory-only.
2. **Live end-to-end exercise** — GREEN: every code fix exercised
   through the real CLI/API/models — blocker (set-high-impact
   preserves practices + waiver), duplicate key rejected (exit 2),
   unknown slug warns (exit 0), bad `--out` exits 1 with no traceback,
   `max_length` caps enforced.
3. **Adversarial re-review of the fix diff** — found and fixed ONE
   regression the fix itself introduced: the no-dup-key SafeLoader had
   dropped YAML merge-key (`<<`) support. Latent (zero `<<` usage
   in-repo) but it narrowed the brand-new feature's input surface.
   Fixed (dup-detect explicit key nodes only, then `flatten_mapping` +
   stock `construct_mapping`), verified merge keys + merge-override
   accepted while genuine dups still reject, and a merge-key
   regression test added. Rebuild of 8 wheels + twine check PASSED;
   osv scan PASS.

## Post-fix gates

pytest full suite green · ruff clean · mypy 292 files · docs-health
`--strict` 0 FAIL · doc-counts · parity 93.4% · version-consistency ·
roadmap-currency (A4 clean) · workflow perms/tools strict · `uv build`
8 wheels + twine PASSED · `run_osv_scan` PASS (osv-scanner v2.4.0) ·
Step-6 scour clean · Row-18 bypass audit (main ruleset
`bypass_actors=[]` active) · pypi/ghcr environments v*-tag-only +
required-reviewer.

## Step 7 — post-tag verification (2026-07-18) — ALL GREEN

| Sub-step | Result |
|---|---|
| release.yml | ✅ run 29659075287 completed/success through both required-reviewer deploy approvals |
| PyPI | ✅ 8/8 packages published at 0.11.0 |
| PEP 740 | ✅ 8/8 wheels verified (note: PyPI's attestation index lags the version index ~1 min post-publish — an immediate sweep can read a false 0/8; wait + re-run before alarm) |
| Container | ✅ cosign signature OK · cosign SLSA attestation (cosign v2.6.3) OK · `gh attestation verify` OK · `:latest` == `:v0.11.0` digest · public GHCR pull from an unauthenticated context OK · in-image `version` = "Evidentia v0.11.0" |
| Fresh install | ✅ `uvx --from evidentia==0.11.0 evidentia version` = v0.11.0; `catalog list` + `conmon ksi` + `ai-gov acquisition` verbs present in the published package |
| GitHub Release | ✅ SBOM asset (`evidentia-sbom.cdx.json`) + `evidentia.intoto.jsonl` + PEP 740 + cosign stanzas in the release body; latest == v0.11.0 |
| Alert hygiene | ✅ code-scanning 0 · Dependabot 0 |

## verify-recipes sentinel — first-run defects (fixed pre-tag)

The verify-recipes sentinel (consumer-side verification recipes)
debuted this cycle and its first runs surfaced two real defects in the
recipes themselves — both root-caused and fixed before the tag:

1. **PR #200** — the PEP 740 sweep counted 0/8 despite all wheels
   verifying: `pypi-attestations 0.0.29` writes `OK:` to **stderr**
   and the step captured stdout only. Fixed by counting by exit code.
2. **PR #201** — Recipe 3 reported "no matching attestations" (masked
   until #200 let the run reach it): the pinned cosign v2.4.1 cannot
   discover the SLSA attestation `actions/attest-build-provenance`
   stores via the OCI 1.1 referrers API. Fixed by pinning cosign
   v2.6.3. Empirically proven against the real image: v2.4.1 fails
   discovery while v2.6.3 and `gh attestation verify` both succeed —
   the attestation is real; only old-cosign discovery was broken.
   `docs/verification.md` gained a "requires cosign ≥ 2.6" note with a
   `gh attestation verify` fallback. Verifier-side cosign must stay
   ≥ 2.6; the release workflow's producer-side `cosign sign` pin is
   unaffected.

## Aggregate cycle metrics

| Metric | v0.11.0 |
|---|---|
| Review window | 2026-07-17T01:30Z → 02:40Z (pre-tag) |
| Head at review | `0b7d477e` (pre-fix; fixes committed on top before push) |
| Unique findings | 20 |
| BLOCKER / fix-now / deferred | 1 / 7 / 8 |
| Regression tests added for fixes | 7+ (one per code fix, incl. the merge-key regression) |
| Merged PRs in cycle | 8 (#194–#201) + #202 post-tag docs |
| Tag | `v0.11.0` (annotated `d260eab` → commit `828a7f9`, signed, `git tag -v` good) |
| **Overall verdict** | **CHANGES-REQUIRED → RESOLVED pre-tag; Step 7 post-tag ALL GREEN** |

## Cross-references

- Per-run JSON: `.local/pre-release-review/runs/2026-07-17T02-40-00Z-v0.11.0.json`
- CHANGELOG block: [CHANGELOG.md §[0.11.0]](../../../CHANGELOG.md)
- Plan: [docs/releases/plans/v0.11-plan.md](../plans/v0.11-plan.md) (re-cut boundary) · forward: [v0.12-plan.md](../plans/v0.12-plan.md)
- Threat-model delta: [docs/threat-model.md](../../threat-model.md) (v0.11.0 federal-surface section)
- Capability matrix: [docs/capability-matrix.md](../../capability-matrix.md) — v0.11.0 section
- Verification recipes: [docs/verification.md](../../verification.md) (cosign ≥ 2.6 note)
