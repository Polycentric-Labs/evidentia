# v0.7.12 Pre-tag /security-review (canonical)

> **Status**: Pre-tag review complete; tag pending Allen approval.
> **Skill**: `/pre-release-review` v4 (`2026.04.30-v4`).
> **Variant**: Pre-tag (full v4 7-step).
> **Diff range**: `v0.7.11..HEAD` (16 commits, +5,612 lines, 0 commits pushed at review time).
> **Review date**: 2026-05-04.

This is the 5th canonical Pre-tag deliverable per v4 G7. CVSS / CWE
/ EPSS columns + 6-framework compliance mapping (NIST SSDF + SLSA +
ISO 27001 + SOC 2 + DORA + OpenSSF) inline below.

---

## Verdict

**PROCEED-CLEAN** — second consecutive PROCEED-CLEAN of the v0.7.x
cycle (v0.7.11 was the first). 0 unfixed findings at Pre-tag close;
1 inline-fix applied during the review (audit-event emit on
GDPR purge).

---

## /security-review invocation summary (G12 — 3 of 3 complete)

| Inv | Step | Scope | Verdict | Findings | Disposition |
|---|---|---|---|---|---|
| 1 | Step 3 | `v0.7.11..HEAD` diff (15 commits at the time) | PROCEED-CLEAN | 0 | + 1 non-finding observation: GDPR purge_immediately doesn't emit RETENTION_GDPR_PURGE audit event despite docstring + threat-model claim |
| 2 | Step 4 | Per-subsystem on E (6-store harmony) + F (REST surface) + G (WORM contract) + H (state machines); A/B/C/D unchanged | PROCEED-CLEAN | 0 | All 4 in-scope subsystems verified |
| 3 | Step 6.C | Post-Step-5 inline-fix delta (commit `7a96fe1` only) | PROCEED-CLEAN | 0 | Purely additive observability + test; no new attack surface |

The Step 3 non-finding observation was inline-fixed in commit
`7a96fe1` (audit-event emit + new test
`test_purge_emits_gdpr_audit_event`). Step 6.C re-validated the
fix.

---

## Findings table

| ID | Sev | CVSS | CWE | EPSS | Location | Disposition |
|---|---|---|---|---|---|---|
*(empty — PROCEED-CLEAN)*

---

## Inline-fix applied during review

| Commit | Fix | Trigger |
|---|---|---|
| `7a96fe1` | `WORMBackend.purge_immediately` now emits `RETENTION_GDPR_PURGE` audit event with `record_id` + `gdpr_request_ref` + `operator_id` + `classification` + `retention_period_days`. Wrapped in try/except so audit-logger failure does NOT unwind the already-completed purge. | Step 3 /security-review observation: threat-model.md v0.7.12 delta promised "every put / delete / extend_retention / legal_hold operation flows through the audit logger" but `purge_immediately` was missing the emit. |
| `6b9d383` | `docs/positioning-and-value.md` line 886 — replaced legacy commercialization-vocabulary phrase in an SACR-targeting row with neutral "OSS-GRC deep dive" framing. | Step 6.D 16-row pre-push gate row 4 (standing-rule keyword sweep). Pre-existing leak shipped since v0.7.8; v0.7.9-v0.7.11 skipped it via Step 2 skip-by-reuse. |

---

## Closure-scope regression check (6 secure stores)

All 6 stores' resolution helpers (`get_<store>_dir`) follow
identical 3-tier pattern (override → env-var → platformdirs):

| Store | Status | Notes |
|---|---|---|
| `vendor_store` | ✅ PASS | unchanged in diff (was already harmonized in v0.7.11) |
| `model_risk_store` | ✅ PASS | unchanged in diff (was already harmonized in v0.7.11) |
| `effective_challenge_store` | ✅ PASS | newly harmonized in v0.7.12 commit `d18930f` |
| `metric_store` | ✅ PASS | newly harmonized in v0.7.12 commit `d18930f` |
| `workflow_store` | ✅ PASS | newly harmonized in v0.7.12 commit `d18930f` |
| `retention_metadata_store` | ✅ PASS | newly harmonized in v0.7.12 commit `d18930f` |

All 6 now apply `Path(env).expanduser().resolve()` consistently —
defensive normalization before downstream `validate_within()` sees
any external input.

---

## Adversarial probing summary (v0.7.12 surfaces)

Coverage: **7 of 7 vectors** (cloud-WORM SDKs introduce real
network surface for the first time in retention/).

| Vector | Coverage |
|---|---|
| Bad input | SSC `portfolio_id` allow-list catches 19 distinct unsafe shapes (parametrized in `tests/integration/test_api/test_collectors.py::TestSecurityScorecardCollectEndpointSSRFGuard`); PERT range validator catches `low > most_likely > high`; Monte Carlo iterations < 1 rejected; cloud bucket name required non-empty; lock_mode allow-list ("COMPLIANCE"\|"GOVERNANCE" for S3, "Locked"\|"Unlocked" for Azure) |
| Missing dependency | Lazy imports + clear ImportError messages directing to `evidentia[worm-s3]` / `[worm-azure]` / `[worm-gcs]`; verified by inspection across all 3 cloud backend modules |
| Network failure | Cloud SDK errors (`HttpResponseError` / `ClientError` / `GoogleAPIError`) surface as `WORMBackendError` preserving the cloud-side message; tests confirm error-translation contract via mocked SDK clients |
| Expired credential | Cloud SDK auth chains handle this canonically — fail-closed (no anonymous fallback); tests via mocked clients |
| Malformed config | Bucket-name + lock-mode validation at backend `__init__`; rejected before any HTTP call |
| Concurrent request / race | GCS uses `if_generation_match=0` for atomic create; S3 + Azure check `head_object` / `exists()` first (acceptable race window since WORM forbids overwrite anyway); LocalFilesystemWORM uses `os.replace(tmp, out)` for atomic metadata writes |
| Large-input DoS | Cloud SDKs handle their own request-size limits; FastAPI default body-size limits cover REST surface; per CLAUDE.md hard exclusions, this is not a security-finding category |

---

## 16-row pre-push gate

In-band rows (verified at Pre-tag time):

| # | Check | Status |
|---|---|---|
| 1 | pytest passing | ✅ 2075 (was 1929 at v0.7.11; +146 new this cycle) |
| 2 | mypy --strict 0/0 | ✅ 188 source files (was 184) |
| 3 | ruff clean | ✅ |
| 4 | Standing-rule keyword sweep | ✅ clean across 16 commits + cleared 1 carry-forward leak |
| 5 | Author attribution | ✅ only "Allen Byrd" across all 16 commits |

Out-of-band rows (fire post-push, post-tag, or post-publish per
the v4 Step 7 deliverable):

| # | Check | When |
|---|---|---|
| 6 | Code-scanning alert delta | Post-push CodeQL run; alert #92 should auto-close (input now provably sanitized) |
| 7 | Container CVE scan (Trivy) | Post-tag `container-build.yml` |
| 8 | Vulnerability aging SLO | Post-push Dependabot scan |
| 9 | License/SCA SPDX allowlist | Post-push CycloneDX SBOM build |
| 10 | Reproducible-build verification | Post-tag (build twice + sha256sum match) |
| 11 | SBOM diff vs prior tag | Tag-time `release.yml` |
| 12 | (alias of #6 — code-scanning delta) | Post-push |
| 13 | PEP 740 verify | Post-publish (Step 7.3) |
| 14 | Cosign verify container | Post-publish (Step 7.5a) |
| 15 | osv-scanner --sbom | Post-publish (Step 7.6) |
| 16 | Scorecard re-run delta | Post-push `scorecard.yml` |

Step 7 post-tag verification will close all 16 rows after the
actual tag + push.

---

## Compliance framework mapping (v4 G15)

| Step | NIST SSDF | SLSA | ISO 27001:2022 | SOC 2 Type II | DORA | OpenSSF Scorecard |
|---|---|---|---|---|---|---|
| Step 3 /security-review | PS.1 + PS.3 | n/a (pre-build) | A.8.28 (secure coding) | CC8.1 (change mgmt) | Art.5 (operational resilience: secure-by-design) | Code-Review check |
| Step 4 capability re-validation + DAST | PS.3.2 + PW.4 | n/a | A.8.29 (security testing) | CC8.1 + CC7.2 | Art.6 (testing) | Fuzzing + Vulnerabilities checks |
| Step 5 commit decomposition | PS.2 | n/a | A.8.31 (separation of dev/test/prod) | CC8.1 | n/a | Maintained + Code-Review |
| Step 6 release-checklist + final review | RV.1 + RV.2 | L1+L2 build provenance | A.8.30 (outsourced dev) — n/a | CC8.1 + CC9.1 | Art.7 (ICT incident reporting) | n/a |
| Step 6 pre-push gate (16 rows) | RV.2 + RV.3 | L1+L2 | A.8.32 (change mgmt) | CC8.1 | Art.7 | Pinned-Dependencies + License + CII-Best-Practices |
| Step 7 post-tag verification | PS.3.1 (provenance) + PS.3.2 (verify) | **L3** (build provenance signed; reproducible) | A.8.33 (test data: SBOM + verify) | CC8.1 + CC9.1 | Art.30 (third-party audit signals) | Signed-Releases + SBOM checks |

---

## Per-run JSON

`.local/pre-release-review/runs/2026-05-04T22-XX-XXZ.json` —
captures the full run state including: variant + scope-confirm
answer + agent invocations + step-output verification gates +
findings + dispositions + per-step timing. (Generated post-Step-7;
v4 G13 deliverable.)

---

## Memory pointer

To be persisted post-ship:
`~/.claude/projects/.../memory/evidentia_v0_7_12_shipped.md`
covers: tag SHA, image digest, PEP 740 verify outputs, cosign
verify outputs, full Step 7 post-tag verification snapshot.

---

## Cross-reference

- `docs/v0.7.12-plan.md` — the original release-plan (P0 / P1 / P3 / P4)
- `docs/threat-model.md` — v0.7.12 attack-surface delta
- `docs/capability-matrix.md` — v0.7.12 in-progress snapshot
- `docs/release-checklist.md` Steps 5.5 + 9.5 — doc-consistency
  + release-notes audit practices introduced this cycle
- `CHANGELOG.md` `[Unreleased]` — full per-feature change log
- `~/.claude/skills/pre-release-review/SKILL.md` — v4 skill
- `~/.claude/projects/.../memory/evidentia_release_documentation_practice.md` — practice memory pointer
