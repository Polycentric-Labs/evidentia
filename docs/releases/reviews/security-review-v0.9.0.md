# Security Review — v0.9.0 (5th Canonical Pre-Tag Deliverable)

> Produced by `/pre-release-review v4` Pre-tag full 7-step run for
> v0.9.0 ship 2026-05-15. Per v4 §G7, this is the 5th canonical
> Pre-tag deliverable alongside `docs/v0.9.0-plan.md`,
> `docs/threat-model.md` v0.9.0 delta,
> `docs/capability-matrix.md` v0.9.0 snapshot, and
> `docs/release-checklist.md`. Cross-link to:
> [`docs/poam-runbook.md`](poam-runbook.md),
> [`docs/conmon-runbook.md`](conmon-runbook.md).

## Verdict: **PROCEED-CLEAN** — 15th consecutive of v0.7.x → v0.8.x → v0.9.x line

- 0 unfixed CRITICAL / HIGH / MEDIUM findings
- 15 LOW polish items surfaced; all 14 inline-fixed in Step 5.A batch (commit `ceab880`) + 1 (F-V90-15 UUID canonicalization) added back at the same commit per Allen's "tackle these following the 9-item batch" direction
- 2 HIGH transitive-dep CVEs (urllib3) surfaced post-push; closed pre-tag via `fix(deps): bump urllib3 2.6.3 → 2.7.0` (commit `4a72048`) before the v0.9.0 tag fired

## Variant + scope

| Item | Value |
|---|---|
| Variant | Pre-tag (full 7-step) |
| Diff range | `v0.8.7..HEAD` (8 commits) |
| Scope (Step 1.4) | **Full re-read** of `packages/*/src` (max thorough; user elected maximum coverage given the 4 substantial new public surfaces) |
| Threat-model G5 freshness | PASS (refreshed today 2026-05-15) |
| /security-review invocations | 3 (per G12: diff + per-subsystem + final-gate) |
| /code-review auto-fire triggers | 4 of 4 fired (19 new public API additions; 10 new src files; 7457 LOC delta; audit/events.py touched) |
| Per-run JSON logs | `.local/pre-release-review/runs/2026-05-15-v0.9.0-step{1,3,4,6-7}.json` |

## /security-review invocations (3 mandatory per v4 G12)

| # | Step | Scope | Verdict |
|---|---|---|---|
| 1 | 3 | `v0.8.7..HEAD` diff | **0 HIGH/MEDIUM** — 10 categories cleared with rationale (path traversal / YAML / JSON / injection / crypto / authZ / data exposure / reflection / state-machine / Pydantic strictness) |
| 2 | 4 | Per-subsystem (5 subsystems: POA&M state machine + OSCAL emit + persistence + CONMON YAML parse + audit emit completeness) | **0 HIGH/MEDIUM** — 1 candidate (UUID-alias normalization) dismissed via FP-filter Hard Exclusion #5 (data-integrity / OSCAL-conformance gap; not security boundary); reclassified as F-V90-15 |
| 3 | 6.C | Final-gate (full HEAD vs prev-tag including post-refinement state) | **0 HIGH/MEDIUM** — ceab880 refinement batch preserves the established clearance; no new attack surface introduced |

## /code-review (Step 3 entry; auto-fired on all 4 triggers)

- 13 LOW suggestions surfaced
- 3 stale doc-string references surfaced (pre-existing carry-over from v0.7.x → v0.8.x cycles)
- Verdict: **Approve with minor cleanup recommendations**

## Per-commit re-read (Step 3.3)

| Commit | Files | Match to message | Findings |
|---|---|---|---|
| `044ded9` P1 POA&M data layer | 11 / +1558 / -1 | ACCURATE — all claims verifiable | 0 |
| `19a4b93` P2 CLI + REST + OSCAL emit | 8 / +3255 / -0 | ACCURATE — minor commit-message test-count breakdown drift (P2-1) | 3 LOW |
| `cdaf254` P3 CONMON | 12 / +1953 / -3 | ACCURATE — commit-message test-count off by 2 (P3-1) | 3 LOW |
| `42e5891` cycle-close docs | 4 / +692 / -0 | ACCURATE | 0 |

## Full `packages/*/src` drift scan (Step 3.4)

~218 Python files swept. Drift findings (all LOW; mostly stale docstrings + inline-import inconsistencies + 1 orphaned type alias):

- D1: governance/__init__.py "Future v0.7.10 sub-slices" stale
- D2 + D3: explain/models.py + models/risk.py `generation_context` "tightened in v0.8" stale
- D4: evidentia/config.py "deprecation may follow in v0.5.0" stale
- D5: conmon/calendar.py unused `ConmonStatusLiteral`
- D6: conmon/calendar.py inline-import + trivial `_add_days` indirection
- D7: oscal/poam_exporter.py function-local `GapStatus` import
- D8: cli/poam.py `out: dict[str, Any]` type-ignore
- D9: audit/events.py + conmon/calendar.py "CLI/REST query paths" docs over-promise (REST not shipped)

## Step 4 — Capability surface walk + adversarial probing

- **Surface clusters tested**: 8 (POA&M state machine; Milestone helpers; poam_store; OSCAL POA&M emit; evidentia poam CLI; /api/poam/* REST router; conmon library; conmon CLI)
- **Surface-specific tests**: 181 PASS
- **Named adversarial probes** (per `capability-matrix.md` v0.9.0 snapshot): 6 ALL PASS (state-machine backward-transition / path-traversal / severity-filter / OSCAL back-matter integrity / YAML parse-error / leap-year calendar arithmetic)
- **DAST G11**: skipped with rationale per v4 graceful-degradation (no UI surface introduced; REST covered by 22 TestClient integration tests; Schemathesis + Playwright not installed)

## Bug-bucketing (CVSS / CWE / EPSS per v4 G7)

| ID | Severity | CVSS | CWE | EPSS | Disposition |
|---|---|---|---|---|---|
| F-V90-1 | LOW | n/a | n/a | n/a | Fixed in `ceab880` Step 5.A |
| F-V90-2 (cleanup batch) | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-3 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-4 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-5 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-6 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-7 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-8 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-9 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-10 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-11 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-12 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-13 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-14 | LOW | n/a | n/a | n/a | Fixed in `ceab880` |
| F-V90-15 (UUID canonicalization) | LOW | n/a | CWE-707 | n/a | Fixed in `ceab880` (data-integrity / OSCAL-conformance; NOT security per FP-filter) |
| **CVE-2026-44431** (urllib3 header forwarding in proxied redirects) | HIGH | 7.5 (CVSS:3.1) | CWE-200 | not yet rated | Fixed in `4a72048` (urllib3 2.7.0); 4-day exposure window; no exploitation observed on Evidentia surfaces (httpx wraps urllib3; no proxying in standard deployment) |
| **CVE-2026-44432** (urllib3 decompression-bomb bypass in streaming API) | HIGH | 7.5 (CVSS:3.1) | CWE-409 | not yet rated | Fixed in `4a72048` (urllib3 2.7.0); 4-day exposure window; provider responses are trusted (LiteLLM + httpx) — bounded practical risk |
| **CVE-2026-44405** (paramiko rsakey.py SHA-1) | LOW | 3.4 (CVSS:3.1) | CWE-327 | not yet rated | **DEFERRED** — upstream paramiko has not released a fix (`first_patched=null`); pure transitive (no SSH paths in Evidentia code); auto-closes when paramiko upstream patches |

## 16-row pre-push gate (Step 6.C)

All 13 evaluated rows PASS; 3 SKIPPED with rationale per v4 graceful-degradation:

| # | Check | Result |
|---|---|---|
| 1 | Credential pattern sweep | PASS (0 hits) |
| 2 | Claude attribution sweep of diff | PASS (0 hits) |
| 3 | Commit-message attribution sweep | PASS (0 hits) |
| 4 | `.gitignore` secret-store coverage | PASS |
| 5 | Staged secret-store files | PASS (only `.env.example` template) |
| 6 | Test gate | PASS (2583 / 17 skipped) |
| 7 | Lint/type gate | PASS (ruff clean + mypy strict 0/0 across 227 source files) |
| 8 | `uv build` | Deferred to release.yml (validated PASS at first-fire) |
| 9 | Identity check | PASS (Allen Byrd) |
| 10 | Branch sanity | PASS (main) |
| 11 | `gh secret list` | PASS (CODECOV_TOKEN current; rotated 2026-05-04) |
| 12 | Code-scanning alert delta | PASS (0 NEW HIGH alerts since v0.8.7) |
| 13 | Container CVE scan | SKIPPED (Trivy missing; v0.9.0 inherits v0.8.7 base image which was clean) |
| 14 | Vulnerability aging SLO | PASS (0 HIGH/CRITICAL > 14 days; urllib3 + paramiko both < 14 days) |
| 15 | License/SCA | SKIPPED (pip-licenses missing; v0.8.7 SBOM osv-scanner clean) |
| 16 | Secret rotation cadence | SKIPPED (gh PAT `admin:public_key` scope absent; CODECOV_TOKEN rotated 12 days ago) |

## Step 7 post-tag verification (ALL PASS)

| Gate | Result |
|---|---|
| G1 PEP 740 verify | PASS — all 7 wheels OK via `pypi-attestations verify pypi --repository https://github.com/polycentric-labs/evidentia` |
| G2 cosign verify | PASS — keyless OIDC + Rekor inclusion proof + SLSA Provenance v1 in-toto attestation matches v0.9.0 + commit `4a72048` |
| G3 osv-scanner --sbom | 169 packages / 1 LOW finding (paramiko 4.0.0 GHSA-r374-rxx8-8654 — acknowledged) |
| G4 docker run smoke | PASS — `Evidentia v0.9.0` reports correctly + 89 catalogs bundled + `poam` + `conmon` CLI surfaces both live |
| G5 fresh-venv install | PASS — **15th consecutive pin-trap fix validation**; all 5 inter-package deps at 0.9.0 first-try; urllib3 2.7.0 carries through |
| G7 Scorecard delta | PASS — 0 NEW alerts since v0.8.7; pre-existing meta-alert #38 (created 2026-04-27) unchanged; will auto-close at next Scorecard scan |
| G16 release body substantiveness | PASS — 10467 bytes (target ≥ 1500); **14th consecutive auto-populate-from-CHANGELOG** via v0.7.13 P2.2.1 release.yml fix |

## Image digest + provenance

- **Container**: `ghcr.io/polycentric-labs/evidentia:v0.9.0`
- **SHA-256 digest**: `sha256:28f8dc21684bda77e49a7e34f68d34d55a374481ee13c01d0eb5628c6c3f6b45`
- **Git commit**: `4a72048a142d7dfb8a0c804e29d4d59879258 94b` (per cosign SLSA v1 attestation)
- **Build workflow**: `.github/workflows/release.yml@refs/tags/v0.9.0`
- **Builder ID**: `https://github.com/polycentric-labs/evidentia/.github/workflows/release.yml@refs/tags/v0.9.0`
- **Invocation**: `https://github.com/polycentric-labs/evidentia/actions/runs/25942605088/attempts/1`

## Compliance framework mapping (per v4 G15)

| Framework | Control / Practice | How v0.9.0 satisfies |
|---|---|---|
| NIST SSDF | PS.3.1 (provenance) + PW.7.1 (verify component) + PS.3.2 (preserve provenance) | PEP 740 attestations on all 7 wheels + cosign SLSA Provenance v1 on container + osv-scanner --sbom + chain-of-custody verification documented in Step 7 outcome |
| SLSA | L3 build provenance | release.yml runs on GitHub-hosted ephemeral runners + `attest-build-provenance@v2` action emits the SLSA v1 in-toto statement; cosign keyless OIDC binds to the tag ref `refs/tags/v0.9.0` |
| ISO 27001:2022 | Annex A 8.25 (Secure development life cycle) + A 8.28 (Secure coding) + A 8.29 (Security testing in development and acceptance) | Documented in `docs/release-checklist.md` Steps 5.5 + 9.5; this 7-step pre-release-review is the canonical SDLC artifact |
| SOC 2 Type II | CC7.1 (System monitoring) + CC8.1 (Change management) | The 8-commit v0.9.0 cycle has explicit per-commit conventional-commit prefixes; all approvals logged via the publishing-authority protocol; this doc preserves the audit trail |
| DORA (EU) | Art. 9 (ICT security policies and procedures) + Art. 28 (Third-party risk management) | TPRM module (v0.7.9) + POA&M module (v0.9.0) + CONMON cycle calendar (v0.9.0) align to Art. 28 + Art. 9 supervision expectations |
| OpenSSF Best Practices | Silver tier (already MET since v0.7.14) + Gold tier (BLOCKED on ≥ 2 contributors) | Silver criteria continue to MET; SBOM + signed artifacts + automated test gate + threat model + this security-review doc all preserved |
| CISA Secure by Design Pledge | Mem. 4 (Default-secure) + Mem. 5 (Reduce hardening guides) + Mem. 6 (Vulnerability disclosure) | POA&M operator runbook is the auditor-facing artifact; backward-state-transition prohibition + back-matter integrity + canonicalized UUIDs all default-secure |

## Outstanding / deferred

| Item | Disposition | Target |
|---|---|---|
| CVE-2026-44405 paramiko SHA-1 | Upstream first_patched=null; pure transitive dep with no Evidentia code path; auto-closes when paramiko upstream releases a fix | v0.9.1+ (passive; uv.lock regen will pull it) |
| Phase 4 walk-through | Operator-driven; not Claude-blocking | v0.9.1 reservation per §31.A POA&M-first / walk-through-as-validation posture |
| Cohen's Kappa recompute on v0.8.5 DFAH corpus | Tied to Phase 4 walk-through (domain-expert second rater) | v0.9.1 |
| Schemathesis + Playwright DAST coverage | Tools not installed; covered via TestClient + comprehensive integration tests | Not v0.9.0-blocking; v1.0 reservation |
| CONMON live-trigger daemon (`evidentia conmon watch`) | Out of scope per §31.1; CLI polling sufficient for v0.9.0 | v1.0 reservation |
| Cryptographic CIMD signatures | v0.8.x carried forward; not v0.9.0 scope | v1.0 reservation |
| OpenSSF Best Practices Badge Gold tier | BLOCKED on ≥ 2 contributors | Post-v0.8.0 reservation; status unchanged |

## Reviewer notes

- The /security-review skill cleared the v0.8.7..HEAD diff THREE TIMES (invocations #1 + #2 + #3) per v4 G12. Each invocation used a different scope lens (diff-scoped / per-subsystem / final-gate). The convergent zero-finding result across all three is the strongest possible clearance signal the v4 skill can produce.
- The urllib3 CVE-2026-44431 + CVE-2026-44432 closure inside the v0.9.0 cycle (NOT deferred to v0.9.0.1 hot-fix) preserves the auditor-defensible posture: v0.9.0 ships with 0 unfixed HIGH/CRITICAL CVEs in transitive deps.
- The capability-matrix v0.9.0 snapshot test-count corrections (F-V90-8) close the doc-vs-truth gap that originated in the P2 + P3 commit-message stats. The originating commit messages are immutable; the cycle-close artifact carries the corrected canonical numbers.
- v0.9.0 is the first minor of the v0.9.x line. The federal-compliance theme was reserved at v0.8.7 cycle-close per the 2026-04-28 §10 Q4 lock-in; v0.9.0 closes that reservation with POA&M + CONMON + OSCAL POA&M 1.1.2 emit.
- v0.9.1 will reopen the cycle if walk-through-driven feedback surfaces material POA&M / CONMON shape adjustments. Otherwise v1.0 transition narrative carries forward per `docs/v1.0-transition.md` DRAFT.
