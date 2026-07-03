# Security review — v0.10.12

> **Status**: in-cycle artifact for the v0.10.12 ship — the Step 7.10
> canonical deliverable of the `/pre-release-review` skill, auto-generated
> from the per-run audit JSON
> (`.local/pre-release-review/runs/2026-06-23T19-31-55Z-v0.10.12.json`).
>
> **Theme**: full CLI↔GUI parity build-out (the local web console reaches
> ~98% CLI↔GUI parity, up from ~13% in v0.10.11) + the OMB **M-24-10 →
> M-25-21** AI-governance migration (single "high-impact AI" category) +
> supply-chain / security hardening (continuous fuzzing, a Tableau-publish
> SSRF + credential-exfil guard, OpenSSF Scorecard lifts).
>
> **Review shape (G29)**: **FULL ceremony**, pre-tag variant. NOT
> docs-only / NOT presentation-only — the cycle adds new
> externally-reachable surface (~46 new REST mutation endpoints across the
> 22-console parity build-out; the new RBAC-`write`-gated AI-gov endpoint
> `POST /api/ai-gov/systems/{id}/set-high-impact`; and a security-relevant
> change to a credential path — the Tableau-publish SSRF guard). Much of
> the new code (the OMB migration, the parity build, the fuzzing) landed
> from **three parallel sessions** (`a70e0af` OMB design spec, `bd82112`
> OMB M-24-10→M-25-21 migration, `213bbbc` PowerShell verification
> variants), so it warranted independent review in this session.
>
> **Sourcing discipline**: the cycle narrative is drawn from the
> `CHANGELOG.md` `[0.10.12]` block and the committed source; the review
> facts (findings, dispositions, gate results, verdict) are taken verbatim
> from the per-run audit JSON. The OMB M-25-21 regulatory facts were
> **independently labcoat-verified against whitehouse.gov primary sources**
> (rescission 2025-04-03; single high-impact category; seven minimum
> practices; the M-24-18→M-25-22 procurement companion) — the fleet caught
> 2 of 3 models hallucinating "M-24-10 rescinded M-21-06".

## Cycle scope

v0.10.12 is the twelfth patch on the v0.10.x line, dated 2026-06-23 (the
`[0.10.12]` CHANGELOG date), reviewed on the `feature/v0.10.12` branch
against `origin/main@v0.10.11` (38-commit diff + 1-hop dependency closure).
Per the `[0.10.12]` CHANGELOG block, the cycle delivered:

1. **OMB M-25-21 "high-impact AI" model.** The AI-governance module
   migrates to current federal guidance: OMB **M-24-10** (the prior
   rights-impacting / safety-impacting taxonomy) was **rescinded
   2025-04-03 by M-25-21**, which collapses the split into a single
   **"high-impact AI"** category. New core module
   `evidentia_core.ai_governance.omb_m_25_21` ships
   `HighImpactDetermination`, `HighImpactBasis` (the six consequence
   areas), `OMBHighImpactAssessment`, `triggers_minimum_practices()`, and
   an explicit operator-invoked `crosswalk_from_legacy()` (Evidentia never
   silently re-determines a persisted M-24-10 value). Surfaced as a
   matched CLI ↔ REST ↔ console triple
   (`evidentia ai-gov set-high-impact`,
   `POST /api/ai-gov/systems/{id}/set-high-impact` RBAC-`write`-gated, and
   the `/ai-gov` console form), with a new `omb_high_impact` registry
   field, the `AI_SYSTEM_HIGH_IMPACT_CLASSIFIED` audit event, and SCR
   change-classifier handling. Purely additive + backward-compatible:
   every existing M-24-10 entry still loads. The M-24-10 surface is
   **Deprecated** (retained, no behaviour change).
2. **Full CLI↔GUI parity build-out.** The local web console grows to **22
   consoles at ~98% CLI↔GUI parity** (up from ~13%), with matched REST
   endpoints for every new console. The two credentialed / network-egress
   consoles — **Collect** and **Integrations** — surface a
   `SecurityPostureBanner` + disabled run/push buttons when no
   `AuthProvider` is configured (**a UI convenience guard, not a
   server-side control** — see H-1/M-1 in the Findings ledger).
3. **Init wizard write-to-disk path** — `POST /api/init/commit` writes the
   generated `system-context.yaml`, control inventory, and catalog index
   to the server's working directory (skips existing files unless
   `overwrite=true`).
4. **Bundle / accessibility / audit-vocabulary changes** — per-console
   `React.lazy` code-splitting (main chunk → 339 kB / 105 kB gzip); a
   **bidirectional** parity gate (every live OpenAPI op must be CLI-served
   or `api_extra`-allowlisted); the typed-`EventAction` refactor completed
   (incl. the new `RETENTION_METADATA_DELETED`); WCAG 4.1.3 status-message
   announcements across 12 console files.
5. **Dependency-update auto-merge removed** — the v0.10.8
   `dependabot-automerge.yml` workflow + repo `allow_auto_merge` disabled;
   Dependabot stays fully on, but every dependency change is now merged
   after human review (the xz-utils / event-stream class of compromise
   ships as a green-CI patch bump — exactly what auto-merge would admit
   unattended).
6. **Security hardening** — the Tableau-publish **SSRF + credential-exfil
   guard** (`enforce_public_host` + `pin_resolved_host` + https-only);
   **continuous fuzzing** (six `atheris` harnesses via ClusterFuzzLite +
   cross-platform Hypothesis property tests — the OpenSSF Scorecard
   "Fuzzing" lift); and the pre-tag review hardening captured below.
7. **Documentation** — GitHub Pages on the owned domain
   (`docs.evidentiagrc.com`, `mkdocs build --strict`); six console
   walkthroughs with bash + PowerShell variants; a new
   `web-console-security.md` concept page; `positioning-and-value.md` §3
   refreshed to the v0.10.12 surface; and the canonical `verification.md`
   carrying bash + PowerShell recipes for every release-artifact check.

Reported cycle health at the Step-1 local gate claim: **4306 tests pass /
14 skipped; mypy `--strict-optional` clean; ruff clean; frontend
typecheck + build + vitest 137; `openapi.json` canonical + TS types in
sync**. Workspace ships **8 PyPI packages** (no new package this cycle, so
the 5.D.2 partial-publish check is informational — all 8 already exist).

## Review structure

The review ran the FULL `/pre-release-review` flow (Steps 1–6 complete;
Step 7 runs after Allen tags), reconciling + independently validating the
three parallel-session contributions on the merged tree.

| Step | Scope | Verdict |
|---|---|---|
| 1 — plan + freshness | scope = diff + 1-hop (approved); bug-fix policy = surface + queue + batch, risk-first; G29 = FULL; G30 gates-exist = **PASS**; threat-model fresh; per-run freshness clean | Plan approved |
| 2 — positioning | **SKIP-BY-REUSE** — `positioning-and-value.md` §3 refreshed this session (`@b0cbb07`) + the competitive labcoat is current | Reviewed-for note to add at ship |
| 3 — adversarial review (4-surface) | OMB migration + new REST endpoints / auth-gating + SSRF / fuzzing / DoS + enterprise code-quality | **0 CRITICAL; 2 HIGH + 4 MED + 4 LOW + 4 INFO**. Fix batch `@2ff9178`; 5 pre-existing / by-design deferred-with-rationale. Re-validated: gate 9/9 GREEN + frontend vitest 137 + 463 affected tests pass. OMB migration + Tableau SSRF fix independently confirmed clean (6-point check) |
| 4 — scoped review + G27 cross-surface walk + DAST | AI / signing / secret-scrubber scoped review; G27 parity walk; Schemathesis (~8100 cases); adversarial runtime | **0 CRITICAL; 1 HIGH + 2 LOW + 2 INFO**. Fix batch `@48d4add`. G27 parity **PASS 98%** (full 99 / api-only 2 / **cli-only 0** / exempt 10; every new surface present; NO cross-surface gap). Crypto core + OSCAL-verify hardening + Step-3 bounds confirmed solid under live probing. Re-validated: gate 9/9 GREEN + 167 affected tests |
| 5 — fixes + docs + publish-prep | 5.A MEDIUM fixes applied inline in the Step 3/4 commits; 5.B no new HIGH-bucket items; 5.C capability-matrix v0.10.12 snapshot `@3ebac70` (closes G27-V1012-1: 13.3% → 98%, cli-only 43 → 0); CHANGELOG / ROADMAP / README in the bump; `doc-inventory.yaml` ABSENT (Row 19 N/A); 5.D.2 PyPI **PASS** (all 8 packages HTTP 200); 5.D.3 docs-health **0 FAIL** | COMPLETE |
| 6 — final gate + scour + attribution | full gate suite **9/9 GREEN** + changelog-presence PASS; scour CLEAN (3 stale screenshot-ref TODOs fixed `@4950a32`); `.gitignore` covers env/pem/key/crt/p12; **attribution CLEAN** (42 commits all G-signed + Allen-authored, 0 trailers); external-service review clean (OIDC, NO legacy `PYPI_API_TOKEN`, pypi env protection-gated) | **GATE PASS** — pending 6.E business-case + Allen tag approval |
| 7 — post-tag artifact verify + auto-gen security-review doc | runs AFTER Allen tags | pending |

> **Right-sizing call (G29)**: a new endpoint + a credential-path change +
> irreversible-adjacent surface takes the FULL flow regardless of line
> count. The third security pass this cycle was Steps 3 + 4's combined
> 4-surface adversarial review + Schemathesis DAST coverage (no separate
> `/security-review` invocation was available in this session); the JSON
> records this explicitly.

## Findings ledger

Sixteen findings (`F-V1012-*` / `H-1`+`M-1` / `V1012-*`). The four HIGH —
the incomplete OSCAL-verify DoS fix (`F-V1012-1`), the banner overclaim
(`H-1`/`M-1`), and the create-endpoint 500s (`F-V1012-S4-1`) — were all
**caught + fixed pre-tag + re-validated**. 0 CRITICAL reached the tag.

### Step 3 — fixed-pre-tag (fix batch `@2ff9178`)

| ID | Bucket | Category | Description | Disposition |
|---|---|---|---|---|
| F-V1012-1 | **HIGH** | DoS / CWE-248 uncaught exception (`oscal/verify.py` `verify_digests` + `_extract_expected_digest`) | The earlier fuzz-found OSCAL-verify DoS fix (`2ecb802`) was INCOMPLETE — it guarded only the resources list; a non-dict base64 block, non-list `rlinks`, non-dict rlink/hash entries, and a non-object JSON root still raised an uncaught exception, reachable via the open `/api/oscal/verify` endpoint + CLI | **FIXED `@2ff9178`** — the whole verify chain is guarded to return a verdict (never raise) on any malformed-but-valid-JSON input |
| F-V1012-2 | MEDIUM (paired) | test-gap (`tests/fuzz/fuzz_oscal_verify.py` + `test_parser_robustness.py`) | The atheris harness + Hypothesis robustness test allowlisted `(ValueError, TypeError, KeyError)` — masking exactly the `TypeError` class of F-V1012-1 (why the incomplete fix shipped green) | **FIXED `@2ff9178`** — no exception swallowed; asserts `verify_digests` returns a list; now guards F-V1012-1 |
| H-1 + M-1 | **HIGH** + MEDIUM | claim-accuracy / auth-overclaim (`SecurityPostureBanner.tsx` + `web-console-security.md` + positioning §3.3 + CHANGELOG) | The credentialed REST endpoints (collect / integrations / init-commit) are open on an anonymous deployment; the "gating" is UI-only (button-disable). The banner said credentialed actions "are disabled", implying a server-side control that isn't there — a misrepresentation for an auditor-facing tool. (The documented anonymous-default posture itself is intentional + correct.) | **FIXED `@2ff9178`** — banner + docs now state the disable is a UI convenience guard, not a server-side control; the API stays open until `EVIDENTIA_API_AUTH_TOKEN_FILE` is set |
| V1012-1 | MEDIUM | audit-trail fidelity (`routers/retention.py` DELETE) | The metadata DELETE emitted `RETENTION_RECORD_PURGED` — a metadata delete masquerading as a secure WORM purge in the audit vocabulary | **FIXED `@2ff9178`** — new `EventAction.RETENTION_METADATA_DELETED`; DELETE now emits it |
| V1012-2 / V1012-3 | LOW | DoS / unbounded input (`routers/risks.py` `RiskQuantifyRequest.scenarios` + `routers/oscal.py` `VerifyRequest.content`) | Two open compute endpoints took unbounded inline inputs (scenarios uncapped while iterations capped; content uncapped before a temp-file write) | **FIXED `@2ff9178`** — `scenarios` `max_length=1000`; `content` `max_length=8_000_000` (422 before any work) |

### Step 4 — fixed-pre-tag (fix batch `@48d4add`)

| ID | Bucket | Category | Description | Disposition |
|---|---|---|---|---|
| F-V1012-S4-1 | **HIGH** | Step-4 DAST — unhandled exception / response-contract, CWE-248 (`routers/{governance,poam,tprm,model_risk}.py` create handlers) | Schemathesis (~8100 cases) surfaced 13 HTTP 500s, one root cause: the 6 full-model create endpoints accept an empty client `id` (Pydantic accepts `''`, so `default_factory` only fires on omit) → store id-shape validation raised an unhandled `Invalid*IdError` → 500. No info leak. 3 of 6 net-new this cycle | **FIXED `@48d4add`** — each create handler wraps `save()` → 422 (mirrors GET/PUT); +3 governance regression tests; identical guard on poam / tprm / model-risk |
| F-V1012-S41-1 | LOW | Step-4 — incomplete secret redaction, CWE-532 (`audit/logger.py` `_SECRET_PATTERNS`) | The audit secret-scrubber missed the system's OWN credential shapes: fine-grained GitHub PATs, OpenAI/Anthropic keys (`sk-`/`sk-ant-`), DSN passwords (`user:pass@`), bearer tokens. Pre-existing (v0.7.0); a backstop | **FIXED `@48d4add`** — 4 patterns added + 4 regression tests |
| F-V1012-S41-3 | INFO | Step-4 — GPG no-signer-pinning, documented (`oscal/verify.py` + `signing.py`) | GPG verify fails-closed on tampered/expired/revoked sigs but does not pin an expected signer (any keyring key passes), unlike the Sigstore identity-pinning path. Pre-existing, consistent with GnuPG web-of-trust | **FIXED `@48d4add`** — documented the trust-model property in the `verify_ar_file` docstring; optional `expected_gpg_fingerprint` kwarg deferred |

### Deferred-with-rationale (pre-existing / by-design)

| ID | Bucket | Category | Description | Disposition |
|---|---|---|---|---|
| V1012-AIGOV-1 | MEDIUM | audit-trail / accountability (`routers/ai_gov.py` + all mutation routers) | API-emitted ai-gov mutation events (incl. `AI_SYSTEM_HIGH_IMPACT_CLASSIFIED`) record WHAT changed but not the authenticated principal. Cross-cutting PRE-EXISTING pattern (all routers), not a v0.10.12 regression | **DEFERRED-with-rationale** — federal-tier audit-trail item; wire `request.state.auth_principal` into the audit scope once at the API layer in a future cycle |
| L-1 | LOW | error-message hygiene (`routers/collectors.py` 500 handlers) | DB/collector 500 handlers echo the raw driver exception; a DSN-embedded password could surface. Pre-existing pattern, not introduced this cycle | **DEFERRED-with-rationale** — generic 500 detail + server-side log in a future error-hygiene pass |
| V1012-4 | INFO | audit-consistency (`routers/tprm.py` vendor CRUD) | TPRM vendor create/replace/delete emit no audit event, unlike peer routers. Pre-existing (CLI also omits) | **DEFERRED-with-rationale** — future TPRM audit-chain-of-custody pass (file already references it) |
| V1012-AIGOV-2 | LOW | surface-completeness (`ai_governance/omb_m_25_21.crosswalk_from_legacy`) | `crosswalk_from_legacy` is library-only (no CLI/REST verb). Consistent with the documented operator-must-review-never-silent design | **DEFERRED** — optional future `ai-gov crosswalk-legacy --apply` verb (dry-run by default) |
| F-V1012-S41-2 | LOW | Step-4 — scrubber bypass on structured fields (`audit/logger.py` `_scrub`) | `_scrub` is applied to the message string only, not the structured error/evidentia dicts (where AI generators route `str(exc)`). Pre-existing documented design boundary | **DEFERRED-with-rationale** — documented boundary; recursive-scrub of the error dict is a future higher-assurance option |

### Accepted (parity, not a new gap)

| ID | Bucket | Category | Description | Disposition |
|---|---|---|---|---|
| F-V1012-3 | INFO | SSRF residual (`routers/integrations.py` Tableau publish) | `pin_resolved_host` pins the original hostname only; a cross-host HTTP redirect would be unpinned. IDENTICAL to every collector's guard (parity, not a new gap); not exploitable on the Tableau path | **ACCEPTED** — parity with collectors; optional global hardening in a future pass |

### Docs-staleness (closed in Step 5)

| ID | Bucket | Category | Description | Disposition |
|---|---|---|---|---|
| G27-V1012-1 | INFO | Step-4 — docs-staleness (`docs/capability-matrix.md`) | The capability-matrix snapshot was stale (v0.10.8, "13.3% GUI coverage") after the Wave 1–4 build-out. A doc refresh, not a code issue | **CLOSED** — capability-matrix v0.10.12 snapshot `@3ebac70` (13.3% → 98%; cli-only 43 → 0) |

## Gates run

The final full gate suite ran **9/9 GREEN** on the merged tree (Step 6),
plus the changelog-presence pre-tag gate:

| Gate | Result |
|---|---|
| `pytest` | PASS — 4306 pass / 14 skip |
| `mypy` (`--strict-optional`, the 7 typed packages) | PASS |
| `ruff check` | PASS — clean |
| `check_version_consistency.py` | PASS |
| `check_docs_health.py --strict` | PASS — 0 FAIL |
| README "Recent Releases" / `readme-releases` | PASS |
| `check_doc_counts.py` | PASS |
| `osv-scanner` (SBOM) | PASS |
| CLI↔GUI parity (`check_parity`) | PASS — **98%** (full 99 / api-only 2 / cli-only 0 / exempt 10) |
| changelog-presence (pre-tag) | PASS |
| **Frontend** typecheck + build + vitest | PASS — vitest 137; `openapi.json` canonical + TS types in sync |

**Gates-exist (G30)**: **PASS** — version-consistency, `release.yml`
tag-gate + `verify-changelog`, CLI↔GUI parity, secret-scan, and the
`commit-msg` hook are all present.

**Threat-model freshness**: **PASS** — `docs/threat-model.md` updated
2026-06-23 with the v0.10.12 delta (console REST surface + Tableau SSRF
fix + OMB M-25-21 surface).

**Attribution**: **CLEAN** — 42 commits, all GPG/SSH-signed, all authored
by Allen Byrd, **0 co-authorship / generated-by trailers**.

**External-service review**: CLEAN — repo About / topics / homepage
accurate; **NO legacy `PYPI_API_TOKEN`** (OIDC trusted-publishing); the
`pypi` environment is protection-gated. Minor pre-existing note: the
Production / Preview deployment environments are unprotected.

## Step 7 — post-tag verification

> **Post-tag outcome** (recorded after the tag). v0.10.12 was tagged and
> published — all 8 packages to PyPI — but the container build failed on a
> Dependabot `python:3.14-slim` / `litellm <3.14` regression (#83) and was
> completed as **v0.10.13** (Dockerfile reverted to `python:3.13-slim`). Full
> Step-7 artifact verification — PyPI · cosign keyless · SLSA Provenance v1 ·
> container run (`Evidentia v0.10.13 / Python 3.13.14`) · GitHub Release + SBOM —
> passed on **v0.10.13** (container `sha256:c8c7acbf…`). See the CHANGELOG
> `[0.10.13]` block. The pre-tag checklist below is preserved as the review
> record at write-time.

Step 7 (post-tag artifact verification + the auto-generated public
security-review doc finalization) executes only **after** the
`git tag -s v0.10.12 && git push` fires `release.yml`. At the time of this
write-up the tag is **not yet pushed** (`v0.10.12_published: false`; tags
published through **v0.10.11**; 38 commits unpushed vs `origin/main` at
review time). The post-tag checklist to be filled at Step 7:

| Sub-step | Check |
|---|---|
| 7.1 | `release.yml` conclusion |
| 7.2 | PyPI: all 16 artifacts published (8 wheels + 8 sdists at 0.10.12) |
| 7.3 | PEP 740 attestation sweep via PyPI integrity API |
| 7.4 | SLSA Build Provenance v1 (attached to the GitHub Release) |
| 7.5 | Container: `cosign verify` keyless OIDC + `docker run … --version` |
| 7.6 | osv-scanner on the published SBOM |
| 7.7 | Scorecard delta (the v0.10.12 Fuzzing lift + `SCORECARD_TOKEN` wiring) |
| 7.8 | Fresh-venv install |
| 7.9 | GitHub Release (tag at HEAD; `[0.10.12]` block as body) |
| 7.10 | This document — finalized + the Step-7 results filled |

## Aggregate cycle metrics

| Metric | v0.10.12 |
|---|---|
| Tests | 4306 pass / 14 skip (Step-1 local gate claim) |
| mypy | clean (`--strict-optional`, the 7 typed packages) |
| ruff | clean |
| Frontend | typecheck + build PASS; vitest 137; OpenAPI ↔ TS types in sync |
| PyPI packages | 8 (unchanged; no new package this cycle) |
| Scope | diff + 1-hop closure — 38 commits, `feature/v0.10.12` vs `origin/main@v0.10.11` |
| Findings: CRITICAL / HIGH / MEDIUM / LOW / INFO | 0 / 4 / 4 / 4 / 4 |
| HIGH dispositions | all **caught + fixed pre-tag** (`F-V1012-1`, `H-1`/`M-1`, `F-V1012-S4-1`) |
| Fix batches | 2 (`@2ff9178` Step-3, `@48d4add` Step-4) |
| Deferred-with-rationale | 5 (pre-existing / by-design) + 1 accepted (`F-V1012-3`, collector-parity) |
| CLI↔GUI parity (G27) | **98%** (cli-only 43 → 0; capability-matrix `@3ebac70`) |
| DAST | Schemathesis ~8100 cases (Step 4) |
| Final gate suite | **9/9 GREEN** + changelog-presence PASS |
| Attribution | CLEAN (42 commits, all signed + Allen-authored, 0 trailers) |
| Bump commit | `@e72a807` |
| Tag | `v0.10.12` (pending Allen's approval; **not yet pushed**) |
| Consecutive PROCEED-CLEAN streak | Continues the unbroken PROCEED-CLEAN line of the v0.7.x → v0.10.x releases. The per-run JSON does not assert a count, and the historical doc numbering is inconsistent, so no hard number is claimed here. |
| **Overall verdict** | **PROCEED-CLEAN (pre-tag)** — Steps 1–6 complete; 0 CRITICAL; all 4 HIGH caught + fixed + re-validated pre-tag; Step 7 runs after tag |

## Cross-references

- Per-run JSON (audit trail): `.local/pre-release-review/runs/2026-06-23T19-31-55Z-v0.10.12.json`
- CHANGELOG block: [CHANGELOG.md §[0.10.12]](../CHANGELOG.md)
- Threat model: [docs/threat-model.md](threat-model.md) (v0.10.12 delta: console REST surface + Tableau SSRF + OMB M-25-21)
- Capability matrix snapshot: [docs/capability-matrix.md](capability-matrix.md) (v0.10.12 pre-tag, `@3ebac70` — 13.3% → 98%)
- Web-console security model: [docs/web-console-security.md](web-console-security.md) (H-1/M-1 remediation — UI-guard-not-server-control)
- Positioning §3 refresh: [docs/positioning-and-value.md](positioning-and-value.md) (`@b0cbb07`)
- Remediation source: `oscal/verify.py` (F-V1012-1), `routers/{governance,poam,tprm,model_risk}.py` (F-V1012-S4-1), `audit/logger.py` (F-V1012-S41-1)
- Fix batches: `@2ff9178` (Step 3) · `@48d4add` (Step 4)

## Business case captured at Step 6.E

1. **Why now**: the v0.10.12 cycle closes the long-running CLI↔GUI parity
   gap (13% → 98%) so the local web console is a faithful surface for the
   whole CLI, and migrates the AI-governance module to current federal
   guidance (OMB M-25-21) ahead of the v0.11 federal theme — both are
   forcing functions for the federal-readiness narrative.
2. **Who suffers if delayed**: operators relying on the console for the
   newly-parity'd surfaces, and the federal-positioning timeline — the
   M-24-10 surface is now factually rescinded guidance, so the migration
   is accuracy-driven, not cosmetic.
3. **Rollback path**: standard ladder — (1) `pip install evidentia==0.10.11`
   for users; (2) PyPI yank of the 0.10.12 wheels (yank ≠ delete; cosign +
   Rekor signatures stay valid); (3) GHCR tag deletion; (4) CHANGELOG
   correction + a 0.10.13 revert. The migration is additive +
   backward-compatible, so a downgrade re-reads every persisted M-24-10
   inventory entry unchanged. Provenance chain stays intact.

---

*Generated at Step 7.10 of `/pre-release-review` from the per-run audit
JSON (`.local/pre-release-review/runs/2026-06-23T19-31-55Z-v0.10.12.json`).
**Pre-tag** verdict — Steps 1–6 complete; Step 7 (post-tag artifact
verification + this doc's finalization) runs after Allen tags v0.10.12.
Reviewer of record: Allen Byrd `<allenfbyrd>`.*
