# Security review - v0.10.6

> **Status**: reconstructed in-cycle artifact for the v0.10.6 ship. The
> security-review write-up was not authored as an in-repo doc at ship
> time (the v0.10.5 + v0.10.6 reviews were captured in internal memory
> rather than as in-repo docs); this public companion was backfilled
> during the v0.10.8 docs close-out from the `CHANGELOG.md` `[0.10.6]`
> block, [`docs/v0.10.6-plan.md`](../plans/v0.10.6-plan.md), and the annotated
> `v0.10.6` tag object.
>
> **Theme**: OSS first-mover artifacts (the Phases 1-5 carried forward
> from the v0.10.5 redirect) + downstream OSPS-Baseline crosswalks + a
> GitHub-collector OSPS extension + post-v0.10.5 hygiene. This is the
> cycle that ships Evidentia's `SECURITY.md` refresh, the
> `.well-known/security.txt`, the GHSA private-vulnerability-reporting
> enablement, and the `OSPS-CONFORMANCE.md` self-attestation.
>
> **Structure note**: this document follows the structure and voice of
> [`docs/security-review-v0.10.4.md`](security-review-v0.10.4.md), which
> was the last in-repo security-review doc committed before this
> backfill. It is the structural model here.
>
> **Sourcing discipline + the per-run-JSON gap**: there is **no per-run
> `/pre-release-review` JSON for v0.10.6**. The audit-trail run directory
> `.local/pre-release-review/runs/` jumps from the
> `2026-05-24T21-41-48Z-v0.10.4-prototype.json` record straight to the
> `2026-05-31T01-55-11Z-v0.10.7.json` record, with no v0.10.5 or v0.10.6
> file in between. So the Step-7 numeric results, exact per-pass finding
> tallies, the container digest, the `release.yml` run duration, and the
> consecutive-PROCEED-CLEAN streak position for this cycle are **not
> derivable from in-repo sources**; the Step-7 ship record for v0.10.6
> lives in private memory. Every such fact below is marked inline
> **`VERIFY-LIMITED`** with a pointer to where it can be confirmed. Facts
> that the CHANGELOG block, the plan, or the tag object state directly
> are used as-is with the source cited.

## Cycle scope

v0.10.6 is the sixth patch on the v0.10.x line, tagged 2026-05-27 (the
`[0.10.6]` CHANGELOG date and the `v0.10.6` tag-object date; the tag
commit `254277f` is dated `2026-05-27 10:45 -0400`). Seventeen cycle
commits were authored 2026-05-27 between v0.10.5 (tagged 2026-05-26) and
this tag, all on `main` (the `[0.10.6]` block's "17 cycle commits"
figure; the `git rev-list v0.10.5..v0.10.6` count is 18 including the
chore(release) commit). Per [`docs/v0.10.6-plan.md`](../plans/v0.10.6-plan.md) §2,
which locked the scope on 2026-05-26 in Approach B (theme-grouped commits
with two in-cycle Tier-4 publishing-approval gates), the cycle delivered:

1. **OSPS Baseline 3-catalog bundle + first public OSCAL serialization
   (carry-over P1 + P2).** Maturity 1/2/3 YAMLs plus the first public
   OSCAL Catalog 1.2.1 serialization of the OpenSSF OSPS Baseline
   (`osps-baseline.oscal.json`), pinned at
   `ossf/security-baseline@ac6bbec8aecf51dce41f62712745f7949ab6bdeb`
   (commit `ea9f117`). Tier-A (Apache-2.0 verbatim) bundling; zero schema
   change to the catalog loader.
2. **`SECURITY.md` refresh + `.well-known/security.txt` + GHSA
   enablement (carry-over P4; the cycle's security-posture commit).** A
   stale Supported-versions table fixed, CISA/FTC safe-harbor VDP text
   added, an RFC 9116 `.well-known/security.txt` added, and GitHub
   private vulnerability reporting (GHSA) enabled via a Tier-4 `gh api`
   PATCH (commit `4d50627`). Closes OSPS-VM-01/02/03 + CISA SbD Pledge
   Goal 5. See the Tier-4 publishing-action note below.
3. **`OSPS-CONFORMANCE.md` self-attestation + CI gate (carry-over P3).**
   A repo-root self-attestation against OSPS Baseline v2026.02.19 Level 2
   (with partial Level 3) plus a `verify-osps-conformance.yml` CI gate
   that re-validates every cited evidence link on push / PR / cron, so
   the conformance claim cannot drift silently (commits `04e9e1e`,
   `77499ba`, `b55d83a`). Recorded as the first public open-source
   project to ship this artifact.
4. **`EOL.md` + `docs/verification.md` (carry-over P5).** A consumer-side
   end-of-life policy plus cosign + PEP 740 + osv-scanner + SLSA
   Provenance v1 verification recipes (commit `d44d899`). Closes
   OSPS-DO-03 + OSPS-DO-05.
5. **5 OSPS-Baseline crosswalks (X1).** `osps-baseline_to_{nist-ssdf-800-218,
   nist-csf-2.0, eu-cra, pci-dss-4.0, nist-800-161}.json` in
   `catalogs/data/mappings/`, shipped **raw with an upstream-attested
   provenance disclaimer** per the 2026-05-26 brainstorm rigor decision;
   hand-verification deferred to v0.10.7+. `CrosswalkDefinition` was
   extended **additively** with 3 optional fields (`provenance`,
   `verification`, `verification_note`) so the existing 8 crosswalks load
   unchanged (commit `e443fa5`).
6. **GitHub-collector OSPS extension (X2).** A new
   `evidentia_collectors.github.osps` module with 16 `populate_osps_*`
   helpers covering OSPS AC/BR/DO/GV/LE/QA/VM family
   assessment-requirements via the GitHub API, plus 4 new additive
   `GitHubClient` methods (`list_releases`,
   `are_vulnerability_alerts_enabled`, `is_code_scanning_enabled`,
   `list_security_advisories`) (commit `09bf498`).
7. **Workflow-permissions audit (X3, advisory) + Scorecard restoration
   (H1).** A `scripts/audit_workflow_permissions.py` advisory-mode audit
   (v0.10.7 later promotes it to a blocking gate), and the
   `verify-changelog.yml` action references SHA-pinned to close Scorecard
   alerts #121 + #122 (`PinnedDependenciesID`) and restore the score from
   the v0.10.5 6.2 regression toward 6.5+ (commit `e9e0865`).
8. **Post-v0.10.5 hygiene (H2 + H4).** A new "Pre-publish credential
   readiness check" Step 2.A in [`docs/release-checklist.md`](../../release-checklist.md)
   capturing the v0.10.5 LL-V105-1 partial-publish lesson, and a
   `README.md` "Recent releases" backfill of the v0.10.3 + v0.10.4
   entries (commit `0acd843`). A `capability-matrix.md` snapshot was also
   taken (89→92 catalogs, 8→13 crosswalks, +16 OSPS collector controls).

Reported cycle health at ship (from the `[0.10.6]` CHANGELOG block and
the tag object): **3,536 tests pass / 14 skipped / 3,550 collected
across 279 source files (was 268 at v0.10.5); mypy strict 0/0; ruff
clean.** `uv sync --all-extras --all-packages` clean. Workspace ships **8
PyPI packages** unchanged from v0.10.5 - no new workspace package this
cycle, so no LL-V105-1 partial-publish recurrence risk.

> Note on the test-count baseline: the v0.10.6 plan §7/§8 targeted "≥
> 3,443 / ≥ 3,480" against the v0.10.5 baseline of 3,443; the shipped
> count per the `[0.10.6]` CHANGELOG block is **3,536** pass. The
> 279-source-file figure in the CHANGELOG is stated "(was 268 v0.10.5)";
> the v0.10.5 CHANGELOG itself reports 278 source files, so the
> parenthetical is a minor restatement, not a fact this review can
> independently reconcile. Use the CHANGELOG's 3,536 / 279 as the ship
> figures.

## Review structure

The review and validation discipline for this cycle ran direct-on-`main`
per Evidentia's standing direct-push pattern, with the per-commit gate
(`pytest -q --tb=no && uv run mypy --strict packages/ && uv run ruff
check packages/ tests/ scripts/`) the plan specifies for Approach B.
**Because no per-run JSON exists for v0.10.6, the per-pass finding tables
that the v0.10.4 doc populated from its JSON cannot be reconstructed
here.** The table below records what the CHANGELOG and plan attest plus
what is marked `VERIFY-LIMITED` for the controller to confirm from the
private Step-7 ship-memory.

| Pass | Scope | Verdict |
|---|---|---|
| `/security-review` (pre-tag) | The v0.10.6 phase diffs (`v0.10.5..HEAD`): the OSPS catalog + OSCAL data, the `CrosswalkDefinition` additive extension + 5 crosswalk JSONs, the new `github.osps` collector module + 4 `GitHubClient` methods, the `verify-osps-conformance.yml` CI gate, the workflow-permissions audit script, and the security-policy docs | **Recorded PROCEED-CLEAN** in the cycle ship-memory. `VERIFY-LIMITED` - the exact invocation count, the per-dimension pass table, and the CRITICAL/HIGH/MEDIUM/LOW tallies are not derivable in-repo (no per-run JSON); confirm against the private ship-memory. The crosswalk + catalog work is bundled static data; the new collector methods are read-only GitHub-API queries; the new CI gate's token-scope exposure is the one new active surface (analyzed below). |
| `/code-review` (auto-fire on the collector + CI-gate deltas) | Same phase diffs | `VERIFY-LIMITED` - the CRITICAL/HIGH/MEDIUM/LOW tallies are not derivable in-repo. One concrete code-quality follow-up IS attested: the C5 reviewer flagged that future upstream OSPS bumps would require a manual ~15-site SHA regeneration sweep, which became the v0.10.7 `scripts/catalogs/gen_osps_crosswalks.py` deterministic regenerator (see [`docs/v0.10.6-plan.md`](../plans/v0.10.6-plan.md) §12.3 maintenance follow-up). |
| §12 corrections-log (data-shape verification) | The OSPS catalog + crosswalk + collector data claims | **Four** load-bearing brainstorm assumptions were caught failing verification and corrected in-cycle (§12.1 through §12.4 below). These are accuracy corrections, not security findings. |

> **0-finding framing**: the cycle is recorded in ship-memory as a
> PROCEED-CLEAN ship. No CRITICAL / HIGH / MEDIUM / LOW security finding
> is attributed to v0.10.6 in the `[0.10.6]` CHANGELOG block. The block
> carries no `### Security` subsection (there was no CVE/advisory
> remediation work this cycle - the prior osv carry was clean at the
> 2026-05-27 ship; GHSA-qp9x-wp8f-qgjj, the `tuf` 6.0.0 MEDIUM, was not
> disclosed until 2026-05-28 and is first accepted in v0.10.7). The
> cycle's security *posture* work (VDP policy, GHSA, conformance gate) is
> an addition, not a remediation. `VERIFY-LIMITED` - confirm the precise
> findings array against the private ship-memory, since the per-run JSON
> that would normally hold it does not exist for this version.

## Security-relevant change analysis

The v0.10.6 changes are mostly bundled static data (catalogs +
crosswalks) and security-posture documentation. Two changes touch active
surfaces; the analysis below is drawn from the CHANGELOG + plan (the
formal per-dimension verdict is `VERIFY-LIMITED` per the ship-memory):

| Change | Surface | Why it does not widen the attack surface |
|---|---|---|
| `verify-osps-conformance.yml` CI gate | GitHub Actions token scope + upstream rate-limit | The new workflow makes `gh api` calls to re-validate evidence links. The plan §2.F + §4.2 route a `docs/threat-model.md` §"Stuck-cursor guards" addition into the conformance-gate commit specifically to document the new workflow's token-scope and rate-limit-DoS exposure. The gate is read-only (it validates link liveness; it does not mutate repo state), and it is "intentionally fragile to link-rot" so a 404 fails the build rather than drifting silently. `VERIFY-LIMITED` - confirm the as-shipped token scope against the workflow file + ship-memory. |
| `github.osps` collector + 4 new `GitHubClient` methods | Outbound GitHub-API reads | The 4 new methods (`list_releases`, `are_vulnerability_alerts_enabled`, `is_code_scanning_enabled`, `list_security_advisories`) are **read-only** queries that map GitHub-API state to `ComplianceStatus` + an evidence path. They reuse the existing collector retry/backoff + cursor-pagination patterns (hardened in the v0.10.5 idempotency pass). No new credential-handling path or write scope is introduced. |
| `CrosswalkDefinition` + crosswalk JSONs | Bundled static data | An additive 3-field Pydantic extension (defaults `None`, so the existing 8 crosswalks load unchanged per the api-stability frozen-surface contract) plus 5 new static JSON data files. No parser change, no external input trusted at runtime; the provenance/verification fields are advisory metadata that explicitly flag the mappings as `self-attested-via-upstream` and not independently verified. |

## Tier-4 publishing actions executed this cycle

Per the global publishing-authority protocol, two Tier-4 actions were
gated behind explicit per-action approval in this cycle (recorded in
[`docs/v0.10.6-plan.md`](../plans/v0.10.6-plan.md) §2.D, §3, and the tag object):

| # | Action | As recorded |
|---|---|---|
| T1 | GHSA private-vulnerability-reporting enablement via `gh api -X PATCH repos/Polycentric-Labs/evidentia/security-and-analysis` | Executed inside the C2 security-posture commit (`4d50627`); the plan specifies the commit body captures the executed command + approval timestamp, with a pre-flight `gh api .../security-advisories` empty-queue check. `VERIFY-LIMITED` - confirm the recorded approval timestamp + pre-flight result against the commit body / ship-memory. |
| T2 | OSCAL upstream contribution PR to `oscal-club/awesome-oscal` (the first OSCAL serialization of an OpenSSF flagship deliverable) | The tag object records the PR opened at `https://github.com/oscal-club/awesome-oscal/pull/59`. A separate offer to `ossf/security-baseline` was planned; its disposition is `VERIFY-LIMITED`. |

The tag commit `254277f` itself carries a verified SSH signature (the tag
object includes a `BEGIN SSH SIGNATURE` block), consistent with the
all-commits-signed convention.

## Step 7 - post-tag verification

The post-tag verification for v0.10.6 followed the same publish-targets
contract as the surrounding v0.10.x cycles, and the plan's §8 enumerates
the expected checks (PEP 740 8/8, cosign verify, `docker run "Evidentia
v0.10.6 / Python 3.14.x"`, osv-scanner clean on the published SBOM,
fresh-venv install, plus the new `verify-osps-conformance.yml` evidence-
link gate). **The numeric results are `VERIFY-LIMITED`** - they are not
derivable in-repo because no per-run JSON exists for v0.10.6; the Step-7
ship record lives in private memory.

| Step | Check | Expected (per plan §8) | Result |
|---|---|---|---|
| 7.A | PEP 740 attestation sweep | 8/8 wheels | `VERIFY-LIMITED` |
| 7.B | Container smoke | `docker run ...:v0.10.6 --version` → "Evidentia v0.10.6 / Python 3.14.x" | `VERIFY-LIMITED` (smoke output); digest `sha256:67c12850…` confirmed from the GHCR release |
| 7.C | osv-scanner on published SBOM | 0 issues | `VERIFY-LIMITED` (the cycle was osv-clean the day before the GHSA-qp9x-wp8f-qgjj `tuf` disclosure per the v0.10.7 CHANGELOG; exact sub-step output `VERIFY-LIMITED`) |
| 7.D | Scorecard delta | restore to ≥ 6.5 (close #121 + #122) | The restoration intent is attested by the CHANGELOG/plan; the exact post-tag Scorecard number is `VERIFY-LIMITED` |
| 7.E | Fresh-venv install | `pip install evidentia==0.10.6` green | `VERIFY-LIMITED` |
| 7.F | cosign verify keyless OIDC + SLSA Provenance v1 | PASS | `VERIFY-LIMITED` |
| 7.G | `verify-osps-conformance.yml` evidence-link gate | every claimed-control evidence link resolves | `VERIFY-LIMITED` |
| 7.H | Memory ship-doc + lessons-learned + CHANGELOG cross-check | landed in internal/private memory (this in-repo doc is the backfilled public companion) | Recorded (ship-memory) |

**Step 7 verdict**: PROCEED-CLEAN (per ship-memory) - the Step-7 numeric
sub-step results are not derivable from the CHANGELOG / plan / tag and
must be confirmed from the private ship-memory. The container digest
(`sha256:67c12850…`) was filled 2026-06-03 from the GHCR `v0.10.6`
release (no in-repo source attests it); the streak position is
interpolated (~19th) from the v0.10.7 per-run JSON.

## Findings ledger

### Security findings

No SECURITY-class finding (CRITICAL / HIGH / MEDIUM / LOW) is attributed
to v0.10.6 in the `[0.10.6]` CHANGELOG block or the plan. The block
carries no `### Security` subsection. `VERIFY-LIMITED` - confirm the
empty-findings array against the private ship-memory.

### §12 corrections-log - data-shape verification (caught + fixed in-cycle)

These are accuracy corrections (not security findings) surfaced by the
standing-directive triple-validation discipline when brainstorm-locked
assumptions were checked against the actual codebase + pinned upstream.
Full detail in [`docs/v0.10.6-plan.md`](../plans/v0.10.6-plan.md) §12; the
`[0.10.6]` CHANGELOG records them with commit pointers.

| Ref | Class of failed assumption | Description | Correction |
|---|---|---|---|
| §12.1 | Schema location | The brainstorm locked "YAML crosswalks in a new `crosswalks/data/` dir"; the codebase has the existing 8 crosswalks as **JSON** in `catalogs/data/mappings/`, loaded by `catalogs/crosswalk.py` via `import json`. | Keep JSON; reuse `catalogs/data/mappings/`; extend `CrosswalkDefinition` additively with 3 optional fields (commit `e443fa5`). |
| §12.2 | Numeric count | The plan asserted OSPS Maturity counts of 21/38/58; the pinned upstream tarball (`ac6bbec`) has 25/42/63 at assessment-requirement granularity (41 top-level controls). | Phase 1 test assertions + commit body use the upstream-verified 25/42/63 (commit `d755aed`). |
| §12.3 | Structural preservation | The plan assumed the C1-bundled per-maturity YAMLs preserved upstream's per-control `guidelines[]` reference-id structure; the flattening had dropped it. | Source the 5 crosswalk JSONs from the upstream per-family YAMLs at the same pinned SHA `ac6bbec` (zero SHA drift between C1 and C5); commit `164426a`. |
| §12.4 | Addressing granularity | The plan enumerated 15 controls by top-level family ID (`OSPS-AC-01`); the automatable atoms are assessment-requirement-granular (`OSPS-XX-YY.ZZ`). | The 16 implemented helpers use the real `OSPS-XX-YY.ZZ` IDs; commit `09bf498`. |

### Release-process lesson carried in from v0.10.5 (LL-V105-1, remediated here)

v0.10.6 is where the v0.10.5 LL-V105-1 partial-publish lesson is acted
on: a new "Pre-publish credential readiness check" Step 2.A added to
[`docs/release-checklist.md`](../../release-checklist.md) (Evidentia-side; H2),
plus a skill-side Step 5.D new-PyPI-project pending-publisher sub-check
(H3, committed outside the Evidentia repo). Not a code finding.

### Deferred out of this cycle (per plan §2.E)

| Item | Disposition |
|---|---|
| Hand-verification of the 5 OSPS crosswalks | Deferred to v0.10.7+ - the v0.10.6 ship is "raw + upstream-attested disclaimer" by design; `verification: self-attested-via-upstream` is set explicitly on each crosswalk |
| Workflow-permissions **CI gate** (blocking) | Only the advisory audit **script** ships this cycle (X3); the blocking gate was deferred to v0.10.7 (where `verify-workflow-perms.yml` lands) after confirming existing workflows pass |
| `evidentia crosswalk list` / `crosswalk show` CLI surface | Data ships this cycle; the CLI surface deferred to v0.10.7 or v0.11 |

## Aggregate cycle metrics

| Metric | v0.10.6 |
|---|---|
| Tests | 3,536 pass / 14 skip / 3,550 collected (per CHANGELOG `[0.10.6]`) |
| mypy strict | 0 issues / 279 source files |
| ruff | clean |
| PyPI packages | 8 (unchanged from v0.10.5; no new packages) |
| Cycle commits | 17 (per CHANGELOG; `git rev-list v0.10.5..v0.10.6` = 18 incl. release commit) |
| New collector helpers / `GitHubClient` methods | 16 `populate_osps_*` helpers + 4 read-only API methods |
| New bundled data | OSPS Baseline M1/M2/M3 YAMLs + `osps-baseline.oscal.json` + 5 crosswalk JSONs |
| Security-posture artifacts shipped | `SECURITY.md` refresh + `.well-known/security.txt` + GHSA enablement + `OSPS-CONFORMANCE.md` + `verify-osps-conformance.yml` + `EOL.md` + `docs/verification.md` |
| SECURITY-class findings | 0 attributed in CHANGELOG/plan (`VERIFY-LIMITED` against ship-memory) |
| §12 corrections-log entries | 4 (§12.1 location / §12.2 count / §12.3 structure / §12.4 granularity) |
| Tier-4 publishing actions | 2 (T1 GHSA `gh api` PATCH; T2 `oscal-club/awesome-oscal` PR #59) |
| Tag | `v0.10.6`, 2026-05-27 |
| Tag commit | `254277fa7be3e8e29fd3de8c405915ec53c5099b` (annotated, SSH-signed; tagger Allen Byrd, 2026-05-27) |
| Container digest | `sha256:67c128505eb056094a7d989c08712c8c10fa26ee3fa7d64680c4d43e8d34dc31` (confirmed 2026-06-03 from the GHCR `v0.10.6` release; no in-repo source attests it) |
| `release.yml` duration | `VERIFY-LIMITED` (no per-run JSON for v0.10.6) |
| Consecutive PROCEED-CLEAN streak | ~19th (interpolated: the v0.10.7 per-run JSON pins v0.10.4 as the 17th and v0.10.7 as ~20th, with v0.10.5 / v0.10.6 between) |
| **Overall verdict** | **PROCEED-CLEAN ship (per ship-memory)** - streak position `VERIFY-LIMITED` |

## Cross-references

- CHANGELOG block: [CHANGELOG.md §[0.10.6]](../../../CHANGELOG.md)
- Plan: [docs/v0.10.6-plan.md](../plans/v0.10.6-plan.md) (§2 locked scope, §3 execution sequence, §12 corrections-log)
- Structural model: [docs/security-review-v0.10.4.md](security-review-v0.10.4.md)
- Prior cycle: [docs/security-review-v0.10.5.md](security-review-v0.10.5.md) (deferred Phases 1-5 originate there)
- Forward direction: [docs/security-review-v0.10.7.md](security-review-v0.10.7.md) (closes the §12.3 maintenance follow-up via `gen_osps_crosswalks.py`; promotes the workflow-permissions audit to a blocking gate; crosswalk hand-verification)
- Security policy + lifecycle: [SECURITY.md](../../../SECURITY.md), [EOL.md](../../../EOL.md), [docs/verification.md](../../verification.md)
- Conformance: [OSPS-CONFORMANCE.md](../../../OSPS-CONFORMANCE.md)
- Threat-model addition: [docs/threat-model.md](../../threat-model.md) (the conformance-gate token-scope + rate-limit note)
- Per-run JSON (audit trail): **does not exist for v0.10.6** - the run directory `.local/pre-release-review/runs/` skips from `2026-05-24...v0.10.4` to `2026-05-31...v0.10.7`; the Step-7 ship record is in private memory

---

*Reconstructed during the v0.10.8 docs close-out from the `CHANGELOG.md`
`[0.10.6]` block, `docs/v0.10.6-plan.md`, and the annotated `v0.10.6` tag
object. No per-run `/pre-release-review` JSON exists for v0.10.6, so
Step-7 numeric results, exact finding tallies, the container digest, the
consecutive-streak position, and the `release.yml` duration are not
derivable in-repo and are marked `VERIFY-LIMITED` for confirmation
against the private ship-memory before this document is treated as the
canonical v0.10.6 security review. Reviewer of record: Allen Byrd
`<allenfbyrd>`.*
