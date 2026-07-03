# Security review — v0.9.8

> **Status**: in-cycle artifact for the v0.9.8 ship. The v4
> pre-release-review's 5th canonical deliverable (see
> `pre-release-review/references/deliverables.md`). v0.9.8 was
> reviewed in two passes across two sessions; this doc consolidates
> both.
>
> **Theme**: v0.9.7 deferral closure + v1.0-prep integration wiring.

## Cycle scope

v0.9.8 wires v0.9.7's data/decision-only primitives into live CLI,
REST, MCP-dispatch, and storage surfaces — multi-tenant RBAC
enforced end-to-end, MCP tool outputs signed at the FastMCP
dispatch layer, an in-tree Sigstore-keyless reference signer — then
closes the CR-V97 review polish and clears a class of supply-chain
and type-safety gaps surfaced during the pre-tag review.

## Review structure

| Pass | Commits | Scope | Verdict |
|---|---|---|---|
| 1 — feature work | `71eb5e6..176eb51` (5) | Full pre-release-review of the integration features (prior session) | PROCEED-CLEAN |
| 2 — supply-chain + type-safety delta | `7b55c6d..7374635` (5) | Focused delta pass over the commits added after Pass 1 | PROCEED-CLEAN |

## Findings ledger

### Pass 1 — feature-work review

Findings as reported by the Pass 1 session's pre-release-review;
granular CVSS / CWE / EPSS scoring is held in that session's
per-run log.

| Finding | Severity | Status |
|---|---|---|
| F-V98-01 — the FastMCP dispatch-signing wrapper mishandled FastMCP 1.27's `(unstructured, structured)` tuple return, breaking every MCP tool call when signing was enabled; the unit tests stubbed `call_tool` with bare values and never exercised the real contract | CRITICAL | FIXED in-cycle — the signature now rides in `CallToolResult._meta` as additive provenance, leaving tool output untouched; 2 real-FastMCP integration tests added to close the coverage gap |
| F-V98-02 — the FastAPI RBAC layer never constructed a multi-tenant policy from the resolved tenant claim | HIGH | FIXED in-cycle via a shared `load_rbac_policy_auto` so CLI and REST classify a policy file identically |
| 3× MEDIUM / LOW batch | MEDIUM / LOW | all FIXED in-cycle |

### Pass 2 — supply-chain + type-safety delta review

Zero findings across all four buckets. Pass 2 reviewed all 5 delta
commits per-commit + 1-hop dependency closure (scope: diff +
dependency closure). The delta is a CVE-removing dependency bump,
two identical sigstore-4.2.0 API-rename migrations, a
type-narrowing assert, a CI-gate strengthening, and the
`chore(release)` commit — no new attack surface, no logic change to
any security-relevant path.

| Finding | Severity | Status |
|---|---|---|
| (none) | — | Zero CRITICAL / HIGH / MEDIUM / LOW |

### Carry-over disposition

| Finding | Severity | Disposition |
|---|---|---|
| F-V97-mcp-signer-trust | INFO | **CLOSED** — v0.9.8 P1.2 ships the in-tree Sigstore-keyless reference signer, removing operator-managed key material from the trust path |
| F-V97-multi-tenant-claim-spoofing | INFO | **CLOSED** — v0.9.8 P1.4 derives the tenant claim from the authenticated principal, not operator-asserted env input |
| idna CVE-2026-45409 | MEDIUM | **CLOSED** — idna 3.11 → 3.15 (Pass 2 commit `7b55c6d`) |
| paramiko CVE-2026-44405 | LOW | **CARRY-FORWARD → v0.9.9** — a fix now exists upstream (paramiko 5.0.0, unblocked by compliance-trestle 4.0.3); deferred as its own focused major-version SSH-library bump rather than a release-day insert |

**Zero unfixed CRITICAL / HIGH / MEDIUM at v0.9.8 ship.** Both
v0.9.7 INFO findings are closed by v0.9.8 integration work.

## `/security-review` + `/code-review`

- **Pass 1** ran the v4-mandated `/security-review` invocations
  against the feature commits; `/code-review` auto-fired on the new
  RBAC / MCP-signing source files.
- **Pass 2** — the `/security-review` and `/code-review` builtins
  auto-scope to current-branch-vs-main; the v0.9.8 work was already
  merged to `origin/main`, so per
  `security-review-integration.md` the delta was reviewed by direct
  file inspection. `/code-review` trigger 4 fired (commit `adfcbf3`
  touched `oscal/sigstore.py`); triggers 1–3 did not (no new public
  API, no new source files, 332 LOC < 500).

## 16-row pre-push gate (Step 6.C)

| # | Check | v0.9.8 outcome |
|---|---|---|
| 1 | Credential sweep of diff | PASS — 0 hits |
| 2 | Claude-attribution in diff content | PASS — 1 hit, dispositioned false-positive: `docs/v0.9.8-plan.md:244` documents the standing no-attribution rule; it is not a commit trailer |
| 3 | Commit-message attribution sweep | PASS — 0 hits across `v0.9.7..HEAD` (git metadata clean) |
| 4 | `.gitignore` secret-store coverage | PASS — `.env*`, `*.pem/.key/.crt/.p12/.pfx`, `secrets/` all covered |
| 5 | Tracked secret-store files | PASS — none tracked (the only filesystem hits are gitignored `.venv/` content) |
| 6 | Test gate | PASS — 3250 passed / 14 skipped |
| 7 | Type / lint gate | PASS — mypy strict clean (262 files / 7 packages); ruff clean |
| 8 | Build sanity | PASS — 7 evidentia-* packages built at 0.9.8 (wheel + sdist); `twine check` all PASSED |
| 9 | Identity | PASS — Allen Byrd / canonical noreply identity |
| 10 | Branch sanity | PASS — `fix/mypy-v0.9.8`, 1 ahead / 0 behind `origin/main` |
| 11 | Legacy secrets | PASS — only `CODECOV_TOKEN` (4 days old); no legacy `PYPI_API_TOKEN` |
| 12 | Code-scanning alert delta | PASS — 0 open code-scanning alerts |
| 13 | Container CVE scan (Trivy) | WARN-SKIP — `trivy` not installed; v0.9.8 changed no Dockerfile content; `release.yml` `container-build` covers the published image |
| 14 | Vulnerability aging SLO | PASS — 0 HIGH/CRITICAL deps unpatched; the 2 open alerts are MEDIUM idna (stale alert — fix already on `main`) + LOW paramiko (documented v0.9.9 carry-forward) |
| 15 | License / SCA enforcement | WARN-SKIP — `pip-licenses` not installed; no new third-party deps in the v0.9.8 source delta; Tier-C placeholder content not bundled in wheels |
| 16 | Secret-rotation cadence | PARTIAL — repo secret `CODECOV_TOKEN` 4 days old (fresh); SSH-key age unverifiable (gh token lacks the `admin:public_key` scope) |

Rows 13 / 15 / 16 degrade gracefully on absent optional tooling
and a withheld gh scope — none touches the v0.9.8 delta's actual
surface. Zero blocking findings.

## Cross-references

- `CHANGELOG.md` `[0.9.8]` block
- `docs/v0.9.8-plan.md` — phase-by-phase cycle plan
- `docs/threat-model.md` — v0.9.8 attack-surface delta
- `docs/capability-matrix.md` — v0.9.8 SHIPPED snapshot
- `docs/ROADMAP.md` — v0.9.8 SHIPPED transition
- `docs/security-review-v0.9.7.md` — prior-cycle artifact (carried the F-V97 INFO findings now closed)

## PROCEED-CLEAN gate verdict

**PROCEED-CLEAN** for the v0.9.8 ship. Both review passes returned
PROCEED-CLEAN; the 16-row pre-push gate carries zero blocking
findings (3 rows WARN-degraded on absent tooling, none material to
the delta). Zero unfixed CRITICAL / HIGH / MEDIUM. Both v0.9.7 INFO
findings are closed by v0.9.8 integration work.

**23rd consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x
line.

## Step 7 — post-tag verification

`release.yml` run `26227600699` — conclusion **success**, ~4m05s
tag-to-publish. Tag `v0.9.8` at commit `9b76417`.

| Sub-step | Outcome |
|---|---|
| 7.1 `release.yml` completion | ✓ success |
| 7.3 PEP 740 attestations | ✓ 7/7 packages verified (`pypi-attestations verify pypi`) |
| 7.4 / 7.5 container | ✓ cosign keyless verify PASSED — Rekor transparency log + cert chain + SLSA provenance v1 predicate; image digest `sha256:5fef096853ff1eb60954f6d828fb7d231f2e009111972e31d1203e66ec38b510`. `gh attestation verify oci://` produced no output in this environment (tooling finickiness, not a verification failure); cosign is the authoritative container check |
| 7.6 SBOM osv-scan | 181 packages; 2 transitive findings, both accepted (below) |
| 7.8 fresh-venv install | ✓ `pip install evidentia[gui]==0.9.8` from PyPI; `evidentia version` → `Evidentia v0.9.8`; `catalog list` functional |
| 7.9 GitHub Release notes | ✓ CHANGELOG `[0.9.8]` auto-populated; CycloneDX SBOM attached as a release asset |

### Accepted findings (Step 7.6 osv-scan)

| Advisory | Package | Severity | Disposition |
|---|---|---|---|
| CVE-2026-44405 / GHSA-r374-rxx8-8654 | `paramiko` 4.0.0 (transitive) | LOW (3.4) | **Carry-forward → v0.9.9** — the SHA-1 `rsakey.py` allowance; fixed upstream post-4.0.0 (`a448945`); deferred as its own focused major-version SSH-library bump |
| PYSEC-2025-183 / CVE-2025-45768 | `pyjwt` 2.12.1 (transitive) | scored 7.0 — **DISPUTED** | **Accepted** — disputed by the pyjwt maintainer (HMAC key length is the calling application's choice, not a library flaw); no fix version exists (every release is flagged); `pyjwt` arrives transitively (`sigstore` / `mcp` / `msal` / `okta` / `pygithub` / `snowflake-connector-python`) and Evidentia exposes no operator-chosen-key JWT-minting surface. Operator-confirmed accept, 2026-05-21 |

The pre-tag gate (Row 14) used Dependabot alerts, which suppress
disputed CVEs; `osv-scanner` includes them. Follow-up for v0.9.9:
add `osv-scanner --sbom` to the pre-push gate so transitive /
disputed advisories surface pre-tag rather than post-tag.

### Step 7 verdict

**PROCEED-CLEAN confirmed post-tag.** The published PyPI + GHCR
artifacts verify against their build provenance; the 2 osv-scan
findings are accepted with rationale (0 unacked). v0.9.8 is
SHIPPED.
