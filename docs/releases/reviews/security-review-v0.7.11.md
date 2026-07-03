# Security review — Evidentia v0.7.11

Pre-tag security review of the Evidentia v0.7.11 release surface,
covering the cumulative diff `v0.7.10..HEAD` (~7,138 LOC added,
12 commits). Per the `pre-release-review` skill v4 G7, this is
the 5th canonical deliverable for the release: a CVSS / CWE /
EPSS-scored finding ledger that maps to the 6-framework
compliance narrative.

## Posture summary

| Bucket | Count | Disposition |
|---|---|---|
| **CRITICAL** | 0 | — |
| **HIGH** | 0 | — |
| **MEDIUM** | 0 | — |
| **LOW** | 0 | — |
| **Unfixed at ship** | **0** | — |

**PROCEED-CLEAN.** First v0.7.x release in this cycle to ship
with zero security findings (v0.7.10 had 1 MEDIUM inline-fixed +
1 LOW deferred). Reflects the maturity gain from the v0.7.11
P3 deferral closures (which addressed several pattern-level
hygiene gaps) + the harmonized 6-store secure pattern.

## Methodology

Reviewer: dedicated `/security-review` subagent invoked at Phase
final of the pre-release-review v4 workflow, with cumulative-diff
scope `v0.7.10..HEAD`. Coverage:

1. **F-V10-S2 closure validation** — empirical probing of the
   `cli/_editor.py` `resolve_editor_or_exit()` helper across 6
   boundary cases (empty $EDITOR, opt-out variants, allowlist
   bypass, unbalanced quotes)
2. **`validate_within` harmonization** — confirmed argument
   order `(candidate, safe_root)` matches `security/paths.py:55`
   across all 6 stores (vendor_store + model_risk_store +
   effective_challenge_store + metric_store + workflow_store +
   retention_metadata_store)
3. **L-1 closure validation** — confirmed all 4 vendor-risk
   endpoints (vanta + drata + bitsight + securityscorecard) reject
   bad input with explicit 400
4. **P1.5 G3/G4/G5 + P0 retention surfaces** — Pydantic
   `extra="forbid"` inheritance, YAML `safe_load` exclusivity,
   Markdown report XSS surface analysis
5. **WORM contract empirical probing** — 4 attack vectors
   tested against `LocalFilesystemWORM.delete` + `extend_retention`
6. **Authentication + secrets** — unauthenticated REST design
   carries forward; tokens flow exclusively from server-side env
   vars

## Items checked + cleared (per area)

### F-V10-S2 (`cli/_editor.py`) — CLEAN

- Empty `$EDITOR` → blocked
- `EVIDENTIA_EDITOR_ALLOW_ANY=yes`/`true`/`on`/`0` → all blocked
  (strict `=="1"` works as documented)
- `EVIDENTIA_EDITOR_ALLOW_ANY=1` + non-allowlist binary → opt-out
  works correctly
- Unbalanced quote `vim "unclosed` → `shlex.split` ValueError →
  `typer.Exit(1)`
- `shutil.which` resolution on head token; basename-allowlist
  matches resolved absolute path (handles symlinks); argv-list
  flow to `subprocess.run` (not `shell=True`) preserves layered
  defense

### `validate_within` harmonization — CLEAN

Confirmed argument order across all 6 stores:
- `vendor_store.py:143` ✓
- `model_risk_store.py:137` ✓
- `metric_store.py:85` ✓
- `workflow_store.py:74` ✓
- `retention_metadata_store.py:77` ✓
- `effective_challenge_store.py` ✓

Three new stores (`metric_store`, `workflow_store`,
`retention_metadata_store`) call `Path(env)` directly rather than
`Path(env).expanduser().resolve()` — cosmetic asymmetry only.
`validate_within` calls `.resolve(strict=False)` internally so
traversal is still rejected. No security impact; fold into a
v0.7.12 cosmetic refactor if desired.

### L-1 closure (`routers/collectors.py`) — CLEAN

All 4 endpoints (vanta, drata, bitsight, securityscorecard) replace
silent `or 2000` coercion with explicit type+range gate. Pattern is
identical across endpoints. Bad input → 400 with clear error.

### P1.5 G3/G4/G5 + P0 retention modules — CLEAN

- Pydantic `extra="forbid"` inheritance verified across
  `Metric`, `Workflow`, `OpenFAIRScenario`, `RetentionMetadata`
- YAML loading uses `yaml.safe_load` consistently (3 call sites);
  no `yaml.load` calls
- Markdown reports embed operator-supplied strings without HTML
  escaping — but deliverables are plain `.md` files, XSS is
  downstream-renderer trust not an Evidentia surface

### WORM contract — CLEAN

3-layer defense holds end-to-end:
1. **legal_hold** check — short-circuits delete + can't reach
   EXPIRED
2. **is_locked** check — rejects delete inside retention window
3. **lifecycle != EXPIRED** check — rejects delete on active /
   preserved records

Subtle vector tested + cleared: GDPR record with
`retention_period_days=0` (lock_until=None, ACTIVE state) cannot
bypass via `transition_lifecycle(ACTIVE→EXPIRED)` because that
transition requires `lock_until is not None and today >= lock_until`
(`metadata.py:275-279`). Cannot reach EXPIRED → cannot reach
delete.

`extend_retention` correctly rejects backward dates
(`worm.py:208-212`).

### Authentication / secrets — UNCHANGED

REST is unauthenticated by design (per v0.7.10 token-auth-
deferred-to-v0.8.0 plugin contract). Tokens flow exclusively from
server-side env vars; never via request bodies.

## Compliance framework mapping (G15)

Per v4 G15, the security-review process maps to controls in 6
compliance frameworks:

| Step | NIST SSDF v1.1 | OpenSSF Scorecard | ISO 27001:2022 | SOC 2 Type II | DORA | CISA Pledge |
|---|---|---|---|---|---|---|
| Static review of new modules | PW.7.1 / PW.7.2 | Code-Review | A.8.25 | CC8.1 | Art. 5(2)(a) | Phishing-Resistant |
| Pattern-reference cross-check | PS.2.1 | — | A.8.27 | CC8.1 | Art. 8(1) | Default Safe Configurations |
| Empirical attack-vector probing | PW.8.2 | — | A.8.26 | CC7.1 | Art. 9(2) | Default Safe Configurations |
| WORM contract enforcement | PW.4.4 | — | A.8.10 | CC6.1 | Art. 11(2) | Reduce Vulnerability Classes |

## Per-run JSON metadata

`/security-review` invocation:

- skill_version: builtin (v4 G12 invocation)
- diff_range: `v0.7.10..HEAD`
- fresh_review_commits: 12
- duration_ms: ~206,000
- outcome: PROCEED-CLEAN (0 HIGH / 0 MEDIUM / 0 LOW)

## Authorial note

Per the v0.7.10 + v0.7.9 ship narrative pattern, this document
is one of the 5 canonical pre-release-review deliverables. The
other four for v0.7.11:

- `docs/positioning-and-value.md` — strategic positioning carried forward
- `docs/capability-matrix.md` — capability tier classification
  (refreshed with v0.7.11 surfaces)
- `docs/v0.7.12-plan.md` — forward release plan
- `docs/release-checklist.md` — per-release SOP
