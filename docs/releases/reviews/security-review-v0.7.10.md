# Security review — Evidentia v0.7.10

Pre-tag security review of the Evidentia v0.7.10 release surface,
covering the cumulative diff `v0.7.9..HEAD` (65 files / +11,347 LOC /
−112 LOC). Per the `pre-release-review` skill v4 G7, this is the
5th canonical deliverable for the release: a CVSS / CWE / EPSS-
scored finding ledger that maps to the 6-framework compliance
narrative.

## Posture summary

| Bucket | Count | Disposition |
|---|---|---|
| **CRITICAL** | 0 | — |
| **HIGH** | 0 | — |
| **MEDIUM** | 1 (F-V10-S1) | INLINE-FIXED before tag |
| **LOW** | 1 (F-V10-S2) | DEFERRED to v0.7.11 with rationale |
| **Unfixed at ship** | **0** | — |

All 7 OpenSSF Best Practices Silver-tier MUST criteria are Met.
Allen files the Silver application form post-tag.

## Methodology

Reviewer: dedicated `/security-review` subagent invoked Step 3
of the `pre-release-review` v4 workflow, with cumulative-diff
scope `v0.7.9..HEAD`. Scope per v4 G12:

1. **Static analysis** of new modules: `model_risk_store.py`,
   `effective_challenge_store.py`, `routers/model_risk.py`,
   `cli/governance.py`, `cli/model_risk.py`,
   `governance/lines_of_defense.py`,
   `model_risk/{documentation,validation_report}.py`,
   `models/model_risk.py`, plus the v0.7.9 P3 collector token-
   strip patches.
2. **Pattern reference**: cross-checked against the v0.7.9
   `vendor_store.py` (the established secure-pattern reference
   for JSON-file persistence with UUID-shape gate +
   `validate_within` belt-and-suspenders).
3. **Empirical traversal probing**: `uuid.UUID()` shape-validator
   tested with canonical / braced / URN-prefixed / hex32 inputs;
   `Path()` composition verified non-traversal for every accepted
   shape.
4. **Categories examined per Step 3 mandate**: path traversal,
   command injection, unsafe deserialization, SQL/NoSQL
   injection, XSS in HTML rendering, YAML deserialization,
   authentication bypass, secret exfiltration.

## Findings

### F-V10-S1 — Defense-in-depth: `effective_challenge_store.py` omitted `validate_within`

| Field | Value |
|---|---|
| **Severity** | MEDIUM |
| **CVSS 3.1** | 4.3 (AV:N / AC:H / PR:N / UI:N / S:U / C:L / I:N / A:N) |
| **CWE** | CWE-22 (path traversal) — defense-in-depth gap, not exploitable |
| **EPSS** | n/a (no published exploit; pattern-only finding) |
| **File:line** | `packages/evidentia-core/src/evidentia_core/effective_challenge_store.py:69-79, 88-92, 124-128` |
| **Status** | **INLINE-FIXED** before tag (commit landing in this slice) |

**Description**: All three CRUD primitives (`save_challenge`,
`load_challenge_by_id`, `delete_challenge`) constructed paths as
`store_dir / f"{challenge_id}.json"` after a `UUID()` shape gate,
but unlike the v0.7.9 `vendor_store.py` and the sibling v0.7.10
`model_risk_store.py`, they did **not** call
`validate_within(candidate, store_dir)` as a belt-and-suspenders
barrier.

**Why it's not directly exploitable today**: empirically verified
that every `UUID()`-accepting input (canonical, braced `{…}`,
URN-prefixed, hex32) resolves *inside* the store directory; no
traversal vector reachable through the shape gate alone.

**Why it warranted an inline fix**: regression risk. If a future
maintainer relaxes the shape gate (e.g., to accept ULIDs alongside
UUIDs, or external-system foreign keys), the second barrier
disappears with it. CodeQL `py/path-injection` also stops
recognizing the call site as sanitized once the established
pattern diverges, degrading static-analysis coverage silently.

**Fix**: added `from evidentia_core.security.paths import
PathTraversalError, validate_within`; wrapped path composition in
all three functions with `path = validate_within(candidate,
store_dir)` matching the model_risk_store pattern; on
`PathTraversalError`, raise `InvalidChallengeIdError` with clear
attribution.

**Compliance mapping**: NIST SSDF PW.4.4 / ISO 27001:2022 A.8.28
(Secure coding) / SOC 2 CC8.1 (Change-management secure-coding
review).

---

### F-V10-S2 — `cli/model_risk.py:586` `subprocess.run([editor_cmd, …])` honors `$EDITOR` without validation

| Field | Value |
|---|---|
| **Severity** | LOW |
| **CVSS 3.1** | 3.3 (AV:L / AC:H / PR:H / UI:R / S:U / C:H / I:N / A:N) |
| **CWE** | CWE-78 (OS command injection — risk amplifier only) |
| **EPSS** | n/a |
| **File:line** | `packages/evidentia/src/evidentia/cli/model_risk.py:573, 586` |
| **Status** | **DEFERRED** to v0.7.11 with documented rationale |

**Description**: `model edit --editor` reads `os.environ.get(
"EDITOR", "vi")` and passes the value as the first argv element
to `subprocess.run`. Argv-list (not `shell=True`) blocks
shell-metachar injection, but an attacker who already controls
`$EDITOR` can launch any binary on the user's `PATH` when the
operator triggers `--editor`.

**Why deferred not fixed**: pre-conditions are high (env-var
write access already implies code-execution potential). The TPRM
vendor CLI shipped at v0.7.9 has the same pattern and was
accepted there; v0.7.10 preserves consistency. The v0.7.11
sub-batch can address both surfaces at once via either (a) a
binary allowlist (`vi` / `vim` / `nano` / `code` / `emacs`) or
(b) explicit threat-model documentation.

**Compliance mapping**: NIST SSDF PW.5.1 / ISO 27001:2022 A.8.25
(Secure development life cycle) / DORA Article 5(2)(a) (ICT
risk-management framework).

## Items checked + cleared (no finding)

| Surface | Result |
|---|---|
| Path traversal in `model_risk_store.py` | ✅ `validate_within` called on every read/delete; UUID gate + path validator matches v0.7.9 vendor_store pattern |
| YAML deserialization | ✅ all `yaml.safe_load`; no `yaml.load` or `Loader=Loader` |
| HTML/XSS in Markdown generators | ✅ plain Markdown via FastAPI `PlainTextResponse` (Content-Type `text/plain`); model `name`/`purpose`/`notes` cannot escalate to script execution in browser |
| FastAPI body validation | ✅ `extra="forbid"` via `EvidentiaModel` base — unknown JSON fields rejected |
| Collector token-strip M-1 closure | ✅ `vanta`/`drata`/`bitsight`/`securityscorecard` correctly normalize whitespace-only tokens via `.strip() or None` before truthiness gate; no secret-logging regressions |
| REST endpoints unauthenticated by design | ✅ per v0.7.10 plan; deferred to v0.8.0 P0 plugin contract |
| `EffectiveChallenge.subject_model_id` cross-link | ✅ stored as opaque string, never used in path construction or filesystem read — no traversal vector even though the field has no UUID validation |

## Compliance framework mapping (G15)

Per v4 G15, the security-review process maps to controls in 6
compliance frameworks:

| Step | NIST SSDF v1.1 | OpenSSF Scorecard | ISO 27001:2022 | SOC 2 Type II | DORA | CISA Pledge |
|---|---|---|---|---|---|---|
| Static review of new modules | PW.7.1 / PW.7.2 | Code-Review | A.8.25 | CC8.1 | Art. 5(2)(a) | Phishing-Resistant |
| Pattern-reference cross-check | PS.2.1 | — | A.8.27 | CC8.1 | Art. 8(1) | Default Safe Configurations |
| Empirical traversal probing | PW.8.2 | — | A.8.26 | CC7.1 | Art. 9(2) | Default Safe Configurations |
| Inline-fix application | PW.4.4 / PO.4.1 | — | A.8.28 | CC8.1 | Art. 11(2) | Reduce Vulnerability Classes |

## Per-run JSON metadata

`/security-review` invocation:

- skill_version: builtin
- diff_range: `v0.7.9..HEAD`
- fresh_review_commits: 12 (after pushes)
- duration_ms: ~127,000
- outcome: PROCEED-AFTER-INLINE-FIX (1 MEDIUM inline / 1 LOW deferred / 0 unfixed)

## Authorial note

Per the v0.7.9 ship narrative pattern (`docs/security-review-
v0.7.9.md`), this document is one of 5 canonical pre-release-
review deliverables. The other four for v0.7.10:

- `docs/positioning-and-value.md` — strategic positioning carried forward
- `docs/capability-matrix.md` — capability tier classification
- `docs/v0.7.10-plan.md` — release plan (now closed)
- `docs/release-checklist.md` — per-release SOP
