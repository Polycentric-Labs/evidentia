# Evidentia v0.7.0 — capability matrix

> Step-4 deliverable from the v0.7.0 comprehensive review (2026-04-25).
> Functional + code-review + adversarial smoke testing of every public
> capability surface, ordered by enterprise risk. Findings queued
> through Step 4 and either fixed in-line (CRITICAL) or deferred to
> v0.7.1 (HIGH-priority but design-decision-laden).
>
> Cross-link to: [enterprise-grade.md](enterprise-grade.md) (the quality
> bar), [positioning-and-value.md](positioning-and-value.md) (where this
> sits in the market), [testing-playbook.md](testing-playbook.md) (the
> operational test loop).

---

## Re-validation snapshot — 2026-05-27 (v0.10.6 PRE-TAG) — OSPS Baseline first-mover

v0.10.6 lands the OpenSSF OSPS Baseline conformance bundle reserved at the
v0.10.5 cycle close: 3 maturity-tier YAML catalogs + OSCAL 1.2.1 conversion
(first-mover) + 5 upstream-sourced crosswalks + 16 GitHub-collector OSPS
controls + an OSPS-CONFORMANCE.md doc + a `verify-osps-conformance.yml` CI
gate verifying the conformance claim. Also lands SECURITY.md refresh +
.well-known/security.txt + GHSA enablement (C2); EOL.md + docs/verification.md
consumer-side recipes (C4); Scorecard restoration via verify-changelog.yml
SHA pins (C7) — reverses the v0.10.5 -0.3 regression by closing alerts
#121 + #122; and an advisory-only workflow-permissions audit (C7) flagging
3-of-11 workflows for v0.10.7 narrowing follow-up. Per skill v5.1 §4.5
patch-release allowance, all unchanged subsystems are REUSED from the
v0.10.0 → v0.10.5 matrices; this snapshot covers the v0.10.5 → v0.10.6
delta.

### Surface delta vs v0.10.5

| Surface | v0.10.5 | v0.10.6 | Delta |
|---|---|---|---|
| Bundled catalogs | 89 | 92 | +3 (OSPS Baseline maturity-1/2/3 YAMLs) |
| OSCAL conversions | 0 | 1 | +1 (osps-baseline.oscal.json) |
| Bundled crosswalks | 8 | 13 | +5 (OSPS → NIST-SSDF, NIST-CSF-2.0, EU-CRA, PCI-DSS-4.0, NIST-800-161) |
| GitHub collector OSPS controls | 0 | 16 | +16 (AC + BR + DO + GV + LE + QA + VM family assessment-requirements) |
| Workflows | 10 | 11 | +1 (verify-osps-conformance.yml; C3) |
| Helper scripts | 12 | 14 | +2 (validate_osps_conformance_yaml.py from C3, audit_workflow_permissions.py from C7) |
| Public API surface additions | — | +3 fields + 16 helpers | CrosswalkDefinition provenance/verification/verification_note (additive) + 16 populate_osps_* helpers |
| OSPS Baseline conformance | not claimed | SHIPPED (Maturity 2 + partial Maturity 3 via OSPS-CONFORMANCE.md + CI gate) | — |

### Highlights

- First Evidentia ship of OpenSSF OSPS Baseline conformance artifacts
  (3-catalog bundle + OSCAL conversion + 5 crosswalks + 16 GitHub-
  collector helpers + conformance gate).
- SECURITY.md refresh + .well-known/security.txt + GHSA enablement (C2).
- EOL.md + docs/verification.md (C4) — consumer-side cosign + PEP 740 +
  osv-scanner + SLSA Provenance v1 recipes.
- Scorecard restoration via verify-changelog.yml SHA pins (C7) — reverses
  the v0.10.5 -0.3 regression by closing alerts #121 + #122.
- Workflow-permissions audit (C7) — advisory only this cycle; 3 of 11
  workflows flagged FAIL (legitimate write scopes for PR/issue comments),
  all justified, v0.10.7 backlog story.

### §12 corrections-log entries added this cycle

4-of-4, per [v0.10.6-plan.md §12](v0.10.6-plan.md):

- §12.1: crosswalk format/path (JSON in catalogs/data/mappings/, NOT YAML in new dir)
- §12.2: OSPS Baseline counts (25/42/63 assessment-requirements, NOT plan's 21/38/58)
- §12.3: crosswalk source data location (upstream per-family YAMLs at pinned SHA, NOT the C1-flattened per-maturity bundle)
- §12.4: OSPS control-ID granularity (OSPS-XX-YY.ZZ assessment-requirement, NOT OSPS-XX-YY family)

---

## Re-validation snapshot — 2026-05-24 (v0.10.4 PRE-TAG) — first run under skill v5.1

v0.10.4 closes the **OCSF symmetry loop** (v0.10.0 SARIF emit + v0.10.1 OCSF
ingest + v0.10.4 OCSF emit) on `evidentia gap analyze`, lands the polish
items from v0.10.3 `/code-review`, ships the CHANGELOG-presence pre-tag CI
gate (lesson from v0.10.3 move-tag re-fire), and stages the v0.10.5 Phase B
audit synthesis as forward direction. Per skill v5.1 §4.5 patch-release
allowance, all unchanged subsystems are REUSED from the v0.10.0 → v0.10.3
matrices; the section below covers only the new + modified surfaces.

**Step 4.1 — `/security-review-scoped` invocation #2**: SKIPPED per the
[security-review-scoped-wrapper.md "When the wrapper isn't needed"](../C:/Users/allen/.claude/skills/pre-release-review/references/security-review-scoped-wrapper.md)
patch-release shortcut. Rationale: the v0.10.3..HEAD diff is entirely
within one subsystem (gap_analyzer / collectors output + a thin MCP
wrapper); the Step 3 builtin invocation #1 already covered the only
touched subsystem with a PROCEED-CLEAN verdict. Logged for audit trail.

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `evidentia gap analyze --format ocsf` | CLI | Symmetric counterpart to v0.10.0 SARIF emit + v0.10.1 OCSF ingest. Closes the integration-survey.md §3 row 15 ("Splunk/Datadog/Elastic ingest OCSF natively"). Output is a JSON array of OCSF Compliance Findings (class_uid 2003). |
| 2 | `evidentia_core.gap_analyzer.ocsf.gap_report_to_ocsf_array(report)` | Library | Maps `GapReport` → `list[ComplianceFinding]`. Embeds `gap.model_dump(mode="json")` under `unmapped["evidentia"]["gap"]` for round-trip fidelity (mirrors v0.10.0 SecurityFinding pattern). |
| 3 | `verify_signed_artifact` MCP tool (#13) | MCP | Thin wrapper exposing `verify_ar_file` to Claude clients. Path-gated via `validate_within(candidate, --allow-root)`. Auto-routed through CIMD scope gate (no per-tool exception list — confirmed at server.py:135). Returns SignedToolOutput envelope per v0.9.8 wrap_signed_output convention. |
| 4 | `OutputFormat = Literal[..., "ocsf"]` extension | Library (additive) | Append-only addition to the frozen `OutputFormat` literal per `docs/api-stability.md` §3 (additive-optional). No breaking change. |
| 5 | `scripts/run_osv_scan.py` | Build tooling | NEW. Reads the project's CycloneDX SBOM, runs `osv-scanner` over it, fails CI on any HIGH+ finding. Subprocess uses list-form args (no shell=True); stdlib only (subprocess + shutil + tomllib + pathlib + argparse). |
| 6 | `verify-changelog.yml` PR-time gate | CI | Lesson from v0.10.3 move-tag re-fire. Gates CHANGELOG `[X.Y.Z]` block presence keyed off `pyproject.toml [project].version`. Per v0.10.4 P5. |

**Modified surfaces** (additive only):
- `evidentia_core.gap_analyzer.reporter.export_report()` — added `format="ocsf"` dispatch branch (delegates to `gap_report_to_ocsf_array`)
- `evidentia_core.catalogs.loader._load_catalog_data()` — error-message polish for no-extension paths (operator-experience improvement only)
- `scripts/catalogs/regenerate_manifest.py` — `framework_id` collision guard (defensive; would catch contributor who forgets to delete the JSON when converting to YAML)

**Adversarial-probe taxonomy** (focused on `--format ocsf`):

| # | Vector | `--format ocsf` |
|---|---|---|
| 1 | Minimal positive | ✅ `tests/fixtures/sample-inventory.yaml` → 106 well-formed OCSF Compliance Findings against nist-csf-2.0 |
| 2 | Empty inventory | ✅ Rejected with clear `ValueError("Invalid Evidentia YAML: expected a mapping with 'controls' key")` at input-validation layer (before reaching OCSF emit) |
| 3 | Oversized inventory (2k items) | ⚠️ Masked by input-validation rejection (YAML probe used `inventory:` instead of `controls:`); not actually exercised. **v0.10.5 follow-on**: re-probe with valid 2k-control inventory to confirm OCSF emit scales. |
| 4 | Malformed YAML (truncated mid-document) | ✅ Rejected with `ScannerError` carrying line + column |
| 5 | Read-only output target | ⚠️ Masked by input-validation rejection (same probe shape bug). **v0.10.5 follow-on**: re-probe. |
| 6 | Concurrent invocation (4 writers, same target) | ⚠️ Masked by input-validation rejection (same). **v0.10.5 follow-on**: re-probe. |
| 7 | Round-trip JSON validity (`json.loads` on the output) | ✅ All emitted output parses cleanly (smoke confirmed via Python) |
| 8 | Trust boundary (untrusted ingest of self-emitted output) | ✅ N/A — gap emit is one-way (no `gap_from_ocsf` exists; documented in code-review L5 deferred to v0.10.5) |

**Vectors not applicable**: SSRF (no URL input on the emit path; only the v0.10.1 OCSF ingest URL mode has the surface, already hardened by `--block-private-ips` in v0.10.2).

**DAST (Step 4.4)**: SKIPPED with rationale logged — `schemathesis` + `playwright` missing from local tool inventory per Step 1 pre-flight; v0.10.4 doesn't touch the FastAPI REST surface or the React UI surface (diff is CLI + MCP + library only), so DAST adds no marginal coverage this cycle. Per the per-run JSON's `tool_availability.degradation_notes`. Will install + run DAST when the next minor touches REST/UI.

**Test count + source-file trajectory**: 3369 tests pass / 17 skipped /
268 source files / mypy strict 0 issues across 268 source files (7
packages); ruff clean. **+14 tests** vs the v0.10.3 baseline (3355 / 14
to 3369 / 17) across 4 new test files (test_yaml_loader.py +
test_ocsf_emit.py + test_ocsf_round_trip.py + test_poam_ocsf_round_trip.py)
+ 1 extended (test_mcp/test_server.py).

**Step 4 disposition**: **PROCEED-CLEAN**. 0 CRITICAL / 0 HIGH carried
into Step 5. 4 fix-now items queued for Step 5.A batch (CR-V104-1 through
CR-V104-4 per the Step 3 findings summary in the per-run JSON). 6
medium-class items deferred to v0.10.5 polish bucket (catalog choke-point
extension, deprecation-comment refresh, enum_value duplicate cleanup,
private-import promotion, 2 test-coverage gaps).

---

## Re-validation snapshot — 2026-05-23 (v0.10.3 PRE-TAG)

v0.10.3 lowers the contributor barrier for new framework catalogs
(YAML alongside JSON) and adds a NORMATIVE positioning piece
(OpenSSF Gemara reference-model mapping). Per v4 §4.5 patch-release
allowance, v0.10.0 + v0.10.1 + v0.10.2 matrices REUSED for all
unchanged subsystems; the section below covers only the new +
modified surfaces.

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `evidentia_core.catalogs.loader._load_catalog_data(catalog_path)` | Library (private; internal helper) | Closed-allowlist extension dispatch (`.json` → `json.loads`; `.yaml` / `.yml` → `yaml.safe_load`); rejects unsupported extensions + non-mapping YAML roots with clear `ValueError`. All catalog loaders now flow through this choke point. |
| 2 | YAML-format catalog files | Data | The bundled `data/<tier>/` directories now accept `.yaml` / `.yml` alongside `.json`. The `regenerate_manifest.py` scanner globs all three; `data/frameworks.yaml` `path` field carries the actual extension so the loader auto-dispatches. |
| 3 | `iso-27017-2015.yaml` (proof) | Data | First YAML catalog in the bundled set — 7-control Tier-C ISO/IEC 27017:2015 cloud-services stub; converted from the equivalent JSON. Both formats produce identical `ControlCatalog` objects (round-trip equivalence test). |
| 4 | `docs/contributing-a-catalog.md` | Docs | The 3-file PR recipe + YAML-vs-JSON comparison + required schema + tier conventions. Lowers the barrier for new framework contributions. |
| 5 | `docs/gemara-mapping.md` | Docs (NORMATIVE positioning) | 13-row mapping table — every OpenSSF Gemara reference-model component (Catalog: Control/Capability/Principle/Risk/Threat/Vector/Guidance/Lexicon + Log: Audit/Enforcement/Evaluation + Document: Mapping/Policy + Entity + Collection) → the Evidentia surface that satisfies it. "Mapping, not conformance claim" framing. Cites Gemara v1.1.0 (2026-05-12), CUE schemas, Go SDK at gemaraproj/go-gemara, adopters FINOS CCC + OpenSSF Security Baseline. |

**Modified surfaces** (additive only): `load_oscal_catalog`,
`load_evidentia_catalog`, `load_non_control_catalog`, `load_catalog`,
`load_any_catalog` all refactored to call `_load_catalog_data` — no
public-API change. `scripts/catalogs/regenerate_manifest.py` extended
to scan YAML extensions; same maintenance-script role.

**Adversarial-probe taxonomy** (focused on the new loader helper;
unchanged subsystems re-validated via the full 3355-test suite):

| # | Vector | YAML loader |
|---|---|---|
| 1 | Minimal positive | ✅ `.json` / `.yaml` / `.yml` all dispatch + parse |
| 2 | Bad input — unsupported extension (`.toml`) | ✅ Rejected with clear `ValueError("Unsupported catalog file extension")` |
| 3 | Bad input — non-mapping YAML root (list) | ✅ Rejected with clear `ValueError("top-level must be a mapping")` |
| 4 | Bad input — malformed YAML | ✅ Propagated as `yaml.YAMLError` (caught + WARN-logged in regenerate_manifest scanner) |
| 5 | Round-trip equivalence (JSON ↔ YAML same content) | ✅ Asserted via `test_yaml_and_json_load_to_identical_catalogs` |
| 6 | Bundled YAML loads via registry | ✅ `iso-27017-2015` end-to-end via `FrameworkRegistry.get_catalog` |
| 7 | Trust boundary (`yaml.load` deserialization RCE) | ✅ N/A — `yaml.safe_load` only constructs basic Python types |
| 8 | Case confusion (`.YAML`, `.YML`, `.JSON`) | ✅ Normalized via `suffix.lower()` |

**Vectors not applicable**: concurrent / race (pure-read loader);
SSRF (no URL input); DAST (no new REST/UI surface).

**Test count + source-file trajectory**: 3355 tests pass / 14
skipped / 267 source files / mypy strict 267 of 267 (7 packages);
ruff clean. **+7 tests** vs the v0.10.2 baseline (3348 / 14).

**Step 4 disposition**: **PROCEED-CLEAN**. 0 CRITICAL / 0 HIGH /
0 MEDIUM / 0 NEW LOW. Code-review surfaced 4 polish-class
suggestions (docstring choke-point note, error-message polish,
manifest framework_id collision guard, multi-line round-trip test
coverage) — all deferred to v0.10.4 polish batch; none block ship.

---

## Re-validation snapshot — 2026-05-23 (v0.10.2 PRE-TAG)

v0.10.2 consolidates the v0.10.x line further — 4 new MCP tools that
expose the v0.10.0 + v0.10.1 OCSF / SARIF / TPRM / POA&M
functionality to AI clients (Claude Desktop, Claude Code) end-to-end;
a GRC Engineering Club marketplace plugin staged in-repo (NOT yet
upstream-submitted — separate approval); and a `--block-private-ips`
flag on `evidentia collect ocsf` URL mode closing the v0.10.1
F-V101-L1 SSRF surface. Per v4 §4.5 patch-release allowance, v0.10.0
+ v0.10.1 matrices REUSED for unchanged subsystems; the section below
covers only the new + modified surfaces.

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `gap_analyze_sarif(inventory_path, frameworks, show_efficiency)` MCP tool | MCP | Wraps v0.10.0's `gap_report_to_sarif` so AI clients emit SARIF 2.1.0 for a CI gate directly. Path safety via the existing `resolved_allow_root` closure. |
| 2 | `collect_ocsf(input_path)` MCP tool | MCP | Wraps v0.10.1's `collect_ocsf_file`. **File mode only** — URL ingest deliberately NOT exposed at the MCP layer to harden out the F-V101-L1 SSRF surface by construction. |
| 3 | `tprm_vendor_list()` MCP tool | MCP | Read-only vendor enumeration. Reads from `EVIDENTIA_VENDOR_STORE_DIR`. |
| 4 | `poam_list()` MCP tool | MCP | Read-only POA&M enumeration. Reads from `EVIDENTIA_POAM_STORE_DIR`. |
| 5 | `evidentia collect ocsf --block-private-ips/--allow-private-ips` | CLI | Default True. Rejects RFC1918 + link-local + loopback + multicast + reserved address ranges via `socket.getaddrinfo` pre-resolution before opening the socket. Closes **F-V101-L1**. |
| 6 | `collect_ocsf_url(..., block_private_ips: bool = True)` | Library | New kwarg on the v0.10.1 ingest function; default True. |
| 7 | GRC Engineering Club marketplace plugin (staged) | Plugin | `marketplace/grc-engineering-suite/plugins/evidentia/` — manifest matches upstream `plugin.json` schema; 2 generalist OSS commands (`gap-analyze-sarif`, `ingest-ocsf`). NOT yet upstream-submitted. |

**Modified surfaces** (additive only): MCP `_register_tools()` registers
4 additional tools; collector module gains `_refuse_private_host`
helper + the kwarg.

**Adversarial-probe taxonomy** (focused on new surfaces; unchanged
subsystems re-validated via the full 3348-test suite which retains
every prior adversarial test):

| # | Vector | New MCP tools | SSRF hardening (`--block-private-ips`) |
|---|---|---|---|
| 1 | Minimal positive | ✅ All 4 tools end-to-end against fixtures | ✅ Default behavior allows public-IP URLs through |
| 2 | Bad input | ✅ Missing inventory file / OCSF file → `FileNotFoundError`; invalid OCSF class_uid → `OCSFIngestError` | n/a |
| 3 | Empty input | ✅ Empty vendor / POA&M stores return `[]` | n/a |
| 4 | Path traversal | ✅ Path safety via `resolved_allow_root` closure when `--allow-root` set | n/a |
| 5 | Trust boundary | ✅ Forged unmapped block ignored via inherited `trust_unmapped=False` | n/a |
| 6 | URL host = AWS metadata `169.254.169.254` | n/a | ✅ Rejected pre-socket-open |
| 7 | URL host = RFC1918 (10/8, 172.16/12, 192.168/16) | n/a | ✅ All ranges rejected |
| 8 | URL host = loopback (127.0.0.1, ::1) | n/a | ✅ Rejected |
| 9 | `--allow-private-ips` bypass | n/a | ✅ Bypasses private-IP check; check confirmed skipped |
| 10 | URL with missing hostname | n/a | ✅ Rejected with clear message |

**Vectors not applicable**: concurrent/race (pure-transform MCP
tools, single-resolve SSRF check); large-input DoS (URL ingest
unchanged from v0.10.1 — still 50 MB capped). **DAST skipped** per
Step 4 G11 — no new REST/UI surface; MCP tools covered by 11 new
direct unit tests; SSRF hardening covered by 5 new unit tests.

**Known limitation (NOT a finding)**: the SSRF check is a single
DNS pre-resolution; an attacker controlling both the DNS server
AND the URL the operator types could in principle do DNS rebinding
between check time and fetch time. Out of scope of v0.10.2's threat
model (operator-typo case); mitigation would require IP pinning +
Host header, deferred to a future release if the threat model
expands.

**Test count + source-file trajectory**: 3348 tests pass / 14
skipped / 267 source files / mypy strict 267 of 267 (7 packages);
ruff clean. **+16 tests** vs the v0.10.1 baseline (3332 / 14).

**Step 4 disposition**: **PROCEED-CLEAN**. 0 CRITICAL / 0 HIGH / 0
MEDIUM / 0 NEW LOW. **F-V101-L1 CLOSED by Phase 3.**

---

## Re-validation snapshot — 2026-05-23 (v0.10.1 PRE-TAG)

v0.10.1 consolidates the v0.10.x integration line: closes the two
v0.10.0 review findings (F-V100-L1 trust-boundary + F-V100-M1
release-tooling), ships the deferred third-party OCSF ingestion
collector + Detection Finding path (Prowler / AWS Security Hub), and
extends the v0.10.0 pilot pattern (`compliance_status` field) to the
remaining 11 collectors. Per v4 §4.5, v0.10.1 (a patch bump) REUSES
the v0.10.0 capability matrix for the 8 unchanged subsystems and
adds the section below for the new surfaces only.

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `evidentia_core.ocsf.finding_from_ocsf` — additive `trust_unmapped: bool = True` kwarg | Library | Closes F-V100-L1. Default `True` preserves the lossless Evidentia round-trip; `False` ignores the `unmapped["evidentia"]` block and rebuilds from native OCSF fields only. Non-breaking under api-stability §1. |
| 2 | `evidentia_core.ocsf.finding_from_ocsf_detection` | Library | OCSF Detection Finding (`class_uid` 2004) → SecurityFinding. Synthesizes `compliance_status` from `severity_id` per a conservative heuristic (CRITICAL/HIGH/MEDIUM/FATAL → FAIL, LOW → WARNING, INFORMATIONAL/UNKNOWN/OTHER → UNKNOWN). Default `trust_unmapped=False`. |
| 3 | `evidentia_collectors.ocsf` package — `collect_ocsf_file(path)` + `collect_ocsf_url(url)` + `OCSFIngestError` | Library | Third-party OCSF JSON ingestion. Dispatches by `class_uid`; passes `trust_unmapped=False` to both mapping functions. URL mode is HTTPS-only, no redirects, 10s timeout, 50 MB body cap. |
| 4 | `evidentia collect ocsf --input <file-or-url>` | CLI | New verb. Surfaces `OCSFIngestError` as non-zero exit + clear message. |
| 5 | `evidentia collect convert --input X --format ocsf [--output Y]` | CLI | New verb — SecurityFinding JSON → OCSF Compliance Finding bundle. Emits `EventAction.COLLECT_OCSF_EMITTED` after a successful write. |
| 6 | `evidentia_core.models.finding.Finding` (alias of `SecurityFinding`) | Library | v0.10.1 rename — both names refer to the same class. `SecurityFinding` retained ≥ 1 minor cycle per the deprecation policy. Target removal: v1.0.0. See [`deprecation-calendar.md`](deprecation-calendar.md). |
| 7 | `EventAction.COLLECT_OCSF_EMITTED` | Library | Append-only enum addition per §2 stability contract. Emitted by `collect convert --format ocsf`. |
| 8 | `[ocsf]` extra on `evidentia-collectors` | Packaging | Mirrors `evidentia-core[ocsf]` so `pip install 'evidentia-collectors[ocsf]'` Just Works. |

**Modified surfaces** (additive only):

| # | Surface | Change |
|---|---|---|
| 9 | 11 collectors (okta, sql/{mysql,mssql,sqlite,oracle}, databricks, snowflake, vanta, drata, bitsight, securityscorecard) — 67 sites | Each `SecurityFinding(...)` call now sets `compliance_status` explicitly per finding semantics — closing the v0.10.0 pilot pattern's extension to the full collector surface. No `remediation` populated (none of these collectors carry structured remediation text). 420 existing collector tests pass unchanged. |
| 10 | `scripts/bump_version.py` — `bump_pin_range(current, target, packages)` | Closes F-V100-M1. Reads `[tool.uv.sources]` as the workspace allowlist; regex now requires a workspace package name to precede the version range. 6 new tests + 1 pre-existing test file aligned. |

**Adversarial-probe taxonomy** (focused on new surfaces; unchanged
subsystems re-validated via the full 3332-test suite which retains
every prior adversarial test):

| # | Vector | OCSF ingestion (file) | OCSF ingestion (URL) | Detection Finding mapping | `Finding` alias / CLI verbs |
|---|---|---|---|---|---|
| 1 | Minimal positive | ✅ Prowler + Security Hub fixtures | ✅ HTTPS-only check | ✅ severity → compliance_status heuristic table | ✅ `Finding is SecurityFinding`; both CLI verbs end-to-end |
| 2 | Bad input | ✅ → `OCSFIngestError`; unsupported `class_uid` rejected | ✅ ftp/file/javascript schemes rejected | ✅ → `OCSFMappingError` | ✅ non-list input / bad format rejected |
| 3 | Empty input | ✅ empty list returns empty | n/a | ✅ → `OCSFMappingError` | ✅ |
| 4 | Tampered (forged unmapped) | ✅ collector passes `trust_unmapped=False`; forged block ignored | n/a | ✅ default `trust_unmapped=False`; close-out adversarial test | ✅ alias is identity-equal |
| 5 | Encoding / special chars | ✅ JSON Unicode survives | ✅ scheme check is case-insensitive | n/a | ✅ |
| 6 | Large-input DoS | bounded by Python json.loads (no explicit cap on file mode) | ✅ 50 MB body cap raises mid-stream | n/a | n/a |
| 7 | Trust-boundary (F-V100-L1 close-out) | ✅ `trust_unmapped=False` wired through dispatch | ✅ same dispatch | ✅ default `trust_unmapped=False` | n/a |
| 8 | **SSRF (NEW)** | n/a | ⚠️ **F-V101-L1 LOW** — no private-IP block; accepted operator-driven, v0.10.2 hardening optional | n/a | n/a |

**Vectors not applicable**: concurrent/race (pure transforms);
expired credential (no auth surface). **DAST skipped** per Step 4
G11 — no new REST/UI surface; the new CLI surfaces are covered
end-to-end by the integration tests under `tests/integration/test_cli/`.

**Test count + source-file trajectory**: 3332 tests pass / 14 skipped
/ 267 source files / mypy strict 267 of 267 (7 packages); ruff clean.
**+37 tests** vs the v0.10.0 baseline (3295 / 265).

**Step 4 disposition**: **PROCEED-CLEAN**. 0 CRITICAL / 0 HIGH / 0
MEDIUM / 1 NEW LOW (F-V101-L1 — SSRF surface on URL ingest;
accepted with documented v0.10.2 follow-up). Both v0.10.0 findings
(F-V100-L1 + F-V100-M1) closed inline.

---

## Re-validation snapshot — 2026-05-22 (v0.10.0 PRE-TAG)

v0.10.0 opens the v0.10.x research-driven integration line. **Three
new public surfaces** (the OCSF Compliance Finding mapping layer,
SARIF 2.1.0 emit on `evidentia gap`, additive `compliance_status` +
`remediation` fields on `SecurityFinding`); **three pilot collectors**
(AWS, GitHub, Postgres) refactored to populate the new fields; the
~11 other collectors untouched (additive-only schema evolution; full
migration deferred to v0.10.1).

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `evidentia_core.ocsf` package — `finding_to_ocsf` / `finding_from_ocsf` / `OCSFMappingError` | Library | Bidirectional Evidentia `SecurityFinding` ↔ OCSF Compliance Finding (`class_uid` 2003) mapping. Pure functions; lazy-imports `py-ocsf-models` from the new `[ocsf]` extra; lossless round-trip for Evidentia-produced findings via the OCSF-standard `unmapped["evidentia"]` block. See [`docs/ocsf-mapping.md`](ocsf-mapping.md). |
| 2 | `evidentia gap analyze --format sarif` + `evidentia_core.gap_analyzer.sarif.gap_report_to_sarif` | CLI + Library | SARIF 2.1.0 output format. Each `ControlGap` → a SARIF result; each distinct control → a rule; stable `partialFingerprints` track gaps across runs; physical + logical locations keep results from being misattributed to source code. Surfaces in GitHub code scanning + GitLab security dashboards. |
| 3 | `SecurityFinding.compliance_status` + `SecurityFinding.remediation` + `ComplianceStatus` enum | Library | Additive Optional Pydantic fields (defaults `UNKNOWN` + `None`). Mirror OCSF `compliance.status` + `remediation.desc`. `finding.py` joins the [`docs/api-stability.md`](api-stability.md) frozen-models table. |
| 4 | `[ocsf]` extra (new optional dependency on `py-ocsf-models>=0.9.0,<0.10.0`) | Packaging | Apache-2.0; Prowler-team-maintained; isolated to the mapping layer so default install stays slim and the core is insulated from OCSF schema churn. |

**Modified surfaces** (additive only — existing tests still pass):

| # | Surface | Change |
|---|---|---|
| 5 | `aws/collector.py` + `aws/access_analyzer.py` + `github/collector.py` + `github/dependabot.py` + `sql/postgres/collector.py` | Each `SecurityFinding(...)` site now sets `compliance_status` explicitly (FAIL / PASS / WARNING / UNKNOWN per finding semantics); AWS Security Hub + GitHub Dependabot also populate `remediation` from source-system text. 5 new test files cover the new fields. |

**Adversarial-probe taxonomy** (10 probes run against the 2 new surfaces; the 8 unchanged subsystems re-validated via the full 3292-test suite which retains every prior adversarial test):

| # | Vector | OCSF mapping | SARIF emit |
|---|---|---|---|
| 1 | Minimal positive round-trip | ✅ id+title preserved | covered by `test_sarif.py` |
| 2 | Bad input (malformed dict) | ✅ → typed `OCSFMappingError` | n/a |
| 3 | Empty input | ✅ → typed `OCSFMappingError` | ✅ empty results + empty rules |
| 4 | Tampered field types (deserialization) | ✅ Pydantic re-validates fail-safe | ✅ `json.dumps`-safe (no enum/datetime leak) |
| 5 | Full-field round-trip incl. OLIR relationship + justification | ✅ exact preservation via unmapped block | n/a |
| 6 | Encoding / special chars / unicode in IDs | n/a | ✅ ruleId survives JSON serialization |
| 7 | Large-input DoS bound | n/a | ✅ 500 gaps → 500 results in 0.002s |
| 8 | Missing-field safe defaults | ✅ best-effort native-OCSF path | ✅ missing `inventory_source` → `"evidentia-gap-analysis"` fallback |

**Vectors not applicable**: concurrent/race (pure functions, no global state); network failure (no I/O in either surface); expired credential (no auth surface). **DAST skipped** per Step 4 G11 — no new API or UI surface; the only CLI surface change (`--format sarif`) is covered end-to-end by `tests/integration/test_cli/test_gap_cli.py`.

**Test count + source-file trajectory**: 3292 tests pass / 17 skipped / 265 source files / mypy strict 265 of 265 (7 packages); ruff clean. **+42 tests** vs the v0.9.9 baseline (3250 / 261); +4 source files (`gap_analyzer/sarif.py`, `ocsf/__init__.py`, `ocsf/finding_mapping.py`, plus 1 incidental).

**Step 4 disposition**: **PROCEED-CLEAN**. 0 CRITICAL / 0 HIGH / 0 MEDIUM / 1 LOW carried from Step 3 (**F-V100-L1** — trust-boundary note on `unmapped["evidentia"]`; not exploitable at v0.10.0 because the ingestion collector that would expose third-party OCSF input is deferred to v0.10.1; accepted with documented design follow-up).

---

## Re-validation snapshot — 2026-05-21 (v0.9.9 SHIPPED)

v0.9.9 SHIPPED at tag `v0.9.9`. A focused supply-chain hygiene +
pre-push gate-fidelity patch — no source or test code changed.

**New public surfaces**: none. v0.9.9 changed dependency versions,
the CI workflow, and supply-chain tooling only.

**New build-time surface**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `scripts/run_osv_scan.py` + `osv-scan` CI job | Tooling / CI | Generates the CycloneDX SBOM and scans it with osv-scanner; the CI job and `docs/release-checklist.md` Step 5 invoke one shared script. Build-time only — no runtime surface. |
| 2 | `osv-scanner.toml` allowlist | Tooling | One accepted finding (pyjwt PYSEC-2025-183, disputed) with a reason + an `ignoreUntil` re-validation date. |

**Adversarial-probe taxonomy**: not re-run — v0.9.9 added no product
surface. The v0.9.8 7-vector probe set remains current. Supply-chain
posture improved: paramiko CVE-2026-44405 (LOW) closed via
`compliance-trestle` 4.0.3 → `paramiko` 5.0.0; the new
`osv-scanner --sbom` gate surfaces transitive + disputed advisories
pre-tag.

**Test count + source-file trajectory**: 3250 tests / 14 skipped /
261 source files / mypy strict 261 of 261 (7 packages). No source or
test code changed. (The v0.9.8 snapshot reported 262 — a +1
over-count; `git ls-files` confirms 261 tracked `.py` under
`packages/*/src/`, and v0.9.9 added no package source files.)

**Step 4 disposition**: no capability walk required — v0.9.9 is a
supply-chain patch with zero new product capability surface.

---

## Re-validation snapshot — 2026-05-21 (v0.9.8 SHIPPED)

v0.9.8 SHIPPED at tag `v0.9.8`. v0.9.7 deferral closure + v1.0-prep
integration wiring — reviewed across two passes (feature work +
supply-chain / type-safety delta), both PROCEED-CLEAN.

**New public surfaces**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `--rbac-tenant` global CLI flag + tenant-aware policy auto-detection | CLI | Multi-tenant RBAC enforced at the CLI. |
| 2 | FastAPI `require_role` tenant-claim-from-principal | REST | Tenant claim provenance-bound to the authenticated AuthProvider; closes F-V97-multi-tenant-claim-spoofing. |
| 3 | Per-tenant POA&M + evidence store directory roots | Library | `validate_tenant_id` slug-gated; single-tenant layout unchanged. |
| 4 | `EventAction.RBAC_TENANT_BOUNDARY_CROSSED` | Library | Audit event for cross-tenant attempts. |
| 5 | `SignedToolOutput` at the FastMCP dispatch layer | MCP | Signature in `CallToolResult._meta`; tool output untouched. |
| 6 | `evidentia_mcp.sigstore_signer` keyless signer / verifier factories | Library / MCP | In-tree Sigstore-keyless reference signer; closes F-V97-mcp-signer-trust. |
| 7 | `evidentia_core.factory_resolver` | Library | Shared dotted-path factory resolver with env-var-keyed caching. |
| 8 | `scripts/publish_hf_eval.py` + FedRAMP / CMMC eval-suite subsets | Tooling | HF Hub GRC eval suite; two-phase publish with a token-free `--dry-run`. |

**Adversarial-probe taxonomy (7 vectors, all PASSED)**:

1. **Cross-tenant claim spoofing** — the FastAPI tenant claim is
   now derived from the authenticated principal; an operator-
   asserted `@@<tenant>` no longer grants access. F-V97 closed.
2. **MCP signature tampering** — the signature is additive in
   `_meta`; a stripped / forged `_meta` fails verification and the
   tool output itself is unaffected.
3. **Sigstore signer key exposure** — the keyless Fulcio path
   removes operator key material; air-gap mode refuses the network
   path.
4. **Tenant-id path traversal** — per-tenant store roots are
   `validate_tenant_id` slug-gated; `../` and absolute paths are
   rejected.
5. **Factory-resolver injection** — `factory_resolver` inherits the
   v0.9.7 dotted-path validation; unimportable / non-callable refs
   raise structured errors.
6. **sigstore 4.2.0 API drift** — the `SigningContext.production()`
   removal was caught by the `--all-extras` mypy gate (now aligned
   across CI + the release checklist) and migrated; the signing
   path is verified.
7. **Supply-chain CVE** — idna 3.11→3.15 closes CVE-2026-45409;
   paramiko CVE-2026-44405 LOW carried forward to v0.9.9 with a
   documented fix path.

**Test count + source-file trajectory**: 3250 tests / 14 skipped /
262 source files / mypy strict 262 of 262 (7 packages).

**Step 4 disposition**: the v0.9.8 capability walk was completed in
Pass 1 (feature-work review); the Pass 2 delta added zero new
capability surface, so this snapshot consolidates Pass 1's surface
inventory with the Pass 2 supply-chain / type-safety verification.

---

## Re-validation snapshot — 2026-05-19 (v0.9.7 SHIPPED)

v0.9.7 SHIPPED at tag `v0.9.7`. Comprehensive ~3-4 week scope
compressed into a focused session per the v0.9.6 cycle-close
lock-in (all 16 items + v1.0 prep). **22nd consecutive
PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x line.

**Headline v1.0 prep**: `docs/api-stability.md` promoted from
DRAFT to NORMATIVE. The contract is now binding through the
remaining v0.9.x line. One of eight v1.0 acceptance gates per
`docs/v1.0-transition.md` is now CLOSED.

**New public surfaces (10+)**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` + `EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY` env vars | Library | Closes F-V96-worm-app-layer. Auto-mirror to cloud-WORM backend after local write. |
| 2 | `evidentia mcp cimd-migrate <registry>` CLI verb | CLI | Closes F-V96-conmon-mcp-cimd-migration. Idempotent + dry-run + atomic write. |
| 3 | `evidentia_core.rbac.multi_tenant.TenantRBACPolicy` + helpers | Library | Multi-tenant RBAC primitives (data model + decision function). CLI + REST integration deferred to v1.0. |
| 4 | `evidentia_mcp.signatures.SignedToolOutput` envelope + helpers | Library | CIMD signatures groundwork. Signer-agnostic; operator-supplied via dotted-path factory. |
| 5 | `EVIDENTIA_MCP_SIGN_OUTPUTS` + `EVIDENTIA_MCP_SIGNER_FACTORY` env vars | Library | Opt-in MCP output signing. |
| 6 | `SCRForm` RFC-0007 fields (8 Optional fields) + `to_oscal_scr_notification()` method | Library | FedRAMP RFC-0007 Significant Change Notification standard alignment. |
| 7 | `evidentia_core.oscal.OSCAL_SCHEMA_VERSION` constant | Library (v0.9.6 NEW; v0.9.7 frozen via api-stability NORMATIVE) | Single source of truth for the emit version. |
| 8 | Codecov target 80% → 85% | CI / Build | Bumped per v0.9.6 84.26% baseline. |
| 9 | `docs/api-stability.md` NORMATIVE | Documentation | v1.0-prep headline deliverable. |
| 10 | `docs/deprecation-calendar.md` | Documentation | Formal catalogue with `conmon check --last-completed-file` anchor (v1.0 removal target). |
| 11 | `docs/hf-eval-suite-scaffolding.md` + positioning §11.2.A + §11.2.B | Documentation | Q3 quarterly resync academic-positioning sharpening. |

**Adversarial-probe taxonomy (7 vectors, all PASSED)**:

1. **WORM auto-mirror env-var spoofing** — env vars without
   factory → RuntimeError at first save; malformed factory ref →
   structured error; unimportable module → RuntimeError. No path
   for unauthorized mirror.
2. **CIMD migrate path traversal** — registry file path validation
   inherits Typer's `exists=True` + atomic-write within registry's
   own directory; no path-traversal vector surfaced.
3. **Multi-tenant claim spoofing** — flagged as F-V97-multi-
   tenant-claim-spoofing INFO; v0.9.7 partial requires v1.0 CLI
   integration to enforce tenant-claim provenance from
   AuthProvider.
4. **MCP signer factory injection** — flagged as F-V97-mcp-signer-
   trust INFO; signer in operator trust boundary; Sigstore-keyless
   v1.0 reference backend eliminates the exposure.
5. **SCRForm RFC-0007 emit missing-required** — surfaces structured
   error listing every missing field BEFORE any partial emission;
   no silent data loss.
6. **CIMD migrate idempotency** — second run on already-migrated
   registry surfaces "no changes required"; no double-write.
7. **api-stability NORMATIVE contract drift** — all 256+ source
   files mypy strict clean; ruff clean; 3092 tests pass; the
   contract is verifiable.

**Test count + source-file trajectory**: 3092 tests / 17 skipped /
~240 source files / mypy strict 258 of 258.

---

## Re-validation snapshot — 2026-05-18 (v0.9.6 SHIPPED)

v0.9.6 SHIPPED at tag `v0.9.6`. Comprehensive ~3-week scope
compressed into a focused session per the v0.9.5 cycle-close
lock-in. **21st consecutive PROCEED-CLEAN** of the v0.7.x →
v0.8.x → v0.9.x line.

**New public surfaces (10)**:

| # | Surface | Layer | Notes |
|---|---|---|---|
| 1 | `evidentia.cli._rbac.require_role_cli(action)` | CLI library | Typer decorator mirroring FastAPI `require_role`. Gates by env-var-driven identity + policy file. Exit code 77 on deny. |
| 2 | `evidentia.cli._rbac_lifecycle` (singleton + override) | CLI library | Process-lifetime policy + identity. `EVIDENTIA_RBAC_POLICY_FILE` + `EVIDENTIA_RBAC_IDENTITY` env vars + `--rbac-identity` global flag. |
| 3 | `evidentia_core.evidence_store` (WORM append-only) | Library | Per-lineage directory layout; `EvidenceWORMViolation` on overwrite; canonical UUID validation. |
| 4 | `evidentia_core.evidence_store_worm.mirror_to_worm` / `fetch_from_worm` | Library | Cloud-WORM mirror composing with `WORMBackend` ABC; record-id `<lineage>_v<version>`. |
| 5 | `evidentia evidence save / history / show` | CLI | 3 new verbs; `save` write-gated, others read-gated by RBAC. JSON + human output. |
| 6 | `evidentia_core.ai_governance.fips199.FIPS199Categorization` | Library | High-water-mark validator per FIPS PUB 199 §3; auto-computes `overall` from C/I/A. |
| 7 | `evidentia_core.ai_governance.omb_m_24_10.OMBImpactCategory` | Library | OMB M-24-10 §5(b) category enum + `triggers_minimum_practices()` helper. |
| 8 | `evidentia_core.ai_governance.scr.SCRForm` + `emit_scr_form` + `classify_change` | Library | FedRAMP SCR template + auto-classifier (Routine / Adaptive / Transformative) + JSON / MD writers. |
| 9 | `evidentia ai-gov categorize-fips / set-omb-impact / update --emit-scr / update --ssp-reference` | CLI | New verbs + flags for federal-tier AI-gov ops. |
| 10 | 4 new CONMON MCP tools (`conmon_list_cadences`, `conmon_next_due`, `conmon_check_state`, `conmon_health`) | MCP | First-mover claim per v0.9.5 Q3 2026 quarterly resync. Gated by existing v0.8.6 CIMD scope enforcement. |

**Other v0.9.6 surfaces**:

- `OSCAL_SCHEMA_VERSION` single-source-of-truth constant + bump
  to `"1.2.1"` + observation type rename
  (`"finding"` → `"implementation-issue"`).
- mypy strict gate extended to all 7 evidentia-* packages: **256
  source files clean** (was 223 of 247 at v0.9.5).
- 6 new EventActions: `EVIDENCE_VERSION_PERSISTED`,
  `EVIDENCE_WORM_VIOLATION_BLOCKED`, `EVIDENCE_LINEAGE_QUERIED`,
  `AI_SYSTEM_FIPS_CATEGORIZED`, `AI_SYSTEM_OMB_CLASSIFIED`,
  `AI_SYSTEM_SCR_EMITTED`.

**Adversarial-probe taxonomy (7 vectors, all PASSED)**:

1. **WORM overwrite** — re-save same lineage+version → `EvidenceWORMViolation`; no `.tmp` left behind.
2. **Path traversal** — `lineage_id="../../etc"` → `InvalidEvidenceIdError` BEFORE path resolution.
3. **RBAC bypass** — `EVIDENTIA_RBAC_IDENTITY` unset + `default_role=deny` → exit code 77.
4. **CIMD scope bypass** — operator on v0.9.5 CIMD registry tries `conmon_*` → tool default-rejected.
5. **FIPS validator bypass** — `overall=LOW` while one objective is `HIGH` → `ValidationError` (high-water-mark mismatch).
6. **SCR auto-classify gaming** — flip `OMB_impact` from None → IMPACTING → routine (not transformative; first-time population shouldn't trigger spurious SCR).
7. **OSCAL schema drift** — pre-v0.9.6 client expecting `types: ["finding"]` → graceful fail with the rename documented in `_version.py`.

**Test count + source-file trajectory**: 3018 tests / 17 skipped /
234 source files / mypy strict 256 of 256.

---

## Re-validation snapshot — 2026-05-08 (v0.9.0 SHIPPED)

v0.9.0 SHIPPED (tag `v0.9.0` at commit TBD). **First minor of
the v0.9.x line.** Opens the federal-compliance theme reserved
at v0.8.7 cycle-close. Lands the Plan-of-Action-and-Milestones
data layer + CLI + REST + OSCAL emit + Continuous Monitoring
cycle calendar — auditor-expected surfaces in any regulated-
industry GRC tool. 15th consecutive PROCEED-CLEAN of v0.7.x →
v0.8.x → v0.9.x line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `POAMState` enum + state machine | `tests/unit/test_poam/test_state.py` (TestValidNextStates + TestIsValidTransition + TestDeriveOverdue; 21 tests) | All 5 states + forward-only transition table + terminal-state semantics + derive_overdue predicate (operator-set + date-derived semantics) |
| `Milestone` Pydantic model | `tests/unit/test_poam/test_state.py` + `test_milestone.py` (TestSortByTargetDate + TestGroupByState + TestUpcomingMilestones + TestDeriveAttentionState; ~22 tests) | UUID stamp + target_date + status + evidence_ref + created_at/updated_at; round-trip preserves all fields |
| `ControlGap.poam_milestones` field (additive optional list) | `tests/unit/test_poam/test_store.py` (TestSaveAndLoad + TestMilestoneUpdatedAtRefresh; ~10 tests) | Default-empty backward-compat with v0.7.x + v0.8.x serialized reports; milestone updated_at refreshes only on state change |
| `evidentia_core.poam.{state,milestone}` helpers | TestValidNextStates + TestDeriveOverdue + TestDeriveAttentionState | `is_valid_transition` + `derive_overdue` + cycle helpers (sort + group + upcoming + attention buckets) |
| `evidentia_core.poam_store` (JSON file-store) | `tests/unit/test_poam/test_store.py` (TestGetPoamStoreDir + TestInvalidIds + TestListPoams + TestDeletePoam; ~17 tests) | Atomic-write + UUID-shape gate + path-traversal defense + EVIDENTIA_POAM_STORE_DIR env override + canonical sort order + malformed-file skip-with-warning |
| `evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam` | `tests/unit/test_oscal/test_poam_exporter.py` (TestTopLevelShape + TestDefaultSeverityFilter + TestPoamItemStructure + TestMilestoneMapping + TestRiskAndObservation + TestBackMatterIntegrity + TestDeterminism; 20 tests) | OSCAL 1.1.2 plan-of-action-and-milestones shape; poam-item↔risk↔observation cross-references; milestones as tracking-entries; back-matter base64 + SHA-256 integrity; FedRAMP §3.1 severity filter default; deterministic back-matter digest across emits |
| `evidentia poam` CLI (7 verbs) | `tests/integration/test_cli/test_poam.py` (TestPoamCreate + TestPoamList + TestPoamShow + TestPoamUpdate + TestMilestoneAdd + TestMilestoneUpdate + TestPoamDelete + TestPoamCalendar; 28 tests) | Create from gap report + severity filter + list with filters + JSON output + show human/json + update with status-transition events + milestone add/update with state-machine enforcement + delete with prompt + calendar with --today override |
| `/api/poam/*` REST router (8 endpoints) | `tests/integration/test_api/test_poam.py` (TestCreatePoam + TestListPoams + TestGetPoam + TestReplacePoam + TestDeletePoam + TestAddMilestone + TestUpdateMilestone + TestCalendar; 22 tests) | CRUD + pagination + filter + 400/404 error normalization + milestone POST/PATCH + state-machine 400-on-invalid-transition + calendar JSON |
| `evidentia_core.conmon` cycle-calendar library | `tests/unit/test_conmon/test_calendar.py` (TestBundledCadences + TestListCadences + TestGetCadence + TestRegisterCadence + TestNextDue + TestDeriveStatus + TestConmonFrequenciesMap; 31 tests) | 7 bundled cadences + unique-slug invariant + framework filter + register-cadence runtime extension + month arithmetic (year-roll + last-day-clamp on regular + leap-year + annual edges) + 3-state attention bucketing |
| `evidentia conmon` CLI (3 verbs) | `tests/integration/test_cli/test_conmon.py` (TestConmonList + TestConmonNext + TestConmonCheck; 17 tests) | List + framework filter + JSON output; compute next-due from anchor; check verb with state-file YAML + overdue/due-soon surfacing + unknown-slug warning + YAML parse errors + clean-state message |
| `CONMON_CYCLE_DUE` + `CONMON_CYCLE_OVERDUE` EventActions | TestConmonCheck (audit-event emission verified via caplog in CliRunner) | Pure-current cycles do NOT emit (absence-of-events invariant); due-soon + overdue cycles emit with cadence_slug + framework + activity + last_completed + next_due + days_until_due |
| 6 POA&M EventActions | Multiple test paths across CLI + REST + store tests | POAM_CREATED on materialize; POAM_UPDATED on field edits; POAM_MILESTONE_REACHED on milestone→COMPLETED; POAM_OVERDUE on operator-set OVERDUE; POAM_CLOSED on status→remediated; POAM_VERIFIED on milestone→VERIFIED |
| `docs/poam-runbook.md` + `docs/conmon-runbook.md` | docs only — no runtime surface | End-to-end POA&M + CONMON operator workflows; cross-linked; cover POA&M/CONMON composition pattern via shared attention-state vocabulary |

**Inherited surface re-validation** (carry-forward from v0.8.7
— no functional changes to TPRM / model-risk / governance / cloud-
WORM / Sigstore eval / DFAH determinism + faithfulness library +
harness / PRT / MCP HTTP/SSE / CIMD scope enforcement / Cohen's
Kappa / plugin-contract scaffolding / `--faithfulness-threshold-
mode` CLI). The v0.9.0 deliverables are wholly additive — no
existing public-surface behavior changed.

**Adversarial probing (DAST per v4 G11)**:

- **POA&M state-machine backward-transition probe**: PATCH to
  `/api/poam/items/{id}/milestones/{ms_id}` with a backward
  status transition (e.g., COMPLETED → IN_PROGRESS) returns 400
  with a clear "file a NEW milestone with a fresh target_date"
  remediation hint. Tested in
  `TestUpdateMilestone::test_backward_transition_returns_400`.
- **POA&M store path-traversal probe**: `load_poam_by_id("../etc/passwd")`
  raises `InvalidPoamIdError` (subclass of `ValueError`) at the
  UUID-shape gate, BEFORE the resolved path reaches the
  filesystem. `validate_within` provides defense-in-depth.
  Tested in `TestInvalidIds`.
- **POA&M severity-filter default-bound probe**: `evidentia
  poam create --from-gap-report report.json` (without `--all`)
  on a 50-gap report with mixed severities materializes only
  CRITICAL + HIGH. Tested in
  `TestPoamCreate::test_create_from_report_materializes_critical_high_only`.
- **OSCAL back-matter integrity probe**: same gap → same
  back-matter SHA-256 across emits (top-level UUIDs differ but
  the integrity-bound record hash is stable). Tested in
  `TestDeterminism::test_repeated_emit_produces_same_back_matter_digest`.
- **CONMON YAML state-file parse-error probe**: `--last-
  completed-file` with malformed dates → exit 1 with ISO-8601
  format hint; YAML root not a dict → exit 1 with "must be a
  YAML mapping" hint; unknown cadence slugs → warning (not
  error) so operators can keep deprecated entries during
  transitions. Tested in `TestConmonCheck::test_invalid_yaml_errors`
  + `test_yaml_root_not_dict_errors` + `test_unknown_slug_warned_not_errored`.
- **CONMON calendar-arithmetic leap-year probe**:
  `next_due("nist-800-53-rev5-ca7", date(2024, 1, 31))` returns
  `date(2024, 2, 29)` (leap year correct); same anchor in
  non-leap years clamps to Feb 28. Tested in
  `TestNextDue::test_last_day_clamp_leap_year`.

**Quality gates at ship** (estimated; final numbers locked at
the /pre-release-review run):

- pytest: ~2575 passing / 17 skipped (was 2386 at v0.8.7;
  +189 new across Phase 1 + Phase 2 + Phase 3)
- mypy strict: 0 errors across ~227 source files (was 217 at
  v0.8.7; +10 new modules: poam package + poam_store + conmon
  package + cli/poam + cli/conmon + routers/poam +
  oscal/poam_exporter)
- ruff: clean
- standing-rule sweep: clean across all v0.9.0-cycle commits

**Pre-release-review v4 Pre-tag deliverables** (target):

- `docs/security-review-v0.9.0.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Pre-tag full variant for the
  minor-bump scope; CVSS/CWE/EPSS bug-bucket; 16-row pre-push
  gate; compliance framework mapping; 15th consecutive
  PROCEED-CLEAN target
- `docs/v0.9.0-plan.md` — public-safe re-statement of §31 scope
- `docs/threat-model.md` v0.9.0 attack-surface delta —
  POA&M data layer + CLI + REST + OSCAL emit + CONMON cycle
  calendar coverage
- `docs/poam-runbook.md` + `docs/conmon-runbook.md` — operator
  guides
- `docs/capability-matrix.md` v0.9.0 snapshot (this section)

**Step 7 post-tag verification expected ALL PASS** (run
post-tag-publish):

- G1 PEP 740 verify all 7 wheels OK
- G2 cosign verify SLSA Provenance v1
- G3 osv-scanner --sbom clean
- G4 docker run "Evidentia v0.9.0"
- G5 fresh-venv install — **15th consecutive pin-trap fix
  validation** (target)
- G7 Scorecard delta no regression (G4 Path 2 7th consecutive
  activation; pip-tools pin durable)
- G16 release-body substantiveness — **14th consecutive
  auto-populate-from-CHANGELOG** (target)

**Phase 4 walk-through status** (operator-driven): if the
domain-expert walk-through ran before ship, federal-SI scenario
rows materialize as additional surface entries in this snapshot
table + Cohen's Kappa recomputes on the v0.8.5 corpus per the
v0.8.6 §29 P2 R3 mitigation acceptance. If deferred, v0.9.0
ships with the v0.8.6 "single-rater κ probe inconclusive"
carry-forward acknowledged; walk-through becomes a v0.9.1
reservation.

---

## Re-validation snapshot — 2026-05-08 (v0.8.7 SHIPPED)

v0.8.7 SHIPPED (tag `v0.8.7` at commit TBD). **FINAL v0.8.x
patch** — wrap-up cycle. Single focused session per Allen's
explicit cycle-open lock-in (§30: Single v0.8.7 wrap-up
release + LLM-rater deferred to v0.9.0 + CIMD signatures
deferred to v1.0). 14th consecutive PROCEED-CLEAN of v0.7.x →
v0.8.x line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `--faithfulness-threshold-mode {framework-aware,fixed}` CLI flag | `tests/unit/test_eval/test_harness.py::TestFaithfulnessThresholdMode` (3 tests) | Invalid mode → exit 2; fixed mode → 0.30 framework-agnostic verified via stdout; framework-aware mode + DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD lookup verified via direct `resolve_threshold` invocation |
| `--faithfulness-threshold` default sentinel | TestFaithfulnessThresholdMode (3 tests) | Default changed from `0.3` → `None`; explicit `--faithfulness-threshold N` always wins over `--faithfulness-threshold-mode` |
| Stdout summary: `faithfulness threshold: X.XX (<source>)` | TestFaithfulnessThresholdMode (verified via stdout assertion) | Source string per resolution path: `explicit` / `framework-aware (framework=...)` / `fixed (framework-agnostic default)` |
| v0.8.6 cycle-close artifacts (Phase 1) | docs only — no runtime surface | 6 docs-only deliverables backfilled per §30 P1 |

**Inherited surface re-validation** (carry-forward from
v0.8.6 — no functional changes; v0.8.7 closes v0.8.6 P3 CLI
deferral + adds wrap-up artifacts without modifying TPRM /
model-risk / governance / cloud-WORM / Sigstore eval / DFAH
determinism / DFAH faithfulness library + harness / PRT /
MCP HTTP/SSE / CIMD scope enforcement / Cohen's Kappa /
plugin-contract scaffolding surfaces).

**Adversarial probing (DAST per v4 G11)**:

- `--faithfulness-threshold-mode` allowlist enforcement
  rejects unexpected values at Typer parse time (tested via
  `test_invalid_mode_exits_2`).
- Default sentinel change (`0.3 → None`) preserves backward
  compat: callers who explicitly pass `--faithfulness-
  threshold 0.3` see identical behavior (tested via
  `test_fixed_mode_uses_0_30` — when in fixed mode, the
  fallback IS 0.30).
- Framework extraction from `prompt_id` is robust to
  unrecognized formats — falls back to framework-agnostic
  threshold without disrupting the LLM call.

**Quality gates at ship**: 2386 tests passing / 17 skipped
(was 2383 / 17 at v0.8.6 close; +3 new from
TestFaithfulnessThresholdMode). mypy strict 0/0 across 217
source files (unchanged). ruff clean. Standing-rule sweep
clean across the v0.8.7-cycle commits.

**Pre-release-review v4 Pre-tag deliverables**:

- `docs/security-review-v0.8.7.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Continuous variant; 0 unfixed
  CRITICAL/HIGH/MEDIUM/LOW findings; 14th consecutive
  PROCEED-CLEAN.
- `docs/v0.8.7-plan.md` — public-safe re-statement of §30
  scope.
- `docs/threat-model.md` v0.8.7 attack-surface delta — covers
  the CLI flag (P2) + the docs-only Phase 1 backfill.

**Step 7 post-tag verification expected ALL PASS** (run
post-tag-publish):

- G1 PEP 740 verify all 7 wheels OK
- G2 cosign verify SLSA Provenance v1
- G3 osv-scanner --sbom clean
- G4 docker run "Evidentia v0.8.7"
- G5 fresh-venv install — **14th consecutive pin-trap fix
  validation**
- G7 Scorecard delta no regression (G4 Path 2 stable)
- G16 release-body substantiveness — **13th consecutive
  auto-populate-from-CHANGELOG**

---

## Re-validation snapshot — 2026-05-07 (v0.8.6 SHIPPED)

v0.8.6 SHIPPED (tag `v0.8.6` at commit `eb0f331`; container
digest `sha256:583d3849b5997edd2557530c48a32f085fa22ebbc2441bbeb2e7fcf7db8799a5`).
Aggressive ~2-3 week comprehensive scope; single-session
compression. 13th consecutive PROCEED-CLEAN of v0.7.x →
v0.8.x line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia mcp serve --default-client-id <slug>` | `tests/unit/test_mcp/test_server.py` (TestCIMDCLIFlag carry-forward) + integration via test_scope.py | CLI flag plumbing through stdio + SSE + HTTP transports; validation warnings (no --cimd-registry → ignore; --cimd-registry without --default-client-id on stdio → every call denies) |
| `evidentia_mcp.scope.enforce_cimd_scope` | `tests/unit/test_mcp/test_scope.py` (8 tests across 7 classes) | Pass-through when registry None; deny-no-client_id; deny-unregistered; deny-out-of-scope; allow-in-scope (2 incl default_client_id fallback); idempotency double-wire raises; per-call UUID4 run_id distinct |
| `EventAction.AI_MCP_TOOL_AUTHORIZED` ACTIVATED | per-call event verified via caplog ecs_record assertion | Fires on registered+in-scope; carries run_id + client_id + tool_name + scope_allowlist |
| `EventAction.AI_MCP_TOOL_DENIED` ACTIVATED | per-call event verified via caplog ecs_record assertion | Fires on ambiguous-caller + unregistered + out-of-scope; raises McpError -32602 to MCP client |
| `scripts/compute_inter_rater_kappa.py` | `tests/unit/test_scripts/test_compute_inter_rater_kappa.py` (25 tests) | Cohen's Kappa formula edge cases (perfect agreement / disagreement / random / 90% / all-positive / mismatched-length / empty); Landis-Koch boundary table (12 parametrized); rule-based jaccard rater (verbatim / hallucination / empty / paraphrase-weakness) |
| `FaithfulnessResult.confidence` field | `tests/unit/test_eval/test_faithfulness.py::TestConfidence` (4 tests) | Default None (cost-aware off); high confidence on consistent verbatim match (seed=42); zero on empty clauses; zero on empty claim |
| `FaithfulnessResult.framework` field | `TestFrameworkField` (2 tests) | Default None; persisted when set |
| `resolve_threshold(framework, method)` helper | `TestResolveThreshold` (4 tests) | Known framework returns mapped threshold (NIST 0.60 / FFIEC 0.35 / ISO27001 0.30); unknown framework falls back; None framework returns default; non-jaccard method returns default |
| `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD` map | exercised via TestResolveThreshold | Empirical per-framework thresholds from v0.8.5 P2 sweep |
| `inter-rater-agreement.md` doc + κ probe results | data file + companion doc | Best κ = 0.4848 (moderate) at threshold 0.85; ships as "single-rater + κ probe inconclusive" per §29 R3 |
| `examples/mcp/cimd-registry-readonly.json` + `cimd-registry-power.json` | operator-facing examples | Two registries with different scope allowlist patterns |
| `docs/v0.7.x-retrospective.md` (NEW) | docs-only narrative | 18-release narrative; per-release highlights; carries-into-v0.8.x section |
| `docs/v1.0-transition.md` DRAFT (NEW) | docs-only narrative | v1.0 theme candidates; what v1.0 will NOT do; deprecation cycle policy; acceptance gates |

**Inherited surface re-validation** (carry-forward from
v0.8.5 — no functional changes; v0.8.6 closes v0.8.5
deferrals + adds new surfaces without modifying TPRM /
model-risk / governance / cloud-WORM / Sigstore eval / DFAH
determinism / DFAH faithfulness library + harness / PRT /
MCP HTTP/SSE / plugin-contract scaffolding / DFAH CLI flags
surfaces).

**Adversarial probing (DAST per v4 G11)**:

- CIMD scope-enforcement gate exercised end-to-end via 8
  unit tests covering all 5 decision paths (pass-through,
  deny-ambiguous, deny-unregistered, deny-out-of-scope,
  allow-in-scope) + idempotency guard + per-call run_id
  uniqueness.
- McpError code -32602 (Invalid Params) verification: deny
  paths raise the expected MCP-protocol error; MCP clients
  see structured errors not server crashes.
- Default `evidentia_cimd is None` behavior verified
  preserved (v0.8.5 callers who don't configure CIMD see
  zero behavior change).
- Rule-based jaccard rater determinism: same corpus + same
  threshold produce same κ across runs (used in CI gate).
- Bootstrap confidence determinism: same claim + clauses +
  seed produce same confidence value (used in TestConfidence
  for verbatim match assertion).

**Quality gates at ship**: 2383 tests passing / 17 skipped
(was 2338 / 17 at v0.8.5 close; +45 new this cycle: 8 scope
+ 25 kappa + 10 confidence/framework + 2 docs-only). mypy
strict 0/0 across 217 source files (was 216; +1 new
`evidentia_mcp/scope.py`). ruff clean. Standing-rule sweep
clean across all v0.8.6-cycle commits.

**Pre-release-review v4 Pre-tag deliverables** (backfilled
2026-05-08 per §30 P1):

- `docs/security-review-v0.8.6.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Continuous variant; 0 unfixed
  CRITICAL/HIGH/MEDIUM/LOW findings; 13th consecutive
  PROCEED-CLEAN of v0.7.x → v0.8.x line.
- `docs/v0.8.6-plan.md` — public-safe re-statement of §29
  scope.
- `docs/threat-model.md` v0.8.6 attack-surface delta.

**Step 7 post-tag verification ALL PASS** (executed at
ship-time 2026-05-07):

- G1 PEP 740 verify all 7 wheels OK
- G2 cosign verify SLSA Provenance v1 at digest
  `sha256:583d3849...8799a5`
- G3 osv-scanner --sbom: 169 packages / 0 issues
- G4 docker run "Evidentia v0.8.6"
- G5 fresh-venv install — **13th consecutive pin-trap fix
  validation**
- G7 Scorecard delta: 0 open code-scanning alerts
- G16 release-body 6837 bytes — **12th consecutive auto-
  populate-from-CHANGELOG**

---

## Re-validation snapshot — 2026-05-06 (v0.8.5 SHIPPED)

v0.8.5 SHIPPED (tag `v0.8.5` at commit TBD post-tag).
Aggressive ~2-3 week comprehensive scope (single-session
compression matching v0.8.3 + v0.8.4 cadence). Closes ALL
4 v0.8.4 carry-overs in one focused session per Allen's
explicit Comprehensive scope + Implement-CIMD-now lock-in
(§28). 12th consecutive PROCEED-CLEAN of v0.7.x → v0.8.x
line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia eval risk-determinism --check-faithfulness` | `tests/unit/test_eval/test_harness.py::TestRiskDeterminismFaithfulnessCLI` (5 tests) | Pre-condition validation (no source-clauses-file → exit 2; invalid method → exit 2; malformed YAML → exit 2; non-list[str] entry → exit 2); happy path with mocked claim_extraction + faithfulness_score → harness wiring + stdout summary + JSON dump faithfulness_results array |
| `--faithfulness-threshold N` CLI flag | same module | Threshold passed through to harness; default 0.3; appears in stdout summary |
| `--faithfulness-method {jaccard,semantic}` CLI flag | same module | Allowlist validation (jaccard / semantic only); jaccard default; method label appears in stdout summary |
| `--source-clauses-file <yaml>` CLI flag | same module | YAML map prompt_id → list[str]; pre-condition required when --check-faithfulness; loaded into source_clauses_by_prompt + attached to EvalSample.source_clauses |
| DFAH calibration corpus expansion | data files exercised by `tune_faithfulness_threshold.py --corpus-pattern` | corpus_nist.jsonl + corpus_ffiec.jsonl + corpus_iso27001.jsonl loaded; per-framework Youden's J reported |
| `tune_faithfulness_threshold.py --corpus-pattern <glob>` | self-tested via cycle commit | Per-framework sweep reports per-file recommended threshold |
| Real-LLM integration tests | `tests/integration/test_eval/test_real_llm_extraction.py` (4 tests; 3 LLM-gated + 1 ungated) | extract_claims() ≥ 2 claims for 3-claim input; DFAHarness end-to-end; score-distribution trend (faithful > unfaithful); empty-input short-circuit |
| `evidentia_mcp.cimd.CIMDDocument` Pydantic model | `tests/unit/test_mcp/test_cimd.py::TestCIMDDocumentModel` (6 tests) | Minimum valid doc; full doc round-trip; has_scope deny-all on empty scope; has_scope allowlist semantics; max-length client_id rejection; empty client_id rejection |
| `evidentia_mcp.cimd.CIMDRegistry.from_file()` | `TestCIMDRegistryFromFile` (7 tests) | Two-client load; empty clients; malformed JSON → ValueError; top-level list → ValueError; unsupported version → ValueError; per-CIMDDocument validation failure → ValueError; missing file → FileNotFoundError |
| `CIMDRegistry.get(client_id)` | `TestCIMDRegistryLookup` (2 tests) | Registered get returns CIMDDocument; unregistered returns None |
| `build_server(cimd_registry=)` + `server.evidentia_cimd` | `TestCIMDInBuildServer` (2 tests) | Without CIMD attaches None; with CIMD attaches the registry; tool implementations can read it |
| `evidentia mcp serve --cimd-registry <path>` CLI flag | `TestCIMDCLIFlag` (2 tests) | Flag advertised in Click introspection; invalid path → exit 2 (Typer's exists=True parse-time gate) |

**Inherited surface re-validation** (carry-forward from v0.8.4
— no functional changes; v0.8.5 closes v0.8.4 carry-overs +
adds CIMD without modifying TPRM / model-risk / governance /
cloud-WORM / Sigstore eval / DFAH determinism / DFAH
faithfulness library + harness / PRT / MCP HTTP/SSE /
plugin-contract scaffolding surfaces).

**Adversarial probing (DAST per v4 G11)**:

- Pre-condition validation on the 4 new CLI flags exercised
  end-to-end via 5 CLI tests; malformed inputs reject BEFORE
  any LLM call fires (cost-aware design).
- CIMD registry version check rejects unsupported versions
  at load time; Pydantic validation rejects malformed
  CIMDDocument entries with operator-friendly error messages.
- `CIMDDocument.has_scope` deny-by-default semantics
  validated — empty scope = deny-all; only tools listed in
  the space-separated scope are allowlisted.
- Real-LLM integration tests use STRUCTURAL assertions
  (claim count, per-claim token count, score distribution
  trend) — not exact-match strings; resilient to
  model-version drift.

**Quality gates at ship**: 2338 tests passing / 17 skipped
(was 2313 / 14 at v0.8.4 close; +25 new this cycle: 5 CLI
faithfulness + 4 real-LLM integration + 19 CIMD; -3 LLM-
gated counted as skipped without env var). mypy strict 0/0
across 216 source files (was 215; +1 new
`evidentia_mcp/cimd.py`). ruff clean. Standing-rule sweep
clean across all v0.8.5-cycle commits (4 commits).

**Pre-release-review v4 Pre-tag deliverables**:

- `docs/security-review-v0.8.5.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Continuous variant; 0 unfixed
  CRITICAL/HIGH/MEDIUM/LOW findings; 12th consecutive
  PROCEED-CLEAN of v0.7.x → v0.8.x line.
- `docs/threat-model.md` extended with v0.8.5 attack-surface
  delta covering all 4 phases (DFAH CLI flags + corpus
  expansion + real-LLM integration tests + MCP CIMD richness)
  + threat-model for CIMD ("CIMD is NOT authentication" —
  prominently documented).

**Step 7 post-tag verification expected ALL PASS** (run
post-tag-publish):

- G1 PEP 740 verify all 7 wheels OK
- G2 cosign verify SLSA Provenance v1
- G3 osv-scanner --sbom clean
- G4 docker run "Evidentia v0.8.5" + 89 frameworks
- G5 fresh-venv install — **12th consecutive pin-trap fix
  validation**
- G7 Scorecard delta no regression (G4 Path 2 stable)
- G16 release-body substantiveness — **11th consecutive auto-
  populate-from-CHANGELOG**

---

## Re-validation snapshot — 2026-05-06 (v0.8.4 SHIPPED)

v0.8.4 SHIPPED (tag `v0.8.4` at commit `5d366af`; container
digest `sha256:59f8305874177c09dbd3ab36e458b87b4454c0ae2d7ac016eeb49d66009ccb9d`).
Aggressive ~2-3 week focused scope (single-session compression
matching v0.8.3 cadence). Closes the v0.8.3 ship-failure root
cause (G4 Path 1 cross-platform reproducibility limitation) via
**Path 2** (post-PyPI regeneration in `release.yml` — sidesteps
cross-platform reproducibility entirely) + the v0.8.3 P1.2
deferred wiring (DFAHarness `check_faithfulness=True`
first-class on the harness loop). 11th consecutive
PROCEED-CLEAN of v0.7.x → v0.8.x line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `EvalSample.source_clauses: list[str] \| None = None` | `tests/unit/test_eval/test_harness_faithfulness.py` (test_eval_sample_source_clauses_optional + test_eval_sample_with_source_clauses) | Schema gains optional field; backward-compatible default None |
| `EvalResult.faithfulness_results: list[PromptFaithfulnessResult]` | `tests/unit/test_eval/test_harness_faithfulness.py` (TestPromptFaithfulnessResultModel × 4) | Default empty list; populated only when harness ran with check_faithfulness=True; JSON-serializable; computed properties (overall_faithful / passed_count / failed_count) |
| `DFAHarness.run(check_faithfulness=, faithfulness_threshold=, faithfulness_method=, claim_extraction_fn=, faithfulness_score_fn=)` | `tests/unit/test_eval/test_harness_faithfulness.py` (TestCheckFaithfulnessKwargDefault + TestCheckFaithfulnessJaccardPath + TestCheckFaithfulnessSemanticPath × 14 tests) | Default check_faithfulness=False (no-op path); samples without source_clauses skipped; jaccard method (default); semantic method opt-in; mock-callable injection points keep tests cost-zero |
| `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` ACTIVATED | `tests/unit/test_eval/test_harness_faithfulness.py` (TestAuditEventFiring; test_check_faithfulness_fires_checked_event_per_prompt) | Reserved-but-inactive in v0.8.0; ACTIVATED in v0.8.4; per-prompt event with run_id + prompt_id + claim_count + passed_count + failed_count |
| `EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` ACTIVATED | `tests/unit/test_eval/test_harness_faithfulness.py` (TestAuditEventFiring; test_check_faithfulness_fires_violation_per_below_threshold_claim) | Reserved-but-inactive in v0.8.0; ACTIVATED in v0.8.4; per-claim below-threshold event with run_id + prompt_id + claim + score + threshold + method |
| `release.yml` G4 Path 2 regen step | First-fire end-to-end validated on v0.8.4 tag-push (release.yml run completed PASS) + ahead-of-tag validated on `5d366af` push (container-build smoke test parallel run completed PASS) | New step "Regenerate hash-pinned requirements.txt against PyPI" runs BETWEEN Wait-for-PyPI + docker build; pip-compile against just-published PyPI wheels; 3-attempt retry loop; ephemeral docker/requirements.txt overwrite |
| `Dockerfile` `--require-hashes` install | First-fire validated on v0.8.4 tag-push (release.yml publish-container completed PASS at digest sha256:59f8305...) | Install line uses `pip install --no-cache-dir --user --require-hashes -r /tmp/requirements.txt`; defense-in-depth (hash verification at pip-compile time + at install time) |

**Inherited surface re-validation** (carry-forward from v0.8.3
— no functional changes to inherited surfaces; v0.8.4 closes
v0.8.3 deferrals + activates events without changing user-
facing contracts on TPRM / model-risk / governance / cloud-WORM
/ Sigstore eval / DFAH determinism / DFAH faithfulness / PRT /
MCP / plugin-contract scaffolding).

**Adversarial probing (DAST per v4 G11)**:

- G4 Path 2 first-fire on production tag: release.yml's new
  regeneration step PASSED end-to-end with no retry needed;
  PyPI propagation < 30s; container build's
  `pip install --require-hashes` succeeded against the
  ephemerally-regenerated docker/requirements.txt.
- DFAHarness `check_faithfulness=True` end-to-end: mock-
  callable injection points exercise the full harness loop
  including audit-event firing + result aggregation; default
  jaccard scorer + reserved semantic path both validated.
- Modal-output extraction: claim extraction runs on the
  post-determinism modal output (matches v0.8.0 P0.1 review
  fix F7 canonical replay logic); per-sample test confirms
  claims come from the canonical replay, not arbitrary
  per-sample variants.
- Smoke-test cycle validation: container-build.yml smoke test
  on `main` push exercises the same Path 2 regeneration code
  path that release.yml's publish-container job runs on tag
  — high confidence that future releases inherit a working
  baseline.

**Quality gates at ship**: 2313 tests passing / 14 skipped
(was 2299 / 14 at v0.8.3.1 close; +14 new from P1 DFAHarness
wiring tests). mypy strict 0/0 across 215 source files (was
216; -1 because evidentia-mcp/src/evidentia_mcp/cli.py has no
public surface change requiring strict re-check while the rest
of the codebase contracted slightly via the `Any` typing fix).
ruff clean. Standing-rule sweep clean across all v0.8.4-cycle
commits (6 commits: G4 Path 2 + DFAHarness wiring + version
bump + 3 ship-cycle hardening commits).

**Pre-release-review v4 Pre-tag deliverables**:

- `docs/security-review-v0.8.4.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Continuous variant; 0 unfixed
  CRITICAL/HIGH/MEDIUM/LOW findings; 11th consecutive
  PROCEED-CLEAN of v0.7.x → v0.8.x line.
- `docs/threat-model.md` extended with v0.8.4 attack-surface
  delta covering G4 Path 2 release-pipeline change +
  DFAHarness wiring + AI_EVAL_FAITHFULNESS_CHECKED +
  AI_EVAL_FAITHFULNESS_VIOLATION ACTIVATED + v0.8.3.1 hot-fix
  historical context + MCP CIMD 5th cycle-deferral note.

**Step 7 post-tag verification ALL PASS**:

- G1 PEP 740 verify all 7 wheels OK
  (`pypi-attestations verify pypi --repository
  https://github.com/polycentric-labs/evidentia ...`)
- G2 cosign verify SLSA Provenance v1 (matching cert + Rekor
  inclusion proof) at digest
  `sha256:59f8305874177c09dbd3ab36e458b87b4454c0ae2d7ac016eeb49d66009ccb9d`
- G3 osv-scanner --sbom: 169 packages / 0 issues
- G4 docker run "Evidentia v0.8.4" / Python 3.14.4 + 89
  frameworks via `catalog list`
- G5 fresh-venv install: 5 packages all at 0.8.4 first-attempt
  — **11th consecutive pin-trap fix validation**
- G7 Scorecard delta: 0 open code-scanning alerts at close
  (CodeQL #119 + #120 dismissed per recurring-FP runbook for
  the new pip-tools install step — same FP cycle as Dockerfile
  alerts dismissed v0.7.12 → v0.8.3.1)
- G16 release-body 5484 bytes — **10th consecutive
  auto-populate-from-CHANGELOG**

**Ship-cycle 3-stage hardening** (post-tag follow-throughs on
the new G4 Path 2 surface):

1. Container-build smoke test broke on the v0.8.4 push because
   the smoke test grepped Dockerfile for the old
   `evidentia[gui]==X.Y.Z` pattern. Fixed by `27fc974` (smoke
   test reads pin from `docker/requirements.txt` + adds same
   Path 2 regeneration step before docker build).
2. YAML mapping-key parse error in commit `27fc974`'s step
   name (unquoted colon at column 42 → 0 jobs scheduled).
   Fixed by `5d366af` (em-dash separator). This is the v0.8.4
   tag commit.
3. Two new CodeQL PinnedDependenciesID alerts (#117 + #118 →
   re-numbered #119 + #120 after pip-tools pin re-fired the
   alert) on the new pip-tools install step. Fixed by `8cf372e`
   (pin pip-tools==7.5.3) + dismissed alerts per the
   recurring-FP runbook.

The 3-stage hardening cycle is the cost of activating a new
release-pipeline step. Future v0.8.x cycles inherit a working
baseline.

---

## Re-validation snapshot — 2026-05-06 (v0.8.1 pre-tag)

v0.8.1 (in progress on `main`; not yet tagged) closes the v0.8.0
review backlog + ships LLM-driven richness for the AI surfaces +
adds network-transport options for MCP + closes the v0.8.0
``/api/metrics`` auth gate via FastAPI AuthProvider middleware.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia eval risk-determinism --context X --gaps Y` (P2.1) | `tests/unit/test_eval/test_harness.py` (TestRiskDeterminismCLI; 2 tests) | Determinism check against mocked RiskStatementGenerator; --gap-id missing-id error path |
| PRT LLM-driven (P2.2) | `tests/unit/test_ai/test_risk_statements.py` (test_generate_with_emit_trace_uses_llm_trace_when_present) | Generator preserves LLM-derived trace over v0.8.0 stub; trace_kind audit-log field |
| `evidentia mcp serve --transport sse\|http` (P3.1) | `tests/unit/test_mcp/test_server.py` (test_serve_help_shows_transport_choices + _host_port; 2 tests) | --transport flag documented + offers stdio/sse/http; --host + --port documented |
| FastAPI AuthProvider middleware (P3.3) | `tests/unit/test_api/test_auth_middleware.py` (TestAuthMiddleware; 6 tests) | No-provider backward compat; /api/metrics gating (no header / wrong token / right token); /api/health bypass; /api/version bypass; /api/openapi.json bypass; static SPA bypass |

**Inherited surface re-validation** (carry-forward from v0.8.0
— no functional changes; v0.8.1 review-deferral closures
strengthen existing surfaces without changing user-facing
contracts).

**Adversarial probing (DAST per v4 G11)**:

- `/api/metrics` auth gating: validated end-to-end via
  TestClient — 401 on missing/wrong token; 200 on valid
  bearer. WWW-Authenticate header per RFC 7235 §4.1.
- MCP HTTP/SSE transport file-path tool inputs: F-V81-S1
  bucketed to v0.8.2 (acceptable for v0.8.1 ship per documented
  trust model — bind defaults to 127.0.0.1; non-loopback
  bindings warn at startup).
- `evidentia eval risk-determinism` LLM credentials: never
  in CLI args; read from env vars by RiskStatementGenerator's
  existing LiteLLM-handshake.

**Quality gates at pre-tag**: 2240 tests passing / 13 skipped
(was 2240 / 13 at v0.8.0 close — same total because v0.8.1
adds 12 new tests but the symlink test skips on Windows + 1
existing test was generalized to opt-in to INFO logging).
mypy strict 0/0 across 211 source files (was 210; +1 new
auth_middleware module). ruff clean. Standing-rule sweep
clean across all v0.8.1-cycle commits.

**Pre-release-review v4 Pre-tag deliverables**:

- `docs/security-review-v0.8.1.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — Continuous variant for the
  review-deferral-cycle shape; 12 v0.8.0 findings closed; 2
  new v0.8.1 findings bucketed to v0.8.2; 0 CRITICAL/HIGH
  unfixed.
- `docs/threat-model.md` extended with v0.8.1 attack-surface
  delta covering Surfaces 5-7 (MCP HTTP/SSE, FastAPI
  AuthProvider, DFAH risk-determinism CLI) + PRT LLM-driven
  notes + v0.8.0 mitigation reinforcements.

---

## Re-validation snapshot — 2026-05-05 (v0.8.0 pre-tag)

v0.8.0 (in progress on `main`; not yet tagged) ships **the
OSS-native AI moat** — four AI-quality features that
distinguish a Vanta-class dashboard from a compliance-
engineering tool, plus the plugin-contract scaffolding that
makes a community catalog ecosystem possible.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia eval stub-smoke` (DFAH P0.1) | `tests/unit/test_eval/test_harness.py` (5 classes / 23 tests) | Determinism scoring, replay equivalence, hash normalization, harness end-to-end with deterministic + non-deterministic stubs, EvalResult JSON round-trip, CliRunner doctor |
| `evidentia risk generate --emit-trace` (PRT P0.2) | `tests/unit/test_prt/test_models.py` (3 classes / 14 tests) + `tests/unit/test_ai/test_risk_statements.py` (2 emit_trace tests) | TraceClaim / ReasoningTrace models, Pydantic round-trip, pre-v0.8.0 backward-compat parsing, OSCAL emit with traces, back-matter resource shape, evidence-digest SHA-256 binding, trestle pydantic.v1 round-trip preservation |
| `evidentia mcp serve / doctor` (P0.3) | `tests/unit/test_mcp/test_server.py` (3 classes / 15 tests) | FastMCP server build, tool registration, list_frameworks/get_control/gap_analyze/gap_diff behavior + error paths (missing files, malformed reports, unknown controls), CliRunner doctor + serve usage |
| Plugin contracts (P0.4) | `tests/unit/test_plugins/test_contracts.py` (5 classes / 38 tests) | ABC abstractness, LocalTokenAuthProvider auth flows + edge cases, FilesystemStorageBackend roundtrips + path validation, LocalDirectoryMarketplaceProvider catalog discovery + manifest fallback, BaseSaaSCollector contract, discover_plugins entry-point discovery |
| `GET /api/metrics` (P1 G3) | `tests/unit/test_prometheus_metrics/test_prometheus.py` (2 classes / 10 tests) | Render output shape (HELP/TYPE annotations + escaped labels + trailing newline), counter increment, EventOutcome failure-counter handling, FastAPI TestClient endpoint roundtrip, audit-event tap into in-process counter dict |
| M-4 collector refactor | `tests/unit/test_collectors/test_{vanta,drata,bitsight,securityscorecard}_collector.py` (92 tests; carry-forward) | Multi-inheritance preserves `pytest.raises(VantaAuthError)` semantics; `_auth_header()` overrides for HTTP Basic + custom Token prefix work end-to-end; ~60% scaffolding LOC reduction without behavior regressions |

**Inherited surface re-validation** (carry-forward from
v0.7.16 — no functional changes in v0.8.0):

| Surface | Status |
|---|---|
| Gap analysis + 89 bundled catalogs | Carry-forward; all v0.7.x tests pass |
| Risk statements (NIST SP 800-30) | Carry-forward; +reasoning_trace optional field (backward-compat) |
| OSCAL Assessment Results emit | Carry-forward; +risk_statements_with_traces kwarg (additive) |
| Evidence collectors (AWS/GitHub/Jira/Okta/SQL/Cloud-DW/BI) | Carry-forward |
| TPRM module (vendor inventory + DD questionnaire + concentration report) | Carry-forward |
| Model Risk Management overlay (SR 11-7 / SR 26-02) | Carry-forward |
| Governance primitives (Three Lines of Defense + Effective Challenge + KRI/KPI/KGI + Open FAIR) | Carry-forward |
| Audit chain-of-custody + WORM backends (S3 + Azure + GCS) | Carry-forward |
| GDPR Article 17 purge flow | Carry-forward |
| Sigstore-signed AR + cosign-signed container + SLSA L3 provenance | Carry-forward (release.yml unchanged) |

**Adversarial probing (DAST per v4 G11)**:

- `/api/metrics` endpoint Prometheus-injection: validated
  via test_prometheus.py `test_label_escaping_preserves_special_chars`
  — backslash + double-quote + newline correctly escaped.
- MCP `gap_analyze` / `gap_diff` path-traversal: documented
  as out-of-scope for v0.8.0 stdio-only trust model in
  `SERVER_INSTRUCTIONS` per F-V08-S1; v0.8.1 HTTP/SSE
  transports require `validate_within` gating.
- Plugin entry-point discovery: opt-in (operators must
  explicitly invoke `discover_plugins()`); no auto-load on
  package import.

**Quality gates at pre-tag**: 2227 tests passing / 12
skipped (was 2120 at v0.7.16; +107). mypy strict 0/0 across
210 source files (was 188; +22). ruff clean. Standing-rule
sweep clean across all 8 v0.8.0-cycle commits. Single-author
attribution.

**Pre-release-review v4 Pre-tag deliverables**:

- `docs/security-review-v0.8.0.md` (5th canonical Pre-tag
  deliverable per v4 §G7) — 17 findings; 5 inline-fixed
  during Step 5.A; 12 bucketed to v0.8.1 with rationale; 0
  CRITICAL/HIGH unfixed.
- `docs/threat-model.md` extended with v0.8.0 attack-surface
  delta covering all 4 new public surfaces + PRT model +
  inherited mitigations.

---

## Re-validation snapshot — 2026-05-04 (v0.7.12 in-progress — pre-pre-tag)

v0.7.12 (in progress on `main`; not yet tagged) ships the **3
concrete cloud-WORM backends** (S3 Object Lock + Azure Immutable
Blob + GCS Bucket Lock), **GDPR Article 17 `purge_immediately`
flow** (closes the v0.7.11 functional gap surfaced by Step-4
/security-review), **FAIR Monte Carlo simulation** (P1.5 G4.1
canonical Beta-PERT path; the v0.7.11 deterministic PERT-mean
shipped first), **CodeQL CRITICAL #92 closure** (`py/partial-
ssrf` in `securityscorecard/collector.py` — 3-layer
`_validate_portfolio_id_shape` defense), **Codecov 0% bug fix**
(P0.7), **PyPI inter-package pin propagation foot-gun closure**
(P0.5), **P3 partial deferral closures** (M-3 + cosmetic
6-store `Path(env).expanduser().resolve()` harmonization), plus
**3 new operator runbooks** + **doc-consistency pass** +
**release-checklist Steps 5.5 + 9.5** + **threat-model v0.7.12
delta**.

### Existing tiers — regression check (v0.7.12)

| Tier | v0.7.12 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched |
| 2 — OSCAL signing + verify | ✅ unchanged | OSCAL exporter surface untouched |
| 3 — Air-gap enforcement | ✅ unchanged | network_guard.py untouched |
| 4 — Secret scrubber | ✅ unchanged | No secret-scrubber files touched; SSC #92 fix is input-shape validation, not scrubbing |
| 5 — Collectors | ✅ hardened | SSC `_validate_portfolio_id_shape` 3-layer defense; M-3 dropped over-defensive contextlib.suppress on _log.info across 4 collectors (vanta/drata/bitsight/securityscorecard) |
| 6 — OSCAL exporter + output formats | ✅ unchanged | gap_report_to_oscal_ar surface untouched |
| 7 — CLI commands | ✅ extended (1 new flag) | `evidentia risk quantify --method fair-mc --iterations N --seed N --csv path` (Monte Carlo path); `--method open-fair` continues as the deterministic path |
| 8 — REST API | ✅ extended (SSC #92) | `/api/collectors/securityscorecard/collect` early-fails with 400 on unsafe `portfolio_id`; matches v0.7.8 F-V08-DAST-3 invariant |
| 9 — Web UI | ✅ unchanged | No evidentia-ui files touched |
| 10 — Configuration precedence | ✅ unchanged | No new env vars added (cloud SDKs use their canonical auth chains) |
| 11 — JSON-file persistence | ✅ harmonized (6-store completion) | All 6 stores now apply `Path(env).expanduser().resolve()` consistently (was: 2 of 6 prior to this cycle) |
| 12 — Bundled regulatory catalogs | ✅ unchanged (89) | No catalog changes |

### New v0.7.12 surfaces

| # | New surface | Status | Evidence |
|---|---|---|---|
| N1 | `S3ObjectLockWORM` (`evidentia[worm-s3]` extra) — boto3 + S3 Object Lock COMPLIANCE/GOVERNANCE modes; legal-hold; backward-extension rejection; multi-tenant prefix isolation; Object-Lock-enabled bucket required at creation | ✅ | 19 tests via moto's mock_aws + Object-Lock-enabled bucket. Cross-cloud parity smoke vs LocalFilesystemWORM passes. |
| N2 | `AzureImmutableBlobWORM` (`evidentia[worm-azure]` extra) — azure-storage-blob `ImmutabilityPolicy(expiry_time, policy_mode)` Locked/Unlocked; per-blob `set_legal_hold`; DefaultAzureCredential auth chain | ✅ | 17 tests via stateful in-memory BlobServiceClient stub (azurite emulator avoided for build-time slimness; stub mirrors the surface the backend uses). |
| N3 | `GCSBucketLockWORM` (`evidentia[worm-gcs]` extra) — bucket-wide retention policy + per-blob `temporary_hold` for legal-hold semantics; ADC auth | ✅ | 17 tests via stateful in-memory storage.Client stub. |
| N4 | `WORMBackend.purge_immediately(record_id, *, gdpr_request_ref, operator_id)` — GDPR Article 17 operator workflow; pre-conditions: GDPR-shaped record (retention_period_days=0) + no legal_hold + populated audit fields; default impl in ABC delegates to `_update_metadata` (override per backend) + `delete()` after lifecycle transition | ✅ | 6 tests on LocalFilesystemWORM happy path + non-GDPR rejection + legal-hold rejection + empty-audit-field rejection + audit-trail snapshot fidelity; 1 test on S3 via moto. |
| N5 | `transition_lifecycle(force_gdpr_purge: bool = False)` — scoped override permitting ACTIVE→EXPIRED for GDPR records (lock_until=None) when retention_period_days==0 AND no legal hold; closes the v0.7.11 functional gap | ✅ | 3 tests covering GDPR happy path + non-GDPR override-does-not-apply + legal-hold-trumps-override. |
| N6 | `evidentia risk quantify --method fair-mc --iterations N [--seed N] [--csv path]` — Monte Carlo simulation form; Beta-PERT sampling via `random.Random.betavariate`; SimulationResult Pydantic model with P10/P50/P90 + mean + stddev + box-and-whisker Markdown + CSV export | ✅ | 24 unit tests + 2 CLI integration tests. Stdlib only — no numpy/scipy dep added. Seed determinism verified golden-file style. |
| N7 | `_validate_portfolio_id_shape` SSC allow-list + `SecurityScorecardInvalidPortfolioIdError` typed exception — closes CodeQL CRITICAL #92 (py/partial-ssrf, CWE-918, CVSS 7.6) | ✅ | 29 unit tests (parametrized 7 safe + 19 unsafe values + non-string rejection + collector __init__ rejection + defense-in-depth on API responses) + 9 REST endpoint integration tests. |
| N8 | Codecov 0% fix (`[tool.coverage.run] relative_files = true` + dropped inverted `fixes:` mapping) | ✅ | Verified locally: coverage.xml emits `filename="packages/evidentia-core/src/evidentia_core/__init__.py"` (was bare `filename="__init__.py"`). On next CI run, Codecov will register actual coverage % against the GitHub tree. |
| N9 | `bump_version.py` pin-trap fix — tightens inter-package range pin LOWER bounds atomically on every release | ✅ | 13 unit tests on `bump_pin_range`. Dry-run verified: v0.7.11→v0.7.12 produces 19 substitutions across 9 files, including 10 inter-package pin tightenings. |

### Adversarial probing summary (v0.7.12 surfaces)

Coverage: **7 of 7 vectors** (cloud-WORM SDKs introduce real network surface for the first time in retention/).

- **Bad input**: SSC portfolio_id allow-list catches 19 distinct unsafe shapes; PERT range validator catches `low > most_likely > high`; Monte Carlo iterations < 1 rejected; cloud bucket name required non-empty
- **Missing dependency**: lazy imports + clear ImportError messages directing to `evidentia[worm-s3]` / `[worm-azure]` / `[worm-gcs]`
- **Network failure**: cloud SDK errors (`HttpResponseError` / `ClientError` / `GoogleAPIError`) surface as `WORMBackendError` preserving the cloud-side message
- **Expired credential**: cloud SDK auth chains handle this canonically; tests via mocked clients
- **Malformed config**: bucket-name + lock-mode validation at backend `__init__`; rejected before any HTTP call
- **Concurrent request / race**: GCS uses `if_generation_match=0` for atomic create; S3 + Azure check `head_object` / `exists()` first (acceptable race window since WORM forbids overwrite anyway)
- **Large-input DoS**: cloud SDKs handle their own request-size limits; FastAPI default body-size limits cover REST surface

### F-V12 findings disposition

**0 findings at this point in cycle.** Phase 7 pre-release-review
v4 Pre-tag run will produce `docs/security-review-v0.7.12.md`
which captures the formal review.

### Step 4 verification gate (v0.7.12 in-progress)

| Check | Status |
|---|---|
| pytest count | ✅ 2074 (was 1929 at v0.7.11; +145) |
| mypy --strict | ✅ 0/0 across 188 files (was 184; +4) |
| ruff | ✅ clean |
| Standing-rule keyword sweep | ✅ clean across 12 commits |
| Cross-cloud WORM parity (RetentionMetadata round-trip) | ✅ S3 + Azure + GCS + LocalFilesystem produce equivalent metadata |
| Codecov path emission | ✅ verified locally (re-runs coverage.xml inspection) |

---

## Re-validation snapshot — 2026-05-04 (v0.7.11 ship — pre-tag)

v0.7.11 ships the **P0 audit chain-of-custody** (RetentionMetadata
+ lifecycle state machine + `WORMBackend` ABC + `LocalFilesystemWORM`
reference impl), **P1.5 governance trio** (G3 KRI/KPI/KGI metrics
+ G4 Open FAIR risk quantification + G5 process-as-code workflows),
**P3 first-batch deferral closures** (9 of 17 closed: F-V10-S2 + M-1
+ M-2 + M-5 + M-6 + L-1 + L-3 + L-6 + L-7), **`validate_within`
harmonization** across 6 secure stores, plus **P4 docs** (audit-
chain-of-custody.md + governance-metrics.md +
risk-quantification.md).

### Existing tiers — regression check (v0.7.11)

| Tier | v0.7.11 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched |
| 2 — OSCAL signing + verify | ✅ unchanged | OSCAL exporter surface untouched |
| 3 — Air-gap enforcement | ✅ unchanged | network_guard.py untouched |
| 4 — Secret scrubber | ✅ extended | F-V10-S2 closure adds `cli/_editor.py` `$EDITOR` allowlist; tokens still flow via env vars only |
| 5 — Collectors | ✅ hardened (P3) | M-5 cross-host break + scheme-downgrade now emit structured warning events; M-6 SSC portfolio auto-pick now warns; M-1 + M-2 + L-3 + L-7 carried from v0.7.10 P3 |
| 6 — OSCAL exporter + output formats | ✅ unchanged | gap_report_to_oscal_ar surface untouched |
| 7 — CLI commands | ✅ extended (4 new top-level groups) | `evidentia retention` (7 verbs) + `evidentia governance metrics` (6 verbs) + `evidentia governance workflow` (6 verbs) + `evidentia risk quantify` (1 verb) |
| 8 — REST API | ✅ extended (L-1 hardening) | All 4 vendor-risk POST endpoints replaced silent `or 2000` coercion with explicit type+range gate |
| 9 — Web UI | ✅ unchanged | No evidentia-ui files touched |
| 10 — Configuration precedence | ✅ extended | EVIDENTIA_METRIC_STORE_DIR + EVIDENTIA_WORKFLOW_STORE_DIR + EVIDENTIA_RETENTION_STORE_DIR + EVIDENTIA_EDITOR_ALLOW_ANY env vars added |
| 11 — JSON-file persistence | ✅ harmonized (6-store pattern) | metric_store + workflow_store + retention_metadata_store add `validate_within` belt-and-suspenders; existing vendor_store + model_risk_store retroactively gain it for save_*; all 6 stores now follow identical secure pattern |
| 12 — Bundled regulatory catalogs | ✅ unchanged (89) | No catalog changes |

### New v0.7.11 surfaces

| # | New surface | Status | Evidence |
|---|---|---|---|
| N1 | `evidentia retention {set,list,show,extend,transition,delete,report}` CLI + RetentionMetadata schema + lifecycle state machine | ✅ | 72 tests (55 unit + 17 CLI). State machine enforces: legal-hold blocks expiration, can't skip ACTIVE→PURGED, PURGED is terminal, WORM forbids retention shortening. |
| N2 | `WORMBackend` ABC + `LocalFilesystemWORM` reference impl | ✅ | 17 tests covering put/get/delete/extend round-trip + 6 contract-violation cases (double-put, in-window delete, legal-hold delete, non-EXPIRED delete, retention shortening, path traversal). Concrete S3/Azure/GCS deferred to v0.7.12. |
| N3 | `evidentia governance metrics {add,observe,list,show,delete,report}` CLI + KRI/KPI/KGI schemas + `evaluate_metric()` + `generate_metrics_report()` | ✅ | 42 tests (28 unit + 14 CLI). Status state machine across both directions; missing-thresholds correctly blocked. |
| N4 | `evidentia risk quantify --method open-fair` CLI + OpenFAIRScenario + PERTRange + ALE computation + Markdown report | ✅ | 30 tests (23 unit + 7 CLI). PERT mean formula validated; risk-band categorization verified across all 5 bands. |
| N5 | `evidentia governance workflow {run,advance,status,list,log,delete}` CLI + Workflow + WorkflowStep schemas + state machine + `advance_workflow_step()` | ✅ | 42 tests (28 unit + 14 CLI). Step ordering enforced; rejection short-circuits; APPROVED/SKIPPED auto-promote next step; PURGED-state-equivalent terminal handling. |

### Adversarial probing summary (v0.7.11 surfaces)

Coverage: **6 of 7 vectors** (network n/a for local-store-only modules).
- Bad input: Pydantic extra="forbid" + range validation
- Missing dependency: lazy imports + clear ImportError messages
- Network failure: n/a
- Expired credential: n/a (REST is unauth by design)
- Malformed config: YAML safe_load + per-entry validation
- Concurrent request / race: atomic os.replace(tmp, out_path)
- Large-input DoS: FastAPI default body-size limits

### F-V11 findings disposition

**0 findings at v0.7.11 ship — first PROCEED-CLEAN of the v0.7.x cycle.**

(v0.7.10 had 1 MEDIUM inline-fixed F-V10-S1 + 1 LOW deferred F-V10-S2; v0.7.11 P3 closes F-V10-S2.)

---

## Re-validation snapshot — 2026-05-04 (v0.7.10 ship — pre-tag)

v0.7.10 ships the **Model Risk Management overlay** (`evidentia
model-risk` top-level subcommand group: model CRUD + doc generate
+ validation-report generate + RiskStatement.model_inventory_ref
AI-feature linkage), **`evidentia governance` primitives** (Three
Lines of Defense lines-report + Effective Challenge log), **7 new
bundled regulatory catalogs** (5 FFIEC IT Handbook booklets + FFIEC
CAT + OCC Bulletin 2026-13a / FRB SR 26-02; total 82 → 89), **P2
Codecov + 81.87% statement coverage closing the last OpenSSF Silver
MUST**, and **P3 first-batch v0.7.9 deferral closures** (M-1 / M-2 /
L-3 / L-7).

### Existing tiers — regression check (v0.7.10)

| Tier | v0.7.10 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ extended (additive) | RiskStatementGenerator gains optional model_inventory_id constructor param; RiskStatement schema gains optional model_inventory_ref field; backward-compatible default None for all pre-v0.7.10 callers. Step 4 /security-review confirmed opaque-metadata-only flow. |
| 2 — OSCAL signing + verify | ✅ unchanged | Zero changes under packages/evidentia-core/src/evidentia_core/oscal/ in v0.7.9..HEAD |
| 3 — Air-gap enforcement | ✅ unchanged | network_guard.py untouched |
| 4 — Secret scrubber | ✅ unchanged + hardened | _scrub regex unchanged; v0.7.10 P3 M-1 closure tightened token-input validation across 4 collectors. |
| 5 — Collectors | ✅ hardened (v0.7.10 P3) | All 4 vendor-risk collectors received: M-1 whitespace-only token rejection + M-2 round() not int() for ratings/scores + L-7 BLIND_SPOTS/COLLECTOR_ID re-exports. 9 new tests. |
| 6 — OSCAL exporter + output formats | ✅ unchanged | gap_report_to_oscal_ar surface untouched in v0.7.10 |
| 7 — CLI commands | ✅ extended (3 new top-level groups) | `evidentia model-risk` + `evidentia governance` + 7 sub-commands |
| 8 — REST API | ✅ extended (8 new endpoints) | 6 model-risk CRUD + 2 Markdown-render endpoints. Error-shape consistency follows v0.7.8 F-V08-DAST-3 + F-V08-DAST-1 widening pattern. PlainTextResponse for Markdown emit prevents MIME-sniffing escalation under SecurityHeadersMiddleware. |
| 9 — Web UI | ✅ unchanged | No evidentia-ui files touched in v0.7.10 |
| 10 — Configuration precedence | ✅ extended | EVIDENTIA_MODEL_STORE_DIR + EVIDENTIA_CHALLENGE_STORE_DIR env vars added; follow established platformdirs precedence |
| 11 — JSON-file persistence | ✅ extended (2 new sibling stores) | model_risk_store.py + effective_challenge_store.py mirror v0.7.9 vendor_store secure pattern. F-V10-S1 inline-fix harmonized validate_within usage across all 3 stores. |
| 12 — Bundled regulatory catalogs | ✅ extended (82 → 89) | 7 new Tier A US-federal public-domain catalogs (full FFIEC IT Handbook stack + FFIEC CAT + OCC Bulletin 2026-13a / FRB SR 26-02). Auto-tested via evidentia_core.catalogs.loader; 169 catalog tests pass. |

### New v0.7.10 surfaces

| # | New surface | Status | Evidence |
|---|---|---|---|
| N1 | `evidentia model-risk model {add/list/show/edit/delete}` CLI + REST | ✅ | 23 CLI integration tests + 24 REST integration tests + 22 unit tests for schemas + 18 unit tests for store. Adversarial: invalid UUID shape → 404, bad enums → 400/Exit(1), path-traversal IDs rejected at UUID gate. |
| N2 | `evidentia model-risk doc generate` + `validation-report generate` Markdown emitters | ✅ | 11 unit tests per generator + 4 CLI tests + 4 REST tests. Determinism tested. |
| N3 | `evidentia governance lines-report` + `challenge {add/list/show}` | ✅ | 23 unit tests for lines-of-defense + 28 unit + CLI tests for effective-challenge. YAML safe_load. F-V10-S1 inline-fixed at Step 3. |
| N4 | `RiskStatement.model_inventory_ref` AI-feature linkage | ✅ | 4 model-level tests + 2 generator-level tests. Step 4 /security-review confirmed opaque-metadata-only flow. |

### Adversarial probing summary (v0.7.10 surfaces)

Coverage: **6 of 7 vectors** addressed where applicable (network n/a for local-store-only modules). Bad-input / missing-dep / malformed-config / race-condition vectors all addressed via Pydantic extra="forbid" + atomic os.replace + YAML safe_load + 1730-test suite.

### F-V10 findings disposition

| ID | Severity | Disposition |
|---|---|---|
| F-V10-S1 | MEDIUM | INLINE-FIXED at Step 3 (effective_challenge_store.py defense-in-depth gap) |
| F-V10-S2 | LOW | DEFERRED to v0.7.11 (cli/model_risk.py --editor $EDITOR not allowlisted; risk amplifier only) |

**0 unfixed findings at v0.7.10 ship.**

---

## Re-validation snapshot — 2026-05-04 (v0.7.9 ship — pre-tag)

v0.7.9 ships the **TPRM module** (`evidentia tprm` top-level
subcommand group: vendor CRUD + concentration-report + DD-
questionnaire generator + ingest), **4 vendor-risk SaaS
collectors** (Vanta + Drata + BitSight + SecurityScorecard), and
**OSCAL TPRM emit** (vendor inventory in metadata.parties[] +
back-matter.resources[] with SHA-256 integrity hashes). Plus
the v0.7.8 Step 5.A carry-over batch (Snowflake count separation
+ quoted-id hardening + Databricks PermissionDenied typed catch
+ Power BI 1MB byte-cap guard + PR #18 workflow fix).

Per the v4 skill rule "patch with substantial new capability
surface = capability-matrix re-walk on the new surfaces +
regression check on existing tiers", this snapshot does a focused
re-walk of the **9 new public surfaces** + a regression check
against the **14 existing surfaces** (10 tiers + 4 v0.7.8 surfaces
that became existing in this snapshot).

### Existing tiers — regression check (no functional change)

| Tier | v0.7.9 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched in `git diff v0.7.8..HEAD` |
| 2 — OSCAL signing + verify | ✅ extended (additive) | `oscal/exporter.py` gained vendor_inventory parameter (P0.5); existing finding-resource integrity + Sigstore signing path unchanged |
| 3 — Air-gap enforcement | ✅ unchanged | `network_guard.py` untouched; new collectors emit explicit `requires_network=True` |
| 4 — Secret scrubber | ✅ unchanged | `audit/logger._scrub` untouched; new collectors source tokens via env vars, never via CLI args or REST bodies |
| 5 — Collectors | ✅ extended (4 new) | Vanta + Drata + BitSight + SecurityScorecard packages added; existing AWS / GitHub / Okta / 5 SQL / Databricks / Snowflake unchanged |
| 6 — OSCAL exporter + output formats | ✅ extended (P0.5) | `gap_report_to_oscal_ar` gained `vendor_inventory: list[Vendor] \| None`; emits vendors as `metadata.parties[]` parties + `back-matter.resources[]` with SHA-256 integrity hash |
| 7 — CLI commands | ✅ extended | `evidentia tprm vendor add/list/show/edit/delete`, `evidentia tprm concentration-report`, `evidentia tprm dd-questionnaire generate/ingest`, `evidentia collect vanta/drata/bitsight/securityscorecard`, `evidentia gap analyze --vendor-inventory <path>`. Existing CLI unchanged |
| 8 — REST API | ✅ extended | TPRM CRUD (5) + concentration (1) + DD-questionnaire (1) + 4 collector endpoints + status endpoint extended with vanta/drata/bitsight/securityscorecard entries. All new endpoints follow v0.7.8 F-V08-DAST-3 pattern (400 not 422 for body errors; 503 for upstream/auth; 500 for unexpected) |
| 9 — Web UI | ✅ unchanged | No `evidentia-ui` files touched in v0.7.9 (frontend bundle unchanged) |
| 10 — Configuration precedence | ✅ unchanged | `VANTA_API_TOKEN` / `DRATA_API_TOKEN` / `BITSIGHT_API_TOKEN` / `SECURITYSCORECARD_API_TOKEN` follow existing env-var precedence; CLI flags + payloads never accept secrets |
| 11 — Databricks collector | ✅ unchanged + hardened | PermissionDenied typed catch (carry-over from v0.7.8 F-V08-CR-MEDIUM); existing 27 unit tests still pass |
| 12 — Snowflake collector | ✅ unchanged + hardened | Quoted-identifier escape + masking-policy / row-access count separation (both carry-over from v0.7.8 F-V08-CR-MEDIUM); 4 new tests for `_quote_snowflake_identifier()` |
| 13 — Tableau integration | ✅ unchanged | No tableau files touched in v0.7.9 |
| 14 — Power BI integration | ✅ unchanged + hardened | 1 MB byte-cap bisection in `push_rows()` (carry-over from v0.7.8 F-V08-CR-MEDIUM); 4 new tests for batch bisection / oversize-row error / empty-rows short-circuit |

### New surfaces — full v0.7.9 capability walk

Each row covers: functional · adversarial · result.

| New surface | Functional | Adversarial | Result |
|---|---|---|---|
| **TPRM Vendor model + storage** (`evidentia_core.models.tprm`, `evidentia_core.vendor_store`) | ✅ 23 unit tests for Pydantic models (Vendor + FourthParty + EvidenceRef + 3 enums + `compute_next_review_due` with leap-year clamp) + 23 unit tests for vendor_store JSON-file persistence (UUID validation, atomic save, EVIDENTIA_VENDOR_STORE_DIR override) | ✅ Pydantic `extra="forbid"` rejects unknown fields; UUID-shape validation rejects path traversal in vendor IDs; EvidenceRef `@model_validator` enforces artifact_id-or-file_path + sha256-with-file_path contract (P0.1 H-1 inline-fix); atomic save via `os.replace(tmp, out_path)` (P0.1 M-1 inline-fix) | **PASS** |
| **TPRM CLI** (`evidentia tprm vendor add/list/show/edit/delete`) | ✅ 25 integration tests via Typer's CliRunner (3 input modes for add: atomic flags + --from-yaml; 3 input modes for edit: atomic + --from-yaml + --editor; --yes-bypass for delete; rich-table + --json for list/show) | ✅ All 11 atomic-flag fields validated through Pydantic on construction; `--from-yaml` only accepts top-level YAML mapping; UUID-shape validation; CLI bare-array vs REST-envelope contract documented in CLI docstring (P0.1 H-2 doc fix) | **PASS** |
| **TPRM REST CRUD** (`/api/tprm/vendors` + cadence preview) | ✅ 23 integration tests via FastAPI TestClient (POST/GET/PUT/DELETE + skip/limit pagination + criticality_tier/type filters + cadence-preview helper); `model_copy(update=...)` pattern in PUT to avoid mutating the request DTO (P0.1 H-3 inline-fix) | ✅ 400 for body-content errors (preserves v0.7.8 F-V08-DAST-3 fix); paginated envelope contract; UUID-shape validation in path params; max `limit=1000` to bound memory usage | **PASS** |
| **TPRM concentration-report** (`evidentia tprm concentration-report` + `/api/tprm/concentration`) | ✅ 20 unit + 6 CLI integration + 6 REST integration = 32 tests; 6 dimensions (region / cloud-provider / 4th-party / service-category / criticality-tier / regulatory-classification); HTML/JSON/CSV outputs; threshold flagging | ✅ HTML output is single-file (no JS deps; `html.escape` XSS-safe on all user-supplied vendor + value names — H-1 P0.3 Continuous fix); CSV-injection defense (`_csv_safe` OWASP single-quote prefix per CWE-1236 — H-1 P0.3 Continuous fix); cloud-provider direct-vs-4P collision resolved with `(direct)` / `(4th-party)` source suffix (H-2 P0.3 Continuous fix); format-string foot-gun on vendor.name closed via `.replace()` (H-3 P0.3 Continuous fix) | **PASS** |
| **TPRM DD-questionnaire generator** (`evidentia tprm dd-questionnaire generate`) | ✅ 24 unit + 7 CLI integration + 6 REST integration = 37 tests; 5 format catalogue (evidentia-generic / caiq-lite / caiq-full / sig BYO / sig-lite BYO); 3 output formats (json / csv / xlsx); 9 new P0.2 second-slice tests covering caiq-full domain coverage + XLSX render + SIG BYO | ✅ Packaged JSON loaded via `importlib.resources` (zipimport-safe); CSV-injection defenses on all user-content cells (vendor name + 4th-party + region + relationship_owner + question_text + notes); XLSX written via openpyxl gated behind `[xlsx]` extra (clear `XlsxNotInstalledError` if missing); SIG BYO `_parse_sig_template` uses fuzzy sheet-name matching + label-based pre-fill (CLI-only; no REST exposure) | **PASS** |
| **TPRM DD-questionnaire ingest** (`evidentia tprm dd-questionnaire ingest`) | ✅ 6 unit + 2 H-4 inline-tests (vendor_id=None ingest + SIG BYO partial-match); auto-detects file format from extension (.json/.csv/.xlsx) | ✅ JSON path uses `json.loads` (CWE-502-safe; never `pickle.loads` / `yaml.unsafe_load`); CSV uses `csv.reader` (safe); XLSX uses `openpyxl.load_workbook(data_only=True)` (no formula evaluation; no VBA macro execution); unsupported extension → typed `ValueError`; missing file → `FileNotFoundError`; missing vendor correlation → clear CLI error w/ remediation | **PASS** |
| **Vanta vendor-risk collector** (`evidentia_collectors.vanta`) | ✅ 13 unit tests with mocked httpx (happy path, pagination, max-vendors ceiling, 4 high-risk field-shape variants, 401/403 → VantaAuthError, network failure → manifest-level error, empty inventory) | ✅ Constructor rejects empty token; bearer-token in headers (never URL/query); `_paginate` cursor-based with `max_vendors=2000` cap; stuck-cursor guard (Continuous H-1 inline-fix); defensive `_is_high_risk` across `riskTier`/`risk_tier`/`riskLevel`/`risk_level`/nested `riskAssessment.{tier,level,severity}`; auth errors fatal (re-raise); connection/query errors land in manifest's `errors` list | **PASS** |
| **Drata vendor-risk collector** (`evidentia_collectors.drata`) | ✅ 13 unit tests with mocked httpx (covers same patterns as Vanta + 6 high-risk field-shape variants including numeric `inherentRisk` / `residualRisk` on Drata's documented 1-5 / 1-25 scales) | ✅ Same posture as Vanta + explicit-key payload-priority `if "data" in data: ...` (Continuous H-2 inline-fix; previously fell through `[]` to other keys); stuck-cursor guard (Continuous H-1 inline-fix); typed `DrataAuthError` on 401/403 | **PASS** |
| **BitSight portfolio collector** (`evidentia_collectors.bitsight`) | ✅ 13 unit tests with mocked httpx (portfolio-inventory + low-rating threshold emit; cross-host pagination guard; oversize/underrated edge cases) | ✅ HTTP Basic auth with token-as-username + empty password (token wrapped internally; never in URL); BitSight returns absolute URLs in `next` field — collector refuses to follow cross-host AND scheme-downgraded URLs (Continuous F-V09-S1 fix per CWE-319); `low_rating_threshold` configurable (default 700 BitSight Basic boundary); rating-as-string falls through gracefully (no false positive on stringified rating) | **PASS** |
| **SecurityScorecard portfolio collector** (`evidentia_collectors.securityscorecard`) | ✅ 13 unit tests with mocked httpx (portfolio-inventory + low-score emit; auto-resolve portfolio path; page-based pagination; auth/connection failure paths) | ✅ `Authorization: Token <value>` header (distinct from BitSight's HTTP Basic + Vanta/Drata's Bearer); explicit-key payload-priority (Continuous H-2 inline-fix); monotonic-increase guard (Continuous H-3 inline-fix); auto-resolve portfolio_id when omitted; empty-portfolios path raises typed `SecurityScorecardQueryError` (NOT auth error) | **PASS** |
| **OSCAL TPRM emit** (`evidentia_core.oscal.exporter` extended) | ✅ 9 new unit tests covering parties+back-matter dual-encoding, UUID consistency, prop population, integrity-hash determinism, canonical-JSON round-trip, vendor-count metadata, no-vendor-no-noise behavior, vendor+finding coexistence | ✅ Vendor.id reused as both party UUID + back-matter resource UUID (cross-reference resolution); Evidentia-namespaced props (`vendor-id` / `vendor-type` / `criticality-tier` / etc.); SHA-256 hash on canonical JSON via deterministic `json.dumps(sort_keys=True, separators=(",", ":"))`; tampering with vendor record changes hash + fails `verify_ar_file`; optional fields surface only when present (clean diff); `--vendor-inventory` CLI flag accepts JSON-array file with operator-friendly error messages on malformed input | **PASS** |
| **`--security-headers` middleware** (`evidentia_api.security_headers`) | ✅ Tests: middleware applies CSP / X-Frame-Options DENY / X-Content-Type-Options nosniff / Referrer-Policy / HSTS / Permissions-Policy on all responses; `should_enable_for_host()` False for 127.0.0.1/localhost/::1 + True for non-loopback | ✅ Always-set semantic (no skip on already-present); `--security-headers / --no-security-headers` CLI flags on `evidentia serve`; default = auto (off for localhost dev parity, on for non-loopback bind = operator opted into network exposure); operators behind TLS-terminating proxy can pass `--no-security-headers` to suppress duplicates. Closes v0.7.8 F-V08-DAST-2 LOW (CWE-693). | **PASS** |

### v0.7.9 in-flight findings re-summary

| Source | Bucket | Count | Status |
|---|---|---|---|
| Continuous-variant Step 3 (P0.4 quartet + P0.5 + P0.2-second-slice) | HIGH | 5 (H-1 stuck cursor / H-2 fall-through / H-3 partial loop guard / H-4 test gaps / H-5 SIG BYO column order) | **all 5 inline-fixed** in commit `3315150` |
| Continuous-variant Step 3 | LOW security | 1 (F-V09-S1 BitSight TLS-downgrade scheme guard / CWE-319) | **inline-fixed** in commit `3315150` |
| Continuous-variant Step 5 | Project-wide | 5 housekeeping (CHANGELOG gaps + README staleness + ROADMAP staleness + plan-status wording + pyproject description) | **all inline-fixed** in commit `3315150` |
| Pre-tag Step 3 incremental | HIGH | 1 (H-1 docs/tprm.md references non-existent `--region` and `--next-review-due` CLI flags) | **inline-fixed** by adding both flags to `vendor add` + `vendor edit` (this commit) |
| v0.7.8 carry-over batch | MEDIUM × 4 | Snowflake count split + quoted-id + Databricks PermissionDenied + Power BI 1MB | **all 4 inline-fixed** in commit `cf1c07e` |
| v0.7.8 carry-over LOW × 9 | LOW | Opportunistic refinements per security-review-v0.7.8.md "no correctness defects" disposition | **DEFERRED to v0.7.10** with explicit rationale (ship-velocity per Allen 2026-05-04) |
| Pre-tag MEDIUM × 9 + LOW × 8 (Continuous run) | MEDIUM/LOW | Whitespace-token validation, int(rating) truncation, contextlib.suppress, cross-collector base-class refactor, etc. | **DEFERRED to v0.7.10** per Continuous-variant disposition |

### DAST sub-step (G11) — regression-only this run

The v0.7.8 ship cleared the schema-fidelity batch (17 endpoints
moved from 422→400; F-V08-DAST-3 batch fix). v0.7.9 added 11 new
POST endpoints (4 collectors + 5 TPRM CRUD + 1 concentration + 1
DD-questionnaire) all following the v0.7.8 F-V08-DAST-3 pattern by
construction (verified by code-review at the per-route HTTPException
sites). UI is unchanged in v0.7.9, so the v0.7.8 Playwright XSS-
probe results carry forward unchanged. F-V08-DAST-2 (security
headers) shipped in commit `ae4fc59` per the v0.7.9 P0 cycle.

Schemathesis re-run **deferred** to ship-time post-tag verification
(Step 7) as a regression check rather than re-fired here for
review-time efficiency. Per-run JSON captures the deferral.

### Step 4 verification gate (v0.7.9)

| Gate | Result |
|---|---|
| Surface-coverage % ≥ 90% | ✅ 26 / 26 surface rows have ✅ verdicts (100%) — 12 new surfaces + 14 existing |
| Adversarial probe coverage ≥ 6 of 7 vectors per new surface | ✅ all 12 new surfaces cleared 7/7 vectors |
| Test-suite green | ✅ 1540 passed, 12 skipped, 0 failed (full repo) |
| mypy strict on changed packages | ✅ 0 issues in 160 source files |
| ruff clean on packages/ + tests/ | ✅ all checks passed |
| DAST regression check (G11) | ✅ all v0.7.9 new POST endpoints follow v0.7.8 F-V08-DAST-3 fix pattern by construction (code-review verified); UI unchanged from v0.7.8 (Playwright results carry forward); Schemathesis re-fire deferred to Step 7 post-tag |
| Standing-rule keyword sweep | ✅ 0 hits across 21 forbidden tokens (Continuous-variant + Pre-tag incremental sweeps both clean) |
| Claude-attribution sweep | ✅ 0 hits in any commit since v0.7.8 |

---

## Re-validation snapshot — 2026-05-03 (v0.7.8 ship — pre-tag)

v0.7.8 adds **two cloud data-warehouse collectors** (Databricks +
Snowflake) and **two BI output integrations** (Tableau + Power BI) —
the first BI/exec-reporting output surface in the project. Per the v4
skill rule "minor with new collector/integration surface = full
re-walk", this snapshot does a focused re-walk of the **4 new public
surfaces** + a regression check against the **existing 10 tiers**, and
also captures the v0.7.8 P0.5 in-flight security batch (S1
SQLite-safe-root-mandatory + S2 user-controlled-values-via-`%r`).

### Existing tiers — regression check (no functional change)

| Tier | v0.7.8 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched in `git diff v0.7.7.1..HEAD` |
| 2 — OSCAL signing + verify | ✅ unchanged | No `oscal/signing` or `sigstore` files touched |
| 3 — Air-gap enforcement | ✅ unchanged | `network_guard.py` untouched; new collectors emit explicit `requires_network=True` |
| 4 — Secret scrubber | ✅ unchanged | `audit/logger._scrub` untouched; v0.7.8 S2 fix switches user-controlled values to `%r` so log statements never embed identifier glyphs that bypass the scrubber |
| 5 — Collectors | ✅ extended (see new rows below) | 2 new public surfaces (Databricks + Snowflake); existing AWS + GitHub + Okta + 5 SQL adapters + Jira unchanged |
| 6 — OSCAL exporter + output formats | ✅ unchanged | No format/exporter files touched |
| 7 — CLI commands | ✅ extended | `collect databricks` + `collect snowflake` + `integrations tableau publish` + `integrations powerbi publish` subcommands added; existing CLI unchanged |
| 8 — REST API | ✅ extended | 4 new POST endpoints + `/api/collectors/status` extended with `databricks` + `snowflake` entries; existing routes unchanged |
| 9 — Web UI | ✅ unchanged | No `evidentia-ui` files touched in v0.7.8 (frontend `package.json` lockfile bumps only) |
| 10 — Configuration precedence | ✅ unchanged | `DATABRICKS_TOKEN` / `SNOWFLAKE_PASSWORD` / `TABLEAU_PAT_SECRET` / `POWERBI_CLIENT_SECRET` follow existing env-var precedence; CLI flags + payloads never accept secrets |

### New surfaces — full v0.7.8 capability walk

Each row covers: functional (tests pass) · adversarial (bad input /
missing dep / network failure / auth failure / malformed config /
permission denied / partial-success path) · result.

| New surface | Functional | Adversarial | Result |
|---|---|---|---|
| **Databricks collector** (`evidentia_collectors.databricks`) | ✅ 27 unit tests via injected `WorkspaceClient` mock; full suite green | ✅ constructor rejects empty `host=` + missing `client=` → typed `DatabricksCollectorError`; `databricks-sdk` ImportError → typed error w/ `pip install evidentia-collectors[databricks]` remediation; `_ensure_client` wraps WorkspaceClient construction → `DatabricksAuthError`; `current_user.me()` failure → `DatabricksAuthError`; sub-check 403/PERMISSION_DENIED → `DatabricksPermissionError` (4 sub-check sites); `manifest.is_complete = not errors` w/ 3 explicit `empty_categories` for partial-evidence transparency | **PASS** |
| **Snowflake collector** (`evidentia_collectors.snowflake`) | ✅ 29 unit tests via mocked `connector.connect`; full suite green | ✅ `account` + `user` are required kwargs (Pydantic-style enforcement at signature); `snowflake-connector-python` ImportError → typed `SnowflakeCollectorError` w/ `[snowflake]` extra remediation; `connector.connect` failure → `SnowflakeAuthError("Could not connect to Snowflake (driver: <class>)")` (driver-class-name only, F-002 pattern carried forward); per-query failures → typed `SnowflakeQueryError`; `manifest.is_complete` False if any of 6 sub-checks raised, w/ `incomplete_reason` joining errors; CLI `--password-env` defaults to `SNOWFLAKE_PASSWORD` so plaintext never enters argv; key-pair forward-compat path (`private_key_path=`) | **PASS** |
| **Tableau integration** (`evidentia_integrations.tableau`) | ✅ 22 unit tests for extract + 3 API smoke tests | ✅ `TableauConfig` is `frozen=True` Pydantic v2 model — config secrets-by-name only (`pat_name_env` + `pat_secret_env`); `tableauserverclient` ImportError → typed `TableauApiError` w/ `[tableau]` extra remediation; missing PAT-name OR missing PAT-secret env → typed `TableauAuthError` w/ remediation; `_signin` wraps SDK failure → `TableauAuthError("Tableau sign-in failed (driver: <class>)")` (no token leakage); project-not-found → `TableauPublishError`; `__exit__` → `_signout` w/ `contextlib.suppress(Exception)` so signout failure never masks publish failure | **PASS** |
| **Power BI integration** (`evidentia_integrations.powerbi`) | ✅ 29 + 15 unit tests (`test_powerbi_extract.py` + `test_powerbi_client.py`) + 4 API smoke tests | ✅ `PowerBIConfig` is `frozen=True` Pydantic v2 model — workspace + tenant + client are required UUIDs, secret-by-name only; `msal` ImportError → typed `PowerBIApiError` w/ `[powerbi]` extra remediation; missing client-secret env → typed `PowerBIAuthError`; MSAL `acquire_token_for_client` non-OK → `PowerBIAuthError` (token never logged); 4xx/5xx on dataset / push-rows / clear-table → typed `PowerBIPublishError` w/ status code; sovereign-cloud overrides accepted (`api_base_url` + `authority_url`) | **PASS** |

API-level coverage (in `tests/integration/test_api/`):
`TestSnowflakeCollectEndpoint` (4 tests — missing account / user /
password env / status-endpoint includes snowflake) +
`TestTableauPublishEndpoint` (3 tests — invalid key / missing
server_url / invalid risks array) + `TestPowerBIPublishEndpoint` (4
tests — invalid key / missing workspace / tenant / client). All routing
+ Pydantic body-validation paths covered without contacting live
backends.

### v0.7.8 in-flight findings re-summary

| ID | Bucket | Resolution |
|---|---|---|
| S1 (commit `d84169c`) | HIGH (CWE-22 / CWE-73 mandatory containment) | **shipped P0.5** — `SQLiteCollector` now requires `safe_root` at REST entrypoints; 16 unit tests; 3 REST safe-root tests |
| S2 (commit `0ae8ed9`) | MEDIUM (CWE-117 log-injection hardening) | **shipped P0.5** — user-controlled values switched to `%r` in `_log` calls across new collectors / integrations |
| F-V08-CR-H1 | HIGH (Snowflake LOGIN_HISTORY no LIMIT — DoS risk on noisy accounts) | **queued for Step 5 batch fix** before tag |
| F-V08-CR-H2 | HIGH (Snowflake cursor reuse across DBs) | **queued for Step 5 batch fix** before tag |
| F-V08-CR-H3 | HIGH (Power BI `clear_table` 4xx on fresh dataset) | **queued for Step 5 batch fix** before tag |
| F-V08-1 | LOW (`[azure]` + `[gcp]` extras advertised without backing impls) | **queued for Step 5.A doc-touch** (remove from extras until v0.7.9 / v0.8.0) |
| F-V08-2 | LOW (DFAH/DSE wording corrections in `docs/positioning-and-value.md`) | **queued for Step 5.A doc-touch** |
| F-V08-3 | LOW (`docs/v0.7.9-plan.md` cites `SR 11-7` — should be `SR 26-02`) | **queued for Step 5.B forward-plan touch-up** |
| 7 MEDIUM + 9 LOW (from `/code-review`) | various | **queued for Step 5 batch fixes** before tag |

### DAST sub-step (G11) — first real run (NEW for v0.7.8)

**DAST tools installed during Step 4 entry** (Allen-approved 2026-05-03): `schemathesis 4.17.0`, `playwright 1.59.0`, chromium runtime (~150 MB). Pinned in pre-release-review env, NOT in `pyproject.toml` (these are review-time tools, not runtime deps).

#### Schemathesis run (OpenAPI fuzz — `evidentia serve` localhost:8765)

```
PYTHONIOENCODING=utf-8 schemathesis run \
  http://127.0.0.1:8765/api/openapi.json \
  --url http://127.0.0.1:8765/ \
  --max-examples 5 --workers 1 --no-color --max-failures 50
```

**Result**: 299 generated test cases; 43 found 62 unique failures across 34/34 selected operations (5.06s). Failure summary:

| Class | Count | Severity | Disposition |
|---|---|---|---|
| **Server error** | 2 | 1 real (`GET /api/frameworks/0/controls/0` → **500**); 1 documented (`POST /collectors/aws/collect` → 503 when AWS creds missing — expected path; OpenAPI just doesn't declare 503) | F-V08-DAST-1 + schema-fidelity gap |
| **Response violates schema** | 17 | OpenAPI `HTTPValidationError.detail` is `array<ValidationError>` but our `HTTPException(422, detail="string")` returns string. Schema-fidelity bug, NOT security. | Step 5.A batch fix |
| **API rejected schema-compliant request** | 17 | Same root cause — endpoints require body fields the OpenAPI schema doesn't declare as required (e.g., `collect aws` accepts `null` body but emits 422 if account/user fields missing) | Step 5.A batch fix |
| **API accepted schema-violating request** | 1 | Specific endpoint accepts a payload the schema declares invalid; schema-fidelity gap | Step 5.A |
| **Undocumented HTTP status code** | 6 | 503/422 paths not declared in OpenAPI `responses` | Step 5.A |
| **Unsupported methods** | 19 | Common FastAPI behavior — endpoints respond to unexpected HTTP methods. Not actionable. | Accept |

**Concrete real findings from Schemathesis**: ONE — F-V08-DAST-1 (the 500 on `/frameworks/{framework_id}/controls/{control_id}` for invalid IDs). Response body is generic `Internal Server Error` (no stack-trace leak), but unhandled-exception in route handler should return 404. The 17×2 schema-fidelity issues are a separate (and substantial) batch-fix concern documented for Step 5.A.

#### Playwright run (web UI smoke + security headers + XSS probe)

```python
GET /                 → 200 ("Evidentia"); 0 console errors/warnings
GET /?q=<script>alert(1)</script>           → 200; React-escaped; no DOM injection
GET /dashboard?q=<xss>                       → 200; React-escaped
GET /frameworks?q=<xss>                      → 200; React-escaped
GET /risks?q=<xss>                           → 200; React-escaped
```

**Result**: React handles XSS correctly across all 4 probed routes. **Missing security response headers** on the SPA response: CSP `<none>`, X-Frame-Options `<none>`, X-Content-Type-Options `<none>`, Referrer-Policy `<none>`, Strict-Transport-Security `<none>`. → F-V08-DAST-2 (LOW for localhost-bound default; defense-in-depth gap). For deployments behind a reverse proxy or exposed to the network, operators should configure security headers at the proxy layer (already documented in `docs/threat-model.md`).

#### v0.7.8 DAST findings table

| ID | Severity | Category | Issue | Disposition |
|---|---|---|---|---|
| F-V08-DAST-1 | MEDIUM | Correctness (CWE-755 missing exception handling) | `GET /api/frameworks/{framework_id}/controls/{control_id}` returns **500 Internal Server Error** for invalid framework ID (e.g., `0`); should return 404. Generic body — no stack-trace exposure. | **Step 5.A batch fix** — wrap the route handler in proper validation + raise `HTTPException(404, ...)` for unknown framework. |
| F-V08-DAST-2 | LOW | Defense-in-depth | Missing security response headers on web UI (CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / HSTS). Localhost-bound default mitigates clickjacking; React-framework escapes mitigate stored XSS. Production deployments should set headers at proxy layer. | **Defer** — document in threat-model + recommend operators set at proxy. Could ship a `--security-headers` flag in v0.7.9+. |
| Schema-fidelity gap (17 endpoints) | MEDIUM | Schema-conformance, NOT security | `HTTPException(422, detail="string")` doesn't match OpenAPI `HTTPValidationError.detail: array<ValidationError>`. Affects FastAPI's auto-generated schema vs actual response across 17 endpoints. | **Step 5.A batch fix** — either return an array-shape detail (FastAPI native pattern), or override the OpenAPI schema for these endpoints to declare `detail: string`. |

### Step 4 verification gate

| Gate | Result |
|---|---|
| Surface-coverage % ≥ 90% | ✅ 14 / 14 surface rows have ✅/⚠/❌ verdicts (100%) — 4 new surfaces + 10 existing tiers |
| Adversarial probe coverage ≥ 6 of 7 vectors per new surface | ✅ all 4 new surfaces cleared 7/7 vectors |
| Test-suite green | ✅ 1256 passed, 12 skipped, 0 failed (full repo); 148 passed in the new-file subset |
| mypy strict on changed packages | ✅ 0 issues in 54 source files |
| DAST run completed | **✅ first real run (G11)** — Schemathesis: 1 real + 17 schema-fidelity findings on 34 endpoints; Playwright: React XSS-safe + missing security headers (F-V08-DAST-2 LOW) |

---

## Re-validation snapshot — 2026-05-02 (v0.7.7 ship — pre-tag)

v0.7.7 adds the **first substantive new collector surface since v0.5.0**:
five SQL-family adapters (Postgres / MySQL / SQLite / MSSQL / Oracle),
one new Okta evidence collector, and one ServiceNow output
integration. Per the v4 skill rule "patch with new collector surface
recommended to re-walk", this snapshot does a focused re-walk of the
**new surfaces** + a regression check against the **existing 10 tiers**.

### Existing tiers — regression check (no functional change)

| Tier | v0.7.7 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched in v0.7.7 diff |
| 2 — OSCAL signing + verify | ✅ unchanged | No `oscal/signing` or `sigstore` files touched |
| 3 — Air-gap enforcement | ✅ unchanged | `network_guard.py` untouched |
| 4 — Secret scrubber | ✅ unchanged | `audit/logger._scrub` untouched; v0.7.7 adds new env-var-keyed secret paths but each adapter rejects URI-embedded passwords at constructor |
| 5 — Collectors | ✅ extended (see new rows below) | 7 new public surfaces; existing AWS + GitHub + Jira unchanged |
| 6 — OSCAL exporter + output formats | ✅ unchanged | No format/exporter files touched |
| 7 — CLI commands | ✅ extended | `collect sql` adapter dispatch + `collect okta` + `integrations servicenow` subcommands added; existing CLI unchanged |
| 8 — REST API | ✅ extended | 6 new POST endpoints + status-endpoint extension; existing routes unchanged |
| 9 — Web UI | ✅ unchanged | No `evidentia-ui` files touched |
| 10 — Configuration precedence | ✅ unchanged | `EVIDENTIA_*_PASSWORD` + `EVIDENTIA_SQLITE_SAFE_ROOT` follow existing env-var precedence; CLI flags + payloads never accept secrets |

### New surfaces — full v0.7.7 capability walk

Each row covers: functional (tests pass) · adversarial (bad input /
missing dep / network failure / expired credential / malformed config /
DoS bound) · result.

| New surface | Functional | Adversarial | Result |
|---|---|---|---|
| **Postgres adapter** (`sql.postgres`) | ✅ 16 unit + 3 Docker integration tests | ✅ password-in-URI rejected at constructor; psycopg ImportError → typed `PostgresCollectorError`; connection-error wrapper trims to driver class name (F-002 fix); read-only probe via `default_transaction_read_only` + CREATE TEMP rollback | **PASS** |
| **MySQL/MariaDB adapter** (`sql.mysql`) | ✅ 13 unit tests | ✅ same pattern as Postgres; PyMySQL ImportError → typed error; `@@global.read_only` + CREATE TEMPORARY rollback probe | **PASS** |
| **SQLite adapter** (`sql.sqlite`) | ✅ 16 unit tests using `:memory:` | ✅ `safe_root=` containment via `validate_within` (CWE-22 mitigation); `os.access(W_OK)` write-priv probe; `file:?mode=ro` read-only URI; F-003 URI quoting fix; F-004 TOCTOU accepted | **PASS** |
| **MS SQL Server adapter** (`sql.mssql`) | ✅ 20 unit tests | ✅ `Encrypt=yes;TrustServerCertificate=no` connection defaults; pyodbc ImportError → typed error; `IS_SRVROLEMEMBER('sysadmin')` + `IS_ROLEMEMBER('db_owner')` write-priv probe | **PASS** |
| **Oracle adapter** (`sql.oracle`) | ✅ 23 unit tests | ✅ oracledb thin-mode (no Oracle Client install required); password-in-URI rejected; session_roles + session_privs write-priv probe | **PASS** |
| **Okta collector** (`okta`) | ✅ 20 unit tests via `httpx.MockTransport` | ✅ HTTPS-only constructor; explicit 30s timeout; `max_users` cap default 10000 (DoS bound); paginates via Link header rel="next"; user-agent identifies collector for Okta system-log correlation | **PASS** |
| **ServiceNow integration** (`evidentia_integrations.servicenow`) | ✅ 35 unit tests (mapper + client + sync) | ✅ HTTPS-only constructor; `password` field excluded from `model_dump`; explicit 20s timeout; `correlation_id` deterministic for idempotency on re-push (no duplicate records) | **PASS** |

### v0.7.7 findings re-summary

| ID | Bucket | Resolution |
|---|---|---|
| F-001 | HIGH (CWE-22) | **fixed in Step 5.A inline** — REST + CLI honor `EVIDENTIA_SQLITE_SAFE_ROOT`; 3 new tests |
| F-002 | MEDIUM (CWE-209) | **fixed in Step 5.A inline** — 5 SQL adapters connection-error wrappers trimmed to driver class name |
| F-003 | MEDIUM (CWE-20) | **fixed in Step 5.A inline** — SQLite URI now uses `urllib.parse.quote` |
| F-004 | LOW (CWE-367 TOCTOU) | accepted (read-only URI + filesystem ACLs limit blast radius) |
| F-005 | LOW (sample-bound MFA enrollment) | accepted (documented as `EVIDENTIA-OKTA-RATE-LIMIT-PARTIAL` BLIND_SPOT) |

### DAST sub-step (G11)

DAST tools (Schemathesis + Playwright) are not installed in this dev
environment. **Documented skip with rationale**: v0.7.7 adds 6 new
REST endpoints, all of which are exhaustively tested via FastAPI's
`TestClient` in `tests/integration/test_api/test_collectors.py` +
unit-test cursor mocks for the DB call paths. No new UI surface
(unchanged from v0.7.6). DAST install + first-run will land in
v0.7.8 P0 alongside the routine CI integration.

### Step 4 verification gate

| Gate | Result |
|---|---|
| Surface-coverage % ≥ 90% | ✅ 17 / 17 surface rows have ✅/⚠/❌ verdicts (100%) |
| Adversarial probe coverage ≥ 6 of 7 vectors per new surface | ✅ all 7 new surfaces cleared 6+ vectors |
| DAST run completed (or explicit skip) | ⚠ explicit skip with rationale |

---

## Re-validation snapshot — 2026-04-26 (v0.7.1 ship)

This v0.7.0 snapshot below remains representative for v0.7.1 because
**v0.7.1 added no new public capability surfaces** — the AI features
hardening (P0) was an internal refactor of `risk_statements/` and
`explain/` (typed exception hierarchy, `@with_retry`,
`GenerationContext` metadata, ECS structured logging,
`run_id`-correlated audit events). The CLI surface, REST surface,
output formats, and configuration-precedence chain are unchanged.

**Per-row updates for v0.7.1**:

- **Risk-tier 1 — AI features**: `risk_statements/generator.py` and
  `explain/generator.py` rows now PASS (HIGH-bucket H1-H4 all closed).
  All four AI subsystems (`evidentia_ai.client`, `risk_statements/`,
  `explain/`, `explain/cache.py`) now ship with the v0.7.0
  collector-pattern enterprise grade. Detail: see
  [`docs/v0.7.1-plan.md`](v0.7.1-plan.md) §"P0 — AI features
  enterprise-grade hardening".
- **Surface tier 7 — CLI commands**: `evidentia version` would now
  report "Evidentia v0.7.1" (the table below shows the v0.7.0 review
  output as a historical record); `evidentia risk generate` row
  upgrades from "⚠ no test coverage (deferred to v0.7.1)" to "✅
  comprehensive test coverage in `tests/unit/test_ai/test_risk_statements.py`
  (772 lines covering sync + async + batch + retry + air-gap + GenerationContext)".
- **Surface tier 8 — REST API**: `GET /api/health` would now report
  `{"status": "ok", "version": "0.7.1"}`; route count and surface
  unchanged.
- **All other tiers**: unchanged from the v0.7.0 snapshot below.

The next full re-validation pass is scheduled for v0.7.2 ship per the
release-checklist Step 5 + Step 6 acceptance gates and the testing-playbook
operational test loop. The historical v0.7.0 tables below remain the
canonical Step-4 review record per the audit-trail-preservation principle
(don't rewrite the past; layer the present on top).

---

## 1. Risk-first ordering — what was tested, what was found

Surfaces are ordered by **enterprise risk** (higher rows = bugs in
this area would damage the v0.7.0 enterprise-grade story most).

### Risk-tier 1 — AI features (`evidentia-ai`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `evidentia_ai.client` (LiteLLM + Instructor wrapper) | ✅ guarded completion paths verified | ✅ strong: air-gap enforcement via `check_llm_model()`, both sync + async wrapped, lru_cache on instances, mypy-strict cast | ✅ correctly raises `OfflineViolationError` for cloud models in air-gap mode | **PASS** |
| `risk_statements/generator.py` | ⚠ no functional smoke (no API key in test env) | ⚠ **2 BLOCKER B3 violations** (lines 173, 227 — bare `except Exception`); no `@with_retry`; no `CollectionContext`; uses stdlib `logging` not v0.7.0 ECS structured logger; no metadata enrichment from `evidentia_core.audit` | ⚠ **ZERO unit tests** (only `test_explain.py` exists) | **FAIL** — deferred to v0.7.1 |
| `explain/generator.py` | ✅ caching layer tested in `test_explain.py` | ⚠ same enterprise-grade gaps as risk_statements (no @with_retry, no CollectionContext, no ECS structured logs) | ⚠ no adversarial tests for cache-corruption or LLM-validation-failure | **PARTIAL** — defer hardening to v0.7.1 |
| `explain/cache.py` (disk cache) | ✅ tested | ✅ corrupt cache → returns None (graceful); env var override; deterministic cache key | ✅ corrupt cache files handled | **PASS** |

**Why deferred to v0.7.1**: hardening AI features properly requires
4 design decisions (CollectionContext-vs-GenerationContext fit;
@with_retry-vs-Instructor-retry stacking; new EventAction enum
entries; comprehensive `test_risk_statements.py` ~200-300 lines of
careful LLM mocking). Rushing these into v0.7.0 would lock in
suboptimal patterns.

### Risk-tier 2 — OSCAL signing + verify pipeline

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `oscal/signing.py` (GPG) | ✅ subprocess wrapper validated; `gpg_available()` precondition | ✅ typed exception hierarchy (GPGError → 4 subclasses); --batch --yes for CI; status-fd parsing; distinguishes mismatch (returns `valid=False`) vs infrastructure error (raises) | ✅ existing tests cover sign+verify roundtrip | **PASS** (minor: uses stdlib `logging` not ECS structured — consistency gap with sigstore.py) |
| `oscal/sigstore.py` (Sigstore/Rekor) | ✅ keyless signing via Fulcio + Rekor; air-gap refusal | ✅ typed exception hierarchy; ECS structured logging via `evidentia_core.audit`; `_ensure_online()` air-gap guard; best-effort metadata extraction | ✅ existing tests via `test_sigstore.py` | **PASS** |
| `oscal/verify.py` (orchestrator) | ✅ digest + GPG + Sigstore checks | ✅ tampered/forged/replayed semantics documented; deferred imports; v0.7.0+ extension to Sigstore added in `851f45f` | ✅ 8 new tests added in `851f45f` covering Sigstore detection, custom bundle path, UnsafeNoOp warnings, require_signature satisfied by either GPG or Sigstore | **PASS (after fix)** |
| `evidentia gap analyze --sign-with-sigstore` | ✅ flag exists + wired to `export_report(sign_with_sigstore=...)` after `851f45f` | ✅ companion flags `--sigstore-bundle`, `--sigstore-identity-token` (env: `SIGSTORE_ID_TOKEN`); guard for non-oscal-ar formats | ✅ smoke-tested via `--help` | **PASS (after fix)** |
| `evidentia oscal verify --check-sigstore` | ✅ flag exists after `851f45f` | ✅ companion flags `--sigstore-bundle`, `--expected-identity`, `--expected-issuer`; rich + JSON output updated to surface Sigstore status | ✅ smoke-tested via `--help` | **PASS (after fix)** |
| `.github/actions/gap-analysis/action.yml` Sigstore path | ✅ bash `--sigstore-bundle` flag matches CLI after `851f45f` (was `--bundle`, would have failed at runtime) | ✅ inline doc clear | ⚠ no automated end-to-end smoke test for the action itself (deferred to v0.7.1) | **PASS (after fix)** |

**3 CRITICAL findings caught + fixed in `851f45f`**: Sigstore CLI gap,
Sigstore verify gap, action.yml broken flag reference. The composite
GitHub Action's `emit-sigstore-bundle: true` path is now functional
end-to-end.

### Risk-tier 3 — Air-gap enforcement (`network_guard`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `network_guard.set_offline()` + `is_offline()` | ✅ module-level flag, single-process, well-documented | ✅ strong design; `LOCAL_LLM_PREFIXES` allowlist + `is_loopback_or_private()` for `api_base`; `offline_mode()` context manager for tests | ✅ existing tests cover flag toggling | **PASS** |
| `evidentia_ai.client._guarded_completion` | ✅ calls `check_llm_model()` before any LLM IO | ✅ both sync + async wrapped; correctly resolves `api_base` from kwargs | ✅ raises `OfflineViolationError` for cloud models | **PASS** |
| `oscal/sigstore._ensure_online()` | ✅ refuses Sigstore in air-gap mode | ✅ raises `SigstoreAirGapError` with clear remediation message ("use GPG signing") | ✅ test coverage in `test_sigstore.py` | **PASS** |
| `evidentia doctor --check-air-gap` | ✅ enumerates per-subsystem posture | ✅ checks LLM client + catalog loader + AI telemetry + gap store + Web UI | ✅ table-formatted output | **PASS** |

### Risk-tier 4 — Secret scrubber (`audit/logger._scrub`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| Regex patterns | ✅ scrubs `AKIA*`/`ASIA*` (AWS), `ghp_/gho_/ghu_/ghs_/ghr_` (GitHub), `password=`/`token=`/`api_key=`/`secret=`/`credential=`, JWTs (3 base64url segments) | ✅ narrow patterns minimize false positives; "false positives are annoying but safe; false negatives are a compliance liability" — correct posture | ⚠ **Misses**: Slack tokens (`xoxb-`, `xoxp-`), Stripe keys (`sk_live_`, `sk_test_`), Google API keys (`AIza`), Atlassian tokens, npm tokens | **PASS with v0.7.1 expansion candidate** |
| Application surface | ✅ called on every `message` field before emission | ✅ documented as safety net; collectors are responsible for keeping secrets out of structured field values | n/a | **PASS** |

### Risk-tier 5 — Collectors

Already verified in Step 3 (commit `7e35b2d` — "harden existing AWS +
GitHub collectors"). The collectors got the v0.7.0 enterprise-grade
treatment that the AI features did not:

| Collector | Typed catches | `@with_retry` | `CollectionContext` | ECS structured logs | `BLIND_SPOTS` list |
|---|---|---|---|---|---|
| AWS Config | ✅ | ✅ | ✅ | ✅ | n/a (Config rules are themselves the disclosure) |
| AWS Security Hub | ✅ | ✅ | ✅ | ✅ | n/a |
| AWS IAM Access Analyzer | ✅ | ✅ | ✅ | ✅ | ✅ 5 entries (kms-grants, s3-acls-vs-block-public-access, service-linked-roles, unsupported-resource-types, finding-latency) |
| GitHub branch protection + CODEOWNERS | ✅ | ✅ | ✅ | ✅ | n/a |
| GitHub Dependabot alerts | ✅ | ✅ | ✅ | ✅ | n/a |

`BLIND_SPOTS` correctly threaded through the new
`gap_report_to_oscal_ar(blind_spots=...)` API into AR back-matter
resources (commit `c26d283`).

---

## 2. Surface-tier smoke tests (functional only)

### Surface tier 6 — OSCAL exporter + output formats

| Format | Smoke test | Result |
|---|---|---|
| `json` | ✅ `gap analyze --format json` against Meridian → 77 controls / 64 gaps / 16.9% coverage / report exported | **PASS** |
| `csv` | (covered by `test_export_all_formats[csv-csv]` in `test_end_to_end.py`) | **PASS** (test) |
| `markdown` | (covered by `test_export_all_formats[markdown-md]`) | **PASS** (test) |
| `oscal-ar` | (covered by `test_export_all_formats[oscal-ar-json]` + 3 trestle conformance tests + 8 verify tests + 3 exporter tests) | **PASS** (test) |
| `github` annotations (gap diff only) | ✅ existing test coverage in test_gap_diff | **PASS** (test) |

### Surface tier 7 — CLI commands

| Command | Smoke result |
|---|---|
| `evidentia version` | ✅ "Evidentia v0.7.0" + Python 3.12.13 |
| `evidentia doctor` | ✅ all packages OK; **82 frameworks registered** (validates README claim end-to-end); 9 frameworks mapped (across 6 crosswalks) |
| `evidentia doctor --check-air-gap` | ✅ per-subsystem posture report (covered above in tier 3) |
| `evidentia catalog list --tier A` | ✅ Tier-A frameworks listed correctly |
| `evidentia catalog show <fw> --control <id>` | covered by tests |
| `evidentia catalog crosswalk` | covered by tests |
| `evidentia catalog import` | covered by tests |
| `evidentia gap analyze` | ✅ end-to-end against Meridian sample (above) |
| `evidentia gap diff` | covered by tests + dogfood workflow `evidentia.yml` |
| `evidentia explain control` | covered by `test_explain.py` |
| `evidentia risk generate` | ⚠ no test coverage (deferred to v0.7.1) |
| `evidentia integrations jira *` | covered by tests (mocked) |
| `evidentia collect aws` | covered by tests (moto-mocked) |
| `evidentia collect github` | covered by tests (responses-mocked) |
| `evidentia oscal verify` | ✅ flag surface validated via `--help` after `851f45f`; 18 unit tests pass |
| `evidentia init` | covered by tests |
| `evidentia serve` | not smoke-tested (would require running browser); covered by `test_serve` integration test |

### Surface tier 8 — REST API

| Endpoint sample | Smoke result |
|---|---|
| `GET /api/health` | ✅ 200 OK, `{"status": "ok", "version": "0.7.0"}` |
| `GET /api/frameworks` | ✅ 200 OK, **82 frameworks returned** (validates the doctor count) |
| 26 routes / 12 router modules total | covered by FastAPI TestClient suite + integration tests |

**Note on README discrepancy**: README claims "18 REST endpoints",
actual count is **26 routes across 12 router modules**. Documentation
fix flagged for Step 5.

### Surface tier 9 — Web UI (8 routes)

Not smoke-tested in this Step 4 pass — would require launching
`evidentia serve` and a browser session. Existing coverage:

- 6 Vitest component tests
- 36 FastAPI TestClient tests for the backing API
- WCAG 2.1 AA via Radix primitives (design-time guarantee, not
  per-page audit)

**Recommendation for Step 5**: add a Playwright E2E smoke test that
launches `evidentia serve` and clicks through the 8 pages
(Dashboard → Gap Analysis → Framework Catalog → Control Explorer →
Risk Statements → Integrations Hub → Settings → Project Init).
Already noted as "Planned for v0.4.2 polish" in ROADMAP.

### Surface tier 10 — Configuration precedence

Not exhaustively tested in this Step 4 pass. Existing coverage:

- `test_config.py` covers the precedence chain (CLI flag > env var >
  yaml > built-in default)
- `evidentia.yaml` loaded via `evidentia_core.config.load_config()`
- precedence resolved per-call via `get_default(cfg, cli_value, key, builtin_default=...)`

**No bugs surfaced** in the smoke tests of `gap analyze` (which
uses `--frameworks` precedence chain).

---

## 3. Bugs caught + fix status

### CRITICAL — fixed in commit `851f45f`

| # | Bug | Fix |
|---|---|---|
| C1 | `evidentia gap analyze` had no `--sign-with-sigstore` flag (CLI users couldn't access the library Sigstore feature) | Added `--sign-with-sigstore`, `--sigstore-bundle`, `--sigstore-identity-token` flags; wired through `export_report` |
| C2 | `verify_ar_file` didn't check Sigstore bundles (CLI verify only detected GPG `.asc`) | Extended verify_ar_file with `check_sigstore`, `sigstore_bundle_path`, `expected_sigstore_identity`, `expected_sigstore_issuer` params; updated VerifyReport with `sigstore_*` fields and `warnings` list; `overall_valid` now requires both signatures (when present) to verify |
| C3 | `.github/actions/gap-analysis/action.yml` referenced `--bundle` (non-existent) instead of `--sigstore-bundle` | Renamed to `--sigstore-bundle` to match new CLI |
| Step-3 fix in `25ccca8` | Inter-package version pins stale at `>=0.6.0,<0.7.0` (9 occurrences across 5 pyproject.toml files) | All bumped to `>=0.7.0,<0.8.0` |
| Step-3 fix in `25ccca8` | LiteLLM dep range `>=1.50,<2.0` allowed compromised 1.82.7/1.82.8 | Tightened to `>=1.83.0,<2.0` |

### HIGH — deferred to v0.7.1

| # | Bug | Why deferred |
|---|---|---|
| H1 | `risk_statements/generator.py` lines 173, 227 — bare `except Exception` (BLOCKER B3 violation per docs/enterprise-grade.md) | Fixing properly requires designing the AI-features hardening pattern (typed exception hierarchy mirroring collector pattern); part of broader v0.7.1 AI hardening |
| H2 | `risk_statements/` module has zero unit tests | New `test_risk_statements.py` needs ~200-300 lines of careful LLM mocking; rushing this produces fragile tests |
| H3 | AI features (risk_statements, explain) lack `@with_retry` from `evidentia_core.audit.retry` | Design decision: stack with Instructor's max_retries or replace? LLM-call retry semantics differ from API-call retry semantics |
| H4 | AI features lack `CollectionContext` metadata on outputs | Design decision: repurpose CollectionContext (poor semantic fit) vs new GenerationContext type (cleaner but new abstraction) |
| H5 | AI features use stdlib `logging` not `evidentia_core.audit.logger` (ECS structured) | Need new EventAction enum entries (`evidentia.risk.generated`, `evidentia.explain.generated`); coordinate with EventAction schema |

### MEDIUM — fix in Step 5 docs polish

| # | Issue | Fix |
|---|---|---|
| M1 | README undercounts REST endpoints ("18", actual 26) | Update README §3.4 |
| M2 | README says "the four workspace sub-packages" — actual is five (incl. evidentia-api) | Update README install section |
| M3 | README CLI list missing `evidentia oscal verify` (added v0.7.0) | Update README CLI table |
| M4 | `oscal/signing.py` uses stdlib `logging` not ECS structured logger (consistency gap with sigstore.py) | ~15-line change; consider for v0.7.1 |
| M5 | Sigstore secret-scrubber misses Slack/Stripe/Google API/Atlassian/npm token patterns | ~20-line addition to `_SECRET_PATTERNS`; consider for v0.7.1 |

### LOW — acknowledge, no fix

| # | Issue | Why no fix |
|---|---|---|
| L1 | Composite action `action.yml` uses version pins (`@v5`, `@v4`, `@v2`) not SHA pins | Acceptable for v0.7.0; documented SHA-pin upgrade path in action README; Dependabot can SHA-pin over time |
| L2 | No automated end-to-end smoke test for the composite action itself | Would require dedicated test workflow + a recipient repo to action against; Step-5 deferred candidate |
| L3 | "82 frameworks bundled" claim verified by both file count + `evidentia doctor` | n/a — README is correct |

---

## 4. Test-suite delta from Step 1 to end of Step 4

| Stage | Tests | Notes |
|---|---|---|
| Pre-review baseline (`efa5678`) | 862 passed, 8 skipped | Before any Step 1-4 work |
| After Step 3 fix (`25ccca8`) | 849 passed, 8 skipped | -16 from `test_rename_shims.py` deletion + +3 trestle conformance tests = -13 net |
| After Step 4 critical fix (`851f45f`) | **857 passed**, 8 skipped | +8 new Sigstore verify tests |

mypy: clean (97 source files, no issues)
ruff lint: clean
ruff format: 2 reformatted files (in commit `6f3051d`)

---

## 5. Step 4 unfinished — deferred / not in scope

These were on the original Step 4 plan but not deeply tested
(functional smoke covered the major flows; full adversarial probing
deferred):

- Surface tier 9 — Web UI 8 pages: would require live browser session;
  Vitest + FastAPI TestClient already cover unit + API layer
- Surface tier 10 — Config precedence chain: existing `test_config.py`
  covers; no smoke bugs surfaced in CLI usage
- Collectors deep-dive — already covered by Step 3 review of commit
  `7e35b2d` and the comprehensive moto/responses test suite

---

## 6. Recommendations

### For v0.7.0 final tag (immediate)

✅ **Proceed to Step 5 (refinements)** then Step 6 (release-checklist
+ tag). The Sigstore CLI/verify gap is fixed; the v0.7.0 supply-chain
hardening story is intact end-to-end.

### For v0.7.1 (next minor; ~6-8 weeks out)

Define the v0.7.1 release theme as **"AI features hardening"**:

1. Apply collector-pattern hardening to `risk_statements/` and `explain/`:
   - Typed exception hierarchy (e.g., `RiskStatementError`,
     `ExplanationError`, `LLMUnavailableError`)
   - `@with_retry` integration (after deciding stacking semantics with
     Instructor's `max_retries`)
   - `GenerationContext` (new type — distinct from `CollectionContext`
     because risk statements are generated, not collected) carrying
     model, temperature, prompt_hash, run_id, generated_at
   - ECS structured logging via `evidentia_core.audit.logger` with new
     `EventAction.AI_RISK_GENERATED`, `AI_EXPLAIN_GENERATED`,
     `AI_GENERATION_FAILED`, `AI_GENERATION_RETRY` entries
2. New `test_risk_statements.py` (~200-300 lines): cover sync + async
   batch, validation retries, cache miss/hit patterns, LLM-call
   failures, air-gap refusal
3. Sigstore policy: change `verify_file()` default behavior — emit a
   warning in addition to the `UnsafeNoOp` fallback (Step-4 fix
   already adds the warning to `VerifyReport`; v0.7.1 should emit it
   to logs too)
4. Secret scrubber expansion (Slack, Stripe, Google, Atlassian, npm)
5. Composite action smoke test workflow
6. SHA-pin third-party actions in the composite action.yml

### For v0.8.0 (next minor after that)

Per `docs/positioning-and-value.md` §13.2, the "OSS-native AI moat"
features:

- DFAH-style determinism harness for risk-statement generation
- Policy Reasoning Traces (PRT) integration
- Open risk-statement benchmark dataset on Hugging Face
- Evidence groundedness gate
- MCP server exposing Evidentia's GRC store
- DSE-based screenshot evidence validator
- Standalone `evidentia-catalogs` repo publication

---

## Federal-SI walk-through scenarios (v0.9.1 P4)

Defines the concrete use cases the domain-expert walk-through will
exercise. Each scenario identifies a persona, goal, Evidentia surfaces
exercised, and expected outcomes. These serve as the walk-through script
and acceptance criteria for v0.9.1 + v1.0 gate.

| # | Persona | Goal | Evidentia surfaces | Expected outcome |
|---|---------|------|--------------------|------------------|
| FS-1 | CSP compliance engineer | Prepare monthly ConMon deliverables for the AO | `evidentia conmon check`, `evidentia poam list --status in_progress`, `POST /api/conmon/check`, `GET /api/poam/items` | Overdue + due-soon cadences surfaced; POA&M items with updated status ready for submission |
| FS-2 | CSP compliance engineer | Generate OSCAL POA&M from gap analysis | `evidentia gap-analyze --framework nist-800-53-rev5`, `evidentia poam create --from-gap-report`, `gap_report_to_oscal_poam()` | OSCAL 1.1.2 plan-of-action-and-milestones JSON with SHA-256 back-matter integrity; CRITICAL + HIGH findings materialized |
| FS-3 | 3PAO assessor | Verify evidence integrity for annual assessment | `evidentia oscal verify`, `evidentia eval verify`, Sigstore signature validation | Cryptographic chain from gap-report through risk-statement through OSCAL export is verifiable; tamper-evidence working |
| FS-4 | ISSO (Information System Security Officer) | Track POA&M lifecycle through remediation | `evidentia poam update`, `evidentia poam milestone add/update`, POA&M state machine (planned→in_progress→completed→verified) | Forward-only state transitions enforced; milestones track incremental progress; attention-state bucketing (overdue/due-soon) surfaces urgency |
| FS-5 | AO (Authorizing Official) reviewer | Review control compliance posture across frameworks | `evidentia gap-analyze --all-frameworks`, `evidentia conmon list`, `/api/conmon/cadences` + `/api/gaps/` | Framework-level compliance view; cadence schedule showing which assessments are current vs overdue |
| FS-6 | DevSecOps engineer (CI/CD) | Integrate compliance gate into deployment pipeline | `evidentia gap-analyze --fail-on-severity critical`, `evidentia eval risk-determinism --fail-on-determinism-rate-below 0.95`, GitHub Action workflow | Pipeline fails on critical gaps or non-deterministic AI output; deterministic blocking of non-compliant deployments |
| FS-7 | CSP compliance engineer | Manage inherited vs system-specific controls | `evidentia gap-analyze` with framework overlay filtering, OSCAL POA&M control-id scoping | Only system-specific + hybrid controls materialize as POA&M items; inherited controls (CSP responsibility) are excluded from tenant POA&M |
| FS-8 | ISSO | Respond to new vulnerability scan findings | `evidentia poam create` (single finding), `evidentia poam milestone add`, `POST /api/poam/items` | New POA&M item created with appropriate severity; milestone tracks first-response SLA; CONMON cadence alignment verified |
| FS-9 | Compliance program manager | Generate executive compliance summary | `evidentia gap-analyze --json` + `evidentia conmon check --json` + `evidentia poam list --json` | Machine-readable JSON output suitable for dashboard consumption; overdue counts + gap severity distribution + cadence health |
| FS-10 | Federal auditor (external) | Validate POA&M against ConMon schedule alignment | `evidentia conmon check`, `evidentia poam list`, OSCAL POA&M export | POA&M update cadence matches ConMon monthly schedule; no stale POA&M items without corresponding ConMon check |

### Walk-through execution protocol

1. Domain expert receives scenarios FS-1 through FS-10 as a script
2. For each scenario, expert runs the specified commands/APIs against
   a pre-populated test dataset (synthetic federal-SI data)
3. Expert documents: what worked, what was confusing, what's missing,
   what doesn't match real-world workflow
4. Findings classified as: (a) code fix needed, (b) documentation
   gap, (c) feature gap for future release, (d) acceptable as-is
5. Code fixes land in v0.9.1; documentation gaps land in v0.9.1;
   feature gaps carry into v0.9.2+ per ROADMAP

### Walk-through test dataset (to be prepared)

- Synthetic gap-analysis report: 50 gaps across NIST 800-53 (mixed
  severity: 5 CRITICAL, 10 HIGH, 20 MEDIUM, 15 LOW)
- Pre-populated POA&M store: 15 items in various states (3 planned,
  5 in_progress, 3 overdue, 2 completed, 2 verified)
- ConMon state file: 7 cadences with realistic last-completed dates
  (2 overdue, 3 due-soon, 2 current)
- Evidence artifacts: 5 signed OSCAL exports + 3 eval results with
  Sigstore signatures

---

## Re-validation snapshot — 2026-05-17 (v0.9.3 SHIPPED)

v0.9.3 SHIPPED (tag `v0.9.3` at commit TBD). **Largest minor of
the v0.9.x line so far.** Combines two originally-PROPOSED themes
(CONMON daemon Theme A + AI governance Theme B) into a single ship
plus 4 carry-overs (LLM-rater κ recompute, drift gate, GHCR docs,
api-stability draft). 18th consecutive PROCEED-CLEAN of v0.7.x →
v0.8.x → v0.9.x line.

**New public surfaces tested this cycle (Theme A — CONMON daemon)**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia conmon watch --poll` daemon | `tests/unit/test_conmon/test_daemon.py` + `tests/integration/test_cli/test_conmon.py` | Daemon lifecycle (STARTED → poll → STOPPED via SIGINT/SIGTERM); state-file YAML `safe_load`; min-60s poll-interval double-enforce; `--state-file` atomic write; PollResult attention-bucket classification; on_due_soon / on_overdue callback dispatch |
| `evidentia conmon mark-completed <slug> --when YYYY-MM-DD` | `tests/integration/test_cli/test_conmon.py` | First-mark (previous=None) + subsequent-mark (previous=prior date); CONMON_CYCLE_MARKED_COMPLETED audit emit with both previous + new values; ValueError on unknown slug |
| `SMTPAlertChannel` + `WebhookAlertChannel` | `tests/unit/test_integrations/test_alerting/test_smtp.py` (8 tests including new STARTTLS-strip regression) + `test_webhook.py` (timestamp + HMAC verification) | STARTTLS-only with `has_extn` assertion (Step 5.A F-V93-S1 fix); credential rejection of CLI value flags; HMAC-SHA256 over `f"{timestamp}.{body}"` (Step 5.A F-V93-S3 fix); HTTPError + URLError mapped to typed RuntimeError |
| `AlertDeduper` (file-backed dedup state) | `tests/unit/test_conmon/test_alerting.py` | Per-(slug, state) 24h suppression; corrupted-state backup to `.json.corrupt-<utc-iso>` (Step 5.A F-V93-Q10 fix); single-writer contract documented |
| `evidentia conmon health` + `GET /api/conmon/health` | `tests/unit/test_conmon/test_health.py` + `tests/integration/test_api/test_conmon.py` | Per-framework attention-bucket counts; cross-framework overall health score; REST 10000-entry cap; framework-filter; dead `unknown` field removal (Step 5.A F-V93-Q1 fix) |
| `ContinuousEvidenceSource` Protocol + `NoopContinuousSource` | `tests/unit/test_plugins/test_continuous.py` (107 LOC; 10 tests) | Protocol-only contract; Noop reference exercises the surface; production refs deferred to v0.9.4 per documented scope-cut |
| 6 new CONMON EventActions | `tests/unit/test_audit/test_events.py` (naming convention) + various integration tests | DAEMON_STARTED / STOPPED / POLL_FAILED (Step 5.A F-V93-Q5 addition) / CYCLE_MARKED_COMPLETED / ALERT_DISPATCHED / SUPPRESSED / HEALTH_REPORT_GENERATED |

**New public surfaces tested this cycle (Theme B — AI governance)**:

| Surface | Test path | Coverage |
|---|---|---|
| EU AI Act tier classifier (`classify()`) | `tests/unit/test_ai_governance/test_classification.py` | 4 tier outputs (unacceptable / high / limited / minimal); Annex III domain detection; deterministic per-input |
| `AISystemRegistryEntry` + `AIRegistryStore` (file-backed JSON store) | `tests/unit/test_ai_governance/test_registry_store.py` | UUID validation (InvalidAISystemIdError); validate_within path-traversal guard; atomic os.replace; EVIDENTIA_AI_REGISTRY_DIR env override; list_all malformed-file skip-with-warning (matches poam_store / vendor_store precedent) |
| `evidentia ai-gov` CLI (5 verbs: classify/register/list/get/delete) | `tests/integration/test_cli/test_ai_gov.py` | Classify happy-path + register persist + list with tier filter (Step 5.A F-V93-Q7 fix drops brittle `str()` wrapper) + get by UUID + delete idempotent; upfront `--deployment-status` validation (Step 5.A F-V93-Q8 fix) |
| `/api/ai-gov/*` REST router (5 endpoints) | `tests/integration/test_api/test_ai_gov.py` | classify / register / list with optional `?tier=` filter / get by UUID / delete; AI_SYSTEM_CLASSIFIED / REGISTERED / RETIRED audit events on mutating endpoints (Step 5.A F-V93-Q2 fix); InvalidAISystemIdError → 400; not-found → 404 |
| EU AI Act catalog enrichment (risk_tier + applies_to_annex_iii on Article 9-15) | Catalog round-trip + load tests | Tier promoted D→A; 8 Annex III risk categories; backward-compat with v0.9.2 catalogs (additive Optional fields with default=None) |
| NIST AI RMF crosswalks (→ EU AI Act 26 mappings; → ISO 42001 23 mappings) | Crosswalk integrity tests | Bidirectional; confidence + confidence_rubric per mapping; FrameworkMapping extension fields Optional |
| 4 new AI governance EventActions | `tests/unit/test_audit/test_events.py` | AI_SYSTEM_CLASSIFIED / REGISTERED / UPDATED / RETIRED — UPDATED + RETIRED CLI verbs reserved for v0.9.4 |

**Adversarial probe coverage** (per-surface ≥6 of 7 attack vectors;
bad-input / missing-dep / network-failure / expired-credential /
malformed-config / concurrent-race / large-input-DoS): average
5.7 / 7 applicable vectors; gaps map to findings already bucketed
in Step 3 of the v0.9.3 review.

**DAST runtime probing (G11)**: documented skip — Schemathesis +
Playwright missing from dev-tool pre-flight. Manual `/security-
review` invocations #1 + #2 compensate. v0.9.4 P4.3 adds DAST
tools to the pre-flight install list.

**Inherited surface re-validation** (carry-forward from v0.9.2 — no
functional changes to TPRM / model-risk / governance / cloud-WORM /
Sigstore eval / DFAH determinism + faithfulness library + harness /
PRT / MCP HTTP/SSE / CIMD scope enforcement / Cohen's Kappa / POA&M
data layer + CLI + REST + OSCAL emit / CONMON read-only library +
v0.9.0 calendar + v0.9.2 REST endpoints / plugin-contract
scaffolding / `--faithfulness-threshold-mode` CLI). The v0.9.3
deliverables are wholly additive — no existing public-surface
behavior changed beyond the Step 5.A pre-release-review batch
(8 MEDIUM + 1 HIGH-via-doc fixes + 1 dead-code removal).

---

## Re-validation snapshot — 2026-05-17 (v0.9.4 SHIPPED)

v0.9.4 SHIPPED (tag `v0.9.4` at commit TBD). **Consolidation pass
closing v0.9.3 deferred review items + landing the federal-SI
walk-through reserved since v0.9.0.** 19th consecutive
PROCEED-CLEAN of v0.7.x → v0.8.x → v0.9.x line.

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia_core.security.FileLock` | `tests/unit/test_security_file_lock.py` (8 tests) | POSIX `fcntl.flock` + Windows `msvcrt.locking`; 4-writer concurrent test confirms no last-writer-wins; FileLockTimeout on contended acquire; exception-path cleanup |
| `--state-lock` CLI flag (watch + mark-completed) | Existing CLI tests + smoke verification | Opt-in lock wrapping mark_completed + AlertDeduper.mark_dispatched read-modify-write |
| `WebhookConfig` SSRF guard | `tests/unit/test_integrations/test_alerting/test_webhook.py` (8 new tests) | Default-deny http:// + loopback + RFC1918 + cloud-metadata; opt-in passthrough for legitimate cases; unresolvable hostname raises clearly |
| `TokenBucketRateLimiter` + `RateLimitMiddleware` | `tests/unit/test_rate_limit.py` (10 tests) + `tests/integration/test_api/test_ai_gov.py::TestRateLimit` | Constructor validation; burst + refill + per-client isolation; LRU eviction; reset; real-time smoke; HTTP 429 + Retry-After header |
| `X-Idempotency-Key` on POST /api/ai-gov/register | `tests/integration/test_api/test_ai_gov.py::TestIdempotency` (3 tests) | Same key + body returns prior system_id; same key + different body returns 409; no key creates fresh entries |
| `GET /api/conmon/daemon-status` + status sidecar | `tests/integration/test_api/test_conmon.py::TestDaemonStatusEndpoint` + `TestDaemonStatusUnitHelpers` (7 tests) | 404 when env unset or file missing; 200 with payload; 404 on corrupt JSON; write/read round-trip; atomic write |
| `evidentia conmon dedup-list` CLI verb | `tests/integration/test_cli/test_conmon.py::TestConmonDedupList` (4 tests) | Missing-file empty; rich table output with multiple entries; slug filter; JSON output shape |
| `evidentia ai-gov update` + `retire` CLI verbs | `tests/integration/test_cli/test_ai_gov.py::TestUpdate` + `TestRetire` (7 tests) | Partial update (owner-only); deployment-status validation; no-fields error; missing-id error; retire preserves entry; idempotent re-retire |
| Federal-SI walk-through smoke | `tests/integration/test_walkthrough_federal_si.py` (6 tests) | fixture-existence; steps 2-7 end-to-end against synthetic data; high vs minimal tier classification |
| 1 new CONMON EventAction | `tests/unit/test_audit/test_events.py` (naming convention) | `CONMON_DAEMON_STATUS_QUERIED` |

**Adversarial probe coverage** for v0.9.4 surfaces averages
~6.0 / 7 applicable vectors. Highlights:

- **bad-input**: webhook SSRF guard rejects malformed schemes;
  rate-limit middleware rejects unauthenticated path with 429
- **race-condition**: FileLock cross-process 4-writer test confirms
  serialization; idempotency-store FileLock-wrapped
- **DoS**: rate-limit middleware caps register/classify; status-
  file mid-write tolerance returns 404 not 500

**Inherited surface re-validation** (carry-forward from v0.9.3):
no functional changes to TPRM / model-risk / governance /
cloud-WORM / Sigstore eval / DFAH / PRT / MCP / POA&M / CONMON
read-only + REST router / AI governance core + classification +
catalog enrichment. The v0.9.4 deliverables are wholly additive
or backward-compat (default-off `--state-lock`, default-deny
webhook with opt-in flags, idempotency only when header supplied).

**Net test trajectory**: 2742 (v0.9.3) → 2798 (v0.9.4): +56 tests
across 12 new test classes. **Source files**: 217 → 219 (+2:
`security/file_lock.py` + `api/rate_limit.py`).

---

## Re-validation snapshot — 2026-05-18 (v0.9.5 SHIPPED)

v0.9.5 SHIPPED (tag `v0.9.5` at commit TBD). **Walk-through-
driven refinement + collaboration-primitives groundwork + 18
deferred review-finding closures.** 20th consecutive
PROCEED-CLEAN of v0.7.x → v0.8.x → v0.9.x line. First
direct-push ship cycle since the v0.9.x line began using PR
workflow (per the post-v0.9.4 lesson;
`enforce_admins: False` on branch protection always allowed
this).

**New public surfaces tested this cycle**:

| Surface | Test path | Coverage |
|---|---|---|
| `evidentia_core.security.atomic_write_text` | `tests/unit/test_security_atomic_write.py` (10 tests) | Basic write + overwrite + parent-dir create + custom encoding + package alias re-export; cleanup on write failure + replace failure + secondary-OSError suppression; no-partial-writes-observable invariant; `.tmp` suffix contract |
| `EVIDENTIA_TRUST_PROXY_HEADERS` + ProxyHeadersMiddleware auto-wire | `tests/integration/test_api/test_proxy_headers.py` (8 tests) | Off by default; explicit True; env-var "1"; env-var non-"1"; explicit False overrides env; smoke-test (no route break); middleware-stack inspection |
| `evidentia_core.rbac` package (Role / RBACPolicy / check_permission / load_policy_from_file) | `tests/unit/test_rbac.py` (21 tests) | Role hierarchy; policy resolution (known/unknown/None identity); default permissive; check_permission per action; deny + deny-by-default; unknown-action raise; YAML policy load; missing/invalid file raise; invalid role value raise; FastAPI `require_role()` dependency |
| `EvidenceArtifact.version` + `lineage_id` + `predecessor_id` + `new_version()` | `tests/unit/test_evidence_versioning.py` (7 tests) | Default-version-1 backward-compat; effective_lineage_id fallback; new_version bumps + fresh id + lineage preserved across chain; field-update overrides; v0.7.x → v0.9.4 JSON loads as v=1 |
| `GET /api/conmon/daemon-history?limit=N` + daemon `--history-file` | `tests/integration/test_api/test_conmon.py::TestDaemonHistoryEndpoint` + `TestDaemonHistoryHelpers` (8 tests) | 404 when env/file unset; 200 with snapshots; limit truncates to most recent; corrupt-line tolerance; append/read round-trip; max_entries cap; empty-file return |
| Prometheus `evidentia_conmon_daemon_*` gauges at `/api/metrics` | `tests/integration/test_api/test_conmon.py::TestMetricsConmonDaemonGauges` (2 tests) | Gauges absent without env; gauges present when status file readable (last_poll_age, last_poll_success, recognized_cadence_count, unknown_cadence_count, uptime) |
| POA&M `Milestone.owner` + `Milestone.reviewer` CLI filter | Existing `test_cli/test_poam.py` smoke-test sufficient | New `--owner X` + `--reviewer Y` flags route through existing rich-table path |
| POA&M REST `?owner=X&reviewer=Y` filter | Existing `test_api/test_poam.py` smoke-test sufficient | `_filter_poams()` honors new optional kwargs |
| Cross-process FileLock via `subprocess.Popen` | `tests/unit/test_security_file_lock.py::TestFileLockSubprocessPopen` (1 test) | Closes F-V94-Q10 — confirms FileLock honored across fully-independent Python interpreters, not just `multiprocessing.Pool` workers |
| Idempotency replay-after-target-deleted regression | `tests/integration/test_api/test_ai_gov.py::TestIdempotency::test_register_replay_after_delete_returns_null_entry` (1 test) | Closes F-V94-Q2 — same key + body after DELETE returns prior system_id with `entry: null` (NOT 500, NOT auto-recreate) |

**Adversarial probe coverage** for v0.9.5 surfaces averages
~6.5 / 7 applicable vectors. Highlights:

- **bad-input**: invalid YAML policy file raises; invalid Role
  value in policy raises; unknown action raises KeyError
- **race-condition**: atomic_write_text cleanup-on-OSError +
  no-partial-writes invariant; FileLock subprocess.Popen test
- **DoS**: rate-limit LRU eviction is idle-aware (closes
  F-V94-S3 IPv6-spray CWE-400); state-file size cap
  (F-V93-S7); SMTP recipient RFC 5321 validation rejects
  injection attempts; daemon history capped at
  `--history-max-entries`
- **path-traversal**: existing `validate_within` guards intact
  via `evidentia_core.security` package alias
- **auth bypass**: RBAC default policy is permissive (preserves
  v0.9.4 behavior); deny-by-default policy + `require_role`
  produces 403 + structured `detail.error="rbac_denied"`
  response shape

**Inherited surface re-validation** (carry-forward from v0.9.4):
no functional regressions in TPRM / model-risk / governance /
cloud-WORM / Sigstore eval / DFAH / PRT / MCP / POA&M / CONMON
read-only + REST router + daemon / AI governance core +
classification + catalog enrichment / FileLock / webhook SSRF /
rate-limit middleware / idempotency. The v0.9.5 deliverables
are wholly additive or backward-compat (default-off RBAC
policy file, Optional ownership fields on Milestone, default-
None lineage fields on EvidenceArtifact, default-off proxy-
headers trust, default-off history-file).

**Net test trajectory**: 2798 (v0.9.4) → 2862 (v0.9.5): +64
tests across ~10 new test classes. **Source files**: 219 → ~225
(+6 modules: `security/atomic_write.py`, `rbac/__init__.py`,
`rbac/policy.py`, `api/rbac_dependency.py`, plus extended
`evidence.py` + `conmon/daemon.py`).

---

*End of capability-matrix.md. Compiled 2026-04-25 as Step 4 deliverable
from the v0.7.0 comprehensive pre-tag review. Will be re-validated
on each future release per the [testing-playbook.md](testing-playbook.md)
operational test loop.*
