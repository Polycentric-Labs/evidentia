# Security review — v0.10.2

> **Status**: in-cycle artifact for the v0.10.2 ship — the v4
> pre-release-review's 5th canonical deliverable.
>
> **Theme**: MCP-as-backend tool surface expansion + GRC Engineering
> Club marketplace plugin (staged) + close the v0.10.1 F-V101-L1
> SSRF surface.

## Cycle scope

v0.10.2 is the second patch on the v0.10.x line (third ship on
2026-05-23 — same calendar day as v0.10.0 + v0.10.1). The
[`docs/v0.10.2-plan.md`](v0.10.2-plan.md) 3 phases:

1. **MCP tool surface expansion**: 4 new tools
   (`gap_analyze_sarif`, `collect_ocsf`, `tprm_vendor_list`,
   `poam_list`) added to `evidentia_mcp.server._register_tools`.
   Append-only per the §MCP tool contract; the 8 prior tools stay
   frozen. Brings the MCP surface from 8 → 12 tools.
2. **GRC Engineering Club marketplace plugin** staged in
   `marketplace/grc-engineering-suite/plugins/evidentia/` —
   manifest matches upstream `plugin.json` schema; 2 generalist OSS
   commands. **OSS-vs-paid scope decision locked at Phase 2 entry:
   generalist OSS only** (TPRM / federal / model-risk persona
   commands reserved for the future Pro / Federal commercial tier).
   Upstream PR is a separate publishing action.
3. **F-V101-L1 SSRF hardening**: new `--block-private-ips` flag on
   `evidentia collect ocsf` URL mode (and `block_private_ips: bool
   = True` kwarg on `collect_ocsf_url`). Rejects RFC1918 +
   link-local + loopback + multicast + reserved ranges via
   `socket.getaddrinfo` pre-resolution before opening the socket.

## Review structure

v0.10.2 was reviewed under the v4 default pre-tag variant with the
Diff + 1-hop dep closure scope (Step 1.4 option 1). The changeset
is on `main` (local), so `/security-review` and `/code-review` use
direct delta inspection per the v0.9.8 / v0.9.9 / v0.10.0 / v0.10.1
precedent.

| Pass | Scope | Verdict |
|---|---|---|
| 3 — commit re-test + 1-hop closure | 4 unpushed commits (3 v0.10.2 phases + 1 positioning skip-by-reuse). 7 importer files inspected via 1-hop closure on `evidentia_mcp.server` + `collect_ocsf_url`. | PROCEED-CLEAN |
| 4 — capability matrix (REUSE + delta) | v0.10.0 + v0.10.1 matrices reused for unchanged subsystems; v0.10.2 PRE-TAG section added with 7 new + 1 modified surface + 10-vector adversarial probe table. | PROCEED-CLEAN |
| 6.C — final pre-tag pass | Pending (see §"16-row pre-push gate" below — filled at Step 6 entry). | TBD |

## Findings ledger

**Zero NEW findings.** F-V101-L1 (v0.10.1 LOW) CLOSED by Phase 3.

| ID | Bucket | Closure |
|---|---|---|
| **F-V101-L1** (LOW, SSRF) | LOW | **CLOSED** by Phase 3 `--block-private-ips` flag (default True). Pre-resolution via `socket.getaddrinfo` rejects RFC1918 / link-local / loopback / multicast / reserved before any socket opens. Adversarial close-out test (`test_block_private_ips_rejects_aws_metadata_endpoint`) confirms 169.254.169.254 is blocked. |

**Cumulative finding state at v0.10.2 ship**:

| Finding | Severity | State |
|---|---|---|
| F-V100-L1 (v0.10.0, trust-boundary) | LOW | CLOSED v0.10.1 Phase 1 |
| F-V100-M1 (v0.10.0, release tooling) | MEDIUM | CLOSED v0.10.1 Phase 5 |
| F-V100-S1 (v0.10.0, starlette CVE) | MEDIUM | CLOSED at v0.10.0 ship |
| F-V101-L1 (v0.10.1, SSRF) | LOW | **CLOSED v0.10.2 Phase 3** |
| paramiko CVE-2026-44405 | LOW | CLOSED v0.9.9 |
| pyjwt PYSEC-2025-183 | DISPUTED | Allowlisted (`ignoreUntil=2026-11-21`) |

**Zero unfixed CRITICAL / HIGH / MEDIUM / LOW** at v0.10.2 pre-tag.

## Security category sweep — direct delta inspection

| Category | v0.10.2 verdict |
|---|---|
| Injection (SQL/shell/path) | NONE in v0.10.2 code |
| Deserialization | Pydantic `model_validate` only (MCP tools wrap existing safe code paths) |
| Weak crypto | None added |
| Secret exposure | No new credential handling; MCP tools enforce the no-creds-in-tool-args policy |
| Authz bypass | No new auth surface; MCP tools inherit the v0.8.2 `--allow-root` path-validation closure when set |
| Trust boundary | **F-V101-L1 CLOSED**; MCP `collect_ocsf` tool deliberately hardens out URL ingest at the AI-client boundary by construction |
| Supply chain | **Zero new third-party deps in v0.10.2** |
| DoS / resource exhaustion | MCP tools wrap bounded existing functions; SSRF check adds 1 DNS resolution (system-default timeout); URL ingest cap unchanged (50 MB) |
| Regex / ReDoS | No new regex |
| **DNS rebinding (NEW threat-model note, NOT a finding)** | Out of scope. Single DNS pre-resolve is appropriate for the F-V101-L1 operator-typo threat model; IP-pin + Host-header defense would mitigate the DNS-rebinding case if the threat model expands in a future release. |

## `/security-review` + `/code-review`

Direct delta inspection per the v0.10.0 / v0.10.1 precedent. Of the
4 `/code-review` auto-fire triggers:

| Trigger | Fired? | Detail |
|---|---|---|
| 1 — new public API/CLI/route | NO | `@server.tool()` decorators don't match the trigger-1 regex (`@router.|@app.|@cli.command|class.*BaseModel`); the `--block-private-ips` CLI flag is added to an EXISTING `@app.command("ocsf")`, not a new command. |
| 2 — new file under `packages/*/src/` | NO | All v0.10.2 changes are INSIDE existing source files (MCP tools in `server.py`, SSRF helper in `collector.py`); marketplace plugin is under `marketplace/`, not `packages/*/src/`. |
| 3 — >500 LOC delta | **YES** | 924 LOC total — dominated by Phase 2's 378 LOC of marketplace docs (pure markdown / JSON) + Phase 1's 357 LOC (4 MCP tools + 11 tests). Code-only LOC ~493. Direct inspection covered every code-bearing change. |
| 4 — security subsystem touched | NO | No paths matching `security/ | network_guard | oscal/(signing|sigstore) | secret | audit`. Phase 3's SSRF hardening touches `collectors/ocsf/collector.py` which isn't in those paths but IS the F-V101-L1 close-out — reviewed thoroughly nonetheless. |

## 16-row pre-push gate (Step 6.C — filled at Step 6 entry)

_Filled by Step 6 when the 16-row gate runs against the final
release-prep state (post-version-bump, post-CHANGELOG-rename)._

## Standards alignment

Same as v0.10.0 / v0.10.1 — NIST SSDF PW.5 / PS.3; OpenSSF Best
Practices Silver; ISO 27001:2022 A.8.27 + SOC 2 Type II CC7.1; CISA
Secure-by-Design (default-secure SSRF block, opt-out via explicit
`--allow-private-ips`).

## Cross-references

- [`docs/v0.10.2-plan.md`](v0.10.2-plan.md) — phase-by-phase scope.
- [`docs/v0.10.2-marketplace.md`](v0.10.2-marketplace.md) — GRC
  Engineering Club marketplace plugin staging + upstream PR plan +
  standing OSS-vs-paid policy for future v0.10.x / v0.11.x scope
  decisions.
- [`docs/v0.10.3-plan.md`](v0.10.3-plan.md) — forward-looking
  next-release scope.
- [`docs/ocsf-mapping.md`](ocsf-mapping.md) — OCSF mapping reference
  (unchanged in v0.10.2).
- [`docs/api-stability.md`](api-stability.md) — §MCP tool contract
  now lists the 4 new v0.10.2 tools; revision-history row added.
- [`docs/capability-matrix.md`](capability-matrix.md) — v0.10.2
  PRE-TAG snapshot.
- [`docs/threat-model.md`](threat-model.md) — v0.10.2 attack-surface
  delta section.
- `.local/pre-release-review/runs/2026-05-23T06-25-00Z.json` — per-run
  log (27th in the series).
