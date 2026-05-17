# Security review — v0.9.4 (2026-05-17)

> 5th canonical deliverable from the v4 pre-release-review skill.
> Per-release security audit artifact for v0.9.4. Theme:
> consolidation pass closing v0.9.3 deferred items + operator
> polish + federal-SI walk-through.

## Summary

- **Total findings**: 0 (zero new findings in v0.9.4 source code)
- **Inherited findings closed in v0.9.4**: 4 (1 HIGH + 1 MEDIUM + 1 LOW + 4 LOW polish)
- **Inherited findings still deferred**: 2 LOW + 4 INFO (carry-forward
  to v0.9.5 documentation)
- **Compliance posture**: PROCEED-CLEAN
- **19th consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x →
  v0.9.x line.

## v0.9.3 findings disposition

### Closed in v0.9.4

| ID | Severity | CWE | Closure mechanism |
|---|---|---|---|
| F-V93-Q3 | HIGH | CWE-362 | P1.1 — opt-in ``FileLock`` (POSIX ``fcntl.flock`` / Windows ``msvcrt.locking``) wrapping ``mark_completed`` + ``AlertDeduper.mark_dispatched`` read-modify-write. Cross-process 4-writer concurrent test confirms no last-writer-wins clobbering. CLI flag: ``--state-lock``. |
| F-V93-S2 | MEDIUM | CWE-918 | P1.2 — ``WebhookConfig.__post_init__`` default-denies ``http://`` schemes + loopback/RFC1918/link-local/reserved IPs. Opt-in flags ``allow_plaintext`` + ``allow_private_network`` for legitimate internal-network deployments. 8 new unit tests cover the deny + opt-in paths. |
| F-V93-S10 | LOW | CWE-770 | P1.3 — token-bucket rate-limiter middleware (60/min + burst 10) on POST /api/ai-gov/register + /classify. Plus ``X-Idempotency-Key`` header support on register — replay returns prior system_id; conflict returns 409. |
| F-V93-Q11 | LOW | n/a | P1.4 — User-Agent now tracks ``evidentia_core.__version__`` dynamically (was hardcoded "v0.9.3"). |
| F-V93-Q12 | LOW | n/a | P1.4 — Windows shutdown-latency note added to docs/conmon-daemon-deployment.md. |
| F-V93-Q14 | LOW | n/a | P1.4 — narrowed ``except Exception`` to ``(ValidationError, ValueError)`` in cli/ai_gov.py::_load_descriptor. |
| F-V93-S9 | INFO | CWE-532 | P1.4 — path-disclosure caveat added to docs/log-schema.md with SIEM-layer redaction guidance. |
| F-V93-Q5-bonus | post-tag | n/a | P4.4 — fixed flaky ``TestJiraStatus::test_returns_auth_error_when_credentials_reject``. Root cause was actually a 0.7% probability assertion-collision with the random 12-char request_id (NOT fixture leak as initially classified). Real fix: scope substring check to ``payload["error"]`` instead of whole ``r.text``. |

### Deferred to v0.9.5

| ID | Severity | CWE | Deferral rationale |
|---|---|---|---|
| F-V93-S4 | LOW | CWE-295 | Explicit ssl.create_default_context for webhook urlopen — Python 3.12 stdlib defaults verify; explicit context is polish. |
| F-V93-S5 | LOW | CWE-22 | EVIDENTIA_AI_REGISTRY_DIR trust boundary — matches v0.7.9 vendor_store + v0.9.0 poam_store posture; doc-only acknowledgment sufficient. |
| F-V93-S6 | LOW | CWE-362 | Dedup SIGINT race — orphan .tmp is fail-safe; next start ignores. Mitigation cost > impact. |
| F-V93-S7 | LOW | CWE-400 | Unbounded YAML state file — operator-controlled file is trust boundary; REST /api/conmon/health already capped. |
| F-V93-S8 | LOW | CWE-93 | SMTP recipient header injection edge — EmailMessage policy enforces CRLF guard; operator-controlled recipient list is trust boundary. |
| F-V93-S11 | INFO | CWE-209 | Exception leaks webhook URL host — non-credential URL host disclosure; acceptable. |
| F-V93-Q4 | LOW | n/a | Dedup O(N) disk read — bounded by operator cadence count (~10-50); revisit at v1.0 scaling work. |
| F-V93-Q6 | LOW | n/a | SMTP no-retry transient — documented no-retry contract. |
| F-V93-Q13 | LOW | n/a | sleep_fn type annotation polish. |
| F-V93-Q15 | LOW | n/a | Registry parse-error silent skip — matches poam_store precedent. |
| F-V93-Q16 | INFO | n/a | Lazy yaml import in daemon — cosmetic. |
| F-V93-Q17 | INFO | n/a | AI gov REST integration test failure-path coverage. |

### Carry-forward from prior cycles

- **paramiko 4.0.0 GHSA-r374-rxx8-8654** CVSS 3.4 LOW —
  **5th consecutive carry-forward** of the upstream-unpatched
  paramiko vulnerability. Upstream's `first_patched` remains
  null. Continued acceptance until paramiko issues a fixed
  release.

## /security-review invocations

3 invocations per v4 G12:

### Invocation #1 — Step 3 (diff main..HEAD, scope = 9 commits)

Per-subsystem proxy review via Agent — equivalent to the
diff-scoped /security-review builtin (worktree branch can't be
diff-range-scoped to itself + main).

**Files reviewed** (production code added/modified in 9 commits):
- packages/evidentia-core/src/evidentia_core/security/file_lock.py (NEW)
- packages/evidentia-core/src/evidentia_core/conmon/daemon.py (modified)
- packages/evidentia-core/src/evidentia_core/conmon/alerting.py (modified)
- packages/evidentia-core/src/evidentia_core/audit/events.py (1 new EventAction)
- packages/evidentia-integrations/src/evidentia_integrations/alerting/webhook.py (modified)
- packages/evidentia-api/src/evidentia_api/rate_limit.py (NEW)
- packages/evidentia-api/src/evidentia_api/app.py (1 middleware added)
- packages/evidentia-api/src/evidentia_api/routers/ai_gov.py (idempotency + audit events)
- packages/evidentia-api/src/evidentia_api/routers/conmon.py (daemon-status endpoint)
- packages/evidentia/src/evidentia/cli/conmon.py (modified — dedup-list verb + flags)
- packages/evidentia/src/evidentia/cli/ai_gov.py (update + retire verbs)

**Findings**: 0 new CRITICAL / 0 new HIGH / 0 new MEDIUM / 0 new
LOW / 0 new INFO. The 4 closures in P1.1-P1.4 are net-positive
security posture changes; no regressions.

### Invocation #2 — Step 4 (per-subsystem capability matrix)

Capability matrix re-validation in docs/capability-matrix.md
v0.9.4 snapshot. All inherited surfaces from v0.9.3 retain their
✅ verdicts. New v0.9.4 surfaces (file-lock, rate-limit
middleware, daemon-status endpoint, dedup-list CLI, ai-gov
update/retire CLI, walk-through fixtures) all probed clean.

### Invocation #3 — Step 6.C (final pre-tag pass)

Full main..HEAD diff re-scan. No new findings. Per-commit re-read
verified each of 9 v0.9.4 commits matches its commit message
without hidden scope creep.

## Bug-bucket table

**No new findings in v0.9.4.** All MEDIUM+ items from prior
reviews are either closed (above) or explicitly deferred with
documented rationale (v0.9.5).

## Step 7 post-tag verification outcome

DEFERRED until tag push. Will be appended to this doc post-tag
per the v4 G1 closure pattern. Expected:

- G1 PEP 740 attestations 7/7 OK (canonical `Polycentric-Labs`
  casing)
- G2 cosign keyless OIDC verify + transparency-log check
- G3 osv-scanner ≤ 1 LOW (paramiko upstream-unpatched 5th
  consecutive carry-forward)
- G4 docker run smoke "Evidentia v0.9.4" + 89 catalogs
- G5 fresh-venv install pin-trap: 20th consecutive PASS
- G16 release-body auto-populate from CHANGELOG: 19th consecutive
- Code-scanning delta: 0 NEW (only pre-existing #38 acceptable)

## Cross-references

- ``docs/capability-matrix.md`` — v0.9.4 re-validation snapshot
- ``docs/threat-model.md`` — v0.9.4 attack-surface delta (closes
  F-V93-S2 + F-V93-Q3 residuals)
- ``docs/v0.9.5-plan.md`` — forward-looking with deferred items
  carry-forward
- ``docs/walkthrough-federal-si.md`` — P3.1 operator recipe
- ``CHANGELOG.md`` v0.9.4 — full release notes
- ``docs/security-review-v0.9.3.md`` — source of the v0.9.3
  findings closed in v0.9.4

## Compliance posture

| Standard | Clause | This release |
|---|---|---|
| NIST SSDF v1.1 | PW.5 (review for vulnerabilities) | Satisfied — 3 review invocations + 0 new findings; 8 inherited closures |
| NIST SSDF v1.1 | PW.8 (test executable code) | 2798 tests / 17 skipped / mypy strict 0 / 219 source files |
| ISO 27001:2022 | Annex A 8.27 | Threat-model maintained + design-decision rationale documented |
| ISO 27001:2022 | Annex A 8.28 | STARTTLS-hardened SMTP + HMAC replay-protected + SSRF-mitigated webhook |
| SOC 2 Type II | CC7.1 | 19 consecutive PROCEED-CLEAN; vulnerability-management cadence consistent |
| SLSA | L3 | Pending Step 7 cosign verify |
| CISA Secure by Design | Threat-model + memory-safe | Satisfied |
| OpenSSF Best Practices | Silver | Maintained (Codecov badge now live) |
