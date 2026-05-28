# Pre-push gate

> Local, blocking quality gate that runs on `git push` before any commits
> leave the machine. Introduced in v0.10.7 (Phase D5) as the structural
> defense against pushing a change that would fail CI, leak a secret, or
> ship a version bump without a CHANGELOG block.
>
> Cross-link to: [release-checklist.md](release-checklist.md) (the
> per-release runbook whose pre-tag gates this hook mirrors locally) and
> [ide-setup.md](ide-setup.md) (the commit-time `.pre-commit-config.yaml`
> hooks, a separate layer — see "Why hand-rolled" below).

---

## The three-layer design

The pre-push gate was specified as three layers. **Only Layer 2 ships in
v0.10.7.** Layers 1 and 3 are explicitly deferred.

| Layer | Purpose | Status |
|---|---|---|
| **L1 — local Scorecard sweep** | Run an OpenSSF Scorecard pass locally before push | **DEFERRED to v0.10.8+** — duplicates the scheduled CI Scorecard workflow with no new signal |
| **L2 — blocking checks** | 7 fast checks that BLOCK the push on failure | **SHIPPED v0.10.7** |
| **L3 — warning-only** | actionlint + online pinact advisories | **DEFERRED to v0.10.8+** — catches syntax errors the GitHub Actions UI already surfaces |

The marginal value of L1 + L3 did not justify the added push latency +
maintenance for this cycle. They may return if a concrete failure pattern
justifies them.

---

## Layer 2 — the seven blocking checks

The orchestrator is [`.githooks/pre-push`](../.githooks/pre-push). It runs
every check below, collects the failures, and exits non-zero if any
blocking check failed — so a single push surfaces **all** problems at once,
not just the first. Each individual check lives under `scripts/pre_push/`
(or reuses an existing repo script).

| # | Check | Script | Blocks on |
|---|---|---|---|
| 1 | `check_action_pins` | `scripts/pre_push/check_action_pins.sh` | an unpinned `uses:` in `.github/workflows/` (only when `pinact` is installed — see below) |
| 2 | `check_secrets` | `scripts/pre_push/check_secrets.sh` | a secret-shaped filename or content pattern in the push range |
| 3 | `check_changelog_present` | `scripts/pre_push/check_changelog_present.py` | a `pyproject.toml` version bump with no matching `## [X.Y.Z]` CHANGELOG block |
| 4 | `check_docs_health` | `scripts/check_docs_health.py --strict` | any doc-health FAIL (exit 2) |
| 5 | `check_workflow_perms` | `scripts/audit_workflow_permissions.py --strict` | an un-justified workflow `write` permission (exit 2) |
| 6 | `check_uv_lock_pin_drift` | `scripts/pre_push/check_uv_lock_pin_drift.py` | a third-party pin that moved alongside a workspace version bump |
| 7 | `check_osps_crosswalk_drift` | `scripts/catalogs/gen_osps_crosswalks.py --check` | OSPS crosswalk drift (only when an OSPS file is in the push range) |

### 1. check_action_pins — and the pinact SKIP-vs-BLOCK rule

`check_action_pins` wraps [`pinact`](https://github.com/suzuki-shunsuke/pinact)
in offline mode (`pinact run --check`, no GitHub API calls) to verify every
action `uses:` is pinned to a full 40-char commit SHA (OSPS-VM-04 /
Scorecard `PinnedDependenciesID`).

`pinact` is a Go binary and is **not auto-installed** by this repo. The
SKIP-vs-BLOCK rule is deliberate:

- **pinact not on PATH → SKIP with a nag (exit 0, does NOT block).** We do
  not want to block a routine push on a missing optional dev tool. The
  check prints install instructions and lets the push proceed; CI's
  Scorecard workflow remains the backstop.
- **pinact installed + an unpinned action → BLOCK (exit 1).**

Install pinact (one of):

```bash
winget install Suzuki-Shunsuke.pinact
go install github.com/suzuki-shunsuke/pinact/v2/cmd/pinact@latest
```

> Implementation note: pinact was not installed in the environment where
> this check was authored, so the exact offline-flag form
> (`pinact run --check`, with a `--no-api` probe) was written to the
> documented pinact v4+ CLI rather than live-verified. The script probes
> `pinact run --help` at runtime and adapts if the installed build exposes
> a different offline flag.

### 2. check_secrets — never leaks the value

`check_secrets` scans the files in the push range for:

- **Filename patterns**: `.env`, `.env.*` (except `.env.example` /
  `.env.template`), `*.pem`, `*.key`, `*.pfx`, `*.p12`, and SSH key names
  (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`).
- **Content patterns**: AWS access key (`AKIA…`), GitHub PAT (`ghp_…`),
  and PEM `-----BEGIN … PRIVATE KEY-----` blocks.

**The script never prints, echoes, or otherwise surfaces the matched
secret value or the file's contents.** It reports only the filename + the
pattern-type that matched (for example, `potential AWS access key in
config/foo.txt`). Content scans always use `grep -l` (filenames-only) so a
matching line is never echoed. This is a hard requirement: a secret-scanner
that leaks the secret in its error output is worse than no scanner.

### 6. check_uv_lock_pin_drift

Guards against the v0.10.0 third-party-pin-over-bump pattern: a workspace
version bump (the 8 `evidentia-*` packages plus the workspace root) must
not drag any third-party (registry-sourced) pin in `uv.lock`. The check
only fires when `uv.lock` changed in the range AND a workspace version
moved; it then BLOCKs if any existing third-party pin's version also moved.
A genuine dependency add/remove is not flagged (only version movement of an
existing pin). Commit a deliberate dependency change separately from a
version bump.

### 7. check_osps_crosswalk_drift

Runs `gen_osps_crosswalks.py --check` only when a
`mappings/osps-baseline_*.json` or `_osps_upstream.py` file is in the push
range (skipped otherwise for speed). Pre-push is the architecturally
correct home for this drift gate rather than CI: the regenerator needs the
`.local/`-cached upstream OSPS YAMLs (or a live `gh api` fetch), which a
clean CI runner would not have without an extra fetch + auth step.

---

## Activation

The gate activates the same way as the existing `commit-msg` hook —
through `core.hooksPath`:

```bash
bash scripts/setup-githooks.sh
```

This sets `git config core.hooksPath .githooks` and marks every script in
`.githooks/` (including `pre-push`) executable. No change to the setup
script was needed when `pre-push` was added — it already chmod's and
activates every file in `.githooks/`.

Verify:

```bash
git config core.hooksPath        # should print: .githooks
ls -la .githooks/                # pre-push + commit-msg, both +x
```

---

## Bypass mechanism

The gate is bypassable in an emergency, but a bypass **requires a reason**
and is **logged**.

```bash
EVIDENTIA_ALLOW_PRE_PUSH_BYPASS=1 \
EVIDENTIA_PRE_PUSH_BYPASS_REASON="why this bypass is justified" \
git push ...
```

- The env var `EVIDENTIA_ALLOW_PRE_PUSH_BYPASS=1` requests the bypass.
- A reason is mandatory. Supply it via `EVIDENTIA_PRE_PUSH_BYPASS_REASON`,
  or — when a terminal is attached — the hook prompts for it on `/dev/tty`.
- If the bypass is requested non-interactively **with no reason env var,
  the bypass is REFUSED** (the hook exits non-zero). This prevents a silent
  unreasoned bypass in CI or scripts.

Every bypass appends a JSONL row to `.local/hooks/pre-push-bypass.log`
(the `.local/` directory is gitignored, so the log never enters the repo):

```json
{"timestamp": "2026-06-10T12:00:00Z", "user": "Allen Byrd", "branch": "main", "reason": "...", "head": "<sha>"}
```

Per the publishing-authority protocol, bypassing the gate does not bypass
the push approval itself — a push to a remote is still a deliberate,
explicitly-approved action.

---

## Why hand-rolled, not the pre-commit framework

This repo sets `git config core.hooksPath .githooks` and ships a
hand-rolled [`.githooks/commit-msg`](../.githooks/commit-msg). The
pre-commit framework installs its shims into `.git/hooks/`, which git
**ignores** when `core.hooksPath` points elsewhere — so a pre-commit
`stages: [pre-push]` hook would never fire here. The pre-push gate is
therefore implemented directly as `.githooks/pre-push`, consistent with the
existing `commit-msg` hook.

Benefits of the hand-rolled approach for this repo:

- **Consistency** with the existing `.githooks/commit-msg` pattern.
- **No `core.hooksPath` conflict** — the framework's `.git/hooks/` shims
  would be silently ignored.
- **No new framework dependency** in the push path — valuable for a
  security-tooling project's supply chain.
- `scripts/setup-githooks.sh` already activates everything in `.githooks/`.

The repo's `.pre-commit-config.yaml` still serves the **commit-time** hooks
(ruff, mypy, yamllint, markdownlint, the keyword sweep) for contributors
who run `pre-commit install`; that is an independent, optional layer. The
pre-push gate does not depend on it.
