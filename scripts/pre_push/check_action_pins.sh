#!/usr/bin/env bash
# scripts/pre_push/check_action_pins.sh — pre-push gate L2 check.
#
# Verifies that every `uses:` in .github/workflows/ pins its action to a
# full 40-char commit SHA (OSPS-VM-04 / Scorecard PinnedDependenciesID).
# Wraps `pinact run --check` in OFFLINE mode (no GitHub API calls) so the
# check is fast + works air-gapped.
#
# pinact is a Go binary (github.com/suzuki-shunsuke/pinact). Per the
# v0.10.7 D5 decision, this repo does NOT auto-install it. If pinact is
# not on PATH the check SKIPs with a nag (exit 0) rather than BLOCKS —
# we don't want to block a push on a missing optional dev tool, but we
# do want to remind the operator to install it. When pinact IS present,
# an unpinned action BLOCKS the push (exit 1).
#
#   SKIP  (exit 0) — pinact not installed (with install instructions).
#   PASS  (exit 0) — pinact installed; all actions SHA-pinned.
#   BLOCK (exit 1) — pinact installed; one or more unpinned actions.
#
# Install pinact (one of):
#   winget install Suzuki-Shunsuke.pinact
#   go install github.com/suzuki-shunsuke/pinact/v2/cmd/pinact@latest
# See docs/pre-push-gate.md for details.
#
# NB: the exact `pinact run --check` offline flag form below is written
# to the documented pinact v4+ CLI. pinact was NOT installed in the dev
# environment when this script was authored, so the flag form could not
# be live-verified; the `pinact --help` discovery branch below adapts at
# runtime if the installed pinact uses a different offline flag.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKFLOWS_DIR="${REPO_ROOT}/.github/workflows"

if ! command -v pinact >/dev/null 2>&1; then
    cat >&2 <<'EOF'
SKIP check_action_pins: pinact not found on PATH.
  pinact validates that .github/workflows/ actions are SHA-pinned
  (OSPS-VM-04). It is an optional Go binary; install it to enable
  this pre-push check:
    winget install Suzuki-Shunsuke.pinact
    go install github.com/suzuki-shunsuke/pinact/v2/cmd/pinact@latest
  See docs/pre-push-gate.md. (Not installed -> SKIP, not BLOCK.)
EOF
    echo "SKIP check_action_pins (pinact missing)"
    exit 0
fi

if [ ! -d "${WORKFLOWS_DIR}" ]; then
    echo "SKIP check_action_pins (no .github/workflows/ directory)"
    exit 0
fi

cd "${REPO_ROOT}"

# Determine the offline flag this pinact build supports. pinact v3+ uses
# `--check` (verify-only, non-zero on unpinned) and historically gated
# network lookups behind the absence of a token, but newer builds expose
# an explicit offline switch. Probe `pinact run --help` once and pick the
# offline flag if present; otherwise run `--check` with no GH token in the
# environment so it cannot reach the API.
offline_flag=""
help_text="$(pinact run --help 2>&1 || true)"
if printf '%s' "${help_text}" | grep -q -- "--no-api"; then
    offline_flag="--no-api"
fi

echo "Running pinact run --check ${offline_flag} on .github/workflows/ ..."

# Run pinact with no GitHub token in the environment so it cannot make
# authenticated API calls. `--check` makes pinact verify-only (it does
# not rewrite files) and exit non-zero when an action is not SHA-pinned.
set +e
if [ -n "${offline_flag}" ]; then
    env -u GITHUB_TOKEN -u GH_TOKEN pinact run --check "${offline_flag}"
    rc=$?
else
    env -u GITHUB_TOKEN -u GH_TOKEN pinact run --check
    rc=$?
fi
set -e

if [ "${rc}" -ne 0 ]; then
    cat >&2 <<'EOF'

BLOCK check_action_pins: pinact reported unpinned action(s).
  Every `uses:` in .github/workflows/ must pin a full 40-char commit
  SHA (with a `# vX.Y.Z` trailing comment). Run `pinact run` locally
  to auto-pin, review the diff, and re-commit. See docs/pre-push-gate.md.
EOF
    echo "BLOCK check_action_pins"
    exit 1
fi

echo "PASS check_action_pins (all actions SHA-pinned)"
exit 0
