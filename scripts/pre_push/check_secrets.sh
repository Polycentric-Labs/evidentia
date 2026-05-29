#!/usr/bin/env bash
# scripts/pre_push/check_secrets.sh — pre-push gate L2 check.
#
# Scans the files in the push range (or, as a fallback, all tracked
# files) for accidentally-committed secrets:
#
#   Filename patterns:  .env, .env.*, *.pem, *.key, *.pfx, *.p12,
#                       id_rsa, id_dsa, id_ecdsa, id_ed25519
#   Content patterns:   AWS access key   AKIA[0-9A-Z]{16}
#                       GitHub PAT        ghp_[A-Za-z0-9]{36}
#                       PEM private key   -----BEGIN ... PRIVATE KEY-----
#
# BLOCK (exit 1) on any match. PASS (exit 0) when clean.
#
# Known-placeholder allowlist (AWS-key check only): the AWS access-key
# pattern is value-precise — a match whose token is one of AWS's published
# documentation example keys (AKIAIOSFODNN7EXAMPLE / AKIAI44QH8DHBEXAMPLE)
# is NOT a real credential and does NOT block, so security docs that teach
# about AWS keys are not false-positived. A real AKIA+16-random key in the
# SAME file still blocks (the filter removes only the exact placeholder
# tokens, never the whole AWS-key check). Mirrors what gitleaks /
# trufflehog / detect-secrets do. The GitHub-PAT + PEM checks have no
# analogous well-known example, so they remain plain filename-only scans.
#
# CRITICAL — secret-handling protocol (~/.claude/CLAUDE.md):
#   This script MUST NEVER print, echo, or otherwise surface the matched
#   secret value or the offending file's contents. It reports ONLY the
#   filename + the pattern-TYPE that matched (e.g. "potential AWS access
#   key in config/foo.txt"). A scanner that leaks the secret in its error
#   output is worse than no scanner. `grep` is therefore always invoked
#   with `-l` (filenames-only) for content scans — never a mode that
#   echoes matching lines.
#
# Range selection:
#   Args $1=<range_base_sha> $2=<range_tip_sha> select the commit range
#   to scan (the orchestrator passes the resolved push range). When the
#   base is empty / all-zeros (new branch) or the range is unavailable,
#   the script falls back to scanning all tracked files.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

RANGE_BASE="${1:-}"
RANGE_TIP="${2:-}"

ZERO_SHA="0000000000000000000000000000000000000000"

# Build the list of files to scan. Prefer the push range (only the files
# actually being pushed); fall back to all tracked files.
files=()
use_range=0
if [ -n "${RANGE_BASE}" ] && [ "${RANGE_BASE}" != "${ZERO_SHA}" ] \
   && [ -n "${RANGE_TIP}" ] && [ "${RANGE_TIP}" != "${ZERO_SHA}" ]; then
    if git rev-parse --verify --quiet "${RANGE_BASE}^{commit}" >/dev/null \
       && git rev-parse --verify --quiet "${RANGE_TIP}^{commit}" >/dev/null; then
        use_range=1
    fi
fi

if [ "${use_range}" -eq 1 ]; then
    # Names of files added/copied/modified/renamed in the range (no deletes).
    while IFS= read -r f; do
        [ -n "${f}" ] && files+=("${f}")
    done < <(git diff --name-only --diff-filter=ACMR "${RANGE_BASE}" "${RANGE_TIP}")
else
    while IFS= read -r f; do
        [ -n "${f}" ] && files+=("${f}")
    done < <(git ls-files)
fi

if [ "${#files[@]}" -eq 0 ]; then
    echo "PASS check_secrets (no files in range)"
    exit 0
fi

found_hit=0

# ---------------------------------------------------------------------------
# 1. Filename-pattern scan. Report the FILENAME + which class matched;
#    never open the file.
# ---------------------------------------------------------------------------
for f in "${files[@]}"; do
    base="$(basename -- "${f}")"
    case "${base}" in
        # .env and .env.* — but allow the documented templates.
        .env.example|.env.template) : ;;
        .env|.env.*)
            echo "BLOCK check_secrets: dotenv file in push range: ${f}" >&2
            found_hit=1
            ;;
    esac
    case "${base}" in
        *.pem|*.key|*.pfx|*.p12)
            echo "BLOCK check_secrets: key/cert file in push range: ${f}" >&2
            found_hit=1
            ;;
        id_rsa|id_dsa|id_ecdsa|id_ed25519)
            echo "BLOCK check_secrets: SSH private-key file in push range: ${f}" >&2
            found_hit=1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# 2. Content-pattern scan. `grep -l` prints ONLY the filename, never the
#    matched line — this is load-bearing for the secret-handling protocol.
#    Skip files that no longer exist in the working tree (range may include
#    a path later deleted) and binary files.
# ---------------------------------------------------------------------------

# Self-exclusion: files that legitimately contain the literal pattern
# STRINGS by definition — this script (which declares the regexes) and the
# doc that documents the patterns. Same self-reference problem the
# standing_rule_sweep.sh SKIP_FILES list solves; without this the content
# scan would flag its own source/doc (SF-11: a guard matching the very
# patterns it declares). Matched against the repo-relative path.
CONTENT_SCAN_SELF_EXCLUDE=(
    "scripts/pre_push/check_secrets.sh"
    "docs/pre-push-gate.md"
)

# Known-placeholder allowlist for the AWS access-key check. These are AWS's
# own published documentation example keys — they match the AKIA regex but
# are never valid credentials. A match is suppressed ONLY when its token IS
# one of these exact values; any other AKIA+16 token still blocks. This is
# value-precise: detection of real keys is fully intact.
# Ref: https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
AWS_KEY_ALLOWLIST=(
    "AKIAIOSFODNN7EXAMPLE"
    "AKIAI44QH8DHBEXAMPLE"
)

# Patterns: a human label + the ERE. Self-documenting; the label is what
# the operator sees, the regex never is.
scan_content() {
    local label="$1"
    local regex="$2"
    local f="$3"
    # -I skips binary; -l prints filename only; -E extended regex; -q would
    # suppress the filename, so use -l and discard via redirect-to-test.
    if grep -I -l -E -- "${regex}" "${f}" >/dev/null 2>&1; then
        echo "BLOCK check_secrets: potential ${label} in ${f}" >&2
        return 0  # hit
    fi
    return 1  # no hit
}

# AWS access-key scan WITH a known-placeholder allowlist. Unlike scan_content
# (filename-only), this must inspect the matched TOKENS to decide whether they
# are real or documented examples. To preserve the no-echo protocol it uses
# `grep -o` to extract ONLY the matched AKIA tokens (never the surrounding
# line / file contents), filters out the allowlisted placeholders, and blocks
# only if a non-placeholder token remains. The token value itself is NEVER
# printed — output is still just the filename + the "AWS access key" label.
scan_aws_key() {
    local f="$1"
    local regex='AKIA[0-9A-Z]{16}'
    # Extract only the matched tokens (-o), binary-safe (-I). No matches -> ok.
    local matches
    matches="$(grep -I -o -E -- "${regex}" "${f}" 2>/dev/null || true)"
    [ -z "${matches}" ] && return 1  # no hit

    # Keep only tokens that are NOT in the placeholder allowlist. A real key
    # survives this filter; a documented example is dropped.
    local tok
    while IFS= read -r tok; do
        [ -n "${tok}" ] || continue
        local allowed=0
        local ex
        for ex in "${AWS_KEY_ALLOWLIST[@]}"; do
            if [ "${tok}" = "${ex}" ]; then allowed=1; break; fi
        done
        if [ "${allowed}" -eq 0 ]; then
            # A non-placeholder AWS-key token remains -> block. Report the
            # FILENAME + label only; never the token value.
            echo "BLOCK check_secrets: potential AWS access key in ${f}" >&2
            return 0  # hit
        fi
    done <<< "${matches}"

    return 1  # every match was an allowlisted placeholder -> no hit
}

for f in "${files[@]}"; do
    # Only scan regular files that still exist in the working tree.
    [ -f "${f}" ] || continue
    # Skip the self-reference files (they declare/document the patterns).
    skip_self=0
    for ex in "${CONTENT_SCAN_SELF_EXCLUDE[@]}"; do
        if [ "${f}" = "${ex}" ]; then skip_self=1; break; fi
    done
    [ "${skip_self}" -eq 1 ] && continue
    if scan_aws_key "${f}"; then found_hit=1; fi
    if scan_content "GitHub personal access token" 'ghp_[A-Za-z0-9]{36}' "${f}"; then found_hit=1; fi
    if scan_content "PEM private key block" '-----BEGIN .*PRIVATE KEY-----' "${f}"; then found_hit=1; fi
done

if [ "${found_hit}" -eq 1 ]; then
    cat >&2 <<'EOF'

BLOCK check_secrets: one or more potential secrets in the push range.
  Only the FILENAME + pattern-type is shown above (never the value, per
  the secret-handling protocol). Remove the file/value, rotate the
  credential if it was ever committed, and verify .gitignore covers it.
  See docs/pre-push-gate.md.
EOF
    echo "BLOCK check_secrets"
    exit 1
fi

echo "PASS check_secrets (${#files[@]} file(s) scanned, no secrets)"
exit 0
