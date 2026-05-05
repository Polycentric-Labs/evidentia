#!/usr/bin/env bash
# v0.7.15 P0.3 + v0.7.16 P1: standing-rule keyword sweep.
#
# Scans the supplied file paths (passed as positional args by
# pre-commit) for the canonical 21-pattern forbidden-token set. Any
# hit prints the offending file + line + token and exits non-zero
# (blocking the commit).
#
# The pattern set comes from the project's standing rule on
# absolute-secrecy posture: certain tokens must never appear on
# public-bound surfaces. Pre-v0.7.15 the sweep ran only as a
# pre-push gate (per the publishing-authority protocol); this hook
# extends it to pre-commit so CI never sees a leak in the first
# place.
#
# Hook stages (v0.7.16):
#   - `standing-rule-sweep` — commit stage; scans STAGED FILE
#     CONTENT (file diff). Catches leaks in code, docs, configs.
#   - `standing-rule-sweep-msg` — commit-msg stage; scans the
#     COMMIT MESSAGE BODY (.git/COMMIT_EDITMSG) for the same
#     pattern set. Catches the specific class of leak that
#     produced the v0.7.13-cycle commit-message-body incident
#     (text only in the message body, not in any tracked file).
#
# Both stages call this same script with positional file paths;
# the script doesn't need to distinguish between the two — a
# COMMIT_EDITMSG file is just another text file from its perspective.
#
# Usage (manual):
#   bash scripts/standing_rule_sweep.sh path/to/file [path/to/file...]
#
# Whole-repo audit (manual):
#   git ls-files | xargs bash scripts/standing_rule_sweep.sh
#   # OR
#   pre-commit run standing-rule-sweep --all-files

set -euo pipefail

# The 21-pattern guard. Each entry is a literal substring (case-
# insensitive match below). Add to this list when a new
# vocabulary item joins the standing rule.
PATTERNS=(
  "Pro tier"
  "Enterprise tier"
  "paid version"
  "open-core"
  "license key"
  "Wexler"
  "Consultant Pack"
  "Booz Allen"
  "SAIC"
  "Leidos"
  "GDIT"
  "Peraton"
  "evidentia-pro"
  "Haleliuk"
  "Capital One"
  "TDRM"
  "R235944"
  "Workday"
  "Pasha"
  "interview prep"
  "allenfbyrd@gmail"
)

# Files to skip — known false-positive sources where the tokens
# appear legitimately by definition (THIS script declares the
# PATTERNS array literally). Excluding self-references avoids the
# script flagging itself.
#
# v0.7.16 update: removed `.pre-commit-config.yaml` from SKIP_FILES
# after paraphrasing the previously-leaked phrase out of its
# documentation comment. The config file no longer contains any
# of the forbidden tokens, so the sweep runs against it normally.
SKIP_FILES=(
  "scripts/standing_rule_sweep.sh"
)

found_hit=0
for f in "$@"; do
  # Skip directories, missing files, binary content.
  if [[ ! -f "$f" ]]; then continue; fi
  if file --mime "$f" 2>/dev/null | grep -q "charset=binary"; then continue; fi

  # Skip self-references that legitimately contain the patterns.
  for skip in "${SKIP_FILES[@]}"; do
    if [[ "$f" == "$skip" ]]; then
      continue 2
    fi
  done

  # Skip plan-mode private files (.local/ + ~/.claude/plans/) —
  # these are gitignored anyway but pre-commit may receive them
  # if a contributor tries to stage them by accident. The sweep
  # surfaces would land via git-ignore rather than this script.
  case "$f" in
    .local/*) continue ;;
    *.claude/plans/*) continue ;;
  esac

  # Build a per-line patterns file + use `grep -F -f -` to scan all
  # 21 patterns in one pass. The previous attempt (`grep -F` with a
  # multi-line string arg) treated the whole block as a single
  # literal sequence — a known footgun. `printf '%s\n' "${arr[@]}"`
  # piped to `-f -` is the canonical fix.
  if matches=$(printf '%s\n' "${PATTERNS[@]}" | grep -n -i -F -f - "$f" 2>/dev/null); then
    while IFS= read -r line; do
      echo "::error::$f:$line"
      found_hit=1
    done <<< "$matches"
  fi
done

if [[ $found_hit -eq 1 ]]; then
  cat >&2 <<EOF

ERROR: standing-rule keyword sweep found hits.

Per the project's absolute-secrecy posture, the 21 forbidden
tokens must never appear on public-bound surfaces (code, docs,
config, commit messages). Review the lines above and either:

1. Remove the offending content
2. Move the content to .local/ (gitignored private notes)
3. If genuinely a false-positive, add the file to SKIP_FILES
   in this script with documented rationale

Block the commit by default. Use `git commit --no-verify` ONLY
if Allen has explicitly approved the override.

EOF
  exit 1
fi

exit 0
