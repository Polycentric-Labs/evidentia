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
  # Finite publisher-data approval: changed bytes, rules, or counts are refused.
  case "$f" in
    packages/evidentia-collectors/src/evidentia_collectors/registries/data/fedramp/snapshot.json|tests/fixtures/registries/fedramp/full-source-tuples.json)
      if uv run --no-sync python - "$f" "${PATTERNS[@]}" <<'EVIDENTIA_REVIEWED_PUBLISHER_BYTES'
# A finite exception must match bytes, the complete rule set, and every count.
import hashlib
import subprocess
import sys

FILES = {
    "packages/evidentia-collectors/src/evidentia_collectors/registries/data/fedramp/snapshot.json": {
        "bytes": 976293,
        "sha256": "d37fdce16b3d497ea12a71757878a36397260fb6940a504d4ba34d4f88c2d99b"
    },
    "tests/fixtures/registries/fedramp/full-source-tuples.json": {
        "bytes": 1535178,
        "sha256": "11a62feef97245ead1ef1f40e90ae48a0074007e4b1508d7ab4345643b0685f7"
    }
}
RULE_HASHES = [
    "a6f100232f151ffd67788e572ac1cec6232feb22e2c2b4afcbf290ed16ae98a2",
    "0e2bbe6e356bc1fa1df4007d980049c24905dcfd34d0ca928432f0422a3d3c67",
    "500f49f5ab9b56322a06627699801cd57838c96d289d1b6fc727137a619ab944",
    "f0369a432737a5a770be5280cc9a7a15a451c6f4e7b420fa7bcf93312a169f23",
    "c2d042e0a2a543ddd3ad789e1ba42283c64f186d36652a08022102bcd3358c23",
    "50f4448b36499b976f4c8163189cea6d203caf04659df831215a625e2892304d",
    "6b2e0cce241b8a3f042a387a8d3eba574e47f5a01e82297013ecf601c994acf9",
    "9df846d3664e95d0ae728560e3949ba863fdd00c6ce5f569bac2efb5ea6571c1",
    "fa5fc7142616d507a80e7b516a934193a90c6ab9fc4dfe704b0def3d9dd1df40",
    "d51736faf831bd13e4a66d99c64901c655d7ef5a5c9ed4f22174285974366adb",
    "5d1586b5b93a528a3d56b83140f831cf2977779049674be2e4777ea470e9e052",
    "d6d2009ddc9b93e77fee0f46bd8194d690d961c8d254933d9665acd261a9fb4c",
    "d39564bf8c8807af083116d13ec20a347ae74c74af03128fda4b98fedfe4c4b4",
    "8735b7ecc3579cb8269be9457d412baa8160ff7a96c258208c314b82c8d1ff17",
    "cf480cbb7a87b6d3440e2a068ee6a57592e14188a6cb9d8c3ac90803aa054e1c",
    "34c4b6136c31e01f6453ecd943b8655b00fd25906692065c34053a7f6ae0a232",
    "5ec11bdf3aaf4519e17c6476ad76890a86ec59fc855f83c077159c7ee8a98661",
    "e35c40edf9819dd4f14de7dd4c038d3529312744942e49b7ac63ee165705057c",
    "2a6250d5144da3510c8c9e39cdec1eff96bc1c96e8d5c9fa3ea99d730e479be1",
    "7cd0717adede6ff10fab6e1cdd9047036cb06b5eb93b47be55a758ddc510c389",
    "dd5fd0807d6fee11a1c4b1af9ab6c537bc4db3d9fa4ac5d621b00b0cba340e20"
]
RULE_COUNTS = [0,0,0,0,0,0,0,4,0,2,0,2,0,0,0,0,0,3,0,0,0]

def approved():
    expected = FILES.get(sys.argv[1])
    patterns = sys.argv[2:]
    actual_hashes = [hashlib.sha256(value.encode('utf-8')).hexdigest() for value in patterns]
    if expected is None or actual_hashes != RULE_HASHES:
        return False
    with open(sys.argv[1], 'rb') as stream:
        data = stream.read(expected['bytes'] + 1)
    if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
        return False
    for pattern, count in zip(patterns, RULE_COUNTS, strict=True):
        result = subprocess.run(
            ['grep', '-o', '-i', '-F', '--', pattern], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
        )
        if result.returncode not in (0, 1) or result.stdout.count(b'\n') != count:
            return False
    return True

try:
    allowed = approved()
except (OSError, ValueError, subprocess.SubprocessError):
    allowed = False
raise SystemExit(0 if allowed else 1)
EVIDENTIA_REVIEWED_PUBLISHER_BYTES
      then
        continue
      else
        echo "::error::$f: finite publisher-data approval refused"
        found_hit=1
        continue
      fi
      ;;
  esac

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
