#!/usr/bin/env python3
"""Atomically bump version + inter-package pin ranges across the Evidentia monorepo.

Replaces the deprecated scripts/_bump_version.py (which was hardcoded
0.5 -> 0.6). This one is general: pass --from X.Y.Z --to A.B.C (or just
--to A.B.C and it auto-detects current).

**v0.10.7 Phase E3**: the set of files to update + the replacement to make
in each is now driven by the declarative manifest
``scripts/version_tracked_files.yaml`` (the ``tracked:`` section) rather
than a hardcoded list. The same manifest is read by
``scripts/check_version_consistency.py`` so the bumper and the
"never-skip-a-version-reference" gate can never drift. Each manifest entry
carries a ``kind`` that selects one of the replacement strategies below:

  - python_version       version = "X.Y.Z"            (pyproject.toml / TOML)
  - json_version         "version": "X.Y.Z"           (package.json)
  - pip_extra_pin        evidentia[gui]==X.Y.Z        (Dockerfile / requirements.in)
  - workspace_pins       >=X.Y.Z,<X.(Y+1).0           (inter-package pins;
                                                       workspace members only —
                                                       the F-V100-M1 guard)
  - cff_version          version: X.Y.Z               (CITATION.cff, YAML)
  - cff_date             date-released: 'YYYY-MM-DD'  (CITATION.cff; set to the
                                                       bump date, UTC)
  - readme_container_tag ghcr.io/.../evidentia:vX.Y.Z (README container line)

**v0.10.7 anchors overlay**: the manifest also supports an optional
``anchors:`` list. Each anchor force-sets the project-version literal on a
SPECIFIC line (identified by a literal ``line_contains`` substring) inside an
otherwise-``frozen`` file, leaving that file's historical literals alone. The
force-set runs even when ``current == target`` (so a drifted "Latest release"
line is fixable on any invocation), preserves a leading ``v``, and touches
ONLY the X.Y.Z(.W) numeric on the anchored line. See
``scripts/version_tracked_files.yaml`` for the schema + semantics.

Skips lockfiles (uv.lock, package-lock.json) - those are regenerated
by `uv sync --all-packages` after running this script. (Lockfiles are
also listed in the manifest's ``frozen:`` section.)

Usage:
  ./scripts/bump_version.py --to 0.8.0
  ./scripts/bump_version.py --from 0.7.0 --to 0.7.1
  ./scripts/bump_version.py --to 0.7.1 --dry-run  # show what would change

Per the publishing-authority protocol (~/.claude/CLAUDE.md), this script
NEVER pushes, tags, or publishes. It only edits files. Use git status
afterward + commit explicitly. Tag creation requires explicit user
approval per the global protocol.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

# Matches X.Y.Z and X.Y.Z.W (hot-fix versions per the v0.7.4 / v0.7.7.1
# precedent: same-day patches that need to ride atop a tagged minor +
# don't earn a fresh patch number).
VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:\.\d+)?")

# Anchor overlay (v0.10.7): the project-version literal AS IT APPEARS on an
# anchored line, capturing an optional leading ``v`` so it can be preserved
# on rewrite. Deliberately mirrors the project-version family +
# boundary guards in check_version_consistency.PROJECT_VERSION_RE (minor >= 7,
# optional 4th hot-fix segment, ``(?<![\w.])`` / ``(?![\w])`` guards) so the
# bumper's force-set and the gate's coverage check see the EXACT same set of
# literals. Group ``v`` holds the optional ``v`` prefix; the numeric body is
# everything after it. Used to FORCE-SET (not cur->target match) the version
# on an anchored line regardless of its prior value.
ANCHOR_VERSION_RE = re.compile(
    r"(?<![\w.])(?P<v>v?)0\.(?:[7-9]|[1-9][0-9])\.\d+(?:\.\d+)?(?![\w])"
)

# The declarative manifest that lists every file carrying the project
# version (the ``tracked:`` section the bumper drives off) plus the
# allowlist of intentionally-historical literals (``frozen:``). Lives next
# to this script. v0.10.7 Phase E2/E3.
MANIFEST_PATH = Path(__file__).resolve().parent / "version_tracked_files.yaml"


def builder_base_image(dockerfile: Path | None = None) -> str:
    """Return the ``python:3.13-slim@sha256:…`` reference the Dockerfile's
    builder stage pins.

    v0.11.1: the non-Linux ``--regenerate-requirements`` path runs
    pip-compile inside this exact image (interpreter parity with the
    ``--require-hashes`` container install), and ``release.yml`` /
    ``container-build.yml`` pin the same digest for the same reason. The
    Dockerfile is the single source of truth — a second hardcoded literal
    here had silently drifted behind the Dockerfile's pin.
    """
    p = dockerfile or Path("Dockerfile")
    if not p.exists():
        sys.exit(f"Cannot read the builder base image: {p} missing")
    m = re.search(
        r"^FROM\s+(python:3\.13-slim@sha256:[0-9a-f]{64})\b",
        p.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if not m:
        sys.exit(
            f"Cannot find the pinned `FROM python:3.13-slim@sha256:<digest>` "
            f"builder line in {p}"
        )
    return m.group(1)


def workspace_packages(pyproject_path: Path | None = None) -> list[str]:
    """Read ``[tool.uv.sources]`` from the root ``pyproject.toml``.

    Returns the package names that the monorepo declares as workspace
    members — i.e. the only packages whose inter-package version pins
    this script is allowed to touch.

    **F-V100-M1 close-out (v0.10.1)**: the v0.10.0 ship surfaced
    ``bump_version.py`` over-bumping the ``py-ocsf-models`` pin because
    the prior substitution didn't distinguish inter-package pins from
    third-party pins matching the same ``>=0.X.0,<0.Y.0`` shape. By
    reading ``[tool.uv.sources]`` as the workspace allowlist, the
    script substitutes pins only on names declared as
    ``{ workspace = true }`` — third-party deps are left alone.

    Returns an empty list if no root ``pyproject.toml`` exists OR if
    the ``[tool.uv.sources]`` section is missing. Callers that
    receive an empty list MUST skip the pin substitution rather than
    falling back to a package-agnostic regex (which would re-introduce
    F-V100-M1).
    """
    root = pyproject_path or Path("pyproject.toml")
    if not root.exists():
        return []
    try:
        data = tomllib.loads(root.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return []
    sources = data.get("tool", {}).get("uv", {}).get("sources", {})
    return sorted(
        name
        for name, spec in sources.items()
        if isinstance(spec, dict) and spec.get("workspace") is True
    )


def tracked_files() -> list[Path]:
    """All git-tracked files (so we never touch generated/ignored content)."""
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [Path(p) for p in out.splitlines() if p]


def detect_current_version() -> str:
    """Read evidentia-core's pyproject.toml as the source of truth."""
    p = Path("packages/evidentia-core/pyproject.toml")
    if not p.exists():
        sys.exit(
            "Cannot detect current version: "
            "packages/evidentia-core/pyproject.toml missing"
        )
    for line in p.read_text(encoding="utf-8").splitlines():
        m = re.match(r'\s*version\s*=\s*"(\d+\.\d+\.\d+)"', line)
        if m:
            return m.group(1)
    sys.exit("Cannot find version field in evidentia-core/pyproject.toml")


def cur_parts_str(version: str) -> str:
    """Return `major.minor` slice of a version for display purposes."""
    parts = version.split(".")
    return f"{parts[0]}.{parts[1]}"


def bump_pin_range(
    current: str,
    target: str,
    packages: list[str],
) -> tuple[str, str]:
    """Return (current-range-regex, next-range-replacement) for inter-package pin updates.

    Pin convention (v0.7.12+): ``>={target},<{M}.{m+1}.0`` — tightens
    the LOWER bound to the current release version, not the minor's
    ``.0``. This closes the v0.7.11 propagation foot-gun where pip
    could resolve a cached ``evidentia-core==0.7.10`` against a
    freshly-published ``evidentia==0.7.11`` because the loose
    ``>=0.7.0,<0.8.0`` pin permitted ANY patch.

    **F-V100-M1 close-out (v0.10.1)**: the regex now **requires** one
    of the workspace package names in ``packages`` to precede the
    range. Third-party deps that happen to use the same range shape
    (``py-ocsf-models>=0.9.0,<0.10.0``) are no longer matched, so
    bumping ``0.9.9 -> 0.10.0`` doesn't over-bump them to
    ``>=0.10.0,<0.11.0`` (unsatisfiable, breaks every fresh install).

    The capture group ``(?P<name>...)`` preserves the package name in
    the replacement via the named back-reference ``\\g<name>``.

    **v0.11.1**: the name group also admits an optional PEP 508 extras
    bracket (``evidentia-eval[faithfulness-semantic]>=X.Y.Z,<M.(m+1).0``
    — the ``evidentia-ai[eval-faithfulness]`` proxy extra). The bracket
    is captured INSIDE ``name`` so ``\\g<name>`` carries it through the
    substitution unchanged. Regression: the v0.11.0 sweep silently
    skipped that pin, shipping an unsatisfiable extra.

    Hot-fix versions (X.Y.Z.W per the v0.7.4 / v0.7.7.1 precedent)
    ride the major.minor of their parent release.
    """
    if not packages:
        # Defensive: empty allowlist means "no workspace members declared"
        # — refuse to fall back to a package-agnostic pattern (which is
        # exactly the F-V100-M1 bug). Callers must detect the empty
        # list and skip the pin substitution.
        raise ValueError(
            "bump_pin_range called with empty workspace package list; "
            "the F-V100-M1 fix requires an explicit allowlist."
        )
    cur_parts = current.split(".")
    tgt_parts = target.split(".")
    cur_maj, cur_min = cur_parts[0], cur_parts[1]
    tgt_maj, tgt_min = tgt_parts[0], tgt_parts[1]
    # Cross-minor bump: match anything in the OLD minor range. Same-minor
    # bump: also match anything in the current minor (catches both
    # already-tightened pins and legacy loose ones).
    name_alt = "|".join(re.escape(p) for p in packages)
    cur_range = (
        rf"(?P<name>(?:{name_alt})(?:\[[^\]]+\])?)>="
        rf"{cur_maj}\.{cur_min}\.\d+(?:\.\d+)?,"
        rf"<{cur_maj}\.{int(cur_min)+1}\.0"
    )
    tgt_range = rf"\g<name>>={target},<{tgt_maj}.{int(tgt_min)+1}.0"
    return cur_range, tgt_range


# ── Manifest-driven replacement (v0.10.7 E3) ───────────────────────────────


def load_manifest(path: Path | None = None) -> dict[str, list[dict[str, str]]]:
    """Load the manifest -> {"tracked": [...], "frozen": [...], "anchors": [...]}.

    Both ``scripts/bump_version.py`` and
    ``scripts/check_version_consistency.py`` read this one file so the
    bumper and the never-skip gate can never drift.

    ``anchors`` is an OPTIONAL line-scoped overlay (default ``[]``): each entry
    force-sets the project-version literal on a specific live line inside an
    otherwise-``frozen`` file. See the manifest's SCHEMA header for the full
    contract.
    """
    p = path or MANIFEST_PATH
    if not p.exists():
        sys.exit(f"Version manifest not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    tracked = data.get("tracked") or []
    frozen = data.get("frozen") or []
    anchors = data.get("anchors") or []
    if (
        not isinstance(tracked, list)
        or not isinstance(frozen, list)
        or not isinstance(anchors, list)
    ):
        sys.exit(
            f"Malformed manifest {p}: 'tracked'/'frozen'/'anchors' must be lists"
        )
    return {"tracked": tracked, "frozen": frozen, "anchors": anchors}


def expand_manifest_path(spec: str, all_tracked: list[Path]) -> list[Path]:
    """Expand a manifest ``path`` (literal or glob) to git-tracked files.

    Uses POSIX-style matching so the manifest's forward-slash globs (e.g.
    ``packages/*/pyproject.toml``) match regardless of the host OS path
    separator. ``**`` matches across directory levels.
    """
    spec_norm = spec.replace("\\", "/")
    matches: list[Path] = []
    for p in all_tracked:
        posix = p.as_posix()
        if posix == spec_norm or fnmatch.fnmatch(posix, spec_norm):
            matches.append(p)
    return matches


def replacements_for_kind(
    kind: str,
    current: str,
    target: str,
    *,
    packages: list[str],
    bump_date: str,
) -> list[tuple[str, str]]:
    """Return the (regex, replacement) pairs for a manifest ``kind``.

    The complex inter-package-pin logic (``workspace_pins``) is delegated to
    :func:`bump_pin_range` so the F-V100-M1 workspace-allowlist guard lives
    in exactly one tested place. The simple literal kinds reuse the same
    patterns the pre-E3 hardcoded list used, including the ``(?!\\.\\d)``
    hot-fix lookahead.
    """
    cur_re = re.escape(current)
    nla = r"(?!\.\d)"  # negative-lookahead: not followed by .digit (X.Y.Z.W safe)
    if kind == "python_version":
        return [(rf'version = "{cur_re}"{nla}', f'version = "{target}"')]
    if kind == "json_version":
        return [(rf'"version": "{cur_re}"{nla}', f'"version": "{target}"')]
    if kind == "pip_extra_pin":
        # v0.7.7.1 trap: the published image must install the NEW version.
        return [(rf'evidentia\[gui\]=={cur_re}{nla}', f'evidentia[gui]=={target}')]
    if kind == "workspace_pins":
        # F-V100-M1: only workspace members from [tool.uv.sources] are
        # rewritten. Empty allowlist => skip (refuse package-agnostic fallback).
        if not packages:
            return []
        return [bump_pin_range(current, target, packages)]
    if kind == "cff_version":
        # CITATION.cff YAML: unquoted `version: X.Y.Z`.
        return [(rf'version: {cur_re}{nla}', f'version: {target}')]
    if kind == "cff_date":
        # CITATION.cff YAML: `date-released: 'YYYY-MM-DD'` -> the bump date.
        # Matches any single-quoted ISO date so it updates regardless of the
        # prior value (the date is not the version, so it never matches cur_re).
        return [
            (
                r"date-released: '\d{4}-\d{2}-\d{2}'",
                f"date-released: '{bump_date}'",
            )
        ]
    if kind == "readme_container_tag":
        # Tightly anchored to the container-pull line so it can NEVER match
        # the historical release-note lines elsewhere in the README.
        return [
            (
                rf"ghcr\.io/polycentric-labs/evidentia:v{cur_re}{nla}",
                f"ghcr.io/polycentric-labs/evidentia:v{target}",
            )
        ]
    sys.exit(f"Unknown manifest kind {kind!r} (fix version_tracked_files.yaml)")


# ── Anchor overlay (v0.10.7) ───────────────────────────────────────────────


def _require_anchor_str(entry: dict[str, Any], key: str) -> str:
    """Return ``entry[key]`` as a ``str`` or ``sys.exit`` with a clean message.

    M-1 hardening: a malformed ``anchors`` entry (a missing or mistyped
    required key) must surface as a clean, actionable error rather than a raw
    ``KeyError`` / ``TypeError`` deep in the substring scan. Both the bumper
    (:func:`apply_anchors`) and the checker
    (``check_version_consistency.check_anchors``) route their ``path`` /
    ``line_contains`` reads through this so the validation lives in one place.
    """
    if key not in entry:
        sys.exit(
            f"malformed anchor entry {entry!r}: missing required {key!r} key — "
            f"each anchor needs a 'path' and a 'line_contains' (both strings) in "
            f"scripts/version_tracked_files.yaml"
        )
    value = entry[key]
    if not isinstance(value, str):
        sys.exit(
            f"malformed anchor entry {entry!r}: {key!r} must be a string, got "
            f"{type(value).__name__} — fix it in "
            f"scripts/version_tracked_files.yaml"
        )
    return value


def force_set_anchor_line(line: str, target: str) -> tuple[str, int]:
    """Force-set every project-version literal on a single anchored line.

    Each match of :data:`ANCHOR_VERSION_RE` (X.Y.Z(.W) with the project-family
    boundary guards, optionally ``v``-prefixed) has its numeric body replaced
    with ``target``, regardless of the literal's prior value (so a stale
    ``v0.10.6`` becomes ``v<target>``). A leading ``v`` is PRESERVED. Only the
    matched version token within the line string is rewritten; the rest of the
    line string is byte-for-byte untouched.

    Note: ":func:`apply_anchors` enforces an EXACTLY-ONE-live-literal invariant
    before calling this (0 or >1 matches are hard errors), so in practice this
    rewrites a single token. The line endings of the file as a whole are
    normalized to LF on write-back by ``Path.write_text`` in :func:`main` —
    shared with the tracked-substitution loop — so the "touches nothing else"
    guarantee is scoped to LF-newline files (a CRLF file's terminators become
    LF, exactly as for any tracked file the bumper rewrites).

    Returns ``(new_line, n_substitutions)``. ``n_substitutions == 0`` means the
    line carried no project-version literal; ``> 1`` means it carried multiple
    in-family literals — both are misconfigured anchors, surfaced by the callers
    as hard errors (the exactly-one-live-literal contract).
    """

    def _repl(m: re.Match[str]) -> str:
        return f"{m.group('v')}{target}"

    return ANCHOR_VERSION_RE.subn(_repl, line)


def classified_paths(
    manifest: dict[str, list[dict[str, str]]], all_tracked: list[Path]
) -> set[str]:
    """POSIX paths classified by the manifest's ``tracked`` + ``frozen`` specs.

    Used by the anchor overlay to enforce that an anchor file is ALSO
    never-skip-classified (an anchor is a coverage overlay, not a substitute
    for classification). Mirrors the union the never-skip gate builds.
    """
    classified: set[str] = set()
    for spec in {e["path"] for e in manifest["tracked"]} | {
        e["path"] for e in manifest["frozen"]
    }:
        for p in expand_manifest_path(spec, all_tracked):
            classified.add(p.as_posix())
    return classified


def apply_anchors(
    manifest: dict[str, list[dict[str, str]]],
    target: str,
    all_tracked: list[Path],
    file_text: dict[Path, str],
    file_subs: dict[Path, int],
) -> None:
    """Force-set the version on every anchored line (the ``anchors:`` overlay).

    For each anchor entry, locate every line in ``path`` that contains the
    literal ``line_contains`` substring and force-set its SINGLE project-version
    literal to ``target`` (preserving a leading ``v``). Mutates the shared
    ``file_text`` / ``file_subs`` accumulators in place so the caller's output
    aggregation and write-back treat anchored files exactly like tracked ones.
    Write-back (in :func:`main`) uses ``Path.write_text``, which normalizes the
    file's line endings to LF — shared with the tracked-substitution loop — so
    an anchored CRLF file's terminators become LF exactly as for any tracked
    file the bumper rewrites; nothing else on the anchored line changes.

    Runs unconditionally — even when ``current == target`` — so a drifted
    anchored line is fixed on any invocation.

    **Exactly-one-live-literal contract**: an anchored line must carry EXACTLY
    ONE in-family project-version literal (matched by :data:`ANCHOR_VERSION_RE`).
    ``0`` literals or ``> 1`` literals are HARD ERRORS — the latter closes the
    multi-literal footgun where a second in-family token on the line (a
    historical project version OR a third-party ``>=0.7`` dependency version)
    would otherwise be silently rewritten by the force-set.

    Misconfiguration is a HARD ERROR (``SystemExit``):
      * an anchor entry missing the required ``path`` / ``line_contains`` keys,
        or carrying a non-``str`` value for either (a clean exit, not KeyError);
      * ``path`` matches no git-tracked file;
      * the anchor's file is in NEITHER ``tracked`` NOR ``frozen``;
      * ``line_contains`` matches 0 lines in the file;
      * a matched (anchored) line contains NO project-version literal;
      * a matched (anchored) line contains MORE THAN ONE project-version literal
        (ambiguous anchor).
    """
    anchors = manifest.get("anchors") or []
    if not anchors:
        return
    classified = classified_paths(manifest, all_tracked)

    for entry in anchors:
        spec = _require_anchor_str(entry, "path")
        marker = _require_anchor_str(entry, "line_contains")
        matched_files = expand_manifest_path(spec, all_tracked)
        if not matched_files:
            sys.exit(
                f"anchor path {spec!r} matched no git-tracked file — fix the "
                f"path in scripts/version_tracked_files.yaml"
            )
        for p in matched_files:
            posix = p.as_posix()
            if posix not in classified:
                sys.exit(
                    f"anchor file {posix} is in NEITHER tracked NOR frozen — an "
                    f"anchor is a coverage overlay, not a substitute for "
                    f"never-skip classification; also classify it in "
                    f"scripts/version_tracked_files.yaml"
                )
            if p not in file_text:
                try:
                    file_text[p] = p.read_text(encoding="utf-8")
                except OSError as exc:
                    sys.exit(f"cannot read anchor file {posix}: {exc}")
            lines = file_text[p].splitlines(keepends=True)
            marked = [i for i, ln in enumerate(lines) if marker in ln]
            if not marked:
                sys.exit(
                    f"anchor marker {marker!r} matched 0 lines in {posix} — fix "
                    f"the line_contains substring in "
                    f"scripts/version_tracked_files.yaml"
                )
            subs_here = 0
            for i in marked:
                n_literals = len(ANCHOR_VERSION_RE.findall(lines[i]))
                if n_literals == 0:
                    sys.exit(
                        f"anchor line in {posix} containing {marker!r} carries no "
                        f"project-version literal to set — fix the anchor in "
                        f"scripts/version_tracked_files.yaml"
                    )
                if n_literals > 1:
                    sys.exit(
                        f"ambiguous anchor: line containing {marker!r} in {posix} "
                        f"has {n_literals} project-version literals; use a more "
                        f"specific line_contains so exactly ONE live version is "
                        f"anchored"
                    )
                new_line, n = force_set_anchor_line(lines[i], target)
                lines[i] = new_line
                subs_here += n
            file_text[p] = "".join(lines)
            if subs_here:
                file_subs[p] = file_subs.get(p, 0) + subs_here


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--from",
        dest="frm",
        help="current version (auto-detected from evidentia-core if omitted)",
    )
    ap.add_argument("--to", required=True, help="target version, e.g. 0.7.1")
    ap.add_argument(
        "--dry-run", action="store_true", help="print changes without writing"
    )
    ap.add_argument(
        "--regenerate-requirements",
        action="store_true",
        help=(
            "v0.7.14 P1.5 (foundation) → v0.8.2 (staged) → v0.8.3 G4 "
            "(activated): regenerate docker/requirements.txt with "
            "SHA256 hashes that match release.yml's reproducible "
            "uv build output. Wraps `uv build --all-packages` (with "
            "SOURCE_DATE_EPOCH from HEAD's commit timestamp) → "
            "pip-compile --find-links=./dist/ against the locally-"
            "built wheels for evidentia[gui]==<--to>. Requires "
            "pip-tools (`pip install pip-tools`) + uv installed. "
            "F-V82-S1 (v0.8.3 LOW): host platform auto-detection "
            "— on non-Linux hosts, pip-compile runs inside the "
            "pinned python:3.13-slim base image so Linux-only "
            "transitives (uvloop) resolve correctly. See "
            "docs/dockerfile-pinning.md for the full regeneration "
            "narrative."
        ),
    )
    args = ap.parse_args()

    if not VERSION_RE.fullmatch(args.to):
        sys.exit(f"--to must be X.Y.Z, got {args.to!r}")
    current = args.frm or detect_current_version()
    if not VERSION_RE.fullmatch(current):
        sys.exit(f"--from must be X.Y.Z, got {current!r}")

    # Whether the cur->target `tracked` substitutions run. They are no-ops
    # when current == target (the cur_re half can't match the new value), so
    # they are SKIPPED in that case. Anchors, by contrast, FORCE-SET their
    # line regardless and therefore run unconditionally below — so a drifted
    # "Latest release" line is fixable even on a same-version invocation.
    do_tracked_subs = current != args.to
    if not do_tracked_subs:
        if args.regenerate_requirements:
            # v0.8.3 G4: allow --regenerate-requirements to fire
            # even when the version doesn't change. Operators may
            # want to refresh requirements.txt hashes after a
            # transitive-dep CVE OR to test the regeneration
            # pipeline without bumping. Skip the substitution loop
            # but proceed to the regeneration block below.
            print(
                f"Already at {args.to} — skipping version "
                "substitutions; will still force-set anchors + proceed "
                "with --regenerate-requirements."
            )
        else:
            # v0.10.7 anchor overlay: even "already at X" must still
            # force-set anchored lines (a drifted live-version line in a
            # frozen file is fixable on any invocation). The tracked
            # substitutions stay skipped (no-ops); the anchor + write-back
            # path below runs, then we return.
            print(
                f"Already at {args.to} — skipping version substitutions; "
                "force-setting anchors only."
            )

    # v0.10.1 F-V100-M1 fix: read the workspace allowlist BEFORE
    # building substitution patterns; refuse to over-bump third-party
    # pins that happen to match the inter-package range shape.
    packages = workspace_packages()
    if packages:
        pin_msg = (
            f"  Inter-package pins ({len(packages)} workspace pkgs): "
            f"<prior-range-in-{cur_parts_str(current)}> -> "
            f">={args.to},<...next-minor..."
        )
    else:
        pin_msg = (
            "  Inter-package pins: SKIPPED (no [tool.uv.sources] "
            "workspace allowlist found in root pyproject.toml; refusing "
            "to fall back to package-agnostic regex per F-V100-M1)."
        )

    # v0.10.7 E3: the bump date (UTC) — used for CITATION.cff date-released.
    # The bump runs at release-prep (≈ tag day), so today's UTC date is the
    # release date.
    bump_date = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")

    if do_tracked_subs:
        print(f"Bump plan: {current} -> {args.to}")
        print(pin_msg)
        print()

    # v0.10.7 E3: drive the replacements off the manifest's `tracked:`
    # section instead of a hardcoded file-type allowlist. Each entry maps a
    # path/glob + a kind to one or more (regex, replacement) pairs. Lockfiles
    # are skipped here AND listed in the manifest `frozen:` section. The
    # `anchors:` overlay (force-set live-version lines in frozen files) runs
    # afterwards and shares the same per-file accumulators + write-back.
    manifest = load_manifest()
    all_tracked = tracked_files()

    # Aggregate per concrete file so the output still prints one line per
    # file even when several manifest entries target the same path (e.g. a
    # pyproject.toml gets both `python_version` and `workspace_pins`).
    file_subs: dict[Path, int] = {}
    file_text: dict[Path, str] = {}
    LOCKFILES = {"uv.lock", "package-lock.json"}

    if do_tracked_subs:
        for entry in manifest["tracked"]:
            spec = entry["path"]
            kind = entry["kind"]
            pairs = replacements_for_kind(
                kind, current, args.to, packages=packages, bump_date=bump_date
            )
            if not pairs:
                continue
            for p in expand_manifest_path(spec, all_tracked):
                if p.name in LOCKFILES:
                    continue
                if p not in file_text:
                    try:
                        file_text[p] = p.read_text(encoding="utf-8")
                    except OSError:
                        continue
                new_text = file_text[p]
                subs_here = 0
                for pattern, new in pairs:
                    new_text, n = re.subn(pattern, new, new_text)
                    subs_here += n
                if subs_here:
                    file_text[p] = new_text
                    file_subs[p] = file_subs.get(p, 0) + subs_here

    # v0.10.7 anchor overlay — runs unconditionally (even at cur == target).
    apply_anchors(manifest, args.to, all_tracked, file_text, file_subs)

    files_changed = 0
    total_subs = 0
    for p in sorted(file_subs, key=lambda x: x.as_posix()):
        n = file_subs[p]
        print(f"  {p}: {n} substitution(s)")
        if not args.dry_run:
            p.write_text(file_text[p], encoding="utf-8")
        files_changed += 1
        total_subs += n

    print()
    suffix = " [DRY RUN]" if args.dry_run else ""
    print(
        f"Summary: {files_changed} file(s), {total_subs} substitution(s){suffix}"
    )

    # v0.7.14 P1.5 (foundation) → v0.8.2 (production-staged) → v0.8.3 G4
    # (production-activated): regenerate docker/requirements.txt with
    # SHA256 hashes that match what release.yml will upload to PyPI.
    #
    # v0.8.3 G4 path — local-wheels via SOURCE_DATE_EPOCH:
    #
    #   1. Build local wheels with SOURCE_DATE_EPOCH derived from the
    #      target version's intended tag commit. Same env var is used
    #      by release.yml when it builds wheels for PyPI publish, so
    #      the wheels are byte-identical → SHA256 hashes match → the
    #      requirements.txt's hashes match what pip downloads from
    #      PyPI at container-build time.
    #   2. Run pip-compile --find-links=./dist/ so the resolver sees
    #      the locally-built wheels for evidentia[gui]==X.Y.Z (which
    #      isn't on PyPI yet because we haven't tagged).
    #   3. The output has hashes for the local wheels; release.yml
    #      will upload those exact bytes to PyPI; pip downloads them
    #      at container-build time + verifies hashes match.
    #
    # F-V82-S1 (v0.8.3 LOW): when host platform != Linux + the user
    # explicitly opts in to --regenerate-requirements, auto-invoke
    # pip-compile inside Docker so Linux-only transitives (uvloop)
    # resolve correctly. Still uses --find-links pointed at the
    # locally-built dist/.
    if args.regenerate_requirements:
        print()
        print("Regenerating docker/requirements.txt (v0.8.3 G4)...")
        if args.dry_run:
            print("  (dry run; would have run uv build + pip-compile)")
        else:
            import os
            import subprocess
            from pathlib import Path

            repo_root = Path(__file__).resolve().parent.parent
            docker_dir = repo_root / "docker"
            dist_dir = repo_root / "dist"
            req_in = docker_dir / "requirements.in"
            req_out = docker_dir / "requirements.txt"

            # Ensure requirements.in pins the new version. v0.11.1: keep
            # every OTHER committed line (e.g. the deliberate
            # `urllib3>=2.7.0` security floor) — release.yml preserves that
            # floor explicitly; a full rewrite here silently dropped it.
            docker_dir.mkdir(exist_ok=True)
            extra_in_lines: list[str] = []
            if req_in.exists():
                extra_in_lines = [
                    ln
                    for ln in req_in.read_text(encoding="utf-8").splitlines()
                    if ln.strip()
                    and not re.match(r"^evidentia(\[[^\]]*\])?==", ln.strip())
                ]
            req_in.write_text(
                "\n".join([f"evidentia[gui]=={args.to}", *extra_in_lines])
                + "\n",
                encoding="utf-8",
            )

            # Step 1 — build local wheels with SOURCE_DATE_EPOCH
            # derived from HEAD's commit timestamp. Matches the
            # release.yml step in v0.8.3 G4.
            sde_proc = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            source_date_epoch = sde_proc.stdout.strip()
            print(
                f"  SOURCE_DATE_EPOCH={source_date_epoch} "
                "(from HEAD commit timestamp)"
            )

            # Clean dist/ so we don't pull in stale wheels from a
            # prior bump.
            if dist_dir.exists():
                import shutil

                shutil.rmtree(dist_dir)

            build_env = os.environ.copy()
            build_env["SOURCE_DATE_EPOCH"] = source_date_epoch
            build_proc = subprocess.run(
                ["uv", "build", "--all-packages"],
                capture_output=True,
                text=True,
                env=build_env,
                check=False,
            )
            if build_proc.returncode != 0:
                print(
                    "  uv build FAILED:",
                    build_proc.stderr[-500:],
                )
                print(
                    "  (regeneration skipped; ensure `uv` is "
                    "installed + the workspace builds cleanly)"
                )
                # Continue with version-bump completion; just skip
                # the regeneration. Operator can re-run.
            else:
                wheel_count = len(list(dist_dir.glob("*.whl")))
                print(
                    f"  uv build OK: {wheel_count} wheels in dist/"
                )

                # Step 2 — invoke pip-compile against local wheels
                # via --find-links. Auto-detect host platform: on
                # non-Linux, run inside Docker so Linux-only deps
                # (uvloop) resolve.
                is_linux_host = sys.platform.startswith("linux")
                if is_linux_host:
                    print(
                        "  Host is Linux; running pip-compile "
                        "directly"
                    )
                    # --no-emit-find-links keeps the local-wheels
                    # path out of the generated requirements.txt
                    # so the file is portable to environments
                    # that don't have dist/ available (the
                    # production container, downstream
                    # consumers).
                    #
                    # --upgrade (F-V109-4): pip-compile treats an
                    # existing --output-file as a set of preferred
                    # pins. Without --upgrade it honors the committed
                    # docker/requirements.txt for every non-conflicting
                    # transitive, so a stale preview's pins (e.g. an
                    # older starlette / aiohttp) survive the regen even
                    # when newer compatible releases exist. --upgrade
                    # ignores the committed file's pins entirely, so the
                    # regeneration is genuinely fresh — every dep
                    # resolves anew. Mirrors the same fix already in
                    # release.yml + container-build.yml.
                    compile_cmd = [
                        "pip-compile",
                        "--generate-hashes",
                        "--upgrade",
                        f"--find-links={dist_dir}",
                        "--no-emit-find-links",
                        "--output-file",
                        str(req_out),
                        str(req_in),
                    ]
                    compile_proc = subprocess.run(
                        compile_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                else:
                    # F-V82-S1: invoke pip-compile inside the
                    # pinned Linux base image.
                    print(
                        f"  Host is {sys.platform}; invoking "
                        "pip-compile inside Docker (Linux base)"
                    )
                    # v0.11.1: read the pin from the Dockerfile (single
                    # source of truth) instead of a second literal that
                    # had drifted behind it.
                    base_image = builder_base_image(repo_root / "Dockerfile")
                    # `pwd -W` yields a forward-slash Windows path under
                    # Git Bash; it does not exist under PowerShell / cmd
                    # (FileNotFoundError), so fall back to the resolved
                    # repo root as a POSIX-style path (Docker Desktop
                    # accepts either form for -v mounts).
                    try:
                        docker_path = subprocess.run(
                            ["pwd", "-W"],
                            capture_output=True,
                            text=True,
                            check=False,
                        ).stdout.strip()
                    except OSError:
                        docker_path = ""
                    docker_path = docker_path or repo_root.resolve().as_posix()
                    compile_cmd = [
                        "docker",
                        "run",
                        "--rm",
                        "-v",
                        f"{docker_path}/docker:/work",
                        "-v",
                        f"{docker_path}/dist:/wheels",
                        "-w",
                        "//work",
                        base_image,
                        "sh",
                        "-c",
                        (
                            # --upgrade (F-V109-4): ignore the committed
                            # docker/requirements.txt's pins so the
                            # in-Docker regen is genuinely fresh, not
                            # anchored to a stale preview. Matches the
                            # Linux-direct path above + release.yml +
                            # container-build.yml.
                            # pip-tools pinned to the same release
                            # release.yml / container-build.yml use so
                            # the local preview and the CI/release regens
                            # agree. 7.6.1 (v0.11.1): 7.5.3 breaks on the
                            # pip 26.2 shipped in the current
                            # python:3.13-slim (`make_requirement_preparer()
                            # missing 'allow_editables'`).
                            "pip install -q pip-tools==7.6.1 && "
                            "pip-compile --generate-hashes "
                            "--upgrade "
                            "--find-links=/wheels "
                            "--no-emit-find-links "
                            "--output-file=requirements.txt "
                            "requirements.in"
                        ),
                    ]
                    compile_proc = subprocess.run(
                        compile_cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                if compile_proc.returncode != 0:
                    print(
                        "  pip-compile FAILED:",
                        compile_proc.stderr[-500:],
                    )
                    print(
                        "  (regeneration skipped; verify pip-tools "
                        "+ Docker (if non-Linux host) installed)"
                    )
                else:
                    pkg_count = sum(
                        1
                        for line in req_out.read_text(
                            encoding="utf-8"
                        ).splitlines()
                        if line and line[0].isalpha()
                    )
                    print(
                        f"  docker/requirements.txt regenerated: "
                        f"{pkg_count} packages with SHA256 hashes"
                    )

    if not args.dry_run and files_changed > 0:
        print()
        print("Next steps (per the publishing-authority protocol, do these manually):")
        print(f"  1. uv sync --all-packages   # regenerate uv.lock at {args.to}")
        print("  2. Run pytest + mypy + ruff to confirm nothing broke")
        print(
            f"  3. git add -p && git commit -m 'chore(release): bump to {args.to}'"
        )
        print(f"  4. (When ready, with explicit approval) push to main + tag v{args.to}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
