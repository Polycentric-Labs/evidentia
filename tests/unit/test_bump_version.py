"""Unit tests for ``scripts/bump_version.py``.

The bump script is the canonical entry point for atomic version
bumps across the monorepo. v0.7.12 P0.5 closes the inter-package
pin propagation foot-gun surfaced during the v0.7.11 fresh-venv
install (where pip resolved a cached ``evidentia-core==0.7.10``
against a freshly-published ``evidentia==0.7.11`` because the
loose ``>=0.7.0,<0.8.0`` pin permitted any patch).

This module imports the script as a module via importlib so the
helper functions (``bump_pin_range``, ``cur_parts_str``) can be
unit-tested in isolation.
"""

from __future__ import annotations

import importlib.util
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUMP_SCRIPT_PATH = REPO_ROOT / "scripts" / "bump_version.py"


def _load_bump_module() -> Any:
    """Import scripts/bump_version.py as a module for direct testing."""
    spec = importlib.util.spec_from_file_location(
        "bump_version_under_test", BUMP_SCRIPT_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bump() -> Any:
    return _load_bump_module()


@pytest.fixture
def chdir_tmp(tmp_path: Path) -> Iterator[Path]:
    """Run the test body with CWD set to a temp dir (restored afterwards).

    Anchor processing reads files via paths relative to the process CWD, so
    the synthetic-manifest anchor tests build a tiny temp "repo" + chdir into
    it (mirrors tests/unit/test_check_version_consistency.py)."""
    prev = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(prev)


# ── bump_pin_range ─────────────────────────────────────────────────


class TestBumpPinRange:
    """v0.10.1 — every call passes the workspace allowlist as the third
    argument (`packages=[...]`) to close F-V100-M1. The regex and
    replacement template now embed the package-name capture group, so
    pin assertions include the workspace package prefix (e.g.
    ``evidentia-core>=0.7.0,<0.8.0`` rather than the bare range)."""

    # Single-element allowlist used across tests — keeps the regex
    # generation deterministic without conflating with the F-V100-M1
    # behavior, which is covered in detail by
    # tests/unit/test_scripts/test_bump_version.py.
    PKGS: ClassVar[list[str]] = ["evidentia-core"]

    def test_same_minor_patch_bump_tightens_lower_bound(
        self, bump: Any
    ) -> None:
        """v0.7.12 P0.5 closure: same-minor patch bumps tighten the
        lower bound to the target patch version, not the minor's .0.
        """
        cur_re, tgt = bump.bump_pin_range("0.7.11", "0.7.12", self.PKGS)
        # Replacement is the canonical tight pin with the package name
        # preserved via the `\g<name>` back-reference (v0.10.1).
        assert tgt == r"\g<name>>=0.7.12,<0.8.0"
        # Pattern matches both legacy loose pins AND already-tightened
        # pins from a prior post-fix patch — but now requires the
        # workspace package prefix.
        regex = re.compile(cur_re)
        assert regex.fullmatch("evidentia-core>=0.7.0,<0.8.0")
        assert regex.fullmatch("evidentia-core>=0.7.10,<0.8.0")
        assert regex.fullmatch("evidentia-core>=0.7.11,<0.8.0")
        # Hot-fix versions also flow through (X.Y.Z.W form)
        assert regex.fullmatch("evidentia-core>=0.7.7.1,<0.8.0")

    def test_cross_minor_bump_replaces_full_range(
        self, bump: Any
    ) -> None:
        """v0.7.X -> v0.8.0 promotes the upper bound + tightens the
        lower bound to the target."""
        cur_re, tgt = bump.bump_pin_range("0.7.12", "0.8.0", self.PKGS)
        assert tgt == r"\g<name>>=0.8.0,<0.9.0"
        regex = re.compile(cur_re)
        assert regex.fullmatch("evidentia-core>=0.7.12,<0.8.0")
        assert regex.fullmatch("evidentia-core>=0.7.0,<0.8.0")
        # Doesn't match the new range (avoids no-op rewrite loops)
        assert not regex.fullmatch("evidentia-core>=0.8.0,<0.9.0")

    def test_pin_with_pep508_extras_bracket_is_matched_and_preserved(
        self, bump: Any
    ) -> None:
        """v0.11.1: a workspace pin that carries a PEP 508 extras bracket
        (``evidentia-eval[faithfulness-semantic]>=0.11.0,<0.12.0`` — the
        ``evidentia-ai[eval-faithfulness]`` proxy extra) must be matched
        AND the bracket must survive the substitution unchanged.

        Regression: the v0.11.0 sweep silently skipped that pin (the
        regex required the bare member name to be followed directly by
        ``>=``), shipping ``evidentia-ai`` with an unsatisfiable extra
        (``evidentia-eval[...]<0.11.0`` against a 0.11.0 base dep).
        """
        cur_re, tgt = bump.bump_pin_range(
            "0.11.0", "0.11.1", ["evidentia-core", "evidentia-eval"]
        )
        regex = re.compile(cur_re)
        line = "evidentia-eval[faithfulness-semantic]>=0.11.0,<0.12.0"
        assert regex.fullmatch(line)
        assert (
            regex.sub(tgt, line)
            == "evidentia-eval[faithfulness-semantic]>=0.11.1,<0.12.0"
        )
        # A bare pin still round-trips exactly as before.
        assert (
            regex.sub(tgt, "evidentia-core>=0.11.0,<0.12.0")
            == "evidentia-core>=0.11.1,<0.12.0"
        )
        # The bracket must belong to a workspace member — a third-party
        # dep with extras + the same range shape stays untouched
        # (F-V100-M1 guard still holds).
        assert not regex.fullmatch("some-lib[extra]>=0.11.0,<0.12.0")

    def test_pin_pattern_does_not_match_unrelated_versions(
        self, bump: Any
    ) -> None:
        """The regex is anchored to the current major.minor; pins
        from other minors are NOT rewritten by accident."""
        cur_re, _ = bump.bump_pin_range("0.7.11", "0.7.12", self.PKGS)
        regex = re.compile(cur_re)
        assert not regex.fullmatch("evidentia-core>=0.6.0,<0.7.0")
        assert not regex.fullmatch("evidentia-core>=0.8.0,<0.9.0")
        assert not regex.fullmatch("evidentia-core>=1.0.0,<2.0.0")

    @pytest.mark.parametrize(
        "current, target, expected_target_pin",
        [
            ("0.7.11", "0.7.12", r"\g<name>>=0.7.12,<0.8.0"),
            ("0.7.0", "0.7.1", r"\g<name>>=0.7.1,<0.8.0"),
            ("0.7.12", "0.8.0", r"\g<name>>=0.8.0,<0.9.0"),
            ("0.8.0", "0.9.0", r"\g<name>>=0.9.0,<0.10.0"),
            # Major bump (hypothetical v1.0.0)
            ("0.9.5", "1.0.0", r"\g<name>>=1.0.0,<1.1.0"),
        ],
    )
    def test_target_pin_uses_full_target_version_as_lower_bound(
        self,
        bump: Any,
        current: str,
        target: str,
        expected_target_pin: str,
    ) -> None:
        """The new pin's lower bound equals the FULL target version,
        not the minor's `.0`. This is the closure of the v0.7.11
        propagation foot-gun.
        """
        _, tgt = bump.bump_pin_range(current, target, self.PKGS)
        assert tgt == expected_target_pin


class TestBuilderBaseImage:
    """v0.11.1: the in-Docker pip-compile path (non-Linux hosts) must run
    inside the SAME ``python:3.13-slim@sha256:…`` the Dockerfile's builder
    stage pins — read from the Dockerfile, not a second hardcoded literal
    (which had silently drifted behind the Dockerfile's pin)."""

    def test_reads_builder_digest_from_dockerfile(
        self, bump: Any, tmp_path: Path
    ) -> None:
        digest = "a" * 64
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "ARG INSTALL_SOURCE=pypi\n"
            f"FROM python:3.13-slim@sha256:{digest} AS base-builder\n"
            "FROM dhi.io/python:3.13@sha256:"
            + "b" * 64
            + " AS final\n",
            encoding="utf-8",
        )
        assert (
            bump.builder_base_image(dockerfile)
            == f"python:3.13-slim@sha256:{digest}"
        )

    def test_missing_pin_is_a_clean_error(
        self, bump: Any, tmp_path: Path
    ) -> None:
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        with pytest.raises(SystemExit, match=r"python:3\.13-slim@sha256"):
            bump.builder_base_image(dockerfile)

    def test_repo_dockerfile_matches_workflow_pins(self, bump: Any) -> None:
        """The Dockerfile builder digest is the single source of truth; the
        two workflows that run pip-compile in that image must carry the
        identical digest (interpreter parity for --require-hashes)."""
        image = bump.builder_base_image(REPO_ROOT / "Dockerfile")
        for wf in ("release.yml", "container-build.yml"):
            text = (REPO_ROOT / ".github" / "workflows" / wf).read_text(
                encoding="utf-8"
            )
            assert image in text, f"{wf} pip-compile base drifted from Dockerfile"


class TestCurPartsStr:
    @pytest.mark.parametrize(
        "version, expected",
        [
            ("0.7.11", "0.7"),
            ("0.7.12", "0.7"),
            ("0.8.0", "0.8"),
            ("1.0.0", "1.0"),
            # Hot-fix variant (X.Y.Z.W)
            ("0.7.7.1", "0.7"),
        ],
    )
    def test_returns_major_minor_slice(
        self, bump: Any, version: str, expected: str
    ) -> None:
        assert bump.cur_parts_str(version) == expected


# ── v0.10.7 E3: manifest-driven replacement ────────────────────────────


def _apply(pairs: list[tuple[str, str]], text: str) -> tuple[str, int]:
    """Apply (regex, replacement) pairs to text; return (new_text, total_subs)."""
    total = 0
    for pattern, repl in pairs:
        text, n = re.subn(pattern, repl, text)
        total += n
    return text, total


class TestReplacementsForKind:
    """Each manifest ``kind`` maps to the correct (regex, replacement) pair(s)
    and preserves the pre-E3 behavior (incl. the (?!\\.\\d) hot-fix lookahead).
    """

    PKGS: ClassVar[list[str]] = ["evidentia-core", "evidentia-ai"]

    def test_python_version(self, bump: Any) -> None:
        pairs = bump.replacements_for_kind(
            "python_version", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        out, n = _apply(pairs, 'version = "0.10.7"\nname = "x"\n')
        assert n == 1
        assert 'version = "0.10.8"' in out

    def test_python_version_hotfix_lookahead(self, bump: Any) -> None:
        """The (?!\\.\\d) lookahead must NOT rewrite a 4-segment hot-fix
        version when bumping the 3-segment base (e.g. 0.10.7 -> 0.10.8 must
        leave a stray 0.10.7.1 literal alone)."""
        pairs = bump.replacements_for_kind(
            "python_version", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        out, n = _apply(pairs, 'version = "0.10.7.1"\n')
        assert n == 0
        assert 'version = "0.10.7.1"' in out

    def test_json_version(self, bump: Any) -> None:
        pairs = bump.replacements_for_kind(
            "json_version", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        out, n = _apply(pairs, '  "version": "0.10.7",\n')
        assert n == 1
        assert '"version": "0.10.8"' in out

    def test_pip_extra_pin(self, bump: Any) -> None:
        pairs = bump.replacements_for_kind(
            "pip_extra_pin", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        out, n = _apply(pairs, "evidentia[gui]==0.10.7\nurllib3>=2.7.0\n")
        assert n == 1
        assert "evidentia[gui]==0.10.8" in out

    def test_workspace_pins_delegates_to_bump_pin_range(self, bump: Any) -> None:
        """workspace_pins reuses bump_pin_range over the allowlist — so a
        workspace pin moves but a third-party pin with the SAME range shape
        does not (F-V100-M1 preserved)."""
        pairs = bump.replacements_for_kind(
            "workspace_pins", "0.9.9", "0.10.0", packages=["evidentia-core"], bump_date="2026-05-29"
        )
        text = (
            '    "evidentia-core>=0.9.0,<0.10.0",\n'
            '    "py-ocsf-models>=0.9.0,<0.10.0",\n'
        )
        out, n = _apply(pairs, text)
        assert n == 1
        assert "evidentia-core>=0.10.0,<0.11.0" in out
        # Third-party pin UNCHANGED — the F-V100-M1 guard.
        assert "py-ocsf-models>=0.9.0,<0.10.0" in out

    def test_workspace_pins_empty_allowlist_is_noop(self, bump: Any) -> None:
        """Empty allowlist => no pairs (refuse package-agnostic fallback)."""
        pairs = bump.replacements_for_kind(
            "workspace_pins", "0.9.9", "0.10.0", packages=[], bump_date="2026-05-29"
        )
        assert pairs == []

    def test_cff_version(self, bump: Any) -> None:
        pairs = bump.replacements_for_kind(
            "cff_version", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        out, n = _apply(pairs, "license: Apache-2.0\nversion: 0.10.7\n")
        assert n == 1
        assert "version: 0.10.8" in out

    def test_cff_date_set_to_bump_date(self, bump: Any) -> None:
        """date-released is rewritten to the supplied bump date regardless of
        its prior value (it is a date, not the version)."""
        pairs = bump.replacements_for_kind(
            "cff_date", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-06-01"
        )
        out, n = _apply(pairs, "date-released: '2026-05-29'\n")
        assert n == 1
        assert "date-released: '2026-06-01'" in out

    def test_readme_container_tag_tight_anchor(self, bump: Any) -> None:
        """The README container-tag replacement updates the docker-pull line
        but does NOT touch historical release-note lines that mention an old
        version WITHOUT the ghcr.io/...:v prefix."""
        pairs = bump.replacements_for_kind(
            "readme_container_tag", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
        )
        readme = (
            "Container: `docker pull ghcr.io/polycentric-labs/evidentia:v0.10.7` (verified).\n"
            "\n"
            "**v0.10.7 (2026-05-29)** — release notes mention v0.10.7 here.\n"
            "**v0.10.6 (2026-05-27)** — older notes mention v0.10.6 here.\n"
        )
        out, n = _apply(pairs, readme)
        # Exactly ONE substitution — only the container-pull line.
        assert n == 1
        assert "evidentia:v0.10.8`" in out
        # Historical release-note prose untouched.
        assert "**v0.10.7 (2026-05-29)**" in out
        assert "**v0.10.6 (2026-05-27)**" in out

    def test_unknown_kind_exits(self, bump: Any) -> None:
        with pytest.raises(SystemExit):
            bump.replacements_for_kind(
                "nonsense_kind", "0.10.7", "0.10.8", packages=self.PKGS, bump_date="2026-05-29"
            )


class TestExpandManifestPath:
    """Glob/literal path expansion against the git-tracked file list uses
    POSIX-style matching so forward-slash globs work on any host OS."""

    def test_literal_path(self, bump: Any) -> None:
        tracked = [Path("README.md"), Path("CITATION.cff"), Path("pyproject.toml")]
        assert bump.expand_manifest_path("README.md", tracked) == [Path("README.md")]

    def test_single_star_glob(self, bump: Any) -> None:
        tracked = [
            Path("packages/evidentia-core/pyproject.toml"),
            Path("packages/evidentia-ai/pyproject.toml"),
            Path("packages/evidentia-core/src/x.py"),
        ]
        got = bump.expand_manifest_path("packages/*/pyproject.toml", tracked)
        assert Path("packages/evidentia-core/pyproject.toml") in got
        assert Path("packages/evidentia-ai/pyproject.toml") in got
        # src file does NOT match the pyproject glob.
        assert Path("packages/evidentia-core/src/x.py") not in got

    def test_double_star_glob(self, bump: Any) -> None:
        tracked = [
            Path("docs/a.md"),
            Path("docs/sub/b.md"),
            Path("README.md"),
        ]
        got = bump.expand_manifest_path("docs/**", tracked)
        assert Path("docs/a.md") in got
        assert Path("docs/sub/b.md") in got
        assert Path("README.md") not in got


class TestRealManifest:
    """Sanity checks against the actual committed manifest."""

    def test_manifest_loads_with_expected_kinds(self, bump: Any) -> None:
        manifest = bump.load_manifest()
        assert isinstance(manifest["tracked"], list) and manifest["tracked"]
        assert isinstance(manifest["frozen"], list) and manifest["frozen"]
        kinds = {e["kind"] for e in manifest["tracked"]}
        # All seven replacement strategies are exercised by the real manifest.
        assert kinds == {
            "python_version",
            "json_version",
            "pip_extra_pin",
            "workspace_pins",
            "cff_version",
            "cff_date",
            "readme_container_tag",
        }

    def test_citation_and_readme_are_tracked(self, bump: Any) -> None:
        """The NEW v0.10.7 tracked targets are present in tracked (not frozen)."""
        manifest = bump.load_manifest()
        tracked_paths = {e["path"] for e in manifest["tracked"]}
        frozen_paths = {e["path"] for e in manifest["frozen"]}
        assert "CITATION.cff" in tracked_paths
        assert "README.md" in tracked_paths
        # Marketplace plugin.json is TRACKED — it mirrors the evidentia-mcp
        # release per the plugin's own "tracks the release line" design. The
        # rest of the marketplace tree stays frozen for its historical literals
        # (the v0.10.2-marketplace.md doc-link + the scope-decision citation).
        assert (
            "marketplace/grc-engineering-suite/plugins/evidentia/"
            ".claude-plugin/plugin.json" in tracked_paths
        )
        assert "marketplace/**" in frozen_paths
        assert "CITATION.cff" not in frozen_paths
        assert "README.md" not in frozen_paths

    def test_anchors_key_present_and_populated(self, bump: Any) -> None:
        """The real manifest exposes an ``anchors`` key that is now POPULATED
        (WS1-B): every LIVE "current version" example inside an otherwise-frozen
        file is anchored so it auto-tracks each ship. Each entry must be a
        well-formed mapping carrying the required ``path`` + ``line_contains``
        string keys, and every anchored file must ALSO be classified in
        ``tracked`` or ``frozen`` (an anchor is a coverage overlay, not a
        substitute for never-skip classification)."""
        manifest = bump.load_manifest()
        assert "anchors" in manifest
        anchors = manifest["anchors"]
        assert isinstance(anchors, list)
        assert anchors, "anchors should be populated post-WS1-B (was [])"
        for entry in anchors:
            assert isinstance(entry, dict)
            assert isinstance(entry.get("path"), str) and entry["path"]
            assert (
                isinstance(entry.get("line_contains"), str) and entry["line_contains"]
            )
        # Every anchor file is also never-skip-classified (tracked ∪ frozen).
        all_tracked = bump.tracked_files()
        classified = bump.classified_paths(manifest, all_tracked)
        for entry in anchors:
            matched = bump.expand_manifest_path(entry["path"], all_tracked)
            assert matched, f"anchor path {entry['path']!r} matched no tracked file"
            for p in matched:
                assert p.as_posix() in classified, (
                    f"anchor file {p.as_posix()} is neither tracked nor frozen"
                )


# ── v0.10.7: anchor overlay (force-set live-version lines in frozen files) ──


class TestForceSetAnchorLine:
    """The line-level force-set primitive: rewrites EVERY project-version
    literal on a single line to the target, preserving a leading ``v`` and
    touching nothing else on the line."""

    def test_force_sets_stale_version(self, bump: Any) -> None:
        line, n = bump.force_set_anchor_line(
            "Latest patched release: 0.10.6 (see CHANGELOG)\n", "0.10.7"
        )
        assert n == 1
        assert line == "Latest patched release: 0.10.7 (see CHANGELOG)\n"

    def test_preserves_leading_v(self, bump: Any) -> None:
        line, n = bump.force_set_anchor_line(
            "image: ghcr.io/x/evidentia:v0.10.6\n", "0.10.8"
        )
        assert n == 1
        assert line == "image: ghcr.io/x/evidentia:v0.10.8\n"

    def test_no_version_literal_reports_zero(self, bump: Any) -> None:
        """A line with no project-version literal yields 0 subs (the caller
        treats that as a misconfigured anchor)."""
        line, n = bump.force_set_anchor_line("no version here at all\n", "0.10.7")
        assert n == 0
        assert line == "no version here at all\n"

    def test_sub_010_dep_versions_below_floor_untouched(self, bump: Any) -> None:
        """Third-party dep versions below the 0.7 family floor are NOT matched
        (so a marker line that happens to mention a 0.6.x dep is left alone if
        it carries no real project version)."""
        line, n = bump.force_set_anchor_line("uses annotated-types 0.6.0\n", "0.10.7")
        assert n == 0
        assert line == "uses annotated-types 0.6.0\n"

    def test_already_current_is_idempotent(self, bump: Any) -> None:
        """Force-setting a line already at the target rewrites it to the same
        value (1 sub, no change) — idempotent."""
        line, n = bump.force_set_anchor_line("Latest: v0.10.7\n", "0.10.7")
        assert n == 1
        assert line == "Latest: v0.10.7\n"


def _patch_tracked(
    bump: Any, monkeypatch: pytest.MonkeyPatch, tracked: list[str]
) -> None:
    """Make the bump module's tracked_files() return a controlled list so the
    anchor tests need no real git."""
    monkeypatch.setattr(bump, "tracked_files", lambda: [Path(p) for p in tracked])


class TestApplyAnchors:
    """``apply_anchors`` force-sets anchored lines into the shared
    file_text/file_subs accumulators, with the four misconfiguration guards."""

    def test_force_sets_stale_line_leaves_historical_literal(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The motivating case: a frozen file whose live 'Latest' line is stale
        gets bumped while a historical literal on a DIFFERENT line is left as
        is."""
        (chdir_tmp / "SECURITY.md").write_text(
            "Latest patched release: 0.10.6\n"  # live line — should bump
            "\n"
            "## CVE-2026-0001 (fixed in 0.9.3)\n",  # historical — untouched
            encoding="utf-8",
        )
        _patch_tracked(bump, monkeypatch, ["SECURITY.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "SECURITY.md"}],
            "anchors": [
                {"path": "SECURITY.md", "line_contains": "Latest patched release:"}
            ],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.7", bump.tracked_files(), file_text, file_subs
        )
        out = file_text[Path("SECURITY.md")]
        assert "Latest patched release: 0.10.7" in out
        # Historical CVE literal on another line is untouched.
        assert "CVE-2026-0001 (fixed in 0.9.3)" in out
        assert file_subs[Path("SECURITY.md")] == 1

    def test_runs_when_current_equals_target(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Force-set still fixes a stale anchored line even when target ==
        current project version (the cur==target invocation path)."""
        # target 0.10.7 == 'current', but the anchored line shows 0.10.6.
        (chdir_tmp / "SECURITY.md").write_text(
            "Latest: 0.10.6\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["SECURITY.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "SECURITY.md"}],
            "anchors": [{"path": "SECURITY.md", "line_contains": "Latest:"}],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.7", bump.tracked_files(), file_text, file_subs
        )
        assert file_text[Path("SECURITY.md")] == "Latest: 0.10.7\n"

    def test_v_prefix_preserved(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (chdir_tmp / "README.md").write_text(
            "Pinned image tag: :v0.10.6 here\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["README.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "README.md"}],
            "anchors": [{"path": "README.md", "line_contains": "Pinned image tag:"}],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.8", bump.tracked_files(), file_text, file_subs
        )
        assert file_text[Path("README.md")] == "Pinned image tag: :v0.10.8 here\n"

    def test_multi_line_marker_bumps_all(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A marker matching 2 lines bumps BOTH anchored lines."""
        (chdir_tmp / "doc.md").write_text(
            "Current release: 0.10.6\n"
            "intervening line with no marker and old 0.9.0 ref\n"
            "Current release: v0.10.5\n",
            encoding="utf-8",
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Current release:"}],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.7", bump.tracked_files(), file_text, file_subs
        )
        out = file_text[Path("doc.md")]
        assert out == (
            "Current release: 0.10.7\n"
            "intervening line with no marker and old 0.9.0 ref\n"
            "Current release: v0.10.7\n"
        )
        # Two anchored lines bumped.
        assert file_subs[Path("doc.md")] == 2

    def test_empty_anchors_is_noop(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tracked(bump, monkeypatch, ["x.md"])
        manifest: dict[str, list[dict[str, str]]] = {
            "tracked": [],
            "frozen": [],
            "anchors": [],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.7", bump.tracked_files(), file_text, file_subs
        )
        assert file_text == {}
        assert file_subs == {}

    # ── misconfiguration guards (each is a hard SystemExit) ───────────────

    def test_guard_path_matches_no_file(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tracked(bump, monkeypatch, ["other.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "missing.md"}],
            "anchors": [{"path": "missing.md", "line_contains": "x"}],
        }
        with pytest.raises(SystemExit, match="matched no git-tracked file"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    def test_guard_marker_matches_zero_lines(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (chdir_tmp / "doc.md").write_text("no marker line here\n", encoding="utf-8")
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
        }
        with pytest.raises(SystemExit, match="matched 0 lines"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    def test_guard_anchored_line_has_no_version(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (chdir_tmp / "doc.md").write_text(
            "Latest release: TBD\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
        }
        with pytest.raises(SystemExit, match="no project-version literal"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    def test_guard_unclassified_file(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchor file in NEITHER tracked NOR frozen hard-fails — an anchor
        is an overlay, not a substitute for never-skip classification."""
        (chdir_tmp / "doc.md").write_text(
            "Latest release: 0.10.6\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest: dict[str, list[dict[str, str]]] = {
            "tracked": [],
            "frozen": [],  # doc.md is NOT classified
            "anchors": [{"path": "doc.md", "line_contains": "Latest release:"}],
        }
        with pytest.raises(SystemExit, match="NEITHER tracked NOR frozen"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    # ── FIX-1: exactly-one-live-literal invariant (ambiguity hard-fail) ───

    def test_guard_ambiguous_two_project_literals_historical(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchored line carrying the current literal AND a second in-family
        PROJECT literal (a historical project version on the same line) is an
        ambiguous anchor — a HARD FAIL. The bumper must NOT silently corrupt the
        second literal (the multi-literal footgun)."""
        (chdir_tmp / "doc.md").write_text(
            "Latest: v0.10.7 (was v0.10.6)\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Latest:"}],
        }
        with pytest.raises(SystemExit, match="ambiguous anchor"):
            bump.apply_anchors(
                manifest, "0.10.8", bump.tracked_files(), {}, {}
            )

    def test_guard_ambiguous_third_party_in_family_literal(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchored line carrying the current project literal AND a 3rd-party
        dependency literal that happens to fall in the >=0.7 project family on
        the SAME line is also ambiguous — a HARD FAIL (the checker could
        otherwise pass a stale token and the bumper could corrupt the dep pin)."""
        (chdir_tmp / "doc.md").write_text(
            "Pinned evidentia 0.10.7 with somedep 0.9.5 today\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Pinned evidentia"}],
        }
        with pytest.raises(SystemExit, match="ambiguous anchor"):
            bump.apply_anchors(
                manifest, "0.10.8", bump.tracked_files(), {}, {}
            )

    def test_ambiguous_message_names_marker_file_and_count(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ambiguity error names the marker, the file, and the literal
        count so the operator can pick a more specific line_contains."""
        (chdir_tmp / "doc.md").write_text(
            "Latest: v0.10.7 (was v0.10.6)\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Latest:"}],
        }
        with pytest.raises(SystemExit) as exc:
            bump.apply_anchors(
                manifest, "0.10.8", bump.tracked_files(), {}, {}
            )
        msg = str(exc.value)
        assert "ambiguous anchor" in msg
        assert "Latest:" in msg
        assert "doc.md" in msg
        assert "2 project-version literals" in msg

    def test_single_literal_with_v_prefix_still_happy_path(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The exactly-one happy path (a single live literal, v-prefixed) still
        force-sets correctly — the invariant tightening must not break it."""
        (chdir_tmp / "doc.md").write_text(
            "Latest release tag: v0.10.6\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": "Latest release tag:"}],
        }
        file_text: dict[Path, str] = {}
        file_subs: dict[Path, int] = {}
        bump.apply_anchors(
            manifest, "0.10.8", bump.tracked_files(), file_text, file_subs
        )
        assert file_text[Path("doc.md")] == "Latest release tag: v0.10.8\n"
        assert file_subs[Path("doc.md")] == 1

    # ── FIX-2 (M-1): malformed anchor entry → clean error, not KeyError ───

    def test_malformed_anchor_missing_line_contains_clean_exit(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchor entry missing the required ``line_contains`` key yields a
        clean SystemExit (NOT a raw KeyError)."""
        (chdir_tmp / "doc.md").write_text(
            "Latest: 0.10.6\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md"}],  # line_contains missing
        }
        with pytest.raises(SystemExit, match="line_contains"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    def test_malformed_anchor_missing_path_clean_exit(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchor entry missing the required ``path`` key yields a clean
        SystemExit (NOT a raw KeyError)."""
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"line_contains": "Latest:"}],  # path missing
        }
        with pytest.raises(SystemExit, match="path"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )

    def test_malformed_anchor_non_str_key_clean_exit(
        self, bump: Any, chdir_tmp: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An anchor entry whose ``line_contains`` is not a str yields a clean
        SystemExit (NOT a TypeError deep in the substring scan)."""
        (chdir_tmp / "doc.md").write_text(
            "Latest: 0.10.6\n", encoding="utf-8"
        )
        _patch_tracked(bump, monkeypatch, ["doc.md"])
        manifest = {
            "tracked": [],
            "frozen": [{"path": "doc.md"}],
            "anchors": [{"path": "doc.md", "line_contains": 123}],  # not a str
        }
        with pytest.raises(SystemExit, match="line_contains"):
            bump.apply_anchors(
                manifest, "0.10.7", bump.tracked_files(), {}, {}
            )
