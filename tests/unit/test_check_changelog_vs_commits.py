"""Tests for scripts/check_changelog_vs_commits.py (#18 advisory diff)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_changelog_vs_commits as adv  # noqa: E402

_CHANGELOG = """# Changelog

## [0.11.0] - 2026-08-01

### Added

- Doc-currency gate (#175) and the dependency-review PR check (#176).

## [0.10.17] - 2026-07-09

- Older block referencing (#173).
"""


class TestChangelogBlock:
    def test_slices_exactly_one_block(self) -> None:
        block = adv.changelog_block(_CHANGELOG, "0.11.0")
        assert block is not None
        assert "#175" in block and "#176" in block
        assert "#173" not in block  # next block excluded

    def test_last_block_runs_to_eof(self) -> None:
        block = adv.changelog_block(_CHANGELOG, "0.10.17")
        assert block is not None and "#173" in block

    def test_missing_version_returns_none(self) -> None:
        assert adv.changelog_block(_CHANGELOG, "9.9.9") is None


class TestPrNumber:
    def test_squash_subject(self) -> None:
        assert adv.pr_number("Feat(gates): Open the v0.11 cycle (#175)") == "175"

    def test_takes_the_last_ref(self) -> None:
        assert adv.pr_number("Revert (#100) follow-up (#101)") == "101"

    def test_no_ref(self) -> None:
        assert adv.pr_number("Direct commit without a PR") is None


class TestCompare:
    def test_partitions_missing_and_unreferenced(self) -> None:
        block = adv.changelog_block(_CHANGELOG, "0.11.0")
        assert block is not None
        subjects = [
            "Feat(gates): Open the v0.11 cycle (#175)",   # mentioned
            "Ci(deps): Add dependency-review gate (#176)",  # mentioned
            "Fix(api): Undocumented fix (#199)",            # NOT mentioned
            "Chore: direct commit",                          # no PR ref
        ]
        missing, unreferenced = adv.compare(subjects, block)
        assert missing == ["Fix(api): Undocumented fix (#199)"]
        assert unreferenced == ["Chore: direct commit"]

    def test_all_mentioned_is_clean(self) -> None:
        block = adv.changelog_block(_CHANGELOG, "0.11.0")
        assert block is not None
        missing, unreferenced = adv.compare(
            ["Feat(gates): Open the v0.11 cycle (#175)"], block
        )
        assert missing == [] and unreferenced == []


class TestWorkspaceVersion:
    def test_reads_real_workspace_version(self) -> None:
        version = adv.workspace_version(REPO_ROOT / "pyproject.toml")
        assert version and version.count(".") == 2

    def test_fail_soft_on_missing_file(self, tmp_path: Path) -> None:
        assert adv.workspace_version(tmp_path / "nope.toml") is None


class TestMainFailSoft:
    def test_already_tagged_version_skips(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(adv, "workspace_version", lambda _p: "0.10.17")
        monkeypatch.setattr(adv, "_git", lambda *a: "v0.10.17\n")
        assert adv.main([]) == 0
        assert "already tagged" in capsys.readouterr().out

    def test_no_tags_visible_skips(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr(adv, "workspace_version", lambda _p: "0.11.0")
        monkeypatch.setattr(adv, "_git", lambda *a: "")
        assert adv.main([]) == 0
        assert "skipping" in capsys.readouterr().err

    def test_release_prep_reports_advisories(self, monkeypatch, capsys, tmp_path) -> None:
        def fake_git(*args: str) -> str:
            if args[0] == "tag":
                return ""  # v0.11.0 not tagged yet
            if args[0] == "describe":
                return "v0.10.17\n"
            if args[0] == "log":
                return (
                    "Feat(gates): Open the v0.11 cycle (#175)\n"
                    "Fix(api): Undocumented fix (#199)\n"
                )
            raise AssertionError(f"unexpected git call: {args}")

        monkeypatch.setattr(adv, "workspace_version", lambda _p: "0.11.0")
        monkeypatch.setattr(adv, "_git", fake_git)
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(_CHANGELOG, encoding="utf-8")
        monkeypatch.setattr(adv, "REPO_ROOT", tmp_path)
        assert adv.main([]) == 0  # advisory NEVER fails
        out = capsys.readouterr().out
        assert "ADVISORY: PR not mentioned in [0.11.0]: Fix(api)" in out
        advisory_line = next(
            line for line in out.splitlines() if "ADVISORY" in line
        )
        assert "#175" not in advisory_line
