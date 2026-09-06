"""Unit tests for the capitalized-subject convention enforced by the
commit-msg gate in ``scripts/check_docs_health.py`` (v0.10.7 E7).

The pure detector (``check_subject_capitalized``) is exercised directly
against this cycle's real commit subjects (which must PASS), deliberately
lower-cased subjects (which must FAIL), and the code-identifier exemption
(which must PASS — capitalizing a symbol would corrupt it).

A small end-to-end test drives ``run_commit_msg_hook_check`` against a
temp message file to confirm the hook entry point returns the right exit
code AND that the cap-check runs even when the private phrase config is
absent (the function loads the phrase config lazily, only after the
cap-check, so it cannot early-return past the cap-check).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_PATH = REPO_ROOT / "scripts" / "check_docs_health.py"


def _load_check_module() -> Any:
    mod_name = "check_docs_health_for_subject_test"
    spec = importlib.util.spec_from_file_location(mod_name, CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cdh() -> Any:
    return _load_check_module()


class TestCheckSubjectCapitalized:
    """The pure detector. ``None`` means pass/exempt; a string means
    violation."""

    # Real subjects from this cycle (+ the spec's explicit examples) that
    # MUST pass (return None).
    PASS_SUBJECTS: ClassVar[list[str]] = [
        # Non-conventional, capitalized.
        "Tweak for clarity: v0.10.7",
        # Conventional, capitalized description.
        "feat(scripts): Add version_tracked_files.yaml manifest",
        "refactor(scripts): Drive bump_version.py from the manifest",
        # Code-identifier-leading description → exempt.
        "fix(hooks): check_secrets allowlists canonical AWS example keys",
        "fix(hooks): check_uv_lock_pin_drift reads workspace members from manifest",
        # Code identifier with a dot / call parens → exempt.
        "refactor(core): gap_report_to_oscal_poam() returns OSCAL 1.1.2",
        "chore(scripts): bump_version.py skips lockfiles",
        # Backtick-wrapped leading identifier → exempt.
        "docs(api): `verify_signed_artifact` tool documented",
        # The new commit subjects this very cycle ships.
        "feat(hooks): Enforce capitalized commit subjects in the commit-msg gate",
        "chore(repo): Manage GitHub About description as code (.github/repo-description.txt)",
        # Bang (breaking) marker, capitalized description.
        "feat(api)!: Drop the legacy Finding alias",
        # Bare type (no scope), capitalized description.
        "feat: Add SARIF output mode",
    ]

    # Subjects that MUST fail (return a non-None message).
    FAIL_SUBJECTS: ClassVar[list[str]] = [
        "feat(x): add a thing",  # → should be "Add"
        "docs: update the readme",  # → should be "Update"
        "new thing without type",  # → should be "New"
    ]

    @pytest.mark.parametrize("subject", PASS_SUBJECTS)
    def test_pass_subjects(self, cdh: Any, subject: str) -> None:
        assert cdh.check_subject_capitalized(subject) is None, subject

    @pytest.mark.parametrize("subject", FAIL_SUBJECTS)
    def test_fail_subjects(self, cdh: Any, subject: str) -> None:
        msg = cdh.check_subject_capitalized(subject)
        assert msg is not None, subject
        assert isinstance(msg, str) and msg, subject

    def test_fail_message_suggests_capitalized_word(self, cdh: Any) -> None:
        msg = cdh.check_subject_capitalized("feat(x): add a thing")
        assert msg is not None
        assert "Add" in msg, msg

    def test_non_conventional_first_word_flagged(self, cdh: Any) -> None:
        msg = cdh.check_subject_capitalized("new thing without type")
        assert msg is not None
        assert "New" in msg, msg

    # ── Git-generated / special subjects are exempt ─────────────────────
    @pytest.mark.parametrize(
        "subject",
        [
            "Merge branch 'develop' into main",
            "Merge pull request #42 from foo/bar",
            'Revert "feat: add a thing"',
            "fixup! feat: add a thing",
            "squash! refactor: clean up",
            "amend! docs: update",
            # A lower-cased merge-message tail does not retroactively make it
            # non-special: the `Merge ` prefix wins.
            "Merge remote-tracking branch 'origin/main'",
        ],
    )
    def test_special_prefixes_exempt(self, cdh: Any, subject: str) -> None:
        assert cdh.check_subject_capitalized(subject) is None, subject

    # ── Code-identifier exemption (focused) ─────────────────────────────
    @pytest.mark.parametrize(
        "subject",
        [
            "fix(hooks): check_secrets allowlists canonical AWS example keys",
            "refactor: bump_version.py drives from the manifest",
            "fix: gap_report_to_oscal_poam() back-matter integrity",
            "docs: `EventAction` enum documented",
            "perf: my_module.func is faster now",
        ],
    )
    def test_code_identifier_leading_exempt(self, cdh: Any, subject: str) -> None:
        assert cdh.check_subject_capitalized(subject) is None, subject

    # ── Leading non-alpha is not flagged ────────────────────────────────
    # After skipping any opening backtick/quote/paren, the first real
    # character is a digit or symbol — there is nothing to capitalize.
    @pytest.mark.parametrize(
        "subject",
        [
            "feat: 3D rendering support",  # leading digit
            "fix: 64-bit offset handling",  # leading digit
            "chore: (2026) refresh copyright",  # paren skipped → digit leads
        ],
    )
    def test_leading_non_alpha_not_flagged(self, cdh: Any, subject: str) -> None:
        assert cdh.check_subject_capitalized(subject) is None, subject

    # After skipping an opening paren/quote, a lowercase WORD is revealed —
    # that IS flagged (the punctuation is skipped, not the requirement).
    @pytest.mark.parametrize(
        "subject",
        [
            "fix: (regression) restore output",  # skip '(' → "regression" lower
            'chore: "quoted" leading token',  # skip '\"' → "quoted" lower
        ],
    )
    def test_lowercase_word_after_opening_punct_flagged(self, cdh: Any, subject: str) -> None:
        assert cdh.check_subject_capitalized(subject) is not None, subject

    def test_empty_and_blank_pass(self, cdh: Any) -> None:
        assert cdh.check_subject_capitalized("") is None
        assert cdh.check_subject_capitalized("   ") is None


class TestSubjectFromMessage:
    def test_skips_blank_and_comment_lines(self, cdh: Any) -> None:
        msg = "\n\n# a git comment\nfeat: Add a thing\nbody line\n"
        assert cdh._subject_from_message(msg) == "feat: Add a thing"

    def test_no_real_line_returns_empty(self, cdh: Any) -> None:
        assert cdh._subject_from_message("# only a comment\n\n") == ""


class TestRunCommitMsgHookCapCheck:
    """End-to-end via the hook entry point. The cap-check must run
    regardless of whether the private phrase config is present — the
    function reads the message + runs the cap-check BEFORE it loads the
    phrase config."""

    def test_bad_subject_blocks(self, cdh: Any, tmp_path: Path) -> None:
        msg = tmp_path / "MSG"
        msg.write_text("feat(x): add a thing\n", encoding="utf-8")
        assert cdh.run_commit_msg_hook_check(str(msg)) == 2

    def test_good_subject_passes(self, cdh: Any, tmp_path: Path) -> None:
        msg = tmp_path / "MSG"
        msg.write_text("feat(x): Add a thing\n", encoding="utf-8")
        assert cdh.run_commit_msg_hook_check(str(msg)) == 0

    def test_code_identifier_subject_passes(self, cdh: Any, tmp_path: Path) -> None:
        msg = tmp_path / "MSG"
        msg.write_text(
            "fix(hooks): check_secrets allowlists canonical AWS example keys\n",
            encoding="utf-8",
        )
        assert cdh.run_commit_msg_hook_check(str(msg)) == 0

    def test_cap_check_runs_with_phrase_config_absent(
        self, cdh: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Force the phrase config to report "not loaded" and confirm the
        cap-check still blocks a bad subject (proves the cap-check is not
        gated behind the phrase config)."""
        absent = cdh.PhraseConfig.empty()
        assert not absent.is_loaded
        monkeypatch.setattr(cdh, "load_phrase_config", lambda: (absent, None))
        bad = tmp_path / "BAD"
        bad.write_text("docs: update the readme\n", encoding="utf-8")
        assert cdh.run_commit_msg_hook_check(str(bad)) == 2

        good = tmp_path / "GOOD"
        good.write_text("docs: Update the readme\n", encoding="utf-8")
        assert cdh.run_commit_msg_hook_check(str(good)) == 0
