"""Tests for scripts/check_uv_pilot_graduation.py (H5 pilot-graduation watcher)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_uv_pilot_graduation as watcher  # noqa: E402

# The exact shape uv 0.11.6 emits today (observed 2026-07-10).
_PREVIEW_STDERR = (
    "warning: `uv audit` is experimental and may change without warning. "
    "Pass `--preview-features audit` to disable this warning.\n"
)
_AUDIT_STDOUT = (
    "Resolved 257 packages in 14ms\n"
    "Found 2 known vulnerabilities and no adverse project statuses "
    "in 248 packages\n"
)


class TestClassifyAuditProbe:
    def test_preview_warning_present(self) -> None:
        assert (
            watcher.classify_audit_probe(0, _AUDIT_STDOUT, _PREVIEW_STDERR)
            == "preview"
        )

    def test_graduated_when_warning_gone(self) -> None:
        assert watcher.classify_audit_probe(0, _AUDIT_STDOUT, "") == "graduated"

    def test_nonzero_exit_with_advisories_still_classifies(self) -> None:
        # `uv audit` exits non-zero when advisories exist — the exit code is
        # not the ran/didn't-run signal.
        assert watcher.classify_audit_probe(1, _AUDIT_STDOUT, "") == "graduated"
        assert (
            watcher.classify_audit_probe(1, _AUDIT_STDOUT, _PREVIEW_STDERR)
            == "preview"
        )

    def test_unrecognized_output_is_indeterminate(self) -> None:
        assert watcher.classify_audit_probe(2, "", "error: no lockfile") == (
            "indeterminate"
        )
        assert watcher.classify_audit_probe(127, "", "") == "indeterminate"


class TestChangelogGraduationHits:
    def test_stabilize_phrasing_matches_either_order(self) -> None:
        text = (
            "## 0.12.0\n"
            "- Stabilize `uv audit` (#12345)\n"
            "- `UV_MALWARE_CHECK` is now stable and on by default\n"
        )
        hits = watcher.changelog_graduation_hits(text)
        assert len(hits) == 2
        assert "Stabilize `uv audit`" in hits[0]
        assert "UV_MALWARE_CHECK" in hits[1]

    def test_no_longer_preview_phrasing(self) -> None:
        text = "- `uv audit` is no longer in preview\n"
        assert len(watcher.changelog_graduation_hits(text)) == 1

    def test_plain_feature_mentions_do_not_match(self) -> None:
        text = (
            "- Add `--ignore` flag to `uv audit` (#111)\n"
            "- Fix malware-check false positive on yanked wheels (#222)\n"
            "- Stabilize `uv python install` defaults (#333)\n"
        )
        assert watcher.changelog_graduation_hits(text) == []

    def test_dedupes_repeated_lines(self) -> None:
        line = "- Stabilize `uv audit`\n"
        assert len(watcher.changelog_graduation_hits(line * 3)) == 1


class TestFetchChangelogFailSoft:
    def test_network_error_returns_none(self) -> None:
        def opener(_req, timeout=30):
            del timeout
            raise OSError("boom")

        assert watcher.fetch_changelog(opener=opener) is None


class TestMain:
    def test_offline_run_writes_empty_findings_and_exits_zero(
        self, tmp_path: Path
    ) -> None:
        out = tmp_path / "findings.md"
        rc = watcher.main(
            ["--output", str(out), "--skip-probe", "--skip-fetch"]
        )
        assert rc == 0
        assert out.read_text(encoding="utf-8") == ""

    def test_graduated_probe_produces_finding(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(watcher, "run_audit_probe", lambda: "graduated")
        out = tmp_path / "findings.md"
        rc = watcher.main(["--output", str(out), "--skip-fetch"])
        assert rc == 0
        text = out.read_text(encoding="utf-8")
        assert "graduate" in text
        assert "--preview-features audit" in text

    def test_preview_probe_produces_no_finding(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(watcher, "run_audit_probe", lambda: "preview")
        out = tmp_path / "findings.md"
        rc = watcher.main(["--output", str(out), "--skip-fetch"])
        assert rc == 0
        assert out.read_text(encoding="utf-8") == ""
