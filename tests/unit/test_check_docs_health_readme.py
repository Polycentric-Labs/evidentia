"""Unit tests for the two README invariants added to
``scripts/check_docs_health.py`` in v0.10.7 E5c:

  * ``readme_header_titlecase``        — every README ##/### header is Title
    Case (stop-words lowercase except first; acronyms + "Evidentia"
    preserved).
  * ``readme_recent_releases_current`` — the README "Recent Releases" block
    has exactly 3 entries and the newest == the current project version.

The Title-Case detector (``_titlecase_violations``) is a pure function and
is exercised directly. The two ``check_*`` entry points read ``README.md``
relative to CWD, so the synthetic FAIL test chdir's into a temp dir with a
crafted README. No network is touched.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_PATH = REPO_ROOT / "scripts" / "check_docs_health.py"


def _load_check_module() -> Any:
    mod_name = "check_docs_health_under_test"
    spec = importlib.util.spec_from_file_location(mod_name, CHECK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cdh() -> Any:
    return _load_check_module()


class TestTitlecaseViolations:
    """The pure detector: real README headers PASS; lowercase principal
    words + miscased acronyms FAIL; stop-words/acronyms are not false
    positives."""

    # (header, expect_violation?) — drawn from the actual post-E5b README
    # plus deliberately-wrong cases.
    GOOD_HEADERS: ClassVar[list[str]] = [
        "What is Evidentia?",  # "is" stop-word; Evidentia proper noun
        "Install",
        "Quickstart (60 Seconds)",  # "(60" skipped; Seconds capitalized
        "Features",
        "What's in the Box",  # "in"/"the" stop-words; Box principal
        "Documentation",
        "Recent Releases",
        "Community & Governance",  # "&" token skipped
        "AI Assistance",  # AI acronym preserved
        "License",
    ]
    BAD_HEADERS: ClassVar[list[str]] = [
        "Recent releases",  # "releases" should be capitalized
        "new thing",  # both principal words lowercase
        "ai assistance",  # "ai" must be AI + "assistance" cap
        "What's in the box",  # "box" should be Box
        "Community + governance",  # "governance" should be capitalized
    ]

    @pytest.mark.parametrize("header", GOOD_HEADERS)
    def test_good_headers_have_no_violations(self, cdh: Any, header: str) -> None:
        assert cdh._titlecase_violations(header) == [], header

    @pytest.mark.parametrize("header", BAD_HEADERS)
    def test_bad_headers_flagged(self, cdh: Any, header: str) -> None:
        assert cdh._titlecase_violations(header), header

    def test_acronym_wrong_case_message(self, cdh: Any) -> None:
        violations = cdh._titlecase_violations("ai assistance")
        assert any("expected AI" in v for v in violations)

    def test_first_word_stopword_still_capitalized(self, cdh: Any) -> None:
        # A stop-word in first position must be capitalized.
        assert cdh._titlecase_violations("the Big Picture")  # "the" first
        assert cdh._titlecase_violations("The Big Picture") == []


class TestCheckReadmeHeaderTitlecaseRealReadme:
    def test_real_readme_headers_all_pass(self, cdh: Any) -> None:
        prev = Path.cwd()
        os.chdir(REPO_ROOT)
        try:
            result = cdh.CheckResult()
            cdh.check_readme_header_titlecase(result)
        finally:
            os.chdir(prev)
        fails = [f for f in result.findings if f.check == "readme_header_titlecase" and f.severity == cdh.Severity.FAIL]
        assert fails == [], [f.message for f in fails]


class TestCheckReadmeHeaderTitlecaseSynthetic:
    @pytest.fixture
    def chdir_tmp(self, tmp_path: Path) -> Iterator[Path]:
        prev = Path.cwd()
        os.chdir(tmp_path)
        try:
            yield tmp_path
        finally:
            os.chdir(prev)

    def test_lowercase_header_fails(self, cdh: Any, chdir_tmp: Path) -> None:
        (chdir_tmp / "README.md").write_text(
            "# Title\n\n## Good Header\n\nbody\n\n## new thing\n\nbody\n",
            encoding="utf-8",
        )
        result = cdh.CheckResult()
        cdh.check_readme_header_titlecase(result)
        fails = [f for f in result.findings if f.check == "readme_header_titlecase" and f.severity == cdh.Severity.FAIL]
        assert len(fails) == 1
        assert "new thing" in fails[0].message

    def test_code_fence_comments_not_flagged(self, cdh: Any, chdir_tmp: Path) -> None:
        # A `# 1. lowercase` bash comment INSIDE a fenced block looks like an
        # h1 but must be skipped (mirrors the quickstart block).
        (chdir_tmp / "README.md").write_text(
            "# Title\n\n## Good Header\n\n```bash\n# 1. list things\n## not a real header\n```\n",
            encoding="utf-8",
        )
        result = cdh.CheckResult()
        cdh.check_readme_header_titlecase(result)
        fails = [f for f in result.findings if f.severity == cdh.Severity.FAIL]
        assert fails == [], [f.message for f in fails]


class TestCheckReadmeRecentReleasesCurrentRealReadme:
    def test_real_readme_recent_releases_passes(self, cdh: Any) -> None:
        prev = Path.cwd()
        os.chdir(REPO_ROOT)
        try:
            result = cdh.CheckResult()
            cdh.check_readme_recent_releases_current(result)
        finally:
            os.chdir(prev)
        fails = [
            f
            for f in result.findings
            if f.check == "readme_recent_releases_current" and f.severity == cdh.Severity.FAIL
        ]
        assert fails == [], [f.message for f in fails]


class TestPublicVendorHostPolicy:
    """Exercise the shipped policy with no private configuration overlay."""

    @pytest.fixture
    def public_config(self, cdh: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        source = REPO_ROOT / cdh.BASE_CONFIG_PATH
        destination = tmp_path / cdh.BASE_CONFIG_PATH
        destination.parent.mkdir(parents=True)
        destination.write_bytes(source.read_bytes())
        monkeypatch.setattr(cdh, "REPO_ROOT", tmp_path)
        config, error = cdh.load_phrase_config()
        assert error is None
        assert config.is_loaded
        assert sum(name == "vendor_host_github_io" for name, _ in config.forbidden_patterns) == 1
        return config

    @pytest.mark.parametrize(
        "labels",
        [
            ("squidfunk", "github", "io"),
            ("untrusted", "github", "io"),
            ("polycentric-labs", "github", "io", "untrusted", "github", "io"),
            ("polycentric-labs", "github", "ioevil", "github", "io"),
            ("child", "polycentric-labs", "github", "io"),
            ("polycentric-labs-other", "github", "io"),
        ],
        ids=["former-exception", "external", "extended-host", "extended-label", "subdomain", "lookalike"],
    )
    def test_external_host_is_rejected(
        self, cdh: Any, public_config: Any, tmp_path: Path, labels: tuple[str, ...]
    ) -> None:
        document = tmp_path / "guide.md"
        target = "https://" + ".".join(labels) + "/reference/"
        document.write_text("[Reference](" + target + ")\n", encoding="utf-8")
        result = cdh.CheckResult()
        cdh.check_phrase_audit([document], public_config, result)
        failures = [finding for finding in result.findings if finding.severity == cdh.Severity.FAIL]
        assert len(failures) == 1
        assert failures[0].check == "phrase_audit:vendor_host_github_io"

    @pytest.mark.parametrize("host", ["polycentric-labs.github.io", "POLYCENTRIC-LABS.GITHUB.IO"])
    @pytest.mark.parametrize("suffix", ["", "/", "/reference/", "?q=docs", "#reference", ":443/docs", "./docs"])
    def test_exact_project_host_is_allowed(
        self, cdh: Any, public_config: Any, tmp_path: Path, host: str, suffix: str
    ) -> None:
        document = tmp_path / "guide.md"
        document.write_text("[Reference](https://" + host + suffix + ")\n", encoding="utf-8")
        result = cdh.CheckResult()
        cdh.check_phrase_audit([document], public_config, result)
        assert result.fail_count == 0, result.findings

    @pytest.mark.parametrize("separator", ["@", ":443@", ",name@", "'name@", ")name@"])
    def test_project_hostname_in_userinfo_does_not_exempt_external_destination(
        self, cdh: Any, public_config: Any, tmp_path: Path, separator: str
    ) -> None:
        document = tmp_path / "guide.md"
        destination = ".".join(("untrusted", "github", "io"))
        target = "https://polycentric-labs.github.io" + separator + destination + "/"
        document.write_text("[Reference](" + target + ")\n", encoding="utf-8")
        result = cdh.CheckResult()
        cdh.check_phrase_audit([document], public_config, result)
        failures = [finding for finding in result.findings if finding.severity == cdh.Severity.FAIL]
        assert len(failures) == 1
        assert failures[0].check == "phrase_audit:vendor_host_github_io"

    @pytest.mark.parametrize(
        ("userinfo", "destination_labels", "rejected"),
        [
            ("reader", ("untrusted", "github", "io"), True),
            ("reader", ("polycentric-labs", "github", "io"), True),
            (".".join(("untrusted", "github", "io")), ("evidentiagrc", "com"), False),
        ],
        ids=["external-destination", "owned-pages-with-userinfo", "owned-custom-destination"],
    )
    def test_userinfo_is_not_the_destination(
        self,
        cdh: Any,
        public_config: Any,
        tmp_path: Path,
        userinfo: str,
        destination_labels: tuple[str, ...],
        rejected: bool,
    ) -> None:
        document = tmp_path / "guide.md"
        target = "https://" + userinfo + "@" + ".".join(destination_labels) + "/"
        document.write_text("[Reference](" + target + ")\n", encoding="utf-8")
        result = cdh.CheckResult()
        cdh.check_phrase_audit([document], public_config, result)
        failures = [finding for finding in result.findings if finding.severity == cdh.Severity.FAIL]
        assert len(failures) == int(rejected)
        assert all(finding.check == "phrase_audit:vendor_host_github_io" for finding in failures)
