"""Check exact publisher link context and refusal outside that scope."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PREFIX = (
    "packages/evidentia-core/src/evidentia_core/catalogs/data/sources/"
    "cisa-scuba-m365/7ef9501d7de9804ddb9d6013af6b665cccfb39d9/"
)
TARGET = "../../../README.md#quick-start-guide"
UPSTREAM = (
    "https://github.com/cisagov/ScubaGear/blob/7ef9501d7de9804ddb9d6013af6b665cccfb39d9/README.md#quick-start-guide"
)
CASES = [
    ("aad.md", "ea0fe8dec93fa85ce580280b326b955c11aeb5fa24a18e840186bff05f58c415", 37),
    ("defender.md", "5718b800e9c99ac73f0196a2665ba563e36bfe0236aaf6a54a0eccbcf97f402e", 38),
    ("exo.md", "de6fd5151958383ecaae4f8a0d1092d5bb6d6d885d21afc8f13221dd775d80c1", 56),
    ("powerplatform.md", "e87a2d553aa0390dcce5d9e7d4a69e1cd898080cd5cf1c519e8e72e2a1cc98e5", 67),
    ("securitysuite.md", "55623da97cb70fbee74c0405639d14150c118e7f1446b10c4477b2b3efaf9bbf", 64),
    ("sharepoint.md", "7ea2f414156f2d367924f8a8d5b2267cfd39a679ae65bbfbc2327cafaac2cb10", 26),
    ("teams.md", "0b7d56dfea2f579face7fa94371f88a038c5e4cc7d795d6c3195c5a46dab2d6a", 59),
]


@pytest.fixture
def checker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    spec = importlib.util.spec_from_file_location(
        "docs_source_context_under_test", REPO_ROOT / "scripts/check_docs_health.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    return module


def put_source(relative: str, raw: bytes) -> Path:
    path = Path(relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize(("name", "digest", "line"), CASES)
def test_exact_publisher_link_uses_pinned_upstream_context(checker: Any, name: str, digest: str, line: int) -> None:
    relative = SOURCE_PREFIX + name
    assert checker.PINNED_SOURCE_LINK_CONTEXTS[relative] == (digest, line, TARGET, UPSTREAM)
    tracked = {
        put_source(SOURCE_PREFIX + sibling, (REPO_ROOT / (SOURCE_PREFIX + sibling)).read_bytes())
        for sibling, _, _ in CASES
    }
    path = Path(relative)
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], tracked, result)
    assert result.fail_count == 0, result.findings


@pytest.mark.parametrize(("name", "digest", "line"), CASES)
@pytest.mark.parametrize("change", ["extra_bytes", "changed_target", "added_link", "changed_line_endings"])
def test_changed_publisher_bytes_refuse_context(checker: Any, name: str, digest: str, line: int, change: str) -> None:
    relative = SOURCE_PREFIX + name
    raw = (REPO_ROOT / relative).read_bytes()
    modified = {
        "extra_bytes": raw + b"\n",
        "changed_target": raw.replace(TARGET.encode(), b"../../../missing.md"),
        "added_link": raw + b"\n[other](missing.md)\n",
        "changed_line_endings": raw.replace(b"\n", b"\r\n"),
    }[change]
    assert modified != raw
    path = put_source(relative, modified)
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], {path}, result)
    assert any(f.check == "source_link_context" and f.severity == checker.Severity.FAIL for f in result.findings)


@pytest.mark.parametrize(("name", "digest", "line"), CASES)
def test_same_bytes_at_another_path_keep_local_link_checks(checker: Any, name: str, digest: str, line: int) -> None:
    path = put_source("docs/nested/more/" + name, (REPO_ROOT / (SOURCE_PREFIX + name)).read_bytes())
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], {path}, result)
    assert any(f.check == "cross_link_resolve" and f.severity == checker.Severity.FAIL for f in result.findings)
    assert not any(f.check == "source_link_context" for f in result.findings)


@pytest.mark.parametrize("field", ["line", "target"])
def test_context_matches_both_line_and_target(checker: Any, monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    name, digest, line = CASES[0]
    relative = SOURCE_PREFIX + name
    changed = (digest, line + 1, TARGET, UPSTREAM) if field == "line" else (digest, line, TARGET + "-other", UPSTREAM)
    monkeypatch.setitem(checker.PINNED_SOURCE_LINK_CONTEXTS, relative, changed)
    path = put_source(relative, (REPO_ROOT / relative).read_bytes())
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], {path}, result)
    assert any(f.check == "cross_link_resolve" and f.severity == checker.Severity.FAIL for f in result.findings)


def test_ordinary_broken_project_link_still_fails(checker: Any) -> None:
    path = put_source("docs/guide.md", b"[missing](missing.md)\n")
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], {path}, result)
    assert result.fail_count == 1
    assert result.findings[0].check == "cross_link_resolve"


def test_context_has_only_seven_pinned_documents(checker: Any) -> None:
    assert set(checker.PINNED_SOURCE_LINK_CONTEXTS) == {SOURCE_PREFIX + name for name, _, _ in CASES}


@pytest.mark.parametrize("name", ["defender.md", "exo.md", "teams.md"])
def test_other_links_in_pinned_documents_still_require_tracked_files(checker: Any, name: str) -> None:
    relative = SOURCE_PREFIX + name
    path = put_source(relative, (REPO_ROOT / relative).read_bytes())
    result = checker.CheckResult()
    checker.check_cross_link_resolve([path], {path}, result)
    assert any(f.check == "cross_link_resolve" and f.severity == checker.Severity.FAIL for f in result.findings)
    assert not any(f.check == "source_link_context" for f in result.findings)
