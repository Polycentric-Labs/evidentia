"""Unit tests for ``scripts/check_public_surface.py`` (v0.12 freeze-prep).

`docs/api-stability.md` is NORMATIVE, but through v0.11.x nothing
mechanically verified it: §5's frozen import list, the MCP frozen-tool
table, and the env-var public contract were all prose that could drift
from the code silently. This gate closes that — and these tests pin the
gate's own parsing + comparison rules against synthetic documents, so
they neither depend on nor freeze the real doc's current content.

The end-to-end assertion (the gate passes on the real repo) lives in
``test_gate_passes_on_the_real_repo`` at the bottom.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "check_public_surface.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load_module("check_public_surface_under_test", CHECK_PATH)


# ── §5 frozen-import extraction ────────────────────────────────────

SECTION_5_DOC = """\
### 4. Plugin contracts

```python
from evidentia_core.plugins import NotTheSectionWeWant
```

### 5. Library entry points

Public importable paths that operators and integrators use:

```python
# A comment line
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models import ControlGap, GapFinding, ...
from evidentia_core.rbac import (
    Role, RBACPolicy,
)
```

### 6. REST API URIs
"""


class TestFrozenImportExtraction:
    def test_reads_only_the_section_5_block(self, check: Any) -> None:
        statements = check.parse_frozen_imports(SECTION_5_DOC)
        joined = "\n".join(statements)
        assert "NotTheSectionWeWant" not in joined
        assert "GapAnalyzer" in joined

    def test_strips_the_elision_marker(self, check: Any) -> None:
        """``, ...`` documents "and more"; it is not valid Python."""
        statements = check.parse_frozen_imports(SECTION_5_DOC)
        models = [s for s in statements if "evidentia_core.models" in s]
        assert models == ["from evidentia_core.models import ControlGap, GapFinding"]

    def test_joins_parenthesised_multi_line_imports(self, check: Any) -> None:
        statements = check.parse_frozen_imports(SECTION_5_DOC)
        rbac = [s for s in statements if "evidentia_core.rbac" in s]
        assert len(rbac) == 1
        assert "Role" in rbac[0] and "RBACPolicy" in rbac[0]

    def test_drops_comment_lines(self, check: Any) -> None:
        statements = check.parse_frozen_imports(SECTION_5_DOC)
        assert not any(s.lstrip().startswith("#") for s in statements)

    def test_every_extracted_statement_is_valid_python(self, check: Any) -> None:
        for statement in check.parse_frozen_imports(SECTION_5_DOC):
            compile(statement, "<frozen-import>", "exec")

    def test_missing_section_is_an_error_not_a_silent_pass(self, check: Any) -> None:
        """A renamed heading must fail loudly, never vacuously pass."""
        with pytest.raises(check.SurfaceParseError):
            check.parse_frozen_imports("# api-stability\n\nNo section five.\n")


# ── MCP frozen-tool table ──────────────────────────────────────────

MCP_DOC = """\
## MCP tool contract

| Tool | Since | Purpose |
|---|---|---|
| `list_frameworks` | v0.8.0 | Enumerate bundled catalogs |
| `get_control` | v0.8.0 | Single-control lookup |

Tool *parameter names* are frozen.

---

## Env-var public contract (v0.9.7 NEW)

| Env var | Since | Purpose |
|---|---|---|
| `EVIDENTIA_POAM_STORE_DIR` | v0.9.0 | POA&M JSON store directory |
"""


class TestMcpToolTable:
    def test_parses_the_frozen_tool_names(self, check: Any) -> None:
        assert check.parse_frozen_mcp_tools(MCP_DOC) == {
            "list_frameworks",
            "get_control",
        }

    def test_does_not_bleed_into_the_next_table(self, check: Any) -> None:
        """The env-var table follows; its rows must not be read as tools."""
        assert "EVIDENTIA_POAM_STORE_DIR" not in check.parse_frozen_mcp_tools(MCP_DOC)

    def test_a_removed_frozen_tool_fails(self, check: Any) -> None:
        failures = check.compare_mcp_tools(
            frozen={"list_frameworks", "get_control"},
            live={"list_frameworks"},
        )
        assert len(failures) == 1
        assert "get_control" in failures[0]

    def test_an_undocumented_new_tool_fails_as_doc_drift(self, check: Any) -> None:
        """Adding a tool is non-breaking, but the table must record it."""
        failures = check.compare_mcp_tools(
            frozen={"list_frameworks"},
            live={"list_frameworks", "brand_new_tool"},
        )
        assert len(failures) == 1
        assert "brand_new_tool" in failures[0]

    def test_matching_sets_pass(self, check: Any) -> None:
        assert check.compare_mcp_tools(frozen={"list_frameworks"}, live={"list_frameworks"}) == []


# ── env-var public contract ────────────────────────────────────────


class TestEnvVarContract:
    def test_parses_the_frozen_env_var_names(self, check: Any) -> None:
        assert check.parse_frozen_env_vars(MCP_DOC) == {"EVIDENTIA_POAM_STORE_DIR"}

    def test_a_frozen_var_absent_from_code_fails(self, check: Any) -> None:
        """A frozen var vanishing from the source is a silent break."""
        failures = check.compare_env_vars(
            frozen={"EVIDENTIA_POAM_STORE_DIR"},
            live={"EVIDENTIA_GAP_STORE_DIR"},
        )
        assert len(failures) == 1
        assert "EVIDENTIA_POAM_STORE_DIR" in failures[0]

    def test_live_but_unfrozen_vars_do_not_fail(self, check: Any) -> None:
        """Unfrozen vars are freeze CANDIDATES, not contract violations.

        Failing on them would make every new internal env var a
        blocking change. They are reported for the v1.0 freeze
        decision instead (see docs/v1.0-freeze-candidates.md).
        """
        assert (
            check.compare_env_vars(
                frozen={"EVIDENTIA_POAM_STORE_DIR"},
                live={"EVIDENTIA_POAM_STORE_DIR", "EVIDENTIA_NEW_THING"},
            )
            == []
        )

    def test_discovers_env_vars_from_source(self, check: Any, tmp_path: Path) -> None:
        pkg = tmp_path / "packages" / "demo" / "src" / "demo"
        pkg.mkdir(parents=True)
        (pkg / "mod.py").write_text(
            "import os\n"
            'A = os.environ.get("EVIDENTIA_ALPHA")\n'
            'B = os.getenv("EVIDENTIA_BETA", "x")\n'
            'C = os.environ["NOT_OURS"]\n',
            encoding="utf-8",
        )
        found = check.discover_live_env_vars(tmp_path / "packages")
        assert "EVIDENTIA_ALPHA" in found
        assert "EVIDENTIA_BETA" in found
        assert "NOT_OURS" not in found


# ── end-to-end ─────────────────────────────────────────────────────


def test_gate_passes_on_the_real_repo(check: Any) -> None:
    """The whole point: HEAD's code matches HEAD's NORMATIVE contract."""
    assert check.main([]) == 0
