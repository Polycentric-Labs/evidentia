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
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "check_public_surface.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module under test declares a dataclass,
    # and dataclasses resolve `from __future__ import annotations` string
    # annotations by looking the module up in sys.modules by name. Without
    # this line that lookup finds nothing and the dataclass decorator
    # raises at import time.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load_module("check_public_surface_under_test", CHECK_PATH)


# ── §1 frozen-model table ──────────────────────────────────────────

SECTION_1_DOC = """\
### 1. Pydantic model fields

**Packages**: every module of `evidentia_core.models`.

| Module | Key models |
|--------|-----------|
| `models/example.py` (v0.10.0+) | `ExampleModel`, `EXAMPLE_CONSTANT`, `helper()`, `field_name` |
| `models/other.py` (v0.9.3+) | `OtherModel` (v0.9.6) |

### 2. EventAction enum
"""


class TestFrozenModelTable:
    def test_parses_the_module_path_from_the_first_cell(self, check: Any) -> None:
        rows = check.parse_frozen_models(SECTION_1_DOC)
        paths = [row.module_path for row in rows]
        assert paths == ["models/example.py", "models/other.py"]

    def test_classifies_capwords_and_upper_snake_tokens_as_symbols(self, check: Any) -> None:
        rows = check.parse_frozen_models(SECTION_1_DOC)
        example = rows[0]
        assert example.symbols == ("ExampleModel", "EXAMPLE_CONSTANT")

    def test_classifies_a_parenthesised_token_as_a_callable(self, check: Any) -> None:
        rows = check.parse_frozen_models(SECTION_1_DOC)
        example = rows[0]
        assert example.callables == ("helper",)

    def test_ignores_a_bare_lowercase_field_name(self, check: Any) -> None:
        rows = check.parse_frozen_models(SECTION_1_DOC)
        example = rows[0]
        assert "field_name" not in example.symbols
        assert "field_name" not in example.callables

    def test_ignores_a_version_annotation_outside_backticks(self, check: Any) -> None:
        """``(v0.9.6)`` trails a symbol in plain text, not inside backticks.

        It must not become a phantom third symbol and must not corrupt
        the one real symbol on the row.
        """
        rows = check.parse_frozen_models(SECTION_1_DOC)
        other = rows[1]
        assert other.symbols == ("OtherModel",)
        assert other.callables == ()

    def test_skips_the_header_and_separator_rows(self, check: Any) -> None:
        rows = check.parse_frozen_models(SECTION_1_DOC)
        assert len(rows) == 2
        assert all(row.module_path.startswith("models/") for row in rows)

    def test_missing_section_is_an_error_not_a_silent_pass(self, check: Any) -> None:
        """A renamed heading must fail loudly, never vacuously pass."""
        with pytest.raises(check.SurfaceParseError):
            check.parse_frozen_models("# api-stability\n\nNo section one.\n")

    def test_compare_reports_a_module_that_does_not_import(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/gone.py", symbols=("Gone",), callables=())]
        live = {"models/gone.py": {"error": "ModuleNotFoundError: no module named evidentia_core.models.gone"}}
        failures = check.compare_frozen_models(rows, live, ["models/gone.py"])
        assert len(failures) == 1
        assert "models/gone.py" in failures[0]

    def test_compare_reports_a_phantom_symbol(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/x.py", symbols=("Phantom",), callables=())]
        live = {"models/x.py": {"names": ["Real"], "class_attrs": {}}}
        failures = check.compare_frozen_models(rows, live, ["models/x.py"])
        assert len(failures) == 1
        assert "Phantom" in failures[0]

    def test_compare_reports_a_phantom_callable(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/x.py", symbols=(), callables=("ghost_fn",))]
        live = {"models/x.py": {"names": ["Real"], "class_attrs": {}}}
        failures = check.compare_frozen_models(rows, live, ["models/x.py"])
        assert len(failures) == 1
        assert "ghost_fn" in failures[0]

    def test_compare_resolves_a_callable_through_a_listed_class(self, check: Any) -> None:
        """A callable need not be a module attribute if a listed class has it."""
        rows = [check.FrozenModelRow(module_path="models/x.py", symbols=("Widget",), callables=("make",))]
        live = {
            "models/x.py": {
                "names": ["Widget"],
                "class_attrs": {"Widget": ["make"]},
                "callables": [],
                "class_callables": {"Widget": ["make"]},
            }
        }
        assert check.compare_frozen_models(rows, live, ["models/x.py"]) == []

    def test_compare_reports_a_models_module_with_no_row(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/x.py", symbols=(), callables=())]
        live = {"models/x.py": {"names": [], "class_attrs": {}}}
        failures = check.compare_frozen_models(rows, live, ["models/x.py", "models/forgotten.py"])
        assert len(failures) == 1
        assert "models/forgotten.py" in failures[0]

    def test_a_fully_matching_table_passes(self, check: Any) -> None:
        rows = [
            check.FrozenModelRow(module_path="models/x.py", symbols=("Widget",), callables=("make",)),
            check.FrozenModelRow(module_path="models/y.py", symbols=("EXAMPLE_CONST",), callables=()),
        ]
        live = {
            "models/x.py": {
                "names": ["Widget"],
                "class_attrs": {"Widget": ["make"]},
                "callables": [],
                "class_callables": {"Widget": ["make"]},
            },
            "models/y.py": {"names": ["EXAMPLE_CONST"], "class_attrs": {}},
        }
        assert check.compare_frozen_models(rows, live, ["models/x.py", "models/y.py"]) == []


class TestDiscoverModuleSymbols:
    def test_discovers_the_real_common_module(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/common.py", symbols=(), callables=())]
        live = check.discover_module_symbols(rows)
        names = live["models/common.py"]["names"]
        assert "EvidentiaModel" in names
        assert "NAMESPACE_EVIDENTIA_FINDING" in names

    def test_a_nonexistent_module_is_an_error_entry_not_an_exception(self, check: Any) -> None:
        rows = [check.FrozenModelRow(module_path="models/nope.py", symbols=(), callables=())]
        live = check.discover_module_symbols(rows)
        assert "error" in live["models/nope.py"]

    @pytest.mark.parametrize("module_path", ["ai_governance/registry.ts", "models.py"])
    def test_an_importable_module_does_not_substitute_for_the_named_python_file(
        self, check: Any, module_path: str
    ) -> None:
        rows = [check.FrozenModelRow(module_path=module_path, symbols=(), callables=())]

        live = check.discover_module_symbols(rows)

        assert "error" in live[module_path]

    @pytest.mark.parametrize("callable_name", ["NAMESPACE_EVIDENTIA_FINDING", "model_config"])
    def test_an_existing_noncallable_attribute_does_not_satisfy_a_frozen_callable(
        self, check: Any, callable_name: str
    ) -> None:
        rows = [
            check.FrozenModelRow(
                module_path="models/common.py", symbols=("EvidentiaModel",), callables=(callable_name,)
            )
        ]

        live = check.discover_module_symbols(rows)
        failures = check.compare_frozen_models(rows, live, ["models/common.py"])

        assert len(failures) == 1
        assert f"{callable_name}()" in failures[0]

    def test_real_functions_methods_constants_and_aliases_remain_valid(self, check: Any) -> None:
        rows = [
            check.FrozenModelRow(
                module_path="models/common.py",
                symbols=("EvidentiaModel", "NAMESPACE_EVIDENTIA_FINDING"),
                callables=("new_id", "model_validate"),
            ),
            check.FrozenModelRow(
                module_path="models/evidence.py", symbols=("EvidenceArtifact",), callables=("new_version",)
            ),
            check.FrozenModelRow(module_path="models/finding.py", symbols=("Finding", "SecurityFinding"), callables=()),
        ]

        live = check.discover_module_symbols(rows)

        assert check.compare_frozen_models(rows, live, [row.module_path for row in rows]) == []


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
