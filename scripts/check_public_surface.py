#!/usr/bin/env python
"""Verify the code still matches ``docs/api-stability.md`` (v0.12 freeze-prep).

`docs/api-stability.md` has been NORMATIVE since v0.9.7, but through
v0.11.x nothing mechanically checked it. Four of its frozen surfaces
were prose that could drift from the code with no gate noticing:

1. **§5 library entry points** — a list of import statements the
   contract promises keep working. A refactor that moved or renamed any
   of them would break integrators silently; nothing imported them.
2. **MCP tool contract** — tool names are frozen (renaming is a
   major-bump trigger). Nothing compared the table to the live server.
3. **Env-var public contract** — frozen var names. Nothing compared the
   table to the source.
4. **§1 frozen model fields** (v0.13): a table of module paths and the
   classes, enums, constants and callables each one exposes. Nothing
   compared the table to the importable code, so a renamed module or a
   class that was never built could sit in a NORMATIVE document with
   nothing to notice.

This script closes all four. It is deliberately *doc-driven*: the
expectations are parsed out of `api-stability.md` itself rather than
duplicated here, so the document cannot drift from the gate that
enforces it.

**What is and is not a failure.** Removing a frozen surface fails —
that is the contract. A live MCP tool missing from the table also fails,
as documentation drift (adding tools is non-breaking, but the table
claims to enumerate the surface). Live env vars that are *not* frozen do
NOT fail: freezing every internal var would make each new one a blocking
change. They are counted and reported as freeze candidates for the v1.0
decision — see `docs/v1.0-freeze-candidates.md`.

Usage::

    python scripts/check_public_surface.py
    python scripts/check_public_surface.py --verbose

Exit codes: ``0`` all surfaces match, ``1`` drift found.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_STABILITY_PATH = REPO_ROOT / "docs" / "api-stability.md"
PACKAGES_ROOT = REPO_ROOT / "packages"

#: Headings that bound the parsed regions of api-stability.md.
_SECTION_1_HEADING = "### 1. Pydantic model fields"
_SECTION_5_HEADING = "### 5. Library entry points"
_MCP_HEADING = "## MCP tool contract"
_ENV_HEADING = "## Env-var public contract"

#: Matches every backtick-delimited token on a §1 table row.
_BACKTICK_TOKEN = re.compile(r"`([^`]+)`")

#: §1 token-classification rules (see "How this table is checked" in the
#: doc itself): a CapWords or UPPER_SNAKE token is a symbol that must be
#: defined in the row's module; a token ending in an open paren is a
#: callable that must be defined on the module or on a class the row
#: lists; anything else (a lowercase field or module reference) is
#: ignored.
_SYMBOL_TOKEN_CAPWORDS = re.compile(r"^[A-Z][A-Za-z0-9]+$")
_SYMBOL_TOKEN_UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]+$")
_CALLABLE_TOKEN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(")

#: Matches a leading ``| `name` |`` table cell — the first column of the
#: MCP-tool and env-var contract tables.
_TABLE_NAME_CELL = re.compile(r"^\|\s*`([^`]+)`\s*\|")

#: ``EVIDENTIA_*`` string literals in source. The contract covers our own
#: namespace only; third-party vars (AWS_*, HTTPS_PROXY, …) are not ours
#: to freeze.
_EVIDENTIA_ENV_LITERAL = re.compile(r'["\']( ?EVIDENTIA_[A-Z0-9_]+)["\']')

#: Documents "…and more" in a §5 import list. Not valid Python — stripped
#: before the statement is compiled or executed.
_ELISION = re.compile(r",\s*\.\.\.")


class SurfaceParseError(RuntimeError):
    """Raised when api-stability.md lacks a region this gate must read.

    Fails loudly on purpose: a renamed heading must not turn the gate
    into a vacuous pass.
    """


def _section(markdown: str, heading: str, *, stop: str) -> str:
    """Return the text between ``heading`` and the next ``stop`` heading."""
    start = markdown.find(heading)
    if start == -1:
        raise SurfaceParseError(
            f"{API_STABILITY_PATH.name} has no {heading!r} heading — this "
            f"gate parses it; update scripts/check_public_surface.py if the "
            f"document was deliberately restructured"
        )
    body = markdown[start + len(heading) :]
    end = body.find(stop)
    return body if end == -1 else body[:end]


@dataclass(frozen=True)
class FrozenModelRow:
    """One row of the §1 frozen-model table.

    ``module_path`` is a path relative to ``evidentia_core/`` (for
    example ``models/common.py``). ``symbols`` are the backticked
    CapWords/UPPER_SNAKE tokens on the row: classes, enums, type
    aliases or constants that must be module attributes. ``callables``
    are the backticked ``name()`` tokens: functions that must exist on
    the module or on one of the classes ``symbols`` names.
    """

    module_path: str
    symbols: tuple[str, ...]
    callables: tuple[str, ...]


def parse_frozen_models(markdown: str) -> list[FrozenModelRow]:
    """Extract §1's frozen-model table as structured rows.

    A row is any line starting with a pipe then a backtick. That
    naturally skips the table's header row and its ``|---|---|``
    separator, neither of which starts with a backtick. The first
    backticked token on the row is the module path; every other
    backticked token is classified per the doc's own "How this table
    is checked" rule (see the ``_SYMBOL_TOKEN_*`` / ``_CALLABLE_TOKEN``
    patterns above). A row with no backticked tokens at all cannot
    happen given the pipe-then-backtick prefix, but is skipped
    defensively rather than crashing.
    """
    section = _section(markdown, _SECTION_1_HEADING, stop="\n### ")

    rows: list[FrozenModelRow] = []
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        tokens = _BACKTICK_TOKEN.findall(line)
        if not tokens:
            continue
        module_path, *rest = tokens
        symbols: list[str] = []
        callables: list[str] = []
        for token in rest:
            if _SYMBOL_TOKEN_CAPWORDS.match(token) or _SYMBOL_TOKEN_UPPER_SNAKE.match(token):
                symbols.append(token)
                continue
            call_match = _CALLABLE_TOKEN.match(token)
            if call_match:
                callables.append(call_match.group(1))
        rows.append(FrozenModelRow(module_path=module_path, symbols=tuple(symbols), callables=tuple(callables)))

    if not rows:
        raise SurfaceParseError(f"{API_STABILITY_PATH.name} §1 parsed to zero frozen-model rows")
    return rows


def list_models_modules(packages_root: Path) -> list[str]:
    """Every ``evidentia_core/models/*.py`` module, as ``models/<name>.py``.

    Used to enforce the other half of §1's contract: not just "every
    row must resolve" but "every model module must have a row." A new
    ``models/`` file that nobody added to the table would otherwise
    ship unfrozen and undocumented.
    """
    models_dir = packages_root / "evidentia-core" / "src" / "evidentia_core" / "models"
    return sorted(f"models/{path.name}" for path in models_dir.glob("*.py") if path.name != "__init__.py")


def discover_module_symbols(rows: list[FrozenModelRow]) -> dict[str, dict[str, object]]:
    """Import every frozen-model module once and report its public surface.

    Runs in a subprocess, mirroring ``discover_live_mcp_tools``: importing
    every frozen module pulls in the whole model + dependency stack, which
    must not leak into this gate's own process. A module that no longer
    exists, or that fails to import for any other reason, does not crash
    the gate: it becomes an ``"error"`` entry that ``compare_frozen_models``
    turns into a failure message rather than a traceback.

    Every row must name an existing Python module file under the core
    package. Returns one entry per distinct module path, with every public
    module attribute in ``names`` and class attribute in ``class_attrs``.
    ``callables`` and ``class_callables`` contain the attributes for which
    Python's ``callable()`` returns True. Invalid paths and imports return
    ``{"error": "<message>"}``.
    """
    module_paths = sorted({row.module_path for row in rows})
    snippet = (
        "import importlib, inspect, json\n"
        "from pathlib import Path\n"
        f"core_root = Path({str(PACKAGES_ROOT / 'evidentia-core' / 'src' / 'evidentia_core')!r})\n"
        f"module_paths = {module_paths!r}\n"
        "result = {}\n"
        "for module_path in module_paths:\n"
        "    if (not module_path.endswith('.py')\n"
        "            or not all(part.isidentifier() for part in module_path[:-3].split('/'))\n"
        "            or not (core_root / module_path).is_file()):\n"
        "        result[module_path] = {'error': 'not an existing relative .py module file under evidentia_core'}\n"
        "        continue\n"
        "    dotted = 'evidentia_core.' + module_path[:-3].replace('/', '.')\n"
        "    try:\n"
        "        mod = importlib.import_module(dotted)\n"
        "    except Exception as exc:\n"
        "        result[module_path] = {'error': f'{type(exc).__name__}: {exc}'}\n"
        "        continue\n"
        "    names = [n for n in dir(mod) if not n.startswith('_')]\n"
        "    class_attrs = {}\n"
        "    module_callables = []\n"
        "    class_callables = {}\n"
        "    for name in names:\n"
        "        obj = getattr(mod, name)\n"
        "        if callable(obj):\n"
        "            module_callables.append(name)\n"
        "        if inspect.isclass(obj):\n"
        "            class_attrs[name] = [a for a in dir(obj) if not a.startswith('_')]\n"
        "            class_callables[name] = [a for a in class_attrs[name] if callable(getattr(obj, a, None))]\n"
        "    result[module_path] = {'names': names, 'class_attrs': class_attrs,\n"
        "                           'callables': module_callables, 'class_callables': class_callables}\n"
        "print(json.dumps(result))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    if proc.returncode != 0:
        raise SurfaceParseError("could not discover frozen-model modules: " + proc.stderr.strip()[-2000:])
    payload = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not payload:
        raise SurfaceParseError("frozen-model discovery produced no JSON: " + proc.stdout[-2000:])
    return json.loads(payload[-1])


def compare_frozen_models(
    rows: list[FrozenModelRow],
    live: dict[str, dict[str, object]],
    models_modules: list[str],
) -> list[str]:
    """§1 rows must resolve against the live code; every models/*.py needs a row.

    Duplicate rows for the same module are allowed (each is checked on
    its own terms); a module with two rows just gets checked twice.
    """
    failures: list[str] = []
    documented: set[str] = set()

    for row in rows:
        documented.add(row.module_path)
        entry = live.get(row.module_path)
        if entry is None or "error" in entry:
            reason = entry["error"] if entry else "not discovered"
            failures.append(f"frozen model module `{row.module_path}` does not exist or does not import: {reason}")
            continue

        names = entry.get("names", [])
        module_callables = entry.get("callables", [])
        class_callables = entry.get("class_callables", {})

        for symbol in row.symbols:
            if symbol not in names:
                failures.append(f"frozen model symbol `{symbol}` is not defined in `{row.module_path}`")

        for callable_name in row.callables:
            on_module = callable_name in module_callables
            on_listed_class = any(callable_name in class_callables.get(cls, []) for cls in row.symbols)
            if not on_module and not on_listed_class:
                failures.append(
                    f"frozen callable `{callable_name}()` is missing or not callable on `{row.module_path}` "
                    f"or on any class it lists"
                )

    for module_path in models_modules:
        if module_path not in documented:
            failures.append(
                f"model module `{module_path}` has no row in section 1; every exported "
                f"model class is under the section 1 contract"
            )

    return failures


def parse_frozen_imports(markdown: str) -> list[str]:
    """Extract §5's frozen import statements as executable Python.

    Handles the documentation conventions used in that block: comment
    lines, parenthesised multi-line import lists, and the ``, ...``
    elision marker that means "and more" rather than ``Ellipsis``.
    """
    section = _section(markdown, _SECTION_5_HEADING, stop="\n### ")

    match = re.search(r"```python\n(.*?)```", section, re.DOTALL)
    if match is None:
        raise SurfaceParseError(f"{API_STABILITY_PATH.name} §5 has no ```python block to check")

    block = _ELISION.sub("", match.group(1))

    statements: list[str] = []
    buffer: list[str] = []
    depth = 0
    for raw_line in block.splitlines():
        line = raw_line.rstrip()
        if not buffer and (not line.strip() or line.lstrip().startswith("#")):
            continue
        buffer.append(line)
        depth += line.count("(") - line.count(")")
        if depth <= 0:
            statement = "\n".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            depth = 0
    if buffer:
        statements.append("\n".join(buffer).strip())

    return statements


def _table_names(markdown: str, heading: str, *, stop: str) -> set[str]:
    """Collect the first-column backticked names of the table under ``heading``."""
    section = _section(markdown, heading, stop=stop)
    return {match.group(1) for line in section.splitlines() if (match := _TABLE_NAME_CELL.match(line))}


def parse_frozen_mcp_tools(markdown: str) -> set[str]:
    """Tool names from the "MCP tool contract" frozen table."""
    return _table_names(markdown, _MCP_HEADING, stop="\n## ")


def parse_frozen_env_vars(markdown: str) -> set[str]:
    """Var names from the "Env-var public contract" frozen table."""
    return _table_names(markdown, _ENV_HEADING, stop="\n## ")


def discover_live_env_vars(packages_root: Path) -> set[str]:
    """Every ``EVIDENTIA_*`` literal appearing in shipped package source."""
    found: set[str] = set()
    for path in packages_root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        found.update(match.group(1).strip() for match in _EVIDENTIA_ENV_LITERAL.finditer(text))
    return found


def discover_live_mcp_tools() -> set[str]:
    """Tool names the MCP server actually registers.

    Runs in a subprocess: importing the server pulls the whole tool
    stack, which must not leak into this gate's process (nor its import
    warnings into the gate's output).
    """
    snippet = (
        "import asyncio, json\n"
        "from evidentia_mcp.server import build_server\n"
        "tools = asyncio.run(build_server().list_tools())\n"
        "print(json.dumps(sorted(t.name for t in tools)))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", snippet],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    if proc.returncode != 0:
        raise SurfaceParseError("could not enumerate live MCP tools: " + proc.stderr.strip()[-2000:])
    # Warnings may precede the payload; the JSON array is the last line.
    payload = [ln for ln in proc.stdout.splitlines() if ln.startswith("[")]
    if not payload:
        raise SurfaceParseError("MCP tool enumeration produced no JSON: " + proc.stdout[-2000:])
    return set(ast.literal_eval(payload[-1]))


def check_frozen_imports(statements: list[str]) -> list[str]:
    """Execute each §5 import; report the ones that no longer resolve."""
    if not statements:
        return ["§5 frozen-import block parsed to zero statements"]

    program = "\n".join(statements)
    proc = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    if proc.returncode == 0:
        return []

    # Re-run one statement at a time so the report names the broken import
    # rather than just the first failure's traceback.
    failures: list[str] = []
    for statement in statements:
        one = subprocess.run(
            [sys.executable, "-c", statement],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO_ROOT,
        )
        if one.returncode != 0:
            last = one.stderr.strip().splitlines()[-1] if one.stderr.strip() else "?"
            flat = " ".join(statement.split())
            failures.append(f"frozen §5 import no longer resolves: {flat}  ->  {last}")
    return failures or ["§5 imports fail as a block but each succeeds alone: " + proc.stderr.strip()[-2000:]]


def compare_mcp_tools(*, frozen: set[str], live: set[str]) -> list[str]:
    """Frozen tool names must match the live server's exactly."""
    failures = []
    for removed in sorted(frozen - live):
        failures.append(
            f"frozen MCP tool {removed!r} is no longer registered by the "
            f"server — renaming/removing a tool is a major-bump trigger "
            f"(docs/api-stability.md § MCP tool contract)"
        )
    for undocumented in sorted(live - frozen):
        failures.append(
            f"MCP tool {undocumented!r} is registered but missing from the "
            f"frozen-tool table — adding tools is non-breaking, but the "
            f"table must enumerate the surface it claims to freeze"
        )
    return failures


def compare_env_vars(*, frozen: set[str], live: set[str]) -> list[str]:
    """Frozen env vars must still exist in code; extras are candidates."""
    return [
        f"frozen env var {name!r} no longer appears in packages/*/src — "
        f"removing it needs a deprecation cycle "
        f"(docs/api-stability.md § Env-var public contract)"
        for name in sorted(frozen - live)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="list the freeze-candidate env vars, not just the count",
    )
    args = parser.parse_args(argv)

    markdown = API_STABILITY_PATH.read_text(encoding="utf-8")

    failures: list[str] = []

    frozen_models = parse_frozen_models(markdown)
    live_models = discover_module_symbols(frozen_models)
    models_modules = list_models_modules(PACKAGES_ROOT)
    failures += compare_frozen_models(frozen_models, live_models, models_modules)

    statements = parse_frozen_imports(markdown)
    failures += check_frozen_imports(statements)

    frozen_tools = parse_frozen_mcp_tools(markdown)
    failures += compare_mcp_tools(frozen=frozen_tools, live=discover_live_mcp_tools())

    frozen_env = parse_frozen_env_vars(markdown)
    live_env = discover_live_env_vars(PACKAGES_ROOT)
    failures += compare_env_vars(frozen=frozen_env, live=live_env)

    candidates = sorted(live_env - frozen_env)

    total_symbols = sum(len(row.symbols) for row in frozen_models)
    total_callables = sum(len(row.callables) for row in frozen_models)
    print(
        f"  §1 frozen models:        {len(frozen_models)} row(s), "
        f"{total_symbols} symbol(s), {total_callables} callable(s)"
    )
    print(f"  §5 library entry points: {len(statements)} import statement(s)")
    print(f"  MCP tool contract:       {len(frozen_tools)} frozen tool(s)")
    print(
        f"  env-var contract:        {len(frozen_env)} frozen, "
        f"{len(live_env)} live, {len(candidates)} freeze candidate(s)"
    )
    if args.verbose and candidates:
        for name in candidates:
            print(f"    candidate: {name}")

    if failures:
        print()
        print(f"PUBLIC SURFACE DRIFT ({len(failures)}):")
        for failure in failures:
            print(f"  - {failure}")
        print()
        print("check_public_surface: FAIL")
        return 1

    print()
    print("check_public_surface: PASS — code matches docs/api-stability.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
