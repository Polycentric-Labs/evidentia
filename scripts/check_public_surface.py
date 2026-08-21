#!/usr/bin/env python
"""Verify the code still matches ``docs/api-stability.md`` (v0.12 freeze-prep).

`docs/api-stability.md` has been NORMATIVE since v0.9.7, but through
v0.11.x nothing mechanically checked it. Three of its frozen surfaces
were prose that could drift from the code with no gate noticing:

1. **§5 library entry points** — a list of import statements the
   contract promises keep working. A refactor that moved or renamed any
   of them would break integrators silently; nothing imported them.
2. **MCP tool contract** — tool names are frozen (renaming is a
   major-bump trigger). Nothing compared the table to the live server.
3. **Env-var public contract** — frozen var names. Nothing compared the
   table to the source.

This script closes all three. It is deliberately *doc-driven*: the
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
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
API_STABILITY_PATH = REPO_ROOT / "docs" / "api-stability.md"
PACKAGES_ROOT = REPO_ROOT / "packages"

#: Headings that bound the parsed regions of api-stability.md.
_SECTION_5_HEADING = "### 5. Library entry points"
_MCP_HEADING = "## MCP tool contract"
_ENV_HEADING = "## Env-var public contract"

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


def parse_frozen_imports(markdown: str) -> list[str]:
    """Extract §5's frozen import statements as executable Python.

    Handles the documentation conventions used in that block: comment
    lines, parenthesised multi-line import lists, and the ``, ...``
    elision marker that means "and more" rather than ``Ellipsis``.
    """
    section = _section(markdown, _SECTION_5_HEADING, stop="\n### ")

    match = re.search(r"```python\n(.*?)```", section, re.DOTALL)
    if match is None:
        raise SurfaceParseError(
            f"{API_STABILITY_PATH.name} §5 has no ```python block to check"
        )

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
    return {
        match.group(1)
        for line in section.splitlines()
        if (match := _TABLE_NAME_CELL.match(line))
    }


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
        found.update(
            match.group(1).strip() for match in _EVIDENTIA_ENV_LITERAL.finditer(text)
        )
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
        raise SurfaceParseError(
            "could not enumerate live MCP tools: " + proc.stderr.strip()[-2000:]
        )
    # Warnings may precede the payload; the JSON array is the last line.
    payload = [ln for ln in proc.stdout.splitlines() if ln.startswith("[")]
    if not payload:
        raise SurfaceParseError(
            "MCP tool enumeration produced no JSON: " + proc.stdout[-2000:]
        )
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
            failures.append(
                f"frozen §5 import no longer resolves: {flat}  ->  {last}"
            )
    return failures or [
        "§5 imports fail as a block but each succeeds alone: "
        + proc.stderr.strip()[-2000:]
    ]


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

    statements = parse_frozen_imports(markdown)
    failures += check_frozen_imports(statements)

    frozen_tools = parse_frozen_mcp_tools(markdown)
    failures += compare_mcp_tools(
        frozen=frozen_tools, live=discover_live_mcp_tools()
    )

    frozen_env = parse_frozen_env_vars(markdown)
    live_env = discover_live_env_vars(PACKAGES_ROOT)
    failures += compare_env_vars(frozen=frozen_env, live=live_env)

    candidates = sorted(live_env - frozen_env)

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
