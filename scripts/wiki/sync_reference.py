#!/usr/bin/env python3
"""Deterministic generator for the 5 wiki REFERENCE pages (D6 Batch 2, v0.10.7).

The ``docs/wiki/4-reference/`` section is a *mechanically generated* index of
Evidentia's runtime surface — CLI verbs, MCP tools, configuration knobs, and
the bundled catalog + crosswalk listings. Hand-authoring these drifts the
moment a command/tool/env-var lands; this script regenerates each page from
the actual code/data instead, and a ``--check`` mode detects drift (the same
``--check``/exit-code idiom as ``scripts/wiki/sync_mirrors.py`` and
``scripts/catalogs/gen_osps_crosswalks.py``).

The 5 pages
-----------
``cli.md``
    Every CLI command + subcommand + flag, introspected from the live Typer
    app (``evidentia.cli.main.app``) via Click's command tree. Grouped by
    command; deterministic alphabetical ordering. Requires the project to be
    importable (``uv run``), since it imports the Typer app rather than
    shelling out to ``--help`` (no terminal-width nondeterminism, no
    subprocess parsing).
``mcp-tools.md``
    The MCP tools, AST-parsed from
    ``evidentia_mcp/server.py``'s ``@server.tool()``-decorated functions
    (name + signature + first docstring line). AST (not import) keeps this
    parse deterministic + dependency-light. Notes the append-only contract
    per ``docs/api-stability.md``.
``configuration.md``
    Environment variables + the ``evidentia.yaml`` config schema. The
    ``EVIDENTIA_*`` env vars are regex-extracted from the package source
    (their *names* only — never their values, several are secrets); the YAML
    schema is AST-parsed from ``evidentia_core/config.py``'s Pydantic models;
    the well-known LLM-provider keys are a small curated list (external keys
    Evidentia reads but does not define).
``catalogs.md``
    Table of bundled framework catalogs parsed from ``frameworks.yaml``,
    grouped by family directory. The headline count is computed from the
    manifest, never hardcoded.
``crosswalks.md``
    Table of the crosswalk JSONs under ``catalogs/data/mappings/`` — source ->
    target framework, verification posture, mapping-row count. Counts computed
    from the actual files.

Each page carries a generated banner: an HTML-comment provenance marker
(machine-detectable, non-rendering) + a short visible blockquote naming this
script and telling editors not to hand-edit. ``--check`` regenerates in
memory + compares byte-for-byte against the committed pages.

Modes
-----
``sync_reference.py``
    Generate / update all 5 reference pages in place under
    ``docs/wiki/4-reference/``.
``sync_reference.py --check``
    Do not write. Exit 0 if every committed page matches what would be
    regenerated; exit 1 + print which pages drifted. (CI / pre-tag drift
    gate; wired into ``sync-wiki.yml`` so a push always refreshes the
    reference pages before the wiki push.)

Per the publishing-authority protocol (~/.claude/CLAUDE.md), this script
NEVER pushes, tags, or publishes. It only reads code/data + writes the
in-tree wiki reference files.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# scripts/wiki/sync_reference.py -> repo root is two parents up.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Canonical blob-URL base (matches scripts/wiki/sync_mirrors.py); used in the
# banner's pointer back to this script.
BLOB_URL_BASE = "https://github.com/Polycentric-Labs/evidentia/blob/main"

# This script's own repo-relative path (named in every page banner).
GENERATOR_REL = "scripts/wiki/sync_reference.py"

# --- repo-relative source locations the generators read --------------------
MCP_SERVER_REL = "packages/evidentia-mcp/src/evidentia_mcp/server.py"
CONFIG_REL = "packages/evidentia-core/src/evidentia_core/config.py"
FRAMEWORKS_REL = (
    "packages/evidentia-core/src/evidentia_core/catalogs/data/frameworks.yaml"
)
MAPPINGS_REL = "packages/evidentia-core/src/evidentia_core/catalogs/data/mappings"
PACKAGES_REL = "packages"

# Well-known LLM-provider API-key env vars Evidentia *reads* but does not
# define (they belong to the provider SDKs via LiteLLM). Surfaced in
# configuration.md so operators know which keys enable the LLM features.
# Mirrors the detection list in evidentia.cli.main.doctor.
PROVIDER_KEY_ENV_VARS: tuple[tuple[str, str], ...] = (
    ("OPENAI_API_KEY", "OpenAI"),
    ("ANTHROPIC_API_KEY", "Anthropic"),
    ("GOOGLE_API_KEY", "Google"),
    ("AZURE_OPENAI_API_KEY", "Azure OpenAI"),
)

# Matches an EVIDENTIA_* env-var string literal in Python source. The name is
# all we ever extract — never the value (several name secret material:
# *_PASSWORD, *_WEBHOOK_SECRET).
_ENV_LITERAL_RE = re.compile(r"""['"](EVIDENTIA_[A-Z0-9_]+)['"]""")


# ---------------------------------------------------------------------------
# Shared markdown helpers (pure).
# ---------------------------------------------------------------------------


def build_banner(page_title: str) -> str:
    """Build the auto-generated header banner for a reference page.

    Combines an HTML-comment provenance marker (machine-detectable, does not
    render) with a short visible blockquote that names this generator and
    tells editors not to hand-edit. ``page_title`` is the page's H1 text
    (e.g. ``"CLI reference"``).
    """
    return (
        f"<!-- AUTO-GENERATED by {GENERATOR_REL} -- do not edit directly -->\n"
        f"# {page_title}\n\n"
        f"> **Auto-generated page.** This page is generated from the live "
        f"Evidentia codebase by [`{GENERATOR_REL}`]({BLOB_URL_BASE}/"
        f"{GENERATOR_REL}). Do not edit it by hand; change the underlying "
        f"code/data and re-run the generator (`uv run python "
        f"{GENERATOR_REL}`).\n\n"
    )


def _md_escape_cell(text: str) -> str:
    """Escape a string for safe inclusion in a markdown table cell.

    Collapses newlines to spaces and escapes the pipe character so a value
    never breaks the column structure.
    """
    return text.replace("\n", " ").replace("|", r"\|").strip()


def first_docstring_line(docstring: str | None) -> str:
    """Return the first non-empty line of a docstring (stripped), or ""."""
    if not docstring:
        return ""
    for line in docstring.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


# ---------------------------------------------------------------------------
# cli.md — Typer/Click introspection.
# ---------------------------------------------------------------------------


def _format_click_param(param: Any) -> tuple[str, str]:
    """Return ``(invocation, help)`` for a Click parameter.

    ``invocation`` is the comma-joined opt strings for an Option (e.g.
    ``--verbose, -v``) or the metavar for an Argument. ``help`` is the
    parameter's help text (empty for Arguments, which Click does not carry
    help on).
    """
    # Duck-type rather than ``isinstance(param, click.Option)``: typer 0.26
    # vendors its own Click, so a Typer app's params are vendored-Click
    # instances that fail an external-``click`` isinstance check.
    # ``param_type_name`` ("option" / "argument") is the stable,
    # vendor-agnostic discriminator that works on either Click.
    if getattr(param, "param_type_name", "") == "option":
        invocation = ", ".join(param.opts + param.secondary_opts)
        return invocation, (param.help or "")
    # Argument: no help attribute; show the (upper-cased) metavar/name.
    # Click 8.2+ made make_metavar() require a ctx; typer's override defaults
    # it to None, so the no-arg call works for Typer params — fall back to the
    # ctx-taking signature (then the raw name) to stay robust on either Click.
    name: Any = param.name
    if hasattr(param, "make_metavar"):
        try:
            name = param.make_metavar()
        except TypeError:
            name = param.make_metavar(None)
    return str(name), ""


def _walk_click_command(
    command: Any,
    path: list[str],
    rows: list[dict[str, Any]],
) -> None:
    """Recursively collect ``{path, help, params}`` for a command tree.

    ``path`` is the command-name path from the root (excluding the program
    name). Groups recurse into their subcommands in sorted order; leaf
    commands record their parameters. Deterministic: subcommands are always
    visited alphabetically.
    """
    # Duck-type the Click introspection so it works on typer 0.26's vendored
    # Click (see _format_click_param): a group exposes ``list_commands`` /
    # ``get_command``; ``param_type_name`` discriminates option vs argument.
    is_group = hasattr(command, "list_commands")

    help_text = first_docstring_line(command.help) if command.help else ""
    params = [
        _format_click_param(p)
        for p in command.params
        # Skip the auto-added --help flag; it is on every command and adds
        # no signal.
        if not (getattr(p, "param_type_name", "") == "option" and p.name == "help")
    ]
    rows.append(
        {
            "path": list(path),
            "help": help_text,
            "params": params,
            "is_group": is_group,
        }
    )
    if is_group:
        # ctx=None is sufficient for a static command tree — list_commands /
        # get_command on a basic group ignore it (verified against the live
        # Typer app). Avoids constructing a Click Context, which would mix
        # the external and vendored Click classes.
        for sub_name in sorted(command.list_commands(None)):
            sub = command.get_command(None, sub_name)
            if sub is None:  # pragma: no cover — defensive
                continue
            _walk_click_command(sub, [*path, sub_name], rows)


def collect_cli_rows() -> list[dict[str, Any]]:
    """Introspect the Evidentia Typer app into an ordered list of command rows.

    Imports ``evidentia.cli.main.app`` and converts it to the underlying
    Click command via ``typer.main.get_command``, then walks the tree. The
    root program node (empty path) is dropped — its params are the global
    options, rendered separately by :func:`render_cli`. Requires the project
    to be importable.
    """
    import typer
    from evidentia.cli.main import app

    root = typer.main.get_command(app)
    rows: list[dict[str, Any]] = []
    _walk_click_command(root, [], rows)
    return rows


def render_cli(rows: list[dict[str, Any]]) -> str:
    """Render cli.md from the collected command rows (pure)."""
    out = [build_banner("CLI reference")]
    out.append(
        "Every `evidentia` command, subcommand, and flag, introspected from "
        "the live [Typer](https://typer.tiangolo.com/) application "
        "(`evidentia.cli.main.app`). Commands are listed alphabetically.\n\n"
    )

    root = next((r for r in rows if not r["path"]), None)
    if root is not None and root["params"]:
        out.append("## Global options\n\n")
        out.append(
            "Applied to every command (pass before the subcommand, e.g. "
            "`evidentia --offline gap analyze ...`).\n\n"
        )
        out.append(_render_params_table(root["params"]))
        out.append("\n")

    # Top-level commands = rows with a single-segment path, sorted.
    top = sorted(
        (r for r in rows if len(r["path"]) == 1), key=lambda r: r["path"][0]
    )
    for top_row in top:
        name = top_row["path"][0]
        out.append(f"## `evidentia {name}`\n\n")
        if top_row["help"]:
            out.append(f"{top_row['help']}\n\n")
        if top_row["params"]:
            out.append(_render_params_table(top_row["params"]))
            out.append("\n")
        # Subcommands of this group (any deeper path that starts with name).
        subs = sorted(
            (
                r
                for r in rows
                if len(r["path"]) > 1 and r["path"][0] == name
            ),
            key=lambda r: r["path"],
        )
        for sub in subs:
            sub_invocation = " ".join(sub["path"])
            out.append(f"### `evidentia {sub_invocation}`\n\n")
            if sub["help"]:
                out.append(f"{sub['help']}\n\n")
            if sub["params"]:
                out.append(_render_params_table(sub["params"]))
                out.append("\n")
    return "".join(out)


def _render_params_table(params: list[tuple[str, str]]) -> str:
    """Render a 2-column flag/description markdown table."""
    lines = ["| Flag / argument | Description |", "| --- | --- |"]
    for invocation, help_text in params:
        inv = _md_escape_cell(invocation)
        desc = _md_escape_cell(help_text) or "—"
        lines.append(f"| `{inv}` | {desc} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# mcp-tools.md — AST parse of @server.tool() functions.
# ---------------------------------------------------------------------------


def _is_server_tool_decorator(decorator: ast.expr) -> bool:
    """True if a decorator node is ``@server.tool()`` / ``@server.tool``.

    Matches both the called (``server.tool()``) and bare (``server.tool``)
    forms, requiring the attribute chain ``<name>.tool``.
    """
    node: ast.expr = decorator
    if isinstance(node, ast.Call):
        node = node.func
    return isinstance(node, ast.Attribute) and node.attr == "tool"


def _format_annotation(node: ast.expr | None) -> str:
    """Render a type-annotation AST node back to source text."""
    if node is None:
        return ""
    return ast.unparse(node)


def _format_signature(func: ast.FunctionDef) -> str:
    """Build a readable ``name(params) -> return`` signature from AST.

    Renders each argument as ``name: annotation`` (annotation omitted when
    absent) with ``= default`` for defaults. ``self`` is never present (these
    are module-level functions). Keeps the rendering deterministic and
    dependency-free.
    """
    args = func.args
    parts: list[str] = []
    # Positional-or-keyword args, aligning defaults to the tail.
    posargs = args.args
    defaults = args.defaults
    default_offset = len(posargs) - len(defaults)
    for i, arg in enumerate(posargs):
        rendered = arg.arg
        if arg.annotation is not None:
            rendered += f": {_format_annotation(arg.annotation)}"
        if i >= default_offset:
            default_node = defaults[i - default_offset]
            rendered += f" = {ast.unparse(default_node)}"
        parts.append(rendered)
    sig = f"{func.name}({', '.join(parts)})"
    if func.returns is not None:
        sig += f" -> {_format_annotation(func.returns)}"
    return sig


def collect_mcp_tools_ordered(source: str) -> list[dict[str, str]]:
    """Parse MCP-tool functions from ``server.py`` source, in registration order.

    Returns one ``{name, signature, summary}`` dict per ``@server.tool()``
    function. Walks the tree recording each tool function's line number, then
    sorts by it so the rendered order matches the file's top-to-bottom
    registration order (= the append-only contract's ordering) regardless of
    AST walk order. ``summary`` is the first docstring line. Pure (operates
    on source text).
    """
    tree = ast.parse(source)
    entries: list[tuple[int, dict[str, str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if not any(_is_server_tool_decorator(d) for d in node.decorator_list):
            continue
        entries.append(
            (
                node.lineno,
                {
                    "name": node.name,
                    "signature": _format_signature(node),
                    "summary": first_docstring_line(ast.get_docstring(node)),
                },
            )
        )
    entries.sort(key=lambda e: e[0])
    return [entry for _lineno, entry in entries]


def render_mcp_tools(tools: list[dict[str, str]]) -> str:
    """Render mcp-tools.md from the collected tool list (pure)."""
    out = [build_banner("MCP tools")]
    out.append(
        f"Evidentia's [Model Context Protocol]"
        f"(https://modelcontextprotocol.io/) server exposes "
        f"**{len(tools)} tools** to MCP-aware AI clients (Claude Desktop, "
        f"Claude Code, ChatGPT Desktop, custom clients). Tools are listed in "
        f"registration order.\n\n"
        f"> **Append-only contract.** Per "
        f"[`docs/api-stability.md`]({BLOB_URL_BASE}/docs/api-stability.md) "
        f"(NORMATIVE), the MCP tool surface is **append-only** within a major "
        f"version: new tools may be added, but existing tool names, "
        f"parameters, and return shapes are not removed or changed "
        f"incompatibly before the next major release.\n\n"
        f"Start the server with `evidentia mcp serve` (requires the "
        f"`evidentia[mcp]` extra).\n\n"
    )
    for tool in tools:
        out.append(f"### `{tool['name']}`\n\n")
        if tool["summary"]:
            out.append(f"{tool['summary']}\n\n")
        out.append(f"```python\n{tool['signature']}\n```\n\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# configuration.md — env vars + evidentia.yaml schema.
# ---------------------------------------------------------------------------


def collect_env_vars(packages_dir: Path) -> list[str]:
    """Collect every ``EVIDENTIA_*`` env-var NAME used across the packages.

    Regex-scans all ``.py`` files under ``packages_dir`` for the env-var
    string literals. Returns a sorted, de-duplicated list of NAMES only —
    the value of an env var is NEVER read (several name secret material, per
    the secret-handling protocol). Pure aside from reading the tracked source
    tree.
    """
    names: set[str] = set()
    for py_file in packages_dir.rglob("*.py"):
        try:
            text = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover — defensive
            continue
        names.update(_ENV_LITERAL_RE.findall(text))
    return sorted(names)


def collect_yaml_schema(config_source: str) -> list[dict[str, str]]:
    """AST-parse ``config.py`` for the ``evidentia.yaml`` Pydantic schema.

    Returns one ``{key, type, description}`` dict per ``Field(...)`` class
    attribute on the ``EvidentiaConfig`` and ``LLMConfig`` models (nested
    ``llm.*`` keys are prefixed ``llm.``). The ``source_path`` internal field
    (``exclude=True``) is skipped. Pure (operates on source text).
    """
    tree = ast.parse(config_source)
    models: dict[str, ast.ClassDef] = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    }

    def fields_for(class_name: str, prefix: str) -> list[dict[str, str]]:
        cls = models.get(class_name)
        if cls is None:
            return []
        rows: list[dict[str, str]] = []
        for stmt in cls.body:
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(
                stmt.target, ast.Name
            ):
                continue
            key = stmt.target.id
            # Skip the internal diagnostics field (exclude=True).
            if key == "source_path":
                continue
            type_str = _format_annotation(stmt.annotation)
            description = _extract_field_description(stmt.value)
            rows.append(
                {
                    "key": f"{prefix}{key}",
                    "type": type_str,
                    "description": description,
                }
            )
        return rows

    schema = fields_for("EvidentiaConfig", "")
    # Expand the nested llm: LLMConfig field into llm.<sub> rows.
    schema = [row for row in schema if row["key"] != "llm"]
    schema.extend(fields_for("LLMConfig", "llm."))
    return schema


def _extract_field_description(value: ast.expr | None) -> str:
    """Pull the ``description=`` kwarg out of a ``Field(...)`` call node.

    Reads only a static string-literal description via ``ast.literal_eval``
    (literals only — never code execution); a non-literal/absent description
    yields an empty string.
    """
    if not isinstance(value, ast.Call):
        return ""
    for keyword in value.keywords:
        if keyword.arg == "description":
            try:
                literal = ast.literal_eval(keyword.value)
            except (ValueError, SyntaxError):
                return ""
            if isinstance(literal, str):
                return literal
    return ""


def render_configuration(
    env_vars: list[str],
    yaml_schema: list[dict[str, str]],
    provider_keys: tuple[tuple[str, str], ...] = PROVIDER_KEY_ENV_VARS,
) -> str:
    """Render configuration.md (pure)."""
    out = [build_banner("Configuration")]
    out.append(
        "Evidentia is configured through three layers, in precedence order: "
        "**CLI flag > environment variable > `evidentia.yaml` > built-in "
        "default**. There is no global config daemon or hidden state — every "
        "knob is one of the items below.\n\n"
    )

    # --- evidentia.yaml ---
    out.append("## `evidentia.yaml`\n\n")
    out.append(
        "An optional project config file discovered by walking the current "
        "directory up to the filesystem root for the first `evidentia.yaml`. "
        "String values support `${ENV_VAR}` interpolation. Honored keys "
        "(schema: `evidentia_core.config.EvidentiaConfig`):\n\n"
    )
    out.append("| Key | Type | Description |\n| --- | --- | --- |\n")
    for row in yaml_schema:
        key = _md_escape_cell(row["key"])
        type_str = _md_escape_cell(row["type"])
        desc = _md_escape_cell(row["description"]) or "—"
        out.append(f"| `{key}` | `{type_str}` | {desc} |\n")
    out.append("\n")

    # --- EVIDENTIA_* env vars ---
    out.append("## Environment variables\n\n")
    out.append(
        f"Evidentia reads the following **{len(env_vars)}** `EVIDENTIA_*` "
        f"environment variables. Variables whose name ends in `_PASSWORD`, "
        f"`_SECRET`, or `_TOKEN_FILE` carry credential material — set them in "
        f"your shell/secret store, never commit their values.\n\n"
    )
    out.append("| Environment variable |\n| --- |\n")
    for name in env_vars:
        out.append(f"| `{_md_escape_cell(name)}` |\n")
    out.append("\n")

    # --- provider keys ---
    out.append("## LLM provider keys\n\n")
    out.append(
        "The LLM-backed commands (`evidentia risk generate`, `evidentia "
        "explain`) read the standard provider SDK keys via LiteLLM. Evidentia "
        "does not define these; set whichever matches your configured model. "
        "`evidentia doctor` reports which are detected.\n\n"
    )
    out.append("| Environment variable | Provider |\n| --- | --- |\n")
    for name, provider in provider_keys:
        out.append(f"| `{_md_escape_cell(name)}` | {_md_escape_cell(provider)} |\n")
    out.append("\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# catalogs.md — frameworks.yaml manifest table.
# ---------------------------------------------------------------------------

# Human labels for the family directory (the first path segment) + the order
# the families appear in the rendered page.
_FAMILY_LABELS: dict[str, str] = {
    "us-federal": "US Federal",
    "international": "International",
    "state-privacy": "US State Privacy",
    "threats": "Threat Intelligence",
    "stubs": "License-required (stub)",
}

# Human labels for the redistribution tier.
_TIER_LABELS: dict[str, str] = {
    "A": "A — authoritative public-domain / open text",
    "B": "B — authoritative, free with attribution",
    "C": "C — placeholder (control text copyrighted)",
    "D": "D — obligation/regulation (paraphrased)",
}


def parse_frameworks_manifest(manifest_text: str) -> list[dict[str, Any]]:
    """Parse ``frameworks.yaml`` text into the list of framework dicts (pure)."""
    data = yaml.safe_load(manifest_text)
    frameworks = data.get("frameworks") if isinstance(data, dict) else None
    if not isinstance(frameworks, list):
        raise ValueError("frameworks.yaml has no top-level `frameworks:` list")
    return frameworks


def render_catalogs(frameworks: list[dict[str, Any]]) -> str:
    """Render catalogs.md from the parsed manifest (pure).

    The headline count + every per-family subtotal is computed from
    ``frameworks`` — nothing is hardcoded.
    """
    out = [build_banner("Bundled catalogs")]
    total = len(frameworks)
    out.append(
        f"Evidentia ships **{total}** framework catalogs in-tree. Tier-A/B "
        f"catalogs carry authoritative control text; tier-C catalogs are "
        f"placeholders (control text is copyrighted — only IDs + neutral "
        f"titles ship, with a `license_url` to obtain the full text); tier-D "
        f"catalogs are paraphrased obligation/regulation references. Use "
        f"`evidentia catalog list` to enumerate them at runtime.\n\n"
    )

    # Tier legend.
    out.append("## Tiers\n\n")
    out.append("| Tier | Meaning |\n| --- | --- |\n")
    for tier in sorted(_TIER_LABELS):
        out.append(f"| {tier} | {_md_escape_cell(_TIER_LABELS[tier])} |\n")
    out.append("\n")

    # Group by family directory (first path segment); deterministic order.
    by_family: dict[str, list[dict[str, Any]]] = {}
    for fw in frameworks:
        family = str(fw.get("path", "")).split("/")[0] or "(uncategorized)"
        by_family.setdefault(family, []).append(fw)

    # Render known families first (in label order), then any unknown ones
    # alphabetically — keeps output stable if a new family dir appears.
    known = [f for f in _FAMILY_LABELS if f in by_family]
    unknown = sorted(f for f in by_family if f not in _FAMILY_LABELS)
    for family in [*known, *unknown]:
        items = sorted(by_family[family], key=lambda f: str(f.get("id", "")))
        label = _FAMILY_LABELS.get(family, family)
        out.append(f"## {label} ({len(items)})\n\n")
        out.append(
            "| ID | Name | Version | Tier | Category |\n"
            "| --- | --- | --- | --- | --- |\n"
        )
        for fw in items:
            out.append(
                "| `{id}` | {name} | {version} | {tier} | {category} |\n".format(
                    id=_md_escape_cell(str(fw.get("id", ""))),
                    name=_md_escape_cell(str(fw.get("name", ""))),
                    version=_md_escape_cell(str(fw.get("version", ""))),
                    tier=_md_escape_cell(str(fw.get("tier", ""))),
                    category=_md_escape_cell(str(fw.get("category", ""))),
                )
            )
        out.append("\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# crosswalks.md — mappings/*.json table.
# ---------------------------------------------------------------------------


def parse_crosswalk(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Extract the row data for one crosswalk JSON payload (pure).

    ``name`` is the JSON filename. Handles both shapes present in-tree: the
    OSPS-extracted files (which carry ``verification`` / ``provenance``) and
    the hand-authored files (which carry only ``source`` / ``version``).
    Missing fields render as ``"—"`` downstream.
    """
    mappings = payload.get("mappings")
    row_count = len(mappings) if isinstance(mappings, list) else 0
    return {
        "file": name,
        "source": str(payload.get("source_framework", "")),
        "target": str(payload.get("target_framework", "")),
        "verification": str(payload.get("verification", "")),
        "rows": row_count,
    }


def collect_crosswalks(mappings_dir: Path) -> list[dict[str, Any]]:
    """Parse every ``*.json`` under ``mappings_dir`` into crosswalk rows.

    Returns rows sorted by filename (deterministic). Reads the JSON files;
    the per-file extraction (:func:`parse_crosswalk`) is pure.
    """
    rows: list[dict[str, Any]] = []
    for json_path in sorted(mappings_dir.glob("*.json")):
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        rows.append(parse_crosswalk(json_path.name, payload))
    return rows


def render_crosswalks(rows: list[dict[str, Any]]) -> str:
    """Render crosswalks.md from the collected crosswalk rows (pure).

    The headline count + the total mapping-row sum are computed from
    ``rows`` — nothing hardcoded.
    """
    out = [build_banner("Crosswalks")]
    total = len(rows)
    total_mappings = sum(r["rows"] for r in rows)
    out.append(
        f"Evidentia bundles **{total}** framework crosswalks "
        f"({total_mappings:,} control-to-control mapping rows in total). A "
        f"crosswalk maps controls in a source framework to related controls "
        f"in a target framework, powering cross-framework gap-analysis "
        f"efficiency. The **verification** column records the posture: "
        f"crosswalks marked `self-attested-via-upstream` are auto-extracted "
        f"from an upstream source and not independently hand-verified; an "
        f"empty posture marks an Evidentia-authored concordance. Always "
        f"verify a mapping before relying on it for an audit.\n\n"
    )
    out.append(
        "| Crosswalk file | Source framework | Target framework | "
        "Verification | Mapping rows |\n"
        "| --- | --- | --- | --- | --- |\n"
    )
    for row in rows:
        out.append(
            "| `{file}` | `{source}` | `{target}` | {verification} | {rows} |\n".format(
                file=_md_escape_cell(row["file"]),
                source=_md_escape_cell(row["source"]) or "—",
                target=_md_escape_cell(row["target"]) or "—",
                verification=_md_escape_cell(row["verification"]) or "—",
                rows=row["rows"],
            )
        )
    out.append("\n")
    return "".join(out)


# ---------------------------------------------------------------------------
# Orchestration: generate all 5 pages.
# ---------------------------------------------------------------------------

# Output paths (repo-relative) for the 5 reference pages.
PAGE_CLI = "docs/wiki/4-reference/cli.md"
PAGE_MCP = "docs/wiki/4-reference/mcp-tools.md"
PAGE_CONFIG = "docs/wiki/4-reference/configuration.md"
PAGE_CATALOGS = "docs/wiki/4-reference/catalogs.md"
PAGE_CROSSWALKS = "docs/wiki/4-reference/crosswalks.md"


def generate_all(repo_root: Path = REPO_ROOT) -> dict[str, str]:
    """Render every reference page; return ``{page_rel_path: rendered_text}``.

    Reads the live code/data under ``repo_root``. The CLI page imports the
    Typer app (requires the project importable); the others parse source/data
    files.
    """
    out: dict[str, str] = {}

    # cli.md — import + introspect the Typer app.
    out[PAGE_CLI] = render_cli(collect_cli_rows())

    # mcp-tools.md — AST parse server.py.
    mcp_source = (repo_root / MCP_SERVER_REL).read_text(encoding="utf-8")
    out[PAGE_MCP] = render_mcp_tools(collect_mcp_tools_ordered(mcp_source))

    # configuration.md — env vars + yaml schema.
    env_vars = collect_env_vars(repo_root / PACKAGES_REL)
    config_source = (repo_root / CONFIG_REL).read_text(encoding="utf-8")
    out[PAGE_CONFIG] = render_configuration(
        env_vars, collect_yaml_schema(config_source)
    )

    # catalogs.md — frameworks.yaml.
    manifest_text = (repo_root / FRAMEWORKS_REL).read_text(encoding="utf-8")
    out[PAGE_CATALOGS] = render_catalogs(parse_frameworks_manifest(manifest_text))

    # crosswalks.md — mappings/*.json.
    out[PAGE_CROSSWALKS] = render_crosswalks(
        collect_crosswalks(repo_root / MAPPINGS_REL)
    )
    return out


# ---------------------------------------------------------------------------
# Compare (--check) + CLI.
# ---------------------------------------------------------------------------


def _diff_summary(expected: str, actual: str, name: str) -> str:
    """Return a short first-divergence summary between two text blobs."""
    exp_lines = expected.splitlines()
    act_lines = actual.splitlines()
    for i, (exp, act) in enumerate(zip(exp_lines, act_lines, strict=False)):
        if exp != act:
            return (
                f"  {name}: first diff at line {i + 1}\n"
                f"    committed:   {exp!r}\n"
                f"    regenerated: {act!r}"
            )
    if len(exp_lines) != len(act_lines):
        return (
            f"  {name}: line-count differs "
            f"(committed={len(exp_lines)}, regenerated={len(act_lines)})"
        )
    return f"  {name}: content differs only in trailing bytes / EOL"


def compare(rendered: dict[str, str], repo_root: Path = REPO_ROOT) -> list[str]:
    """Compare rendered pages against the committed files on disk.

    ``rendered`` is ``{page_rel_path: rendered_text}`` (the output of
    :func:`generate_all`). Returns an ordered list of per-file drift
    summaries; an empty list means every page matches byte-for-byte. Pure
    read-only (no writes, no network).
    """
    drift: list[str] = []
    for page_rel, content in sorted(rendered.items()):
        committed_path = repo_root / page_rel
        if not committed_path.exists():
            drift.append(f"  {page_rel}: committed page missing")
            continue
        committed = committed_path.read_text(encoding="utf-8")
        if committed != content:
            drift.append(_diff_summary(committed, content, page_rel))
    return drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Do not write. Exit 0 if every committed reference page matches "
            "what would be regenerated from the live code/data; exit 1 + "
            "print a drift summary on divergence. (CI / pre-tag gate.)"
        ),
    )
    args = parser.parse_args(argv)

    rendered = generate_all()

    if args.check:
        drift = compare(rendered)
        if drift:
            print(
                "DRIFT: committed wiki reference pages differ from the live "
                "code/data:",
                file=sys.stderr,
            )
            for line in drift:
                print(line, file=sys.stderr)
            print(
                f"\nRe-run `uv run python {GENERATOR_REL}` (no --check) to "
                "regenerate the pages, then commit.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: all {len(rendered)} wiki reference pages match the live code/data.")
        return 0

    for page_rel, content in rendered.items():
        out_path = REPO_ROOT / page_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        print(f"  wrote {page_rel}")
    print(f"Generated {len(rendered)} wiki reference pages from live code/data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
