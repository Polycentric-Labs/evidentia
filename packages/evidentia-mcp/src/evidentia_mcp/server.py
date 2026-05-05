"""FastMCP server build + stdio run helper (v0.8.0 P0.3).

The MCP server exposes a focused tool surface mapping
Evidentia's library functions into a shape MCP clients
(Claude Desktop, Claude Code, ChatGPT Desktop, custom
clients) can call directly.

Tool surface (v0.8.0 ship):

- ``list_frameworks`` — enumerate the 89 bundled catalogs +
  their tier / placeholder / license-required metadata.
- ``get_control`` — return the raw catalog entry (id, title,
  description) for a single control. Read-only; no LLM.
- ``gap_analyze`` — load a control inventory from disk, run
  :class:`evidentia_core.gap_analyzer.GapAnalyzer` against
  the requested frameworks, return the report as a JSON-
  serializable dict. Read-only; no LLM.
- ``gap_diff`` — load two ``GapAnalysisReport`` JSON files
  from disk, run :func:`evidentia_core.gap_diff.compute_gap_diff`,
  return the diff summary. Read-only; no LLM.

Tools that require the LLM provider env vars (LiteLLM-driven
``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY`` / etc.) gracefully
return a structured error when the env var is absent rather
than crashing the server.

Future slices add: ``risk_generate``, ``explain_control_llm``,
``oscal_emit``, ``collect_aws`` / ``collect_github`` /
``collect_jira``. Each new tool ships with a self-contained
test fixture.

Per the Evidentia secret-handling protocol, the MCP server
NEVER accepts credentials in tool arguments — provider-specific
env vars are read at tool-call time, and the resulting auth
errors surface as structured tool errors (not raw stack
traces).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer.analyzer import GapAnalyzer
from evidentia_core.gap_analyzer.inventory import load_inventory
from evidentia_core.gap_diff import compute_gap_diff
from evidentia_core.models.gap import GapAnalysisReport
from mcp.server.fastmcp import FastMCP

SERVER_NAME = "evidentia"

# v0.8.0 P0.3: keep the user-facing instructions short — MCP
# clients render this as the server description in their
# tool-picker UI. Long descriptions get truncated.
SERVER_INSTRUCTIONS = (
    "Evidentia GRC tooling — MCP server. Provides read-only "
    "gap analysis, control lookup, and gap-diff over a local "
    "control inventory. All tools operate on file paths the "
    "operator already has on disk; the server never fetches "
    "remote data unless an explicit collector tool is invoked. "
    "Use list_frameworks first to discover the 89 bundled "
    "catalogs, then gap_analyze + gap_diff to surface findings."
)


def build_server() -> FastMCP:
    """Construct the FastMCP server with all tools registered.

    Returns:
        A :class:`mcp.server.fastmcp.FastMCP` instance ready to
        be run over any MCP transport. Use :func:`run_stdio` for
        the canonical stdio transport.
    """
    server = FastMCP(name=SERVER_NAME, instructions=SERVER_INSTRUCTIONS)
    _register_tools(server)
    return server


def run_stdio() -> None:
    """Run the MCP server over stdio (the canonical transport).

    Blocks until the client disconnects (or the operator presses
    Ctrl-C). Used by ``evidentia mcp serve``.
    """
    server = build_server()
    server.run(transport="stdio")


# ── Tool implementations ──────────────────────────────────────────


def _register_tools(server: FastMCP) -> None:
    """Wire the tool surface onto the server.

    Each tool is a regular Python function with a structured
    docstring (FastMCP exposes the docstring as the tool's
    description in the MCP tool-picker). The function's type
    annotations drive the JSONSchema for the tool's input
    parameters.
    """

    @server.tool()
    def list_frameworks() -> list[dict[str, str]]:
        """List the bundled compliance catalogs + their metadata.

        Returns one entry per framework (89 frameworks ship
        in-tree as of v0.8.0). Each entry carries:

        - ``id``: catalog identifier (e.g., ``nist-800-53-rev5-moderate``)
        - ``name``: human-readable name
        - ``version``: catalog version string
        - ``tier``: ``A`` (authoritative public-domain text), ``B``
          (authoritative under license), or ``C`` (placeholder —
          control text is copyrighted; only id + title ship)
        - ``category``: ``control``, ``regulation``, ``standard``,
          or ``industry``
        - ``placeholder``: ``true`` if this is a tier-C placeholder
          (control descriptions show "see source" stubs)
        - ``license_required``: ``true`` if the catalog requires
          a separate license to use the full control text
        """
        registry = FrameworkRegistry()
        return list(registry.list_frameworks())

    @server.tool()
    def get_control(
        framework_id: str, control_id: str
    ) -> dict[str, Any]:
        """Return the raw catalog entry for a single control.

        Args:
            framework_id: Catalog identifier (e.g.,
                ``nist-800-53-rev5-moderate``). Use
                ``list_frameworks`` to discover available IDs.
            control_id: Control identifier within the catalog
                (e.g., ``AC-2`` for NIST 800-53 access control).

        Returns:
            The control's raw catalog entry as a JSON-serializable
            dict (id + title + description + family + related
            controls). Tier-C placeholders return the title +
            stub description but no copyrighted body.

        Raises:
            ValueError: framework_id is not a known catalog OR
                control_id is not present in the catalog.
        """
        registry = FrameworkRegistry()
        control = registry.get_control(framework_id, control_id)
        if control is None:
            catalog = registry.get_catalog(framework_id)
            raise ValueError(
                f"Control {control_id!r} not found in catalog "
                f"{framework_id!r}. The catalog has "
                f"{len(catalog.controls)} controls; verify the "
                f"control_id matches the catalog's convention "
                "(e.g., 'AC-2' not 'ac-2' or 'AC2')."
            )
        return control.model_dump(mode="json")

    @server.tool()
    def gap_analyze(
        inventory_path: str,
        frameworks: list[str],
        show_efficiency: bool = True,
    ) -> dict[str, Any]:
        """Run a gap analysis against a local control inventory.

        Args:
            inventory_path: Filesystem path to a control inventory
                file (JSON / YAML / CSV — the loader auto-detects).
                Must already exist on disk; the server does not
                fetch remote inventories.
            frameworks: List of catalog IDs to assess against
                (e.g., ``["nist-800-53-rev5-moderate", "soc2-tsc"]``).
            show_efficiency: Whether to include cross-framework
                efficiency metrics in the report. Default True.

        Returns:
            The complete :class:`GapAnalysisReport` as a JSON-
            serializable dict. Includes per-framework gap counts,
            severity distribution, control-level findings, and
            cross-framework efficiency analysis if requested.

        Raises:
            FileNotFoundError: inventory_path does not exist.
            ValueError: a framework id is not recognised by the
                bundled catalog registry.
        """
        path = Path(inventory_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(
                f"Inventory file not found: {path}"
            )
        inventory = load_inventory(path)
        analyzer = GapAnalyzer()
        report = analyzer.analyze(
            inventory=inventory,
            frameworks=frameworks,
            show_efficiency=show_efficiency,
        )
        return report.model_dump(mode="json")

    @server.tool()
    def gap_diff(
        base_report_path: str, head_report_path: str
    ) -> dict[str, Any]:
        """Diff two gap analysis reports.

        Useful for tracking compliance posture changes over time
        (release N vs release N+1; pre-remediation vs post-
        remediation). The diff surfaces which gaps opened, which
        closed, and which had severity changes.

        Args:
            base_report_path: Filesystem path to the prior
                ``GapAnalysisReport`` JSON file (the baseline).
            head_report_path: Filesystem path to the newer
                ``GapAnalysisReport`` JSON file (compared against
                the baseline).

        Returns:
            The :class:`GapDiff` as a JSON-serializable dict.
            Includes opened / closed / severity-increased /
            severity-decreased entry lists + summary counts.

        Raises:
            FileNotFoundError: either path does not exist.
            ValueError: a path's contents cannot be parsed as a
                ``GapAnalysisReport``.
        """
        base_path = Path(base_report_path).expanduser().resolve()
        head_path = Path(head_report_path).expanduser().resolve()
        if not base_path.exists():
            raise FileNotFoundError(
                f"Base report not found: {base_path}"
            )
        if not head_path.exists():
            raise FileNotFoundError(
                f"Head report not found: {head_path}"
            )
        base_data = json.loads(base_path.read_text(encoding="utf-8"))
        head_data = json.loads(head_path.read_text(encoding="utf-8"))
        try:
            base_report = GapAnalysisReport.model_validate(base_data)
        except Exception as exc:
            raise ValueError(
                f"Base report at {base_path} cannot be parsed as "
                f"GapAnalysisReport: {exc}"
            ) from exc
        try:
            head_report = GapAnalysisReport.model_validate(head_data)
        except Exception as exc:
            raise ValueError(
                f"Head report at {head_path} cannot be parsed as "
                f"GapAnalysisReport: {exc}"
            ) from exc
        diff = compute_gap_diff(base=base_report, head=head_report)
        return diff.model_dump(mode="json")
