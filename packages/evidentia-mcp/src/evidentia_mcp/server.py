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
from evidentia_core.security.paths import validate_within
from mcp.server.fastmcp import FastMCP

from evidentia_mcp.cimd import CIMDRegistry

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
    "catalogs, then gap_analyze + gap_diff to surface findings. "
    "TRUST MODEL: stdio transport runs as the client's UID and "
    "inherits the client's filesystem authority. HTTP/SSE "
    "transports SHOULD pass --allow-root <path> at server start "
    "(v0.8.2 F-V81-S1) to gate file-path tool inputs (e.g., "
    "gap_analyze.inventory_path) against the bound directory. "
    "When --allow-root is unset, file-path tools accept any path "
    "the server's UID can read; this matches v0.8.1 stdio "
    "behavior but is risky for non-loopback HTTP/SSE deployments."
)


def build_server(
    *,
    allow_root: Path | None = None,
    cimd_registry: CIMDRegistry | None = None,
    default_client_id: str | None = None,
) -> FastMCP:
    """Construct the FastMCP server with all tools registered.

    Args:
        allow_root: Optional bound directory. When set, the
            file-path tools (``gap_analyze``, ``gap_diff``) gate
            their path inputs via
            :func:`evidentia_core.security.paths.validate_within`
            against this root — out-of-root inputs surface as
            ``PathTraversalError`` (subclass of ``ValueError``).
            When ``None`` (default), tools preserve the v0.8.1
            behavior of accepting any path the server's UID can
            read (appropriate for stdio + loopback HTTP/SSE).
        cimd_registry: v0.8.5 P4. Optional Client ID Metadata
            Document registry. When set, the server attaches the
            registry to its instance + (v0.8.6 P1) wires the
            scope-enforcement gate so every tool dispatch routes
            through :func:`evidentia_mcp.scope.enforce_cimd_scope`.
            The registry IS visible to tool implementations via
            ``server.evidentia_cimd`` attribute (custom-attached;
            not a FastMCP standard field).
        default_client_id: v0.8.6 P1. Fallback ``client_id`` when
            the MCP request meta does not carry one (canonical
            stdio behavior; sometimes HTTP/SSE too). Combined
            with ``cimd_registry`` to wire the scope-enforcement
            gate. When ``cimd_registry`` is ``None`` this argument
            is informational only.

    Returns:
        A :class:`mcp.server.fastmcp.FastMCP` instance ready to
        be run over any MCP transport. Use :func:`run_stdio` /
        :func:`run_sse` / :func:`run_http` to launch the
        appropriate transport.
    """
    server = FastMCP(name=SERVER_NAME, instructions=SERVER_INSTRUCTIONS)
    # v0.8.5 P4: attach CIMD registry as a server-side attribute
    # so audit-trail consumers + future scope-gating logic can
    # consult it. FastMCP doesn't reserve this attribute name; we
    # use the ``evidentia_*`` prefix convention to avoid future
    # collisions.
    server.evidentia_cimd = cimd_registry  # type: ignore[attr-defined]
    _register_tools(server, allow_root=allow_root)
    # v0.8.6 P1: wire the CIMD scope-enforcement gate AFTER tools
    # are registered. The gate is idempotent + checks
    # ``server.evidentia_cimd`` at call time (so a None registry
    # passes through with no audit emit; preserves v0.8.5
    # behavior). When a registry IS attached, every tool dispatch
    # routes through one authorization choke-point + emits
    # AI_MCP_TOOL_AUTHORIZED / AI_MCP_TOOL_DENIED audit events.
    from evidentia_mcp.scope import enforce_cimd_scope

    enforce_cimd_scope(server, default_client_id=default_client_id)

    # v0.9.8 P1.1: wire the SignedToolOutput auto-wrap LAST so it
    # composes outside the scope gate — authorization happens first,
    # then signing wraps the authorized result. Pass-through when the
    # operator hasn't set EVIDENTIA_MCP_SIGN_OUTPUTS, so the v0.9.7
    # default wire format is preserved.
    from evidentia_mcp.signed_dispatch import wrap_signed_output

    wrap_signed_output(server)
    return server


def run_stdio(
    *,
    allow_root: Path | None = None,
    cimd_registry: CIMDRegistry | None = None,
    default_client_id: str | None = None,
) -> None:
    """Run the MCP server over stdio (the canonical transport).

    Blocks until the client disconnects (or the operator presses
    Ctrl-C). Used by ``evidentia mcp serve``.

    Args:
        allow_root: See :func:`build_server`. Defaults to ``None``
            (no path gating) for stdio — the client process runs
            as the operator's UID, so an extra gate adds little
            value. Operators concerned about a malicious LLM
            client can still set the flag.
        cimd_registry: v0.8.5 P4. See :func:`build_server`.
        default_client_id: v0.8.6 P1. See :func:`build_server`.
            On stdio, the MCP wire protocol carries no per-request
            client_id, so this flag IS the client_id. Documented
            as informational, NOT a security boundary, in
            :mod:`evidentia_mcp.scope`.
    """
    server = build_server(
        allow_root=allow_root,
        cimd_registry=cimd_registry,
        default_client_id=default_client_id,
    )
    server.run(transport="stdio")


def run_sse(
    *,
    host: str,
    port: int,
    allow_root: Path | None = None,
    cimd_registry: CIMDRegistry | None = None,
    default_client_id: str | None = None,
) -> None:
    """Run the MCP server over SSE (Server-Sent Events).

    v0.8.1 P3.1: legacy HTTP transport for older MCP clients.
    Binds an HTTP server on ``host:port``. Blocks until the
    process is interrupted.

    Args:
        host: Bind address (default in caller is ``127.0.0.1``).
        port: Bind port.
        allow_root: See :func:`build_server`. v0.8.2 F-V81-S1:
            non-loopback ``host`` SHOULD pair with a non-``None``
            ``allow_root`` so file-path tool inputs are gated
            against the bound directory.
        cimd_registry: v0.8.5 P4. See :func:`build_server`.
            Especially relevant for non-loopback HTTP/SSE
            deployments where multiple clients may connect.
        default_client_id: v0.8.6 P1. Fallback when MCP request
            meta does not carry a client_id. See
            :func:`build_server` + :mod:`evidentia_mcp.scope`.

    Operators binding to non-loopback addresses MUST also front
    the server with reverse-proxy auth. See
    ``docs/threat-model.md`` Surface 2 for the full posture.
    """
    server = build_server(
        allow_root=allow_root,
        cimd_registry=cimd_registry,
        default_client_id=default_client_id,
    )
    # FastMCP exposes ``settings.host`` + ``settings.port`` as
    # the canonical knobs for the HTTP transports. Mutate before
    # ``server.run(transport="sse")`` so the bind address takes
    # effect.
    server.settings.host = host
    server.settings.port = port
    server.run(transport="sse")


def run_http(
    *,
    host: str,
    port: int,
    allow_root: Path | None = None,
    cimd_registry: CIMDRegistry | None = None,
    default_client_id: str | None = None,
) -> None:
    """Run the MCP server over streamable-http.

    v0.8.1 P3.1: modern MCP HTTP transport supporting bi-
    directional streaming. Used by browser-based agents +
    remote MCP clients that don't speak stdio.

    Same security posture as :func:`run_sse` — operators
    binding to non-loopback MUST front with reverse-proxy
    auth AND set ``allow_root`` (v0.8.2 F-V81-S1).

    Args:
        host: Bind address.
        port: Bind port.
        allow_root: See :func:`build_server`.
        cimd_registry: v0.8.5 P4. See :func:`build_server`.
        default_client_id: v0.8.6 P1. See :func:`build_server`.
    """
    server = build_server(
        allow_root=allow_root,
        cimd_registry=cimd_registry,
        default_client_id=default_client_id,
    )
    server.settings.host = host
    server.settings.port = port
    server.run(transport="streamable-http")


# ── Tool implementations ──────────────────────────────────────────


def _register_tools(
    server: FastMCP, *, allow_root: Path | None = None
) -> None:
    """Wire the tool surface onto the server.

    Each tool is a regular Python function with a structured
    docstring (FastMCP exposes the docstring as the tool's
    description in the MCP tool-picker). The function's type
    annotations drive the JSONSchema for the tool's input
    parameters.

    The ``allow_root`` argument is captured in the closure of
    the file-path tools (``gap_analyze``, ``gap_diff``). When
    set, those tools gate their path inputs via
    :func:`evidentia_core.security.paths.validate_within`
    before any filesystem I/O.
    """
    # v0.8.2 F-V81-S1: the bound allow-root is captured here
    # via closure + resolved once at server-build time so per-
    # tool-call resolution is cheap. The resolved root is what
    # ``validate_within`` will compare ``candidate.resolve()``
    # against.
    resolved_allow_root: Path | None = (
        allow_root.resolve(strict=False) if allow_root is not None else None
    )

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
                bundled catalog registry. Or — when the server
                was started with ``--allow-root`` — the inventory
                path resolves outside the bound directory
                (``PathTraversalError``, a ``ValueError`` subclass).
        """
        # v0.8.2 F-V81-S1: when --allow-root is set, gate the
        # input path against it via validate_within. When unset
        # (stdio default), preserve v0.8.1 behavior of resolving
        # to absolute form without bound-directory checking.
        candidate = Path(inventory_path).expanduser()
        if resolved_allow_root is not None:
            path = validate_within(candidate, resolved_allow_root)
        else:
            path = candidate.resolve(strict=False)
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
                ``GapAnalysisReport``. Or — when the server was
                started with ``--allow-root`` — either path
                resolves outside the bound directory
                (``PathTraversalError``, a ``ValueError`` subclass).
        """
        # v0.8.2 F-V81-S1: same path-gating as gap_analyze.
        base_candidate = Path(base_report_path).expanduser()
        head_candidate = Path(head_report_path).expanduser()
        if resolved_allow_root is not None:
            base_path = validate_within(
                base_candidate, resolved_allow_root
            )
            head_path = validate_within(
                head_candidate, resolved_allow_root
            )
        else:
            base_path = base_candidate.resolve(strict=False)
            head_path = head_candidate.resolve(strict=False)
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

    # ── CONMON tools (v0.9.6 P4 — first-mover MCP wrap) ─────────
    # Wraps the v0.9.3 CONMON daemon's read-only library surface as
    # MCP tools. Verified-unclaimed at v0.9.5 Q3 2026 quarterly
    # resync: existing OSCAL MCPs (oscal-compass, awslabs) are
    # authoring-only; vendor MCPs (Vanta / Drata / Optro / ComplyAI)
    # expose platform data only. The open-source CONMON-cadence
    # lane is wide open until further notice.
    #
    # Tools are read-only (no daemon mutation; no state-file
    # writes). Operators who want write semantics use the CLI verbs
    # `conmon mark-completed` and `conmon watch`, which are gated
    # by RBAC at the CLI layer (v0.9.6 P1).

    @server.tool()
    def conmon_list_cadences(
        framework: str | None = None,
    ) -> list[dict[str, Any]]:
        """List bundled continuous-monitoring cadences.

        Args:
            framework: Optional framework filter (e.g.,
                ``fedramp-rev5-mod``). When omitted, lists all
                bundled cadences across all frameworks.

        Returns:
            One entry per matching cadence with ``slug``,
            ``framework``, ``activity``, ``frequency``, and
            ``citation`` fields. Empty list if the filter excludes
            all cadences.

        v0.9.6 P4: shipped as part of the CONMON MCP first-mover
        position. See ``docs/positioning-and-value.md`` §6 + §11
        for the moat-trinity framing.
        """
        from evidentia_core.conmon import list_cadences

        cadences = list_cadences(framework=framework)
        return [c.model_dump(mode="json") for c in cadences]

    @server.tool()
    def conmon_next_due(
        slug: str, last_completed: str
    ) -> dict[str, Any]:
        """Compute the next-due date for a single CONMON cadence.

        Args:
            slug: Cadence slug (e.g.,
                ``nist-800-53-rev5-ca7``). Use ``conmon_list_cadences``
                to discover valid slugs.
            last_completed: ISO-8601 date (YYYY-MM-DD) of the most
                recent cycle completion for this cadence.

        Returns:
            A dict with ``slug``, ``last_completed``, and ``next_due``
            (ISO-8601 date).

        Raises:
            ValueError: ``slug`` is not a known cadence OR
                ``last_completed`` is not a valid ISO-8601 date.
        """
        from datetime import date as _date

        from evidentia_core.conmon import get_cadence, next_due

        cadence = get_cadence(slug)
        if cadence is None:
            raise ValueError(
                f"Unknown CONMON cadence slug: {slug!r}. Use "
                "conmon_list_cadences to discover valid slugs."
            )
        try:
            anchor = _date.fromisoformat(last_completed)
        except ValueError as exc:
            raise ValueError(
                f"last_completed must be ISO-8601 date "
                f"(YYYY-MM-DD); got {last_completed!r}: {exc}"
            ) from exc
        due = next_due(slug, anchor)
        return {
            "slug": slug,
            "last_completed": anchor.isoformat(),
            "next_due": due.isoformat(),
        }

    @server.tool()
    def conmon_check_state(
        state_file_path: str,
        window_days: int = 14,
    ) -> dict[str, Any]:
        """Read a state-file + report attention-state per cadence.

        Args:
            state_file_path: Path to a YAML mapping of
                ``{cadence_slug: ISO-8601-date}``. The file MUST
                exist; the tool does NOT create it.
            window_days: Due-soon window in days from today.
                Default 14.

        Returns:
            A dict with ``overdue``, ``due_soon``, and ``current``
            lists of cadences. Each entry carries the slug,
            framework, activity, next_due date, and days_until_due.

        Raises:
            FileNotFoundError: ``state_file_path`` does not exist.
            ValueError: state-file is not valid YAML / does not
                parse as a mapping.
        """
        from datetime import date as _date

        import yaml as yaml_mod
        from evidentia_core.conmon import (
            derive_status,
            get_cadence,
            next_due,
        )

        candidate = Path(state_file_path).expanduser()
        if resolved_allow_root is not None:
            path = validate_within(candidate, resolved_allow_root)
        else:
            path = candidate.resolve(strict=False)
        if not path.exists():
            raise FileNotFoundError(
                f"State file not found: {path}"
            )
        try:
            raw = yaml_mod.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml_mod.YAMLError as exc:
            raise ValueError(
                f"Could not parse state file {path}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise ValueError(
                f"State file {path} must contain a mapping at top level"
            )

        today = _date.today()
        overdue: list[dict[str, str]] = []
        due_soon: list[dict[str, str]] = []
        current: list[dict[str, str]] = []
        for slug, anchor_str in raw.items():
            cadence = get_cadence(slug)
            if cadence is None:
                continue  # unknown slugs surface in CLI, not here
            try:
                anchor = _date.fromisoformat(str(anchor_str))
            except ValueError:
                continue
            due = next_due(slug, anchor)
            state = derive_status(due, today, window_days=window_days)
            row = {
                "slug": slug,
                "framework": cadence.framework,
                "activity": cadence.activity,
                "next_due": due.isoformat(),
                "days_until_due": str((due - today).days),
            }
            if state.value == "overdue":
                overdue.append(row)
            elif state.value == "due_soon":
                due_soon.append(row)
            else:
                current.append(row)
        return {
            "today": today.isoformat(),
            "window_days": window_days,
            "overdue": overdue,
            "due_soon": due_soon,
            "current": current,
        }

    @server.tool()
    def conmon_health(state_file_path: str) -> dict[str, Any]:
        """Return the CONMON health report for a state-file.

        Args:
            state_file_path: Path to a YAML mapping of
                ``{cadence_slug: ISO-8601-date}``.

        Returns:
            The dict form of the v0.9.5 ``health_from_state_file``
            report — overall posture + per-framework breakdown +
            counts.

        Raises:
            FileNotFoundError: ``state_file_path`` does not exist.
            ValueError: state-file is not valid YAML.
        """
        import dataclasses

        from evidentia_core.conmon import health_from_state_file

        candidate = Path(state_file_path).expanduser()
        if resolved_allow_root is not None:
            path = validate_within(candidate, resolved_allow_root)
        else:
            path = candidate.resolve(strict=False)
        if not path.exists():
            raise FileNotFoundError(
                f"State file not found: {path}"
            )
        report = health_from_state_file(path)
        # HealthReport is a frozen dataclass — convert via
        # dataclasses.asdict for JSON-serializable output (mirrors
        # the conmon-health CLI verb's JSON serialization path).
        return dataclasses.asdict(report)
