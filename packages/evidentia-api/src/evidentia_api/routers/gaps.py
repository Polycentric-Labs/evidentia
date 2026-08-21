"""Gap-analysis router — run + list + diff gap reports.

Endpoints:
- ``POST /api/gap/analyze`` — run a GapAnalyzer pass and persist to gap_store
- ``GET /api/gap/reports`` — list saved reports (newest first)
- ``GET /api/gap/reports/{key}`` — load a specific saved report
- ``POST /api/gap/diff`` — compute a diff between two saved reports

Inventory input accepts either a server-side file path (typical for CLI
integration) or an inline YAML/JSON blob (typical for browser upload).
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Callable
from datetime import UTC
from pathlib import Path

from evidentia_core.gap_analyzer import export_report
from evidentia_core.gap_analyzer.analyzer import GapAnalyzer
from evidentia_core.gap_analyzer.inventory import load_inventory
from evidentia_core.gap_diff import compute_gap_diff
from evidentia_core.gap_store import (
    GapReportRepository,
    InvalidReportKeyError,
    get_gap_store_dir,
    list_reports,
    load_report_by_key,
    save_report,
)
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.models.gap_diff import GapDiff
from evidentia_core.ocsf.finding_mapping import OCSFMappingError
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)
from fastapi import APIRouter, Response

from evidentia_api.errors import api_error, error_responses
from evidentia_api.schemas import (
    GAP_EXPORT_FORMATS,
    GapAnalyzeRequest,
    GapDiffRequest,
    GapExportRequest,
)

# Per-format download metadata: (file extension, MIME type). The
# extension drives the browser's suggested filename; the MIME type
# sets Content-Type so the browser treats the body correctly. SARIF /
# OCSF / VEX / OSCAL-AR are all JSON-family payloads but keep their
# semantic extensions so downstream tooling (GitHub code-scanning,
# Dependency-Track, SIEM loaders) recognizes them by name.
_EXPORT_MEDIA: dict[str, tuple[str, str]] = {
    "json": ("json", "application/json"),
    "csv": ("csv", "text/csv"),
    "markdown": ("md", "text/markdown"),
    "oscal-ar": ("oscal.json", "application/json"),
    "sarif": ("sarif", "application/sarif+json"),
    "ocsf": ("ocsf.json", "application/json"),
    "ocsf-detection": ("ocsf-detection.json", "application/json"),
    "cyclonedx-vex": ("vex.cdx.json", "application/vnd.cyclonedx+json"),
}

logger = logging.getLogger(__name__)
router = APIRouter()


def _stored_report_read_responses() -> dict[int | str, dict[str, object]]:
    return error_responses(
        {
            400: "Malformed report ``key`` (``error: invalid_id``).",
            404: "No saved report under ``key`` (``error: not_found``).",
        }
    )


def _load_stored_report(
    key: str,
    load_by_key: Callable[[str], GapAnalysisReport | None],
) -> GapAnalysisReport:
    try:
        report = load_by_key(key)
    except (InvalidReportKeyError, PathTraversalError) as exc:
        # Both InvalidReportKeyError + PathTraversalError reflect
        # client-supplied bad keys; both normalize to 400 — the
        # F-V08-DAST-3 status normalization — with the structured
        # ``detail`` from ``evidentia_api.errors`` (2026-07-06
        # error-shape convergence).
        raise api_error(
            400, "invalid_id", str(exc), resource="gap_report"
        ) from exc
    if report is None:
        raise api_error(
            404,
            "not_found",
            f"Report {key} not found.",
            resource="gap_report",
            resource_id=key,
        )
    return report


def create_stored_report_read_router(
    repository: GapReportRepository,
) -> APIRouter:
    """Build the exact-key report-read route around ``repository``.

    This factory intentionally exposes no report list, analyze, diff, export,
    risk, or integration route. The repository is captured at construction,
    so request handling never consults ambient store selection.
    """
    if repository is None:
        raise TypeError(
            "create_stored_report_read_router requires a repository."
        )

    report_router = APIRouter()

    @report_router.get(
        "/gap/reports/{key}",
        response_model=GapAnalysisReport,
        responses=_stored_report_read_responses(),
    )
    async def get_report(key: str) -> GapAnalysisReport:
        """Load a saved gap report by its storage key."""
        return _load_stored_report(key, repository.load_by_key)

    return report_router


def _materialize_inventory_content(
    content: str, inventory_format: str
) -> Path:
    """Write inline inventory content to a temp file so ``load_inventory`` can parse it.

    The existing loader is path-based (auto-detects format by extension);
    the API accepts inline strings for browser-originated uploads. Rather
    than duplicate the three parser entry points, we round-trip through a
    temp file.
    """
    suffix_map = {"yaml": ".yaml", "yml": ".yaml", "csv": ".csv", "json": ".json"}
    suffix = suffix_map.get(inventory_format.lower(), ".yaml")
    # A short-lived temp file handed to the caller; the caller unlinks it
    # after load_inventory() completes. A context manager would delete the
    # file on __exit__, which is the opposite of what we want.
    tmp_root = Path(tempfile.gettempdir())
    fd = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", encoding="utf-8", suffix=suffix, delete=False, dir=tmp_root
    )
    try:
        fd.write(content)
        fd.flush()
        # tempfile.NamedTemporaryFile already returns a path inside the
        # tmp dir; validate_within is the CodeQL-recognizable barrier
        # that lets static analysis stop flagging downstream IO on this
        # path as a path-injection sink.
        return validate_within(Path(fd.name), tmp_root)
    finally:
        fd.close()


@router.post(
    "/gap/analyze",
    response_model=GapAnalysisReport,
    responses=error_responses(
        {
            400: (
                "Missing/invalid inventory input or a failed "
                "inventory parse (``error: invalid_body``)."
            ),
        }
    ),
)
async def analyze(payload: GapAnalyzeRequest) -> GapAnalysisReport:
    """Run gap analysis and persist the result to the gap store.

    Returns the freshly-computed report. The persisted JSON lives under
    the user-dir gap_store and is referenced by the ``GET /api/gap/reports``
    endpoint after this call completes.
    """
    if not payload.inventory_path and not payload.inventory_content:
        raise api_error(
            400,
            "invalid_body",
            "Either inventory_path or inventory_content must be provided.",
        )

    tmp_path: Path | None = None
    try:
        if payload.inventory_content:
            tmp_path = _materialize_inventory_content(
                payload.inventory_content, payload.inventory_format
            )
            inventory_source = tmp_path
        else:
            assert payload.inventory_path is not None
            # The inventory_path field is for CLI-adjacent use (a server
            # invoked locally that loads from disk). For an API exposed
            # to untrusted callers, restrict to paths inside the server's
            # current working directory — operators who need to read
            # inventories from elsewhere should pass inventory_content
            # instead of inventory_path.
            try:
                inventory_source = validate_within(
                    Path(payload.inventory_path), Path.cwd()
                )
            except PathTraversalError as exc:
                raise api_error(400, "invalid_body", str(exc)) from exc

        try:
            inventory = load_inventory(inventory_source)
        except (FileNotFoundError, ValueError) as e:
            # Use 400 (not 422) for runtime body-content validation
            # errors — the F-V08-DAST-3 status normalization. 422 stays
            # reserved for Pydantic auto-validation responses (array-
            # shape ``detail``); deliberate errors carry the structured
            # object ``detail`` from ``evidentia_api.errors``
            # (2026-07-06 error-shape convergence).
            raise api_error(400, "invalid_body", str(e)) from e

        # CLI-style overrides
        if payload.organization:
            inventory.organization = payload.organization
        if payload.system_name:
            inventory.system_name = payload.system_name

        report = GapAnalyzer().analyze(inventory, payload.frameworks)
        save_report(report)
        return report
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _safe_filename_stem(organization: str) -> str:
    """Derive a filesystem-safe filename stem from an org name.

    Keeps ASCII alphanumerics, dash, and underscore; collapses
    everything else to a single dash. Prevents header-injection /
    path characters from a user-controlled organization string
    landing in the Content-Disposition filename.
    """
    cleaned = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "-_")) else "-"
        for ch in organization.strip()
    ).strip("-")
    # Collapse runs of dashes for readability.
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "gap-report"


@router.post(
    "/gap/export",
    responses=error_responses(
        {
            400: (
                "Unsupported/unavailable ``format``, ambiguous report "
                "source, or a malformed report key (``error: "
                "unsupported_format`` / ``feature_unavailable`` / "
                "``invalid_body`` / ``invalid_id``)."
            ),
            404: "Unknown ``report_key`` (``error: not_found``).",
        }
    ),
)
async def export(payload: GapExportRequest) -> Response:
    """Export a gap report in an engine-supported format as a download.

    Reuses :func:`evidentia_core.gap_analyzer.export_report` — the exact
    emitters behind the CLI's ``evidentia gap analyze --format ...`` — so
    the API never re-implements a serialization. The artifact is returned
    with a ``Content-Disposition: attachment`` header so the browser saves
    it directly.

    The report source is either an inline ``report`` body (what the GUI
    holds after running an analysis) or a ``report_key`` referencing a
    saved gap-store report. Exactly one must be supplied.
    """
    fmt = payload.format
    if fmt not in GAP_EXPORT_FORMATS:
        raise api_error(
            400,
            "unsupported_format",
            (
                f"Unsupported format {fmt!r}. "
                f"Expected one of: {', '.join(GAP_EXPORT_FORMATS)}."
            ),
            format=fmt,
            supported=list(GAP_EXPORT_FORMATS),
        )

    if (payload.report is None) == (payload.report_key is None):
        raise api_error(
            400,
            "invalid_body",
            "Provide exactly one of 'report' or 'report_key'.",
        )

    report: GapAnalysisReport
    if payload.report is not None:
        report = payload.report
    else:
        assert payload.report_key is not None
        try:
            loaded = load_report_by_key(payload.report_key)
        except (InvalidReportKeyError, PathTraversalError) as exc:
            raise api_error(
                400, "invalid_id", str(exc), resource="gap_report"
            ) from exc
        if loaded is None:
            raise api_error(
                404,
                "not_found",
                f"Report {payload.report_key} not found.",
                resource="gap_report",
                resource_id=payload.report_key,
            )
        report = loaded

    extension, media_type = _EXPORT_MEDIA[fmt]
    filename = f"{_safe_filename_stem(report.organization)}.{extension}"

    # export_report() is path-based — round-trip through a temp file in
    # the system temp dir, then read the bytes back to return inline.
    # validate_within is the CodeQL-recognizable barrier confirming the
    # write target sits inside the temp root.
    tmp_root = Path(tempfile.gettempdir())
    fd = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", encoding="utf-8", suffix=f".{extension}", delete=False, dir=tmp_root
    )
    fd.close()
    tmp_path = validate_within(Path(fd.name), tmp_root)
    try:
        try:
            export_report(report, tmp_path, format=fmt)  # type: ignore[arg-type]
        except OCSFMappingError as exc:
            # Raised by the OCSF emitters when the optional [ocsf] extra
            # (py-ocsf-models) is not installed on the server. Surface a
            # 400 with install guidance rather than a 500 — this is an
            # operator-config issue, not a server fault.
            raise api_error(
                400,
                "feature_unavailable",
                (
                    f"Format {fmt!r} is unavailable: {exc}. "
                    "Install the server's [ocsf] extra "
                    "(pip install 'evidentia-core[ocsf]') to enable "
                    "OCSF export formats."
                ),
                format=fmt,
            ) from exc
        except ValueError as exc:
            raise api_error(400, "invalid_body", str(exc)) from exc

        data = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)

    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/gap/reports")
async def get_reports() -> dict[str, object]:
    """List saved gap reports, newest first.

    Each entry includes the storage key, mtime, byte size, and a short
    summary (organization + framework list) so the UI can render a
    listing without loading every report body.
    """
    import json
    from datetime import datetime

    entries: list[dict[str, object]] = []
    for path in list_reports():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            entries.append(
                {
                    "key": path.stem,
                    "mtime_iso": datetime.fromtimestamp(
                        path.stat().st_mtime, tz=UTC
                    ).isoformat(),
                    "size_bytes": path.stat().st_size,
                    "organization": data.get("organization", "(unknown)"),
                    "frameworks_analyzed": data.get("frameworks_analyzed", []),
                    "total_gaps": data.get("total_gaps", 0),
                    "critical_gaps": data.get("critical_gaps", 0),
                    "coverage_percentage": data.get("coverage_percentage"),
                }
            )
        except Exception as e:
            logger.warning("Skipping malformed report %s: %s", path, e)

    return {"total": len(entries), "reports": entries, "store_dir": str(get_gap_store_dir())}


@router.get(
    "/gap/reports/{key}",
    response_model=GapAnalysisReport,
    responses=_stored_report_read_responses(),
)
async def get_report(key: str) -> GapAnalysisReport:
    """Load a saved gap report by its storage key."""
    return _load_stored_report(key, load_report_by_key)


@router.post(
    "/gap/diff",
    response_model=GapDiff,
    responses=error_responses(
        {
            400: (
                "Malformed ``base_key`` / ``head_key`` "
                "(``error: invalid_id``)."
            ),
            404: "Base or head report not found (``error: not_found``).",
        }
    ),
)
async def diff(payload: GapDiffRequest) -> GapDiff:
    """Compute a diff between two saved gap reports.

    Referenced by the /gap/diff page: user picks base + head from the
    reports list, clicks "Compare", and the result drives the summary +
    per-entry table.
    """
    loaded: dict[str, GapAnalysisReport] = {}
    for label, key in (("base", payload.base_key), ("head", payload.head_key)):
        try:
            report = load_report_by_key(key)
        except InvalidReportKeyError as exc:
            raise api_error(
                400,
                "invalid_id",
                f"Invalid {label} key: {exc}",
                resource="gap_report",
            ) from exc
        except PathTraversalError as exc:
            raise api_error(
                400,
                "invalid_id",
                f"Invalid {label} key: {exc}",
                resource="gap_report",
            ) from exc
        if report is None:
            raise api_error(
                404,
                "not_found",
                f"{label.capitalize()} report {key} not found.",
                resource="gap_report",
                resource_id=key,
            )
        loaded[label] = report

    return compute_gap_diff(loaded["base"], loaded["head"])
