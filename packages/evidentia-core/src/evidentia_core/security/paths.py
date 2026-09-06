"""Path-traversal-safe filesystem helpers.

The :func:`validate_within` helper is the canonical primitive for
guarding any filesystem access whose path is influenced by external
input — request bodies, URL path parameters, environment variables,
configuration files, or third-party data sources. Call sites that
compose a path from such input must validate the composed path
against a known-safe root *before* opening, reading, or writing the
file. This converts ``../traversal`` and absolute-path attacks into
``PathTraversalError`` at the trust boundary, where the caller can
return a 4xx and log the offending input.

Usage at FastAPI router boundaries::

    from evidentia_core.security.paths import (
        PathTraversalError,
        validate_within,
    )

    safe_root = get_gap_store_dir()
    candidate = safe_root / f"{user_supplied_key}.json"
    try:
        path = validate_within(candidate, safe_root)
    except PathTraversalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return path.read_text(encoding="utf-8")

Static analyzers (CodeQL ``py/path-injection`` in particular)
recognize this exact pattern as a sanitizing barrier and stop
flagging the downstream filesystem call.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "PathTraversalError",
    "validate_within",
]


class PathTraversalError(ValueError):
    """Raised when a candidate path resolves outside its safe root.

    Subclasses :class:`ValueError` so existing FastAPI exception
    handlers + CLI ``except (ValueError, ...):`` chains continue to
    handle the violation without code churn. The exception message
    is short + redacted (it does not echo the unsafe candidate back
    in full); callers that need to log the offending input should
    log it themselves at the call site.
    """


def validate_within(candidate: Path, safe_root: Path) -> Path:
    """Return ``candidate`` resolved if and only if it is within ``safe_root``.

    Resolves both paths to absolute form (following symlinks and
    collapsing ``..`` segments) without requiring either to exist on
    disk, then verifies the resolved candidate is identical to or a
    descendant of the resolved safe-root. Raises
    :class:`PathTraversalError` on violation.

    The function is intentionally ``strict=False`` on resolution so
    new-file paths (write destinations not yet created) are accepted
    — the safety check is on the resolved *parent chain*, not on
    file existence.

    Parameters
    ----------
    candidate:
        The path to check. Typically composed from external input
        (request body field, URL path parameter, env var).
    safe_root:
        The directory that ``candidate`` must lie within. Typically
        the application's user-data directory, gap-store directory,
        static-asset directory, or temp directory.

    Returns
    -------
    Path
        The resolved (absolute, symlink-followed) form of
        ``candidate``.

    Raises
    ------
    PathTraversalError
        If the resolved candidate is not equal to or a descendant of
        the resolved safe root.
    """
    resolved_candidate = candidate.resolve(strict=False)
    resolved_root = safe_root.resolve(strict=False)
    if not resolved_candidate.is_relative_to(resolved_root):
        raise PathTraversalError("Path resolves outside the permitted directory.")
    return resolved_candidate
