"""Health + version endpoints — minimal dependencies.

These are used by:
- The Playwright e2e-smoke test (`wait-on http://127.0.0.1:8000/api/health`)
- The React UI on load to verify the backend is reachable
- Deployment health probes
"""

from __future__ import annotations

import sys

from fastapi import APIRouter, Request

from evidentia_api import __version__ as api_version
from evidentia_api.schemas import HealthResponse, VersionResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Simple liveness probe — returns 200 when the server is serving requests.

    Also reports ``auth_configured`` (whether an AuthProvider is wired on
    ``app.state``) so the web console can gate credentialed actions and show an
    unsecured-deployment notice on an anonymous deployment. Stays unauthenticated
    (in ``UNAUTHENTICATED_PATHS``); ``auth_configured`` is not a secret — an
    anonymous caller already learns the API is unauthenticated by reaching it.
    """
    auth_configured = (
        getattr(request.app.state, "auth_provider", None) is not None
    )
    return HealthResponse(
        status="ok", version=api_version, auth_configured=auth_configured
    )


@router.get("/version", response_model=VersionResponse)
async def version() -> VersionResponse:
    """Return installed Evidentia component versions + Python info."""
    # Imports deferred so health stays dependency-light when cores fail.
    try:
        from evidentia_core import __version__ as core_version
    except ImportError:
        core_version = "unknown"
    try:
        from evidentia_ai import __version__ as ai_version
    except ImportError:
        ai_version = "unknown"

    py = ".".join(str(v) for v in sys.version_info[:3])
    return VersionResponse(
        api_version=api_version,
        core_version=core_version,
        ai_version=ai_version,
        python_version=py,
    )
