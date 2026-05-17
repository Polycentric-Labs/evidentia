"""FastAPI application factory.

The module-level ``app`` is the canonical instance that uvicorn references.
For testing (TestClient), prefer :func:`create_app` which accepts overrides.

All API routes live under ``/api/*``. Static assets (the bundled React SPA)
are mounted at ``/`` and serve ``index.html`` for every non-``/api/*`` path
to support client-side routing (React Router).

In v0.4.0 the static directory is populated at wheel-build time by the
frontend build hook in ``.github/workflows/release.yml`` (it runs
``npm run build`` in ``packages/evidentia-ui`` and copies ``dist/*``
into ``src/evidentia_api/static/``). When the directory is empty at
runtime (e.g. fresh dev install without a build), a placeholder JSON
response is returned instead of 404 so the error is self-explanatory.

Offline mode: the ``evidentia serve --offline`` CLI entry point sets
``EVIDENTIA_API_OFFLINE=1`` in the subprocess env. This module reads
that at import time to flip the process-wide air-gap guard before any
router handler runs.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from evidentia_api import __version__

if TYPE_CHECKING:
    from evidentia_core.plugins.auth import AuthProvider

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _auth_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """v0.8.2 F-V81-S2: defer env-driven AuthProvider construction.

    Replaces the v0.8.1 module-level construction (which read
    ``EVIDENTIA_API_AUTH_TOKEN_FILE`` at import time) with a
    startup-time read. Explicit injection via
    :func:`create_app(auth_provider=...)` continues to take
    precedence — this lifespan only constructs a provider when
    ``app.state.auth_provider`` is ``None`` at startup.

    Importing this module no longer has filesystem side effects;
    the env var is read only when the FastAPI app is actually
    started (uvicorn / TestClient context-manager / etc.). This
    makes the module safer for tooling that imports without
    running (OpenAPI generation, mypy plugin scans, doc builds).

    Failure mode is preserved: if the env var is set but the
    token file is missing/empty/symlinked, the lifespan raises
    so app startup fails loudly. The operator sees a clear
    error rather than a silent fall-through to no-auth.
    """
    if app.state.auth_provider is None:
        env_token_file = os.environ.get(
            "EVIDENTIA_API_AUTH_TOKEN_FILE", ""
        ).strip()
        if env_token_file:
            from evidentia_core.plugins.auth.local_token import (
                LocalTokenAuthProvider,
            )

            try:
                app.state.auth_provider = LocalTokenAuthProvider(
                    token_file=env_token_file
                )
            except (FileNotFoundError, ValueError):
                # Fail loud at startup — operator passed
                # --auth-token-file but the file is missing /
                # empty / symlinked. Don't silently fall back to
                # no-auth.
                logger.error(
                    "AuthProvider construction failed at startup "
                    "(token file %s)",
                    env_token_file,
                )
                raise
    yield

STATIC_DIR = Path(__file__).parent / "static"
"""Absolute path to the bundled SPA assets (populated at build time)."""


def create_app(
    *,
    offline: bool = False,
    dev_mode: bool = False,
    cors_origins: list[str] | None = None,
    security_headers: bool | None = None,
    auth_provider: AuthProvider | None = None,
) -> FastAPI:
    """Build and return a FastAPI application.

    Parameters
    ----------
    offline
        When True, flips the process-wide air-gap guard at app creation.
        Every LLM/network call then refuses non-loopback targets.
    dev_mode
        When True, CORS is permissive to support the Vite dev server
        (http://127.0.0.1:5173) without a proxy.
    cors_origins
        Explicit allow-list override. Default: restrictive localhost-only.
    security_headers
        When True, attach :class:`SecurityHeadersMiddleware` so every
        response carries CSP / X-Frame-Options / X-Content-Type-Options
        / Referrer-Policy / Strict-Transport-Security / Permissions-
        Policy headers. When None (default), reads the
        ``EVIDENTIA_API_SECURITY_HEADERS`` env var (``"1"`` → on; any
        other value → off). The CLI ``evidentia serve`` flag wires the
        env var on the operator's behalf with auto-detection per
        bind-host. Closes v0.7.8 F-V08-DAST-2 LOW finding (CWE-693).
    auth_provider
        v0.8.1 P3.3: optional :class:`AuthProvider` instance from
        ``evidentia_core.plugins.auth``. When non-None, attaches
        :class:`AuthProviderMiddleware` so every ``/api/*`` route
        requires a valid bearer token (gating
        :class:`AuthResult.authenticated`). Liveness probes
        (``/api/health``, ``/api/version``) bypass auth per the
        UNAUTHENTICATED_PATHS allowlist. Default ``None`` matches
        v0.8.0 behavior (no auth gating). Closes v0.8.0 review
        F-V08-S3 ``/api/metrics`` MEDIUM finding when populated.
    """
    if offline:
        from evidentia_core.network_guard import set_offline

        set_offline(True)

    if security_headers is None:
        security_headers = (
            os.environ.get("EVIDENTIA_API_SECURITY_HEADERS") == "1"
        )

    app = FastAPI(
        title="Evidentia API",
        description=(
            "REST API for the Evidentia GRC tool. All endpoints mirror "
            "CLI capabilities. Binds to 127.0.0.1 by default for localhost "
            "web-UI use."
        ),
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        # v0.8.2 F-V81-S2: env-driven AuthProvider construction
        # happens at startup, not import time. The lifespan
        # reads EVIDENTIA_API_AUTH_TOKEN_FILE iff
        # app.state.auth_provider is None at startup (i.e.,
        # the explicit-injection path didn't pre-populate it).
        lifespan=_auth_lifespan,
    )

    # v0.8.2 F-V81-S2: pre-populate app.state.auth_provider with
    # the explicit-injection value (if any). The lifespan only
    # falls back to env-var construction when this is None at
    # startup. Set BEFORE middleware add so the dispatch path
    # reads a consistent state during cold-start.
    app.state.auth_provider = auth_provider

    # CORS: dev_mode is permissive for Vite HMR; prod is localhost-only.
    if cors_origins is None:
        cors_origins = (
            [
                "http://127.0.0.1:5173",
                "http://localhost:5173",
                "http://127.0.0.1:8000",
                "http://localhost:8000",
            ]
            if dev_mode
            else ["http://127.0.0.1:8000", "http://localhost:8000"]
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # Defense-in-depth security headers (v0.7.9 F-V08-DAST-2 carry-over).
    # Off by default; on when host is non-loopback or when explicitly
    # enabled via --security-headers / EVIDENTIA_API_SECURITY_HEADERS=1.
    if security_headers:
        from evidentia_api.security_headers import SecurityHeadersMiddleware

        app.add_middleware(SecurityHeadersMiddleware)

    # v0.8.1 P3.3 + v0.8.2 F-V81-S2: AuthProvider middleware.
    # Always attaches now — the middleware reads
    # ``request.app.state.auth_provider`` at dispatch and is a
    # no-op when None. This decouples middleware attachment
    # (must happen at app build time per Starlette) from
    # provider construction (which can defer to the lifespan
    # event for the env-var-driven path). Attaches BEFORE the
    # security-headers middleware in the FastAPI middleware
    # stack (Starlette runs middleware in reverse-add order, so
    # this becomes the OUTER ring — auth check fires before
    # any security-header logic).
    from evidentia_api.auth_middleware import (
        AuthProviderMiddleware,
    )

    app.add_middleware(AuthProviderMiddleware)

    # v0.9.4 P1.3: per-client-IP token-bucket rate limiter on the
    # AI gov mutating endpoints (POST /classify + POST /register).
    # Closes v0.9.3 F-V93-S10 LOW (no rate limit + unbounded
    # registry growth from a single authenticated client). Default
    # 60 req/min/client + burst of 10 — comfortably above any
    # legitimate interactive UI pattern, restrictive enough to
    # blunt a register-flood. Process-local; multi-worker
    # deployments share-nothing (acceptable for v0.9.4 OSS).
    from evidentia_api.rate_limit import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware)

    # Attach flags to app state so every router dep can consult them.
    # NOTE: app.state.auth_provider was set above (pre-FastAPI-init
    # path) so the dispatch path is consistent during cold start.
    app.state.offline = offline
    app.state.dev_mode = dev_mode
    app.state.security_headers = security_headers

    # Register routers. Each router is a focused module — see routers/*.py.
    # Imports are deferred so module-load errors in one router don't take
    # down the whole server.
    from evidentia_api.routers import (
        ai_gov as ai_gov_router,
    )
    from evidentia_api.routers import (
        collectors as collectors_router,
    )
    from evidentia_api.routers import (
        config as config_router,
    )
    from evidentia_api.routers import (
        conmon as conmon_router,
    )
    from evidentia_api.routers import (
        doctor as doctor_router,
    )
    from evidentia_api.routers import (
        explain as explain_router,
    )
    from evidentia_api.routers import (
        frameworks as frameworks_router,
    )
    from evidentia_api.routers import (
        gaps as gaps_router,
    )
    from evidentia_api.routers import (
        health as health_router,
    )
    from evidentia_api.routers import (
        init_wizard as init_wizard_router,
    )
    from evidentia_api.routers import (
        integrations as integrations_router,
    )
    from evidentia_api.routers import (
        llm_status as llm_status_router,
    )
    from evidentia_api.routers import (
        metrics as metrics_router,
    )
    from evidentia_api.routers import (
        model_risk as model_risk_router,
    )
    from evidentia_api.routers import (
        poam as poam_router,
    )
    from evidentia_api.routers import (
        risks as risks_router,
    )
    from evidentia_api.routers import (
        tprm as tprm_router,
    )

    app.include_router(health_router.router, prefix="/api", tags=["health"])
    app.include_router(metrics_router.router, prefix="/api", tags=["metrics"])
    app.include_router(config_router.router, prefix="/api", tags=["config"])
    app.include_router(doctor_router.router, prefix="/api", tags=["doctor"])
    app.include_router(llm_status_router.router, prefix="/api", tags=["llm"])
    app.include_router(
        frameworks_router.router, prefix="/api", tags=["frameworks"]
    )
    app.include_router(gaps_router.router, prefix="/api", tags=["gaps"])
    app.include_router(risks_router.router, prefix="/api", tags=["risks"])
    app.include_router(explain_router.router, prefix="/api", tags=["explain"])
    app.include_router(
        init_wizard_router.router, prefix="/api", tags=["init"]
    )
    app.include_router(
        integrations_router.router, prefix="/api", tags=["integrations"]
    )
    app.include_router(
        collectors_router.router, prefix="/api", tags=["collectors"]
    )
    app.include_router(tprm_router.router, prefix="/api", tags=["tprm"])
    app.include_router(
        model_risk_router.router, prefix="/api", tags=["model-risk"]
    )
    app.include_router(poam_router.router, prefix="/api", tags=["poam"])
    app.include_router(conmon_router.router, prefix="/api", tags=["conmon"])
    app.include_router(ai_gov_router.router, prefix="/api", tags=["ai-gov"])

    # Static SPA mount — everything that isn't /api/* falls through to index.html.
    _mount_spa(app)

    return app


def _mount_spa(app: FastAPI) -> None:
    """Mount the bundled React SPA at the root.

    If the static directory is missing or empty (common in fresh dev checkouts
    before ``npm run build`` has been executed), serve a helpful placeholder
    instead of 404 so users can self-diagnose.
    """
    if STATIC_DIR.is_dir() and (STATIC_DIR / "index.html").is_file():
        # Mount static/assets first for JS/CSS/fonts; then SPA fallback.
        assets_dir = STATIC_DIR / "assets"
        if assets_dir.is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=assets_dir),
                name="spa-assets",
            )

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa_fallback(full_path: str, request: Request) -> FileResponse:
            """Serve index.html for every non-API path so React Router owns routing."""
            if full_path.startswith("api/"):
                # Defensive — FastAPI routing should have caught these already.
                return FileResponse(STATIC_DIR / "index.html", status_code=404)
            # full_path is user-controlled (URL path component). Validate
            # the resolved candidate sits inside STATIC_DIR before
            # serving — a request for ``../../etc/passwd`` resolves
            # outside the static root and falls through to index.html.
            try:
                target = validate_within(STATIC_DIR / full_path, STATIC_DIR)
            except PathTraversalError:
                return FileResponse(STATIC_DIR / "index.html")
            if target.is_file():
                return FileResponse(target)
            return FileResponse(STATIC_DIR / "index.html")

    else:
        logger.info(
            "Static SPA directory is empty at %s — serving dev placeholder. "
            "Run `npm run build` in packages/evidentia-ui/ to populate.",
            STATIC_DIR,
        )

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _dev_placeholder(full_path: str) -> JSONResponse:
            if full_path.startswith("api/"):
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            return JSONResponse(
                status_code=503,
                content={
                    "error": "spa_not_built",
                    "message": (
                        "The Evidentia web UI is not bundled in this install. "
                        "If you are developing, run `npm install && npm run dev` "
                        "in packages/evidentia-ui/ and use `evidentia "
                        "serve --dev`. If you are an end user, please reinstall "
                        "with `pip install --force-reinstall evidentia[gui]`."
                    ),
                    "api_docs": "/api/docs",
                },
            )


# Read env-var flags set by ``evidentia serve`` subprocess launch.
# EVIDENTIA_API_OFFLINE=1     -> offline mode
# EVIDENTIA_API_DEV=1         -> permissive CORS for Vite dev server
# EVIDENTIA_API_AUTH_TOKEN_FILE -> path to token file for the
#     LocalTokenAuthProvider. v0.8.2 F-V81-S2: read at app
#     STARTUP (FastAPI lifespan), not at module import. See
#     ``_auth_lifespan`` above.
_env_offline = os.environ.get("EVIDENTIA_API_OFFLINE", "").strip().lower() in {
    "1",
    "true",
    "yes",
}
_env_dev = os.environ.get("EVIDENTIA_API_DEV", "").strip().lower() in {
    "1",
    "true",
    "yes",
}

# Default instance for `uvicorn evidentia_api.app:app` usage.
# v0.8.2 F-V81-S2: auth_provider is left None here; the
# lifespan reads EVIDENTIA_API_AUTH_TOKEN_FILE at startup if
# present. Module import is now side-effect-free (no filesystem
# I/O) — safe for tooling that imports for OpenAPI generation,
# mypy plugin scans, or doc builds.
app = create_app(
    offline=_env_offline,
    dev_mode=_env_dev,
)
