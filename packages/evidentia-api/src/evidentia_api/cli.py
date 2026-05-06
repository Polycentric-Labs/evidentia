"""`evidentia serve` implementation.

Invoked from :mod:`evidentia.cli.main` via the `serve` Typer command.
Uses ``subprocess.Popen`` against ``sys.executable -m uvicorn`` for
portability across Windows/macOS/Linux — per the Plan-agent pressure-test,
this pattern survives Ctrl+C on Windows consoles more reliably than
``uvicorn.run()`` in-process.

Dev mode (``--dev``) leaves frontend serving to the Vite dev server
(``npm run dev`` in ``packages/evidentia-ui/``) on port 5173; the
FastAPI server at 8000 enables permissive CORS so the two co-exist.
Production mode serves the bundled SPA from the wheel.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    offline: bool = False,
    dev: bool = False,
    open_browser: bool = True,
    reload: bool = False,
    security_headers: bool | None = None,
    auth_token_file: str | None = None,
) -> int:
    """Spawn uvicorn serving the Evidentia API + web UI.

    Returns the child process exit code. Errors raised before spawn (e.g.
    missing uvicorn install) surface as ``ImportError`` for the caller to
    translate into a friendly message.

    The ``security_headers`` argument controls whether the FastAPI
    application attaches :class:`SecurityHeadersMiddleware` (v0.7.9
    F-V08-DAST-2 carry-over). ``None`` (default) auto-detects from
    the bind host: enabled when binding to non-loopback, disabled
    when binding to loopback. Pass ``True`` / ``False`` to override.
    """
    # Verify uvicorn is importable before spawning — otherwise the
    # subprocess error message is opaque on Windows.
    try:
        import uvicorn  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "uvicorn is not installed. Install the [gui] extra: "
            "`pip install 'evidentia[gui]'` or "
            "`uv tool install 'evidentia[gui]'`."
        ) from e

    # Host-binding security: warn if binding to a non-loopback address.
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(
            "SECURITY: binding to %s exposes the web UI on your network. "
            "Evidentia has no auth in v0.4.0 — anyone who can reach this "
            "address can view and modify your gap reports. Bind to 127.0.0.1 "
            "unless you know what you're doing.",
            host,
        )

    # Auto-detect security_headers when not explicitly set: on for
    # non-loopback binds, off for loopback. Operator can override with
    # `--security-headers` / `--no-security-headers`.
    if security_headers is None:
        from evidentia_api.security_headers import should_enable_for_host

        security_headers = should_enable_for_host(host)
        if security_headers:
            logger.info(
                "SECURITY: non-loopback bind detected; "
                "auto-enabling defense-in-depth security headers "
                "(--no-security-headers to suppress)."
            )

    # Environment plumbing: offline flag + dev mode + security-headers
    # flag + auth-token-file are read by evidentia_api.app.create_app
    # via module-level env vars so they survive the subprocess boundary.
    env = os.environ.copy()
    if offline:
        env["EVIDENTIA_API_OFFLINE"] = "1"
    if dev:
        env["EVIDENTIA_API_DEV"] = "1"
    if security_headers:
        env["EVIDENTIA_API_SECURITY_HEADERS"] = "1"
    if auth_token_file:
        env["EVIDENTIA_API_AUTH_TOKEN_FILE"] = auth_token_file

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "evidentia_api.app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        cmd.append("--reload")

    if open_browser and not reload:
        # Open browser slightly after spawn so the server has time to bind.
        import threading
        import webbrowser

        def _open() -> None:
            import time

            time.sleep(1.5)
            webbrowser.open(f"http://{host}:{port}")

        threading.Thread(target=_open, daemon=True).start()

    logger.info("Spawning: %s", " ".join(cmd))

    # Windows: CREATE_NEW_PROCESS_GROUP lets Ctrl+C in the parent terminate
    # the child cleanly without leaving a zombie on the port.
    popen_kwargs: dict[str, Any] = {"env": env}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(cmd, **popen_kwargs)
    try:
        return proc.wait()
    except KeyboardInterrupt:
        logger.info("Received Ctrl+C; shutting down uvicorn...")
        if sys.platform == "win32":
            import signal

            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.terminate()
        return proc.wait()


def resolve_static_dir() -> Path:
    """Return the static-asset directory, for diagnostics."""
    from evidentia_api.app import STATIC_DIR

    return STATIC_DIR
