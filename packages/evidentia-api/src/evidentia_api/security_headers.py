"""Defense-in-depth security-response-headers middleware (v0.7.9 carry-over from F-V08-DAST-2).

Closes the v0.7.8 Step 5.A deferred LOW finding (CWE-693, Protection
Mechanism Failure): the SPA root response carried no
Content-Security-Policy / X-Frame-Options / X-Content-Type-Options /
Referrer-Policy / Strict-Transport-Security / Permissions-Policy
headers. The localhost-bound default (``evidentia serve --host
127.0.0.1``) made network-side clickjacking impractical, but operators
who exposed the UI to a network without TLS-terminating proxy
configuration would inherit the same defense-in-depth gap.

Activation policy (per plan §17 carry-over):

- **OFF by default** when binding to loopback (``127.0.0.1`` /
  ``localhost`` / ``::1``). Localhost dev-loop parity matters.
- **ON when binding to non-loopback** (``0.0.0.0`` or any
  external interface) — the operator has opted into network
  exposure; defense-in-depth headers should travel with that.
- **Forceable via** the ``--security-headers`` CLI flag or the
  ``EVIDENTIA_API_SECURITY_HEADERS=1`` env var (override the
  auto-detect; turn ON regardless of host).
- **Suppressible via** ``--no-security-headers`` (override; turn
  OFF regardless of host — useful when a reverse proxy already
  injects these headers and you don't want duplicates).

The header set follows the OWASP Secure Headers Project + Mozilla
Observatory defaults, tightened for Evidentia's specific surface
(no third-party scripts, no remote images, no embedded frames).
Single tweakable knob is `unsafe-inline` on script-src and
style-src — required by Vite's production-build SPA bundle and
Tailwind's atomic-CSS injection. v0.8.0 will revisit nonce-based
CSP once the SPA build pipeline supports CSP nonces natively.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# The security header set. Module-level so consumers can introspect
# (testing, OpenAPI security-schemes auto-doc, etc.).
SECURITY_HEADERS: dict[str, str] = {
    # Content-Security-Policy: restrict resource loads to same-origin.
    # `unsafe-inline` on script-src + style-src is required by the
    # current React/Vite bundle + Tailwind's atomic-CSS injection. The
    # production Vite build does NOT need 'unsafe-eval', and the dev
    # mode (which does) is localhost-only by definition. v0.8.0 will
    # tighten to nonce-based CSP once the bundle supports it.
    # `data:` allowed for img-src + font-src to support inline icons +
    # base64-embedded fonts produced by the build.
    # `frame-ancestors 'none'` is the modern replacement for X-Frame-Options;
    # both are sent for legacy-browser compatibility.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    # X-Frame-Options DENY: refuse to load in any frame (legacy
    # equivalent of frame-ancestors 'none').
    "X-Frame-Options": "DENY",
    # X-Content-Type-Options nosniff: disable MIME sniffing so a
    # maliciously-mistyped response can't be reinterpreted as a script.
    "X-Content-Type-Options": "nosniff",
    # Referrer-Policy: send origin on cross-origin navigations, full
    # URL on same-origin. Best-balance choice per OWASP guidance.
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Strict-Transport-Security: force HTTPS for one year on the
    # current host + all subdomains. Browsers IGNORE this header over
    # plain HTTP per RFC 6797 §7.2, so it's safe to always emit when
    # security headers are on — operators running TLS via reverse
    # proxy benefit; localhost dev users are unaffected.
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Permissions-Policy: refuse to grant sensitive browser APIs.
    # Evidentia doesn't need camera / microphone / geolocation /
    # payment / USB. `interest-cohort=()` opts out of FLoC tracking.
    "Permissions-Policy": ("camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"),
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject the :data:`SECURITY_HEADERS` set on every response.

    Sub-classed Starlette ``BaseHTTPMiddleware`` rather than wired as
    a function so consumers (tests, integration suites) can swap the
    header set via the constructor for fixture-specific scenarios
    without monkey-patching the module-level dict.
    """

    def __init__(
        self,
        app: object,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._headers = headers if headers is not None else SECURITY_HEADERS

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        # Always set: security headers are defense-in-depth and
        # should win over any route-level customization. A future
        # route that genuinely needs looser CSP (OAuth callback,
        # embedded-iframe scenarios) should opt out via a separate
        # mechanism — e.g., a path-allow-list passed to this
        # middleware's constructor — rather than relying on
        # per-route header override that could be missed during
        # security review.
        for name, value in self._headers.items():
            response.headers[name] = value
        return response


def should_enable_for_host(host: str) -> bool:
    """Auto-detect whether to enable security headers based on bind host.

    True for any non-loopback bind address — the operator has opted
    into network exposure, so defense-in-depth headers should travel
    with that. False for ``127.0.0.1`` / ``localhost`` / ``::1``
    (dev-loop parity).

    Used by ``evidentia serve`` when ``--security-headers`` is not
    explicitly set.
    """
    return host not in ("127.0.0.1", "localhost", "::1")
