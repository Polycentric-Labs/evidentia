"""RFC 8594 deprecation signalling for REST operations (v0.12.0).

`docs/deprecation-calendar.md` § How removals are sequenced requires
every announced deprecation to carry a machine-readable signal:
a ``DeprecationWarning`` for Python surfaces, a ``Deprecation: true``
header for REST ones. Through v0.11.x the REST half was documented
but never implemented — the `ai-gov set-omb-impact` deprecation
(announced v0.10.12, removal targeted at v1.0.0) existed only in
prose, so no client could discover it programmatically. This module
closes that gap.

Two pieces:

``deprecation_headers``
    A pure header-construction function. Emits ``Deprecation: true``
    always, a ``successor-version`` ``Link`` when a replacement
    exists, and ``Sunset`` **only** when a real removal *date* is
    committed — see the honesty note below.

``DeprecationAwareRoute``
    An ``APIRoute`` subclass that applies those headers to every
    response from a route already declared ``deprecated=True``. Set
    it once as a router's ``route_class`` and the existing FastAPI
    ``deprecated=True`` flag — which previously only affected the
    OpenAPI document — starts driving the wire behaviour too. The
    successor is read from the route's own ``openapi_extra``, so
    there is no second registry to keep in sync.

**Why no default ``Sunset``**: RFC 8594 §3 defines ``Sunset`` as an
HTTP-date after which the resource is expected to become
unresponsive. Evidentia's calendar commits to a removal *release*
(v1.0.0), and release dates are not fixed in advance. Emitting a
guessed timestamp would be a machine-readable promise we have not
made, so the header is omitted until a date genuinely exists.

References:
  - RFC 8594, "The Deprecation HTTP Header Field"
  - `docs/deprecation-calendar.md`, `docs/api-stability.md`
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import UTC, date, datetime
from email.utils import format_datetime
from typing import Any

from fastapi import HTTPException, Request, Response
from fastapi.routing import APIRoute

__all__ = [
    "SUCCESSOR_VERSION_EXTENSION",
    "DeprecationAwareRoute",
    "deprecation_headers",
    "successor_version",
]

#: OpenAPI specification extension carrying a deprecated operation's
#: replacement path. ``x-`` prefixed per the OpenAPI extension rules,
#: so it is valid in the emitted document and visible to SDK
#: generators as well as to :class:`DeprecationAwareRoute`.
SUCCESSOR_VERSION_EXTENSION = "x-successor-version"


def deprecation_headers(
    *,
    successor: str | None = None,
    sunset: date | None = None,
) -> dict[str, str]:
    """Build the RFC 8594 response headers for a deprecated resource.

    Args:
        successor: Path or URI of the replacement resource, advertised
            with ``rel="successor-version"`` (RFC 8594 §4). Omitted
            when there is no direct replacement.
        sunset: Committed removal date, rendered as an IMF-fixdate
            ``Sunset`` header (RFC 8594 §3). Omitted when no date is
            committed — see the module docstring.

    Returns:
        A fresh mutable mapping, safe for the caller to merge into
        an ``HTTPException``'s own headers.

    Raises:
        ValueError: If ``successor`` is given but blank.
    """
    headers = {"Deprecation": "true"}

    if successor is not None:
        if not successor.strip():
            raise ValueError(
                "successor must be a non-empty path or URI; pass None when the deprecated resource has no replacement"
            )
        headers["Link"] = f'<{successor}>; rel="successor-version"'

    if sunset is not None:
        # RFC 8594 §3 requires an HTTP-date; format_datetime(usegmt=True)
        # emits the IMF-fixdate production ("Fri, 15 Jan 2027 … GMT").
        midnight_utc = datetime(sunset.year, sunset.month, sunset.day, tzinfo=UTC)
        headers["Sunset"] = format_datetime(midnight_utc, usegmt=True)

    return headers


def successor_version(path: str) -> dict[str, Any]:
    """Build the ``openapi_extra`` payload naming a successor route.

    Pair with ``deprecated=True`` on the route decorator::

        @router.post(
            "/legacy",
            deprecated=True,
            openapi_extra=successor_version("/api/replacement"),
        )

    :class:`DeprecationAwareRoute` reads it back to construct the
    ``Link`` header, so the successor is declared exactly once,
    beside the operation it describes.
    """
    if not path.strip():
        raise ValueError("successor path must be non-empty")
    return {SUCCESSOR_VERSION_EXTENSION: path}


class DeprecationAwareRoute(APIRoute):
    """Applies RFC 8594 headers to routes declared ``deprecated=True``.

    Install as a router's ``route_class``; routes that are not
    deprecated keep FastAPI's stock handler untouched, so the class is
    safe to apply router-wide::

        router = APIRouter(route_class=DeprecationAwareRoute)

    Both the success path and deliberately-raised ``HTTPException``
    responses (404 for an unknown ID, 403 from an RBAC gate) carry the
    headers — a client probing a deprecated verb learns it is going
    away even when the specific call fails. Request-validation (422)
    responses do not, since those requests never reached the resource.
    """

    def get_route_handler(
        self,
    ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original_handler = super().get_route_handler()
        if not self.deprecated:
            return original_handler

        extra = self.openapi_extra or {}
        headers = deprecation_headers(successor=extra.get(SUCCESSOR_VERSION_EXTENSION))

        async def deprecation_aware_handler(request: Request) -> Response:
            try:
                response = await original_handler(request)
            except HTTPException as exc:
                exc.headers = {**(exc.headers or {}), **headers}
                raise
            response.headers.update(headers)
            return response

        return deprecation_aware_handler
