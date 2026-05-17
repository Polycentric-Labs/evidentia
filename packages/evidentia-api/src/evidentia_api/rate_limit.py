"""Per-client-IP token bucket rate limiter (v0.9.4 P1.3).

Closes v0.9.3 F-V93-S10 LOW: AI gov register + classify endpoints
had no rate limit, allowing an authenticated client to fill the
registry store via repeated POSTs.

Stdlib-only implementation — no Redis, no external middleware lib,
no in-process global state side effects beyond the limiter
instance. Fits the project's "minimal runtime deps" posture.

Algorithm: standard token bucket.

- Each client identity (currently: source IP) starts with ``burst``
  tokens.
- Tokens regenerate at ``rate_per_minute / 60.0`` tokens/second.
- Each ``check(client_id)`` attempts to consume 1 token.
- Returns ``True`` (allowed) if a token was consumed; ``False``
  (throttled) if the bucket was empty.

Memory bounds: per-client state is an ``OrderedDict``; older entries
are evicted LRU-style at ``max_tracked_clients`` (default 10000).
This caps memory growth from observation-only clients without
breaking the rate-limit guarantee for active ones.

NOT thread-safe by design — the FastAPI middleware wires this into
the request handler path which is async-cooperative; the GIL plus
the short critical sections (dict lookup + arithmetic) keep races
practically harmless. Operators wanting hard guarantees can wrap
``check()`` in an asyncio.Lock at the middleware layer.

Threat model note: source-IP is the rate-limit identity. Operators
behind a reverse proxy MUST configure FastAPI to honor the
``X-Forwarded-For`` header by wiring Starlette's
``ProxyHeadersMiddleware`` themselves — otherwise all requests
appear to come from the proxy itself and share a single bucket.
``evidentia_api.app`` does NOT currently wire ProxyHeaders
middleware automatically; operators are responsible for adding it
to their deployment ASGI stack if they sit behind a reverse proxy.
A future v0.9.5 ``EVIDENTIA_TRUST_PROXY_HEADERS=1`` env var
+ auto-wired ProxyHeadersMiddleware integration is tracked as a
v0.9.5 polish item.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass
class _BucketState:
    """Per-client bucket state: token count + last refill timestamp."""

    tokens: float
    last_refill_monotonic: float


class TokenBucketRateLimiter:
    """Per-client-IP token bucket.

    Args:
        rate_per_minute: Steady-state requests per minute the
            limiter will permit per client. Default 60 (1 / sec).
        burst: Maximum burst the limiter will accept above the
            steady-state rate. Default 10 (matches typical
            interactive-UI burst patterns: classify-then-register
            click sequences).
        max_tracked_clients: LRU eviction threshold. Default 10000;
            larger values cost ~200 bytes/client RSS.

    Example::

        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=10)
        if not limiter.check(request.client.host):
            raise HTTPException(429, "rate limit exceeded")

    The limiter is process-local. For multi-worker deployments
    (uvicorn ``--workers N``), each worker has its own buckets;
    operators wanting global rate-limiting need a shared store
    (Redis, sticky-session at the LB, etc.) — out of scope for
    v0.9.4 OSS.
    """

    def __init__(
        self,
        rate_per_minute: int = 60,
        burst: int = 10,
        max_tracked_clients: int = 10000,
    ) -> None:
        if rate_per_minute < 0:
            raise ValueError(
                f"rate_per_minute must be >= 0; got {rate_per_minute}"
            )
        if burst < 1:
            raise ValueError(f"burst must be >= 1; got {burst}")
        if max_tracked_clients < 1:
            raise ValueError(
                f"max_tracked_clients must be >= 1; got {max_tracked_clients}"
            )
        self._rate_per_second = rate_per_minute / 60.0
        self._burst = float(burst)
        self._max_tracked = max_tracked_clients
        self._buckets: OrderedDict[str, _BucketState] = OrderedDict()

    def check(self, client_id: str) -> bool:
        """Attempt to consume one token for ``client_id``.

        Returns:
            True if a token was consumed (request allowed),
            False if the bucket was empty (request throttled).
        """
        now = time.monotonic()
        state = self._buckets.get(client_id)
        if state is None:
            # First request from this client: full bucket + refill anchor.
            state = _BucketState(tokens=self._burst, last_refill_monotonic=now)
            self._buckets[client_id] = state
            # Evict LRU if we exceeded the cap (do this after insert so
            # the just-inserted entry isn't first to evict).
            while len(self._buckets) > self._max_tracked:
                self._buckets.popitem(last=False)
        else:
            # Mark as recently used (move-to-end for LRU ordering).
            self._buckets.move_to_end(client_id)
            # Refill: tokens accrued = elapsed * rate, capped at burst.
            elapsed = now - state.last_refill_monotonic
            state.tokens = min(
                self._burst,
                state.tokens + elapsed * self._rate_per_second,
            )
            state.last_refill_monotonic = now

        if state.tokens >= 1.0:
            state.tokens -= 1.0
            return True
        return False

    def reset(self) -> None:
        """Discard all bucket state. Intended for tests."""
        self._buckets.clear()

    @property
    def tracked_client_count(self) -> int:
        """Number of clients currently in the LRU. Diagnostic."""
        return len(self._buckets)


# Default rate-limited path allowlist for the AI gov register +
# classify endpoints. Other operator-instance allowlists can be
# passed via :class:`RateLimitMiddleware`'s ``rate_limited_paths``
# constructor argument.
DEFAULT_RATE_LIMITED_PATHS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/ai-gov/register"),
        ("POST", "/api/ai-gov/classify"),
    }
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware applying a token bucket to specific
    (method, path) pairs. Returns ``429 Too Many Requests`` when
    the per-client bucket is empty.

    Wires into FastAPI like other Starlette middleware::

        app.add_middleware(
            RateLimitMiddleware,
            limiter=TokenBucketRateLimiter(rate_per_minute=60, burst=10),
        )

    Args:
        limiter: A :class:`TokenBucketRateLimiter` instance.
            Operators can construct with custom rate/burst per their
            deployment posture.
        rate_limited_paths: Iterable of ``(method, path)`` pairs to
            rate-limit. Default: ``DEFAULT_RATE_LIMITED_PATHS`` (the
            two AI gov mutation endpoints). Path matching is exact;
            wildcards not supported (keeps the dispatch path fast
            and the allowlist explicit/auditable).

    The middleware identifies clients by ``request.client.host``.
    Behind a reverse proxy, configure FastAPI to honor
    ``X-Forwarded-For`` (Starlette's ProxyHeaders middleware) —
    otherwise all requests share a single bucket from the proxy's
    IP. See module docstring.
    """

    def __init__(
        self,
        app: object,
        limiter: TokenBucketRateLimiter | None = None,
        rate_limited_paths: frozenset[tuple[str, str]] | None = None,
    ) -> None:
        # Matches AuthProviderMiddleware's ``app: object`` pattern
        # — Starlette's middleware-factory protocol accepts any
        # ASGI app object; tighter typing breaks add_middleware().
        super().__init__(app)  # type: ignore[arg-type]
        self._limiter = limiter or TokenBucketRateLimiter()
        self._paths = rate_limited_paths or DEFAULT_RATE_LIMITED_PATHS

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        key = (request.method, request.url.path)
        if key in self._paths:
            client_host = (
                request.client.host
                if request.client is not None
                else "unknown"
            )
            if not self._limiter.check(client_host):
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": (
                            "Rate limit exceeded for "
                            f"{request.method} {request.url.path}. "
                            "Retry after a short delay."
                        )
                    },
                    headers={"Retry-After": "5"},
                )
        return await call_next(request)
