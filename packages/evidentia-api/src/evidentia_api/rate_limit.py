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
the request handler path which is async-cooperative. The reader-
writer pattern (per-bucket lookup + arithmetic) has no awaits
between read and write, so the active coroutine cannot be
preempted mid-check on a single event loop. Hard guarantees under
multi-event-loop deployments (e.g., Granian, multiple uvicorn
workers) require an ``asyncio.Lock`` at the middleware layer OR a
shared Redis-backed limiter. v0.9.4 ships single-event-loop
deployments; multi-worker is documented in
``docs/conmon-daemon-deployment.md`` with the
"share-nothing per worker" caveat.

Threat model note: source-IP is the rate-limit identity. Operators
behind a reverse proxy MUST honor ``X-Forwarded-For`` to identify
the real client IP — otherwise every request appears to come from
the proxy itself and shares a single bucket, defeating the limiter.

v0.9.5 P1.6: ``evidentia_api.app.create_app(trust_proxy_headers=
True)`` (or the equivalent ``EVIDENTIA_TRUST_PROXY_HEADERS=1`` env
var) auto-wires uvicorn's ``ProxyHeadersMiddleware`` so the rate
limiter + audit-log middleware see the forwarded IP. Default off
because honoring the header without a proxy in front lets clients
spoof their IP for rate-limit bypass + audit-log evasion. Closes
the v0.9.4 deferral noted in this module's docstring.
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
            # v0.9.5 F-V94-S3 closure (CWE-400): the v0.9.4 LRU
            # evicted the oldest entry on overflow unconditionally.
            # An attacker can spray distinct IPv6 source IPs (the
            # /64 prefix delegates ~18.4 quintillion addresses to
            # a single client) to evict legitimate active clients
            # from the bucket, resetting their rate limit to a
            # fresh burst window. Fix: only evict entries that
            # have been idle long enough that their bucket is
            # already fully refilled (idle > burst-refill-time);
            # newly-active entries with partial buckets are not
            # candidates for eviction. Under heavy spray the
            # bucket cap is exceeded transiently, but legitimate
            # clients keep their state. (The transient overage is
            # bounded by the spray rate; in steady state the
            # eviction predicate catches up.)
            self._evict_idle()
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

    def _evict_idle(self) -> None:
        """Evict idle entries to keep ``len(buckets) <= max_tracked``.

        Only entries idle long enough for the bucket to have refilled
        to its burst capacity are eviction candidates — newly-active
        clients with partial buckets are preserved. Closes the IPv6-
        spray LRU-eviction attack noted in v0.9.5 F-V94-S3.

        If the rate is zero (``rate_per_second == 0``), every entry's
        bucket stays at its initial value and the idle-refill
        threshold is meaningless; in that mode we still evict the
        LRU entry to bound memory, accepting that a spray attack
        could evict legitimate clients (but a zero-rate limiter is
        an operator config error anyway — rate 0 means "no requests
        allowed for anyone", which would already be a deployment
        misuse).
        """
        if len(self._buckets) <= self._max_tracked:
            return
        # Refill-to-full time = (burst tokens) / (rate per second).
        # Below this idle threshold, the bucket is still refilling
        # and the entry represents an active client.
        if self._rate_per_second <= 0:
            # Zero-rate edge case: just LRU-evict to keep the cap.
            while len(self._buckets) > self._max_tracked:
                self._buckets.popitem(last=False)
            return
        refill_to_full = self._burst / self._rate_per_second
        now = time.monotonic()
        # Walk from LRU end forward, evicting entries that have been
        # idle long enough that their bucket is back to full. Stop
        # when we hit an entry that's still active OR we've trimmed
        # back under the cap.
        for client_id in list(self._buckets.keys()):
            if len(self._buckets) <= self._max_tracked:
                return
            entry = self._buckets[client_id]
            idle_seconds = now - entry.last_refill_monotonic
            if idle_seconds >= refill_to_full:
                del self._buckets[client_id]

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
