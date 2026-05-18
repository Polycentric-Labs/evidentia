"""Unit tests for evidentia_api.rate_limit (v0.9.4 P1.3)."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from evidentia_api.rate_limit import TokenBucketRateLimiter


class TestConstructorValidation:
    def test_rejects_negative_rate(self) -> None:
        with pytest.raises(ValueError, match="rate_per_minute"):
            TokenBucketRateLimiter(rate_per_minute=-1)

    def test_rejects_zero_burst(self) -> None:
        with pytest.raises(ValueError, match="burst"):
            TokenBucketRateLimiter(burst=0)

    def test_rejects_zero_max_tracked(self) -> None:
        with pytest.raises(ValueError, match="max_tracked_clients"):
            TokenBucketRateLimiter(max_tracked_clients=0)


class TestTokenConsumption:
    def test_first_check_allowed(self) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=10)
        assert limiter.check("client-1") is True

    def test_burst_capacity_then_throttle(self) -> None:
        """Burst of 5: 5 requests allowed, 6th throttled (no refill
        time has elapsed)."""
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=5)
        # Freeze time so refill doesn't add tokens between calls.
        with patch("evidentia_api.rate_limit.time.monotonic", return_value=0.0):
            for _ in range(5):
                assert limiter.check("client-1") is True
            assert limiter.check("client-1") is False

    def test_refill_after_elapsed_time(self) -> None:
        """At 60/min (1/sec) rate: drain burst, advance time 2s,
        should have ~2 tokens back."""
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=5)
        with patch("evidentia_api.rate_limit.time.monotonic") as mock_time:
            mock_time.return_value = 0.0
            for _ in range(5):
                limiter.check("client-1")
            assert limiter.check("client-1") is False  # drained

            mock_time.return_value = 2.0  # +2s elapsed
            # Should have 2 tokens accrued at 1/sec.
            assert limiter.check("client-1") is True
            assert limiter.check("client-1") is True
            assert limiter.check("client-1") is False

    def test_per_client_isolation(self) -> None:
        """Two clients have independent buckets — exhausting one
        doesn't affect the other."""
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=3)
        with patch("evidentia_api.rate_limit.time.monotonic", return_value=0.0):
            for _ in range(3):
                assert limiter.check("client-A") is True
            assert limiter.check("client-A") is False
            # Different client: full bucket.
            assert limiter.check("client-B") is True
            assert limiter.check("client-B") is True
            assert limiter.check("client-B") is True
            assert limiter.check("client-B") is False


class TestLRUEviction:
    def test_lru_eviction_at_max_tracked_after_idle(self) -> None:
        """v0.9.5 F-V94-S3 closure: eviction is idle-aware. The LRU
        entry is evicted ONLY when its bucket has had time to refill
        to the burst capacity (idle_seconds >= refill_to_full).
        Entries that recently consumed tokens are NOT evictable
        even when the cap is exceeded — this defeats the IPv6-spray
        LRU-eviction attack."""
        # rate=60/min=1/sec, burst=2 → refill-to-full = 2 seconds.
        limiter = TokenBucketRateLimiter(
            rate_per_minute=60, burst=2, max_tracked_clients=3
        )
        clock = {"now": 0.0}
        with patch(
            "evidentia_api.rate_limit.time.monotonic",
            side_effect=lambda: clock["now"],
        ):
            # Fill 3 clients, each drains burst at t=0.
            for client in ("A", "B", "C"):
                limiter.check(client)
                limiter.check(client)
                assert limiter.check(client) is False
            assert limiter.tracked_client_count == 3

            # Advance time past the refill window so A/B/C are
            # eligible for eviction (their buckets have refilled).
            clock["now"] = 3.0

            # 4th client at t=3 triggers idle-aware eviction (A
            # has been idle 3s ≥ refill-to-full 2s).
            limiter.check("D")
            assert limiter.tracked_client_count == 3
            # A was evicted → fresh bucket on next check.
            assert limiter.check("A") is True

    def test_lru_eviction_skipped_under_spray(self) -> None:
        """v0.9.5 F-V94-S3: the spray-protection guarantee. When all
        existing entries are active (their buckets haven't had time
        to refill), a new entry does NOT evict them — transient
        overage above max_tracked is accepted so the limiter
        preserves the active clients' rate-limit state."""
        limiter = TokenBucketRateLimiter(
            rate_per_minute=60, burst=2, max_tracked_clients=3
        )
        with patch(
            "evidentia_api.rate_limit.time.monotonic", return_value=0.0
        ):
            # Fill 3 clients at t=0.
            for client in ("A", "B", "C"):
                limiter.check(client)
            assert limiter.tracked_client_count == 3

            # 4th client at t=0 → no entries are evictable
            # (idle_seconds=0 < refill-to-full=2). The limiter
            # accepts the transient overage.
            limiter.check("attacker-spray-1")
            assert limiter.tracked_client_count == 4

            # A's state is preserved — not evicted.
            assert limiter.check("A") is True  # consumes 2nd token


class TestReset:
    def test_reset_clears_all_buckets(self) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=1)
        with patch("evidentia_api.rate_limit.time.monotonic", return_value=0.0):
            limiter.check("client-1")
            assert limiter.check("client-1") is False  # drained
            limiter.reset()
            assert limiter.tracked_client_count == 0
            # Fresh bucket after reset.
            assert limiter.check("client-1") is True


class TestRealTimeSmoke:
    """Single un-mocked test verifying the real time.monotonic path
    actually works (not just the mocked path). Slow but cheap."""

    def test_real_time_path(self) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=600, burst=3)
        # Burst of 3, rate of 10/sec.
        assert limiter.check("real") is True
        assert limiter.check("real") is True
        assert limiter.check("real") is True
        assert limiter.check("real") is False
        # Wait long enough to accrue at least one token.
        time.sleep(0.15)
        assert limiter.check("real") is True
