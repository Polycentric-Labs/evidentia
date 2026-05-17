"""Unit tests for the v0.9.4 Step 5.A F-V94-Q1 closure —
idempotency-store TTL + max-entries cap pruning.

The on-disk idempotency-store grew unbounded in initial v0.9.4
(every register POST with X-Idempotency-Key appended without
pruning). _prune_idempotency_store now applies a 24h TTL + 10k
FIFO cap. These tests lock the prune-helper contract independent
of the FastAPI integration tests in test_ai_gov.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from evidentia_api.routers.ai_gov import (
    IDEMPOTENCY_MAX_ENTRIES,
    IDEMPOTENCY_TTL_HOURS,
    _prune_idempotency_store,
)


def _entry(body_hash: str, system_id: str, recorded_at: datetime) -> dict:
    return {
        "body_hash": body_hash,
        "system_id": system_id,
        "recorded_at": recorded_at.isoformat(),
    }


class TestPrune:
    def test_empty_store_returns_empty(self) -> None:
        assert _prune_idempotency_store({}) == {}

    def test_ttl_drops_expired_entries(self) -> None:
        now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
        fresh_ts = now - timedelta(hours=IDEMPOTENCY_TTL_HOURS - 1)
        stale_ts = now - timedelta(hours=IDEMPOTENCY_TTL_HOURS + 1)
        store = {
            "fresh-key": _entry("hash-fresh", "uuid-fresh", fresh_ts),
            "stale-key": _entry("hash-stale", "uuid-stale", stale_ts),
        }
        pruned = _prune_idempotency_store(store, now=now)
        assert "fresh-key" in pruned
        assert "stale-key" not in pruned

    def test_max_entries_cap_fifo_evicts_oldest(self) -> None:
        """When store has more than IDEMPOTENCY_MAX_ENTRIES + 1
        fresh entries, the oldest is FIFO-evicted."""
        now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
        # Build IDEMPOTENCY_MAX_ENTRIES + 2 fresh entries with
        # monotonically-increasing recorded_at timestamps so the
        # FIFO order is deterministic.
        store = {}
        for i in range(IDEMPOTENCY_MAX_ENTRIES + 2):
            # All within TTL — only the cap should trigger eviction.
            ts = now - timedelta(seconds=IDEMPOTENCY_MAX_ENTRIES + 2 - i)
            store[f"key-{i:05d}"] = _entry(
                f"hash-{i}", f"uuid-{i:05d}", ts
            )
        pruned = _prune_idempotency_store(store, now=now)
        assert len(pruned) == IDEMPOTENCY_MAX_ENTRIES
        # Oldest 2 entries evicted (key-00000 + key-00001).
        assert "key-00000" not in pruned
        assert "key-00001" not in pruned
        # Newest entries retained.
        assert f"key-{IDEMPOTENCY_MAX_ENTRIES + 1:05d}" in pruned

    def test_legacy_entries_without_recorded_at_evict_first(self) -> None:
        """Entries without recorded_at (legacy from pre-Q1 store)
        treated as epoch — drop on TTL check."""
        now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
        legacy_entry = {
            "body_hash": "hash-legacy",
            "system_id": "uuid-legacy",
            "recorded_at": "1970-01-01T00:00:00+00:00",
        }
        fresh = _entry(
            "hash-fresh",
            "uuid-fresh",
            now - timedelta(hours=1),
        )
        store = {"legacy-key": legacy_entry, "fresh-key": fresh}
        pruned = _prune_idempotency_store(store, now=now)
        assert "legacy-key" not in pruned
        assert "fresh-key" in pruned
