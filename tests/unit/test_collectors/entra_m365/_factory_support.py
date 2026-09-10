"""Deterministic synthetic collection clock."""

from datetime import UTC, datetime

NOW = datetime(2026, 9, 10, tzinfo=UTC)


class Clock:
    value = 0.0
    wall = NOW

    def monotonic(self):
        return self.value

    def utc(self):
        return self.wall

    def sleep(self, seconds):
        self.value += seconds
