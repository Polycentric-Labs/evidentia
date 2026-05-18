"""TestClient coverage for /api/conmon/* endpoints (v0.9.1 P1).

CONMON REST router parity with the v0.9.0 CLI surface.
Reuses the project-wide ``api_client`` fixture from conftest.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


class TestListCadences:
    """GET /api/conmon/cadences."""

    def test_list_all_returns_bundled(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 7
        slugs = [c["slug"] for c in data]
        assert "nist-800-53-rev5-ca7" in slugs
        assert "fedramp-conmon-poam" in slugs

    def test_list_filter_by_framework(self, api_client: TestClient) -> None:
        resp = api_client.get(
            "/api/conmon/cadences", params={"framework": "fedramp-rev5-mod"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for item in data:
            assert item["framework"] == "fedramp-rev5-mod"

    def test_list_filter_unknown_framework_returns_empty(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get(
            "/api/conmon/cadences", params={"framework": "nonexistent"}
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_cadence_shape(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences")
        first = resp.json()[0]
        assert "slug" in first
        assert "framework" in first
        assert "activity" in first
        assert "frequency" in first
        assert "description" in first
        assert "citation" in first


class TestGetCadence:
    """GET /api/conmon/cadences/{slug}."""

    def test_get_known_slug(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences/nist-800-53-rev5-ca7")
        assert resp.status_code == 200
        data = resp.json()
        assert data["slug"] == "nist-800-53-rev5-ca7"
        assert data["framework"] == "nist-800-53-rev5"
        assert data["frequency"] == "monthly"

    def test_get_unknown_slug_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/api/conmon/cadences/nonexistent-slug")
        assert resp.status_code == 404


class TestNextDue:
    """POST /api/conmon/next."""

    def test_compute_monthly(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "last_completed": "2026-04-15",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["slug"] == "nist-800-53-rev5-ca7"
        assert data["next_due"] == "2026-05-15"
        assert data["last_completed"] == "2026-04-15"

    def test_compute_annual(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "fedramp-conmon-annual",
                "last_completed": "2025-06-01",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["next_due"] == "2026-06-01"

    def test_unknown_slug_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "no-such-cadence",
                "last_completed": "2026-01-01",
            },
        )
        assert resp.status_code == 404

    def test_last_day_clamping(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/next",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "last_completed": "2026-01-31",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["next_due"] == "2026-02-28"


class TestCheck:
    """POST /api/conmon/check."""

    def test_overdue_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-01-01",
                    }
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["today"] == "2026-05-15"
        assert len(data["overdue"]) == 1
        assert data["overdue"][0]["slug"] == "nist-800-53-rev5-ca7"
        assert data["overdue"][0]["state"] == "overdue"

    def test_due_soon_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-01",
                    }
                ],
                "today": "2026-05-20",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["due_soon"]) == 1
        assert data["due_soon"][0]["state"] == "due_soon"

    def test_current_detection(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-10",
                    }
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["current"]) == 1
        assert data["current"][0]["state"] == "current"

    def test_unknown_slugs_collected(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "unknown-slug-xyz",
                        "last_completed": "2026-01-01",
                    },
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-05-10",
                    },
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "unknown-slug-xyz" in data["unknown_slugs"]
        assert len(data["current"]) == 1

    def test_batch_multiple_cadences(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2026-01-01",
                    },
                    {
                        "slug": "fedramp-conmon-poam",
                        "last_completed": "2026-05-01",
                    },
                    {
                        "slug": "fedramp-conmon-annual",
                        "last_completed": "2025-06-01",
                    },
                ],
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        total = (
            len(data["overdue"])
            + len(data["due_soon"])
            + len(data["current"])
        )
        assert total == 3

    def test_default_today_uses_real_date(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {
                        "slug": "nist-800-53-rev5-ca7",
                        "last_completed": "2020-01-01",
                    }
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["today"] is not None
        assert len(data["overdue"]) == 1

    def test_empty_entries_returns_422(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": []},
        )
        assert resp.status_code == 422

    def test_over_100_entries_returns_422(self, api_client: TestClient) -> None:
        entries = [
            {"slug": "nist-800-53-rev5-ca7", "last_completed": "2026-01-01"}
            for _ in range(101)
        ]
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": entries, "today": "2026-05-15"},
        )
        assert resp.status_code == 422


# ── health (v0.9.3 P1.3) ──────────────────────────────────────────


class TestHealth:
    """POST /api/conmon/health."""

    def test_overall_health_with_overdue(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={
                "state": {
                    "nist-800-53-rev5-ca7": "2025-01-01",
                    "fedramp-conmon-poam": "2026-05-10",
                },
                "today": "2026-05-15",
                "window_days": 14,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_cycles"] == 2
        assert body["total_overdue"] == 1
        assert body["total_current"] == 1
        assert 0.0 < body["overall_health_score"] < 1.0

    def test_framework_filter(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={
                "state": {
                    "nist-800-53-rev5-ca7": "2025-01-01",
                    "fedramp-conmon-poam": "2026-05-10",
                },
                "today": "2026-05-15",
                "framework": "nist-800-53-rev5",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["frameworks"]) == 1
        assert body["frameworks"][0]["framework"] == "nist-800-53-rev5"

    def test_unknown_slugs_collected(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={
                "state": {
                    "nist-800-53-rev5-ca7": "2026-05-10",
                    "no-such-cadence": "2026-05-10",
                },
                "today": "2026-05-15",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "no-such-cadence" in body["unknown_slugs"]
        assert body["total_cycles"] == 1

    def test_default_today_uses_real_date(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={
                "state": {
                    "nist-800-53-rev5-ca7": "2025-01-01",
                },
            },
        )
        assert resp.status_code == 200
        assert resp.json()["today"] is not None

    def test_empty_state_returns_perfect_health(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={"state": {}, "today": "2026-05-15"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_cycles"] == 0
        assert body["overall_health_score"] == 1.0


# ── v0.9.4 P2.1: daemon-status endpoint ─────────────────────────────


class TestDaemonStatusEndpoint:
    """GET /api/conmon/daemon-status reads a sidecar JSON written by
    the daemon after each poll cycle. Configured via the
    EVIDENTIA_CONMON_DAEMON_STATUS_FILE env var."""

    def test_returns_404_when_env_unset(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", raising=False
        )
        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 404
        assert (
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE" in resp.json()["detail"]
        )

    def test_returns_404_when_file_missing(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        status_file = tmp_path / "nonexistent.json"
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file)
        )
        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 404
        assert "missing" in resp.json()["detail"]

    def test_returns_payload_when_file_present(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json as _json

        status_file = tmp_path / "daemon.status.json"
        payload = {
            "started_at": "2026-05-18T12:00:00+00:00",
            "last_poll_at": "2026-05-18T13:00:00+00:00",
            "last_poll_outcome": "success",
            "last_poll_error": None,
            "recognized_cadence_count": 7,
            "poll_interval_seconds": 3600,
            "state_file": "/etc/evidentia/state.yaml",
            "window_days": 14,
            "daemon_uptime_seconds": 3600,
        }
        status_file.write_text(_json.dumps(payload))
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file)
        )

        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["last_poll_outcome"] == "success"
        assert body["recognized_cadence_count"] == 7
        assert body["daemon_uptime_seconds"] == 3600

    def test_returns_404_on_corrupt_json(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Corrupt-file reads return 404 (mid-write tolerance), NOT 500."""
        status_file = tmp_path / "daemon.status.json"
        status_file.write_text("{ not valid json")
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file)
        )
        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 404


class TestDaemonStatusUnitHelpers:
    """write_daemon_status + read_daemon_status round-trip + edge
    cases. Validates the file-format contract independent of HTTP."""

    def test_write_then_read_round_trip(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime

        from evidentia_core.conmon.daemon import (
            read_daemon_status,
            write_daemon_status,
        )

        status_file = tmp_path / "daemon.status.json"
        started = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
        polled = datetime(2026, 5, 18, 13, 30, 0, tzinfo=UTC)
        write_daemon_status(
            status_file,
            started_at=started,
            last_poll_at=polled,
            last_poll_outcome="success",
            last_poll_error=None,
            recognized_cadence_count=5,
            poll_interval_seconds=1800,
            state_file=Path("/etc/evidentia/state.yaml"),
            window_days=14,
        )

        payload = read_daemon_status(status_file)
        assert payload is not None
        assert payload["last_poll_outcome"] == "success"
        assert payload["recognized_cadence_count"] == 5
        assert payload["poll_interval_seconds"] == 1800
        # daemon_uptime_seconds = polled - started = 5400s (90 min)
        assert payload["daemon_uptime_seconds"] == 5400

    def test_read_returns_none_for_missing_file(
        self, tmp_path: Path
    ) -> None:
        from evidentia_core.conmon.daemon import read_daemon_status

        assert read_daemon_status(tmp_path / "missing.json") is None

    def test_atomic_write_uses_tmp_then_replace(
        self, tmp_path: Path
    ) -> None:
        """Verify write goes through .tmp + replace (no half-written
        files visible to a concurrent reader)."""
        from datetime import UTC, datetime

        from evidentia_core.conmon.daemon import write_daemon_status

        status_file = tmp_path / "daemon.status.json"
        now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
        write_daemon_status(
            status_file,
            started_at=now,
            last_poll_at=now,
            last_poll_outcome="failed",
            last_poll_error="ValueError: bad state",
            recognized_cadence_count=0,
            poll_interval_seconds=60,
            state_file=Path("/tmp/x.yaml"),
            window_days=14,
        )
        # No .tmp file left behind.
        assert not (tmp_path / "daemon.status.json.tmp").exists()
        assert status_file.exists()


class TestDaemonHistoryEndpoint:
    """v0.9.5 P2.3: GET /api/conmon/daemon-history reads a rolling
    JSONL history file the daemon appends to after each poll."""

    def test_returns_404_when_env_unset(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv(
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", raising=False
        )
        resp = api_client.get("/api/conmon/daemon-history")
        assert resp.status_code == 404
        assert (
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE"
            in resp.json()["detail"]
        )

    def test_returns_404_when_file_missing(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        history_file = tmp_path / "history.jsonl"
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file)
        )
        resp = api_client.get("/api/conmon/daemon-history")
        assert resp.status_code == 404

    def test_returns_snapshots_when_file_present(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json as _json

        history_file = tmp_path / "history.jsonl"
        # 3 snapshots in chronological order (oldest first).
        snapshots = [
            {
                "last_poll_at": "2026-05-18T10:00:00+00:00",
                "last_poll_outcome": "success",
                "recognized_cadence_count": 7,
            },
            {
                "last_poll_at": "2026-05-18T11:00:00+00:00",
                "last_poll_outcome": "failed",
                "recognized_cadence_count": 7,
            },
            {
                "last_poll_at": "2026-05-18T12:00:00+00:00",
                "last_poll_outcome": "success",
                "recognized_cadence_count": 7,
            },
        ]
        history_file.write_text(
            "\n".join(_json.dumps(s) for s in snapshots) + "\n"
        )
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file)
        )

        resp = api_client.get("/api/conmon/daemon-history?limit=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 3
        assert body["snapshots"][0]["last_poll_outcome"] == "success"
        assert body["snapshots"][1]["last_poll_outcome"] == "failed"
        assert body["snapshots"][2]["last_poll_outcome"] == "success"

    def test_limit_truncates_to_most_recent(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json as _json

        history_file = tmp_path / "history.jsonl"
        snapshots = [
            {"last_poll_at": f"2026-05-18T{h:02d}:00:00+00:00",
             "last_poll_outcome": "success"}
            for h in range(10)
        ]
        history_file.write_text(
            "\n".join(_json.dumps(s) for s in snapshots) + "\n"
        )
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file)
        )

        resp = api_client.get("/api/conmon/daemon-history?limit=3")
        assert resp.status_code == 200
        body = resp.json()
        # Last 3 entries — most recent.
        assert body["count"] == 3
        assert body["snapshots"][-1]["last_poll_at"] == (
            "2026-05-18T09:00:00+00:00"
        )

    def test_corrupt_lines_skipped(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Partial-write tolerance: corrupt lines are skipped, not 500."""
        history_file = tmp_path / "history.jsonl"
        history_file.write_text(
            '{"valid": "line"}\n'
            "{ corrupted line\n"
            '{"another": "valid"}\n'
        )
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file)
        )

        resp = api_client.get("/api/conmon/daemon-history")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 2


class TestDaemonHistoryHelpers:
    """v0.9.5 P2.3: append_daemon_history + read_daemon_history
    round-trip + cap behavior."""

    def test_append_then_read(self, tmp_path: Path) -> None:
        from evidentia_core.conmon.daemon import (
            append_daemon_history,
            read_daemon_history,
        )

        history = tmp_path / "h.jsonl"
        for i in range(3):
            append_daemon_history(history, {"poll": i})
        entries = read_daemon_history(history)
        assert [e["poll"] for e in entries] == [0, 1, 2]

    def test_max_entries_caps_history(self, tmp_path: Path) -> None:
        from evidentia_core.conmon.daemon import (
            append_daemon_history,
            read_daemon_history,
        )

        history = tmp_path / "h.jsonl"
        for i in range(10):
            append_daemon_history(history, {"poll": i}, max_entries=5)
        entries = read_daemon_history(history)
        # Last 5 retained.
        assert [e["poll"] for e in entries] == [5, 6, 7, 8, 9]

    def test_read_returns_empty_for_missing_file(
        self, tmp_path: Path
    ) -> None:
        from evidentia_core.conmon.daemon import read_daemon_history

        assert read_daemon_history(tmp_path / "missing.jsonl") == []


class TestMetricsConmonDaemonGauges:
    """v0.9.5 P2.3: Prometheus exposition includes conmon-daemon
    gauges when EVIDENTIA_CONMON_DAEMON_STATUS_FILE is set + the
    sidecar is parseable."""

    def test_gauges_absent_when_env_unset(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", raising=False
        )
        resp = api_client.get("/api/metrics")
        assert resp.status_code == 200
        # Standard gauges present, conmon-daemon gauges absent.
        assert "evidentia_app_info" in resp.text
        assert "evidentia_conmon_daemon_last_poll_age_seconds" not in (
            resp.text
        )

    def test_gauges_present_when_status_file_readable(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json as _json
        from datetime import UTC, datetime, timedelta

        status_file = tmp_path / "daemon.status.json"
        # 60s ago, success.
        last_poll = datetime.now(tz=UTC) - timedelta(seconds=60)
        payload = {
            "started_at": (last_poll - timedelta(hours=1)).isoformat(),
            "last_poll_at": last_poll.isoformat(),
            "last_poll_outcome": "success",
            "last_poll_error": None,
            "recognized_cadence_count": 7,
            "unknown_cadence_count": 0,
            "poll_interval_seconds": 3600,
            "state_file": "/tmp/state.yaml",
            "window_days": 14,
            "daemon_uptime_seconds": 3600,
        }
        status_file.write_text(_json.dumps(payload))
        monkeypatch.setenv(
            "EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file)
        )

        resp = api_client.get("/api/metrics")
        assert resp.status_code == 200
        assert (
            "evidentia_conmon_daemon_last_poll_age_seconds" in resp.text
        )
        assert "evidentia_conmon_daemon_last_poll_success 1.0" in (
            resp.text
        )
        assert (
            "evidentia_conmon_daemon_recognized_cadence_count 7"
            in resp.text
        )
        assert (
            "evidentia_conmon_daemon_unknown_cadence_count 0" in resp.text
        )
