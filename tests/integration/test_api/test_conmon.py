"""TestClient coverage for /api/conmon/* endpoints (v0.9.1 P1).

CONMON REST router parity with the v0.9.0 CLI surface.
Reuses the project-wide ``api_client`` fixture from conftest.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
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
        resp = api_client.get("/api/conmon/cadences", params={"framework": "fedramp-rev5-mod"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for item in data:
            assert item["framework"] == "fedramp-rev5-mod"

    def test_list_filter_unknown_framework_returns_empty(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences", params={"framework": "nonexistent"})
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

    def test_get_unknown_slug_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/api/conmon/cadences/nonexistent-slug")
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "cadence"
        assert detail["resource_id"] == "nonexistent-slug"


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
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "cadence"

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
        total = len(data["overdue"]) + len(data["due_soon"]) + len(data["current"])
        assert total == 3

    def test_default_today_uses_real_date(self, api_client: TestClient) -> None:
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
        entries = [{"slug": "nist-800-53-rev5-ca7", "last_completed": "2026-01-01"} for _ in range(101)]
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": entries, "today": "2026-05-15"},
        )
        assert resp.status_code == 422


# ── health (v0.9.3 P1.3) ──────────────────────────────────────────


class TestHealth:
    """POST /api/conmon/health."""

    def test_overall_health_with_overdue(self, api_client: TestClient) -> None:
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

    def test_unknown_slugs_collected(self, api_client: TestClient) -> None:
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

    def test_default_today_uses_real_date(self, api_client: TestClient) -> None:
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

    def test_empty_state_returns_perfect_health(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={"state": {}, "today": "2026-05-15"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_cycles"] == 0
        assert body["overall_health_score"] == 1.0


# ── series (v0.13, V13-01: cadence evidence series) ────────────────


def _save_evidence_artifact(
    store: Path,
    collected: datetime,
    slug: str = "pci-dss-11-6-1-weekly",
    source: str = "nessus",
) -> Path:
    from evidentia_core.evidence_store import save_evidence
    from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

    artifact = EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": source,
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": {"cadence_slug": slug},
        }
    )
    return save_evidence(artifact, evidence_store_dir=store)


class TestSeriesEndpoint:
    """POST /api/conmon/series."""

    def test_continuous_then_gapped_after_removal(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from datetime import UTC, timedelta

        store = tmp_path / "evidence"
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))

        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        lineage_dirs = [_save_evidence_artifact(store, start + timedelta(days=7 * i)).parent for i in range(4)]

        resp = api_client.post(
            "/api/conmon/series",
            json={
                "slug": "pci-dss-11-6-1-weekly",
                "since": "2026-06-01",
                "until": "2026-06-22",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["series"]["verdict"] == "continuous"
        assert body["series"]["gaps"] == []
        assert len(body["series"]["observations"]) == 4
        assert "evidence of cadence" in body["description"]

        # Remove the 2026-06-15 observation's lineage -> a gap opens up.
        import shutil

        shutil.rmtree(lineage_dirs[2])

        resp2 = api_client.post(
            "/api/conmon/series",
            json={
                "slug": "pci-dss-11-6-1-weekly",
                "since": "2026-06-01",
                "until": "2026-06-22",
            },
        )
        assert resp2.status_code == 200, resp2.text
        body2 = resp2.json()
        assert body2["series"]["verdict"] == "gapped"
        assert len(body2["series"]["gaps"]) == 1

    def test_unknown_slug_returns_404(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        resp = api_client.post(
            "/api/conmon/series",
            json={"slug": "no-such-cadence"},
        )
        assert resp.status_code == 404, resp.text
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "cadence"
        assert detail["resource_id"] == "no-such-cadence"

    def test_bad_window_returns_400(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        resp = api_client.post(
            "/api/conmon/series",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "since": "2026-06-15",
                "until": "2026-06-01",
            },
        )
        assert resp.status_code == 400, resp.text
        detail = resp.json()["detail"]
        assert detail["error"] == "invalid_window"

    def test_insufficient_verdict_on_empty_store(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        resp = api_client.post(
            "/api/conmon/series",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "since": "2026-06-01",
                "until": "2026-06-15",
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["series"]["verdict"] == "insufficient"

    def test_lookback_days_out_of_range_returns_422(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(tmp_path / "evidence"))
        resp = api_client.post(
            "/api/conmon/series",
            json={"slug": "nist-800-53-rev5-ca7", "lookback_days": 0},
        )
        assert resp.status_code == 422


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
        monkeypatch.delenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", raising=False)
        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert "EVIDENTIA_CONMON_DAEMON_STATUS_FILE" in detail["message"]

    def test_returns_404_when_file_missing(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        status_file = tmp_path / "nonexistent.json"
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file))
        resp = api_client.get("/api/conmon/daemon-status")
        assert resp.status_code == 404
        assert "missing" in resp.json()["detail"]["message"]

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
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file))

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
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file))
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

    def test_read_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        from evidentia_core.conmon.daemon import read_daemon_status

        assert read_daemon_status(tmp_path / "missing.json") is None

    def test_atomic_write_uses_tmp_then_replace(self, tmp_path: Path) -> None:
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
        monkeypatch.delenv("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", raising=False)
        resp = api_client.get("/api/conmon/daemon-history")
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert "EVIDENTIA_CONMON_DAEMON_HISTORY_FILE" in detail["message"]

    def test_returns_404_when_file_missing(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        history_file = tmp_path / "history.jsonl"
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file))
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
        history_file.write_text("\n".join(_json.dumps(s) for s in snapshots) + "\n")
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file))

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
            {"last_poll_at": f"2026-05-18T{h:02d}:00:00+00:00", "last_poll_outcome": "success"} for h in range(10)
        ]
        history_file.write_text("\n".join(_json.dumps(s) for s in snapshots) + "\n")
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file))

        resp = api_client.get("/api/conmon/daemon-history?limit=3")
        assert resp.status_code == 200
        body = resp.json()
        # Last 3 entries — most recent.
        assert body["count"] == 3
        assert body["snapshots"][-1]["last_poll_at"] == ("2026-05-18T09:00:00+00:00")

    def test_corrupt_lines_skipped(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Partial-write tolerance: corrupt lines are skipped, not 500."""
        history_file = tmp_path / "history.jsonl"
        history_file.write_text('{"valid": "line"}\n{ corrupted line\n{"another": "valid"}\n')
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_HISTORY_FILE", str(history_file))

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

    def test_read_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
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
        monkeypatch.delenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", raising=False)
        resp = api_client.get("/api/metrics")
        assert resp.status_code == 200
        # Standard gauges present, conmon-daemon gauges absent.
        assert "evidentia_app_info" in resp.text
        assert "evidentia_conmon_daemon_last_poll_age_seconds" not in (resp.text)

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
        monkeypatch.setenv("EVIDENTIA_CONMON_DAEMON_STATUS_FILE", str(status_file))

        resp = api_client.get("/api/metrics")
        assert resp.status_code == 200
        assert "evidentia_conmon_daemon_last_poll_age_seconds" in resp.text
        assert "evidentia_conmon_daemon_last_poll_success 1.0" in (resp.text)
        assert "evidentia_conmon_daemon_recognized_cadence_count 7" in resp.text
        assert "evidentia_conmon_daemon_unknown_cadence_count 0" in resp.text


# ── v0.10.12: mark-completed endpoint ───────────────────────────────


def _read_state_file(path: Path) -> dict[str, str]:
    """Parse the YAML conmon state file into a {slug: iso-date} dict."""
    import yaml as _yaml

    raw = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in raw.items()}


class TestMarkCompleted:
    """POST /api/conmon/mark-completed records a cycle completion into
    the YAML state file the server exposes via
    EVIDENTIA_CONMON_STATE_FILE. Mirrors the ``evidentia conmon
    mark-completed`` CLI verb (state mutation; require_role("write"))."""

    def test_records_first_completion(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_file = tmp_path / "conmon-state.yaml"
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(state_file))

        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={
                "slug": "nist-800-53-rev5-ca7",
                "when": "2026-05-15",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["slug"] == "nist-800-53-rev5-ca7"
        assert body["new_last_completed"] == "2026-05-15"
        # First mark → no previous value.
        assert body["previous_last_completed"] is None
        # State change persisted to the YAML state file.
        assert _read_state_file(state_file) == {"nist-800-53-rev5-ca7": "2026-05-15"}

    def test_records_subsequent_completion_returns_previous(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_file = tmp_path / "conmon-state.yaml"
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(state_file))

        api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7", "when": "2026-04-15"},
        )
        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7", "when": "2026-05-15"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["previous_last_completed"] == "2026-04-15"
        assert body["new_last_completed"] == "2026-05-15"
        assert _read_state_file(state_file) == {"nist-800-53-rev5-ca7": "2026-05-15"}

    def test_unknown_slug_returns_400(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        state_file = tmp_path / "conmon-state.yaml"
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(state_file))

        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "no-such-cadence", "when": "2026-05-15"},
        )
        assert resp.status_code == 400, resp.text
        detail = resp.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert detail["field"] == "slug"
        # State file must not be created for a rejected mark.
        assert not state_file.exists()

    def test_missing_when_returns_422(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Pydantic body validation: 'when' is required.
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(tmp_path / "s.yaml"))
        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7"},
        )
        assert resp.status_code == 422

    def test_malformed_when_returns_422(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(tmp_path / "s.yaml"))
        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7", "when": "not-a-date"},
        )
        assert resp.status_code == 422

    def test_returns_400_when_state_file_env_unset(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_CONMON_STATE_FILE", raising=False)
        resp = api_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7", "when": "2026-05-15"},
        )
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["error"] == "feature_unavailable"
        assert "EVIDENTIA_CONMON_STATE_FILE" in detail["message"]


# ── v0.10.12: dedup-list endpoint ───────────────────────────────────


class TestDedupList:
    """GET /api/conmon/dedup-list reads the alert-dedup JSON file the
    daemon writes (exposed via EVIDENTIA_CONMON_ALERT_DEDUP_FILE).
    Mirrors the ``evidentia conmon dedup-list`` CLI verb (open read)."""

    def _write_dedup(self, path: Path) -> None:
        import json as _json

        path.write_text(
            _json.dumps(
                {
                    "nist-800-53-rev5-ca7|overdue": ("2026-05-16T03:00:00+00:00"),
                    "fedramp-conmon-poam|due_soon": ("2026-05-15T09:00:00+00:00"),
                }
            )
        )

    def test_returns_deduped_entries(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        dedup_file = tmp_path / "dedup.json"
        self._write_dedup(dedup_file)
        monkeypatch.setenv("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", str(dedup_file))

        resp = api_client.get("/api/conmon/dedup-list")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["count"] == 2
        entries = body["entries"]
        # Sorted by last_dispatched_at descending (newest first).
        assert entries[0]["cadence_slug"] == "nist-800-53-rev5-ca7"
        assert entries[0]["state"] == "overdue"
        assert entries[0]["last_dispatched_at"] == ("2026-05-16T03:00:00+00:00")
        assert "suppression_remaining_minutes" in entries[0]
        assert entries[1]["cadence_slug"] == "fedramp-conmon-poam"
        assert entries[1]["state"] == "due_soon"

    def test_slug_filter(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        dedup_file = tmp_path / "dedup.json"
        self._write_dedup(dedup_file)
        monkeypatch.setenv("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", str(dedup_file))

        resp = api_client.get(
            "/api/conmon/dedup-list",
            params={"slug": "nist-800-53-rev5-ca7"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["count"] == 1
        assert body["entries"][0]["cadence_slug"] == "nist-800-53-rev5-ca7"

    def test_missing_file_returns_empty(
        self,
        api_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Missing dedup file yields an empty result (CLI parity: the
        # verb tolerates a not-yet-created file).
        dedup_file = tmp_path / "never-written.json"
        monkeypatch.setenv("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", str(dedup_file))
        resp = api_client.get("/api/conmon/dedup-list")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 0
        assert body["entries"] == []

    def test_returns_400_when_dedup_file_env_unset(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", raising=False)
        resp = api_client.get("/api/conmon/dedup-list")
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["error"] == "feature_unavailable"
        assert "EVIDENTIA_CONMON_ALERT_DEDUP_FILE" in detail["message"]


# ── v0.10.12: RBAC enforcement (proves the write gate bites) ────────


@pytest.fixture
def conmon_readonly_client(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    """A conmon TestClient under a restrictive read-only RBAC policy.

    Installs a deny-by-default policy whose ``default_role`` is
    ``reader``. An anonymous request (identity None) resolves to that
    role, so reads pass while ``require_role("write")`` gates deny —
    proving the mark-completed gate actually bites (it is inert under
    the permissive DEFAULT_POLICY the other tests run with).
    Mirrors test_governance_router.gov_readonly_client.
    """
    from evidentia_api.routers import conmon as conmon_router
    from evidentia_core.rbac import RBACPolicy, Role

    app = FastAPI()
    app.include_router(conmon_router.router, prefix="/api")
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)
    with TestClient(app) as client:
        yield client


class TestConmonRBAC:
    """Under a read-only policy the write gate must deny, reads pass."""

    def test_anonymous_mark_completed_denied_403(
        self,
        conmon_readonly_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_CONMON_STATE_FILE", str(tmp_path / "state.yaml"))
        resp = conmon_readonly_client.post(
            "/api/conmon/mark-completed",
            json={"slug": "nist-800-53-rev5-ca7", "when": "2026-05-15"},
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_dedup_list_allowed_200(
        self,
        conmon_readonly_client: TestClient,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # dedup-list carries no require_role gate (reads are open), so
        # it returns 200 even under the read-only policy.
        dedup_file = tmp_path / "dedup.json"
        monkeypatch.setenv("EVIDENTIA_CONMON_ALERT_DEDUP_FILE", str(dedup_file))
        resp = conmon_readonly_client.get("/api/conmon/dedup-list")
        assert resp.status_code == 200, resp.text
        assert resp.json()["count"] == 0


# ── 2026-07-06 error-shape convergence: OpenAPI error docs ──────────


class TestConmonOpenApiErrorDocs:
    """Every deliberate 4xx the conmon router raises is documented on
    its OpenAPI operation (schemathesis undocumented-status noise →
    contract)."""

    def test_conmon_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            ("/api/conmon/cadences/{slug}", "get", ["404"]),
            ("/api/conmon/next", "post", ["404"]),
            ("/api/conmon/series", "post", ["400", "404"]),
            ("/api/conmon/daemon-status", "get", ["404"]),
            ("/api/conmon/daemon-history", "get", ["404"]),
            ("/api/conmon/mark-completed", "post", ["400", "403"]),
            ("/api/conmon/dedup-list", "get", ["400"]),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"
