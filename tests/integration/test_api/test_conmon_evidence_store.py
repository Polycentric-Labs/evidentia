"""`use_evidence_store` on POST /api/conmon/check and /api/conmon/health (v0.13, batch 5).

The server reads its own configured store (``EVIDENTIA_EVIDENCE_STORE_DIR``);
the request never carries a path.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidentia_core.conmon import CADENCE_SLUG_METADATA_KEY
from evidentia_core.evidence_store import save_evidence
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from fastapi.testclient import TestClient

WEEKLY = "pci-dss-11-6-1-weekly"
MONTHLY = "nist-800-53-rev5-ca7"
START = datetime(2026, 6, 1, 12, tzinfo=UTC)


@pytest.fixture()
def weekly_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "store"
    for offset in range(8):
        artifact = EvidenceArtifact.model_validate(
            {
                "title": f"scan {offset}",
                "evidence_type": EvidenceType.TEST_RESULT,
                "source_system": "nessus",
                "collected_by": "test-runner@example.com",
                "collected_at": START + timedelta(days=7 * offset),
                "content": {"ok": True},
                "metadata": {CADENCE_SLUG_METADATA_KEY: WEEKLY},
            }
        )
        save_evidence(artifact, evidence_store_dir=store)
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))
    return store


class TestCheck:
    def test_store_supplies_missing_anchors_and_series(self, api_client: TestClient, weekly_store: Path) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": [], "use_evidence_store": True, "today": "2026-07-25"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        rows = {r["slug"]: r for r in body["overdue"] + body["due_soon"] + body["current"]}
        assert rows[WEEKLY]["last_completed"] == "2026-07-20"
        assert rows[WEEKLY]["series"] == "gapped"

    def test_entries_win_over_the_store(self, api_client: TestClient, weekly_store: Path) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={
                "entries": [
                    {"slug": WEEKLY, "last_completed": "2026-05-01"},
                    {"slug": MONTHLY, "last_completed": "2026-07-10"},
                ],
                "use_evidence_store": True,
                "today": "2026-07-25",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        rows = {r["slug"]: r for r in body["overdue"] + body["due_soon"] + body["current"]}
        assert rows[WEEKLY]["last_completed"] == "2026-05-01"
        assert rows[MONTHLY]["series"] == "insufficient"

    def test_series_is_null_without_the_store(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/api/conmon/check",
            json={"entries": [{"slug": WEEKLY, "last_completed": "2026-07-20"}], "today": "2026-07-25"},
        )
        assert resp.status_code == 200, resp.text
        rows = resp.json()["due_soon"]
        assert rows and rows[0]["series"] is None

    def test_empty_entries_need_the_store(self, api_client: TestClient) -> None:
        resp = api_client.post("/api/conmon/check", json={"entries": []})
        assert resp.status_code == 422


class TestHealth:
    def test_store_merged_into_state(self, api_client: TestClient, weekly_store: Path) -> None:
        resp = api_client.post(
            "/api/conmon/health",
            json={"state": {MONTHLY: "2026-07-10"}, "use_evidence_store": True, "today": "2026-07-25"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["total_cycles"] == 2

    def test_store_ignored_by_default(self, api_client: TestClient, weekly_store: Path) -> None:
        resp = api_client.post("/api/conmon/health", json={"state": {MONTHLY: "2026-07-10"}, "today": "2026-07-25"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["total_cycles"] == 1
