"""TestClient coverage for the read-only ``POST /api/oscal/verify`` endpoint.

Surfaces the CLI-only ``evidentia oscal verify`` integrity check as a
GUI-backing REST endpoint. The endpoint VERIFIES an OSCAL Assessment
Result supplied as inline ``content`` (a JSON string, NOT a server path —
so there is no arbitrary-file-read surface) and reports the structured
outcome: back-matter SHA-256 digests valid? GPG/Sigstore signature
valid? per-check detail. SIGNING stays CLI-only — this endpoint never
signs.

Hermetic: a LOCAL ``FastAPI()`` app includes ONLY the oscal router under
``prefix="/api"`` (the router is NOT registered in
``evidentia_api.app.create_app``, so we cannot reuse the project-wide
``api_client`` fixture). No real Rekor/network is ever hit — the valid /
tampered fixtures are digest-only (no ``.sigstore.json`` on disk) and
the offline test forces ``offline_mode()`` so the Sigstore/Rekor leg is
reported skipped rather than attempted.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator

import pytest
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import SecurityFinding
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_core.network_guard import offline_mode, set_offline
from evidentia_core.oscal.exporter import gap_report_to_oscal_ar
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def oscal_client() -> Iterator[TestClient]:
    """A TestClient over a local app holding ONLY the oscal router.

    The endpoint is read-only + stateless (it verifies posted content),
    so no store isolation is needed. We still reset offline-mode around
    each test so a forced-offline test cannot leak into the next one.
    """
    set_offline(False)
    from evidentia_api.routers import oscal as oscal_router

    app = FastAPI()
    app.include_router(oscal_router.router, prefix="/api")
    try:
        with TestClient(app) as client:
            yield client
    finally:
        set_offline(False)


# ── fixtures: AR document builders ─────────────────────────────────


def _make_gap(control_id: str = "AC-2") -> ControlGap:
    return ControlGap(
        framework="nist-800-53-mod",
        control_id=control_id,
        control_title=f"{control_id} title",
        control_description="desc",
        gap_severity=GapSeverity.HIGH,
        implementation_status="missing",
        gap_description="not implemented",
        remediation_guidance="implement",
        implementation_effort=ImplementationEffort.MEDIUM,
        priority_score=1.0,
        status=GapStatus.OPEN,
    )


def _make_finding() -> SecurityFinding:
    return SecurityFinding(
        id="22222222-2222-2222-2222-222222222222",
        title="Privileged account lacks MFA",
        description="Root account missing MFA enforcement.",
        severity=Severity.HIGH,
        source_system="aws-config",
        control_ids=["AC-2"],
    )


def _make_report() -> GapAnalysisReport:
    gap = _make_gap("AC-2")
    return GapAnalysisReport(
        organization="TestOrg",
        frameworks_analyzed=["nist-800-53-mod"],
        total_controls_required=1,
        total_controls_in_inventory=0,
        total_gaps=1,
        critical_gaps=0,
        high_gaps=1,
        medium_gaps=0,
        low_gaps=0,
        informational_gaps=0,
        coverage_percentage=0.0,
        gaps=[gap],
        efficiency_opportunities=[],
        prioritized_roadmap=[gap.id],
        inventory_source="test.yaml",
    )


def _valid_ar_doc() -> dict:
    """A clean AR with one hashed back-matter evidence resource."""
    return gap_report_to_oscal_ar(_make_report(), findings=[_make_finding()])


def _tampered_ar_doc() -> dict:
    """A valid AR whose embedded evidence payload was rewritten but the
    stored hash left intact — the classic chain-of-custody attack the
    digest check is meant to detect."""
    doc = _valid_ar_doc()
    resource = doc["assessment-results"]["back-matter"]["resources"][0]
    resource["base64"]["value"] = base64.b64encode(
        b'{"malicious": "payload"}'
    ).decode("ascii")
    return doc


# ── POST /api/oscal/verify — valid AR ──────────────────────────────


class TestVerifyValidAR:
    def test_valid_ar_digests_pass(self, oscal_client: TestClient) -> None:
        r = oscal_client.post(
            "/api/oscal/verify",
            json={"content": json.dumps(_valid_ar_doc())},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["overall_valid"] is True
        assert body["digests_valid"] is True
        # One embedded evidence resource → one digest check, valid.
        assert len(body["digest_checks"]) == 1
        assert body["digest_checks"][0]["valid"] is True
        # No signature artifacts supplied → not checked (None).
        assert body["signature_valid"] is None
        assert body["sigstore_signature_valid"] is None

    def test_response_does_not_leak_temp_path(
        self, oscal_client: TestClient
    ) -> None:
        """G-9: the structured result must not echo the server-side temp
        file path back to the client (no filesystem-path leak)."""
        r = oscal_client.post(
            "/api/oscal/verify",
            json={"content": json.dumps(_valid_ar_doc())},
        )
        assert r.status_code == 200, r.text
        blob = r.text
        # The temp filename pattern + common temp roots must be absent.
        assert ".oscal-ar.json" not in blob
        assert "/tmp" not in blob
        assert "Temp" not in blob
        assert "AppData" not in blob


# ── POST /api/oscal/verify — tampered AR ───────────────────────────


class TestVerifyTamperedAR:
    def test_tampered_ar_reports_invalid_but_http_200(
        self, oscal_client: TestClient
    ) -> None:
        """A tampered AR is a NEGATIVE verdict, not a server error: the
        verification ran successfully and concluded the document is bad,
        so the HTTP status stays 200 and the body carries the failure."""
        r = oscal_client.post(
            "/api/oscal/verify",
            json={"content": json.dumps(_tampered_ar_doc())},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["overall_valid"] is False
        assert body["digests_valid"] is False
        assert body["digest_checks"][0]["valid"] is False
        assert (
            body["digest_checks"][0]["expected_digest"]
            != body["digest_checks"][0]["actual_digest"]
        )


# ── POST /api/oscal/verify — bad input ─────────────────────────────


class TestVerifyBadInput:
    def test_unparseable_content_returns_400(
        self, oscal_client: TestClient
    ) -> None:
        r = oscal_client.post(
            "/api/oscal/verify",
            json={"content": "this is not json {{{"},
        )
        assert r.status_code == 400, r.text
        # Detail is a string; must not leak the temp path.
        detail = r.json()["detail"]
        assert isinstance(detail, str)
        assert ".oscal-ar.json" not in detail
        assert "/tmp" not in detail
        assert "AppData" not in detail

    def test_missing_content_field_returns_422(
        self, oscal_client: TestClient
    ) -> None:
        """Pydantic body validation (no ``content``) → 422, not 400."""
        r = oscal_client.post("/api/oscal/verify", json={})
        assert r.status_code == 422

    def test_only_one_identity_field_returns_400(
        self, oscal_client: TestClient
    ) -> None:
        """Both-or-neither (cosign model, F-V109-1): supplying exactly
        one of expected_sigstore_identity / _issuer is a usage error."""
        r = oscal_client.post(
            "/api/oscal/verify",
            json={
                "content": json.dumps(_valid_ar_doc()),
                "expected_sigstore_identity": "ci@example.com",
            },
        )
        assert r.status_code == 400, r.text
        assert isinstance(r.json()["detail"], str)


# ── POST /api/oscal/verify — offline mode ──────────────────────────


class TestVerifyOffline:
    def test_offline_reports_rekor_skipped(
        self, oscal_client: TestClient
    ) -> None:
        """In offline/air-gap mode the Sigstore/Rekor (outbound network)
        leg is skipped + clearly reported, while the digest + local-GPG
        checks still run. Digests on a clean AR still pass."""
        with offline_mode():
            r = oscal_client.post(
                "/api/oscal/verify",
                json={"content": json.dumps(_valid_ar_doc())},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sigstore_checked"] is False
        assert body["offline"] is True
        # Reason mentions offline so a GUI can render "skipped (offline)".
        assert "offline" in body["sigstore_status"].lower()
        # Digest verification still ran + passed offline.
        assert body["digests_valid"] is True
        assert body["overall_valid"] is True
