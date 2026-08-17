"""Differential contracts for the explicit-root stored-report router."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from evidentia_api import __version__
from evidentia_api.app import create_app
from evidentia_api.auth_middleware import AuthProviderMiddleware
from evidentia_api.errors import body_parse_error_handler
from evidentia_api.rate_limit import RateLimitMiddleware
from evidentia_api.routers import gaps
from evidentia_core.gap_store import GapReportRepository, save_report
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.plugins.auth.local_token import LocalTokenAuthProvider
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from httpx import Response
from starlette.exceptions import HTTPException as StarletteHTTPException


def _report(organization: str) -> GapAnalysisReport:
    return GapAnalysisReport(
        organization=organization,
        frameworks_analyzed=["nist-800-53-mod"],
        total_controls_required=1,
        total_controls_in_inventory=1,
        total_gaps=0,
        critical_gaps=0,
        high_gaps=0,
        medium_gaps=0,
        low_gaps=0,
        informational_gaps=0,
        coverage_percentage=100.0,
        gaps=[],
        efficiency_opportunities=[],
        prioritized_roadmap=[],
        inventory_source="same-inventory.yaml",
    )


def _stored_report_router_factory() -> Any:
    factory = getattr(gaps, "create_stored_report_read_router", None)
    assert factory is not None, (
        "create_stored_report_read_router must bind a repository at "
        "router construction"
    )
    return factory


def _explicit_app(
    repository: GapReportRepository,
    *,
    auth_provider: LocalTokenAuthProvider | None = None,
) -> FastAPI:
    """Build a narrow test host with the public route middleware stack."""
    app = FastAPI(
        title="Evidentia API",
        description=(
            "REST API for the Evidentia GRC tool. All endpoints mirror "
            "CLI capabilities. Binds to 127.0.0.1 by default for localhost "
            "web-UI use."
        ),
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.add_exception_handler(
        StarletteHTTPException,
        body_parse_error_handler,
    )
    app.state.auth_provider = auth_provider
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    app.add_middleware(AuthProviderMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.include_router(
        _stored_report_router_factory()(repository),
        prefix="/api",
        tags=["gaps"],
    )
    return app


def _assert_wire_equivalent(
    baseline: Response,
    candidate: Response,
) -> None:
    assert candidate.status_code == baseline.status_code
    assert candidate.content == baseline.content
    for header in ("content-type", "content-length", "www-authenticate"):
        assert candidate.headers.get(header) == baseline.headers.get(header)


def test_explicit_router_reads_only_its_bound_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient environment changes must not redirect the explicit router."""
    ambient_root = tmp_path / "ambient"
    bound_root = tmp_path / "bound"
    changed_ambient_root = tmp_path / "changed-ambient"
    ambient_path = save_report(
        _report("Ambient Sentinel"),
        gap_store_dir=ambient_root,
    )
    bound_path = save_report(
        _report("Bound Sentinel"),
        gap_store_dir=bound_root,
    )
    changed_path = save_report(
        _report("Changed Ambient Sentinel"),
        gap_store_dir=changed_ambient_root,
    )
    assert ambient_path.stem == bound_path.stem == changed_path.stem

    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(ambient_root))
    legacy_client = TestClient(create_app())
    explicit_client = TestClient(
        _explicit_app(GapReportRepository(bound_root))
    )

    assert (
        legacy_client.get(
            f"/api/gap/reports/{ambient_path.stem}"
        ).json()["organization"]
        == "Ambient Sentinel"
    )
    assert (
        explicit_client.get(
            f"/api/gap/reports/{bound_path.stem}"
        ).json()["organization"]
        == "Bound Sentinel"
    )

    monkeypatch.setenv(
        "EVIDENTIA_GAP_STORE_DIR",
        str(changed_ambient_root),
    )
    assert (
        legacy_client.get(
            f"/api/gap/reports/{changed_path.stem}"
        ).json()["organization"]
        == "Changed Ambient Sentinel"
    )
    assert (
        explicit_client.get(
            f"/api/gap/reports/{bound_path.stem}"
        ).json()["organization"]
        == "Bound Sentinel"
    )


def test_explicit_router_success_wire_contract_matches_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repository binding must not change a successful public response."""
    legacy_root = tmp_path / "legacy"
    explicit_root = tmp_path / "explicit"
    report = _report("Same Sentinel")
    legacy_path = save_report(
        report,
        gap_store_dir=legacy_root,
    )
    explicit_path = save_report(
        report,
        gap_store_dir=explicit_root,
    )
    assert legacy_path.stem == explicit_path.stem
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(legacy_root))

    baseline = TestClient(create_app()).get(
        f"/api/gap/reports/{legacy_path.stem}"
    )
    candidate = TestClient(
        _explicit_app(GapReportRepository(explicit_root))
    ).get(f"/api/gap/reports/{explicit_path.stem}")

    _assert_wire_equivalent(baseline, candidate)


@pytest.mark.parametrize(
    "key",
    ["not-a-report-key", "0123456789abcdef"],
)
def test_explicit_router_error_wire_contract_matches_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    """Malformed and missing keys retain exact public error contracts."""
    legacy_root = tmp_path / "legacy"
    explicit_root = tmp_path / "explicit"
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(legacy_root))

    baseline = TestClient(create_app()).get(f"/api/gap/reports/{key}")
    candidate = TestClient(
        _explicit_app(GapReportRepository(explicit_root))
    ).get(f"/api/gap/reports/{key}")

    _assert_wire_equivalent(baseline, candidate)


def test_explicit_router_auth_contract_matches_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same public auth middleware yields the same deny/allow results."""
    legacy_root = tmp_path / "legacy"
    explicit_root = tmp_path / "explicit"
    report = _report("Same Sentinel")
    legacy_path = save_report(
        report,
        gap_store_dir=legacy_root,
    )
    save_report(
        report,
        gap_store_dir=explicit_root,
    )
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(legacy_root))
    token_file = tmp_path / "synthetic-token.txt"
    token_file.write_text("synthetic-report-token", encoding="utf-8")
    provider = LocalTokenAuthProvider(token_file=token_file)
    baseline_client = TestClient(create_app(auth_provider=provider))
    candidate_client = TestClient(
        _explicit_app(
            GapReportRepository(explicit_root),
            auth_provider=provider,
        )
    )
    request_headers = [
        {},
        {"Authorization": "Bearer wrong-synthetic-token"},
        {"Authorization": "Bearer synthetic-report-token"},
    ]

    for headers in request_headers:
        baseline = baseline_client.get(
            f"/api/gap/reports/{legacy_path.stem}",
            headers=headers,
        )
        candidate = candidate_client.get(
            f"/api/gap/reports/{legacy_path.stem}",
            headers=headers,
        )
        _assert_wire_equivalent(baseline, candidate)


def test_explicit_router_openapi_operation_matches_legacy(
    tmp_path: Path,
) -> None:
    """The bound route must retain the existing OpenAPI operation contract."""
    path = "/api/gap/reports/{key}"
    baseline_operation = create_app().openapi()["paths"][path]["get"]
    candidate_operation = _explicit_app(
        GapReportRepository(tmp_path / "explicit")
    ).openapi()["paths"][path]["get"]

    assert candidate_operation == baseline_operation


def test_explicit_router_exposes_only_exact_report_read(
    tmp_path: Path,
) -> None:
    """The narrow factory must not make other gap operations reachable."""
    saved = save_report(
        _report("Bound Sentinel"),
        gap_store_dir=tmp_path / "explicit",
    )
    client = TestClient(
        _explicit_app(GapReportRepository(tmp_path / "explicit"))
    )

    assert client.get(f"/api/gap/reports/{saved.stem}").status_code == 200
    assert client.get("/api/gap/reports").status_code == 404
    assert client.post("/api/gap/analyze", json={}).status_code == 404
    assert client.post("/api/gap/diff", json={}).status_code == 404
    assert client.post("/api/gap/export", json={}).status_code == 404
