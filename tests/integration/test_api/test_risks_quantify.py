"""TestClient coverage for ``POST /api/risk/quantify`` (v0.10.12).

The quantify endpoint is the HTTP mirror of the ``evidentia risk
quantify`` CLI verb: pure local Open FAIR math (deterministic
PERT-mean) plus the optional FAIR Monte Carlo (``fair-mc``) path.
No credentials, no network, no state mutation.

Each test builds a *local* ``FastAPI()`` app mounting only the risks
router under ``/api`` so the suite is hermetic and doesn't depend on
``create_app()`` wiring. Determinism is held by passing an explicit
``seed`` + a small fixed ``iterations`` count on the Monte Carlo path.
"""

from __future__ import annotations

import pytest
from evidentia_api.routers import risks as risks_router
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> TestClient:
    """Local FastAPI app mounting only the risks router under /api."""
    app = FastAPI()
    app.include_router(risks_router.router, prefix="/api")
    return TestClient(app)


def _scenarios() -> list[dict[str, object]]:
    """Two valid Open FAIR scenarios — one scalar, one PERT-range."""
    return [
        {
            "name": "Credential stuffing",
            "description": "External attackers reuse leaked credentials.",
            "tef": 365,
            "vulnerability": 0.001,
            "primary_loss": 5000,
            "secondary_loss": 50000,
        },
        {
            "name": "Ransomware",
            "description": "Untargeted ransomware drive-by.",
            "tef": 12,
            "vulnerability": 0.05,
            "primary_loss": 250000,
            "secondary_loss": {
                "low": 100000,
                "most_likely": 500000,
                "high": 2000000,
            },
        },
    ]


# ── open-fair (deterministic) ──────────────────────────────────────


class TestOpenFairMethod:
    def test_default_method_returns_deterministic_result(
        self, client: TestClient
    ) -> None:
        r = client.post(
            "/api/risk/quantify",
            json={"scenarios": _scenarios()},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["method"] == "open-fair"
        assert body["scenario_count"] == 2
        # Total ALE is the sum of per-scenario ALEs.
        # Credential stuffing: 365 * 0.001 * (5000 + 50000) = 20_075
        # Ransomware: 12 * 0.05 * (250000 + PERT_mean(100k,500k,2M))
        #   PERT mean = (100000 + 4*500000 + 2000000) / 6 = 683_333.33…
        #   ALE = 0.6 * (250000 + 683333.33…) = 560_000.0
        assert body["total_ale"] == pytest.approx(20_075 + 560_000.0)
        scenarios = body["scenarios"]
        assert len(scenarios) == 2
        names = {s["name"] for s in scenarios}
        assert names == {"Credential stuffing", "Ransomware"}
        cred = next(s for s in scenarios if s["name"] == "Credential stuffing")
        assert cred["ale"] == pytest.approx(20_075.0)
        assert cred["lef"] == pytest.approx(0.365)
        assert cred["loss_magnitude"] == pytest.approx(55_000.0)
        assert cred["risk_category"] == "moderate"

    def test_deterministic_across_calls(self, client: TestClient) -> None:
        payload = {"method": "open-fair", "scenarios": _scenarios()}
        first = client.post("/api/risk/quantify", json=payload).json()
        second = client.post("/api/risk/quantify", json=payload).json()
        # The computed numbers are deterministic. (Each request re-parses
        # the scenarios, minting a fresh per-scenario UUID via the core
        # default_factory, so the auto-stamped `id` legitimately varies —
        # compare the math, not the identity.)
        assert first["total_ale"] == second["total_ale"]
        first_math = [
            (s["name"], s["lef"], s["loss_magnitude"], s["ale"], s["risk_category"])
            for s in first["scenarios"]
        ]
        second_math = [
            (s["name"], s["lef"], s["loss_magnitude"], s["ale"], s["risk_category"])
            for s in second["scenarios"]
        ]
        assert first_math == second_math


# ── fair-mc (Monte Carlo, seeded → deterministic) ──────────────────


class TestFairMcMethod:
    def test_seeded_run_returns_percentiles(self, client: TestClient) -> None:
        r = client.post(
            "/api/risk/quantify",
            json={
                "method": "fair-mc",
                "scenarios": _scenarios(),
                "iterations": 200,
                "seed": 42,
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["method"] == "fair-mc"
        assert body["scenario_count"] == 2
        sims = body["simulations"]
        assert len(sims) == 2
        for sim in sims:
            # SimulationResult core model fields round-trip in the response.
            assert sim["iterations"] == 200
            assert sim["seed"] == 42
            assert sim["p10"] <= sim["p50"] <= sim["p90"]
            assert "mean" in sim
            assert sim["risk_category_p50"] in {
                "severe",
                "high",
                "significant",
                "moderate",
                "low",
            }

    def test_seed_makes_run_deterministic(self, client: TestClient) -> None:
        payload = {
            "method": "fair-mc",
            "scenarios": _scenarios(),
            "iterations": 200,
            "seed": 7,
        }
        first = client.post("/api/risk/quantify", json=payload).json()
        second = client.post("/api/risk/quantify", json=payload).json()
        # Same seed + iterations → identical percentile bands + samples.
        # (`id` / `created_at` / `scenario_id` are auto-stamped per call and
        # legitimately differ — compare the simulation math, not identity.)
        first_math = [
            (s["scenario_name"], s["p10"], s["p50"], s["p90"], s["mean"], s["samples"])
            for s in first["simulations"]
        ]
        second_math = [
            (s["scenario_name"], s["p10"], s["p50"], s["p90"], s["mean"], s["samples"])
            for s in second["simulations"]
        ]
        assert first_math == second_math


# ── error handling ─────────────────────────────────────────────────


class TestErrors:
    def test_unknown_method_returns_400(self, client: TestClient) -> None:
        r = client.post(
            "/api/risk/quantify",
            json={"method": "monte-carlo-old-name", "scenarios": _scenarios()},
        )
        assert r.status_code == 400
        # F-V08-DAST-3 invariant: detail is a string, not array.
        assert isinstance(r.json()["detail"], str)

    def test_bad_pert_range_returns_422(self, client: TestClient) -> None:
        # The PERTRange validator (low <= most_likely <= high) fires during
        # FastAPI request-body parsing because OpenFAIRScenario is a typed
        # field on the DTO → Pydantic auto-validation 422 (array-shape detail).
        bad = _scenarios()
        bad[0]["primary_loss"] = {
            "low": 100,
            "most_likely": 10,
            "high": 5,
        }
        r = client.post(
            "/api/risk/quantify",
            json={"method": "open-fair", "scenarios": bad},
        )
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_empty_scenarios_returns_422(self, client: TestClient) -> None:
        # min_length=1 on the scenarios field → Pydantic auto-validation 422.
        r = client.post("/api/risk/quantify", json={"scenarios": []})
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_missing_required_scenario_field_returns_422(
        self, client: TestClient
    ) -> None:
        # OpenFAIRScenario requires tef/vulnerability/primary_loss; drop one.
        r = client.post(
            "/api/risk/quantify",
            json={
                "scenarios": [
                    {
                        "name": "x",
                        "description": "x",
                        "vulnerability": 0.5,
                        "primary_loss": 1000,
                    }
                ]
            },
        )
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_iterations_out_of_range_returns_422(
        self, client: TestClient
    ) -> None:
        # iterations is bounded (ge=1, le=1_000_000); over-cap → 422.
        r = client.post(
            "/api/risk/quantify",
            json={
                "method": "fair-mc",
                "scenarios": _scenarios(),
                "iterations": 5_000_000,
            },
        )
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)
