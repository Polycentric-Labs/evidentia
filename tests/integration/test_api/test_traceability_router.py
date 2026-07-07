"""TestClient coverage for /api/traceability/* endpoints (v0.10.12).

Surfaces the ``evidentia traceability emit`` verb over HTTP as a
READ-MOSTLY GUI-backing endpoint: it emits the Control↔Threat
Traceability Matrix as an **UNSIGNED** OSCAL profile. The GPG/Sigstore
signing path stays CLI-only — it is deliberately NOT exposed over HTTP.

Hermetic: a LOCAL ``FastAPI()`` app includes ONLY the traceability
router under ``prefix="/api"`` (mirrors the catalog-router test). The
endpoint computes/emits purely from inline body content — it reads no
server paths and persists no state — so no store isolation is needed
and there is no network.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def trace_client() -> Iterator[TestClient]:
    """A TestClient over a local app holding ONLY the traceability router."""
    from evidentia_api.routers import traceability as traceability_router

    app = FastAPI()
    app.include_router(traceability_router.router, prefix="/api")
    with TestClient(app) as client:
        yield client


def _matrix_payload(
    *,
    with_mappings: bool = True,
) -> dict[str, object]:
    """A minimal valid TraceabilityMatrix request body."""
    payload: dict[str, object] = {
        "title": "Control-to-Threat Traceability: Acme",
        "catalog_href": "nist-800-53-rev5-moderate.json",
        "framework_id": "nist-800-53-rev5-moderate",
        "crosswalk_source": "self-attested",
        "mappings": [],
    }
    if with_mappings:
        payload["mappings"] = [
            {
                "control_id": "AC-2",
                "threat_id": "T1078",
                "threat_framework": "mitre-attack",
                "threat_name": "Valid Accounts",
                "relationship": "mitigates",
                "coverage": "partial",
            }
        ]
    return payload


# ════════════════════════════════════════════════════════════════════
# emit — happy path
# ════════════════════════════════════════════════════════════════════


class TestEmit:
    def test_emit_returns_unsigned_oscal_profile(
        self, trace_client: TestClient
    ) -> None:
        r = trace_client.post(
            "/api/traceability/emit", json=_matrix_payload()
        )
        assert r.status_code == 200, r.text
        body = r.json()

        # The emit produces an OSCAL *profile* (the 2026-06-17
        # representation decision), not Assessment Results / mapping.
        assert "profile" in body
        profile = body["profile"]
        assert profile["metadata"]["title"] == (
            "Control-to-Threat Traceability: Acme"
        )

        # The imported catalog + the annotated control survive into the
        # emitted document.
        assert profile["imports"][0]["href"] == "nist-800-53-rev5-moderate.json"
        alters = profile["modify"]["alters"]
        assert alters[0]["control-id"] == "ac-2"

        # The threat lives in an integrity-hashed back-matter resource.
        resources = profile["back-matter"]["resources"]
        assert len(resources) == 1
        res = resources[0]
        assert res["title"] == "Valid Accounts"
        assert res["rlinks"][0]["hashes"][0]["algorithm"] == "SHA-256"
        assert res["rlinks"][0]["hashes"][0]["value"]

    def test_emitted_profile_is_unsigned(
        self, trace_client: TestClient
    ) -> None:
        """The HTTP emit MUST be unsigned — no GPG/Sigstore artifact.

        Signing is CLI-only. A signed OSCAL document carries its
        detached/embedded signature *alongside* the JSON (a ``.asc`` /
        ``.sigstore.json`` sidecar) — never inside the profile body — and
        an OSCAL signing convention also surfaces a back-matter signature
        resource. Assert none of that leaks into the HTTP response: the
        body is the bare profile and nothing else.
        """
        r = trace_client.post(
            "/api/traceability/emit", json=_matrix_payload()
        )
        assert r.status_code == 200, r.text
        body = r.json()

        # Top-level: only the OSCAL profile — no signature/bundle sidecar.
        assert set(body.keys()) == {"profile"}
        for leaked in (
            "signature",
            "signed",
            "sigstore",
            "sigstore_bundle",
            "gpg_signature",
            "signature_path",
            "asc",
        ):
            assert leaked not in body

        # No signature-bearing back-matter resource (the threat resources
        # carry integrity hashes, but none is a document signature).
        profile = body["profile"]
        for res in profile["back-matter"]["resources"]:
            title = (res.get("title") or "").lower()
            assert "signature" not in title
            for prop in res.get("props", []):
                assert "signature" not in prop.get("name", "").lower()

        # The serialized document contains no signing markers at all.
        serialized = r.text.lower()
        assert "sigstore" not in serialized
        assert "-----begin pgp" not in serialized


# ════════════════════════════════════════════════════════════════════
# emit — invalid / insufficient input
# ════════════════════════════════════════════════════════════════════


class TestEmitInvalidInput:
    def test_empty_mappings_returns_400(
        self, trace_client: TestClient
    ) -> None:
        # A schema-valid matrix with no mappings is insufficient to emit
        # (mirrors the CLI's "nothing to emit" guard) → 400 with the
        # structured detail from evidentia_api.errors.
        r = trace_client.post(
            "/api/traceability/emit",
            json=_matrix_payload(with_mappings=False),
        )
        assert r.status_code == 400, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "message" in detail

    def test_missing_required_field_returns_422(
        self, trace_client: TestClient
    ) -> None:
        # Drop a required field (catalog_href) → Pydantic 422.
        payload = _matrix_payload()
        del payload["catalog_href"]
        r = trace_client.post("/api/traceability/emit", json=payload)
        assert r.status_code == 422, r.text

    def test_empty_body_returns_422(self, trace_client: TestClient) -> None:
        r = trace_client.post("/api/traceability/emit", json={})
        assert r.status_code == 422, r.text

    def test_invalid_threat_framework_returns_422(
        self, trace_client: TestClient
    ) -> None:
        payload = _matrix_payload()
        payload["mappings"] = [  # type: ignore[assignment]
            {
                "control_id": "AC-2",
                "threat_id": "T1078",
                "threat_framework": "not-a-real-framework",
            }
        ]
        r = trace_client.post("/api/traceability/emit", json=payload)
        assert r.status_code == 422, r.text


# ════════════════════════════════════════════════════════════════════
# signing knobs are NOT accepted over HTTP (signing is CLI-only)
# ════════════════════════════════════════════════════════════════════


class TestSigningKnobsRejected:
    def test_sign_with_gpg_in_body_is_rejected(
        self, trace_client: TestClient
    ) -> None:
        # The body model forbids extra fields, so a signing knob smuggled
        # into the request is structurally rejected (422) — the HTTP
        # surface offers no way to trigger signing.
        payload = {**_matrix_payload(), "sign_with_gpg": "DEADBEEF"}
        r = trace_client.post("/api/traceability/emit", json=payload)
        assert r.status_code == 422, r.text

    def test_sign_with_sigstore_in_body_is_rejected(
        self, trace_client: TestClient
    ) -> None:
        payload = {**_matrix_payload(), "sign_with_sigstore": True}
        r = trace_client.post("/api/traceability/emit", json=payload)
        assert r.status_code == 422, r.text


# ════════════════════════════════════════════════════════════════════
# OpenAPI error-status documentation (2026-07-06 convergence)
# ════════════════════════════════════════════════════════════════════


def test_traceability_error_statuses_documented_in_openapi(
    trace_client: TestClient,
) -> None:
    """Every status the traceability route deliberately raises is
    documented on the operation's ``responses`` in the OpenAPI schema.
    The hermetic app serves its schema at ``/openapi.json`` (the
    ``/api`` prefix applies to the routes, not the schema endpoint)."""
    schema = trace_client.get("/openapi.json").json()
    expected = [
        ("/api/traceability/emit", "post", ["400"]),
    ]
    for path, method, statuses in expected:
        responses = schema["paths"][path][method]["responses"]
        for status in statuses:
            assert status in responses, (path, method, status)
