"""TestClient coverage for /api/collectors/* endpoints.

Smoke coverage only — full collector happy-paths are covered in
``tests/unit/test_collectors/``. Here we verify routing, validation,
and error-code mapping.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestCollectorsStatus:
    def test_reports_packages_and_env(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_never_appear_in_response")
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        payload = r.json()
        assert "aws" in payload
        assert "github" in payload
        assert payload["github"]["token_configured"] is True
        assert payload["github"]["token_source"] == "env:GITHUB_TOKEN"
        # Token value must NEVER appear in the response.
        assert "should_never_appear_in_response" not in r.text

    def test_reports_github_unconfigured_when_env_missing(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        r = api_client.get("/api/collectors/status")
        payload = r.json()
        assert payload["github"]["token_configured"] is False
        assert payload["github"]["token_source"] is None


class TestGithubCollectEndpoint:
    def test_rejects_malformed_repo(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/github/collect", json={"repo": "notaformat"})
        # 400 (not 422) — runtime body-content validation; structured
        # detail shape (F-V08-DAST-3 status normalization; 2026-07-06
        # error-shape convergence).
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert "owner/repo" in detail["message"]

    def test_missing_repo_returns_400(self, api_client: TestClient) -> None:
        r = api_client.post("/api/collectors/github/collect", json={})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "missing_field"


class TestSQLiteCollectEndpointSafeRoot:
    """v0.7.7 Step 5.A — F-001 path-traversal containment.

    The REST endpoint must honor EVIDENTIA_SQLITE_SAFE_ROOT and refuse
    any database_path that resolves outside it (CWE-22 mitigation).
    """

    def test_rejects_path_outside_safe_root(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        from pathlib import Path as _P

        safe = _P(str(tmp_path)) / "safe"
        safe.mkdir()
        outside = _P(str(tmp_path)) / "outside.db"
        import sqlite3
        sqlite3.connect(str(outside)).close()

        monkeypatch.setenv("EVIDENTIA_SQLITE_SAFE_ROOT", str(safe))
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(outside)},
        )
        # SQLiteCollectorError -> 503 with "outside safe_root" detail
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert detail["error"] == "upstream_error"
        assert "outside safe_root" in detail["message"]

    def test_accepts_path_inside_safe_root(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        from pathlib import Path as _P

        safe = _P(str(tmp_path)) / "safe"
        safe.mkdir()
        inside = safe / "app.db"
        import sqlite3
        sqlite3.connect(str(inside)).close()

        monkeypatch.setenv("EVIDENTIA_SQLITE_SAFE_ROOT", str(safe))
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(inside)},
        )
        # Path inside safe_root is accepted; collection succeeds (200)
        # — even an empty DB produces file-ACL + integrity findings
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_no_safe_root_env_falls_back_to_unconstrained(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: object,
    ) -> None:
        """When EVIDENTIA_SQLITE_SAFE_ROOT is unset, any readable path
        is accepted (single-tenant trusted-perimeter posture)."""
        from pathlib import Path as _P

        db = _P(str(tmp_path)) / "app.db"
        import sqlite3
        sqlite3.connect(str(db)).close()

        monkeypatch.delenv("EVIDENTIA_SQLITE_SAFE_ROOT", raising=False)
        r = api_client.post(
            "/api/collectors/sql/sqlite/collect",
            json={"database_path": str(db)},
        )
        assert r.status_code == 200


class TestSnowflakeCollectEndpoint:
    """Smoke coverage for /api/collectors/snowflake/collect (v0.7.8 P0.2).

    No live Snowflake; we validate routing + body validation + secret-
    handling guarantees.
    """

    def test_missing_account_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={"user": "EVIDENTIA_AUDIT_RO"},
        )
        # 400 (not 422) — body-content validation. F-V08-DAST-3
        # status normalization; structured detail per the 2026-07-06
        # error-shape convergence.
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert "account" in detail["message"]

    def test_missing_user_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={"account": "acme-prod"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert "user" in detail["message"]

    def test_missing_password_env_returns_400(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Ensure neither default nor any custom env is set.
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
        r = api_client.post(
            "/api/collectors/snowflake/collect",
            json={
                "account": "acme-prod",
                "user": "EVIDENTIA_AUDIT_RO",
            },
        )
        # 400 because the password env var resolves to nothing.
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "credentials_missing"
        assert "SNOWFLAKE_PASSWORD" in detail["message"]

    def test_status_endpoint_includes_snowflake_entry(
        self, api_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "SNOWFLAKE_PASSWORD",
            "fake-pwd-must-not-appear-in-response",
        )
        r = api_client.get("/api/collectors/status")
        assert r.status_code == 200
        payload = r.json()
        assert "snowflake" in payload
        assert payload["snowflake"]["default_password_env_configured"] is True
        # Secret value MUST NOT leak.
        assert "fake-pwd-must-not-appear-in-response" not in r.text


class TestSecurityScorecardCollectEndpointSSRFGuard:
    """v0.7.12 P0.6 / CodeQL #92 closure (CRITICAL py/partial-ssrf).

    The /api/collectors/securityscorecard/collect endpoint must
    reject portfolio_id values containing path-traversal segments
    BEFORE they flow into the f-string URL composition at
    ``_paginate_portfolio``. The collector itself also validates
    (defense-in-depth) but a 400 here gives the API consumer a
    sharper error than the collector's 503.
    """

    @pytest.mark.parametrize(
        "bad_portfolio_id",
        [
            "../admin",
            "portfolio/companies",
            "portfolio\\evil",
            "/leading-slash",
            "trailing-slash/",
            "portfolio?inject=1",
            "portfolio#frag",
            "portfolio with spaces",
            "portfolio\nnewline",
        ],
    )
    def test_rejects_unsafe_portfolio_id_with_400(
        self,
        api_client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        bad_portfolio_id: str,
    ) -> None:
        # Provide a token so the env-var gate doesn't fail first
        monkeypatch.setenv("SECURITYSCORECARD_API_TOKEN", "ssc_test")
        r = api_client.post(
            "/api/collectors/securityscorecard/collect",
            json={"portfolio_id": bad_portfolio_id},
        )
        # 400 (not 422) — early-fail at the REST boundary; structured
        # detail shape (F-V08-DAST-3 status normalization; 2026-07-06
        # error-shape convergence).
        assert r.status_code == 400, (
            f"Expected 400 for portfolio_id={bad_portfolio_id!r}, "
            f"got {r.status_code}: {r.text}"
        )
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert "portfolio_id" in detail["message"].lower()


# A minimal-but-valid OCSF Compliance Finding (class_uid 2003). Lifted from
# the unit OCSF collector test's forged-block fixture — the native fields
# alone are enough to ingest (the unmapped block is ignored at the REST
# boundary because the collector passes trust_unmapped=False). The
# distinctive native title proves an ACTUAL ingest happened, not a forged
# round-trip.
_VALID_OCSF_COMPLIANCE_FINDING: dict[str, object] = {
    "activity_id": 1,
    "category_uid": 2,
    "class_uid": 2003,
    "type_uid": 200301,
    "time": 1_716_422_400_000,
    "severity_id": 2,
    "metadata": {
        "version": "1.5.0",
        "product": {"name": "Prowler", "vendor_name": "Prowler"},
    },
    "finding_info": {"title": "Encryption at rest disabled", "uid": "ocsf-uid-1"},
    # `requirements` (not `standards`) drives the native control_mappings —
    # the framework name comes from `standards`, the control_id from each
    # `requirements` entry (see _security_finding_from_native_ocsf).
    "compliance": {
        "status_id": 3,
        "standards": ["cis-aws"],
        "requirements": ["2.1.1"],
    },
}


@pytest.mark.usefixtures("api_client")
class TestOcsfCollectEndpoint:
    """v0.10.12 — /api/collectors/ocsf/collect (inline-content + URL modes).

    Hermetic: inline mode never touches the network; the URL-mode SSRF
    cases use literal private / loopback IPs so no DNS round-trip fires
    and the guard refusal is asserted BEFORE any socket is opened.
    """

    def test_inline_content_returns_findings(
        self, api_client: TestClient
    ) -> None:
        pytest.importorskip("py_ocsf_models")
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"content": [_VALID_OCSF_COMPLIANCE_FINDING]},
        )
        assert r.status_code == 200, r.text
        payload = r.json()
        assert isinstance(payload, list)
        assert len(payload) == 1
        # The native finding_info.title flows through (proves real ingest).
        assert payload[0]["title"] == "Encryption at rest disabled"
        # trust_unmapped=False path: control mapping comes from native
        # compliance.standards, not a forged block.
        assert payload[0]["control_mappings"][0]["framework"] == "cis-aws"

    def test_inline_single_object_content_returns_findings(
        self, api_client: TestClient
    ) -> None:
        """Content may be a single OCSF object (not just a list)."""
        pytest.importorskip("py_ocsf_models")
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"content": _VALID_OCSF_COMPLIANCE_FINDING},
        )
        assert r.status_code == 200, r.text
        assert len(r.json()) == 1

    def test_missing_content_and_url_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post("/api/collectors/ocsf/collect", json={})
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "content" in detail["message"].lower()

    def test_bad_content_returns_400(self, api_client: TestClient) -> None:
        pytest.importorskip("py_ocsf_models")
        # class_uid 9999 is not a supported Findings class → 400.
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"content": {"class_uid": 9999, "category_uid": 2}},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "ocsf" in detail["message"].lower()

    def test_url_mode_rejects_http(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"url": "http://example.com/ocsf.json"},
        )
        assert r.status_code == 400
        assert "https" in r.json()["detail"]["message"].lower()

    def test_url_mode_metadata_endpoint_refused_by_default(
        self, api_client: TestClient
    ) -> None:
        """SSRF guard: the AWS instance-metadata endpoint is refused by
        default. Literal IP host → no DNS; the refusal fires before any
        socket is opened, so this is fully hermetic."""
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"url": "https://169.254.169.254/latest/meta-data/"},
        )
        assert r.status_code == 400, r.text
        message = r.json()["detail"]["message"]
        assert "169.254" in message
        assert "link-local" in message or "private" in message

    @pytest.mark.parametrize(
        "url",
        [
            "https://10.0.0.1/api",
            "https://192.168.1.1/api",
            "https://127.0.0.1:8080/api",
        ],
    )
    def test_url_mode_private_and_loopback_refused_by_default(
        self, api_client: TestClient, url: str
    ) -> None:
        """RFC1918 + loopback URLs are all refused by the default-on guard."""
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={"url": url},
        )
        assert r.status_code == 400, r.text
        message = r.json()["detail"]["message"].lower()
        assert (
            "private" in message
            or "loopback" in message
            or "link-local" in message
        )

    def test_url_mode_allowed_only_with_block_private_ips_false(
        self, api_client: TestClient
    ) -> None:
        """With the explicit opt-out the guard is SKIPPED, so the request
        proceeds to the actual fetch — which fails on connection refusal
        (no listener on 127.0.0.1:1). The KEY assertion: the error is NOT
        the SSRF policy refusal, proving the guard was bypassed."""
        r = api_client.post(
            "/api/collectors/ocsf/collect",
            json={
                "url": "https://127.0.0.1:1/api",
                "block_private_ips": False,
            },
        )
        # Connection-refused / fetch failure → the collector raises
        # OCSFIngestError, which the router maps to 400 (bad url/content).
        assert r.status_code == 400, r.text
        message = r.json()["detail"]["message"].lower()
        assert "private" not in message
        assert "loopback" not in message
        assert "fetch failed" in message or "fetch" in message


class TestConvertEndpoint:
    """v0.10.12 — /api/collectors/convert (local, no network)."""

    def _security_finding_payload(self) -> dict[str, object]:
        """A minimal valid SecurityFinding dict (the convert input)."""
        return {
            "id": "EVID-TEST-1",
            "title": "Encryption at rest disabled",
            "description": "Bucket has no default encryption.",
            "severity": "high",
            "source_system": "aws-config",
        }

    def test_convert_happy_path_to_ocsf(self, api_client: TestClient) -> None:
        pytest.importorskip("py_ocsf_models")
        r = api_client.post(
            "/api/collectors/convert",
            json={
                "content": [self._security_finding_payload()],
                "to_format": "ocsf",
            },
        )
        assert r.status_code == 200, r.text
        payload = r.json()
        assert isinstance(payload, list)
        assert len(payload) == 1
        # OCSF Compliance Finding output carries the canonical class_uid.
        assert payload[0]["class_uid"] == 2003

    def test_convert_single_object_content(
        self, api_client: TestClient
    ) -> None:
        pytest.importorskip("py_ocsf_models")
        r = api_client.post(
            "/api/collectors/convert",
            json={
                "content": self._security_finding_payload(),
                "to_format": "ocsf",
            },
        )
        assert r.status_code == 200, r.text
        assert len(r.json()) == 1

    def test_convert_unsupported_format_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/convert",
            json={
                "content": [self._security_finding_payload()],
                "to_format": "stix",
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "unsupported_format"
        assert "format" in detail["message"].lower()

    def test_convert_missing_content_returns_400(
        self, api_client: TestClient
    ) -> None:
        r = api_client.post(
            "/api/collectors/convert",
            json={"to_format": "ocsf"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "missing_field"
        assert "content" in detail["message"].lower()

    def test_convert_bad_finding_returns_400(
        self, api_client: TestClient
    ) -> None:
        """Content that isn't a valid SecurityFinding → 400 (not 500)."""
        r = api_client.post(
            "/api/collectors/convert",
            json={
                "content": [{"not": "a finding"}],
                "to_format": "ocsf",
            },
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        message = detail["message"].lower()
        assert "finding" in message or "invalid" in message


def test_collectors_error_statuses_documented_in_openapi(
    api_client: TestClient,
) -> None:
    """Every deliberate 4xx/5xx a collectors route raises is documented
    in its OpenAPI ``responses`` (2026-07-06 error-shape convergence —
    schemathesis can hold undocumented-status noise to the contract)."""
    schema = api_client.get("/api/openapi.json").json()
    expected: list[tuple[str, str, list[str]]] = [
        ("/api/collectors/aws/collect", "post", ["500", "503"]),
        (
            "/api/collectors/github/collect",
            "post",
            ["400", "404", "502", "503"],
        ),
        ("/api/collectors/okta/collect", "post", ["400", "500", "503"]),
        (
            "/api/collectors/sql/postgres/collect",
            "post",
            ["400", "500", "503"],
        ),
        ("/api/collectors/sql/mysql/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/sql/mssql/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/sql/oracle/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/sql/sqlite/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/databricks/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/snowflake/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/vanta/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/drata/collect", "post", ["400", "500", "503"]),
        ("/api/collectors/bitsight/collect", "post", ["400", "500", "503"]),
        (
            "/api/collectors/securityscorecard/collect",
            "post",
            ["400", "500", "503"],
        ),
        ("/api/collectors/ocsf/collect", "post", ["400", "503"]),
        ("/api/collectors/nessus/collect", "post", ["400", "503"]),
        ("/api/collectors/convert", "post", ["400", "503"]),
    ]
    for path, method, statuses in expected:
        op = schema["paths"][path][method]
        for status in statuses:
            assert status in op["responses"], (
                f"{method.upper()} {path} missing documented {status}"
            )
