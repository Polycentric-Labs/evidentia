"""End-to-end collector idempotency tests (v0.10.5 Phase 10).

For each collector that has a stable mockable fixture, this module
runs ``collect()`` twice against an unchanged source and asserts the
contract documented in ``docs/collector-idempotency-audit.md``:

1. The set of ``(source_system, source_finding_id)`` pairs is
   identical across runs (natural-key stability sanity check).
2. The set of :attr:`evidentia_core.models.finding.SecurityFinding.id`
   values is identical across runs (the v1.0 idempotency guarantee).
3. Finding cardinality is preserved (zero net new findings).

Per-run timestamps (``collected_at`` / ``first_observed`` /
``last_observed``) and the per-run ULID (``CollectionContext.run_id``)
WILL legitimately differ between runs — they are not part of the
identity contract and not asserted here.

Cross-references:

- ``docs/collector-idempotency-audit.md`` (the contract this test guards).
- ``packages/evidentia-core/src/evidentia_core/models/finding.py``
  (``SecurityFinding._derive_deterministic_id`` validator).
- ``packages/evidentia-core/src/evidentia_core/models/common.py``
  (``deterministic_finding_id`` helper + the
  ``NAMESPACE_EVIDENTIA_FINDING`` pinned constant).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from evidentia_core.models.finding import SecurityFinding

# ── Shared assertion helper ──────────────────────────────────────────────


def _assert_idempotent(
    first: Iterable[SecurityFinding],
    second: Iterable[SecurityFinding],
) -> None:
    """Assert that two collect() invocations produced identical identities.

    Parameters
    ----------
    first, second:
        Findings returned from two separate ``collect()`` runs against
        the same fixture. Both MUST contain at least one finding —
        empty-input tests would trivially pass and provide no signal.
    """
    first_list = list(first)
    second_list = list(second)

    assert first_list, "first run produced zero findings — fixture broken"
    assert second_list, "second run produced zero findings — fixture broken"

    # (1) Cardinality must match.
    assert len(first_list) == len(second_list), (
        f"finding-count delta: first={len(first_list)} second={len(second_list)}"
    )

    # (2) Natural keys must match (sanity check; this exercises the
    # collector's own deterministic source_finding_id construction).
    first_natural = {(f.source_system, f.source_finding_id) for f in first_list}
    second_natural = {(f.source_system, f.source_finding_id) for f in second_list}
    assert first_natural == second_natural, (
        "natural-key set diverged between runs — collector emits non-deterministic source_finding_id values"
    )

    # (3) The actual idempotency contract: SecurityFinding.id values
    # must be identical across runs.
    first_ids = {f.id for f in first_list}
    second_ids = {f.id for f in second_list}
    new_in_second = second_ids - first_ids
    removed_in_second = first_ids - second_ids
    assert not new_in_second, (
        f"second run produced {len(new_in_second)} NEW finding ids "
        f"(idempotency contract violated). Sample: "
        f"{sorted(new_in_second)[:3]}"
    )
    assert not removed_in_second, (
        f"second run is missing {len(removed_in_second)} finding ids "
        f"present in first. Sample: {sorted(removed_in_second)[:3]}"
    )


# ── AWS Config + Security Hub + Access Analyzer ──────────────────────────


def _aws_config_paginator_responses() -> tuple[Any, Any]:
    """Return ``(describe_paginator_factory, details_paginator_factory)``."""
    from datetime import UTC, datetime

    def describe_paginator() -> Any:
        p = MagicMock()
        p.paginate.return_value = iter(
            [
                {
                    "ComplianceByConfigRules": [
                        {
                            "ConfigRuleName": "s3-bucket-public-read-prohibited",
                            "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                        }
                    ]
                }
            ]
        )
        return p

    def details_paginator() -> Any:
        p = MagicMock()
        p.paginate.return_value = iter(
            [
                {
                    "EvaluationResults": [
                        {
                            "EvaluationResultIdentifier": {
                                "EvaluationResultQualifier": {
                                    "ResourceType": "AWS::S3::Bucket",
                                    "ResourceId": "bucket-one",
                                }
                            },
                            "Annotation": "Bucket has public read ACL.",
                            "ResultRecordedTime": datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
                        },
                        {
                            "EvaluationResultIdentifier": {
                                "EvaluationResultQualifier": {
                                    "ResourceType": "AWS::S3::Bucket",
                                    "ResourceId": "bucket-two",
                                }
                            },
                            "Annotation": "Bucket has public read ACL.",
                            "ResultRecordedTime": datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
                        },
                    ]
                }
            ]
        )
        return p

    return describe_paginator, details_paginator


def _build_aws_config_mock() -> MagicMock:
    """Build a fresh mock AWS Config client. Call once per run."""
    describe, details = _aws_config_paginator_responses()
    mock_config = MagicMock()

    def get_paginator(name: str) -> Any:
        if name == "describe_compliance_by_config_rule":
            return describe()
        if name == "get_compliance_details_by_config_rule":
            return details()
        raise KeyError(name)

    mock_config.get_paginator.side_effect = get_paginator
    return mock_config


def test_aws_config_collector_is_idempotent() -> None:
    from evidentia_collectors.aws import AwsCollector

    def run_once() -> list[SecurityFinding]:
        collector = AwsCollector(region="us-east-1", _clients={"config": _build_aws_config_mock()})
        return collector.collect_config_findings()

    _assert_idempotent(run_once(), run_once())


def _build_aws_security_hub_mock() -> MagicMock:
    mock_sh = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = iter(
        [
            {
                "Findings": [
                    {
                        "Id": "arn:aws:securityhub:us-east-1:111:finding/abc",
                        "Title": "S3 bucket public",
                        "Description": "A public S3 bucket exists.",
                        "Severity": {"Label": "HIGH"},
                        "Workflow": {"Status": "NEW"},
                        "AwsAccountId": "111222333444",
                        "CreatedAt": "2026-04-15T10:00:00.000Z",
                        "UpdatedAt": "2026-04-15T11:00:00.000Z",
                        "Compliance": {
                            "SecurityControlId": "S3.3",
                            "RelatedRequirements": [
                                "NIST.800-53.r5 AC-3",
                                "NIST.800-53.r5 AC-6",
                            ],
                        },
                        "Resources": [
                            {
                                "Id": "arn:aws:s3:::my-bucket",
                                "Type": "AwsS3Bucket",
                                "Region": "us-east-1",
                            }
                        ],
                    }
                ]
            }
        ]
    )
    mock_sh.get_paginator.return_value = paginator
    return mock_sh


def test_aws_security_hub_collector_is_idempotent() -> None:
    from evidentia_collectors.aws import AwsCollector

    def run_once() -> list[SecurityFinding]:
        collector = AwsCollector(
            region="us-east-1",
            _clients={"securityhub": _build_aws_security_hub_mock()},
        )
        return collector.collect_security_hub_findings()

    _assert_idempotent(run_once(), run_once())


# ── GitHub repo settings collector ───────────────────────────────────────


def _github_handler() -> Any:
    """Return an httpx handler that serves a deterministic GitHub fixture."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/acme/platform":
            return httpx.Response(
                200,
                json={
                    "name": "platform",
                    "full_name": "acme/platform",
                    "private": True,
                    "visibility": "private",
                    "default_branch": "main",
                },
            )
        if req.url.path.endswith("/protection"):
            return httpx.Response(
                200,
                json={
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 2,
                        "dismiss_stale_reviews": True,
                    },
                    "required_status_checks": {
                        "strict": True,
                        "contexts": ["ci/tests"],
                    },
                    "enforce_admins": {"enabled": True},
                },
            )
        if "/contents/" in req.url.path:
            if req.url.path.endswith(".github/CODEOWNERS"):
                return httpx.Response(200, json={"path": ".github/CODEOWNERS"})
            return httpx.Response(404)
        return httpx.Response(404)

    return handler


def test_github_collector_is_idempotent() -> None:
    from evidentia_collectors.github import GitHubClient, GitHubCollector

    def run_once() -> list[SecurityFinding]:
        http = httpx.Client(
            base_url="https://api.github.com",
            transport=httpx.MockTransport(_github_handler()),
            headers={"Accept": "application/vnd.github+json"},
        )
        client = GitHubClient(http=http)
        with GitHubCollector(owner="acme", repo="platform", client=client) as c:
            return c.collect()

    _assert_idempotent(run_once(), run_once())


# ── GitHub Dependabot alerts collector ───────────────────────────────────


def _dependabot_alert() -> dict[str, Any]:
    """A single deterministic Dependabot alert fixture."""
    return {
        "number": 42,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "pip", "name": "requests"},
        },
        "security_advisory": {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "cve_id": "CVE-2025-12345",
            "summary": "Test vulnerability summary",
            "severity": "high",
            "cvss_severities": {"cvss_v3": {"score": 8.5, "vector_string": "x"}},
        },
        "security_vulnerability": {
            "package": {"ecosystem": "pip", "name": "requests"},
            "severity": "high",
            "first_patched_version": {"identifier": "2.31.0"},
        },
        "created_at": "2025-04-01T00:00:00Z",
        "updated_at": "2025-04-02T00:00:00Z",
    }


def test_dependabot_collector_is_idempotent() -> None:
    from evidentia_collectors.github.dependabot import DependabotCollector

    def run_once() -> list[SecurityFinding]:
        client = MagicMock()
        # Return the alert on the first page, then empty so the
        # pagination loop terminates.
        call_count = {"n": 0}

        def request(_method: str, _path: str, **_kwargs: Any) -> Any:
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [_dependabot_alert()]
            return []

        client.request.side_effect = request
        coll = DependabotCollector(owner="acme", repo="platform", client=client)
        return coll.collect()

    _assert_idempotent(run_once(), run_once())


# ── Okta collector ───────────────────────────────────────────────────────


def _okta_handler() -> Any:
    from datetime import UTC, datetime, timedelta
    from urllib.parse import parse_qs, urlparse

    # Compute fixed timestamps relative to a frozen anchor so the
    # fixture doesn't drift across runs (idempotency means the
    # SAME input on each call, not "wall-clock-equivalent").
    now = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)

    def iso_ago(days: int) -> str:
        return (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    responses: dict[str, Any] = {
        "/api/v1/org": {
            "subdomain": "test-org",
            "companyName": "Test Org Inc.",
            "status": "ACTIVE",
        },
        "/api/v1/users": [
            {
                "id": "u01",
                "status": "ACTIVE",
                "lastLogin": iso_ago(2),
                "profile": {"login": "alice@example.com"},
            },
            {
                "id": "u02",
                "status": "ACTIVE",
                "lastLogin": iso_ago(120),
                "profile": {"login": "bob@example.com"},
            },
        ],
        "/api/v1/iam/assignees/users": [
            {"id": "u01", "status": "ACTIVE"},
        ],
        "/api/v1/users/u01/factors": [{"id": "f01", "factorType": "push", "status": "ACTIVE"}],
        "/api/v1/users/u02/factors": [],
        "/api/v1/policies": {
            "PASSWORD": [
                {
                    "id": "p01",
                    "status": "ACTIVE",
                    "settings": {
                        "password": {
                            "complexity": {"minLength": 12},
                            "age": {"maxAgeDays": 90},
                            "lockout": {"maxAttempts": 5},
                        }
                    },
                }
            ],
            "OKTA_SIGN_ON": [
                {
                    "id": "p02",
                    "status": "ACTIVE",
                    "rules": [
                        {
                            "id": "r01",
                            "actions": {"signon": {"factorPromptMode": "ALWAYS"}},
                        }
                    ],
                }
            ],
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/policies":
            params = parse_qs(urlparse(str(request.url)).query)
            policy_type = (params.get("type") or [""])[0]
            return httpx.Response(200, json=responses["/api/v1/policies"].get(policy_type, []))
        if path in responses:
            return httpx.Response(200, json=responses[path])
        return httpx.Response(404, json={"error": f"unstubbed {path!r}"})

    return handler


def test_okta_collector_is_idempotent() -> None:
    from evidentia_collectors.okta import OktaCollector

    def run_once() -> list[SecurityFinding]:
        client = httpx.Client(
            transport=httpx.MockTransport(_okta_handler()),
            base_url="https://test-org.okta.com",
            headers={"Authorization": "SSWS test-token"},
        )
        with OktaCollector(client=client) as c:
            return c.collect()

    _assert_idempotent(run_once(), run_once())


# ── Vanta / Drata / BitSight / SecurityScorecard (SaaS vendor risk) ──────


def _vanta_page(vendors: list[dict[str, Any]]) -> MagicMock:
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.json.return_value = {
        "results": vendors,
        "pageInfo": {"endCursor": None, "hasNextPage": False},
    }
    response.raise_for_status = MagicMock()
    return response


def test_vanta_collector_is_idempotent() -> None:
    from evidentia_collectors.vanta import VantaCollector

    vendors = [
        {
            "id": "v-low-1",
            "name": "LowCo",
            "category": "Productivity",
            "owner": "owner-1",
            "url": "https://example.com",
            "riskTier": "low",
        },
        {
            "id": "v-high-1",
            "name": "HighCo",
            "category": "Security",
            "owner": "owner-2",
            "url": "https://high.example.com",
            "riskTier": "high",
        },
    ]

    def run_once() -> list[SecurityFinding]:
        client = MagicMock(spec=httpx.Client)
        client.get = MagicMock(return_value=_vanta_page(vendors))
        client.close = MagicMock()
        collector = VantaCollector(api_token="vt_test", client=client)
        return collector.collect()

    _assert_idempotent(run_once(), run_once())


def _google_workspace_handler() -> Any:
    """Return an httpx handler serving a small, deterministic Google
    Workspace tenant (a super admin plus one ordinary active user),
    keyed off a frozen anchor rather than wall-clock time, plus a
    single Reports login-activity page."""
    from datetime import UTC, datetime, timedelta
    from urllib.parse import parse_qs, urlparse

    anchor = datetime(2026, 5, 25, 12, 0, 0, tzinfo=UTC)

    def iso_ago(days: int) -> str:
        return (anchor - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    users = [
        {
            "id": "gw01",
            "primaryEmail": "admin@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": True,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": iso_ago(1),
            "creationTime": iso_ago(500),
        },
        {
            "id": "gw02",
            "primaryEmail": "user@example.com",
            "suspended": False,
            "archived": False,
            "isAdmin": False,
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "lastLoginTime": iso_ago(2),
            "creationTime": iso_ago(500),
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/admin/directory/v1/users":
            return httpx.Response(200, json={"users": users})
        if path == "/admin/reports/v1/activity/users/all/applications/login":
            params = parse_qs(urlparse(str(request.url)).query)
            if params.get("pageToken"):
                return httpx.Response(200, json={"items": []})
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "actor": {"email": "admin@example.com"},
                            "events": [{"name": "login_success"}],
                        }
                    ]
                },
            )
        return httpx.Response(404, json={"error": f"unstubbed {path!r}"})

    return handler, anchor


def test_google_workspace_collector_is_idempotent() -> None:
    from evidentia_collectors.google_workspace import GoogleWorkspaceCollector

    handler, anchor = _google_workspace_handler()

    def run_once() -> list[SecurityFinding]:
        client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://admin.googleapis.com",
            headers={"Authorization": "Bearer test-token"},
        )
        with GoogleWorkspaceCollector(client=client, now=anchor) as c:
            return c.collect()

    _assert_idempotent(run_once(), run_once())


def test_drata_collector_is_idempotent() -> None:
    from evidentia_collectors.drata import DrataCollector

    # Drata's collector accepts vendor data via the same shape pattern,
    # paginated via cursor. Mirror Vanta's mock with the Drata-specific
    # response envelope: ``{"data": [...], "meta": {"next_cursor": ...}}``.
    vendors = [
        {
            "id": "drata-low-1",
            "name": "LowCo",
            "category": "Productivity",
            "owner": "owner-1",
            "url": "https://example.com",
            "riskTier": "low",
        },
        {
            "id": "drata-crit-1",
            "name": "CritCo",
            "category": "Security",
            "owner": "owner-2",
            "url": "https://crit.example.com",
            "riskTier": "critical",
        },
    ]

    def make_response() -> MagicMock:
        response = MagicMock(spec=httpx.Response)
        response.status_code = 200
        response.json.return_value = {
            "data": vendors,
            "meta": {"next_cursor": None, "has_more": False},
        }
        response.raise_for_status = MagicMock()
        return response

    def run_once() -> list[SecurityFinding]:
        client = MagicMock(spec=httpx.Client)
        client.get = MagicMock(return_value=make_response())
        client.close = MagicMock()
        collector = DrataCollector(api_token="dt_test", client=client)
        return collector.collect()

    _assert_idempotent(run_once(), run_once())


# ── OCSF file ingest (third-party + Evidentia round-trip) ────────────────


@pytest.fixture
def ocsf_fixtures() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures" / "ocsf"


def test_ocsf_file_collector_is_idempotent_prowler(ocsf_fixtures: Path) -> None:
    pytest.importorskip("py_ocsf_models")
    from evidentia_collectors.ocsf import collect_ocsf_file

    fixture = ocsf_fixtures / "prowler-detection-finding.json"
    if not fixture.exists():
        pytest.skip("prowler-detection-finding.json fixture not present")

    _assert_idempotent(collect_ocsf_file(fixture), collect_ocsf_file(fixture))


def test_ocsf_file_collector_is_idempotent_mixed(
    ocsf_fixtures: Path,
) -> None:
    pytest.importorskip("py_ocsf_models")
    from evidentia_collectors.ocsf import collect_ocsf_file

    fixture = ocsf_fixtures / "mixed-batch.json"
    if not fixture.exists():
        pytest.skip("mixed-batch.json fixture not present")

    _assert_idempotent(collect_ocsf_file(fixture), collect_ocsf_file(fixture))


# ── Two-fixture independence sanity check ────────────────────────────────


def test_distinct_fixtures_produce_distinct_ids() -> None:
    """Two collectors with DIFFERENT natural keys must produce
    different SecurityFinding.id values.

    Guards against a regression that accidentally collapses unrelated
    findings onto the same id (e.g. by hashing only the source_system
    and dropping the source_finding_id).
    """
    a = SecurityFinding(
        title="a",
        description="d",
        severity="medium",
        source_system="aws-config",
        source_finding_id="s3-public:bucket-a",
    )
    b = SecurityFinding(
        title="b",
        description="d",
        severity="medium",
        source_system="aws-config",
        source_finding_id="s3-public:bucket-b",
    )
    c = SecurityFinding(
        title="c",
        description="d",
        severity="medium",
        source_system="aws-security-hub",
        source_finding_id="s3-public:bucket-a",
    )
    assert a.id != b.id
    assert a.id != c.id
    assert b.id != c.id


# ── OSCAL round-trip sanity check ────────────────────────────────────────


def test_oscal_json_roundtrip_preserves_id() -> None:
    """Pre-v0.10.5 OSCAL AR documents carry explicit ``id`` fields.

    The validator's "explicit id wins" branch must survive a
    ``json.dumps`` -> ``json.loads`` -> ``SecurityFinding.model_validate``
    round-trip.
    """
    f = SecurityFinding(
        title="t",
        description="d",
        severity="medium",
        source_system="aws-config",
        source_finding_id="s3-public:bucket-1",
    )
    serialized = json.loads(f.model_dump_json())
    restored = SecurityFinding.model_validate(serialized)
    assert restored.id == f.id
