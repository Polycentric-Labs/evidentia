"""GitHub collector tests — httpx.MockTransport-backed.

Covers:
- Visibility finding (public vs private)
- Branch protection present vs missing
- Individual protection rules (review, status checks, enforce_admins)
- CODEOWNERS present (any of three locations) vs missing
- API error handling
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from evidentia_collectors.github import (
    GitHubApiError,
    GitHubClient,
    GitHubCollector,
)
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import FindingStatus

# ── Fixtures ─────────────────────────────────────────────────────────────


def _make_collector(handler: Callable[[httpx.Request], httpx.Response]) -> GitHubCollector:
    """Build a collector wired to an httpx MockTransport."""
    http = httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
        headers={"Accept": "application/vnd.github+json"},
    )
    client = GitHubClient(http=http)
    return GitHubCollector(owner="acme", repo="platform", client=client)


def _repo(private: bool = True, default_branch: str = "main") -> dict[str, Any]:
    return {
        "name": "platform",
        "full_name": "acme/platform",
        "private": private,
        "visibility": "private" if private else "public",
        "default_branch": default_branch,
    }


def _protection_full() -> dict[str, Any]:
    """A fully-configured protection object."""
    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": 2,
            "dismiss_stale_reviews": True,
        },
        "required_status_checks": {
            "strict": True,
            "contexts": ["ci/tests", "ci/lint"],
        },
        "enforce_admins": {"enabled": True},
    }


# ── Visibility ───────────────────────────────────────────────────────────


class TestVisibility:
    def test_private_repo_resolved_finding(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo(private=True))
            if req.url.path.endswith("/protection"):
                return httpx.Response(200, json=_protection_full())
            if "/contents/" in req.url.path:
                # CODEOWNERS at .github
                if req.url.path.endswith(".github/CODEOWNERS"):
                    return httpx.Response(200, json={"path": ".github/CODEOWNERS"})
                return httpx.Response(404)
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        visibility = next(
            f for f in findings if f.source_finding_id == "acme/platform:visibility"
        )
        assert visibility.severity == Severity.INFORMATIONAL
        assert visibility.status == FindingStatus.RESOLVED
        assert "AC-3" in visibility.control_ids
        assert "private" in visibility.description.lower()

    def test_public_repo_active_finding(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo(private=False))
            if req.url.path.endswith("/protection"):
                return httpx.Response(200, json=_protection_full())
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        visibility = next(
            f for f in findings if f.source_finding_id == "acme/platform:visibility"
        )
        assert visibility.severity == Severity.MEDIUM
        assert visibility.status == FindingStatus.ACTIVE


# ── Branch protection ────────────────────────────────────────────────────


class TestBranchProtection:
    def test_unprotected_default_branch_is_high_severity(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo())
            if req.url.path.endswith("/protection"):
                return httpx.Response(404)  # no protection -> 404
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        prot = next(
            f for f in findings if "unprotected" in (f.source_finding_id or "")
        )
        assert prot.severity == Severity.HIGH
        assert set(prot.control_ids) >= {"SA-11", "CM-3"}

    def test_protected_branch_emits_three_sub_findings(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo())
            if req.url.path.endswith("/protection"):
                return httpx.Response(200, json=_protection_full())
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        rule_ids = {
            f.source_finding_id for f in findings if f.source_finding_id
        }
        assert "acme/platform:main:pr_review" in rule_ids
        assert "acme/platform:main:status_checks" in rule_ids
        assert "acme/platform:main:enforce_admins" in rule_ids

        pr_review = next(
            f for f in findings if f.source_finding_id == "acme/platform:main:pr_review"
        )
        assert pr_review.status == FindingStatus.RESOLVED

    def test_zero_reviewers_emits_high_severity_finding(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo())
            if req.url.path.endswith("/protection"):
                return httpx.Response(
                    200,
                    json={
                        "required_pull_request_reviews": {
                            "required_approving_review_count": 0
                        },
                        "required_status_checks": {"contexts": ["ci/tests"]},
                        "enforce_admins": {"enabled": True},
                    },
                )
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        pr_review = next(
            f for f in findings if f.source_finding_id == "acme/platform:main:pr_review"
        )
        assert pr_review.severity == Severity.HIGH
        assert pr_review.status == FindingStatus.ACTIVE


# ── CODEOWNERS ───────────────────────────────────────────────────────────


class TestCodeowners:
    @pytest.mark.parametrize(
        "present_path",
        [".github/CODEOWNERS", "docs/CODEOWNERS", "CODEOWNERS"],
    )
    def test_present_at_any_canonical_path(self, present_path: str) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo())
            if req.url.path.endswith("/protection"):
                return httpx.Response(200, json=_protection_full())
            if "/contents/" in req.url.path:
                if req.url.path.endswith(present_path):
                    return httpx.Response(200, json={"path": present_path})
                return httpx.Response(404)
            return httpx.Response(404)

        with _make_collector(handler) as c:
            findings = c.collect()

        co = next(
            f for f in findings if f.source_finding_id == "acme/platform:codeowners"
        )
        assert co.status == FindingStatus.RESOLVED
        assert co.severity == Severity.INFORMATIONAL
        assert "SA-11" in co.control_ids

    def test_missing_codeowners_yields_medium_severity(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path == "/repos/acme/platform":
                return httpx.Response(200, json=_repo())
            if req.url.path.endswith("/protection"):
                return httpx.Response(200, json=_protection_full())
            return httpx.Response(404)  # no CODEOWNERS anywhere

        with _make_collector(handler) as c:
            findings = c.collect()

        co = next(
            f for f in findings
            if f.source_finding_id == "acme/platform:codeowners-missing"
        )
        assert co.severity == Severity.MEDIUM
        assert co.status == FindingStatus.ACTIVE


# ── Repo-read errors ─────────────────────────────────────────────────────


class TestRepoReadErrors:
    def test_repo_404_raises_collector_error(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"message": "Not Found"})

        with pytest.raises(Exception) as excinfo, _make_collector(handler) as c:
            c.collect()

        assert "Could not read repo" in str(excinfo.value)

    def test_constructor_rejects_empty_slug(self) -> None:
        with pytest.raises(Exception, match="owner \\+ repo"):
            GitHubCollector(owner="", repo="", token="x")

    def test_api_error_does_not_leak_token(self) -> None:
        """The GitHubApiError must not carry the Authorization header value."""

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": "Bad credentials"})

        http = httpx.Client(
            base_url="https://api.github.com",
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer ghp_MUST_NOT_APPEAR_IN_ERROR"},
        )
        client = GitHubClient(http=http)

        with pytest.raises(GitHubApiError) as excinfo:
            client.get_repo("acme", "platform")

        assert "MUST_NOT_APPEAR" not in str(excinfo.value)


# ── v0.10.0: compliance_status + OCSF round-trip ─────────────────────────


def _full_handler(
    *, private: bool = True, codeowners: bool = True
) -> Callable[[httpx.Request], httpx.Response]:
    """A handler serving a repo + full protection + (optional) CODEOWNERS."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/acme/platform":
            return httpx.Response(200, json=_repo(private=private))
        if req.url.path.endswith("/protection"):
            return httpx.Response(200, json=_protection_full())
        if "/contents/" in req.url.path:
            if codeowners and req.url.path.endswith(".github/CODEOWNERS"):
                return httpx.Response(
                    200, json={"path": ".github/CODEOWNERS"}
                )
            return httpx.Response(404)
        return httpx.Response(404)

    return handler


def test_private_repo_compliance_status_is_pass() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    with _make_collector(_full_handler(private=True)) as c:
        findings = c.collect()
    vis = next(
        f for f in findings if f.source_finding_id == "acme/platform:visibility"
    )
    assert vis.compliance_status == ComplianceStatus.PASS


def test_public_repo_compliance_status_is_warning() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    with _make_collector(_full_handler(private=False)) as c:
        findings = c.collect()
    vis = next(
        f for f in findings if f.source_finding_id == "acme/platform:visibility"
    )
    assert vis.compliance_status == ComplianceStatus.WARNING


def test_protected_branch_subfinding_compliance_status_is_pass() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    with _make_collector(_full_handler()) as c:
        findings = c.collect()
    pr_review = next(
        f
        for f in findings
        if f.source_finding_id == "acme/platform:main:pr_review"
    )
    assert pr_review.compliance_status == ComplianceStatus.PASS


def test_missing_codeowners_compliance_status_is_fail() -> None:
    from evidentia_core.models.finding import ComplianceStatus

    with _make_collector(_full_handler(codeowners=False)) as c:
        findings = c.collect()
    co = next(
        f
        for f in findings
        if f.source_finding_id == "acme/platform:codeowners-missing"
    )
    assert co.compliance_status == ComplianceStatus.FAIL


def test_github_findings_ocsf_round_trip() -> None:
    pytest.importorskip("py_ocsf_models")
    from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

    with _make_collector(_full_handler()) as c:
        findings = c.collect()
    assert findings
    for f in findings:
        assert finding_from_ocsf(finding_to_ocsf(f)) == f
