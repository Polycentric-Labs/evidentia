"""Google Workspace evidence collector for Evidentia (v0.13 batch 7).

Read-only collector that surfaces compliance-relevant evidence about a
Google Workspace tenant's identity posture (Directory user inventory,
inactive accounts, admin accounts, 2-Step Verification enrollment) and
recent login activity (Reports API), emitting NIST-mapped
SecurityFinding objects.

Public surface::

    from evidentia_collectors.google_workspace import GoogleWorkspaceCollector

    collector = GoogleWorkspaceCollector(
        api_token=os.environ["GOOGLE_WORKSPACE_ACCESS_TOKEN"],
        customer="my_customer",
    )
    findings = collector.collect()

Or via context manager::

    with GoogleWorkspaceCollector(api_token=..., customer=...) as c:
        findings, manifest = c.collect_v2()

The access token is sourced from the ``GOOGLE_WORKSPACE_ACCESS_TOKEN``
env var per the secret-handling protocol. It MUST be a pre-minted
OAuth 2.0 access token carrying two read-only scopes:

- ``https://www.googleapis.com/auth/admin.directory.user.readonly``
  (Directory user inventory, admin roles, 2-Step Verification status)
- ``https://www.googleapis.com/auth/admin.reports.audit.readonly``
  (login activity; only requested when ``login_window_days > 0``)

The collector never mints or refreshes a token itself: an access token
minted through a service-account domain-wide-delegation flow (which
would refresh automatically) is a later, optional extra, not something
this collector does today.

Driver: ``httpx`` (already a core Evidentia dependency, no optional
extra needed for the HTTP client).
"""

from evidentia_collectors.google_workspace.collector import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    GoogleWorkspaceAuthError,
    GoogleWorkspaceCollector,
    GoogleWorkspaceCollectorError,
    GoogleWorkspaceConnectionError,
    GoogleWorkspaceQueryError,
)

__all__ = [
    "BLIND_SPOTS",
    "COLLECTOR_ID",
    "GoogleWorkspaceAuthError",
    "GoogleWorkspaceCollector",
    "GoogleWorkspaceCollectorError",
    "GoogleWorkspaceConnectionError",
    "GoogleWorkspaceQueryError",
]
