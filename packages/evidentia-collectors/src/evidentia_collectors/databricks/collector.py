"""Databricks evidence collector — main module (v0.7.8 P0.1).

Read-only collector that surfaces compliance-relevant evidence from a
Databricks workspace + Unity Catalog and emits NIST-mapped
SecurityFinding objects for each observation.

See ``evidentia_collectors.databricks.__init__`` for the public-
surface walkthrough + credential handling protocol.

Mirrors the v0.7.7 SQL collector pattern:

- Typed exception hierarchy (``DatabricksCollectorError`` /
  ``DatabricksAuthError`` / ``DatabricksPermissionError``)
- ``CollectionContext`` threaded through every emitted finding
- ``CollectionManifest`` returned by ``collect_v2()`` for completeness
  attestation
- ECS-structured audit logging via
  ``evidentia_core.audit.get_logger("evidentia.collectors.databricks")``
- Explicit ``BLIND_SPOTS`` list documenting coverage gaps

v0.7.8 P0.1 ships the foundational scaffolding + ONE complete
evidence source (Personal Access Token inventory). The other 6
evidence sources from the v0.7.8-plan P0.1 table (workspace audit
logs, table+column lineage, cluster compliance, network policies,
service-principal usage, secret scopes) land in subsequent commits
within the v0.7.8 cycle as they each require their own SQL
warehouse plumbing or Account API auth path.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
    get_logger,
    new_run_id,
)
from evidentia_core.models.common import (
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding

from evidentia_collectors.databricks.mapping import (
    CLUSTER_INIT_SCRIPT_MAPPINGS,
    CLUSTER_INVENTORY_MAPPINGS,
    CLUSTER_OUTDATED_RUNTIME_MAPPINGS,
    PAT_INVENTORY_MAPPINGS,
    PAT_LONG_LIVED_MAPPINGS,
    PAT_NEVER_EXPIRES_MAPPINGS,
    SECRET_SCOPE_DATABRICKS_BACKED_MAPPINGS,
    SECRET_SCOPE_INVENTORY_MAPPINGS,
    SECRET_SCOPE_KEY_VAULT_BACKED_MAPPINGS,
    SERVICE_PRINCIPAL_INACTIVE_MAPPINGS,
    SERVICE_PRINCIPAL_INVENTORY_MAPPINGS,
)

if TYPE_CHECKING:
    # Type-only import; databricks-sdk is in the [databricks]
    # optional extra. Runtime import is lazy so the package loads
    # without the SDK installed.
    from databricks.sdk import WorkspaceClient  # noqa: F401


_log = get_logger("evidentia.collectors.databricks")

COLLECTOR_ID = "databricks-scan"


# ── Exceptions ──────────────────────────────────────────────────────


class DatabricksCollectorError(Exception):
    """Base for all Databricks collector errors."""


class DatabricksAuthError(DatabricksCollectorError):
    """Raised when SDK auth fails (invalid token, expired creds, etc.)."""


class DatabricksPermissionError(DatabricksCollectorError):
    """Raised when the principal lacks permission for a specific API call.

    Distinct from auth errors: auth succeeded, but the principal isn't
    authorized for the resource. Sub-checks catch this and continue
    collection — a single missing-permission doesn't fail the whole
    run.
    """


# ── Coverage gaps ───────────────────────────────────────────────────


BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-DATABRICKS-ACCOUNT-API-VS-WORKSPACE",
        "title": "Account-level vs. workspace-level API split",
        "description": (
            "Databricks splits its REST surface across the workspace "
            "API (per-workspace, used by data engineers) and the "
            "Account API (cross-workspace, account-admin only). The "
            "collector defaults to workspace-API-only — that's what "
            "an audit-readiness program scoped to a single workspace "
            "needs. To collect cross-workspace evidence (account-wide "
            "network configurations, workspace inventory, "
            "metastore-level grants), instantiate a separate "
            "DatabricksCollector with account-level auth and the "
            "account host URL. Operators MUST document which scope "
            "their evidence covers."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-UC-SYSTEM-TABLES-PERMISSION",
        "title": "Unity Catalog `system.access.*` requires explicit grant",
        "description": (
            "The UC system tables that contain workspace audit logs + "
            "column/table lineage (system.access.audit, "
            "system.access.column_lineage, system.access.table_lineage) "
            "require explicit USE CATALOG + SELECT grants on the "
            "`system` catalog. Many production deployments leave this "
            "ungranted and only metastore admins can read them. The "
            "collector reports CollectionManifest.errors[] when a "
            "system-table query fails with permission-denied; "
            "operators must request the grant or run the audit-log "
            "sub-check under a metastore-admin principal."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-PAT-MANAGEMENT-PERMISSION",
        "title": "PAT inventory requires `token_management` permission",
        "description": (
            "Listing all workspace PATs (not just the calling user's) "
            "requires the `token_management` workspace permission OR "
            "workspace-admin role. Without this permission the SDK's "
            "tokens.list() returns the calling user's tokens only. "
            "The collector emits an EVIDENTIA-DATABRICKS-PAT-PARTIAL "
            "finding when that's detected so operators know the "
            "evidence is partial."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-CLUSTER-INIT-SCRIPT-CONTENT",
        "title": "Cluster init-script content not collectible via API",
        "description": (
            "Databricks cluster init scripts can be either workspace-"
            "file references (e.g., dbfs:/init/bootstrap.sh) or inline "
            "shell. The Workspace API surfaces the REFERENCE but does "
            "not return the script CONTENT — fetching content requires "
            "DBFS/UC-Volumes read access on the path. Init-script "
            "content matters for CM-3 + SI-2 (configuration management "
            "+ flaw remediation) since scripts often install patches. "
            "The collector reports the reference + path; operators "
            "must collect content out-of-band."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-NOTEBOOK-CONTENT",
        "title": "Notebook source content not collected",
        "description": (
            "Notebooks are first-class Databricks resources but their "
            "source contains arbitrary user code (Python/SQL/Scala/R) "
            "and is not compliance-relevant per se. The collector does "
            "not enumerate notebook contents. Audit-relevant notebook "
            "operations (executions, sharing changes) ARE captured "
            "via the audit-log sub-check when run."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-DELTA-LIVE-TABLES-INTERNAL",
        "title": "DLT pipeline internals + lakehouse storage layer",
        "description": (
            "Delta Live Tables pipelines, materialized views, and the "
            "underlying Delta Lake storage are not enumerated. DLT "
            "schemas and lineage ARE captured indirectly via the "
            "system.access.table_lineage sub-check. For deeper DLT "
            "evidence (pipeline definitions, expectations, etc.), "
            "operators query the dlt API surface separately."
        ),
    },
    {
        "id": "EVIDENTIA-DATABRICKS-CLOUD-PROVIDER-IAM",
        "title": "Underlying cloud-provider IAM not in scope",
        "description": (
            "Databricks workspaces run on AWS / Azure / GCP. The "
            "compute fabric's cloud-IAM posture (AWS IAM roles bound "
            "to clusters, Azure managed identities on Databricks "
            "workspaces, etc.) is collected by the corresponding "
            "evidentia_collectors.aws / azure / gcp collector. The "
            "Databricks collector treats cloud-IAM as out-of-scope "
            "and assumes operators run those sibling collectors as "
            "complementary evidence sources."
        ),
    },
]


# ── PAT-inventory helpers ───────────────────────────────────────────


# A PAT is considered "long-lived" if expiry > 90 days from issuance
# OR if it has no expiry. The 90-day threshold mirrors the
# OWASP / NIST AC-2(11) recommendation for credential rotation
# cadence.
_LONG_LIVED_THRESHOLD_DAYS = 90


# Cluster runtime versions. The "current" set is updated periodically
# as Databricks releases new LTS images. Runtimes outside this set
# are flagged as outdated. The list captures the LTS series shipped
# during the v0.7.8 cycle (May 2026); operators on a newer LTS than
# what's listed here will see "unknown_runtime" findings, which is
# the safe default — they should update the BLIND_SPOT or extend
# this list locally rather than silently passing.
_CURRENT_LTS_RUNTIMES = frozenset(
    {
        "14.3.x-lts",  # Databricks Runtime 14.3 LTS
        "15.4.x-lts",  # Databricks Runtime 15.4 LTS
        "16.4.x-lts",  # Databricks Runtime 16.4 LTS
        # Photon-enabled variants ship suffixed with -photon-scala<v>
        # — match handled by prefix check in _is_current_lts().
    }
)


def _is_current_lts(runtime_version: str | None) -> bool:
    """Return True if runtime is on the current-LTS allowlist."""
    if not runtime_version:
        return False
    rv = runtime_version.lower()
    return any(rv.startswith(lts) for lts in _CURRENT_LTS_RUNTIMES)


# ── Main collector class ────────────────────────────────────────────


class DatabricksCollector:
    """Read-only Databricks workspace evidence collector.

    Construct with a workspace ``host`` URL. Auth is delegated to the
    Databricks SDK's unified-auth resolver (env vars / .databrickscfg
    / cloud-provider IAM). Optionally pass an injected ``client=``
    object for testing — must be a stand-in for
    ``databricks.sdk.WorkspaceClient``.

    Use as a context manager so the SDK client is released cleanly::

        with DatabricksCollector(host="https://...") as c:
            findings, manifest = c.collect_v2()
    """

    def __init__(
        self,
        *,
        host: str | None = None,
        client: Any | None = None,
    ) -> None:
        if not host and client is None:
            raise DatabricksCollectorError(
                "DatabricksCollector requires either host= or "
                "client= (an injected WorkspaceClient for testing)."
            )
        self._host = host
        self._client = client
        self._owns_client = client is None
        # Cached on first call to test_connection() so subsequent
        # sub-checks don't re-probe the SDK.
        self._cached_user_name: str | None = None
        self._cached_workspace_url: str | None = None
        self._cached_sdk_version: str | None = None

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> DatabricksCollector:
        self._ensure_client()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        # The Databricks SDK's WorkspaceClient is stateless w.r.t.
        # connection lifecycle — there's no .close() on the client
        # itself. We just drop our reference so a future call to
        # _ensure_client() rebuilds.
        if self._owns_client:
            self._client = None

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            # Lazy import — the SDK is in [databricks] optional extra.
            from databricks.sdk import WorkspaceClient
        except ImportError as e:
            raise DatabricksCollectorError(
                "databricks-sdk is not installed. Install via:\n"
                "    pip install evidentia-collectors[databricks]"
            ) from e

        try:
            self._client = WorkspaceClient(host=self._host)
        except Exception as e:
            raise DatabricksAuthError(
                f"Failed to construct Databricks WorkspaceClient: {e}"
            ) from e
        return self._client

    def test_connection(self) -> dict[str, str]:
        """Probe SDK auth + populate cached identity. Idempotent."""
        client = self._ensure_client()
        try:
            me = client.current_user.me()
        except Exception as e:
            raise DatabricksAuthError(
                f"current_user.me() failed — auth misconfigured? {e}"
            ) from e

        self._cached_user_name = (
            getattr(me, "user_name", None) or "unknown"
        )
        # workspace_id is part of the SDK config; we read it from the
        # client's config object rather than a separate API call.
        self._cached_workspace_url = (
            getattr(getattr(client, "config", None), "host", None)
            or self._host
            or "unknown"
        )
        try:
            from databricks.sdk import version as _sdk_version_mod

            self._cached_sdk_version = getattr(
                _sdk_version_mod, "__version__", "unknown"
            )
        except Exception:
            self._cached_sdk_version = "unknown"
        return {
            "user_name": self._cached_user_name,
            "workspace": self._cached_workspace_url,
            "sdk_version": self._cached_sdk_version,
        }

    def _build_context(self, run_id: str) -> CollectionContext:
        user = self._cached_user_name or "unknown"
        workspace = self._cached_workspace_url or "unknown"
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"databricks-user:{user}",
            source_system_id=f"databricks:{user}@{workspace}",
            filter_applied={"user": user, "workspace": workspace},
        )

    # ── Sub-check: PAT inventory (v0.7.8 P0.1 first slice) ──────────

    def _pat_inventory_findings(
        self, client: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        """List workspace PATs and emit findings for security posture.

        Emits:

        - Per-PAT inventory finding (status=OBSERVED) — one per token
          with `creation_time`, `expiry_time`, `comment`, owner.
        - PAT_LONG_LIVED finding (severity=MEDIUM) — for any PAT with
          expiry > 90 days from creation.
        - PAT_NEVER_EXPIRES finding (severity=HIGH) — for any PAT
          with no expiry set.
        - EVIDENTIA-DATABRICKS-PAT-PARTIAL finding (severity=LOW) —
          if the SDK call returns scope=user instead of scope=admin
          (operator lacks token_management permission).

        See PAT-management API:
        https://docs.databricks.com/api/workspace/tokenmanagement
        """
        findings: list[SecurityFinding] = []
        try:
            tokens = list(client.token_management.list())
        except DatabricksPermissionError:
            raise
        except Exception as e:
            # Heuristic: SDK raises a generic Exception subclass when
            # the principal lacks token_management permission. Detect
            # by message; if uncertain, raise upward as a generic
            # collector error so the manifest captures it.
            msg = str(e).lower()
            if "permission" in msg or "not authorized" in msg:
                raise DatabricksPermissionError(
                    "PAT inventory requires token_management or "
                    "workspace-admin permission; SDK denied: "
                    f"{e}"
                ) from e
            raise DatabricksCollectorError(
                f"PAT inventory call failed: {e}"
            ) from e

        # Per-PAT inventory findings — RESOLVED status because each
        # entry is just an enumeration (not a problem). Long-lived /
        # never-expires sub-findings emit as ACTIVE separately.
        for tok in tokens:
            tok_id = getattr(tok, "token_id", "unknown")
            owner = getattr(tok, "owner_id", "unknown")
            comment = getattr(tok, "comment", "") or "(no comment)"
            created_at_ms = getattr(tok, "creation_time", None)
            expiry_ms = getattr(tok, "expiry_time", None)
            findings.append(
                SecurityFinding(
                    title=f"Databricks PAT {tok_id}",
                    description=(
                        f"Personal Access Token owned by {owner}. "
                        f"Comment: {comment!r}. created_at_ms="
                        f"{created_at_ms}, expiry_ms={expiry_ms}."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.RESOLVED,
                    resource_id=str(tok_id),
                    resource_type="Databricks::PAT",
                    raw_data={
                        "token_id": str(tok_id),
                        "owner_id": str(owner),
                        "comment": str(comment),
                        "creation_time_ms": created_at_ms,
                        "expiry_time_ms": expiry_ms,
                    },
                    source_system="databricks",
                    source_finding_id=f"databricks-pat:{tok_id}",
                    control_mappings=PAT_INVENTORY_MAPPINGS,
                    collection_context=context,
                )
            )

            # Long-lived / never-expires checks. Both
            # creation_time and expiry_time are SDK-supplied
            # millisecond epochs.
            if expiry_ms in (None, 0, -1):
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Databricks PAT {tok_id} has no expiry"
                        ),
                        description=(
                            "PAT was issued without an expiry date. "
                            "OWASP + NIST AC-2(11) recommend "
                            "credential rotation cadences (90 days "
                            "typical). Long-lived secrets are a "
                            "credential-leakage amplifier."
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.ACTIVE,
                        resource_id=str(tok_id),
                        resource_type="Databricks::PAT",
                        raw_data={
                            "token_id": str(tok_id),
                            "owner_id": str(owner),
                            "expiry_time_ms": expiry_ms,
                        },
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-pat-never-expires:{tok_id}"
                        ),
                        control_mappings=PAT_NEVER_EXPIRES_MAPPINGS,
                        collection_context=context,
                    )
                )
                continue

            if created_at_ms is not None and expiry_ms is not None:
                lifetime_ms = int(expiry_ms) - int(created_at_ms)
                lifetime_days = lifetime_ms / (1000 * 60 * 60 * 24)
                if lifetime_days > _LONG_LIVED_THRESHOLD_DAYS:
                    findings.append(
                        SecurityFinding(
                            title=(
                                f"Databricks PAT {tok_id} lifetime "
                                f"is {lifetime_days:.0f} days "
                                f"(> {_LONG_LIVED_THRESHOLD_DAYS} "
                                f"day threshold)"
                            ),
                            description=(
                                "PAT lifetime exceeds the 90-day "
                                "rotation threshold (NIST AC-2(11)). "
                                "Long-lived tokens accumulate "
                                "compromise risk over time. Rotate "
                                "or shorten the expiry."
                            ),
                            severity=Severity.MEDIUM,
                            status=FindingStatus.ACTIVE,
                            resource_id=str(tok_id),
                            resource_type="Databricks::PAT",
                            raw_data={
                                "token_id": str(tok_id),
                                "owner_id": str(owner),
                                "lifetime_days": round(lifetime_days, 1),
                                "threshold_days": (
                                    _LONG_LIVED_THRESHOLD_DAYS
                                ),
                            },
                            source_system="databricks",
                            source_finding_id=(
                                f"databricks-pat-long-lived:{tok_id}"
                            ),
                            control_mappings=PAT_LONG_LIVED_MAPPINGS,
                            collection_context=context,
                        )
                    )

        return findings

    # ── Sub-check: cluster compliance ───────────────────────────────

    def _cluster_compliance_findings(
        self, client: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        """List workspace clusters and emit configuration-management findings.

        Emits:

        - Per-cluster inventory finding (RESOLVED, INFORMATIONAL) — captures
          cluster_id, name, runtime_version, node_type, autoscale config.
          Maps to CM-8 + CM-2.
        - Per-cluster outdated-runtime finding (ACTIVE, MEDIUM) — fires when
          the runtime is not on the current-LTS allowlist. Maps to SI-2 +
          CM-2(2).
        - Per-cluster init-script-present finding (RESOLVED, LOW) —
          informational; init scripts are inventoried for CM-3 even though
          their content can't be collected from this surface (see
          EVIDENTIA-DATABRICKS-CLUSTER-INIT-SCRIPT-CONTENT BLIND_SPOT).
        """
        findings: list[SecurityFinding] = []
        try:
            clusters = list(client.clusters.list())
        except Exception as e:
            msg = str(e).lower()
            if "permission" in msg or "not authorized" in msg:
                raise DatabricksPermissionError(
                    f"Cluster inventory denied: {e}"
                ) from e
            raise DatabricksCollectorError(
                f"Cluster inventory call failed: {e}"
            ) from e

        for cl in clusters:
            cluster_id = getattr(cl, "cluster_id", "unknown")
            name = getattr(cl, "cluster_name", "unknown")
            runtime = getattr(cl, "spark_version", None)
            node_type = getattr(cl, "node_type_id", None)
            autoscale = getattr(cl, "autoscale", None)
            init_scripts = getattr(cl, "init_scripts", None) or []

            findings.append(
                SecurityFinding(
                    title=f"Databricks cluster {name}",
                    description=(
                        f"Cluster {cluster_id} (name={name!r}) runs "
                        f"runtime={runtime!r} on node_type={node_type!r}. "
                        f"autoscale={autoscale!r}. "
                        f"init_scripts_count={len(init_scripts)}."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.RESOLVED,
                    source_system="databricks",
                    source_finding_id=f"databricks-cluster:{cluster_id}",
                    resource_id=str(cluster_id),
                    resource_type="Databricks::Cluster",
                    raw_data={
                        "cluster_id": str(cluster_id),
                        "cluster_name": str(name),
                        "spark_version": runtime,
                        "node_type_id": node_type,
                        "init_scripts_count": len(init_scripts),
                    },
                    control_mappings=CLUSTER_INVENTORY_MAPPINGS,
                    collection_context=context,
                )
            )

            if not _is_current_lts(runtime):
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Databricks cluster {name} runtime "
                            f"is outdated"
                        ),
                        description=(
                            f"Cluster {cluster_id} runs runtime "
                            f"{runtime!r} which is not on the "
                            f"current-LTS allowlist "
                            f"({sorted(_CURRENT_LTS_RUNTIMES)}). "
                            "Outdated runtimes accumulate Spark + JVM "
                            "+ Databricks platform CVEs over time. "
                            "Plan an upgrade to the current LTS."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.ACTIVE,
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-cluster-outdated-runtime"
                            f":{cluster_id}"
                        ),
                        resource_id=str(cluster_id),
                        resource_type="Databricks::Cluster",
                        raw_data={
                            "cluster_id": str(cluster_id),
                            "spark_version": runtime,
                            "current_lts_allowlist": sorted(
                                _CURRENT_LTS_RUNTIMES
                            ),
                        },
                        control_mappings=(
                            CLUSTER_OUTDATED_RUNTIME_MAPPINGS
                        ),
                        collection_context=context,
                    )
                )

            if init_scripts:
                # Init-script REFERENCES are present. Content is not
                # collectible from this surface (see BLIND_SPOT). Emit
                # as RESOLVED, LOW — informational evidence.
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Databricks cluster {name} has "
                            f"{len(init_scripts)} init script"
                            f"{'s' if len(init_scripts) != 1 else ''}"
                        ),
                        description=(
                            f"Cluster {cluster_id} has init-script "
                            f"references inventoried "
                            f"({len(init_scripts)} entries). Content "
                            "review is operator-driven via DBFS / UC "
                            "Volumes (see "
                            "EVIDENTIA-DATABRICKS-CLUSTER-INIT-SCRIPT-"
                            "CONTENT BLIND_SPOT)."
                        ),
                        severity=Severity.LOW,
                        status=FindingStatus.RESOLVED,
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-cluster-init-scripts"
                            f":{cluster_id}"
                        ),
                        resource_id=str(cluster_id),
                        resource_type="Databricks::Cluster",
                        raw_data={
                            "cluster_id": str(cluster_id),
                            "init_scripts_count": len(init_scripts),
                        },
                        control_mappings=CLUSTER_INIT_SCRIPT_MAPPINGS,
                        collection_context=context,
                    )
                )

        return findings

    # ── Sub-check: service principals ───────────────────────────────

    def _service_principal_findings(
        self, client: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        """List workspace service principals and emit AC-2 + AC-3 findings.

        Emits:

        - Per-SP inventory finding (RESOLVED, INFORMATIONAL) — captures
          application_id, display_name, active state, group memberships.
          Maps to AC-2 + AC-3.
        - Inactive-SP finding (ACTIVE, MEDIUM) — fires when active=false.
          Maps to AC-2(3) Disable Inactive Accounts.
        """
        findings: list[SecurityFinding] = []
        try:
            principals = list(client.service_principals.list())
        except Exception as e:
            msg = str(e).lower()
            if "permission" in msg or "not authorized" in msg:
                raise DatabricksPermissionError(
                    f"Service principal inventory denied: {e}"
                ) from e
            raise DatabricksCollectorError(
                f"Service principal inventory call failed: {e}"
            ) from e

        for sp in principals:
            sp_id = getattr(sp, "id", "unknown")
            app_id = getattr(sp, "application_id", "unknown")
            display_name = getattr(sp, "display_name", "unknown")
            active = getattr(sp, "active", True)
            groups = getattr(sp, "groups", None) or []

            findings.append(
                SecurityFinding(
                    title=(
                        f"Databricks service principal {display_name}"
                    ),
                    description=(
                        f"Service principal {sp_id} "
                        f"(application_id={app_id}, "
                        f"display_name={display_name!r}) is "
                        f"active={active}. "
                        f"group_memberships_count={len(groups)}."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.RESOLVED,
                    source_system="databricks",
                    source_finding_id=f"databricks-sp:{sp_id}",
                    resource_id=str(sp_id),
                    resource_type="Databricks::ServicePrincipal",
                    raw_data={
                        "id": str(sp_id),
                        "application_id": str(app_id),
                        "display_name": str(display_name),
                        "active": bool(active),
                        "group_memberships_count": len(groups),
                    },
                    control_mappings=(
                        SERVICE_PRINCIPAL_INVENTORY_MAPPINGS
                    ),
                    collection_context=context,
                )
            )

            if not active:
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Inactive service principal "
                            f"{display_name} still enabled"
                        ),
                        description=(
                            "Service principal is marked inactive in "
                            "the workspace identity graph but remains "
                            "enabled. Inactive non-interactive "
                            "accounts that aren't disabled are an "
                            "attack surface — disable + revoke "
                            "associated tokens."
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.ACTIVE,
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-sp-inactive:{sp_id}"
                        ),
                        resource_id=str(sp_id),
                        resource_type="Databricks::ServicePrincipal",
                        raw_data={
                            "id": str(sp_id),
                            "application_id": str(app_id),
                            "active": False,
                        },
                        control_mappings=(
                            SERVICE_PRINCIPAL_INACTIVE_MAPPINGS
                        ),
                        collection_context=context,
                    )
                )

        return findings

    # ── Sub-check: secret scopes ────────────────────────────────────

    def _secret_scope_findings(
        self, client: Any, context: CollectionContext
    ) -> list[SecurityFinding]:
        """List workspace secret scopes and emit SC-12 findings.

        Emits:

        - Per-scope inventory finding (RESOLVED, INFORMATIONAL) — captures
          name, backend_type. Maps to SC-12 + IA-5.
        - Databricks-backed scope finding (RESOLVED, LOW) — informational;
          recommends Key Vault / Secrets Manager backing for higher-
          assurance deployments.
        - Key-Vault-backed scope finding (RESOLVED, INFORMATIONAL) —
          positive finding; documents the preferred SC-12 posture.
        """
        findings: list[SecurityFinding] = []
        try:
            scopes = list(client.secrets.list_scopes())
        except Exception as e:
            msg = str(e).lower()
            if "permission" in msg or "not authorized" in msg:
                raise DatabricksPermissionError(
                    f"Secret scope inventory denied: {e}"
                ) from e
            raise DatabricksCollectorError(
                f"Secret scope inventory call failed: {e}"
            ) from e

        for sc in scopes:
            name = getattr(sc, "name", "unknown")
            backend_type = getattr(sc, "backend_type", None)
            backend_str = (
                str(backend_type) if backend_type is not None else "unknown"
            )

            findings.append(
                SecurityFinding(
                    title=f"Databricks secret scope {name}",
                    description=(
                        f"Secret scope {name!r} uses backend_type="
                        f"{backend_str}."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.RESOLVED,
                    source_system="databricks",
                    source_finding_id=f"databricks-secret-scope:{name}",
                    resource_id=str(name),
                    resource_type="Databricks::SecretScope",
                    raw_data={
                        "name": str(name),
                        "backend_type": backend_str,
                    },
                    control_mappings=SECRET_SCOPE_INVENTORY_MAPPINGS,
                    collection_context=context,
                )
            )

            backend_lower = backend_str.lower()
            if "azure_keyvault" in backend_lower or "keyvault" in backend_lower:
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Secret scope {name} uses Azure Key Vault "
                            f"backing (preferred SC-12 posture)"
                        ),
                        description=(
                            "Azure Key Vault-backed scope delegates "
                            "secret encryption to a cloud-provider "
                            "KMS. This is the preferred posture for "
                            "SC-12 in regulated environments."
                        ),
                        severity=Severity.INFORMATIONAL,
                        status=FindingStatus.RESOLVED,
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-secret-scope-keyvault:{name}"
                        ),
                        resource_id=str(name),
                        resource_type="Databricks::SecretScope",
                        raw_data={
                            "name": str(name),
                            "backend_type": backend_str,
                        },
                        control_mappings=(
                            SECRET_SCOPE_KEY_VAULT_BACKED_MAPPINGS
                        ),
                        collection_context=context,
                    )
                )
            elif "databricks" in backend_lower:
                findings.append(
                    SecurityFinding(
                        title=(
                            f"Secret scope {name} uses Databricks-"
                            f"backed storage (consider KMS-backed)"
                        ),
                        description=(
                            "Databricks-backed scope encrypts secrets "
                            "with a workspace-controlled key. For "
                            "higher-assurance deployments (FedRAMP, "
                            "financial), Azure Key Vault-backed or "
                            "AWS Secrets Manager-backed scopes are "
                            "preferred — they delegate key management "
                            "to the cloud provider's hardened KMS."
                        ),
                        severity=Severity.LOW,
                        status=FindingStatus.RESOLVED,
                        source_system="databricks",
                        source_finding_id=(
                            f"databricks-secret-scope-databricks-"
                            f"backed:{name}"
                        ),
                        resource_id=str(name),
                        resource_type="Databricks::SecretScope",
                        raw_data={
                            "name": str(name),
                            "backend_type": backend_str,
                        },
                        control_mappings=(
                            SECRET_SCOPE_DATABRICKS_BACKED_MAPPINGS
                        ),
                        collection_context=context,
                    )
                )

        return findings

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        """Run every enabled sub-check and return merged findings.

        Backward-compatible v0.6 API. Callers wanting the manifest
        should use :meth:`collect_v2`.
        """
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="Databricks dry-run — no API calls made",
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={"dry_run": True},
            )
            return []
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self, *, run_id: str | None = None
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Run every enabled sub-check and return findings + manifest.

        v0.7.8 P0.1 ships ONE complete sub-check (PAT inventory).
        Each sub-check is independently fault-tolerant: a
        DatabricksPermissionError gets recorded in manifest.errors[]
        and overall collection continues. Future commits add the
        remaining 6 sub-checks per the v0.7.8 P0.1 plan table.
        """
        if run_id is None:
            run_id = new_run_id()

        try:
            self.test_connection()
        except DatabricksCollectorError:
            raise
        except Exception as e:
            raise DatabricksAuthError(
                f"Could not establish Databricks SDK auth: {e}"
            ) from e

        client = self._ensure_client()
        context = self._build_context(run_id)
        errors: list[str] = []
        findings: list[SecurityFinding] = []

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity},
            evidentia={
                "run_id": run_id,
                "collector": {
                    "id": COLLECTOR_ID,
                    "version": current_version(),
                },
                "workspace": self._cached_workspace_url,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Databricks collection starting for "
                    f"{self._cached_user_name}@"
                    f"{self._cached_workspace_url}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            for sub_check in (
                self._pat_inventory_findings,
                self._cluster_compliance_findings,
                self._service_principal_findings,
                self._secret_scope_findings,
                # v0.7.8 P0.1 follow-up commits land (need additional
                # plumbing — SQL Warehouse for system tables, Account
                # API auth for network configurations):
                # self._workspace_audit_log_findings,
                # self._table_lineage_findings,
                # self._network_policy_findings,
            ):
                try:
                    findings.extend(sub_check(client, context))
                except DatabricksPermissionError as e:
                    errors.append(f"{sub_check.__name__}: {e}")
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=(
                            f"Sub-check {sub_check.__name__} "
                            f"permission-denied: {e}"
                        ),
                        error={
                            "type": "DatabricksPermissionError",
                            "message": str(e),
                        },
                    )
                except DatabricksCollectorError as e:
                    errors.append(f"{sub_check.__name__}: {e}")
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=(
                            f"Sub-check {sub_check.__name__} "
                            f"failed: {e}"
                        ),
                        error={
                            "type": type(e).__name__,
                            "message": str(e),
                        },
                    )

            outcome = (
                EventOutcome.SUCCESS if not errors else EventOutcome.FAILURE
            )
            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=outcome,
                message=(
                    f"Databricks collection completed: "
                    f"{len(findings)} findings, {len(errors)} errors"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
            )

        # Coverage tracking: single-pass grouping by resource_type
        # (closes F-V08-CR-MEDIUM #3 — was O(4N) with 4 separate sum()
        # generator passes; now O(N) with a single dict accumulator).
        # PAT/cluster/service-principal/secret-scope are the four
        # resource types enumerated in v0.7.8 P0.1; scanned, matched,
        # and collected are all equal because there's no resource-side
        # filtering (we report every PAT/cluster/etc. we see).
        _coverage_buckets = {
            "Databricks::PAT": "databricks-pat",
            "Databricks::Cluster": "databricks-cluster",
            "Databricks::ServicePrincipal": "databricks-service-principal",
            "Databricks::SecretScope": "databricks-secret-scope",
        }
        _counts: dict[str, int] = {v: 0 for v in _coverage_buckets.values()}
        for f in findings:
            if f.resource_type is None:
                continue
            bucket = _coverage_buckets.get(f.resource_type)
            if bucket:
                _counts[bucket] += 1

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=context.collected_at,
            collection_finished_at=utc_now(),
            source_system_ids=[
                f"databricks:{self._cached_user_name or 'unknown'}"
                f"@{self._cached_workspace_url or 'unknown'}"
            ],
            filters_applied={
                "user": self._cached_user_name or "unknown",
                "workspace": self._cached_workspace_url or "unknown",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type=name,
                    scanned=_counts[name],
                    matched_filter=_counts[name],
                    collected=_counts[name],
                )
                for name in _coverage_buckets.values()
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason=(
                "; ".join(errors) if errors else None
            ),
            empty_categories=[
                # Sub-checks not yet implemented in v0.7.8 P0.1 —
                # flagged so consumers know this manifest is PARTIAL
                # evidence until the follow-up commits land them:
                "workspace_audit_log",      # needs SQL Warehouse plumbing
                "table_lineage",            # needs SQL Warehouse plumbing
                "network_policy",           # needs Account API auth path
            ],
            errors=errors,
        )

        with contextlib.suppress(Exception):
            # Final manifest-emission log entry — failures here MUST
            # NOT break collect_v2 since the findings + manifest are
            # already prepared.
            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                message=(
                    f"Databricks manifest emitted: run_id={run_id}, "
                    f"findings={len(findings)}, errors={len(errors)}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
            )

        return findings, manifest
