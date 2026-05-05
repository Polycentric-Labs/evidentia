"""Unit tests for the Databricks evidence collector (v0.7.8 P0.1).

Mocks the Databricks SDK's WorkspaceClient — no real Databricks
workspace required. Integration tests against a real workspace would
require workspace credentials + a non-trivial fixture; deferred to a
future v0.7.8 P0.x bucket as a follow-up to this scaffolding commit.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from evidentia_collectors.databricks import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    DatabricksAuthError,
    DatabricksCollector,
    DatabricksCollectorError,
    DatabricksPermissionError,
)
from evidentia_core.models.common import Severity
from evidentia_core.models.finding import FindingStatus

# ── Mock SDK infrastructure ─────────────────────────────────────────


def _make_mock_pat(
    *,
    token_id: str,
    owner_id: str = "user-42",
    comment: str = "CI-build token",
    creation_time: int | None = 1700000000000,  # 2023-11-14
    expiry_time: int | None = 1707776000000,  # ~90 days later
) -> Any:
    """Build a minimal SDK-shaped TokenInfo stand-in."""
    tok = MagicMock()
    tok.token_id = token_id
    tok.owner_id = owner_id
    tok.comment = comment
    tok.creation_time = creation_time
    tok.expiry_time = expiry_time
    return tok


def _make_mock_cluster(
    *,
    cluster_id: str,
    cluster_name: str = "test-cluster",
    spark_version: str = "15.4.x-lts-scala2.12",
    node_type_id: str = "i3.xlarge",
    init_scripts: list[Any] | None = None,
) -> Any:
    cl = MagicMock()
    cl.cluster_id = cluster_id
    cl.cluster_name = cluster_name
    cl.spark_version = spark_version
    cl.node_type_id = node_type_id
    cl.autoscale = None
    cl.init_scripts = init_scripts or []
    return cl


def _make_mock_sp(
    *,
    sp_id: str,
    application_id: str = "00000000-0000-0000-0000-000000000000",
    display_name: str = "test-sp",
    active: bool = True,
    groups: list[Any] | None = None,
) -> Any:
    sp = MagicMock()
    sp.id = sp_id
    sp.application_id = application_id
    sp.display_name = display_name
    sp.active = active
    sp.groups = groups or []
    return sp


def _make_mock_secret_scope(
    *,
    name: str,
    backend_type: str = "DATABRICKS",
) -> Any:
    sc = MagicMock()
    sc.name = name
    sc.backend_type = backend_type
    return sc


def _make_mock_client(
    *,
    user_name: str = "alice@example.com",
    pats: list[Any] | None = None,
    pat_list_raises: Exception | None = None,
    clusters: list[Any] | None = None,
    cluster_list_raises: Exception | None = None,
    service_principals: list[Any] | None = None,
    sp_list_raises: Exception | None = None,
    secret_scopes: list[Any] | None = None,
    scope_list_raises: Exception | None = None,
) -> Any:
    """Build a minimal WorkspaceClient stand-in.

    The collector calls `client.current_user.me()` (auth probe),
    `client.token_management.list()` (PAT inventory),
    `client.clusters.list()` (cluster compliance),
    `client.service_principals.list()` (SP inventory), and
    `client.secrets.list_scopes()` (secret scopes).
    """
    client = MagicMock()
    client.current_user.me.return_value = MagicMock(user_name=user_name)
    client.config = MagicMock(host="https://test.cloud.databricks.com")

    if pat_list_raises is not None:
        client.token_management.list.side_effect = pat_list_raises
    else:
        client.token_management.list.return_value = pats or []

    if cluster_list_raises is not None:
        client.clusters.list.side_effect = cluster_list_raises
    else:
        client.clusters.list.return_value = clusters or []

    if sp_list_raises is not None:
        client.service_principals.list.side_effect = sp_list_raises
    else:
        client.service_principals.list.return_value = (
            service_principals or []
        )

    if scope_list_raises is not None:
        client.secrets.list_scopes.side_effect = scope_list_raises
    else:
        client.secrets.list_scopes.return_value = secret_scopes or []

    return client


# ── Construction tests ─────────────────────────────────────────────


class TestConstruction:
    def test_requires_host_or_client(self) -> None:
        with pytest.raises(
            DatabricksCollectorError, match="requires either host"
        ):
            DatabricksCollector()

    def test_accepts_injected_client(self) -> None:
        c = DatabricksCollector(client=_make_mock_client())
        assert c is not None

    def test_accepts_host_only(self) -> None:
        # Host-only (no client) is valid — SDK is constructed lazily
        # in test_connection() / collect_v2() so this should not
        # raise here even if databricks-sdk isn't installed.
        c = DatabricksCollector(host="https://test.databricks.com")
        assert c is not None


# ── Public-surface tests ───────────────────────────────────────────


class TestPublicSurface:
    def test_collector_id_constant(self) -> None:
        assert COLLECTOR_ID == "databricks-scan"

    def test_blind_spots_documented(self) -> None:
        # v0.7.8 P0.1 ships 7 BLIND_SPOTS entries covering the
        # account-vs-workspace split, UC system-table grants, PAT
        # management permission, init-script content, notebook
        # source content, DLT internals, and cloud-IAM scope.
        assert len(BLIND_SPOTS) == 7
        for entry in BLIND_SPOTS:
            assert {"id", "title", "description"} <= set(entry.keys())
            assert entry["id"].startswith("EVIDENTIA-DATABRICKS-")
            assert len(entry["description"]) > 100  # substantive prose

    def test_exception_hierarchy(self) -> None:
        assert issubclass(DatabricksAuthError, DatabricksCollectorError)
        assert issubclass(
            DatabricksPermissionError, DatabricksCollectorError
        )


# ── PAT inventory sub-check tests ──────────────────────────────────


class TestPATInventory:
    def test_emits_one_inventory_finding_per_pat(self) -> None:
        pats = [
            _make_mock_pat(token_id="tok-1"),
            _make_mock_pat(token_id="tok-2"),
            _make_mock_pat(token_id="tok-3"),
        ]
        client = _make_mock_client(pats=pats)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        # 3 inventory findings (one per PAT). The mock PATs all have
        # creation/expiry within the 90-day window so no long-lived
        # findings emit.
        inventory_findings = [
            f for f in findings if f.title.startswith("Databricks PAT ")
            and "lifetime" not in f.title and "no expiry" not in f.title
        ]
        assert len(inventory_findings) == 3
        for f in inventory_findings:
            # Inventory findings are RESOLVED status (informational —
            # they're enumerations, not problems).
            assert f.status == FindingStatus.RESOLVED
            assert f.severity == Severity.INFORMATIONAL
            assert f.resource_type == "Databricks::PAT"

    def test_long_lived_pat_emits_active_finding(self) -> None:
        # 180-day lifetime: creation = 0ms, expiry = 180 days * msPerDay.
        ms_per_day = 1000 * 60 * 60 * 24
        pat = _make_mock_pat(
            token_id="tok-longlived",
            creation_time=0,
            expiry_time=180 * ms_per_day,
        )
        client = _make_mock_client(pats=[pat])
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        long_lived = [f for f in findings if "lifetime" in f.title]
        assert len(long_lived) == 1
        f = long_lived[0]
        assert f.severity == Severity.MEDIUM
        assert f.status == FindingStatus.ACTIVE
        assert f.raw_data["lifetime_days"] == 180.0
        assert f.raw_data["threshold_days"] == 90

    def test_never_expires_pat_emits_high_finding(self) -> None:
        # SDK can return None or 0 or -1 for "no expiry"; cover the
        # None case here.
        pat = _make_mock_pat(
            token_id="tok-permanent",
            expiry_time=None,
        )
        client = _make_mock_client(pats=[pat])
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        no_expiry = [f for f in findings if "no expiry" in f.title]
        assert len(no_expiry) == 1
        f = no_expiry[0]
        assert f.severity == Severity.HIGH
        assert f.status == FindingStatus.ACTIVE

    def test_zero_pats_yields_no_findings(self) -> None:
        client = _make_mock_client(pats=[])
        with DatabricksCollector(client=client) as c:
            findings, manifest = c.collect_v2()

        assert findings == []
        assert manifest.is_complete is True
        assert manifest.errors == []

    def test_permission_denied_recorded_in_manifest(self) -> None:
        # Simulate the SDK raising a permission-denied error —
        # the collector heuristic-detects this from the message and
        # records it in manifest.errors[] without aborting the run.
        pat_err = RuntimeError(
            "PERMISSION_DENIED: token_management permission required"
        )
        client = _make_mock_client(pat_list_raises=pat_err)
        with DatabricksCollector(client=client) as c:
            findings, manifest = c.collect_v2()

        assert findings == []
        assert manifest.is_complete is False
        assert any(
            "permission" in err.lower() for err in manifest.errors
        )


# ── Manifest tests ────────────────────────────────────────────────


class TestManifest:
    def test_manifest_lists_pat_resource_type(self) -> None:
        client = _make_mock_client(
            pats=[_make_mock_pat(token_id="tok-x")]
        )
        with DatabricksCollector(client=client) as c:
            _findings, manifest = c.collect_v2()

        assert manifest.collector_id == COLLECTOR_ID
        resource_types = [
            cc.resource_type for cc in manifest.coverage_counts
        ]
        assert "databricks-pat" in resource_types

    def test_manifest_flags_other_sub_checks_as_empty(self) -> None:
        # v0.7.8 P0.1 (post-3-follow-up-sources): PAT + cluster + SP +
        # secret-scope all implemented; only audit log + lineage +
        # network policy remain in empty_categories.
        client = _make_mock_client(pats=[])
        with DatabricksCollector(client=client) as c:
            _findings, manifest = c.collect_v2()

        expected_pending = {
            "workspace_audit_log",
            "table_lineage",
            "network_policy",
        }
        assert expected_pending == set(manifest.empty_categories)


# ── Lifecycle tests ───────────────────────────────────────────────


class TestLifecycle:
    def test_context_manager_lifecycle(self) -> None:
        client = _make_mock_client()
        with DatabricksCollector(client=client) as c:
            assert c is not None
        # SDK client is stateless — close() is a no-op for injected
        # clients (since _owns_client is False), but it must not
        # raise.

    def test_dry_run_yields_empty_findings(self) -> None:
        client = _make_mock_client(
            pats=[_make_mock_pat(token_id="tok-x")]
        )
        c = DatabricksCollector(client=client)
        findings = c.collect(dry_run=True)
        assert findings == []
        # SDK should NOT have been called in dry-run mode.
        assert not client.current_user.me.called
        assert not client.token_management.list.called

    def test_test_connection_caches_user(self) -> None:
        client = _make_mock_client(user_name="bob@example.com")
        c = DatabricksCollector(client=client)
        info = c.test_connection()
        assert info["user_name"] == "bob@example.com"
        # Idempotent — second call doesn't re-probe (we cached).
        info2 = c.test_connection()
        assert info2["user_name"] == info["user_name"]


# ── Cluster compliance sub-check tests ────────────────────────────


class TestClusterCompliance:
    def test_inventory_finding_per_cluster(self) -> None:
        clusters = [
            _make_mock_cluster(cluster_id="c-1"),
            _make_mock_cluster(cluster_id="c-2"),
        ]
        client = _make_mock_client(clusters=clusters)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        cluster_inventory = [
            f
            for f in findings
            if f.resource_type == "Databricks::Cluster"
            and f.title.startswith("Databricks cluster ")
            and "outdated" not in f.title
            and "init script" not in f.title
        ]
        assert len(cluster_inventory) == 2

    def test_outdated_runtime_emits_active_finding(self) -> None:
        clusters = [
            _make_mock_cluster(
                cluster_id="c-old",
                spark_version="11.3.x-lts-scala2.12",  # not on allowlist
            ),
        ]
        client = _make_mock_client(clusters=clusters)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        outdated = [f for f in findings if "outdated" in f.title]
        assert len(outdated) == 1
        assert outdated[0].severity == Severity.MEDIUM
        assert outdated[0].status == FindingStatus.ACTIVE

    def test_current_lts_does_not_emit_outdated(self) -> None:
        clusters = [
            _make_mock_cluster(
                cluster_id="c-current",
                spark_version="15.4.x-lts-scala2.12",
            ),
            _make_mock_cluster(
                cluster_id="c-also-current",
                spark_version="16.4.x-lts-photon-scala2.12",
            ),
        ]
        client = _make_mock_client(clusters=clusters)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        assert not [f for f in findings if "outdated" in f.title]

    def test_init_scripts_emit_inventory_finding(self) -> None:
        clusters = [
            _make_mock_cluster(
                cluster_id="c-with-init",
                init_scripts=[
                    MagicMock(
                        dbfs=MagicMock(
                            destination="dbfs:/init/bootstrap.sh"
                        )
                    ),
                    MagicMock(
                        dbfs=MagicMock(destination="dbfs:/init/perms.sh")
                    ),
                ],
            ),
        ]
        client = _make_mock_client(clusters=clusters)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        init_findings = [f for f in findings if "init script" in f.title]
        assert len(init_findings) == 1
        assert init_findings[0].severity == Severity.LOW
        assert init_findings[0].raw_data["init_scripts_count"] == 2


# ── Service principal sub-check tests ─────────────────────────────


class TestServicePrincipal:
    def test_inventory_finding_per_sp(self) -> None:
        sps = [
            _make_mock_sp(sp_id="sp-1", display_name="ci-runner"),
            _make_mock_sp(sp_id="sp-2", display_name="airflow"),
        ]
        client = _make_mock_client(service_principals=sps)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        sp_inventory = [
            f
            for f in findings
            if f.resource_type == "Databricks::ServicePrincipal"
            and "Inactive" not in f.title
        ]
        assert len(sp_inventory) == 2

    def test_inactive_sp_emits_active_finding(self) -> None:
        sps = [
            _make_mock_sp(sp_id="sp-inactive", active=False),
            _make_mock_sp(sp_id="sp-active", active=True),
        ]
        client = _make_mock_client(service_principals=sps)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        inactive = [f for f in findings if "Inactive" in f.title]
        assert len(inactive) == 1
        assert inactive[0].severity == Severity.MEDIUM
        assert inactive[0].status == FindingStatus.ACTIVE


# ── Secret scope sub-check tests ──────────────────────────────────


class TestSecretScope:
    def test_inventory_finding_per_scope(self) -> None:
        scopes = [
            _make_mock_secret_scope(name="prod"),
            _make_mock_secret_scope(name="dev"),
        ]
        client = _make_mock_client(secret_scopes=scopes)
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        scope_inventory = [
            f
            for f in findings
            if f.resource_type == "Databricks::SecretScope"
            and "preferred" not in f.title
            and "consider KMS-backed" not in f.title
        ]
        assert len(scope_inventory) == 2

    def test_databricks_backed_scope_emits_advisory_finding(
        self,
    ) -> None:
        scope = _make_mock_secret_scope(
            name="prod-secrets", backend_type="DATABRICKS"
        )
        client = _make_mock_client(secret_scopes=[scope])
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        advisory = [
            f for f in findings if "consider KMS-backed" in f.title
        ]
        assert len(advisory) == 1
        assert advisory[0].severity == Severity.LOW

    def test_key_vault_backed_scope_emits_positive_finding(
        self,
    ) -> None:
        scope = _make_mock_secret_scope(
            name="kv-prod", backend_type="AZURE_KEYVAULT"
        )
        client = _make_mock_client(secret_scopes=[scope])
        with DatabricksCollector(client=client) as c:
            findings, _manifest = c.collect_v2()

        preferred = [
            f for f in findings if "preferred SC-12 posture" in f.title
        ]
        assert len(preferred) == 1
        assert preferred[0].severity == Severity.INFORMATIONAL


# ── Manifest test (updated for 3 new evidence sources) ────────────


class TestManifestAfterAllSubChecks:
    def test_manifest_lists_all_4_resource_types(self) -> None:
        client = _make_mock_client(
            pats=[_make_mock_pat(token_id="t-1")],
            clusters=[_make_mock_cluster(cluster_id="c-1")],
            service_principals=[_make_mock_sp(sp_id="sp-1")],
            secret_scopes=[_make_mock_secret_scope(name="s-1")],
        )
        with DatabricksCollector(client=client) as c:
            _findings, manifest = c.collect_v2()

        resource_types = {
            cc.resource_type for cc in manifest.coverage_counts
        }
        # All 4 evidence sources implemented in P0.1 should appear.
        assert resource_types >= {
            "databricks-pat",
            "databricks-cluster",
            "databricks-service-principal",
            "databricks-secret-scope",
        }

    def test_manifest_only_lists_remaining_3_as_empty(self) -> None:
        client = _make_mock_client()
        with DatabricksCollector(client=client) as c:
            _findings, manifest = c.collect_v2()

        # After the 3 follow-up commits land, only audit logs +
        # lineage + network_policy remain in empty_categories.
        assert set(manifest.empty_categories) == {
            "workspace_audit_log",
            "table_lineage",
            "network_policy",
        }


# ── v0.7.14 P1.3: DATABRICKS_EXTRA_LTS_RUNTIMES env-var ───────────


class TestExtraLTSFromEnv:
    """v0.7.14 P1.3 closure for v0.7.8 LOW item 6.

    Operators on a newer LTS than what evidentia-collectors
    ships can supply additional version prefixes via
    ``DATABRICKS_EXTRA_LTS_RUNTIMES`` (comma-separated).
    """

    def test_no_env_var_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_collectors.databricks.collector import (
            _extra_lts_from_env,
        )
        monkeypatch.delenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES", raising=False
        )
        assert _extra_lts_from_env() == frozenset()

    def test_single_value_lowercased(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_collectors.databricks.collector import (
            _extra_lts_from_env,
        )
        monkeypatch.setenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES", "17.3.X-LTS"
        )
        assert _extra_lts_from_env() == frozenset({"17.3.x-lts"})

    def test_multi_value_comma_separated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_collectors.databricks.collector import (
            _extra_lts_from_env,
        )
        monkeypatch.setenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES",
            "17.3.x-lts, 18.0.x-lts ,19.1.x-lts",
        )
        assert _extra_lts_from_env() == frozenset(
            {"17.3.x-lts", "18.0.x-lts", "19.1.x-lts"}
        )

    def test_empty_entries_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from evidentia_collectors.databricks.collector import (
            _extra_lts_from_env,
        )
        monkeypatch.setenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES",
            "17.3.x-lts,,  ,18.0.x-lts",
        )
        assert _extra_lts_from_env() == frozenset(
            {"17.3.x-lts", "18.0.x-lts"}
        )

    def test_is_current_lts_includes_env_extras(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operator-supplied entries are honored by
        ``_is_current_lts()`` via the merged allowlist."""
        from evidentia_collectors.databricks.collector import (
            _is_current_lts,
        )
        # 17.3 is NOT in the in-package allowlist (only 14.3 / 15.4 / 16.4)
        monkeypatch.delenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES", raising=False
        )
        assert not _is_current_lts(
            "17.3.x-lts-photon-scala2.12"
        )
        # With env-var override, it's recognized via the
        # startswith() prefix match (17.3.x-lts matches
        # 17.3.x-lts-photon-scala2.12).
        monkeypatch.setenv(
            "DATABRICKS_EXTRA_LTS_RUNTIMES", "17.3.x-lts"
        )
        assert _is_current_lts(
            "17.3.x-lts-photon-scala2.12"
        )
