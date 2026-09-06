"""Per-collector SSRF-guard tests (threat-model T2 close-out).

Every outbound collector that accepts an operator-supplied host must, by
default, REFUSE a host that resolves to a loopback / RFC-1918 / link-local
(169.254.169.254 cloud-metadata) address, and ALLOW it only when the
``block_private_ips=False`` opt-out is set (surfaced as ``--allow-private-ips``
on the CLI).

These tests are hermetic — they use literal private IPs so no DNS round-trip
is needed, and they assert the guard fires at the connect / client-factory
path BEFORE any real socket / driver work. For the opt-out case the assertion
is that the failure is NOT the SSRF refusal (proving the guard was skipped) —
the request then proceeds to the driver path, which fails for an unrelated
reason (driver-not-installed or connection-refused), and that's the point.
"""

from __future__ import annotations

from typing import Any

import pytest

# A literal IP host avoids DNS entirely, so these tests never touch the
# network for the refusal path. 169.254.169.254 is the canonical
# cloud-instance-metadata endpoint (the highest-value SSRF target).
METADATA_HOST = "169.254.169.254"
LOOPBACK_HOST = "127.0.0.1"
RFC1918_HOST = "10.0.0.1"

# Marker the SSRF refusal always carries (from SSRFBlockedError). We assert
# on this rather than substring-matching a URL (the CodeQL
# py/incomplete-url-substring-sanitization smell).
_SSRF_MARKER = "SSRF policy"


def _is_ssrf_refusal(exc: Exception) -> bool:
    return _SSRF_MARKER in str(exc)


# ── Okta ────────────────────────────────────────────────────────────


class TestOktaSSRF:
    def test_metadata_host_refused_by_default(self) -> None:
        from evidentia_collectors.okta import (
            OktaCollector,
            OktaCollectorError,
        )

        collector = OktaCollector(
            org_url=f"https://{METADATA_HOST}",
            api_token="t",
        )
        with pytest.raises(OktaCollectorError) as exc:
            collector._ensure_client()
        # The SSRFBlockedError message (carried through OktaConnectionError)
        # names the policy + the disallowed address.
        assert _is_ssrf_refusal(exc.value)
        assert "link-local" in str(exc.value)

    @pytest.mark.parametrize("host", [LOOPBACK_HOST, RFC1918_HOST])
    def test_loopback_and_rfc1918_refused(self, host: str) -> None:
        from evidentia_collectors.okta import (
            OktaCollector,
            OktaCollectorError,
        )

        collector = OktaCollector(org_url=f"https://{host}", api_token="t")
        with pytest.raises(OktaCollectorError) as exc:
            collector._ensure_client()
        assert _is_ssrf_refusal(exc.value)

    def test_allow_private_ips_bypasses_guard(self) -> None:
        """With the opt-out, the guard is skipped and a real client is built
        (the org_url is private but the constructor proceeds — no refusal)."""
        from evidentia_collectors.okta import OktaCollector

        collector = OktaCollector(
            org_url=f"https://{METADATA_HOST}",
            api_token="t",
            block_private_ips=False,
        )
        # The guard is skipped, so _ensure_client builds the httpx.Client
        # without raising. (No request is issued here.)
        client = collector._ensure_client()
        assert client is not None
        collector.close()


# ── SaaS collectors (Vanta / Drata / BitSight / SecurityScorecard /
# Google Workspace) ──
# All five share BaseSaaSCollector._ensure_client, so the guard lives in
# one chokepoint — we exercise it through each subclass.


_SAAS_CASES = [
    ("evidentia_collectors.vanta", "VantaCollector", "VantaConnectionError"),
    ("evidentia_collectors.drata", "DrataCollector", "DrataConnectionError"),
    (
        "evidentia_collectors.bitsight",
        "BitSightCollector",
        "BitSightConnectionError",
    ),
    (
        "evidentia_collectors.securityscorecard",
        "SecurityScorecardCollector",
        "SecurityScorecardConnectionError",
    ),
    (
        "evidentia_collectors.google_workspace",
        "GoogleWorkspaceCollector",
        "GoogleWorkspaceConnectionError",
    ),
]


class TestSaaSCollectorsSSRF:
    @pytest.mark.parametrize("module,cls_name,err_name", _SAAS_CASES)
    def test_metadata_base_url_refused_by_default(
        self, module: str, cls_name: str, err_name: str
    ) -> None:
        import importlib

        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)
        err = getattr(mod, err_name)

        collector = cls(api_token="t", base_url=f"https://{METADATA_HOST}")
        with pytest.raises(err) as exc:
            collector._ensure_client()
        assert _is_ssrf_refusal(exc.value)

    @pytest.mark.parametrize("module,cls_name,err_name", _SAAS_CASES)
    def test_allow_private_ips_bypasses_guard(
        self, module: str, cls_name: str, err_name: str
    ) -> None:
        import importlib

        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)

        collector = cls(
            api_token="t",
            base_url=f"https://{METADATA_HOST}",
            block_private_ips=False,
        )
        # Guard skipped → client built without raising.
        client = collector._ensure_client()
        assert client is not None
        collector.__exit__(None, None, None)


# ── GitHub (Enterprise base_url is the SSRF surface) ────────────────


class TestGitHubSSRF:
    def test_metadata_base_url_refused_by_default(self) -> None:
        from evidentia_collectors.github import GitHubCollectorError
        from evidentia_collectors.github.client import GitHubApiError, GitHubClient

        with pytest.raises(GitHubApiError) as exc:
            GitHubClient(token="t", base_url=f"https://{METADATA_HOST}")
        assert _is_ssrf_refusal(exc.value)
        # The collector wraps the client constructor too.
        from evidentia_collectors.github import GitHubCollector

        with pytest.raises(GitHubApiError):
            GitHubCollector(
                owner="o", repo="r", token="t", base_url=f"https://{RFC1918_HOST}"
            )
        # Keep the import referenced for clarity even though the wrap raises
        # GitHubApiError (collector ctor does not catch it).
        assert GitHubCollectorError is not None

    def test_allow_private_ips_bypasses_guard(self) -> None:
        from evidentia_collectors.github.client import GitHubClient

        client = GitHubClient(
            token="t",
            base_url=f"https://{METADATA_HOST}",
            block_private_ips=False,
        )
        assert client is not None
        client.close()

    def test_default_public_base_url_is_noop(self) -> None:
        """The default api.github.com is public — the guard is a no-op."""
        from evidentia_collectors.github.client import GitHubClient

        client = GitHubClient(token="t")  # default BASE_URL
        assert client is not None
        client.close()


# ── SQL collectors (postgres / mysql / mssql / oracle) ──────────────


# (module, collector class, connection-error class, URI template, driver
# module, driver connect attr) — the driver attr is monkeypatched in the
# opt-out test so NO real socket is opened.
_SQL_CASES = [
    (
        "evidentia_collectors.sql.postgres",
        "PostgresCollector",
        "PostgresConnectionError",
        "postgresql://reader@{host}:5432/app",
        "psycopg",
        "connect",
    ),
    (
        "evidentia_collectors.sql.mysql",
        "MySQLCollector",
        "MySQLConnectionError",
        "mysql://reader@{host}:3306/app",
        "pymysql",
        "connect",
    ),
    (
        "evidentia_collectors.sql.mssql",
        "MSSQLCollector",
        "MSSQLConnectionError",
        "mssql://reader@{host}:1433/app",
        "pyodbc",
        "connect",
    ),
    (
        "evidentia_collectors.sql.oracle",
        "OracleCollector",
        "OracleConnectionError",
        "oracle://reader@{host}:1521/svc",
        "oracledb",
        "connect",
    ),
]


class _DriverReached(Exception):
    """Sentinel raised by a monkeypatched driver to prove the SSRF guard
    was bypassed and execution reached the driver-connect call."""


def _fake_driver_module(name: str, attr: str) -> Any:
    """A stand-in driver module whose connect-attr raises ``_DriverReached``,
    so the SSRF opt-out tests run with ZERO real drivers installed."""
    import types

    mod = types.ModuleType(name)

    def _connect(*_a: object, **_k: object) -> object:
        raise _DriverReached("driver connect reached")

    setattr(mod, attr, _connect)
    return mod


class TestSQLCollectorsSSRF:
    @pytest.mark.parametrize(
        "module,cls_name,err_name,uri,drv,_attr", _SQL_CASES
    )
    def test_private_host_refused_without_driver(
        self,
        module: str,
        cls_name: str,
        err_name: str,
        uri: str,
        drv: str,
        _attr: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The SSRF guard fires BEFORE the optional driver import, so a private
        host is refused even when the driver is NOT installed. We force the
        driver absent (``sys.modules[drv] = None`` makes ``import drv`` raise) to
        prove guard-before-import: the refusal must be the SSRF policy error,
        never a driver-missing error. This keeps the guard verified in a
        no-extras CI run (the proper fix behind the v0.10.10 --all-extras hotfix)."""
        import importlib
        import sys

        # `sys.modules[name] = None` makes a subsequent `import name` raise
        # ImportError — the hermetic way to simulate the driver being absent.
        monkeypatch.setitem(sys.modules, drv, None)

        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)
        base_err = getattr(
            mod, cls_name.replace("Collector", "CollectorError")
        )

        collector = cls(
            connection_uri=uri.format(host=METADATA_HOST), password="pw"
        )
        with pytest.raises(base_err) as exc:
            collector._ensure_connected()
        assert _is_ssrf_refusal(exc.value)

    @pytest.mark.parametrize(
        "module,cls_name,err_name,uri,drv,attr", _SQL_CASES
    )
    def test_allow_private_ips_bypasses_guard(
        self,
        module: str,
        cls_name: str,
        err_name: str,
        uri: str,
        drv: str,
        attr: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Opt-out skips the guard, so execution reaches the driver connect. We
        inject a FAKE driver module (no real driver needed) whose connect-attr
        raises a sentinel — reaching it proves the guard was bypassed. The
        collector wraps the sentinel in its typed error, NEVER the SSRF refusal."""
        import importlib
        import sys

        monkeypatch.setitem(sys.modules, drv, _fake_driver_module(drv, attr))

        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)
        base_err = getattr(
            mod, cls_name.replace("Collector", "CollectorError")
        )

        collector = cls(
            connection_uri=uri.format(host=METADATA_HOST),
            password="pw",
            block_private_ips=False,
        )
        with pytest.raises(base_err) as exc:
            collector._ensure_connected()
        # The KEY assertions: the guard was bypassed (driver was reached)
        # and the failure is NOT the SSRF policy refusal.
        assert not _is_ssrf_refusal(exc.value)
        assert isinstance(exc.value.__cause__, _DriverReached)


# ── Databricks ──────────────────────────────────────────────────────


class TestDatabricksSSRF:
    def test_metadata_host_refused_by_default(self) -> None:
        from evidentia_collectors.databricks import (
            DatabricksAuthError,
            DatabricksCollector,
        )

        collector = DatabricksCollector(host=f"https://{METADATA_HOST}")
        with pytest.raises(DatabricksAuthError) as exc:
            collector._ensure_client()
        assert _is_ssrf_refusal(exc.value)

    def test_allow_private_ips_bypasses_guard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opt-out skips the guard. We monkeypatch WorkspaceClient to raise
        a sentinel so no SDK auth/network runs — reaching it proves the
        guard was bypassed, and the wrapped error is NOT the SSRF refusal."""
        import databricks.sdk
        from evidentia_collectors.databricks import (
            DatabricksAuthError,
            DatabricksCollector,
        )

        def _sentinel(*_a: object, **_k: object) -> object:
            raise _DriverReached("WorkspaceClient reached")

        monkeypatch.setattr(databricks.sdk, "WorkspaceClient", _sentinel)
        collector = DatabricksCollector(
            host=f"https://{METADATA_HOST}", block_private_ips=False
        )
        # WorkspaceClient construction failures are wrapped as
        # DatabricksAuthError by the collector.
        with pytest.raises(DatabricksAuthError) as exc:
            collector._ensure_client()
        assert not _is_ssrf_refusal(exc.value)
        assert isinstance(exc.value.__cause__, _DriverReached)


# ── Snowflake (account locator -> <account>.snowflakecomputing.com) ─


class TestSnowflakeSSRF:
    def test_account_resolving_to_private_refused_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A Snowflake account locator whose host resolves to a private IP
        (private-link / DNS-rebinding) is refused. We stub getaddrinfo on
        the derived <account>.snowflakecomputing.com host."""
        import socket

        from evidentia_collectors.snowflake import (
            SnowflakeAuthError,
            SnowflakeCollector,
        )

        def _fake(host: str, *a: object, **k: object) -> object:
            assert host == "evil-acct.snowflakecomputing.com"
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.7", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake)
        collector = SnowflakeCollector(account="evil-acct", user="u")
        with pytest.raises(SnowflakeAuthError) as exc:
            collector._ensure_connected()
        assert _is_ssrf_refusal(exc.value)

    def test_allow_private_ips_bypasses_guard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opt-out skips the guard. We monkeypatch the connector's connect
        to raise a sentinel so no real socket opens — reaching it proves
        the guard was bypassed, and the wrapped error is NOT the SSRF
        refusal."""
        import snowflake.connector
        from evidentia_collectors.snowflake import (
            SnowflakeAuthError,
            SnowflakeCollector,
        )

        def _sentinel(*_a: object, **_k: object) -> object:
            raise _DriverReached("snowflake connect reached")

        monkeypatch.setattr(snowflake.connector, "connect", _sentinel)
        collector = SnowflakeCollector(
            account="evil-acct", user="u", block_private_ips=False
        )
        # Snowflake wraps driver connect failures as SnowflakeAuthError.
        with pytest.raises(SnowflakeAuthError) as exc:
            collector._ensure_connected()
        assert not _is_ssrf_refusal(exc.value)
        assert isinstance(exc.value.__cause__, _DriverReached)
