"""Unit tests for the SSRF guard in ``evidentia_core.network_guard``.

The SSRF guard (``enforce_public_host`` / ``resolve_host_is_private`` /
``SSRFBlockedError``) is the reusable, default-on chokepoint every outbound
collector calls before opening a connection. It closes threat-model T2 by
refusing hosts that resolve to private / loopback / link-local / metadata
addresses, while allowing an explicit opt-out (``block_private=False``).

These tests monkeypatch ``socket.getaddrinfo`` so no real DNS / network IO
runs — the literal-IP cases resolve trivially, and the hostname cases are
stubbed to a chosen address class.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest
from evidentia_core import network_guard
from evidentia_core.network_guard import (
    SSRFBlockedError,
    enforce_public_host,
    resolve_host_is_private,
)


def _fake_getaddrinfo(ip: str) -> Any:
    """Return a getaddrinfo stub that resolves any host to ``ip``."""

    def _inner(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (ip, 0))]

    return _inner


# ── resolve_host_is_private (literal IPs — no DNS needed) ──────────────────


class TestResolveHostIsPrivate:
    @pytest.mark.parametrize(
        "ip",
        [
            "169.254.169.254",  # cloud instance-metadata (link-local)
            "127.0.0.1",  # loopback
            "10.0.0.1",  # RFC-1918
            "172.16.0.1",  # RFC-1918
            "192.168.1.1",  # RFC-1918
            "::1",  # IPv6 loopback
            "fd00::1",  # IPv6 unique-local
            "0.0.0.0",  # unspecified
            "224.0.0.1",  # multicast
        ],
    )
    def test_private_addresses_flagged(self, ip: str) -> None:
        is_private, bad = resolve_host_is_private(ip)
        assert is_private is True
        assert bad == ip

    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888"],
    )
    def test_public_addresses_pass(self, ip: str) -> None:
        is_private, bad = resolve_host_is_private(ip)
        assert is_private is False
        assert bad == ""

    def test_dns_returning_private_is_flagged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hostname that DNS-resolves to a private IP is refused
        (DNS-rebinding-style bypass attempt)."""
        monkeypatch.setattr(
            socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254")
        )
        is_private, bad = resolve_host_is_private("metadata.evil.example")
        assert is_private is True
        assert bad == "169.254.169.254"


# ── enforce_public_host ────────────────────────────────────────────────────


class TestEnforcePublicHost:
    def test_rejects_metadata_endpoint_by_default(self) -> None:
        with pytest.raises(SSRFBlockedError) as exc:
            enforce_public_host(
                "https://169.254.169.254/latest/meta-data/",
                subsystem="okta",
            )
        assert exc.value.subsystem == "okta"
        assert exc.value.resolved_ip == "169.254.169.254"

    @pytest.mark.parametrize(
        "url",
        [
            "https://10.0.0.1/api",
            "https://172.16.0.1/api",
            "https://192.168.1.1/api",
            "https://127.0.0.1:8080/api",
        ],
    )
    def test_rejects_rfc1918_and_loopback(self, url: str) -> None:
        with pytest.raises(SSRFBlockedError):
            enforce_public_host(url, subsystem="test")

    def test_allows_public_host(self) -> None:
        # 8.8.8.8 is a literal public IP; no DNS round-trip needed.
        enforce_public_host("https://8.8.8.8/api", subsystem="test")

    def test_opt_out_skips_check(self) -> None:
        """block_private=False is a no-op even for a metadata endpoint."""
        enforce_public_host(
            "https://169.254.169.254/latest/meta-data/",
            subsystem="test",
            block_private=False,
        )

    def test_bare_host_with_port(self) -> None:
        with pytest.raises(SSRFBlockedError):
            enforce_public_host("127.0.0.1:5432", subsystem="sql-postgres")

    def test_bracketed_ipv6_loopback(self) -> None:
        with pytest.raises(SSRFBlockedError):
            enforce_public_host("https://[::1]:8443/api", subsystem="test")

    def test_unresolvable_host_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A host that cannot be resolved cannot be proven public — refused."""

        def _boom(*_a: Any, **_k: Any) -> Any:
            raise socket.gaierror("name resolution failed")

        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        with pytest.raises(SSRFBlockedError) as exc:
            enforce_public_host(
                "https://does-not-resolve.invalid/api", subsystem="test"
            )
        assert exc.value.resolved_ip == "(unresolvable)"

    def test_hostname_resolving_public_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("8.8.8.8"))
        enforce_public_host("https://api.example.com/v1", subsystem="test")

    def test_hostname_resolving_private_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
        with pytest.raises(SSRFBlockedError) as exc:
            enforce_public_host("https://intranet.example.com/v1", subsystem="okta")
        assert exc.value.resolved_ip == "10.1.2.3"

    def test_exported_symbol(self) -> None:
        assert "enforce_public_host" in network_guard.__all__
        assert "SSRFBlockedError" in network_guard.__all__
