"""The DNS-rebinding pin applies to internationalised hostnames (v0.13.0 review M6, CWE-367).

``urlparse`` keeps a non-ASCII hostname in Unicode while httpx resolves its
IDNA form; the registry used to key on the raw text, so the pin never
matched the lookup and the connecting library resolved freely.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest
from evidentia_core import network_guard
from evidentia_core.network_guard import pin_resolved_host

PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "169.254.169.254"
UNICODE_HOST = "bücher.example"
IDNA_HOST = "xn--bcher-kva.example"

_PRISTINE = socket.getaddrinfo


@pytest.fixture()
def _rebinding_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def resolver(host: Any, port: Any, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        # Whatever the library asks for, an unpinned lookup lands on the
        # metadata address: the test fails loudly if the pin does not apply.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PRIVATE_IP, port))]

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", resolver)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    try:
        yield
    finally:
        socket.getaddrinfo = _PRISTINE


@pytest.mark.parametrize("pinned_as", [UNICODE_HOST, IDNA_HOST, UNICODE_HOST.upper(), IDNA_HOST + "."])
@pytest.mark.parametrize("looked_up_as", [UNICODE_HOST, IDNA_HOST])
def test_pin_matches_unicode_and_idna_forms(_rebinding_resolver: None, pinned_as: str, looked_up_as: str) -> None:
    with pin_resolved_host(pinned_as, [PUBLIC_IP]):
        infos = socket.getaddrinfo(looked_up_as, 443)
    assert {info[4][0] for info in infos} == {PUBLIC_IP}


def test_pin_key_normalises() -> None:
    assert network_guard._pin_key("Bücher.Example.") == IDNA_HOST
    assert network_guard._pin_key("API.Example.COM") == "api.example.com"
