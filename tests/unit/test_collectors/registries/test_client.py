"""Keep shared RDAP admission separate from unsupported Unicode comparison."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_collectors.registries import _client, rdap
from evidentia_collectors.registries._contracts import (
    RegistryDiagnostic,
    RegistryLookupResult,
    canonical_hostname,
    diagnostic,
    result_bytes,
)
from evidentia_collectors.registries._snapshots import RDAPBootstrap


@pytest.mark.parametrize(
    "name,expected",
    [
        ("f\u00f3o.example", ["source_name_comparison_unsupported"]),
        ("b\u00e1r.example", ["source_name_comparison_unsupported"]),
        ("foo\u3002example", ["source_name_comparison_unsupported"]),
        ("XN--FO-5JA.EXAMPLE.", []),
        ("other.example", ["source_name_conflict"]),
        ("bad space.example", ["source_name_conflict"]),
        ("", ["source_name_conflict"]),
        (None, []),
        (True, ["invalid_response"]),
        (7, ["invalid_response"]),
        ([], ["invalid_response"]),
        ({}, ["invalid_response"]),
    ],
)
def test_rdap_unicode_comparison_preserves_literals(
    monkeypatch: pytest.MonkeyPatch, name: Any, expected: list[str]
) -> None:
    source = {"objectClassName": "domain", "ldhName": "xn--fo-5ja.example", "unicodeName": name}
    content = json.dumps(source, ensure_ascii=False).encode()
    requested: list[str] = []
    canonical = canonical_hostname

    def ascii_only(value: str) -> str:
        assert value.isascii()
        return canonical(value)

    class Replay(_client.HttpAttempt):
        def fetch(self, url: str, *, remaining: Any, consume: Any, max_bytes: int = 1048576) -> bytes:
            requested.append(url)
            remaining()
            self.status_code = 200
            self.content_types = ("application/rdap+json",)
            consume(len(content), len(content))
            return content

    monkeypatch.setattr(_client, "canonical_hostname", ascii_only)
    bootstrap = RDAPBootstrap(
        "a" * 64,
        "2026-09-01T00:00:00Z",
        b'{"kind":"synthetic"}',
        ((("example",), ("https://rdap.example.org/base/",)),),
    )
    request = {"registry": "rdap", "target": {"domain": "XN--FO-5JA.EXAMPLE."}}
    session = _client.RegistryReadSession(
        request,
        _utc=lambda: datetime(2026, 9, 12, tzinfo=UTC),
        _monotonic=lambda: 0.0,
        _http_factory=Replay,
        _bootstrap_factory=lambda: bootstrap,
    )
    result = rdap.lookup(session)
    assert requested == ["https://rdap.example.org/base/domain/xn--fo-5ja.example"]
    assert result.request.model_dump(mode="json") == {**request, "scope_label": None}
    assert [item.code for item in result.diagnostics] == expected
    raw = result_bytes(result)
    assert result_bytes(RegistryLookupResult.model_validate_json(raw)) == raw
    if expected == ["invalid_response"]:
        assert result.lookup_outcome == "unavailable" and not result.observations
    else:
        assert result.lookup_outcome == "found" and result.collection_status == "complete"
        assert len(result.observations) == 1
        assert result.observations[0].fields == source
        assert all(item.effect == "advisory" and item.source_read_id for item in result.diagnostics)


def test_rdap_unsupported_comparison_has_fixed_advisory_effect() -> None:
    assert diagnostic("source_name_comparison_unsupported").effect == "advisory"
    with pytest.raises(ValueError):
        RegistryDiagnostic.model_validate({"code": "source_name_comparison_unsupported", "effect": "gap"})
