"""Run ownership and authoritative result checks for storage collection."""

from __future__ import annotations

import importlib
import socket
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from evidentia_collectors.retention import _contracts as contracts
from evidentia_collectors.retention._client import ComponentResponse, StorageReadSession
from evidentia_collectors.retention._credentials import AwsCredentials, BearerCredentials, CredentialResolution
from evidentia_core import network_guard

collector = importlib.import_module("evidentia_collectors.retention.collector")


class Clock:
    def __init__(self) -> None:
        self.seconds = 0.0

    def utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.seconds)

    def tick(self) -> float:
        return self.seconds

    def sleep(self, value: float) -> None:
        self.seconds += value


class Credentials:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def resolve(self, provider: str) -> CredentialResolution:
        self.calls.append(provider)
        material = (
            AwsCredentials("synthetic-access", "synthetic-secret")
            if provider == "s3"
            else BearerCredentials("synthetic-bearer")
        )
        return CredentialResolution(material, None)


class Wire(httpx.BaseTransport):
    def __init__(self, statuses: list[int], *, failed_close: bool = False) -> None:
        self.statuses = statuses
        self.requests: list[httpx.Request] = []
        self.closes = 0
        self.failed_close = failed_close

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        index = len(self.requests)
        self.requests.append(request)
        body = b"<Source/>" if request.url.host.startswith("s3.") else b"{}"
        return httpx.Response(self.statuses[min(index, len(self.statuses) - 1)], stream=httpx.ByteStream(body))

    def close(self) -> None:
        self.closes += 1
        if self.failed_close:
            raise OSError("synthetic close failure with private context")


def selected(provider: str = "gcs", count: int = 2) -> contracts.StorageRetentionCollectRequest:
    targets: list[dict[str, str]]
    if provider == "s3":
        targets = [{"bucket": f"bucket-{i}", "region": "us-east-1"} for i in range(count)]
    elif provider == "azure":
        targets = [
            {
                "subscription_id": "12345678-abcd-1234-abcd-123456789abc",
                "resource_group": "Example",
                "account": "account123",
                "container": f"container-{i}",
            }
            for i in range(count)
        ]
    else:
        targets = [{"bucket": f"bucket-{i}"} for i in range(count)]
    return contracts.validated_request({"provider": provider, "scope_label": "selected-scope", "targets": targets})


def project(response: ComponentResponse, target: contracts.StorageTarget) -> contracts.ProjectedComponent:
    return contracts.ProjectedComponent(
        api_version="synthetic-facade-test",
        native_scope="configuration",
        fields={"observed": True},
        source_etag=response.source_etag,
    )


def fake_reader(
    target: contracts.StorageTarget, session: StorageReadSession
) -> list[contracts.StorageRetentionComponentResult]:
    return [
        session.read_component(name, target, project)
        for name in contracts.component_ids(contracts.target_provider(target))
    ]


@pytest.fixture
def setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., tuple[Any, Credentials, list[Wire], Clock]]]:
    monkeypatch.delenv("EVIDENTIA_OFFLINE", raising=False)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(collector, "_read_target", fake_reader)
    cases: list[Any] = []

    def create(
        statuses: list[int] | None = None, failed_close: bool = False
    ) -> tuple[Any, Credentials, list[Wire], Clock]:
        credentials, wires, clock = Credentials(), [], Clock()

        def wire() -> Wire:
            value = Wire(statuses or [200], failed_close=failed_close)
            wires.append(value)
            return value

        instance = collector.StorageRetentionCollector(
            credentials=credentials,
            transport_factory=wire,
            utc_clock=clock.utc,
            monotonic_clock=clock.tick,
            sleep=clock.sleep,
            run_id_factory=lambda: "synthetic-storage-run",
        )
        cases.append(instance)
        return instance, credentials, wires, clock

    with network_guard.offline_mode(False):
        yield create
        for instance in cases:
            instance.close()


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_finite_plan_and_full_evidence_are_revalidated(setup: Callable[..., Any], provider: str) -> None:
    instance, credentials, wires, _ = setup()
    request = selected(provider)
    result = instance.collect_v2(request)
    assert result.status == "complete" and len(result.resources) == len(result.findings) == 2
    assert result.planned_components == 2 * len(contracts.component_ids(provider))
    assert result.completed_components == result.attempted_components == result.planned_components
    assert len(wires) == 1 and len(wires[0].requests) == result.planned_components and wires[0].closes == 1
    assert credentials.calls == [provider]
    assert all(
        finding.compliance_status == "unknown" and finding.resolved_at is None and not finding.control_mappings
        for finding in result.findings
    )
    restored = contracts.StorageRetentionCollectResult.model_validate_json(result.model_dump_json(warnings="error"))
    assert restored == result
    assert not result.object_enforcement_assessed and not result.authenticated_identity_verified
    if provider != "azure":
        request.root.targets[0].bucket = "changed-bucket"
    else:
        request.root.targets[0].container = "changed-container"
    assert result.resources[0].canonical_resource_id.endswith("bucket-0") or provider == "azure"


def test_offline_collection_preserves_targets_without_credentials_or_transport(setup: Callable[..., Any]) -> None:
    instance, credentials, wires, _ = setup()
    with network_guard.offline_mode():
        result = instance.collect_v2(selected())
    assert result.status == "unavailable" and len(result.resources) == 2
    assert credentials.calls == [] and wires == []
    assert all(
        component.attempts == 0
        and component.projection is None
        and [item.code for item in component.diagnostics] == ["offline_refused"]
        for resource in result.resources
        for component in resource.components
    )


@pytest.mark.parametrize(
    "statuses,status,findings", [([403], "unavailable", 0), ([200, 403], "partial", 1), ([200], "complete", 2)]
)
def test_component_failures_keep_every_selected_resource(
    setup: Callable[..., Any], statuses: list[int], status: str, findings: int
) -> None:
    instance, _, wires, _ = setup(statuses)
    result = instance.collect_v2(selected())
    assert result.status == status and len(result.resources) == 2 and len(result.findings) == findings
    assert wires[0].closes == 1


def test_rejection_latch_keeps_unattempted_resources(setup: Callable[..., Any]) -> None:
    instance, credentials, wires, _ = setup([401])
    result = instance.collect_v2(selected(count=3))
    assert result.status == "unavailable" and len(result.resources) == 3
    assert [item.components[0].attempts for item in result.resources] == [1, 0, 0]
    assert credentials.calls == ["gcs"] and len(wires[0].requests) == wires[0].closes == 1


def test_owned_client_cleanup_changes_complete_to_partial(setup: Callable[..., Any]) -> None:
    instance, _, wires, _ = setup(failed_close=True)
    result = instance.collect_v2(selected())
    assert result.status == "partial" and len(result.findings) == 2
    assert [item.code for item in result.diagnostics] == ["cleanup_failed"]
    assert wires[0].closes == 1 and "private context" not in result.model_dump_json()


def test_run_budget_after_reader_retains_earlier_evidence(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _, wires, clock = setup()
    calls = 0

    def consume(
        target: contracts.StorageTarget, session: StorageReadSession
    ) -> list[contracts.StorageRetentionComponentResult]:
        nonlocal calls
        answer = fake_reader(target, session)
        calls += 1
        if calls == 1:
            clock.seconds = 120
        return answer

    monkeypatch.setattr(collector, "_read_target", consume)
    result = instance.collect_v2(selected())
    assert result.status == "partial" and len(result.findings) == 1 and len(result.resources) == 2
    assert [item.code for item in result.diagnostics] == ["run_budget_exhausted"]
    assert wires[0].closes == 1


@pytest.mark.parametrize("exception", [RuntimeError("private reader details"), KeyboardInterrupt()])
def test_reader_failure_always_closes_owned_transport(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, exception: BaseException
) -> None:
    instance, _, wires, _ = setup()

    def broken(
        target: contracts.StorageTarget, session: StorageReadSession
    ) -> list[contracts.StorageRetentionComponentResult]:
        fake_reader(target, session)
        raise exception

    monkeypatch.setattr(collector, "_read_target", broken)
    if isinstance(exception, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            instance.collect_v2(selected())
    else:
        with pytest.raises(ValueError, match=r"^collector_failed$"):
            instance.collect_v2(selected())
    assert wires[0].closes == 1


def test_each_call_owns_a_new_transport_and_credential_resolution(setup: Callable[..., Any]) -> None:
    instance, credentials, wires, _ = setup()
    first = instance.collect_v2(selected(count=1))
    second = instance.collect_v2(selected(count=1))
    assert first == second and first is not second
    assert len(wires) == 2 and all(wire.closes == 1 for wire in wires)
    assert credentials.calls == ["gcs", "gcs"]
    findings = instance.collect(selected(count=1))
    assert findings == first.findings and findings is not first.findings
    assert len(wires) == 3


def test_invalid_request_fails_before_optional_import_or_resolution(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, credentials, wires, _ = setup()

    def loader(name: str) -> None:
        pytest.fail("optional import before request validation")

    monkeypatch.setattr(collector, "_import_module", loader)
    with pytest.raises(contracts.StorageRetentionInputError):
        instance.collect_v2({"provider": "s3", "scope_label": "bad ", "targets": []})
    assert credentials.calls == [] and wires == []


@pytest.mark.parametrize("missing", ["botocore", "defusedxml", "unrelated_transitive"])
def test_s3_optional_import_failure_preserves_exact_identity(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    instance, credentials, wires, _ = setup()

    def absent(name: str) -> Any:
        raise ModuleNotFoundError("synthetic import details", name=missing)

    monkeypatch.setattr(collector, "_import_module", absent)
    with pytest.raises(ModuleNotFoundError) as error:
        instance.collect_v2(selected("s3"))
    assert error.value.name == missing
    assert credentials.calls == [] and wires == []


@pytest.mark.parametrize("provider", ["azure", "gcs"])
def test_base_providers_never_import_s3_optional_modules(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    instance, _, _, _ = setup()
    monkeypatch.setattr(collector, "_import_module", lambda name: pytest.fail("S3 optional import for base provider"))
    assert instance.collect_v2(selected(provider, 1)).status == "complete"


def test_closed_collector_has_no_side_effects(setup: Callable[..., Any]) -> None:
    instance, credentials, wires, _ = setup()
    instance.close()
    instance.close()
    with pytest.raises(ValueError, match=r"^collector_closed$"):
        instance.collect_v2(selected())
    with pytest.raises(ValueError, match=r"^collector_closed$"):
        instance.__enter__()
    assert credentials.calls == [] and wires == []


@pytest.mark.parametrize("bad", ["naive-clock", "bad-run-id"])
def test_unrepresentable_run_state_is_fixed_error_without_io(setup: Callable[..., Any], bad: str) -> None:
    instance, credentials, wires, _ = setup()
    if bad == "naive-clock":
        instance._utc_clock = lambda: datetime(2026, 1, 1)
    else:
        instance._run_id_factory = lambda: "unaccepted run id"
    with pytest.raises(ValueError, match=r"^collector_failed$"):
        instance.collect_v2(selected())
    assert credentials.calls == [] and wires == []


def test_final_observation_clock_is_sampled_before_budget_decision(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _, wires, clock = setup()

    def finish(
        target: contracts.StorageTarget, session: StorageReadSession
    ) -> list[contracts.StorageRetentionComponentResult]:
        answer = fake_reader(target, session)

        def slow_clock() -> datetime:
            clock.seconds = 120
            return clock.utc()

        session.context._utc_clock = slow_clock
        return answer

    monkeypatch.setattr(collector, "_read_target", finish)
    result = instance.collect_v2(selected(count=1))
    assert result.status == "partial" and len(result.findings) == 1
    assert [item.code for item in result.diagnostics] == ["run_budget_exhausted"]
    assert wires[0].closes == 1
