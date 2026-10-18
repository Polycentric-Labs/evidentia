"""The v0.13 collectors emit the collect audit events (v0.13.0 review H6, CWE-778).

Every collector that shipped before v0.13 writes COLLECT_STARTED,
COLLECT_COMPLETED and COLLECT_FAILED through the ECS audit logger; the
nine collectors added in v0.13 emitted nothing. The Nessus and Greenbone
importers are exercised end to end here; the other seven are checked
structurally because their entry points need credentials, sessions or a
provider, and their own suites cover the behaviour around the events.
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging

import pytest
from evidentia_core.audit import EventAction

pytest.importorskip("defusedxml", reason="the scan extra is not installed")

NEW_COLLECTOR_MODULES = [
    "evidentia_collectors.entra_m365.collector",
    "evidentia_collectors.greenbone.collector",
    "evidentia_collectors.incident_clock.collector",
    "evidentia_collectors.nessus.collector",
    "evidentia_collectors.registries.collector",
    "evidentia_collectors.release_cadence.collector",
    "evidentia_collectors.retention.collector",
    "evidentia_collectors.enterprise_retention.collector",
    "evidentia_collectors.scap.collector",
]


def _actions(caplog: pytest.LogCaptureFixture, logger_name: str) -> list[str]:
    found: list[str] = []
    for record in caplog.records:
        if record.name != logger_name:
            continue
        ecs = getattr(record, "ecs_record", None)
        blob = json.dumps(ecs, default=str) if ecs is not None else record.getMessage()
        for action in (EventAction.COLLECT_STARTED, EventAction.COLLECT_COMPLETED, EventAction.COLLECT_FAILED):
            if action.value in blob:
                found.append(action.value)
    return found


def test_nessus_ingest_emits_started_and_completed(caplog: pytest.LogCaptureFixture) -> None:
    from evidentia_collectors.nessus import collect_nessus_text

    xml = '<?xml version="1.0"?><NessusClientData_v2><Report name="empty"></Report></NessusClientData_v2>'
    with caplog.at_level(logging.INFO, logger="evidentia.collectors.nessus"):
        collect_nessus_text(xml, source_name="inline")
    actions = _actions(caplog, "evidentia.collectors.nessus")
    assert actions == [EventAction.COLLECT_STARTED.value, EventAction.COLLECT_COMPLETED.value]
    assert "empty" not in caplog.text.replace('"report_name": "empty"', "")


def test_nessus_parse_failure_emits_failed(caplog: pytest.LogCaptureFixture) -> None:
    from evidentia_collectors.nessus import NessusIngestError, collect_nessus_text

    with caplog.at_level(logging.INFO, logger="evidentia.collectors.nessus"), pytest.raises(NessusIngestError):
        collect_nessus_text("<NotNessus/>", source_name="inline")
    assert _actions(caplog, "evidentia.collectors.nessus") == [
        EventAction.COLLECT_STARTED.value,
        EventAction.COLLECT_FAILED.value,
    ]


def test_greenbone_ingest_emits_started_and_completed(caplog: pytest.LogCaptureFixture) -> None:
    from evidentia_collectors.greenbone import collect_greenbone_text

    xml = '<?xml version="1.0"?><report id="r-1"><report id="r-1"><results></results></report></report>'
    with caplog.at_level(logging.INFO, logger="evidentia.collectors.greenbone"):
        collect_greenbone_text(xml, source_name="inline")
    assert _actions(caplog, "evidentia.collectors.greenbone") == [
        EventAction.COLLECT_STARTED.value,
        EventAction.COLLECT_COMPLETED.value,
    ]


def test_greenbone_parse_failure_emits_failed(caplog: pytest.LogCaptureFixture) -> None:
    from evidentia_collectors.greenbone import GreenboneIngestError, collect_greenbone_text

    with (
        caplog.at_level(logging.INFO, logger="evidentia.collectors.greenbone"),
        pytest.raises(GreenboneIngestError),
    ):
        collect_greenbone_text("<NotGreenbone/>", source_name="inline")
    assert _actions(caplog, "evidentia.collectors.greenbone") == [
        EventAction.COLLECT_STARTED.value,
        EventAction.COLLECT_FAILED.value,
    ]


@pytest.mark.parametrize("module_name", NEW_COLLECTOR_MODULES)
def test_every_new_collector_wires_the_three_collect_events(module_name: str) -> None:
    module = importlib.import_module(module_name)
    source = inspect.getsource(module)
    for member in ("COLLECT_STARTED", "COLLECT_COMPLETED", "COLLECT_FAILED"):
        assert f"EventAction.{member}" in source, (module_name, member)
    assert 'get_logger("evidentia.collectors.' in source, module_name
