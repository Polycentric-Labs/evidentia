"""Request models refuse values that would make a stored record unloadable (v0.13.0 review)."""

from __future__ import annotations

import math
from datetime import date

import pytest
from pydantic import ValidationError


def test_milestone_patch_description_must_not_be_blank() -> None:
    from evidentia_api.routers.poam import MilestoneUpdatePayload

    with pytest.raises(ValidationError):
        MilestoneUpdatePayload(description="   ")
    assert MilestoneUpdatePayload(description=None).description is None
    assert MilestoneUpdatePayload(description="Rotate the keys").description == "Rotate the keys"


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_metric_observation_value_must_be_finite(value: float) -> None:
    from evidentia_api.routers.governance import MetricObservationPayload
    from evidentia_core.governance.metrics import MetricObservation

    with pytest.raises(ValidationError):
        MetricObservationPayload(value=value, observed_at=date(2026, 1, 1))
    with pytest.raises(ValidationError):
        MetricObservation(value=value, observed_at=date(2026, 1, 1))


def test_poam_deleted_audit_event_exists() -> None:
    from evidentia_core.audit import EventAction

    assert EventAction.POAM_DELETED.value == "evidentia.poam.deleted"
