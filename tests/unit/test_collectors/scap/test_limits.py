"""Fixed failure envelopes and the shared processing/publication clock."""

import math

import pytest
from evidentia_collectors.scap import _limits
from evidentia_collectors.scap._contracts import ScapError
from evidentia_collectors.scap._json import canonical_bytes
from evidentia_collectors.scap._limits import ERRORS, Budget, ScapFailure, text_value


@pytest.mark.parametrize("code", list(ERRORS))
def test_every_declared_failure_uses_the_closed_value_free_wire(code):
    failure = ScapFailure(code)
    record = failure.as_dict()
    assert ScapError.model_validate(record).model_dump() == record
    assert set(record) == {"schema_version", "code", "message"}
    assert len(canonical_bytes(record)) <= _limits.ERROR_LIMIT
    assert failure.cli_exit in (1, 2)


def test_unknown_failure_does_not_invoke_a_value_protocol():
    class Unknown:
        def __str__(self):
            raise AssertionError("Unknown failures must not expose values")

        def __hash__(self):
            raise AssertionError("Unknown failures must not be hashed")

    assert ScapFailure(Unknown()).as_dict() == ScapFailure().as_dict()


@pytest.mark.parametrize("deadline", [True, 60, 0.0, -1.0, math.inf, -math.inf, math.nan])
def test_clock_requires_one_positive_finite_native_float(deadline):
    with pytest.raises(ScapFailure):
        Budget(deadline)


def test_processing_reserve_and_publication_share_the_original_deadline(monkeypatch):
    now = [49.999]
    monkeypatch.setattr(_limits.time, "monotonic", lambda: now[0])
    budget = Budget(60.0)
    budget.check()
    now[0] = 50.0
    with pytest.raises(ScapFailure) as reserved:
        budget.check()
    assert reserved.value.code == "processing_deadline_exceeded"
    budget.check(publication=True)
    now[0] = 59.999
    budget.check(publication=True)
    now[0] = 60.0
    with pytest.raises(ScapFailure) as expired:
        budget.check(publication=True)
    assert expired.value.code == "processing_deadline_exceeded"
    assert budget.deadline == 60.0


def test_text_limits_count_utf8_bytes_and_preserve_admitted_source_spacing():
    assert text_value("  source  ", 1, 10) == "  source  "
    assert text_value("\U0001f642", 1, 4) == "\U0001f642"
    with pytest.raises(ScapFailure):
        text_value("\U0001f642", 1, 3)
