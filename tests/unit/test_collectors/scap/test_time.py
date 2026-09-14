"""Reviewed XML source calendar examples and finite normalization boundaries."""

import pytest
from evidentia_collectors.scap._limits import ScapFailure, start_budget
from evidentia_collectors.scap._time import normalize_source_time


@pytest.mark.parametrize(
    "source,state,utc",
    [
        pytest.param("2026-01-02T03:04:05Z", "normalized", "2026-01-02T03:04:05Z", id="zero_z"),
        pytest.param("2026-01-02T03:04:05+00:00", "normalized", "2026-01-02T03:04:05Z", id="zero_plus"),
        pytest.param("2026-01-02T03:04:05-00:00", "normalized", "2026-01-02T03:04:05Z", id="zero_minus"),
        pytest.param("2026-01-02T03:04:05+03:30", "normalized", "2026-01-01T23:34:05Z", id="positive_offset"),
        pytest.param("2026-01-02T03:04:05-00:30", "normalized", "2026-01-02T03:34:05Z", id="negative_half_hour"),
        pytest.param("2026-01-02T03:04:05-14:00", "normalized", "2026-01-02T17:04:05Z", id="last_allowed_zone"),
        pytest.param("2026-01-02T03:04:05", "timezone_missing", None, id="no_zone"),
        pytest.param("2024-02-28T24:00:00Z", "normalized", "2024-02-29T00:00:00Z", id="midnight_rollover"),
        pytest.param("2024-02-29T24:00:00.0000000Z", "normalized", "2024-03-01T00:00:00Z", id="midnight_zero_fraction"),
        pytest.param("9999-12-31T24:00:00+14:00", "normalized", "9999-12-31T10:00:00Z", id="upper_boundary_24"),
        pytest.param("10000-01-01T00:00:00+14:00", "normalized", "9999-12-31T10:00:00Z", id="upper_boundary_extended"),
        pytest.param("9999-12-31T24:00:00Z", "range_unsupported", None, id="upper_overflow"),
        pytest.param("0001-01-01T00:00:00+00:01", "range_unsupported", None, id="lower_underflow"),
        pytest.param("-0001-12-31T24:00:00Z", "normalized", "0001-01-01T00:00:00Z", id="bce_ce_rollover"),
        pytest.param("-0001-01-01T00:00:00Z", "range_unsupported", None, id="negative_year"),
        pytest.param("-0004-02-29T00:00:00Z", "range_unsupported", None, id="negative_leap_year_value"),
        pytest.param("12345-06-07T08:09:10Z", "range_unsupported", None, id="extended_year"),
        pytest.param("2026-01-02T03:04:05.123456Z", "normalized", "2026-01-02T03:04:05.123456Z", id="microseconds"),
        pytest.param(
            "2026-01-02T03:04:05.123456000Z", "normalized", "2026-01-02T03:04:05.123456Z", id="exact_extra_zeros"
        ),
        pytest.param("2026-01-02T03:04:05.123456001Z", "precision_unsupported", None, id="significant_extra_precision"),
        pytest.param("2026-01-02T03:04:05.120000Z", "normalized", "2026-01-02T03:04:05.12Z", id="fraction_trim"),
        pytest.param("2016-12-31T23:59:60Z", "normalization_unsupported", None, id="leap_second_lexical"),
        pytest.param("2016-12-31T23:59:60.25Z", "normalization_unsupported", None, id="leap_second_fraction"),
        pytest.param("\t\n2026-01-02T03:04:05-00:00\r ", "normalized", "2026-01-02T03:04:05Z", id="xml_whitespace"),
        pytest.param("0000-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_year_zero"),
        pytest.param("-0000-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_negative_zero"),
        pytest.param("02026-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_extended_leading_zero"),
        pytest.param("+2026-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_year_plus"),
        pytest.param("026-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_short_year"),
        pytest.param("-0001-02-29T00:00:00Z", "source_contract_invalid", None, id="invalid_negative_leap_year_value"),
        pytest.param("1900-02-29T00:00:00Z", "source_contract_invalid", None, id="invalid_positive_leap"),
        pytest.param("2000-02-29T00:00:00Z", "normalized", "2000-02-29T00:00:00Z", id="valid_century_leap"),
        pytest.param("2026-04-31T00:00:00Z", "source_contract_invalid", None, id="invalid_day"),
        pytest.param("2026-01-01T00:00:61Z", "source_contract_invalid", None, id="invalid_second_61"),
        pytest.param("2026-01-01T24:00:00.1Z", "source_contract_invalid", None, id="invalid_24_fraction"),
        pytest.param("2026-01-01T24:01:00Z", "source_contract_invalid", None, id="invalid_24_minute"),
        pytest.param("2026-01-01T24:00:60Z", "source_contract_invalid", None, id="invalid_24_leap_second"),
        pytest.param("2026-01-01T00:00:00+14:01", "source_contract_invalid", None, id="invalid_offset_minute"),
        pytest.param("2026-01-01T00:00:00+15:00", "source_contract_invalid", None, id="invalid_offset_hour"),
        pytest.param("2026-01-01T00:00:00.Z", "source_contract_invalid", None, id="invalid_empty_fraction"),
        pytest.param("2026-01-01t00:00:00z", "source_contract_invalid", None, id="invalid_lowercase"),
        pytest.param("2026-01-01 T00:00:00Z", "source_contract_invalid", None, id="invalid_internal_space"),
        pytest.param("\u00a02026-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_non_xml_space"),
        pytest.param(
            "\uff12\uff10\uff12\uff16-01-01T00:00:00Z", "source_contract_invalid", None, id="invalid_unicode_digits"
        ),
    ],
)
def test_reviewed_source_time_vectors(source: str, state: str, utc: str | None) -> None:
    original = source
    if state == "source_contract_invalid":
        with pytest.raises(ScapFailure) as caught:
            normalize_source_time(source, start_budget())
        assert caught.value.code == state
    else:
        result = normalize_source_time(source, start_budget())
        assert result.state == state
        assert result.utc == utc
    assert source == original


@pytest.mark.parametrize(
    "source,state",
    [
        ("2026-01-02T03:04:05.0000001", "timezone_missing"),
        ("2016-12-31T23:59:60.0000001Z", "precision_unsupported"),
        ("12345-12-31T23:59:60Z", "normalization_unsupported"),
        ("-0004-02-29T00:00:00", "timezone_missing"),
    ],
)
def test_normalization_precedence_follows_source_validation(source: str, state: str) -> None:
    result = normalize_source_time(source, start_budget())
    assert result.state == state
    assert result.utc is None


def test_far_year_is_scanned_without_constructing_datetime(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.scap import _time

    def forbidden(*args, **kwargs):
        raise AssertionError("A far source year must not reach datetime construction")

    monkeypatch.setattr(_time, "datetime", forbidden)
    result = normalize_source_time("1" + "0" * 200_000 + "-02-29T00:00:00Z", start_budget())
    assert result.state == "range_unsupported"
    assert result.utc is None


def test_long_fraction_retains_only_exact_microseconds() -> None:
    assert (
        normalize_source_time("2026-01-02T03:04:05.123456" + "0" * 200_000 + "Z", start_budget()).utc
        == "2026-01-02T03:04:05.123456Z"
    )
    assert (
        normalize_source_time("2026-01-02T03:04:05.123456" + "0" * 199_999 + "1Z", start_budget()).state
        == "precision_unsupported"
    )


def test_long_year_checks_original_real_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_collectors.scap import _limits

    budget = start_budget()
    current = [budget.deadline - 20.0]
    calls = []

    def elapsed() -> float:
        calls.append(True)
        if len(calls) > 3:
            return budget.deadline
        return current[0]

    monkeypatch.setattr(_limits.time, "monotonic", elapsed)
    with pytest.raises(ScapFailure) as caught:
        normalize_source_time("1" + "0" * 200_000 + "-01-01T00:00:00Z", budget)
    assert caught.value.code == "processing_deadline_exceeded"
    assert len(calls) == 4
