"""Tests for the v0.3.0 plain-English explanation facility.

LLM calls are mocked — these tests exercise the cache semantics,
validation, and generator plumbing without actually hitting an LLM.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from evidentia_ai.explain.cache import (
    _cache_key,
    clear_cache,
    get_cache_dir,
    load_cached,
    store,
)
from evidentia_ai.explain.generator import ExplanationGenerator
from evidentia_ai.explain.models import PlainEnglishExplanation
from evidentia_core.models.catalog import CatalogControl


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch):
    """Point the explanation cache at an isolated tmp dir per test."""
    cache = tmp_path / "cache"
    monkeypatch.setenv("EVIDENTIA_EXPLAIN_CACHE_DIR", str(cache))
    yield cache


def _fake_explanation(
    framework_id: str = "nist-800-53-rev5",
    control_id: str = "AC-2",
    control_title: str = "Account Management",
) -> PlainEnglishExplanation:
    return PlainEnglishExplanation(
        framework_id=framework_id,
        control_id=control_id,
        control_title=control_title,
        plain_english=(
            "You need a documented process for creating, modifying, and "
            "removing user accounts across every system that matters."
        ),
        why_it_matters=(
            "Unmanaged accounts are a top attack vector — attackers "
            "frequently exploit former-employee credentials that were "
            "never cleaned up. A single dormant admin account with an "
            "unchanged password is a complete bypass of your IAM "
            "perimeter."
        ),
        what_to_do=[
            "Document a provisioning and deprovisioning procedure",
            "Perform quarterly access reviews with written approvals",
            "Configure automated account deactivation after 90 days inactive",
        ],
        effort_estimate=(
            "Medium — policy documentation plus quarterly review process. "
            "Add 2-4 weeks for orgs over 50 employees that need IAM tooling."
        ),
    )


def _fake_control(control_id: str = "AC-2", title: str = "Account Management") -> CatalogControl:
    return CatalogControl(
        id=control_id,
        title=title,
        description="The organization employs account management procedures...",
    )


# -----------------------------------------------------------------------------
# cache_key + cache directory resolution
# -----------------------------------------------------------------------------


def test_cache_key_is_deterministic() -> None:
    a = _cache_key("fw", "AC-2", "gpt-4o", 0.1)
    b = _cache_key("fw", "AC-2", "gpt-4o", 0.1)
    assert a == b


def test_cache_key_varies_by_model() -> None:
    a = _cache_key("fw", "AC-2", "gpt-4o", 0.1)
    b = _cache_key("fw", "AC-2", "claude-opus-4", 0.1)
    assert a != b


def test_cache_key_varies_by_temperature() -> None:
    a = _cache_key("fw", "AC-2", "gpt-4o", 0.0)
    b = _cache_key("fw", "AC-2", "gpt-4o", 0.2)
    assert a != b


def test_get_cache_dir_env_override(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_EXPLAIN_CACHE_DIR", str(tmp_path))
    assert get_cache_dir() == tmp_path.resolve()


def test_get_cache_dir_explicit_override_wins(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("EVIDENTIA_EXPLAIN_CACHE_DIR", str(tmp_path / "env"))
    explicit = tmp_path / "explicit"
    assert get_cache_dir(explicit) == explicit.resolve()


# -----------------------------------------------------------------------------
# load/store roundtrip
# -----------------------------------------------------------------------------


def test_store_then_load_roundtrip() -> None:
    exp = _fake_explanation()
    store(exp, model="gpt-4o", temperature=0.1)
    loaded = load_cached("nist-800-53-rev5", "AC-2", "gpt-4o", 0.1)
    assert loaded is not None
    assert loaded.control_id == "AC-2"
    assert loaded.plain_english == exp.plain_english


def test_load_returns_none_when_missing() -> None:
    assert load_cached("fw", "unseen-control", "gpt-4o", 0.1) is None


def test_cache_miss_on_different_model() -> None:
    exp = _fake_explanation()
    store(exp, model="gpt-4o", temperature=0.1)
    assert load_cached("nist-800-53-rev5", "AC-2", "claude-opus-4", 0.1) is None


def test_corrupt_cache_file_returns_none(tmp_path: Path) -> None:
    """A malformed JSON file in the cache doesn't crash — it's just ignored."""
    cache_path = get_cache_dir() / f"{_cache_key('fw', 'AC-2', 'gpt-4o', 0.1)}.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("not valid json")
    assert load_cached("fw", "AC-2", "gpt-4o", 0.1) is None


def test_clear_cache_empties_dir() -> None:
    for ctrl_id in ["AC-2", "AC-3", "AU-2"]:
        store(_fake_explanation(control_id=ctrl_id), "gpt-4o", 0.1)
    n = clear_cache()
    assert n == 3
    assert load_cached("nist-800-53-rev5", "AC-2", "gpt-4o", 0.1) is None


def test_clear_cache_on_missing_dir_returns_zero(tmp_path: Path) -> None:
    missing = tmp_path / "never-created"
    # Use explicit override so we don't race with the autouse fixture
    assert clear_cache(missing) == 0


# -----------------------------------------------------------------------------
# ExplanationGenerator — cache hit avoids LLM call
# -----------------------------------------------------------------------------


def test_generator_cache_hit_skips_llm() -> None:
    """If an explanation is already cached, generate() returns it without LLM calls."""
    # Pre-populate the cache for (nist-800-53-rev5, AC-2, gpt-4o, 0.1)
    store(_fake_explanation(), model="gpt-4o", temperature=0.1)

    with patch("evidentia_ai.explain.generator.get_instructor_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client_factory.return_value = mock_client
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
        # Cache hit — the LLM must not have been called
        mock_client.chat.completions.create.assert_not_called()
    assert result.control_id == "AC-2"


def test_generator_cache_miss_calls_llm_and_caches() -> None:
    with patch("evidentia_ai.explain.generator.get_instructor_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _fake_explanation()
        mock_client_factory.return_value = mock_client
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
        mock_client.chat.completions.create.assert_called_once()
    # Subsequent call with the same key should hit the cache now
    assert load_cached("nist-800-53-rev5", "AC-2", "gpt-4o", 0.1) is not None


def test_generator_refresh_bypasses_cache() -> None:
    store(_fake_explanation(), model="gpt-4o", temperature=0.1)
    with patch("evidentia_ai.explain.generator.get_instructor_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _fake_explanation()
        mock_client_factory.return_value = mock_client
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        gen.generate(_fake_control(), framework_id="nist-800-53-rev5", refresh=True)
        mock_client.chat.completions.create.assert_called_once()


def test_generator_use_cache_false_bypasses_both_read_and_write() -> None:
    with patch("evidentia_ai.explain.generator.get_instructor_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _fake_explanation()
        mock_client_factory.return_value = mock_client
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1, use_cache=False)
        gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    # Nothing written to cache
    assert load_cached("nist-800-53-rev5", "AC-2", "gpt-4o", 0.1) is None


def test_generator_echoes_framework_and_control_ids_even_if_llm_drifts() -> None:
    """Defensive: if the LLM returns mismatched echo fields, we overwrite them."""
    llm_output = _fake_explanation(
        framework_id="wrong-fw",
        control_id="WRONG-ID",
        control_title="Wrong title",
    )
    with patch("evidentia_ai.explain.generator.get_instructor_client") as mock_client_factory:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = llm_output
        mock_client_factory.return_value = mock_client
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1, use_cache=False)
        result = gen.generate(
            _fake_control(control_id="AC-2", title="Account Management"),
            framework_id="nist-800-53-rev5",
        )
    assert result.framework_id == "nist-800-53-rev5"
    assert result.control_id == "AC-2"
    assert result.control_title == "Account Management"


# -----------------------------------------------------------------------------
# PlainEnglishExplanation schema validation
# -----------------------------------------------------------------------------


def test_explanation_model_rejects_too_few_steps() -> None:
    """what_to_do must have 3-8 bullets."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):  # pydantic ValidationError
        PlainEnglishExplanation(
            framework_id="fw",
            control_id="AC-2",
            control_title="Account Management",
            plain_english="A" * 50,
            why_it_matters="B" * 100,
            what_to_do=["only one"],  # too few
            effort_estimate="C" * 30,
        )


def test_explanation_model_rejects_short_plain_english() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PlainEnglishExplanation(
            framework_id="fw",
            control_id="AC-2",
            control_title="Account Management",
            plain_english="too short",  # min 40 chars
            why_it_matters="B" * 100,
            what_to_do=["a", "b", "c"],
            effort_estimate="C" * 30,
        )


def test_explanation_model_rejects_extra_fields() -> None:
    """Strict schema (extra='forbid') — unknown keys from a drifting LLM fail."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PlainEnglishExplanation.model_validate(
            {
                "framework_id": "fw",
                "control_id": "AC-2",
                "control_title": "Account Management",
                "plain_english": "A" * 50,
                "why_it_matters": "B" * 100,
                "what_to_do": ["a", "b", "c"],
                "effort_estimate": "C" * 30,
                "invented_field": "should fail",
            }
        )


# -----------------------------------------------------------------------------
# v0.7.1 enterprise-grade hardening tests
# -----------------------------------------------------------------------------

from typing import Any  # noqa: E402

from evidentia_ai.exceptions import (  # noqa: E402
    LLM_TRANSIENT_EXCEPTIONS,
    EvidentiaAIError,
    ExplainError,
    ExplainGenerationFailed,
    LLMUnavailableError,
    LLMValidationError,
)
from evidentia_core.audit import TEST_MODE_ENV, EventAction  # noqa: E402
from evidentia_core.network_guard import OfflineViolationError  # noqa: E402
from instructor.core import InstructorRetryException  # noqa: E402
from litellm.exceptions import (  # noqa: E402
    APIConnectionError,
    BadGatewayError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)


@pytest.fixture(autouse=True)
def _test_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero out retry backoff so retry-heavy tests don't burn wall-clock."""
    monkeypatch.setenv(TEST_MODE_ENV, "1")


def _make_litellm_exc(exc_cls: type[BaseException]) -> BaseException:
    if exc_cls is RateLimitError:
        return RateLimitError("rate limited", llm_provider="openai", model="gpt-4o")
    if exc_cls is APIConnectionError:
        return APIConnectionError(message="conn refused", llm_provider="openai", model="gpt-4o")
    if exc_cls is Timeout:
        return Timeout("timeout", model="gpt-4o", llm_provider="openai")
    if exc_cls is InternalServerError:
        return InternalServerError("500", model="gpt-4o", llm_provider="openai")
    if exc_cls is ServiceUnavailableError:
        return ServiceUnavailableError("503", model="gpt-4o", llm_provider="openai")
    if exc_cls is BadGatewayError:
        return BadGatewayError(message="502", model="gpt-4o", llm_provider="openai")
    raise AssertionError(f"unhandled litellm exception class {exc_cls}")


def _patched_create(side_effect: Any) -> Any:
    fake_client = MagicMock()
    fake_client.chat.completions.create = MagicMock(side_effect=side_effect)
    return patch(
        "evidentia_ai.explain.generator.get_instructor_client",
        return_value=fake_client,
    )


# Exception hierarchy
def test_explain_exception_hierarchy_shape() -> None:
    assert issubclass(ExplainError, EvidentiaAIError)
    assert issubclass(ExplainGenerationFailed, ExplainError)


# GenerationContext attached on cache miss
def test_generate_attaches_generation_context_on_cache_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVIDENTIA_AI_OPERATOR", "alice@acme.com")
    with _patched_create(side_effect=[_fake_explanation()]):
        gen = ExplanationGenerator(model="claude-sonnet-4", temperature=0.2)
        result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert result.generation_context is not None
    ctx = result.generation_context
    assert ctx.model == "claude-sonnet-4"
    assert ctx.temperature == 0.2
    assert ctx.attempts == 1
    assert ctx.credential_identity == "alice@acme.com"
    assert len(ctx.prompt_hash) == 64
    assert len(ctx.run_id) == 26


# GenerationContext NOT minted on cache hit (cached value preserved)
def test_generate_does_not_mint_new_context_on_cache_hit() -> None:
    """Cache hits return whatever was cached \u2014 no new GenerationContext minted."""
    # Pre-populate cache with an explanation that has NO generation_context
    pre_cached = _fake_explanation()
    assert pre_cached.generation_context is None
    store(pre_cached, "gpt-4o", 0.1)

    with _patched_create(side_effect=[]):  # LLM should never be called
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert result.generation_context is None  # preserved from cache


# Network retries on transient errors
@pytest.mark.parametrize(
    "exc_cls",
    [RateLimitError, APIConnectionError, Timeout, InternalServerError, BadGatewayError],
)
def test_generate_retries_transient_then_succeeds(
    exc_cls: type[BaseException],
) -> None:
    side_effect = [
        _make_litellm_exc(exc_cls),
        _make_litellm_exc(exc_cls),
        _fake_explanation(),
    ]
    with _patched_create(side_effect=side_effect):
        gen = ExplanationGenerator(use_cache=False)
        result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert result.generation_context is not None
    assert result.generation_context.attempts == 3


def test_generate_exhausted_retries_raises_llm_unavailable() -> None:
    side_effect = [_make_litellm_exc(RateLimitError) for _ in range(5)]
    with _patched_create(side_effect=side_effect):
        gen = ExplanationGenerator(use_cache=False)
        with pytest.raises(LLMUnavailableError) as excinfo:
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert isinstance(excinfo.value.__cause__, RateLimitError)


def test_generate_validation_exhausted_raises_llm_validation_error() -> None:
    instructor_exc = InstructorRetryException(
        "validation failed",
        last_completion=None,
        n_attempts=3,
        total_usage=0,
    )
    with _patched_create(side_effect=[instructor_exc]):
        gen = ExplanationGenerator(use_cache=False)
        with pytest.raises(LLMValidationError) as excinfo:
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert isinstance(excinfo.value.__cause__, InstructorRetryException)


def test_generate_unexpected_exception_wraps_as_explain_generation_failed() -> None:
    with _patched_create(side_effect=[RuntimeError("boom")]):
        gen = ExplanationGenerator(use_cache=False)
        with pytest.raises(ExplainGenerationFailed) as excinfo:
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")
    assert isinstance(excinfo.value.__cause__, RuntimeError)


def test_generate_offline_violation_propagates_unwrapped() -> None:
    with _patched_create(side_effect=[OfflineViolationError(subsystem="evidentia_ai", target="gpt-4o")]):
        gen = ExplanationGenerator(use_cache=False)
        with pytest.raises(OfflineViolationError):
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")


# Structured event emission
def test_generate_emits_ai_explain_generated_event_on_success(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _patched_create(side_effect=[_fake_explanation()]):
        gen = ExplanationGenerator(use_cache=False)
        with caplog.at_level("INFO", logger="evidentia.ai.explain"):
            result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")

    success_records = [
        r
        for r in caplog.records
        if (hasattr(r, "ecs_record") and r.ecs_record["event"]["action"] == EventAction.AI_EXPLAIN_GENERATED.value)
    ]
    assert len(success_records) == 1
    # L2: prompt_hash surfaced in success event
    assert result.generation_context is not None
    assert success_records[0].ecs_record["evidentia"]["prompt_hash"] == result.generation_context.prompt_hash


def test_generate_emits_ai_explain_cache_hit_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store(_fake_explanation(), "gpt-4o", 0.1)
    with _patched_create(side_effect=[]):
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        with caplog.at_level("INFO", logger="evidentia.ai.explain"):
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")

    cache_records = [
        r
        for r in caplog.records
        if (hasattr(r, "ecs_record") and r.ecs_record["event"]["action"] == EventAction.AI_EXPLAIN_CACHE_HIT.value)
    ]
    assert len(cache_records) == 1


def test_generate_emits_ai_explain_failed_event_with_run_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H1: failure events MUST carry run_id for SIEM correlation."""
    with _patched_create(side_effect=[RuntimeError("boom")]):
        gen = ExplanationGenerator(use_cache=False)
        with caplog.at_level("ERROR", logger="evidentia.ai.explain"), pytest.raises(ExplainGenerationFailed):
            gen.generate(_fake_control(), framework_id="nist-800-53-rev5")

    failure_records = [
        r
        for r in caplog.records
        if (hasattr(r, "ecs_record") and r.ecs_record["event"]["action"] == EventAction.AI_EXPLAIN_FAILED.value)
    ]
    assert len(failure_records) == 1
    assert failure_records[0].ecs_record["evidentia"]["run_id"] is not None


def test_generate_emits_ai_explain_retry_events_with_trace_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H2: retry events MUST inherit trace.id from the run_id scope."""
    side_effect = [
        _make_litellm_exc(RateLimitError),
        _make_litellm_exc(RateLimitError),
        _fake_explanation(),
    ]
    with _patched_create(side_effect=side_effect):
        gen = ExplanationGenerator(use_cache=False)
        with caplog.at_level("WARNING", logger="evidentia.audit.retry"):
            result = gen.generate(_fake_control(), framework_id="nist-800-53-rev5")

    retry_records = [
        r
        for r in caplog.records
        if (hasattr(r, "ecs_record") and r.ecs_record["event"]["action"] == EventAction.AI_EXPLAIN_RETRY.value)
    ]
    assert len(retry_records) == 2
    assert result.generation_context is not None
    expected_run_id = result.generation_context.run_id
    for rec in retry_records:
        assert rec.ecs_record["trace"]["id"] == expected_run_id


def test_generate_writes_cache_with_generation_context() -> None:
    """The cached explanation includes the GenerationContext so subsequent
    cache hits can surface the original provenance."""
    with _patched_create(side_effect=[_fake_explanation()]):
        gen = ExplanationGenerator(model="gpt-4o", temperature=0.1)
        gen.generate(_fake_control(), framework_id="nist-800-53-rev5")

    cached = load_cached("nist-800-53-rev5", "AC-2", "gpt-4o", 0.1)
    assert cached is not None
    assert cached.generation_context is not None
    assert cached.generation_context.model == "gpt-4o"


def test_explain_transient_set_is_the_shared_one() -> None:
    """Single source of truth: both subsystems import from
    evidentia_ai.exceptions.LLM_TRANSIENT_EXCEPTIONS."""
    # Sanity: tuple is non-empty and contains the expected litellm types.
    assert RateLimitError in LLM_TRANSIENT_EXCEPTIONS
    assert APIConnectionError in LLM_TRANSIENT_EXCEPTIONS
    assert Timeout in LLM_TRANSIENT_EXCEPTIONS
    assert InternalServerError in LLM_TRANSIENT_EXCEPTIONS
    assert ServiceUnavailableError in LLM_TRANSIENT_EXCEPTIONS
    assert BadGatewayError in LLM_TRANSIENT_EXCEPTIONS
