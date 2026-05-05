"""Unit tests for the v0.7.1 risk-statement generator.

The LLM is fully mocked — these tests exercise the typed-exception
hierarchy, retry behaviour, GenerationContext attachment, and
batch-tolerance semantics without ever issuing a network call.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from evidentia_ai.exceptions import (
    LLM_TRANSIENT_EXCEPTIONS,
    EvidentiaAIError,
    LLMUnavailableError,
    LLMValidationError,
    RiskGenerationFailed,
    RiskStatementError,
)
from evidentia_ai.risk_statements.generator import (
    RiskStatementGenerator,
)
from evidentia_ai.risk_statements.templates import (
    SystemComponent,
    SystemContext,
)
from evidentia_core.audit import TEST_MODE_ENV, EventAction
from evidentia_core.models.gap import (
    ControlGap,
    GapSeverity,
    ImplementationEffort,
)
from evidentia_core.models.risk import (
    ImpactRating,
    LikelihoodRating,
    RiskLevel,
    RiskStatement,
    RiskTreatment,
)
from evidentia_core.network_guard import OfflineViolationError
from instructor.core import InstructorRetryException
from litellm.exceptions import (
    APIConnectionError,
    AuthenticationError,
    BadGatewayError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _test_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero out retry backoff so retry-heavy tests don't burn wall-clock."""
    monkeypatch.setenv(TEST_MODE_ENV, "1")


@pytest.fixture
def system_context() -> SystemContext:
    return SystemContext(
        organization="Acme Corp",
        system_name="Customer Portal",
        system_description="Public-facing customer self-service portal",
        data_classification=["PII", "PCI"],
        hosting="AWS us-east-1",
        risk_tolerance="low",
        components=[
            SystemComponent(
                name="api-gateway",
                type="api",
                technology="AWS API Gateway",
                data_handled=["PII"],
                location="us-east-1",
            ),
        ],
        threat_actors=["external attackers", "malicious insiders"],
        existing_controls=["WAF", "MFA"],
    )


def _make_gap(control_id: str = "AC-2") -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title="Account Management",
        control_description="The org manages accounts...",
        gap_severity=GapSeverity.HIGH,
        gap_description="No automated account deactivation",
        implementation_status="missing",
        cross_framework_value=["soc2-tsc:CC6.1"],
        remediation_guidance="Enable AWS IAM Access Analyzer and quarterly access reviews",
        implementation_effort=ImplementationEffort.MEDIUM,
    )


def _fake_risk_statement() -> RiskStatement:
    """Build a minimal-fields RiskStatement matching what the LLM would return."""
    return RiskStatement(
        asset="Customer Portal",
        threat_source="External attacker",
        threat_event="Credential stuffing against dormant accounts",
        vulnerability="No automated account deactivation",
        likelihood=LikelihoodRating.HIGH,
        likelihood_rationale="Dormant accounts are a known attack vector",
        impact=ImpactRating.HIGH,
        impact_rationale="PII exposure carries regulatory penalties",
        risk_level=RiskLevel.HIGH,
        risk_description="An external attacker could compromise dormant accounts",
        recommended_controls=["AC-2(3)", "AC-12"],
        remediation_priority=2,
        treatment=RiskTreatment.MITIGATE,
    )


def _patched_sync_create(side_effect: Any) -> Any:
    """Patch the sync Instructor client's chat.completions.create."""
    fake_client = MagicMock()
    fake_client.chat.completions.create = MagicMock(side_effect=side_effect)
    return patch(
        "evidentia_ai.risk_statements.generator.get_instructor_client",
        return_value=fake_client,
    )


def _patched_async_create(side_effect: Any) -> Any:
    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(side_effect=side_effect)
    return patch(
        "evidentia_ai.risk_statements.generator.get_async_instructor_client",
        return_value=fake_client,
    )


def _make_litellm_exc(exc_cls: type[BaseException]) -> BaseException:
    """LiteLLM exception ctors require positional args; build them uniformly."""
    if exc_cls is RateLimitError:
        return RateLimitError("rate limited", llm_provider="openai", model="gpt-4o")
    if exc_cls is APIConnectionError:
        return APIConnectionError(
            message="conn refused", llm_provider="openai", model="gpt-4o"
        )
    if exc_cls is Timeout:
        return Timeout("timeout", model="gpt-4o", llm_provider="openai")
    if exc_cls is InternalServerError:
        return InternalServerError("500", model="gpt-4o", llm_provider="openai")
    if exc_cls is ServiceUnavailableError:
        return ServiceUnavailableError(
            "503", model="gpt-4o", llm_provider="openai"
        )
    if exc_cls is BadGatewayError:
        return BadGatewayError(
            message="502", model="gpt-4o", llm_provider="openai"
        )
    raise AssertionError(f"unhandled litellm exception class {exc_cls}")


# -----------------------------------------------------------------------------
# Exception hierarchy
# -----------------------------------------------------------------------------


def test_exception_hierarchy_shape() -> None:
    """Every concrete AI error must inherit from EvidentiaAIError, and the
    risk-specific failures must inherit from RiskStatementError."""
    assert issubclass(LLMUnavailableError, EvidentiaAIError)
    assert issubclass(LLMValidationError, EvidentiaAIError)
    assert issubclass(RiskStatementError, EvidentiaAIError)
    assert issubclass(RiskGenerationFailed, RiskStatementError)


def test_transient_exception_set_excludes_programmer_errors() -> None:
    """AuthenticationError must NOT be in the retry set — auth issues are
    programmer/config errors that retrying cannot fix."""
    assert AuthenticationError not in LLM_TRANSIENT_EXCEPTIONS
    # Sanity-check the inclusions:
    for cls in (
        RateLimitError,
        APIConnectionError,
        Timeout,
        InternalServerError,
        ServiceUnavailableError,
        BadGatewayError,
    ):
        assert cls in LLM_TRANSIENT_EXCEPTIONS


# -----------------------------------------------------------------------------
# Sync generate — happy path + provenance
# -----------------------------------------------------------------------------


def test_generate_success_attaches_generation_context(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    fake_risk = _fake_risk_statement()

    with _patched_sync_create(side_effect=[fake_risk]):
        gen = RiskStatementGenerator(model="claude-sonnet-4", temperature=0.3)
        result = gen.generate(gap, system_context)

    assert result.generation_context is not None
    ctx = result.generation_context
    assert ctx.model == "claude-sonnet-4"
    assert ctx.temperature == 0.3
    assert ctx.attempts == 1
    assert ctx.instructor_max_retries == 3
    assert len(ctx.prompt_hash) == 64
    assert len(ctx.run_id) == 26


def test_generate_enriches_with_source_gap_and_framework_mappings(
    system_context: SystemContext,
) -> None:
    gap = _make_gap("AC-3")
    fake_risk = _fake_risk_statement()

    with _patched_sync_create(side_effect=[fake_risk]):
        gen = RiskStatementGenerator(model="gpt-4o")
        result = gen.generate(gap, system_context)

    assert result.source_gap_id == gap.id
    assert result.model_used == "gpt-4o"
    assert "nist-800-53-rev5:AC-3" in result.framework_mappings
    assert "soc2-tsc:CC6.1" in result.framework_mappings


def test_generate_with_explicit_run_id_threads_through(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context, run_id="01HXAAAAAAAAAAAAAAAAAAAAAA")
    assert result.generation_context is not None
    assert result.generation_context.run_id == "01HXAAAAAAAAAAAAAAAAAAAAAA"


def test_generate_without_emit_trace_leaves_reasoning_trace_none(
    system_context: SystemContext,
) -> None:
    """v0.8.0 P0.2 — emit_trace=False (default) keeps reasoning_trace None.

    Backward compat for operators not opting in to PRT.
    """
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context)
    assert result.reasoning_trace is None


def test_generate_with_emit_trace_attaches_stub_trace(
    system_context: SystemContext,
) -> None:
    """v0.8.0 P0.2 — emit_trace=True attaches a stub PRT to the risk."""
    gap = _make_gap("AC-2")
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context, emit_trace=True)
    assert result.reasoning_trace is not None
    # Stub trace has exactly one foundational claim citing the source gap.
    assert len(result.reasoning_trace.claims) == 1
    cite = result.reasoning_trace.claims[0].clause_citations[0]
    assert "AC-2" in cite
    assert "nist-800-53-rev5" in cite
    # Stub overall_confidence is 0.5 (intentionally moderate to
    # signal it's not LLM-derived).
    assert result.reasoning_trace.overall_confidence == 0.5
    assert "stub" in result.reasoning_trace.methodology.lower()


def test_generate_propagates_model_inventory_ref_when_configured(
    system_context: SystemContext,
) -> None:
    """v0.7.10 P0.6.4 — RiskStatementGenerator(model_inventory_id=...)
    propagates the linkage onto every produced RiskStatement so SR 11-7
    / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin 2026-13a auditors
    can trace back from a risk statement to its model inventory entry."""
    gap = _make_gap()
    inv_id = "aaaa1111-2222-3333-4444-555566667777"
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator(model_inventory_id=inv_id)
        result = gen.generate(gap, system_context)
    assert result.model_inventory_ref == inv_id


def test_generate_leaves_model_inventory_ref_none_when_not_configured(
    system_context: SystemContext,
) -> None:
    """Backward-compat: callers that don't set `model_inventory_id`
    on the generator continue to produce RiskStatements with
    model_inventory_ref=None (matches all pre-v0.7.10 behavior)."""
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context)
    assert result.model_inventory_ref is None


def test_generate_prompt_hash_is_deterministic_for_same_inputs(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        a = gen.generate(gap, system_context)
        b = gen.generate(gap, system_context)
    assert a.generation_context is not None
    assert b.generation_context is not None
    assert a.generation_context.prompt_hash == b.generation_context.prompt_hash


# -----------------------------------------------------------------------------
# Sync generate — retry behaviour
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls",
    [RateLimitError, APIConnectionError, Timeout, InternalServerError, BadGatewayError],
)
def test_generate_retries_transient_then_succeeds(
    system_context: SystemContext, exc_cls: type[BaseException]
) -> None:
    gap = _make_gap()
    fake_risk = _fake_risk_statement()
    side_effect = [
        _make_litellm_exc(exc_cls),
        _make_litellm_exc(exc_cls),
        fake_risk,
    ]
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context)
    # 3rd attempt succeeded → attempts == 3
    assert result.generation_context is not None
    assert result.generation_context.attempts == 3


def test_generate_exhausted_retries_raises_llm_unavailable(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    side_effect = [_make_litellm_exc(RateLimitError) for _ in range(5)]
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        with pytest.raises(LLMUnavailableError) as excinfo:
            gen.generate(gap, system_context)
    # Original LiteLLM exception preserved as __cause__
    assert isinstance(excinfo.value.__cause__, RateLimitError)


def test_generate_validation_exhausted_raises_llm_validation_error(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    instructor_exc = InstructorRetryException(
        "validation failed",
        last_completion=None,
        n_attempts=3,
        total_usage=0,
    )
    with _patched_sync_create(side_effect=[instructor_exc]):
        gen = RiskStatementGenerator()
        with pytest.raises(LLMValidationError) as excinfo:
            gen.generate(gap, system_context)
    assert isinstance(excinfo.value.__cause__, InstructorRetryException)


def test_generate_unexpected_exception_wraps_as_risk_generation_failed(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    with _patched_sync_create(side_effect=[RuntimeError("totally unexpected")]):
        gen = RiskStatementGenerator()
        with pytest.raises(RiskGenerationFailed) as excinfo:
            gen.generate(gap, system_context)
    assert isinstance(excinfo.value.__cause__, RuntimeError)


def test_generate_offline_violation_propagates_unwrapped(
    system_context: SystemContext,
) -> None:
    """Air-gap violations must NOT be wrapped — they're programmer/policy
    errors that operators need to see immediately."""
    gap = _make_gap()
    with _patched_sync_create(
        side_effect=[OfflineViolationError(subsystem="evidentia_ai", target="gpt-4o")]
    ):
        gen = RiskStatementGenerator()
        with pytest.raises(OfflineViolationError):
            gen.generate(gap, system_context)


# -----------------------------------------------------------------------------
# Sync generate — structured event emission
# -----------------------------------------------------------------------------


def test_generate_emits_ai_risk_generated_event_on_success(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        with caplog.at_level("INFO", logger="evidentia.ai.risk_statements"):
            gen.generate(gap, system_context)
    success_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_GENERATED.value
        )
    ]
    assert len(success_records) >= 1


def test_generate_emits_ai_risk_failed_event_on_unrecoverable_failure(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    gap = _make_gap()
    with (
        _patched_sync_create(side_effect=[RuntimeError("boom")]),
        caplog.at_level("ERROR", logger="evidentia.ai.risk_statements"),
        pytest.raises(RiskGenerationFailed),
    ):
        gen = RiskStatementGenerator()
        gen.generate(gap, system_context)
    failure_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_FAILED.value
        )
    ]
    assert len(failure_records) == 1


def test_generate_emits_ai_risk_retry_event_on_each_retry(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    gap = _make_gap()
    side_effect = [
        _make_litellm_exc(RateLimitError),
        _make_litellm_exc(RateLimitError),
        _fake_risk_statement(),
    ]
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        with caplog.at_level("WARNING", logger="evidentia.audit.retry"):
            gen.generate(gap, system_context)
    retry_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_RETRY.value
        )
    ]
    # 3 attempts total → 2 before_sleep callbacks → 2 retry events
    assert len(retry_records) == 2


# -----------------------------------------------------------------------------
# Sync batch — log-and-continue tolerance
# -----------------------------------------------------------------------------


def test_generate_batch_continues_past_failures(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2"), _make_gap("AC-3"), _make_gap("AC-6")]
    side_effect: list[Any] = [
        _fake_risk_statement(),
        RuntimeError("boom on AC-3"),
        _fake_risk_statement(),
    ]
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        results = gen.generate_batch(gaps, system_context)
    assert len(results) == 2  # AC-3 dropped; AC-2 + AC-6 kept


def test_generate_batch_threads_one_run_id_through_all_outputs(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        results = gen.generate_batch(gaps, system_context)
    assert len(results) == 2
    assert results[0].generation_context is not None
    assert results[1].generation_context is not None
    assert results[0].generation_context.run_id == results[1].generation_context.run_id


def test_generate_batch_air_gap_violation_aborts_batch(
    system_context: SystemContext,
) -> None:
    """A single OfflineViolationError must abort the whole batch, NOT be
    swallowed by the per-gap try/except."""
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_sync_create(
        side_effect=[OfflineViolationError(subsystem="evidentia_ai", target="gpt-4o"), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        with pytest.raises(OfflineViolationError):
            gen.generate_batch(gaps, system_context)


def test_generate_batch_progress_callback_invoked_per_success(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    progress_calls: list[tuple[int, int]] = []

    def on_progress(current: int, total: int) -> None:
        progress_calls.append((current, total))

    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        gen.generate_batch(gaps, system_context, on_progress=on_progress)
    assert progress_calls == [(1, 2), (2, 2)]


# -----------------------------------------------------------------------------
# Async paths
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_async_success_attaches_context(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    with _patched_async_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator(model="claude-sonnet-4")
        result = await gen.generate_async(gap, system_context)
    assert result.generation_context is not None
    assert result.generation_context.model == "claude-sonnet-4"
    assert result.generation_context.attempts == 1


@pytest.mark.asyncio
async def test_generate_async_retries_then_succeeds(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    side_effect = [
        _make_litellm_exc(RateLimitError),
        _make_litellm_exc(RateLimitError),
        _fake_risk_statement(),
    ]
    with _patched_async_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        result = await gen.generate_async(gap, system_context)
    assert result.generation_context is not None
    assert result.generation_context.attempts == 3


@pytest.mark.asyncio
async def test_generate_async_exhausted_raises_llm_unavailable(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    side_effect = [_make_litellm_exc(RateLimitError) for _ in range(5)]
    with _patched_async_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        with pytest.raises(LLMUnavailableError):
            await gen.generate_async(gap, system_context)


@pytest.mark.asyncio
async def test_generate_async_offline_violation_propagates(
    system_context: SystemContext,
) -> None:
    gap = _make_gap()
    with _patched_async_create(
        side_effect=[OfflineViolationError(subsystem="evidentia_ai", target="gpt-4o")]
    ):
        gen = RiskStatementGenerator()
        with pytest.raises(OfflineViolationError):
            await gen.generate_async(gap, system_context)


@pytest.mark.asyncio
async def test_generate_batch_async_continues_past_failures(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2"), _make_gap("AC-3"), _make_gap("AC-6")]
    side_effect: list[Any] = [
        _fake_risk_statement(),
        RuntimeError("boom on AC-3"),
        _fake_risk_statement(),
    ]
    with _patched_async_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        results = await gen.generate_batch_async(gaps, system_context)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_generate_batch_async_air_gap_aborts(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2")]
    with _patched_async_create(
        side_effect=[OfflineViolationError(subsystem="evidentia_ai", target="gpt-4o")]
    ):
        gen = RiskStatementGenerator()
        with pytest.raises(OfflineViolationError):
            await gen.generate_batch_async(gaps, system_context)


@pytest.mark.asyncio
async def test_generate_batch_async_threads_single_run_id(
    system_context: SystemContext,
) -> None:
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_async_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        results = await gen.generate_batch_async(gaps, system_context)
    assert len(results) == 2
    assert results[0].generation_context is not None
    assert results[1].generation_context is not None
    assert results[0].generation_context.run_id == results[1].generation_context.run_id


# -----------------------------------------------------------------------------
# Post-review fixes (H1, H2, H3, L2, M2, M4)
# -----------------------------------------------------------------------------


def test_h3_credential_identity_populated_from_helper(
    system_context: SystemContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H3: GenerationContext.credential_identity is populated from the
    operator-identity helper so AI artifacts satisfy NIST AU-3 'Identity'."""
    monkeypatch.setenv("EVIDENTIA_AI_OPERATOR", "alice@acme.com")
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        result = gen.generate(gap, system_context)
    assert result.generation_context is not None
    assert result.generation_context.credential_identity == "alice@acme.com"


def test_h1_failure_event_carries_run_id_from_batch(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """H1: AI_RISK_FAILED events MUST carry the batch run_id so SIEM can
    correlate failures back to the batch via evidentia.run_id."""
    gaps = [_make_gap("AC-2"), _make_gap("AC-3"), _make_gap("AC-6")]
    side_effect: list[Any] = [
        _fake_risk_statement(),
        RuntimeError("boom"),  # AC-3 fails
        _fake_risk_statement(),
    ]
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        with caplog.at_level("ERROR", logger="evidentia.ai.risk_statements"):
            results = gen.generate_batch(gaps, system_context)

    failure_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"] == EventAction.AI_RISK_FAILED.value
        )
    ]
    assert len(failure_records) == 1
    failure_run_id = failure_records[0].ecs_record["evidentia"]["run_id"]
    # Must match the run_id on the surviving outputs
    assert failure_run_id is not None
    assert results[0].generation_context is not None
    assert failure_run_id == results[0].generation_context.run_id


def test_h2_retry_events_inherit_trace_id_from_run_id(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """H2: AI_RISK_RETRY events emitted from inside the retry loop MUST
    inherit trace.id from the run_id scope, so retry storms tie back to
    their batch in SIEM."""
    gap = _make_gap()
    side_effect = [
        _make_litellm_exc(RateLimitError),
        _make_litellm_exc(RateLimitError),
        _fake_risk_statement(),
    ]
    explicit_run_id = "01HXBBBBBBBBBBBBBBBBBBBBBB"
    with _patched_sync_create(side_effect=side_effect):
        gen = RiskStatementGenerator()
        with caplog.at_level("WARNING", logger="evidentia.audit.retry"):
            gen.generate(gap, system_context, run_id=explicit_run_id)

    retry_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"] == EventAction.AI_RISK_RETRY.value
        )
    ]
    assert len(retry_records) == 2
    for rec in retry_records:
        assert rec.ecs_record["trace"]["id"] == explicit_run_id


def test_l2_success_event_carries_prompt_hash(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """L2: AI_RISK_GENERATED success events surface prompt_hash for SIEM
    correlation between the log event and the artifact's GenerationContext."""
    gap = _make_gap()
    with _patched_sync_create(side_effect=[_fake_risk_statement()]):
        gen = RiskStatementGenerator()
        with caplog.at_level("INFO", logger="evidentia.ai.risk_statements"):
            result = gen.generate(gap, system_context)

    success_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_GENERATED.value
        )
    ]
    assert len(success_records) >= 1
    assert result.generation_context is not None
    log_hash = success_records[0].ecs_record["evidentia"]["prompt_hash"]
    assert log_hash == result.generation_context.prompt_hash


def test_m2_batch_emits_distinct_batch_completed_event(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """M2: Batch summary uses AI_RISK_BATCH_COMPLETED, not AI_RISK_GENERATED,
    so SIEM 'count of risks' queries don't double-count."""
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        with caplog.at_level("INFO", logger="evidentia.ai.risk_statements"):
            gen.generate_batch(gaps, system_context)

    batch_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_BATCH_COMPLETED.value
        )
    ]
    assert len(batch_records) == 1
    # Per-call AI_RISK_GENERATED still fire \u2014 one per gap
    per_call_records = [
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_GENERATED.value
        )
    ]
    assert len(per_call_records) == 2


def test_m4_partial_batch_outcome_is_unknown_not_success(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """M4: When succeeded < total, batch outcome is UNKNOWN per ECS spec
    (NOT misleadingly SUCCESS)."""
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), RuntimeError("boom")]
    ):
        gen = RiskStatementGenerator()
        with caplog.at_level("INFO", logger="evidentia.ai.risk_statements"):
            gen.generate_batch(gaps, system_context)

    batch_record = next(
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_BATCH_COMPLETED.value
        )
    )
    assert batch_record.ecs_record["event"]["outcome"] == "unknown"
    assert batch_record.ecs_record["evidentia"]["succeeded"] == 1
    assert batch_record.ecs_record["evidentia"]["failed"] == 1
    assert batch_record.ecs_record["evidentia"]["total"] == 2


def test_m4_full_success_batch_outcome_is_success(
    system_context: SystemContext, caplog: pytest.LogCaptureFixture
) -> None:
    """Counter-test: when every gap succeeds, batch outcome IS success."""
    gaps = [_make_gap("AC-2"), _make_gap("AC-3")]
    with _patched_sync_create(
        side_effect=[_fake_risk_statement(), _fake_risk_statement()]
    ):
        gen = RiskStatementGenerator()
        with caplog.at_level("INFO", logger="evidentia.ai.risk_statements"):
            gen.generate_batch(gaps, system_context)

    batch_record = next(
        r for r in caplog.records
        if (
            hasattr(r, "ecs_record")
            and r.ecs_record["event"]["action"]
            == EventAction.AI_RISK_BATCH_COMPLETED.value
        )
    )
    assert batch_record.ecs_record["event"]["outcome"] == "success"
    assert batch_record.ecs_record["evidentia"]["failed"] == 0
