"""Generate plain-English explanations for compliance controls using an LLM.

v0.7.1 enterprise-grade refactor (mirrors the v0.7.1 risk-statements
refactor exactly):

- Stdlib ``logging`` replaced with
  :func:`evidentia_core.audit.get_logger` for ECS-8.11 structured
  output.
- LLM call wrapped in bounded retry via
  :func:`evidentia_core.audit.build_retrying` against the shared
  :data:`evidentia_ai.exceptions.LLM_TRANSIENT_EXCEPTIONS` set. Retry
  events tag as
  :attr:`~evidentia_core.audit.events.EventAction.AI_EXPLAIN_RETRY`.
- Typed exception hierarchy
  (:class:`~evidentia_ai.exceptions.ExplainError` and friends).
- Cache-miss outputs carry a
  :class:`~evidentia_core.audit.provenance.GenerationContext` block;
  cache-hit returns preserve whatever was cached (no re-mint).
- Air-gap policy violations
  (:class:`~evidentia_core.network_guard.OfflineViolationError`)
  propagate unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import litellm
from evidentia_core.audit import (
    EventAction,
    EventOutcome,
    GenerationContext,
    build_retrying,
    compute_prompt_hash,
    get_logger,
    new_run_id,
)
from evidentia_core.models.catalog import CatalogControl
from evidentia_core.network_guard import OfflineViolationError
from instructor.core import InstructorRetryException

from evidentia_ai.client import (
    get_default_model,
    get_instructor_client,
    get_operator_identity,
    get_temperature,
)
from evidentia_ai.exceptions import (
    LLM_TRANSIENT_EXCEPTIONS as _LLM_TRANSIENT_EXCEPTIONS,
)
from evidentia_ai.exceptions import (
    ExplainGenerationFailed,
    LLMUnavailableError,
    LLMValidationError,
)
from evidentia_ai.explain.cache import load_cached, store
from evidentia_ai.explain.models import PlainEnglishExplanation

_log = get_logger("evidentia.ai.explain")


@contextmanager
def _no_scope() -> Iterator[None]:
    """No-op context manager used when no run_id is available to scope on."""
    yield


EXPLAIN_SYSTEM_PROMPT = """\
You are a compliance translator. Your job is to take control text written for
compliance auditors and policy writers — which is dense, formal, and written
for legal defensibility — and rewrite it so an engineer or executive can act
on it without a compliance specialist's help.

RULES for every field you produce:

1. Plain language. Zero acronyms without expansion. Zero jargon like "shall",
   "commensurate", "consistent with the foregoing".

2. Concrete over abstract. "Configure Okta" beats "Implement identity
   governance"; "Review IAM roles quarterly" beats "Perform periodic access
   review".

3. Honest about effort. If this control really requires a FedRAMP 3PAO and
   $200K of consulting time, say so. If it's a one-afternoon Terraform change,
   say so. Compliance teams lose trust when tooling pretends hard things are
   easy.

4. Threat-grounded. When explaining "why it matters", tie to a real-world
   attack pattern: credential stuffing, supply-chain compromise, insider
   exfil, ransomware lateral movement. Avoid abstract "maintain security
   posture" language.

5. Neutral on vendors. Don't recommend specific products unless the control
   genuinely names one (e.g., "FIPS 140-2 validated crypto modules"). "Your
   IdP" is fine; "Okta" is not fine unless Okta is actually the thing.
"""


def _build_user_prompt(control: CatalogControl, framework_id: str) -> str:
    desc = (control.description or "").strip() or "(no description in catalog)"
    family = f"\nFamily: {control.family}" if control.family else ""
    guidance = f"\n\nOSCAL guidance:\n{control.guidance}" if getattr(control, "guidance", None) else ""
    return (
        f"Framework: {framework_id}\n"
        f"Control ID: {control.id}\n"
        f"Control title: {control.title}{family}\n\n"
        f"Authoritative text:\n{desc}{guidance}\n\n"
        f"Produce a plain-English explanation following the system prompt rules. "
        f"Populate every field of the PlainEnglishExplanation schema."
    )


class ExplanationGenerator:
    """Plain-English explanation factory.

    Usage::

        gen = ExplanationGenerator(model="claude-sonnet-4", temperature=0.2)
        exp = gen.generate(control, framework_id="nist-800-53-rev5")

    Caching is on by default — repeated calls for the same
    ``(framework, control, model, temperature)`` tuple return the disk
    cache hit instantly. Pass ``use_cache=False`` to force a fresh
    generation, or call ``generate(..., refresh=True)``.

    Failure modes (v0.7.1):

    - :class:`LLMUnavailableError` — LiteLLM transient exception
      survived 3 retries.
    - :class:`LLMValidationError` — Instructor's validation retries
      were exhausted.
    - :class:`ExplainGenerationFailed` — anything else unexpected.
    - :class:`OfflineViolationError` — propagates unchanged.

    Cache hits never raise (they short-circuit before any LLM call).
    """

    def __init__(
        self,
        model: str | None = None,
        temperature: float | None = None,
        max_retries: int = 3,
        use_cache: bool = True,
        cache_dir: Path | None = None,
    ) -> None:
        self.model = model or get_default_model()
        self.temperature = temperature if temperature is not None else get_temperature()
        self.max_retries = max_retries
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        self.client = get_instructor_client()

    def _invoke_llm_sync(
        self,
        system_prompt: str,
        user_prompt: str,
        run_id: str | None = None,
    ) -> tuple[PlainEnglishExplanation, int]:
        retrying = build_retrying(
            function_name="explanation_generate",
            max_attempts=3,
            retry_on=_LLM_TRANSIENT_EXCEPTIONS,
            event_action=EventAction.AI_EXPLAIN_RETRY,
        )
        last_attempt = 0
        result: PlainEnglishExplanation | None = None
        # H2: scope retry events with the run_id so before_sleep emissions
        # in retry.py inherit trace.id (visible to SIEM correlation).
        with _log.scope(trace_id=run_id) if run_id else _no_scope():
            for attempt in retrying:
                with attempt:
                    last_attempt = attempt.retry_state.attempt_number
                    result = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        response_model=PlainEnglishExplanation,
                        max_retries=self.max_retries,
                        temperature=self.temperature,
                    )
        # M1: explicit raise survives -O (which strips asserts).
        if result is None:
            raise RuntimeError(
                "Internal invariant violated: tenacity retry loop exited without populating result and without raising."
            )
        return result, last_attempt

    def _build_generation_context(
        self,
        system_prompt: str,
        user_prompt: str,
        attempts: int,
        run_id: str | None = None,
    ) -> GenerationContext:
        return GenerationContext(
            model=self.model,
            temperature=self.temperature,
            prompt_hash=compute_prompt_hash(system_prompt, user_prompt),
            run_id=run_id if run_id is not None else new_run_id(),
            attempts=attempts,
            instructor_max_retries=self.max_retries,
            credential_identity=get_operator_identity(),
        )

    def generate(
        self,
        control: CatalogControl,
        framework_id: str,
        refresh: bool = False,
    ) -> PlainEnglishExplanation:
        """Return an explanation, from cache if available."""
        control_label = f"{framework_id}:{control.id}"

        # ── Cache hit fast path ───────────────────────────────────────
        if self.use_cache and not refresh:
            cached = load_cached(
                framework_id,
                control.id,
                self.model,
                self.temperature,
                cache_dir=self.cache_dir,
            )
            if cached is not None:
                self._emit_cache_hit(control_label, cached)
                return cached

        # ── Cache miss: invoke the LLM ────────────────────────────────
        prompt = _build_user_prompt(control, framework_id)
        # Mint a fresh run_id per generation so cache misses tie their
        # AI_EXPLAIN_GENERATED event to their AI_EXPLAIN_RETRY events
        # via trace.id correlation.
        run_id = new_run_id()

        try:
            explanation, attempts = self._invoke_llm_sync(EXPLAIN_SYSTEM_PROMPT, prompt, run_id=run_id)
        except OfflineViolationError:
            # Programmer/policy error — must surface to the operator.
            raise
        except _LLM_TRANSIENT_EXCEPTIONS as exc:
            self._emit_failure(control_label, exc, "transient_after_retries", run_id)
            raise LLMUnavailableError(
                f"LLM transient error for {control_label} after retries: {type(exc).__name__}: {exc}"
            ) from exc
        except InstructorRetryException as exc:
            self._emit_failure(control_label, exc, "validation_exhausted", run_id)
            raise LLMValidationError(f"Instructor validation retries exhausted for {control_label}: {exc}") from exc
        except Exception as exc:
            self._emit_failure(control_label, exc, "unexpected", run_id)
            raise ExplainGenerationFailed(
                f"Unexpected explanation failure for {control_label}: {type(exc).__name__}: {exc}"
            ) from exc

        # ── Post-generation enrichment ────────────────────────────────
        gen_ctx = self._build_generation_context(EXPLAIN_SYSTEM_PROMPT, prompt, attempts, run_id=run_id)
        # Enforce echo fields in case the LLM drifted, AND attach provenance.
        explanation = explanation.model_copy(
            update={
                "framework_id": framework_id,
                "control_id": control.id,
                "control_title": control.title,
                "generation_context": gen_ctx,
            }
        )

        if self.use_cache:
            store(
                explanation,
                self.model,
                self.temperature,
                cache_dir=self.cache_dir,
            )

        self._emit_success(explanation, control_label, attempts)
        return explanation

    # Exposed so tests can stub without reaching into litellm internals.
    def _litellm_module(self):  # type: ignore[no-untyped-def]
        return litellm

    # ── Structured event helpers ──────────────────────────────────────

    def _emit_cache_hit(self, control_label: str, cached: PlainEnglishExplanation) -> None:
        # Cached explanations may carry a v0.7.1 GenerationContext OR be from
        # a pre-v0.7.1 cache write (no provenance). Surface whatever we have
        # so SIEM can join cache hits to their original generation event.
        cached_ctx = cached.generation_context
        _log.info(
            action=EventAction.AI_EXPLAIN_CACHE_HIT,
            outcome=EventOutcome.SUCCESS,
            message=f"Cached explanation hit for {control_label} (no LLM call)",
            evidentia={
                "model": self.model,
                "control_label": control_label,
                "cached_run_id": (cached_ctx.run_id if cached_ctx is not None else None),
                "cached_prompt_hash": (cached_ctx.prompt_hash if cached_ctx is not None else None),
            },
        )

    def _emit_success(
        self,
        explanation: PlainEnglishExplanation,
        control_label: str,
        attempts: int,
    ) -> None:
        gen_ctx = explanation.generation_context
        _log.info(
            action=EventAction.AI_EXPLAIN_GENERATED,
            outcome=EventOutcome.SUCCESS,
            message=(f"Generated explanation for {control_label} (attempts={attempts})"),
            evidentia={
                "model": self.model,
                "control_label": control_label,
                "attempts": attempts,
                # H1+L2: surface run_id and prompt_hash so SIEM can join the
                # log event to the artifact-level GenerationContext block.
                "run_id": gen_ctx.run_id if gen_ctx is not None else None,
                "prompt_hash": gen_ctx.prompt_hash if gen_ctx is not None else None,
            },
        )

    def _emit_failure(
        self,
        control_label: str,
        exc: BaseException,
        failure_kind: str,
        run_id: str | None = None,
    ) -> None:
        _log.error(
            action=EventAction.AI_EXPLAIN_FAILED,
            outcome=EventOutcome.FAILURE,
            message=(
                f"Explanation generation failed for {control_label} ({failure_kind}): {type(exc).__name__}: {exc}"
            ),
            error={
                "type": type(exc).__name__,
                "message": str(exc),
            },
            evidentia={
                "model": self.model,
                "control_label": control_label,
                "failure_kind": failure_kind,
                # H1: thread the run_id into failure events so SIEM
                # queries on evidentia.run_id surface successes AND failures.
                "run_id": run_id,
            },
        )


__all__ = [
    "EXPLAIN_SYSTEM_PROMPT",
    "ExplanationGenerator",
]
