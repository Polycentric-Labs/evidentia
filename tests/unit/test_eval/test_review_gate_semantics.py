"""Eval gate semantics closed by the v0.13.0 review (M19, M20)."""

from __future__ import annotations

from evidentia_eval.faithfulness import (
    DEFAULT_FAITHFULNESS_THRESHOLD,
    DEFAULT_SEMANTIC_FAITHFULNESS_THRESHOLD,
    DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD,
    resolve_threshold,
)


def test_semantic_method_has_its_own_default() -> None:
    assert DEFAULT_SEMANTIC_FAITHFULNESS_THRESHOLD == 0.7
    assert resolve_threshold(None, "semantic") == DEFAULT_SEMANTIC_FAITHFULNESS_THRESHOLD
    assert resolve_threshold("nist-800-53-rev5-moderate", "semantic") == DEFAULT_SEMANTIC_FAITHFULNESS_THRESHOLD


def test_jaccard_defaults_are_unchanged() -> None:
    assert resolve_threshold(None, "jaccard") == DEFAULT_FAITHFULNESS_THRESHOLD
    for framework, threshold in DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD.items():
        assert resolve_threshold(framework, "jaccard") == threshold


def test_run_result_exposes_faithfulness_violations() -> None:
    from evidentia_eval import harness

    result_cls = next(
        cls for name, cls in vars(harness).items() if name.endswith("Result") and hasattr(cls, "replay_violations")
    )
    assert hasattr(result_cls, "faithfulness_violations")
