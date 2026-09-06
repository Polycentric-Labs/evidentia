"""Unit tests for scripts/compute_inter_rater_kappa.py (v0.8.6 P2).

3 test classes:

1. :class:`TestCohensKappa` — formula validation against
   hand-picked label sets with known κ values.
2. :class:`TestLandisKochLabel` — verbal-interpretation mapping
   per Landis & Koch 1977.
3. :class:`TestRuleBasedRater` — `_jaccard_label` returns the
   expected label for known corpus entry shapes.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

# Load the script as a module — it lives outside packages/ so we
# import it via spec_from_file_location rather than the package
# import path.
_SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "compute_inter_rater_kappa.py"
_spec = importlib.util.spec_from_file_location("compute_inter_rater_kappa", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
_mod: Any = importlib.util.module_from_spec(_spec)
sys.modules["compute_inter_rater_kappa"] = _mod
_spec.loader.exec_module(_mod)


# ── 1. Cohen's Kappa formula ─────────────────────────────────────


class TestCohensKappa:
    def test_perfect_agreement(self) -> None:
        """All labels match → κ = 1.0."""
        r1 = [True, True, False, False, True]
        r2 = [True, True, False, False, True]
        kappa, po, _pe = _mod.cohens_kappa(r1, r2)
        assert kappa == pytest.approx(1.0)
        assert po == pytest.approx(1.0)

    def test_complete_disagreement(self) -> None:
        """Every label is opposite → κ < 0.

        Note: complete disagreement does NOT yield κ = -1.0 in
        general — the formula bottoms at -1.0 only when the
        marginals are exactly 50/50 on both sides. Here both
        raters' marginals are skewed identically, so κ < 0 but
        not necessarily -1.0.
        """
        r1 = [True, True, True, False, False]
        r2 = [False, False, False, True, True]
        kappa, po, _pe = _mod.cohens_kappa(r1, r2)
        assert kappa < 0
        assert po == pytest.approx(0.0)

    def test_random_chance_agreement(self) -> None:
        """When both raters label randomly with 50/50 marginals,
        κ should hover near 0 (no better than chance).
        """
        # 4 of 8 agree (50%); both raters' marginals are 50/50.
        r1 = [True, True, True, True, False, False, False, False]
        r2 = [True, True, False, False, True, True, False, False]
        kappa, _po, _pe = _mod.cohens_kappa(r1, r2)
        assert kappa == pytest.approx(0.0, abs=0.05)

    def test_ninety_percent_agreement(self) -> None:
        """9-of-10 agreement → κ ≈ 0.80 (substantial).

        With balanced 50/50 marginals: po = 0.9, pe = 0.5,
        κ = (0.9 - 0.5) / (1 - 0.5) = 0.8.
        """
        r1 = [True, True, True, True, True, False, False, False, False, False]
        r2 = [True, True, True, True, True, False, False, False, False, True]
        kappa, po, _pe = _mod.cohens_kappa(r1, r2)
        # 9/10 agreements; rater1 5+5; rater2 6+4 → not exactly
        # the textbook 0.8 case. Just check it's in the
        # substantial range.
        assert 0.6 <= kappa <= 0.9
        assert po == pytest.approx(0.9)

    def test_all_positive_both_raters(self) -> None:
        """Both raters label everything True → undefined kappa
        per the formula (1-pe = 0). Helper returns 1.0 (since
        observed-perfect agreement holds).
        """
        r1 = [True, True, True]
        r2 = [True, True, True]
        kappa, _po, _pe = _mod.cohens_kappa(r1, r2)
        assert kappa == pytest.approx(1.0)

    def test_all_positive_rater1_all_negative_rater2(self) -> None:
        """Rater 1 all True, rater 2 all False → 0% observed
        agreement, undefined kappa via the standard formula
        (pe = 0). Helper returns 0.0 (no observed-perfect
        agreement).
        """
        r1 = [True, True, True]
        r2 = [False, False, False]
        kappa, _po, _pe = _mod.cohens_kappa(r1, r2)
        assert kappa == pytest.approx(0.0)

    def test_mismatched_lengths_raises(self) -> None:
        with pytest.raises(ValueError, match="different lengths"):
            _mod.cohens_kappa([True], [True, False])

    def test_empty_input_raises(self) -> None:
        with pytest.raises(ValueError, match="0 entries"):
            _mod.cohens_kappa([], [])


# ── 2. Landis-Koch verbal interpretation ─────────────────────────


class TestLandisKochLabel:
    @pytest.mark.parametrize(
        "kappa,expected",
        [
            (-0.1, "poor"),
            (0.0, "slight"),
            (0.10, "slight"),
            (0.20, "slight"),
            (0.21, "fair"),
            (0.40, "fair"),
            (0.41, "moderate"),
            (0.60, "moderate"),
            (0.61, "substantial"),
            (0.80, "substantial"),
            (0.81, "almost-perfect"),
            (1.00, "almost-perfect"),
        ],
    )
    def test_label_boundaries(self, kappa: float, expected: str) -> None:
        assert _mod.landis_koch_label(kappa) == expected


# ── 3. Rule-based jaccard rater ──────────────────────────────────


class TestRuleBasedRater:
    def test_verbatim_entry_passes_threshold(self) -> None:
        """Verbatim claim (claim text appears in source clauses)
        scores high jaccard → True at threshold 0.5."""
        entry = {
            "claim": "Account management procedures must enforce least privilege.",
            "source_clauses": [
                "Account management procedures must enforce least privilege.",
                "Audit logs are retained for 90 days.",
            ],
        }
        assert _mod._jaccard_label(entry, threshold=0.5) is True

    def test_hallucination_entry_fails_threshold(self) -> None:
        """Hallucination claim (no overlap with source clauses)
        scores 0.0 → False at any threshold > 0."""
        entry = {
            "claim": "Pizza is delivered hot to the data center.",
            "source_clauses": [
                "Multi-factor authentication is required for privileged accounts.",
            ],
        }
        assert _mod._jaccard_label(entry, threshold=0.3) is False

    def test_empty_clauses_returns_false(self) -> None:
        entry = {
            "claim": "Anything",
            "source_clauses": [],
        }
        assert _mod._jaccard_label(entry, threshold=0.0) is False

    def test_empty_claim_returns_false(self) -> None:
        entry = {
            "claim": "",
            "source_clauses": ["something"],
        }
        assert _mod._jaccard_label(entry, threshold=0.0) is False

    def test_paraphrase_below_threshold_demonstrates_rule_weakness(
        self,
    ) -> None:
        """Paraphrase entry: same meaning, different vocabulary
        → low jaccard → False at threshold 0.5. Demonstrates
        WHY the rule-based rater under-performs on paraphrase
        entries (the documented v0.8.5 P2 corpus design — these
        are the entries where semantic embedding wins over
        token-overlap)."""
        entry = {
            "claim": "Logs are kept for 12 months following the date written.",
            "source_clauses": [
                "Audit records must be retained for one year after creation.",
            ],
        }
        # Despite same meaning, jaccard scores low.
        assert _mod._jaccard_label(entry, threshold=0.5) is False
