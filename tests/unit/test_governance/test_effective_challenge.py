"""Unit tests for EffectiveChallenge schema + store (v0.7.10 P1.5 G2)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.effective_challenge_store import (
    CHALLENGE_STORE_ENV_VAR,
    InvalidChallengeIdError,
    delete_challenge,
    get_challenge_store_dir,
    list_challenges,
    load_challenge_by_id,
    save_challenge,
)
from evidentia_core.governance import (
    ChallengeOutcome,
    EffectiveChallenge,
)
from pydantic import ValidationError

# ── enums + schema ─────────────────────────────────────────────────


class TestChallengeOutcome:
    def test_four_values(self) -> None:
        values = {o.value for o in ChallengeOutcome}
        assert values == {"accepted", "rejected", "modify", "pending"}


def _minimal_challenge() -> EffectiveChallenge:
    return EffectiveChallenge(
        subject_model_id="aaaa1111-2222-3333-4444-555566667777",
        challenger_email="mrm-director@example.com",
        challenger_role="MRM Director",
        challenge_date=date(2026, 1, 15),
        challenge_topic="Methodology — feature selection rationale",
        challenge_substance=(
            "Why were 5 alternative feature sets evaluated? Show the comparison + selection criteria."
        ),
    )


class TestEffectiveChallenge:
    def test_minimal_construction(self) -> None:
        c = _minimal_challenge()
        assert c.id  # auto-UUID
        assert c.outcome == ChallengeOutcome.PENDING.value
        assert c.response is None
        assert c.resolved_at is None
        assert c.created_at is not None
        assert c.evidentia_version

    def test_with_outcome_and_response(self) -> None:
        c = EffectiveChallenge(
            subject_model_id="aaaa1111-2222-3333-4444-555566667777",
            challenger_email="x@y.com",
            challenger_role="Audit",
            challenge_date=date(2026, 1, 1),
            challenge_topic="x",
            challenge_substance="y",
            response="Comparison documented in section 4 of model doc.",
            outcome=ChallengeOutcome.ACCEPTED,
            outcome_rationale="Documentation gap closed.",
            resolved_at=date(2026, 2, 1),
        )
        assert c.outcome == ChallengeOutcome.ACCEPTED.value
        assert c.resolved_at == date(2026, 2, 1)

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EffectiveChallenge(  # type: ignore[call-arg]
                subject_model_id="aaaa1111-2222-3333-4444-555566667777",
                challenger_email="x@y.com",
                challenger_role="x",
                challenge_date=date(2026, 1, 1),
                challenge_topic="x",
                challenge_substance="y",
                bogus="should fail",
            )


# ── store ──────────────────────────────────────────────────────────


@pytest.fixture()
def isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "challenge-store"
    monkeypatch.setenv(CHALLENGE_STORE_ENV_VAR, str(store))
    return store


class TestStoreDirResolution:
    def test_env_var_overrides_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = tmp_path / "from-env"
        monkeypatch.setenv(CHALLENGE_STORE_ENV_VAR, str(target))
        resolved = get_challenge_store_dir()
        assert resolved == target

    def test_explicit_override_beats_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(CHALLENGE_STORE_ENV_VAR, str(tmp_path / "env"))
        explicit = tmp_path / "explicit"
        resolved = get_challenge_store_dir(override=explicit)
        assert resolved == explicit


class TestSaveLoad:
    def test_save_and_load_round_trip(self, isolated_store: Path) -> None:
        c = _minimal_challenge()
        save_challenge(c)
        loaded = load_challenge_by_id(c.id)
        assert loaded is not None
        assert loaded.id == c.id
        assert loaded.challenge_topic == c.challenge_topic
        assert loaded.subject_model_id == c.subject_model_id

    def test_save_atomic_no_tmp_leftover(self, isolated_store: Path) -> None:
        c = _minimal_challenge()
        save_challenge(c)
        # No .tmp files should linger
        tmp_files = list(isolated_store.glob("*.tmp"))
        assert tmp_files == []

    def test_save_refreshes_updated_at(self, isolated_store: Path) -> None:
        from datetime import timedelta

        from evidentia_core.models.common import utc_now

        c = _minimal_challenge()
        original = utc_now() - timedelta(days=10)
        c2 = c.model_copy(update={"updated_at": original})
        save_challenge(c2)
        loaded = load_challenge_by_id(c2.id)
        assert loaded is not None
        assert loaded.updated_at > original

    def test_load_unknown_returns_none(self, isolated_store: Path) -> None:
        result = load_challenge_by_id("00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_load_invalid_id_shape_raises(self, isolated_store: Path) -> None:
        with pytest.raises(InvalidChallengeIdError):
            load_challenge_by_id("not-a-uuid")

    def test_save_invalid_id_raises_via_path_traversal(self, isolated_store: Path) -> None:
        c = _minimal_challenge()
        c2 = c.model_copy(update={"id": "../escape"})
        with pytest.raises(InvalidChallengeIdError):
            save_challenge(c2)


class TestList:
    def test_empty_returns_empty(self, isolated_store: Path) -> None:
        assert list_challenges() == []

    def test_sort_by_date_descending(self, isolated_store: Path) -> None:
        old = _minimal_challenge()
        old2 = old.model_copy(update={"challenge_date": date(2025, 6, 1)})
        new = _minimal_challenge()
        new2 = new.model_copy(update={"challenge_date": date(2026, 6, 1)})
        save_challenge(old2)
        save_challenge(new2)
        listed = list_challenges()
        assert len(listed) == 2
        # Newest first
        assert listed[0].challenge_date == date(2026, 6, 1)
        assert listed[1].challenge_date == date(2025, 6, 1)


class TestDelete:
    def test_delete_returns_true(self, isolated_store: Path) -> None:
        c = _minimal_challenge()
        save_challenge(c)
        assert delete_challenge(c.id) is True
        assert load_challenge_by_id(c.id) is None

    def test_delete_unknown_returns_false(self, isolated_store: Path) -> None:
        assert delete_challenge("00000000-0000-0000-0000-000000000000") is False

    def test_delete_invalid_id_raises(self, isolated_store: Path) -> None:
        with pytest.raises(InvalidChallengeIdError):
            delete_challenge("not-a-uuid")
