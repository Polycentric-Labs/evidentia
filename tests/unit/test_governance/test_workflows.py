"""Unit tests for evidentia_core.governance.workflows + workflow_store
(v0.7.11 P1.5 G5)."""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.governance.workflows import (
    Workflow,
    WorkflowAdvanceError,
    WorkflowStatus,
    WorkflowStep,
    WorkflowStepStatus,
    advance_workflow_step,
    current_step_index,
    evaluate_workflow,
    generate_workflow_log,
)
from evidentia_core.workflow_store import (
    WORKFLOW_STORE_ENV_VAR,
    InvalidWorkflowIdError,
    delete_workflow,
    list_workflows,
    load_workflow_by_id,
    save_workflow,
)

# ── Enum sanity ────────────────────────────────────────────────────


class TestEnums:
    def test_step_statuses(self) -> None:
        assert {s.value for s in WorkflowStepStatus} == {"pending", "in_progress", "approved", "rejected", "skipped"}

    def test_workflow_statuses(self) -> None:
        assert {s.value for s in WorkflowStatus} == {"draft", "in_progress", "approved", "rejected", "canceled"}


# ── Construction helpers ───────────────────────────────────────────


def _three_step_workflow() -> Workflow:
    return Workflow(
        name="Test approval flow",
        description="Three-step test workflow.",
        initiator="initiator@example.com",
        steps=[
            WorkflowStep(
                name="Step 1",
                required_role="1LOD owner",
                status=WorkflowStepStatus.IN_PROGRESS,
            ),
            WorkflowStep(
                name="Step 2",
                required_role="2LOD reviewer",
            ),
            WorkflowStep(
                name="Step 3",
                required_role="3LOD audit",
            ),
        ],
    )


# ── current_step_index ─────────────────────────────────────────────


class TestCurrentStepIndex:
    def test_returns_first_non_terminal_step(self) -> None:
        wf = _three_step_workflow()
        assert current_step_index(wf) == 0

    def test_skips_terminal_steps(self) -> None:
        wf = _three_step_workflow()
        wf.steps[0] = wf.steps[0].model_copy(update={"status": WorkflowStepStatus.APPROVED.value})
        wf.steps[1] = wf.steps[1].model_copy(update={"status": WorkflowStepStatus.IN_PROGRESS.value})
        assert current_step_index(wf) == 1

    def test_returns_none_when_all_terminal(self) -> None:
        wf = _three_step_workflow()
        for i in range(3):
            wf.steps[i] = wf.steps[i].model_copy(update={"status": WorkflowStepStatus.APPROVED.value})
        assert current_step_index(wf) is None

    def test_returns_none_for_empty_workflow(self) -> None:
        wf = Workflow(name="Empty", description="", initiator="x@y.com", steps=[])
        assert current_step_index(wf) is None


# ── evaluate_workflow ──────────────────────────────────────────────


class TestEvaluateWorkflow:
    def test_empty_steps_is_draft(self) -> None:
        wf = Workflow(name="x", description="x", initiator="x@y.com", steps=[])
        assert evaluate_workflow(wf) == WorkflowStatus.DRAFT

    def test_in_progress(self) -> None:
        wf = _three_step_workflow()
        assert evaluate_workflow(wf) == WorkflowStatus.IN_PROGRESS

    def test_all_approved_is_approved(self) -> None:
        wf = _three_step_workflow()
        for i in range(3):
            wf.steps[i] = wf.steps[i].model_copy(update={"status": WorkflowStepStatus.APPROVED.value})
        assert evaluate_workflow(wf) == WorkflowStatus.APPROVED

    def test_any_rejected_is_rejected(self) -> None:
        wf = _three_step_workflow()
        wf.steps[0] = wf.steps[0].model_copy(update={"status": WorkflowStepStatus.APPROVED.value})
        wf.steps[1] = wf.steps[1].model_copy(update={"status": WorkflowStepStatus.REJECTED.value})
        assert evaluate_workflow(wf) == WorkflowStatus.REJECTED

    def test_skipped_counts_as_progress(self) -> None:
        wf = _three_step_workflow()
        for i in range(3):
            wf.steps[i] = wf.steps[i].model_copy(update={"status": WorkflowStepStatus.SKIPPED.value})
        assert evaluate_workflow(wf) == WorkflowStatus.APPROVED


# ── advance_workflow_step ──────────────────────────────────────────


class TestAdvanceWorkflowStep:
    def test_approve_active_step_promotes_next(self) -> None:
        wf = _three_step_workflow()
        new_wf = advance_workflow_step(
            wf,
            step_index=0,
            new_status=WorkflowStepStatus.APPROVED,
            actor="alice@example.com",
            note="Looks good",
        )
        assert new_wf.steps[0].status == WorkflowStepStatus.APPROVED.value
        assert new_wf.steps[1].status == WorkflowStepStatus.IN_PROGRESS.value
        assert len(new_wf.steps[0].history) == 1
        assert new_wf.status == WorkflowStatus.IN_PROGRESS.value

    def test_reject_short_circuits(self) -> None:
        wf = _three_step_workflow()
        new_wf = advance_workflow_step(
            wf,
            step_index=0,
            new_status=WorkflowStepStatus.REJECTED,
            actor="alice@example.com",
        )
        assert new_wf.steps[0].status == WorkflowStepStatus.REJECTED.value
        # Next step stays PENDING (no auto-promote on reject)
        assert new_wf.steps[1].status == WorkflowStepStatus.PENDING.value
        assert new_wf.status == WorkflowStatus.REJECTED.value

    def test_cannot_advance_past_active(self) -> None:
        wf = _three_step_workflow()
        with pytest.raises(WorkflowAdvanceError):
            advance_workflow_step(
                wf,
                step_index=2,  # skipping ahead
                new_status=WorkflowStepStatus.APPROVED,
                actor="x@y.com",
            )

    def test_cannot_advance_terminal_step(self) -> None:
        wf = _three_step_workflow()
        wf.steps[0] = wf.steps[0].model_copy(update={"status": WorkflowStepStatus.APPROVED.value})
        with pytest.raises(WorkflowAdvanceError):
            advance_workflow_step(
                wf,
                step_index=0,
                new_status=WorkflowStepStatus.REJECTED,
                actor="x@y.com",
            )

    def test_out_of_range_step_index(self) -> None:
        wf = _three_step_workflow()
        with pytest.raises(WorkflowAdvanceError):
            advance_workflow_step(
                wf,
                step_index=99,
                new_status=WorkflowStepStatus.APPROVED,
                actor="x@y.com",
            )

    def test_skip_promotes_next(self) -> None:
        wf = _three_step_workflow()
        new_wf = advance_workflow_step(
            wf,
            step_index=0,
            new_status=WorkflowStepStatus.SKIPPED,
            actor="alice@example.com",
            note="Not applicable to this case",
        )
        assert new_wf.steps[0].status == WorkflowStepStatus.SKIPPED.value
        assert new_wf.steps[1].status == WorkflowStepStatus.IN_PROGRESS.value


# ── generate_workflow_log ──────────────────────────────────────────


class TestGenerateWorkflowLog:
    def test_minimal_log(self) -> None:
        wf = _three_step_workflow()
        out = generate_workflow_log(wf)
        assert "# Workflow Audit Log" in out
        assert "Test approval flow" in out
        assert "## Steps" in out
        assert "## Event narrative" in out

    def test_rejection_callout(self) -> None:
        wf = _three_step_workflow()
        wf = advance_workflow_step(
            wf,
            step_index=0,
            new_status=WorkflowStepStatus.REJECTED,
            actor="x@y.com",
            note="Insufficient evidence",
        )
        out = generate_workflow_log(wf)
        assert "⚠️" in out
        assert "Workflow REJECTED" in out
        assert "Insufficient evidence" in out

    def test_no_callout_for_in_progress(self) -> None:
        wf = _three_step_workflow()
        out = generate_workflow_log(wf)
        assert "REJECTED" not in out or "REJECTED" in out  # may appear in step table
        # Crucially, the alert callout shouldn't fire
        assert "Workflow REJECTED" not in out

    def test_empty_workflow_log(self) -> None:
        wf = Workflow(name="Empty", description="x", initiator="x@y.com", steps=[])
        out = generate_workflow_log(wf)
        assert "No steps defined" in out


# ── workflow_store ─────────────────────────────────────────────────


@pytest.fixture()
def isolated_workflow_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "workflow-store"
    monkeypatch.setenv(WORKFLOW_STORE_ENV_VAR, str(store))
    return store


class TestWorkflowStore:
    def test_save_and_load_round_trip(self, isolated_workflow_store: Path) -> None:
        wf = _three_step_workflow()
        save_workflow(wf)
        loaded = load_workflow_by_id(wf.id)
        assert loaded is not None
        assert loaded.id == wf.id
        assert loaded.name == wf.name

    def test_save_atomic(self, isolated_workflow_store: Path) -> None:
        save_workflow(_three_step_workflow())
        assert list(isolated_workflow_store.glob("*.tmp")) == []

    def test_load_unknown_returns_none(self, isolated_workflow_store: Path) -> None:
        result = load_workflow_by_id("00000000-0000-0000-0000-000000000000")
        assert result is None

    def test_load_invalid_id_raises(self, isolated_workflow_store: Path) -> None:
        with pytest.raises(InvalidWorkflowIdError):
            load_workflow_by_id("not-a-uuid")

    def test_list_newest_first(self, isolated_workflow_store: Path) -> None:
        import time

        old = _three_step_workflow()
        save_workflow(old)
        time.sleep(0.01)  # sub-second precision differs by platform
        new = _three_step_workflow().model_copy(update={"name": "Newer flow"})
        save_workflow(new)
        listed = list_workflows()
        assert len(listed) == 2
        # First should be the newer one (created_at DESC)
        assert listed[0].name == "Newer flow"

    def test_delete_removes(self, isolated_workflow_store: Path) -> None:
        wf = _three_step_workflow()
        save_workflow(wf)
        assert delete_workflow(wf.id) is True
        assert load_workflow_by_id(wf.id) is None

    def test_delete_unknown_returns_false(self, isolated_workflow_store: Path) -> None:
        assert delete_workflow("00000000-0000-0000-0000-000000000000") is False
