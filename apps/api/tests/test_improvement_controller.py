"""Integration tests for the Autonomous Self-Improvement Controller and Analytics."""

import pytest
from cyberduel_contracts.enums import CycleStatus
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.lab import FailureFindingRecord, LabExperimentRecord
from apps.api.app.services.improvement.analytics import ImprovementAnalyticsService
from apps.api.app.services.improvement.checkpoints import CheckpointManager
from apps.api.app.services.improvement.controller import SelfImprovementController
from apps.api.app.services.improvement.policy import ControllerPolicyConfig


@pytest.mark.asyncio
async def test_controller_10_step_cycle_execution(test_db_session: AsyncSession) -> None:
    """Verify that SelfImprovementController executes all 10 bounded cycle steps and stores checkpoints."""
    # 1. Seed an experiment and an open failure finding
    experiment = LabExperimentRecord(
        name="adversarial_evasion_test",
        goal="Test evasion discrepancies",
        status="completed",
    )
    test_db_session.add(experiment)
    await test_db_session.flush()

    finding = FailureFindingRecord(
        experiment_id=experiment.id,
        failure_category="evasion",
        discrepancy_type="false_negative",
        hypothesis="Detector missed suspicious homograph punycode domain",
        affected_scenarios_count=3,
        representative_scenario_ids=[],
        suggested_remedy="Deploy declarative punycode inspection rule",
        severity="high",
        status="open",
    )
    test_db_session.add(finding)
    await test_db_session.commit()

    # 2. Execute bounded cycle
    config = ControllerPolicyConfig(
        max_candidates_per_cycle=1,
        cycle_timeout_seconds=30.0,
        benchmark_manifest_version="benchmark-golden-v1",
    )
    controller = SelfImprovementController(session=test_db_session)
    summary = await controller.execute_cycle(config=config, trigger_reason="test_audit_loop")

    assert summary.cycle_number >= 1
    assert summary.status in {CycleStatus.COMPLETED, CycleStatus.STOPPED_BUDGET_EXHAUSTED}
    assert summary.candidates_evaluated == 1
    assert summary.findings_selected >= 1
    assert summary.duration_seconds > 0.0

    # 3. Verify step checkpoints
    checkpoints = await CheckpointManager.get_checkpoints_for_cycle(
        test_db_session, cycle_id=summary.cycle_id
    )
    step_numbers = [c.step_number for c in checkpoints]
    assert 1 in step_numbers  # SELECT_OPPORTUNITIES
    assert 2 in step_numbers  # GENERATE_CANDIDATE
    assert 3 in step_numbers  # VALIDATE_CANDIDATE
    assert 4 in step_numbers  # PRELIMINARY_CHECKS
    assert 5 in step_numbers  # SUBMIT_EVALUATION
    assert 6 in step_numbers  # RECORD_EVALUATION
    assert 7 in step_numbers  # PROVIDE_FEEDBACK
    assert 8 in step_numbers  # DECIDE_NEXT_STEPS
    assert 9 in step_numbers  # ENFORCE_RESOURCE_BOUNDS
    assert 10 in step_numbers  # CYCLE_FINALIZED


@pytest.mark.asyncio
async def test_controller_enforces_budget_exhaustion(test_db_session: AsyncSession) -> None:
    """Controller must safely stop with STOPPED_BUDGET_EXHAUSTED when candidate ceiling is reached."""
    config = ControllerPolicyConfig(
        max_candidates_per_cycle=2,
        cycle_timeout_seconds=30.0,
    )
    controller = SelfImprovementController(session=test_db_session)
    summary = await controller.execute_cycle(config=config, trigger_reason="budget_test")

    assert summary.status == CycleStatus.STOPPED_BUDGET_EXHAUSTED
    assert summary.candidates_evaluated == 2
    assert "budget exhausted" in summary.terminal_reason.lower()


@pytest.mark.asyncio
async def test_analytics_and_trend_reporting(test_db_session: AsyncSession) -> None:
    """Verify ImprovementAnalyticsService computes longitudinal cycle trends accurately."""
    # List cycles
    history = await ImprovementAnalyticsService.list_cycles(test_db_session, limit=10)
    assert isinstance(history, list)

    # Compute trend report
    trend = await ImprovementAnalyticsService.get_trend_report(test_db_session, limit=10)
    assert trend.total_cycles >= 0
    assert trend.mean_cycle_duration_seconds >= 0.0
