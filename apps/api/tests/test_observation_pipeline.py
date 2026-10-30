"""Tests for threat observation pipeline, status transitions, and deduplication."""

from uuid import uuid4

import pytest
from cyberduel_contracts.enums import Decision, ObservationSource
from cyberduel_contracts.observation import ThreatObservationReport
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.services.threat_observation_service import (
    ThreatObservationService,
)


@pytest.mark.asyncio
async def test_observation_ingestion_and_deduplication(test_db_session: AsyncSession) -> None:
    service = ThreatObservationService(session=test_db_session)
    target_hash = "test_target_" + "a" * 48

    report = ThreatObservationReport(
        observation_id=uuid4(),
        source=ObservationSource.BROWSER_EXTENSION,
        normalized_target=target_hash,
        local_action_taken=Decision.WARN,
        engine_version="0.2.0",
        policy_version="2026.10.1",
        telemetry_summary={"flag": "homoglyph_detected", "password": "should_be_stripped"},
    )

    res1 = await service.ingest_observation(report)
    assert res1["status"] == "received"
    assert res1["duplicate"] is False

    # Second submission with same target and source is flagged as duplicate
    res2 = await service.ingest_observation(report)
    assert res2["duplicate"] is True
    assert res2["observation_id"] == res1["observation_id"]


@pytest.mark.asyncio
async def test_observation_status_lifecycle_transitions(test_db_session: AsyncSession) -> None:
    service = ThreatObservationService(session=test_db_session)
    obs_id = uuid4()
    report = ThreatObservationReport(
        observation_id=obs_id,
        source=ObservationSource.MOBILE_APP,
        normalized_target="test_target_" + "b" * 48,
        engine_version="0.2.0",
        policy_version="2026.10.1",
    )
    await service.ingest_observation(report)

    # Valid transition: received -> queued
    t1 = await service.transition_status(obs_id, "queued")
    assert t1 is True

    # Valid transition: queued -> investigating
    t2 = await service.transition_status(obs_id, "investigating")
    assert t2 is True

    # Valid transition: investigating -> confirmed
    t3 = await service.transition_status(obs_id, "confirmed")
    assert t3 is True

    # Invalid transition: confirmed is terminal; cannot transition back to queued
    with pytest.raises(ValueError, match="Invalid status transition"):
        await service.transition_status(obs_id, "queued")
