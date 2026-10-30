"""Integration tests for Release Management and Client Update REST API endpoints."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cyberduel_contracts.enums import ReleaseStatus
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.auth import create_token
from apps.api.app.models.evaluations import (
    BenchmarkManifestRecord,
    EvaluationProtocolRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
)
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.services.releases import SigningKeyManager


@pytest.mark.asyncio
async def test_releases_and_updates_api_lifecycle(
    async_client: AsyncClient,
    test_db_session: AsyncSession,
) -> None:
    """End-to-end integration test of release authorization, rollout advance, update checking, downloading, and ack."""
    # 0. Initialize signing key in database
    key_mgr = SigningKeyManager()
    await key_mgr.get_or_create_primary_key(test_db_session, key_id="api-test-key-01")
    await test_db_session.commit()

    # 1. Create passing candidate defense and evaluation report
    protocol = EvaluationProtocolRecord(
        id=uuid4(),
        protocol_name="api-eval-protocol",
        version="1.0.0",
        description="Protocol for API testing",
        metrics_required=["accuracy", "recall"],
        split_spec={},
        pass_fail_thresholds={},
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    test_db_session.add(protocol)

    bench = BenchmarkManifestRecord(
        id="benchmark-golden-v1",
        name="Golden Benchmark v1",
        version="1.0.0",
        description="Golden test suite",
        split_counts={"development": 10},
        family_counts={"homograph_mimicry": 10},
        scenario_count=10,
        scenarios_payload=[],
        integrity_hash="00" * 32,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    test_db_session.add(bench)

    cand = CandidateDefenseRecord(
        id=uuid4(),
        version="0.4.0-candidate",
        author_agent="BlueAI-v1",
        description="Candidate for API release testing",
        rule_spec={
            "rules": [
                {
                    "rule_id": "RULE-API-01",
                    "rule_version": "1.0.0",
                    "description": "API test rule",
                    "author": "BlueAI",
                    "purpose": "Testing",
                    "target_family": "authority_spoofing",
                    "predicates": [{"field": "has_homoglyphs", "operator": "eq", "value": True}],
                    "action": "warn",
                    "severity": "medium",
                    "weight": 0.8,
                }
            ],
            "warn_threshold": 0.5,
            "block_threshold": 0.85,
        },
        status="accepted",
    )
    test_db_session.add(cand)

    req = EvaluationRequestRecord(
        id=uuid4(),
        candidate_id=cand.id,
        candidate_version=cand.version,
        baseline_detector_version="0.2.0-heuristic-intel",
        baseline_policy_version="2026.10.1",
        benchmark_manifest_id="benchmark-golden-v1",
        status="completed",
        requested_by="TestRunner",
        resource_budget={},
        target_finding_ids=[],
        target_scenario_ids=[],
    )
    test_db_session.add(req)
    await test_db_session.flush()

    report = EvaluationReportRecord(
        id=uuid4(),
        request_id=req.id,
        candidate_id=cand.id,
        candidate_version=cand.version,
        baseline_version="1.0.0",
        benchmark_manifest_id="benchmark-golden-v1",
        verdict="pass",
        status="completed",
        verdict_rationale="Passed all criteria",
        acceptance_reasons=["Meets accuracy thresholds"],
        rejection_reasons=[],
        baseline_metrics={},
        candidate_metrics={
            "accuracy": 0.98,
            "recall": 0.95,
            "false_positive_rate": 0.005,
            "f1_score": 0.96,
        },
        split_metrics={},
        improvement_metrics={"regression_count": 0},
        operational_metrics={},
        report_digest="33" * 32,
        evaluated_at=datetime.now(UTC),
    )
    test_db_session.add(report)
    await test_db_session.commit()

    # 2. Check Eligibility via API
    elig_resp = await async_client.post(
        "/api/v1/releases/eligibility",
        json={"candidate_id": str(cand.id), "evaluation_report_id": str(report.id)},
    )
    assert elig_resp.status_code == 200
    elig_data = elig_resp.json()
    assert elig_data["is_eligible"] is True

    # 3. Verify unauthenticated release authorization is blocked with 403 Forbidden
    auth_payload = {
        "candidate_id": str(cand.id),
        "evaluation_report_id": str(report.id),
        "policy_version": "2026.10.20",
        "target_channel": "stable",
        "authorized_by": "lead-secops-admin",
        "rationale": "Passed complete golden v1 evaluation suite",
        "release_notes": "Initial authenticated security release",
    }
    unauth_resp = await async_client.post("/api/v1/releases/authorize", json=auth_payload)
    assert unauth_resp.status_code == 403

    # Authenticate as admin operator with releases:manage permission
    admin_token = create_token({"sub": "admin", "role": "admin"})
    auth_headers = {"Authorization": f"Bearer {admin_token}"}

    auth_resp = await async_client.post(
        "/api/v1/releases/authorize",
        json=auth_payload,
        headers=auth_headers,
    )
    assert auth_resp.status_code == 201
    auth_data = auth_resp.json()
    release_id = auth_data["release_id"]
    artifact_digest = auth_data["artifact_digest"]
    assert auth_data["policy_version"] == "2026.10.20"
    assert auth_data["status"] == ReleaseStatus.APPROVED.value

    # 4. List Releases
    list_resp = await async_client.get("/api/v1/releases")
    assert list_resp.status_code == 200
    releases_list = list_resp.json()
    assert any(r["policy_version"] == "2026.10.20" for r in releases_list)

    # 5. Get Release Detail
    detail_resp = await async_client.get(f"/api/v1/releases/{release_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["release"]["policy_version"] == "2026.10.20"
    assert len(detail_data["authorizations"]) == 1

    # 6. Advance Rollout to General Availability
    adv_resp = await async_client.post(
        f"/api/v1/releases/{release_id}/advance?target_stage=general_availability",
        headers=auth_headers,
    )
    assert adv_resp.status_code == 200
    adv_data = adv_resp.json()
    assert adv_data["stage"] == "general_availability"
    assert adv_data["rollout_percentage"] == 100.0

    # 7. Edge Client checks for updates
    check_resp = await async_client.post(
        "/api/v1/updates/check",
        json={
            "client_id": "client-browser-ext-001",
            "client_type": "browser_extension",
            "current_policy_version": "2026.10.1",
            "current_sequence_number": 0,
            "engine_version": "1.0.0",
            "platform": "browser_extension",
            "channel": "stable",
        },
    )
    assert check_resp.status_code == 200
    check_data = check_resp.json()
    assert check_data["update_available"] is True
    assert check_data["target_version"] == "2026.10.20"
    assert check_data["rules_digest"] == artifact_digest

    # 8. Retrieve Signed Release Manifest
    manifest_resp = await async_client.get("/api/v1/updates/manifests/2026.10.20")
    assert manifest_resp.status_code == 200
    manifest_data = manifest_resp.json()
    assert manifest_data["policy_version"] == "2026.10.20"
    assert len(manifest_data["signature"]) == 128

    # 9. Download Immutable Policy Bundle Artifact
    art_resp = await async_client.get(f"/api/v1/updates/artifacts/{artifact_digest}")
    assert art_resp.status_code == 200
    assert art_resp.headers["etag"] == f'"{artifact_digest}"'
    bundle_data = art_resp.json()
    assert bundle_data["policy_version"] == "2026.10.20"
    assert len(bundle_data["rules"]) == 1

    # 10. Retrieve Public Trust Anchors
    anchor_resp = await async_client.get("/api/v1/updates/trust-anchors")
    assert anchor_resp.status_code == 200
    anchors_data = anchor_resp.json()
    assert len(anchors_data["active_keys"]) >= 1

    # 11. Client sends update acknowledgement
    ack_resp = await async_client.post(
        "/api/v1/updates/ack",
        json={
            "client_id": "client-browser-ext-001",
            "policy_version": "2026.10.20",
            "sequence_number": check_data["sequence_number"],
            "status": "applied",
        },
    )
    assert ack_resp.status_code == 200
    assert ack_resp.json()["status"] == "recorded"

    # 12. Client checks again: already on latest version -> update_available is False
    check2_resp = await async_client.post(
        "/api/v1/updates/check",
        json={
            "client_id": "client-browser-ext-001",
            "client_type": "browser_extension",
            "current_policy_version": "2026.10.20",
            "current_sequence_number": check_data["sequence_number"],
            "engine_version": "1.0.0",
            "platform": "browser_extension",
            "channel": "stable",
        },
    )
    assert check2_resp.status_code == 200
    assert check2_resp.json()["update_available"] is False

    # 13. Emergency Rollback execution
    # First create a second release so we can rollback to the first
    auth2_resp = await async_client.post(
        "/api/v1/releases/authorize",
        json={
            "candidate_id": str(cand.id),
            "evaluation_report_id": str(report.id),
            "policy_version": "2026.10.21",
            "target_channel": "stable",
            "authorized_by": "lead-secops-admin",
            "rationale": "Candidate v2",
            "release_notes": "Second release",
        },
        headers=auth_headers,
    )
    assert auth2_resp.status_code == 201
    bad_rel_id = auth2_resp.json()["release_id"]

    # Rollback bad release back to 2026.10.20
    rb_resp = await async_client.post(
        "/api/v1/releases/rollback",
        json={
            "regressed_release_id": bad_rel_id,
            "target_version": "2026.10.20",
            "authorized_by": "security-officer",
            "reason": "Unexpected edge-case regression observed in telemetry",
        },
        headers=auth_headers,
    )
    assert rb_resp.status_code == 201
    rb_data = rb_resp.json()
    assert rb_data["is_rollback"] is True
    assert rb_data["is_mandatory"] is True
    assert rb_data["rollback_target_version"] == "2026.10.20"
    assert rb_data["sequence_number"] > auth2_resp.json()["sequence_number"]
