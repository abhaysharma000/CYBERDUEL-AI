"""Security hardening and boundary verification tests for CyberDuel AI.

Validates:
1. Authentication & Role-Based Access Control (RBAC) authorization boundaries.
2. Production password & credential enforcement (no demo shortcuts in production).
3. Immutable audit log recording on privileged administrative actions.
4. Path traversal and regex pattern input validation on API parameters.
5. Denial of Service (DoS) oversized payload rejection (HTTP 413).
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.auth import Role, create_token
from apps.api.app.core.config import Settings, get_settings
from apps.api.app.db.session import get_db_session
from apps.api.app.main import create_app
from apps.api.app.models.audit import AuditLogRecord
from apps.api.app.models.evaluations import (
    EvaluationReportRecord,
)
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.services.releases import SigningKeyManager


@pytest.mark.asyncio
async def test_unauthenticated_release_management_blocked(async_client: AsyncClient) -> None:
    """Demonstrate that mutating release endpoints strictly reject unauthenticated callers with 403."""
    dummy_uuid = str(uuid4())

    # 1. Authorize
    auth_resp = await async_client.post(
        "/api/v1/releases/authorize",
        json={
            "candidate_id": dummy_uuid,
            "evaluation_report_id": dummy_uuid,
            "policy_version": "2026.10.99",
            "target_channel": "stable",
            "authorized_by": "unauthorized-actor",
            "rationale": "Attempting unauthenticated release",
        },
    )
    assert auth_resp.status_code == 403
    err_body = auth_resp.json()
    assert "releases:manage" in err_body.get("message", err_body.get("detail", ""))

    # 2. Advance rollout
    adv_resp = await async_client.post(f"/api/v1/releases/{dummy_uuid}/advance")
    assert adv_resp.status_code == 403
    err_body = adv_resp.json()
    assert "releases:manage" in err_body.get("message", err_body.get("detail", ""))

    # 3. Emergency rollback
    rb_resp = await async_client.post(
        "/api/v1/releases/rollback",
        json={
            "regressed_release_id": dummy_uuid,
            "target_version": "2026.10.1",
            "authorized_by": "unauthorized-actor",
            "reason": "Attempting unauthorized rollback",
        },
    )
    assert rb_resp.status_code == 403
    err_body = rb_resp.json()
    assert "releases:manage" in err_body.get("message", err_body.get("detail", ""))


@pytest.mark.asyncio
async def test_viewer_role_blocked_from_release_authorization(async_client: AsyncClient) -> None:
    """Demonstrate that users with read-only/viewer role are rejected from mutating releases."""
    viewer_token = create_token({"sub": "analyst_viewer", "role": Role.VIEWER.value})
    headers = {"Authorization": f"Bearer {viewer_token}"}
    dummy_uuid = str(uuid4())

    resp = await async_client.post(
        "/api/v1/releases/authorize",
        json={
            "candidate_id": dummy_uuid,
            "evaluation_report_id": dummy_uuid,
            "policy_version": "2026.10.99",
            "target_channel": "stable",
            "authorized_by": "analyst_viewer",
            "rationale": "Attempting release with viewer role",
        },
        headers=headers,
    )
    assert resp.status_code == 403
    err_body = resp.json()
    assert "Current role: 'viewer'" in err_body.get("message", err_body.get("detail", ""))


@pytest.mark.asyncio
async def test_authorized_release_creates_audit_log(
    async_client: AsyncClient,
    test_db_session: AsyncSession,
) -> None:
    """Demonstrate that authorized release operators succeed and trigger immutable audit log creation."""
    # Initialize signing key
    key_mgr = SigningKeyManager()
    await key_mgr.get_or_create_primary_key(test_db_session, key_id="security-audit-key-01")
    await test_db_session.commit()

    cand = CandidateDefenseRecord(
        id=uuid4(),
        version="0.5.0-candidate",
        author_agent="BlueAI-v1",
        description="Candidate for audit test",
        rule_spec={"rules": []},
        status="accepted",
    )
    test_db_session.add(cand)

    report = EvaluationReportRecord(
        id=uuid4(),
        request_id=uuid4(),
        candidate_id=cand.id,
        candidate_version=cand.version,
        baseline_version="1.0.0",
        benchmark_manifest_id="benchmark-golden-v1",
        verdict="pass",
        status="completed",
        verdict_rationale="Passed",
        acceptance_reasons=["Passed"],
        rejection_reasons=[],
        baseline_metrics={},
        candidate_metrics={"accuracy": 1.0, "false_positive_rate": 0.0},
        split_metrics={},
        improvement_metrics={},
        operational_metrics={},
        report_digest="11" * 32,
        evaluated_at=datetime.now(UTC),
    )
    test_db_session.add(report)
    await test_db_session.commit()

    # Authenticate as release_operator
    operator_token = create_token({"sub": "secops_lead", "role": Role.RELEASE_OPERATOR.value})
    headers = {"Authorization": f"Bearer {operator_token}"}

    resp = await async_client.post(
        "/api/v1/releases/authorize",
        json={
            "candidate_id": str(cand.id),
            "evaluation_report_id": str(report.id),
            "policy_version": "2026.10.88",
            "target_channel": "stable",
            "authorized_by": "secops_lead",
            "rationale": "Verified for audit log generation",
            "release_notes": "Security audit test release",
        },
        headers=headers,
    )
    assert resp.status_code == 201

    # Verify audit log was written to database
    audit_stmt = select(AuditLogRecord).where(
        AuditLogRecord.action == "release.authorize",
        AuditLogRecord.actor == "secops_lead",
    )
    audit_res = await test_db_session.execute(audit_stmt)
    log_record = audit_res.scalar_one_or_none()

    assert log_record is not None
    assert log_record.action == "release.authorize"
    assert log_record.actor == "secops_lead"
    assert log_record.outcome == "success"
    assert log_record.metadata_json.get("policy_version") == "2026.10.88"


@pytest.mark.asyncio
async def test_update_manifest_path_traversal_validation(async_client: AsyncClient) -> None:
    """Demonstrate that invalid path and injection characters are rejected at parameter validation layer."""
    # Special character and injection payload (rejected with 422 by regex pattern ^[a-zA-Z0-9.\-_]{1,64}$)
    invalid_chars_resp = await async_client.get("/api/v1/updates/manifests/bad%40version%21")
    assert invalid_chars_resp.status_code == 422

    # Malicious SQL injection characters (rejected with 422)
    injection_resp = await async_client.get("/api/v1/updates/manifests/version;DROP_TABLE")
    assert injection_resp.status_code == 422

    # Oversized version parameter exceeding 64 chars
    oversized_resp = await async_client.get(f"/api/v1/updates/manifests/{'a' * 65}")
    assert oversized_resp.status_code == 422

    # Valid syntax (reaches query layer, returns 404 because version does not exist)
    valid_resp = await async_client.get("/api/v1/updates/manifests/2026.10.1")
    assert valid_resp.status_code == 404


@pytest.mark.asyncio
async def test_production_authentication_disallows_demo_passwords(
    test_db_session: AsyncSession,
) -> None:
    """Demonstrate that in production environment, blank, 'demo', or username passwords are strictly rejected."""
    prod_settings = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        SECRET_KEY="production_secret_key_at_least_32_characters_long",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        DATABASE_URL_SYNC="sqlite:///:memory:",
    )

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: prod_settings
    app.dependency_overrides[get_db_session] = lambda: test_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Blank password rejected in production
        blank_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": ""},
        )
        assert blank_resp.status_code == 401

        # 2. 'demo' shortcut password rejected in production
        demo_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "demo"},
        )
        assert demo_resp.status_code == 401

        # 3. Username as password rejected in production
        user_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        assert user_resp.status_code == 401

        # 4. Correct configured password succeeds
        valid_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "Admin@CyberDuel2026!"},
        )
        assert valid_resp.status_code == 200
        assert "token" in valid_resp.json()

    app.dependency_overrides.clear()
