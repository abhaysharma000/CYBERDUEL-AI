"""Integration tests for Threat Analysis, Intelligence, and Policy Export APIs."""

from uuid import uuid4

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_analyze_url_phishing_block(async_client: AsyncClient) -> None:
    # URL targeting Chase bank hosted on raw IP with custom port
    payload = {
        "url": "http://192.168.1.100:8080/chase-online-banking/verify-login.html",
        "client_id": "test-client-01",
    }
    response = await async_client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] in ["warn", "block"]
    assert data["threat_score"] >= 0.35
    assert data["input_validation_status"] == "valid"
    assert len(data["evidence"]) >= 1
    assert "explanation" in data


@pytest.mark.asyncio
async def test_analyze_url_benign_allow(async_client: AsyncClient) -> None:
    payload = {
        "url": "https://www.google.com/search?q=cybersecurity+defense",
    }
    response = await async_client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["threat_score"] <= 0.35
    assert data["input_validation_status"] == "valid"


@pytest.mark.asyncio
async def test_analyze_url_malformed_returns_safe_allow(async_client: AsyncClient) -> None:
    # Malformed URL: parsing error is NOT proof of maliciousness
    payload = {
        "url": "javascript:alert(document.cookie)",
    }
    response = await async_client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_validation_status"] == "malformed"
    assert data["decision"] == "allow"
    assert data["threat_score"] == 0.0


@pytest.mark.asyncio
async def test_get_analysis_record_lifecycle(async_client: AsyncClient) -> None:
    # 1. Analyze URL
    payload = {"url": "https://paypal.com@malicious-lure.net/auth"}
    res = await async_client.post("/api/v1/analyze/url", json=payload)
    assert res.status_code == 200
    analysis_id = res.json()["analysis_id"]

    # 2. Retrieve recorded analysis
    fetch_res = await async_client.get(f"/api/v1/analyze/{analysis_id}")
    assert fetch_res.status_code == 200
    fetch_data = fetch_res.json()
    assert fetch_data["analysis_id"] == analysis_id
    assert fetch_data["decision"] in ["warn", "block"]

    # 3. Nonexistent record returns 404
    missing_id = str(uuid4())
    missing_res = await async_client.get(f"/api/v1/analyze/{missing_id}")
    assert missing_res.status_code == 404


@pytest.mark.asyncio
async def test_intelligence_status(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/intelligence/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert data["active_indicators"] > 0
    assert data["registered_heuristic_rules"] >= 10
    assert data["policy_version"] == "2026.10.1"


@pytest.mark.asyncio
async def test_submit_threat_report(async_client: AsyncClient) -> None:
    payload = {
        "url": "https://secure-login.suspicious-phish-domain.org/verify",
        "reported_category": "phishing",
        "user_notes": "Received via SMS text lure",
        "client_id": "test-user-mobile-01",
    }
    response = await async_client.post("/api/v1/threat-reports", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "received"
    assert "report_id" in data
    assert "target_digest" in data


@pytest.mark.asyncio
async def test_import_intelligence_indicators(async_client: AsyncClient) -> None:
    payload = {
        "indicators": [
            {
                "indicator_type": "domain",
                "normalized_value": "newly-discovered-c2.net",
                "classification": "c2",
                "source": "threat_exchange_feed",
                "severity": "critical",
                "confidence": 0.99,
            }
        ]
    }
    response = await async_client.post(
        "/api/v1/intelligence/import",
        json=payload,
        headers={"X-Admin-Key": "dev_secret_key_at_least_32_characters_long_for_security"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["imported_count"] == 1


@pytest.mark.asyncio
async def test_export_policy_bundle(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/policy/export")
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["format_version"] == "1.0.0"
    assert bundle["policy_version"] == "2026.10.1"
    assert len(bundle["declarative_rules"]) >= 3
    assert len(bundle["rules_digest"]) == 64
