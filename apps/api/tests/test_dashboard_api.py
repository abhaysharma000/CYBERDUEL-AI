"""Tests for Dashboard, RBAC Authentication, Client Telemetry, and Audit APIs."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_auth_login_and_me(async_client: AsyncClient) -> None:
    # 1. Login with demo admin
    res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "Admin@CyberDuel2026!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"
    assert "releases:manage" in data["user"]["permissions"]

    token = data["token"]

    # 2. Query /auth/me with Bearer token
    me_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "admin"
    assert me_data["role"] == "admin"


@pytest.mark.asyncio
async def test_auth_invalid_login(async_client: AsyncClient) -> None:
    res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_user", "password": "wrong"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_auth_list_operators(async_client: AsyncClient) -> None:
    res = await async_client.get("/api/v1/auth/operators")
    assert res.status_code == 200
    operators = res.json()
    assert len(operators) >= 4
    usernames = [op["username"] for op in operators]
    assert "admin" in usernames
    assert "researcher" in usernames
    assert "reviewer" in usernames
    assert "releaser" in usernames


@pytest.mark.asyncio
async def test_dashboard_overview(async_client: AsyncClient) -> None:
    res = await async_client.get("/api/v1/dashboard/overview")
    assert res.status_code == 200
    data = res.json()

    assert "health" in data
    assert data["health"]["status"] == "healthy"
    assert "research" in data
    assert "total_experiments" in data["research"]
    assert "defense" in data
    assert "total_candidates" in data["defense"]
    assert "evaluations" in data
    assert "releases" in data
    assert "clients" in data
    assert "recent_events" in data
    assert isinstance(data["recent_events"], list)


@pytest.mark.asyncio
async def test_client_endpoints(async_client: AsyncClient) -> None:
    # 1. List clients
    list_res = await async_client.get("/api/v1/clients")
    assert list_res.status_code == 200
    clients = list_res.json()
    assert isinstance(clients, list)

    # 2. Get metrics
    metrics_res = await async_client.get("/api/v1/clients/metrics")
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert "total_registered" in metrics
    assert "by_type" in metrics
    assert "acknowledgements_breakdown" in metrics


@pytest.mark.asyncio
async def test_audit_events_endpoint(async_client: AsyncClient) -> None:
    res = await async_client.get("/api/v1/audit/events?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "total" in data
    assert isinstance(data["events"], list)


@pytest.mark.asyncio
async def test_lab_experiments_list(async_client: AsyncClient) -> None:
    res = await async_client.get("/api/v1/lab/experiments?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
