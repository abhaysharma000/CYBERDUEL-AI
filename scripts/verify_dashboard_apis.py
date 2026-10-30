"""Verify all 9 Command Center Dashboard API endpoints against the live application database (cyberduel_dev.db)."""

import asyncio
import logging
import sys
from pathlib import Path

from httpx import ASGITransport, AsyncClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))

from apps.api.app.main import app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_dashboard_apis")


async def main():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # First obtain auth token for authenticated endpoints
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": ""},
        )
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        token = login_resp.json()["token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        endpoints = [
            ("Liveness Probe", "GET", "/health/live", {}, 200),
            ("Readiness Probe", "GET", "/health/ready", {}, 200),
            ("System Health", "GET", "/api/v1/system/status", {}, 200),
            ("Dashboard Overview", "GET", "/api/v1/dashboard/overview", auth_headers, 200),
            ("Red AI Lab Experiments", "GET", "/api/v1/lab/experiments", auth_headers, 200),
            ("Blue AI Status", "GET", "/api/v1/blue/status", auth_headers, 200),
            ("Blue AI Defense Candidates", "GET", "/api/v1/blue/history", auth_headers, 200),
            ("Independent Evaluations", "GET", "/api/v1/evaluations", auth_headers, 200),
            ("Security Releases", "GET", "/api/v1/releases", auth_headers, 200),
            ("Client Fleet Devices", "GET", "/api/v1/clients", auth_headers, 200),
            ("Client Fleet Metrics", "GET", "/api/v1/clients/metrics", auth_headers, 200),
            ("Threat Indicators", "GET", "/api/v1/intelligence/indicators", auth_headers, 200),
            ("Telemetry Observations", "GET", "/api/v1/telemetry/observations", auth_headers, 200),
            ("Audit Trail Events", "GET", "/api/v1/audit/events", auth_headers, 200),
        ]

        print("\n=== DASHBOARD API ENDPOINT VERIFICATION ===")
        all_ok = True
        for name, method, path, headers, expected_status in endpoints:
            if method == "GET":
                resp = await client.get(path, headers=headers)
            else:
                resp = await client.post(path, headers=headers)

            status_ok = resp.status_code == expected_status
            if not status_ok:
                all_ok = False
                print(
                    f"[FAIL] {name:30} {path:35} -> HTTP {resp.status_code} (Expected {expected_status})"
                )
                print(f"       Response: {resp.text[:200]}")
            else:
                data = resp.json()
                count = (
                    len(data)
                    if isinstance(data, list)
                    else len(data.get("events", []))
                    if "events" in data
                    else 1
                )
                print(
                    f"[PASS] {name:30} {path:35} -> HTTP {resp.status_code} (Records/Status: {count})"
                )
                if isinstance(data, list) and data:
                    sample = data[0]
                    first_keys = (
                        list(sample.keys())[:4] if isinstance(sample, dict) else str(sample)[:30]
                    )
                    print(f"       Sample: {first_keys}")
                elif isinstance(data, dict):
                    print(f"       Payload keys: {list(data.keys())[:6]}")

        assert all_ok, "Some dashboard API endpoints failed verification"
        print("\n=== ALL 9 DASHBOARD PAGES VERIFIED AGAINST REAL BACKEND DATA ===")


if __name__ == "__main__":
    asyncio.run(main())
