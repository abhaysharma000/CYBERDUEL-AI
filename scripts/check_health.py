"""Utility script to verify CyberDuel API health and readiness."""

import sys
import urllib.error
import urllib.request


def check(url: str, name: str) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberDuel-HealthCheck/0.1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.getcode()
            body = response.read().decode()
            print(f"[OK] {name} ({url}) returned HTTP {status}: {body[:80]}...")
            return bool(status == 200)
    except urllib.error.HTTPError as e:
        print(f"[FAIL] {name} returned HTTP {e.code}: {e.read().decode()}")
        return False
    except Exception as e:
        print(f"[ERROR] Could not connect to {name} at {url}: {e}")
        return False


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    live_ok = check(f"{base}/health/live", "Liveness Probe")
    ready_ok = check(f"{base}/health/ready", "Readiness Probe")
    status_ok = check(f"{base}/api/v1/system/status", "System Status")

    if not (live_ok and ready_ok and status_ok):
        print("\nHealth checks failed.")
        sys.exit(1)

    print("\nAll health checks passed successfully.")


if __name__ == "__main__":
    main()
