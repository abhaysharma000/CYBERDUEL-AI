"""CyberDuel AI - Vercel Serverless ASGI Entrypoint.

Bridges Vercel Serverless Python functions to the FastAPI application.
Ensures repository packages, temporary writable storage, and fallback databases
are properly configured within the Vercel execution environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Resolve workspace root and package paths
ROOT_DIR = Path(__file__).resolve().parent.parent
for pkg_path in [
    ROOT_DIR,
    ROOT_DIR / "apps" / "api",
    ROOT_DIR / "packages" / "shared-contracts",
    ROOT_DIR / "packages" / "threat-intelligence",
    ROOT_DIR / "packages" / "policy-engine",
    ROOT_DIR / "services" / "lab-worker",
    ROOT_DIR / "services" / "lab_worker",
    ROOT_DIR / "services" / "evaluator",
]:
    p_str = str(pkg_path)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)

# Ensure writeable temporary directories in Vercel serverless environment
if not os.environ.get("STORAGE_RELEASES_DIR"):
    os.environ["STORAGE_RELEASES_DIR"] = "/tmp/storage/releases"
os.makedirs(os.environ["STORAGE_RELEASES_DIR"], exist_ok=True)

# Default to /tmp SQLite database if external DATABASE_URL is not configured
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/cyberduel.db"
    os.environ["DATABASE_URL_SYNC"] = "sqlite:////tmp/cyberduel.db"

try:
    from apps.api.app.main import app as main_app

    app = main_app
except Exception as exc:
    import json
    import traceback

    err_msg = str(exc)
    err_tb = traceback.format_exc()
    print("FATAL INIT ERROR IN api/index.py:\n", err_tb, flush=True)

    async def fallback_app(scope, receive, send):
        if scope["type"] == "http":
            response_body = json.dumps(
                {
                    "error": "CyberDuel Serverless Initialization Failed",
                    "exception": err_msg,
                    "traceback": err_tb,
                    "sys_path": sys.path,
                    "task_files": os.listdir("/var/task") if os.path.exists("/var/task") else [],
                },
                indent=2,
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 500,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"access-control-allow-origin", b"*"],
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": response_body,
                }
            )

    app = fallback_app

# Vercel serverless ASGI handler
__all__ = ["app"]
