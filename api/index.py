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

from apps.api.app.main import app as _fastapi_app  # noqa: E402

# Explicit top-level FastAPI application assignment for Vercel detector
app = _fastapi_app

__all__ = ["app"]
