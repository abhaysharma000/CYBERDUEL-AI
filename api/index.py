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
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "apps" / "api"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))

# Ensure writeable temporary directories in Vercel serverless environment
if not os.environ.get("STORAGE_RELEASES_DIR"):
    os.environ["STORAGE_RELEASES_DIR"] = "/tmp/storage/releases"
os.makedirs(os.environ["STORAGE_RELEASES_DIR"], exist_ok=True)

# Default to /tmp SQLite database if external DATABASE_URL is not configured
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/cyberduel.db"
    os.environ["DATABASE_URL_SYNC"] = "sqlite:////tmp/cyberduel.db"

from apps.api.app.main import app  # noqa: E402

# Vercel serverless ASGI handler
__all__ = ["app"]

