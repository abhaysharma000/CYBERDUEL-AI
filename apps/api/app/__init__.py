"""CyberDuel AI Core API Package."""

import contextlib
import os
import sys
from pathlib import Path

# Bootstrap repository root and package paths into sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _CURRENT_DIR.parent.parent.parent

for _p in [
    _REPO_ROOT,
    _REPO_ROOT / "apps" / "api",
    _REPO_ROOT / "packages" / "shared-contracts",
    _REPO_ROOT / "packages" / "threat-intelligence",
    _REPO_ROOT / "packages" / "policy-engine",
    _REPO_ROOT / "services" / "lab-worker",
    _REPO_ROOT / "services" / "lab_worker",
    _REPO_ROOT / "services" / "evaluator",
]:
    _p_str = str(_p)
    if _p_str not in sys.path:
        sys.path.insert(0, _p_str)

# Ensure temporary writable directories on serverless runtimes
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    if not os.environ.get("DATABASE_URL"):
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/cyberduel.db"
        os.environ["DATABASE_URL_SYNC"] = "sqlite:////tmp/cyberduel.db"
    if not os.environ.get("STORAGE_RELEASES_DIR"):
        os.environ["STORAGE_RELEASES_DIR"] = "/tmp/storage/releases"
    with contextlib.suppress(Exception):
        os.makedirs(os.environ["STORAGE_RELEASES_DIR"], exist_ok=True)
