#!/usr/bin/env python3
"""Inspect database tables, row counts, and sample records in the active CyberDuel database."""

import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from apps.api.app.core.config import get_settings


def inspect_db() -> dict[str, int]:
    settings = get_settings()
    db_url = settings.DATABASE_URL_SYNC
    if db_url.startswith("sqlite:///"):
        db_path = db_url.replace("sqlite:///", "")
    else:
        db_path = "cyberduel_dev.db"

    path = Path(db_path)
    if not path.is_absolute():
        path = Path.cwd() / path

    print(f"Active Database File: {path} (Exists: {path.exists()})")
    if not path.exists():
        return {}

    conn = sqlite3.connect(str(path))
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    tables = [r[0] for r in cursor.fetchall()]

    counts = {}
    print(f"\n--- Database Table Counts ({len(tables)} tables) ---")
    for t in tables:
        cursor.execute(f'SELECT count(*) FROM "{t}"')
        cnt = cursor.fetchone()[0]
        counts[t] = cnt
        print(f"  {t:<35}: {cnt}")

    conn.close()
    return counts


if __name__ == "__main__":
    inspect_db()
