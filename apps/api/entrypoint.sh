#!/bin/sh
set -e

echo "==> CyberDuel AI: Checking and applying database migrations..."
python scripts/run_migrations.py

echo "==> Starting CyberDuel Core API Gateway on port ${PORT:-8000}..."
exec uvicorn apps.api.app.main:app --host 0.0.0.0 --port "${PORT:-8000}"

