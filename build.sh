#!/usr/bin/env bash
set -e

echo "==> Checking CyberDuel AI Dashboard distribution..."
if [ -d "apps/dashboard/dist" ] && [ -f "apps/dashboard/dist/index.html" ]; then
    echo "==> Pre-compiled Red & Black dashboard distribution found! Serving directly."
elif command -v npm &> /dev/null; then
    echo "==> Compiling CyberDuel AI Dashboard with npm..."
    cd apps/dashboard
    npm install
    npm run build
    cd ../..
else
    echo "==> Warning: npm not found, falling back to pre-packaged dist."
fi

echo "==> Installing Python dependencies..."
pip install -U pip
pip install -e ".[dev]"

echo "==> CyberDuel AI Build Complete!"


