#!/usr/bin/env bash
set -e

echo "==> Building CyberDuel AI Dashboard..."
cd apps/dashboard
npm install
npm run build
cd ../..

echo "==> Installing Python dependencies..."
pip install -U pip
pip install -e ".[dev]"

echo "==> CyberDuel AI Build Complete!"
