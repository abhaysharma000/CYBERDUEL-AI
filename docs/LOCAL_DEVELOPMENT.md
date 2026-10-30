# CyberDuel AI — Local Development Guide

## 1. Prerequisites

- **Python 3.12** (pinned)
- **uv** (v0.5.0+)
- **Docker & Docker Compose** (Docker 24+)
- **Git**

---

## 2. Environment Setup (Without Docker)

### Step 1: Create Virtual Environment with Python 3.12
```bash
uv venv --python 3.12 .venv
```

Activate the virtual environment:
- **Windows (PowerShell):**
  ```powershell
  .venv\Scripts\activate
  ```
- **macOS / Linux:**
  ```bash
  source .venv/bin/activate
  ```

### Step 2: Install Workspace Dependencies
```bash
uv pip install -e ".[dev]"
```

### Step 3: Configure Environment Variables
```bash
cp .env.example .env
```
*Note: In development mode, `AI_PROVIDER_TYPE=mock` allows running the entire application and all tests without any cloud keys.*

### Step 4: Run Database Migrations (Optional for Postgres)
If using PostgreSQL locally:
```bash
alembic -c apps/api/alembic.ini upgrade head
```
*(For automated tests, SQLite in-memory mode is supported automatically).*

### Step 5: Start Development Server
```bash
uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 3. Running with Docker Compose

To run the complete isolated stack (API + PostgreSQL + Redis + Lab Worker):

```bash
# Build and start services in background
docker compose up -d --build

# Inspect running containers
docker compose ps

# View live API logs
docker compose logs -f api

# View lab worker logs
docker compose logs -f lab-worker

# Stop and tear down environment
docker compose down
```

---

## 4. Development Quality & Verification Commands

```bash
# Run complete test suite
pytest

# Run tests with code coverage report
pytest --cov=apps/api/app --cov=packages/shared-contracts/cyberduel_contracts

# Run linter
ruff check .

# Fix auto-fixable lint issues
ruff check --fix .

# Check code formatting
ruff format --check .

# Format code
ruff format .

# Type checking
mypy apps/api/app packages/shared-contracts/cyberduel_contracts
```

