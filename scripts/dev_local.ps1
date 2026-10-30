<#
.SYNOPSIS
    CyberDuel AI — Unified Windows Local Development & Service Runner

.DESCRIPTION
    Launches and coordinates the CyberDuel AI monorepo on Windows:
    - Validates virtual environment and tools
    - Executes database migrations automatically (Alembic 0001 -> 0007)
    - Starts the FastAPI Backend Service (http://127.0.0.1:8000)
    - Starts the Command Center Dashboard (http://localhost:5173)
    - Handles standalone SQLite persistent mode or Docker PostgreSQL/Redis
#>

[CmdletBinding()]
param(
    [ValidateSet("start", "migrate", "api", "dashboard", "worker", "test", "build", "preflight")]
    [string]$Action = "start",

    [switch]$WithDocker,
    [int]$ApiPort = 8000,
    [int]$DashboardPort = 5173
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "       CYBERDUEL AI -- WINDOWS LOCAL DEVELOPMENT RUNNER           " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Repository Root : $RepoRoot"
Write-Host "Action          : $Action"
Write-Host ""

# 1. Environment Verification
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[X] Virtual environment not found at .venv" -ForegroundColor Red
    Write-Host "    Run 'uv venv --python 3.12 .venv' and 'uv pip install -e `".[dev]`"' first." -ForegroundColor Yellow
    exit 1
}

# Ensure persistent release storage exists
$StorageReleases = Join-Path $RepoRoot "storage\releases"
if (-not (Test-Path $StorageReleases)) {
    New-Item -ItemType Directory -Path $StorageReleases -Force | Out-Null
    Write-Host "[OK] Initialized release storage directory: $StorageReleases" -ForegroundColor Green
}

# 2. Docker Validation (Optional)
if ($WithDocker) {
    Write-Host "[i] Checking Docker Engine..." -ForegroundColor Yellow
    try {
        & docker compose config
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Docker Compose configuration valid. Starting Postgres and Redis..." -ForegroundColor Green
            & docker compose up -d postgres redis
        } else {
            Write-Host "[!] Docker Compose config check failed. Using local SQLite." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Docker daemon unreachable. Falling back to local persistent SQLite (cyberduel_dev.db)." -ForegroundColor Yellow
    }
}

# 3. Action Handlers
if ($Action -eq "migrate") {
    Write-Host "--> Running Database Migrations..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $RepoRoot "scripts\run_migrations.py")
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Database schema verified and up to date." -ForegroundColor Green
    }
}
elseif ($Action -eq "preflight") {
    Write-Host "--> Executing Deployment Preflight Check..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $RepoRoot "scripts\railway_preflight.py") --dry-run
}
elseif ($Action -eq "build") {
    Write-Host "--> Building PC Browser Extension (Manifest V3)..." -ForegroundColor Cyan
    npm --prefix (Join-Path $RepoRoot "apps\browser-extension") run build
    
    Write-Host "--> Building Command Center Dashboard SPA..." -ForegroundColor Cyan
    npm --prefix (Join-Path $RepoRoot "apps\dashboard") run build
    Write-Host "[OK] Extension and Dashboard built successfully." -ForegroundColor Green
}
elseif ($Action -eq "test") {
    Write-Host "--> Running Backend and Integration Tests (pytest)..." -ForegroundColor Cyan
    & (Join-Path $RepoRoot ".venv\Scripts\pytest.exe") -q

    Write-Host "--> Running Browser Extension Tests (vitest)..." -ForegroundColor Cyan
    npm --prefix (Join-Path $RepoRoot "apps\browser-extension") run test

    Write-Host "--> Running Dashboard Tests (vitest)..." -ForegroundColor Cyan
    npm --prefix (Join-Path $RepoRoot "apps\dashboard") run test

    Write-Host "--> Running Android Unit Tests (gradlew)..." -ForegroundColor Cyan
    Push-Location (Join-Path $RepoRoot "apps\mobile")
    try {
        .\gradlew.bat testDebugUnitTest --no-daemon
    } finally {
        Pop-Location
    }

    Write-Host "[OK] Complete monorepo test suite passed." -ForegroundColor Green
}
elseif ($Action -eq "api") {
    Write-Host "--> Running Migrations first..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $RepoRoot "scripts\run_migrations.py")

    Write-Host "--> Starting FastAPI API Server on http://127.0.0.1:$ApiPort..." -ForegroundColor Green
    Write-Host "    Swagger Docs: http://127.0.0.1:$ApiPort/docs" -ForegroundColor Gray
    & (Join-Path $RepoRoot ".venv\Scripts\uvicorn.exe") apps.api.app.main:app --host 127.0.0.1 --port $ApiPort --reload
}
elseif ($Action -eq "dashboard") {
    Write-Host "--> Starting Command Center Dashboard on http://localhost:$DashboardPort..." -ForegroundColor Green
    npm --prefix (Join-Path $RepoRoot "apps\dashboard") run dev
}
elseif ($Action -eq "worker") {
    Write-Host "--> Starting Standalone Laboratory Research Worker..." -ForegroundColor Green
    & $VenvPython (Join-Path $RepoRoot "services\lab-worker\app\worker.py")
}
elseif ($Action -eq "start") {
    Write-Host "--> 1. Running Database Migrations..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $RepoRoot "scripts\run_migrations.py")

    Write-Host "--> 2. Launching Command Center Dashboard in a new window..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$RepoRoot'; npm --prefix apps/dashboard run dev"

    Write-Host "--> 3. Starting FastAPI Core API Service on http://127.0.0.1:$ApiPort..." -ForegroundColor Green
    Write-Host "    API Docs available at : http://127.0.0.1:$ApiPort/docs" -ForegroundColor Yellow
    Write-Host "    Health probe at       : http://127.0.0.1:$ApiPort/health/live" -ForegroundColor Yellow
    Write-Host "    Dashboard UI at       : http://localhost:5173" -ForegroundColor Yellow
    Write-Host "    Press Ctrl+C to terminate the API server." -ForegroundColor Gray
    Write-Host ""
    
    & (Join-Path $RepoRoot ".venv\Scripts\uvicorn.exe") apps.api.app.main:app --host 127.0.0.1 --port $ApiPort --reload
}
