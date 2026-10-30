# CyberDuel AI

CyberDuel AI is a continuously improving defensive cybersecurity platform designed for proactive, multi-tier threat defense. It combines an adversarial cloud research laboratory with lightweight edge protection components for personal computers (browser extension) and mobile devices.

## Operating Principle
> **The research laboratory may experiment continuously; production defenses change only after independent validation and controlled release.**

CyberDuel AI operates on the strict tenet that continuous learning and synthetic adversarial testing do not automatically guarantee absolute safety. Candidate defenses, detection heuristics, and models are generated in an isolated laboratory, subjected to rigorous adversarial evaluation against regressions and false positives, and released only as cryptographically signed, declarative policy packages.

---

## High-Level Architecture

The platform consists of three primary tiers:

```
+-----------------------------------------------------------------------------------+
|                           CYBERDUEL RESEARCH LABORATORY                           |
|                                                                                   |
|  +--------------------+        +---------------------+        +----------------+  |
|  |       RED AI       |        |       BLUE AI       |        |  EVALUATION    |  |
|  | Threat Generation  | =====> | Candidate Defenses  | =====> |  & REGRESSION  |  |
|  | & Weakness Search  |        | & Rule Formulation  |        |  ENGINE        |  |
|  +--------------------+        +---------------------+        +----------------+  |
|                                                                       ||          |
|                                                          [Validated Candidate]   |
|                                                                       \/          |
|                                                               +----------------+  |
|                                                               | RELEASE SIGNER |  |
|                                                               +----------------+  |
+-----------------------------------------------------------------------||----------+
                                                                        ||
                                                               [Signed Policy Releases]
                                                                        \/
+-----------------------------------------------------------------------------------+
|                             PRODUCTION API SERVICE                                |
|  - Real-time Threat Analysis                                                      |
|  - Privacy-Preserving Telemetry Ingestion                                         |
|  - Cryptographically Verified Policy Distribution                                 |
+-----------------------------------------------------------------------------------+
             ||                                                    ||
             \/                                                    \/
+---------------------------+                        +------------------------------+
|     BROWSER EXTENSION     |                        |      MOBILE APPLICATION      |
| Fast local heuristic &    |                        | Local connection protection  |
| reputation checking       |                        | & cloud fallback analysis    |
+---------------------------+                        +------------------------------+
```

---

## Repository Structure

```text
cyberduel-ai/
  apps/
    api/                     # FastAPI core backend service & routing
      app/
        api/v1/              # Versioned API routes (system, analysis, updates, telemetry)
        core/                # Configuration, logging, exception handlers, security
        models/              # SQLAlchemy 2.x domain models
        repositories/        # Data access patterns
        services/            # Business logic
        providers/           # AI & classification provider abstractions
        main.py              # Application entrypoint
      tests/                 # API unit & integration tests
      Dockerfile             # Container specification
    browser-extension/       # Manifest V3 browser extension for local threat defense (Completed)
    dashboard/               # Unified Security Command Center (React 18 + Vite 6 + Tailwind CSS) (Completed)
    mobile/                  # Native Android security application (Jetpack Compose, offline engine, signed updates) (Completed)
  services/
    lab-worker/              # Sandboxed adversarial scenario generator & simulator
    evaluator/               # Automated regression & benchmark validation runner
  packages/
    shared-contracts/        # Canonical Pydantic schemas, DTOs, and domain enums
    threat-intelligence/     # Feed parsers, IOC normalizers, and threat categorizers
    policy-engine/           # Declarative rule matching and signature validation
  datasets/                  # Curated benchmark manifests and evaluation corpora
  infrastructure/
    docker/                  # Dockerfiles and support configurations (Postgres, Redis)
    railway/                 # Cloud deployment configurations
  .github/workflows/         # Automated multi-job CI/CD pipeline (ci.yml)
  railway.json               # Multi-service Railway cloud deployment configuration
  scripts/                   # Developer automation, preflight, and migration utilities
  docs/                      # Comprehensive technical documentation
  tests/                     # Cross-service integration & smoke tests
  docker-compose.yml         # Local orchestrated container environment
  pyproject.toml             # Pinned project configuration and tool definitions
  Makefile                   # Standardized development commands
  PROJECT_STATUS.md          # Real-time implementation status & audit tracker
  IMPLEMENTATION_ROADMAP.md  # 10-phase master implementation roadmap
```

---

## Prerequisites

- **Python:** 3.12 (CPython 3.12 pinned)
- **uv:** Fast package manager (`>=0.5.0`)
- **Docker & Docker Compose:** Docker 24+ and Compose v2+
- **Make:** Optional convenience runner (or direct `python`/`uv` scripts on Windows)

---

## Quickstart & Local Development

### Windows One-Command Development Runner (`scripts/dev_local.ps1`)

On Windows, use the unified automation script to run migrations, launch the backend, start the dashboard, execute tests, or perform preflight checks:

```powershell
# Apply database migrations and start API + Dashboard (runs natively without requiring Docker)
powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action start

# Run all 243 monorepo automated tests across Python, Extension, Dashboard, and Android
powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action test

# Run Railway deployment preflight verification
powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action preflight

# Build extension, dashboard, and Android APK
powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action build
```

---

### Manual Setup & Execution

### 1. Initialize Virtual Environment & Install Dependencies

```bash
# Create virtual environment with Python 3.12
uv venv --python 3.12 .venv

# Activate environment (Windows)
.venv\Scripts\activate

# Install all workspace packages in editable mode with development tools
uv pip install -e ".[dev]"
```

### 2. Configure Environment

Copy the template configuration file:
```bash
cp .env.example .env
```
By default, `AI_PROVIDER_TYPE=mock` allows running the entire application and test suite without any external AI API keys or third-party cloud accounts.

### 3. Run the Backend Locally

```bash
uvicorn apps.api.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify endpoints:
- Liveness check: `http://localhost:8000/health/live`
- Readiness check: `http://localhost:8000/health/ready`
- System status: `http://localhost:8000/api/v1/system/status`
- OpenAPI documentation: `http://localhost:8000/docs`

---

## Docker Orchestration

Run the fully isolated local environment:

```bash
# Build and start all services in the background
docker compose up -d --build

# View logs
docker compose logs -f api

# Stop and tear down the environment
docker compose down
```

---

## Testing Commands

```bash
# Run all unit and integration tests (132 tests)
pytest -v

# Run tests with test coverage across app, packages, lab-worker, blue-ai, and evaluator
pytest --cov=apps/api/app --cov=packages/threat-intelligence/cyberduel_threat_intel --cov=packages/shared-contracts/cyberduel_contracts --cov=packages/policy-engine/cyberduel_policy_engine --cov=services/lab-worker/app/red_ai --cov=services/evaluator/app

# Run linter
ruff check .

# Run code formatter check
ruff format --check .

# Run static type checking
mypy apps/api services/evaluator packages/shared-contracts packages/policy-engine packages/threat-intelligence

# Run Threat Detection Benchmark Evaluation (100% Accuracy, 0% FPR)
python scripts/evaluate_dataset.py --dataset datasets/manifests/synthetic_url_dataset.json

# Run Red AI Adversarial Experiment via CLI
python scripts/lab_cli.py run --name "Adversarial Test" --goal "Homoglyphs and False Positives" --count 50 --seed 42

# Run Blue AI Defense Cycle via CLI
python scripts/blue_cli.py cycle

# Run Independent Evaluator benchmark audit & leakage checks via CLI
python scripts/evaluator_cli.py validate-splits --manifest-id benchmark-golden-v1
python scripts/evaluator_cli.py evaluate --version 0.3.0-candidate

# Run Autonomous Self-Improvement Controller cycle via CLI
python scripts/controller_cli.py run-cycle --max-candidates 3 --timeout 90
python scripts/controller_cli.py list-cycles
python scripts/controller_cli.py trend-report

# Release Management & Cryptographic Signing CLI (Phase 6)
python scripts/release_cli.py init-keys --key-id cyberduel-prod-2026-k1
python scripts/release_cli.py trust-anchors
python scripts/release_cli.py check-eligibility --candidate-id <UUID> --report-id <UUID>
python scripts/release_cli.py authorize --candidate-id <UUID> --report-id <UUID> --version 2026.10.2 --channel stable --authorizer "ciso@cyberduel.internal" --rationale "Passed golden v1 benchmark"
python scripts/release_cli.py advance --release 2026.10.2 --stage canary_25
python scripts/release_cli.py verify --release 2026.10.2 --platform browser_extension
python scripts/release_cli.py rollback --regressed-release 2026.10.2 --target-version 2026.10.1 --authorizer "ciso@cyberduel.internal" --reason "Telemetry regression detected"
python scripts/release_cli.py list

# Browser Extension Build & Test (Phase 7)
cd apps/browser-extension
npm install
npm run type-check       # Strict TypeScript verification
npm run test             # Vitest test suite (39 tests)
npm run build            # Manifest V3 production build into dist/
cd ../..
```

---

## Implemented vs Planned Features (Phases 1, 2, 3, 4, 5, 6 & 7)

| Subsystem / Feature | Status | Notes |
| :--- | :---: | :--- |
| Modular Monorepo Scaffold | **Implemented** | Root package layout, contracts, services |
| FastAPI Application Core | **Implemented** | Structured logging, request correlation IDs, error handlers |
| Health & System Status Endpoints | **Implemented** | `/health/live`, `/health/ready`, `/api/v1/system/status` |
| Canonical Shared Contracts | **Implemented** | Pydantic v2 schemas for all core workflows |
| SQLAlchemy 2.x Domain Models | **Implemented** | 34 persistent domain entities with provenance |
| Alembic Migrations | **Implemented** | Migrations `0001` through `0006_release_management` verified |
| AI Provider Abstraction | **Implemented** | Protocol interfaces + deterministic mock provider |
| Docker Compose Setup | **Implemented** | Non-root users, isolated lab network, resource limits |
| Sandboxed Lab Worker Harness | **Implemented** | Safe, isolated worker with strict timeout & concurrency constraints |
| Safe URL Normalizer & Validator | **Implemented** | IDN/Punycode homoglyphs, IPv4/IPv6, default ports, secret redaction |
| Deterministic Heuristic Engine | **Implemented** | 11 transparent rules with evidence explanations |
| Explainable Risk Scoring Engine | **Implemented** | Soft independence saturation ($S = 1 - \prod(1 - w_i)$), deduplication |
| Optional ML Classifier | **Implemented** | 18 features, lightweight linear model, sigmoid scoring |
| Threat Observation Pipeline | **Implemented** | Privacy-conscious reporting, SHA-256 target hashing, lifecycle states |
| Edge Policy Bundle Exporter | **Implemented** | `LocalProtectionPolicyBundle` with integrity digest |
| Dataset Evaluation Benchmark | **Implemented** | `scripts/evaluate_dataset.py` with 100% detection rate & 0% FPR |
| Red AI Research Laboratory | **Implemented** | `ScenarioGenerator`, `ScenarioMutationEngine`, 14 scenario families, 100+ scenarios |
| Defensive Test Runner | **Implemented** | Executes synthetic scenarios directly against real `URLAnalysisService` |
| Failure Analyzer | **Implemented** | Categorizes discrepancies, extracts hypotheses, computes lab metrics |
| Evaluation Handoff Service | **Implemented** | Produces `EvaluationHandoffPackage` for Evaluator and Blue AI |
| Research Laboratory REST API | **Implemented** | `/api/v1/lab/*` (status, generate, experiments, results, metrics) |
| Laboratory CLI Tool | **Implemented** | `scripts/lab_cli.py` (generate, validate, run, report, reproduce) |
| Safe Declarative Rule Engine | **Implemented** | 20 allowlisted features, 9 deterministic operators, ReDoS bounds, zero eval/exec |
| Candidate Detector Sandbox | **Implemented** | Isolated side-by-side comparative execution of baseline vs candidate without mutation |
| Blue AI Defense Engine | **Implemented** | Automated research clustering, mathematical prioritization, invariant analysis, rule synthesis |
| Blue AI REST API | **Implemented** | `/api/v1/blue/*` (status, research, failure-groups, candidates, comparisons, evaluations, history) |
| Blue AI CLI Tool | **Implemented** | `scripts/blue_cli.py` (research, propose, test-sandbox, evaluate, cycle, status) |
| Independent Evaluation Engine | **Implemented** | Standalone auditor, zero label leakage, real sandbox execution, confusion matrix, P95 latency |
| Leakage-Resistant Benchmarks | **Implemented** | 5-way splits (`development`, `validation`, `regression`, `held_out`, `benign_control`) & group isolation |
| Acceptance Policy Engine | **Implemented** | Configurable gates: integrity, zero regressions, $\le 5\%$ FPR, target resolution, generalization |
| Autonomous Improvement Controller | **Implemented** | 10-step bounded self-improvement loop, resource guardrails, checkpoints, and trend reports |
| Evaluator & Controller REST APIs | **Implemented** | `/api/v1/evaluations/*` and `/api/v1/improvement/*` |
| Evaluator & Controller CLI Tools | **Implemented** | `scripts/evaluator_cli.py` and `scripts/controller_cli.py` |
| RFC 8785 Canonical Serialization | **Implemented** | Deterministic JSON byte encoding across all operating systems |
| Ed25519 Cryptographic Signing Authority | **Implemented** | Isolated signing service with detached digital signatures (`cyberduel_contracts.crypto`) |
| Key Authority & Trust Anchors | **Implemented** | Key generation, rotation, revocation, public `TrustAnchorSet` distribution |
| Release Eligibility Gates | **Implemented** | Verifies genuine evaluation reports, zero regressions, and accuracy/FPR thresholds |
| Explicit Release Authorization Gate | **Implemented** | Non-bypassable administrative authorization requirement (passing eval != deploy) |
| Safe Declarative Policy Bundler | **Implemented** | Compiles safe AST rules and threat indicators; zero executable code |
| Immutable Artifact Storage | **Implemented** | Atomic filesystem storage in `storage/releases/` with path-traversal & SHA-256 checks |
| Monotonic Release Sequencing | **Implemented** | Incrementing sequence numbers ($S_{n+1} > S_n$) preventing replay & downgrade attacks |
| Multi-Channel Staged Rollouts | **Implemented** | Channels (`development`, `canary`, `stable`, `emergency`), stages (`internal` $\to$ `GA`), hash bucketing |
| Automated Safety Circuit-Breaker | **Implemented** | Halts rollouts automatically if client install failure rate exceeds 5% |
| 7-Step Client Verification Pipeline | **Implemented** | Edge client reference standard enforcing cryptographic, anti-replay, and AST safety checks |
| Verifiable Emergency Rollback | **Implemented** | Generates signed rollback releases with higher sequence numbers for immediate fleet recovery |
| Release & Update Distribution REST APIs | **Implemented** | `/api/v1/releases/*` and `/api/v1/updates/*` |
| Release Management CLI | **Implemented** | `scripts/release_cli.py` |
| Browser Extension (Manifest V3) | **Implemented** | Chromium/Edge navigation guard with DNR, Link Guard, and 7-step verifier |
| Mobile Application (Android) | **Implemented** | Native Jetpack Compose app with offline URL engine, Share-to-Check, and signed updates |
| SOC / Research Command Center | **Implemented** | Real-time security operations console, RBAC, research observability, release management |
| Production Hardening & CI/CD | **Implemented** | Security audit, path-traversal mitigation, multi-job GitHub Actions CI, Railway deployment ready |

---

## Authoritative Documentation Suite

- [Final Verification Report](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/FINAL_VERIFICATION_REPORT.md) — Monorepo test breakdown, benchmark proofs, and execution evidence.
- [Security Findings & Hardening Register](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/SECURITY_FINDINGS.md) — Itemized vulnerability remediation, threat boundaries, and audit log.
- [Operations Runbook & Disaster Recovery](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/OPERATIONS_RUNBOOK.md) — Incident response, key rotation, emergency rollback, and backup protocols.
- [Railway Deployment Guide](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/RAILWAY_DEPLOYMENT.md) — Multi-service Railway topology, environment variable matrix, and preflight checklist.
- [Interactive Demonstration Guide](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/DEMO_GUIDE.md) — Step-by-step walkthrough of research-to-release lifecycle, browser extension, and dashboard.
- [System Architecture](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/ARCHITECTURE.md) — Technical architecture and boundary definitions.
- [API Contracts](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/API_CONTRACTS.md) — REST endpoints, payloads, and response envelopes.
- [Security Model](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/SECURITY_MODEL.md) — Cryptographic architecture and privilege boundaries.
- [Threat Model](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/THREAT_MODEL.md) — STRIDE threat analysis and countermeasure mappings.
- [Implementation Roadmap](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/IMPLEMENTATION_ROADMAP.md) — 10-phase master development plan.
- [Project Status & Audit Tracker](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/PROJECT_STATUS.md) — Empirical test logs and architecture decisions (ADR-001 through ADR-015).

---

## Known Limitations

- Production databases require PostgreSQL 16+; the development environment provides graceful fallback to SQLite for headless unit testing.
- The threat intelligence engine operates fully offline without external API keys or third-party web crawlers (zero SSRF risk).
- Red AI scenarios use strictly reserved documentation domains (`.test`, `.example`, `example.com`) and documentation IP ranges (RFC 5737 / RFC 3849). No real-world infrastructure is scanned or attacked.
- Red AI produces experimental failure findings and hypotheses; it is architecturally prohibited from modifying or authorizing production defenses directly.
- Blue AI and the Self-Improvement Controller only formulate candidate defenses and verify them against benchmarks. Passing evaluation makes a candidate eligible for release consideration, but production deployment requires explicit administrative authorization (`ReleaseApprovalService`).
- Authority Ed25519 private keys are strictly isolated in `infrastructure/keys` with restricted file permissions (`0o600`), and are never packaged into client distributions or exposed via public APIs.

