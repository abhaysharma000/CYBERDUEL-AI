# CyberDuel AI — Railway Deployment Guide & Infrastructure Topology

**Document Version:** 1.0.0  
**Target Environment:** Railway Cloud Platform (Staging & Production)  
**Configuration Files:** `railway.json`, `apps/api/railway.json`, `apps/dashboard/railway.json`, `services/lab-worker/railway.json`  

---

## 1. Multi-Service Railway Topology

CyberDuel AI is configured for deployment on Railway using a multi-service architecture backed by managed persistence and cache plugins:

```
                          ┌───────────────────────────┐
                          │   Railway Public Edge     │
                          └─────────────┬─────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    ▼                                       ▼
       ┌────────────────────────┐              ┌────────────────────────┐
       │   cyberduel-api        │              │  cyberduel-dashboard   │
       │   FastAPI Web Service  │              │  NGINX SPA Service     │
       │   Port: $PORT          │              │  Port: $PORT           │
       │   Health: /health/live │              │  Health: /health/live  │
       └───────────┬────────────┘              └────────────────────────┘
                   │
         ┌─────────┴─────────┬───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌──────────────────┐ ┌───────────────┐ ┌────────────────────────┐
│  Railway Postgres│ │ Railway Redis │ │   cyberduel-worker     │
│  PostgreSQL 16   │ │ Redis 7 Cache │ │   Sandboxed Lab Worker │
│  (Managed Plugin)│ │ (Managed Queue│ │   (Private Service)    │
└──────────────────┘ └───────────────┘ └────────────────────────┘
         ▲                                       │
         └───────────────────────────────────────┘
                     (Task Processing)
```

### Service Breakdown:
1. **`cyberduel-api`** (Public Web Service):
   - **Source:** `apps/api/Dockerfile`
   - **Start Command:** `sh -c 'python scripts/run_migrations.py && uvicorn apps.api.app.main:app --host 0.0.0.0 --port ${PORT:-8000}'`
   - **Healthcheck Path:** `/health/live` (Timeout: 30s)
   - **Volume Mount:** `/app/storage/releases` (Persistent volume for immutable release bundles)
2. **`cyberduel-dashboard`** (Public Web Service):
   - **Source:** `apps/dashboard/Dockerfile`
   - **Runtime:** Lightweight NGINX Alpine serving Vite-built React SPA with SPA fallback routing.
   - **Healthcheck Path:** `/health/live`
3. **`cyberduel-worker`** (Private Background Service):
   - **Source:** `services/lab-worker/Dockerfile`
   - **Start Command:** `python services/lab-worker/app/worker.py`
   - **Networking:** Private only (no public domain or open ports). Connects to Redis broker.
4. **`postgres`** (Railway Plugin):
   - Managed PostgreSQL 16 database.
5. **`redis`** (Railway Plugin):
   - Managed Redis 7 in-memory cache and task queue broker.

---

## 2. Environment Variables Matrix

| Variable Name | Required | Default / Example | Sensitivity | Description |
|---|---|---|---|---|
| `ENVIRONMENT` | **Yes** | `production` | Public | Environment mode (`production`, `staging`, `development`). In `production`, mock AI is strictly prohibited. |
| `DEBUG` | **Yes** | `false` | Public | Debug mode. **MUST BE FALSE** in production. |
| `SECRET_KEY` | **Yes** | `[64-char random hex]` | **SECRET** | Core cryptographic session and JWT signing secret. Must be $\ge 32$ chars. |
| `DATABASE_URL` | **Yes** | `postgresql+asyncpg://...` | **SECRET** | Asynchronous database connection string for FastAPI async engine. |
| `DATABASE_URL_SYNC` | **Yes** | `postgresql+psycopg://...` | **SECRET** | Synchronous connection string for Alembic migrations. Auto-normalized if asyncpg is provided. |
| `REDIS_URL` | **Yes** | `${{Redis.REDIS_URL}}` | **SECRET** | Redis connection URL for worker queues and sliding-window rate limiting. |
| `STORAGE_RELEASES_DIR` | **Yes** | `/app/storage/releases` | Public | Persistent volume directory path for immutable policy bundles. |
| `CYBERDUEL_KEYSTORE_DIR`| **Yes** | `/app/storage/releases/keystore` | **SECRET** | Isolated directory on persistent volume for production Ed25519 signing private keys. |
| `AI_PROVIDER_TYPE` | **Yes** | `qwen` | Public | AI inference provider. In production, **MUST BE `qwen`**. Mock provider raises fatal `RuntimeError`. |
| `QWEN_API_BASE` | Conditional | `https://api.deepinfra.com/v1/openai` | Public | Base URL for OpenAI-compatible Qwen 2.5 endpoint (e.g. DeepInfra, Together AI, RunPod, or private vLLM). |
| `QWEN_API_KEY` | Conditional | `[API Key]` | **SECRET** | Required for authenticated hosted endpoints. Configure via Railway Secrets; never commit. |
| `QWEN_MODEL_NAME` | No | `Qwen/Qwen2.5-Coder-7B-Instruct` | Public | Target Qwen model name for Red AI scenario synthesis and Blue AI AST rule reasoning. |
| `QWEN_TIMEOUT_SECONDS` | No | `15.0` | Public | Hard timeout for Qwen inference requests. Fails closed upon timeout. |
| `RATE_LIMIT_ENABLED` | No | `true` | Public | Enables API rate limiter (120 req/min per IP default). |
| `MAX_REQUEST_BODY_BYTES`| No | `1048576` (1MB) | Public | Maximum permissible request body size to mitigate DoS attacks. |
| `CORS_ORIGINS` | No | `https://dashboard.cyberduel.ai` | Public | Comma-separated list of authorized browser origins (never include localhost in prod). |

---

## 3. Step-by-Step Railway Deployment Process

### Step 1: Provision Railway Project & Plugins
1. Log in to [Railway](https://railway.com) and create a new project: `cyberduel-defense-platform`.
2. Add a **PostgreSQL** database service (`Postgres 16`).
3. Add a **Redis** cache service (`Redis 7`).

### Step 2: Configure Environment Variables
Under Project Settings / Shared Variables, configure:
```env
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=YOUR_SECURE_RANDOMLY_GENERATED_64_CHAR_HEX_SECRET
STORAGE_RELEASES_DIR=/app/storage/releases
CYBERDUEL_KEYSTORE_DIR=/app/storage/releases/keystore
AI_PROVIDER_TYPE=qwen
QWEN_API_BASE=https://api.deepinfra.com/v1/openai
QWEN_API_KEY=YOUR_SECURE_QWEN_API_KEY
QWEN_MODEL_NAME=Qwen/Qwen2.5-Coder-7B-Instruct
CORS_ORIGINS=https://dashboard.cyberduel.ai
```
Reference Railway plugin variables:
- In `cyberduel-api`: `DATABASE_URL=${{Postgres.DATABASE_URL}}`
- In `cyberduel-api`: `DATABASE_URL_SYNC=${{Postgres.DATABASE_URL}}`
- In `cyberduel-api`: `REDIS_URL=${{Redis.REDIS_URL}}`
- In `cyberduel-worker`: `REDIS_URL=${{Redis.REDIS_URL}}`

> [!CAUTION]
> **GPU Hardware Architecture Reality:**
> Standard Railway container instances provide up to 8GB RAM / 4–8 vCPUs with **NO GPU hardware**.
> Do NOT attempt to load Qwen 7B weights inside a standard Railway CPU container. Running full or quantized Qwen on CPU leads to OOM crashes or prohibitive latency (>45s).
> Connect `cyberduel-api` and `cyberduel-worker` to an external OpenAI-compatible GPU endpoint (e.g. DeepInfra, Together, RunPod, or a private vLLM instance).

### Step 3: Attach Persistent Storage Volume
1. Open the `cyberduel-api` service in Railway.
2. Under **Volumes**, click **Add Volume**.
3. Set Mount Path: `/app/storage/releases`.
4. Set Size: `5 GB` (sufficient for ~50,000 policy releases and isolated keystore).

### Step 4: Run Preflight Verification Script
Before switching traffic to the production cluster, execute the preflight check locally or via a one-off Railway container:
```bash
python scripts/railway_preflight.py
```
Expected output:
```
Preflight Status: READY FOR RAILWAY DEPLOYMENT
Exit Code: 0
```

### Step 5: Trigger Deployments
1. Connect your GitHub repository to Railway.
2. Railway reads `railway.json` and builds the services.
3. Database migrations apply automatically during container startup before the Uvicorn web server starts (`python scripts/run_migrations.py`).
4. Railway polls `/health/live`. Upon successful liveness confirmation, traffic routes to the new containers.

---

## 4. Production Release Gating & Rollout Architecture

### 4.1 Channel vs. Rollout Stage Invariant
In CyberDuel AI:
- `ReleaseChannel`: `STABLE`, `BETA`, `NIGHTLY`.
- `RolloutStage`: `INTERNAL`, `CANARY`, `STAGED`, `FULL`, `PAUSED`, `HALTED`.

A release marked with `channel = "stable"` and `stage = "internal"` with `rollout_percentage = 0.0` means:
The policy is targeted for the stable client channel, but its distribution is strictly restricted to internal test fixtures. Real production clients will NOT receive or ingest this policy until a Security Officer authorizes rollout advancement:
1. **Internal Verification (`0%`):** Synthetic regression and dogfooding validation.
2. **Canary Rollout (`5% - 10%`):** Cohort-bucketed exposure to early client fleet.
3. **Staged Rollout (`25% -> 50%`):** Monitored expansion with telemetry observation checks.
4. **Full Production (`100%`):** Complete fleet availability.

### 4.2 Emergency Rollback & Key Revocation
If a published release produces false positive anomalies in the client fleet:
1. **One-Click Rollback:**
   ```bash
   POST /api/v1/releases/{release_id}/rollback
   Authorization: Bearer <SecOps_Token>
   {"reason": "Anomalous false-positive spike observed in canary fleet"}
   ```
2. **Atomic Rollback Manifest Delivery:**
   The backend synthesizes a signed emergency rollback manifest targeting the previous verified stable version ($V_{\text{target}}$) with an incremented sequence number ($S_{\text{new}} = S_{\text{current}} + 1$). Clients verify the signature and immediately downgrade their local AST rule table without violating anti-replay invariants.
3. **Key Revocation & Rotation:**
   If a signing key is suspected of compromise:
   ```bash
   POST /api/v1/releases/keys/rotate
   Authorization: Bearer <Admin_Token>
   {"old_key_id": "cyberduel-prod-2026-k1", "reason": "Scheduled key rotation / compromise mitigation"}
   ```
   The old key status is transitioned to `ROTATED` or `REVOKED`, and the new trust anchor is published to `/api/v1/updates/trust-anchors`.

