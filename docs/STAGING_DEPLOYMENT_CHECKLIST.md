# CyberDuel AI — Staging Deployment Checklist & Runbook

**Target Platform:** Railway (Staging Project)  
**Security Level:** Controlled Pre-Production  
**Governing Principle:** Zero unapproved deployment, zero exposed secrets, verified health before public routing.

---

## 1. Pre-Deployment Verification (Local Operator)

Execute these checks on the local workstation before initiating any Railway staging provisioning:

- [ ] **Automated Tests:** All 248 monorepo tests pass cleanly:
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action test
  ```
- [ ] **Deployment Preflight Check:** Dry-run completes with zero fatal errors:
  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action preflight
  ```
- [ ] **Clean Git Workspace:** All code changes and migration revisions are committed to branch `staging` or `main`.
- [ ] **Secret Generation:** Secure 32-byte (64 hex character) random token generated for `SECRET_KEY`:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] **No Hardcoded Secrets:** Verify no private keys, passwords, or test tokens exist in repository commits.

---

## 2. Railway Project & Plugin Provisioning (Manual Operator Action)

Log in to the [Railway Dashboard](https://railway.app) and create a private project named `cyberduel-staging`:

1. **Provision Managed PostgreSQL 16:**
   - In Railway: **+ New** -> **Database** -> **Add PostgreSQL**.
   - Note the provided connection variables: `${{Postgres.DATABASE_URL}}`.
2. **Provision Managed Redis 7:**
   - In Railway: **+ New** -> **Database** -> **Add Redis**.
   - Note the connection variable: `${{Redis.REDIS_URL}}`.
3. **Configure Volume Storage for Releases:**
   - For `cyberduel-api`: Add Volume with mount path `/app/storage/releases`.

---

## 3. Environment Variable Configuration Checklist

Configure the following variables in the Railway service dashboard using `.env.staging.example` as a template:

| Service | Variable Name | Recommended Staging Value | Secret? |
| :--- | :--- | :--- | :---: |
| `cyberduel-api` | `ENVIRONMENT` | `staging` | No |
| `cyberduel-api` | `DEBUG` | `false` | No |
| `cyberduel-api` | `SECRET_KEY` | `[Generated 64-char Hex String]` | **YES** |
| `cyberduel-api` | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | **YES** |
| `cyberduel-api` | `DATABASE_URL_SYNC` | `${{Postgres.DATABASE_URL}}` | **YES** |
| `cyberduel-api` | `REDIS_URL` | `${{Redis.REDIS_URL}}` | **YES** |
| `cyberduel-api` | `STORAGE_RELEASES_DIR` | `/app/storage/releases` | No |
| `cyberduel-api` | `AI_PROVIDER_TYPE` | `mock` | No |
| `cyberduel-api` | `CORS_ORIGINS` | `${{cyberduel-dashboard.RAILWAY_PUBLIC_DOMAIN}}` | No |
| `cyberduel-worker` | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | **YES** |
| `cyberduel-worker` | `REDIS_URL` | `${{Redis.REDIS_URL}}` | **YES** |
| `cyberduel-worker` | `LAB_ALLOW_EXTERNAL_NETWORK` | `false` | No |
| `cyberduel-dashboard` | `VITE_API_URL` | `https://${{cyberduel-api.RAILWAY_PUBLIC_DOMAIN}}` | No |

---

## 4. Multi-Service Deployment Sequence

Deploy the services in this exact dependency order:

1. **Deploy Managed Databases:** Ensure PostgreSQL and Redis show green "Active" health.
2. **Deploy API Service (`apps/api`):**
   - Container executes `apps/api/entrypoint.sh`.
   - Automated Alembic migrations apply revisions `0001` through `0007_audit_log_records`.
   - Process liveness check at `/health/live` must return HTTP 200 within 30 seconds.
3. **Deploy Research Worker (`services/lab-worker`):**
   - Private background worker connecting to Redis broker.
   - Strictly verify `LAB_ALLOW_EXTERNAL_NETWORK=false`.
4. **Deploy Command Center Dashboard (`apps/dashboard`):**
   - NGINX web server serving Vite SPA.
   - Verify health probe at `/health/live`.

---

## 5. Post-Deployment Staging Validation (Smoke Tests)

Once deployed, run the smoke verification script against the staging URL:

- [ ] **Liveness Probe:**
  ```bash
  curl -fsSL https://[STAGING_API_DOMAIN]/health/live
  # Expected: {"status":"healthy","checks":{"process":"alive"}}
  ```
- [ ] **Readiness Probe:**
  ```bash
  curl -fsSL https://[STAGING_API_DOMAIN]/health/ready
  # Expected: {"status":"healthy","checks":{"database":"reachable","ai_provider":"configured (mock)"}}
  ```
- [ ] **System Status:**
  ```bash
  curl -fsSL https://[STAGING_API_DOMAIN]/api/v1/system/status
  # Expected: {"status":"operational", ...}
  ```
- [ ] **RBAC Security Enforcement Check:**
  ```bash
  # Unauthenticated release authorization MUST fail with 403 Forbidden
  curl -s -o /dev/null -w "%{http_code}" -X POST https://[STAGING_API_DOMAIN]/api/v1/releases/authorize \
    -H "Content-Type: application/json" -d '{"candidate_id":"00000000-0000-0000-0000-000000000000"}'
  # Expected: 403
  ```
- [ ] **Dashboard Web Interface:** Open `https://[STAGING_DASHBOARD_DOMAIN]` in browser and verify overview cards render without network console errors.

---

## 6. Abort & Rollback Procedures

If any post-deployment smoke check fails:

1. **Immediate Traffic Halt:** In Railway dashboard, remove the public domain mapping from `cyberduel-api`.
2. **Review Deployment Logs:** Inspect `cyberduel-api` runtime logs for database connection or migration errors.
3. **Database Reversion (if necessary):**
   ```bash
   python -m alembic downgrade -1
   ```
4. **Rollback Container Image:** In Railway service view, click **Deployments** -> select previous successful build -> **Rollback**.

