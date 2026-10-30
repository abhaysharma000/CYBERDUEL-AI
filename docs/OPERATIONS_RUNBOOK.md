# CyberDuel AI — Operations Runbook & Disaster Recovery

**Document Version:** 1.0.0  
**Target Audience:** Security Operations Engineers, Site Reliability Engineers, Release Managers  
**Classification:** Operational Security Procedures  

---

## 1. System Overview & Routine Health Checks

The CyberDuel AI platform operates as a distributed system comprising the Core API, sandboxed Red/Blue laboratory workers, independent evaluation engine, and edge client applications (Browser Extension and Android).

### 1.1 Routine Health Endpoints
- **Liveness Probe**: `GET /health/live`  
  Returns HTTP 200 `{"status": "healthy"}` if the Python process is responsive.
- **Readiness Probe**: `GET /health/ready`  
  Returns HTTP 200 `{"status": "ready", "database": "connected", "redis": "connected"}` only if PostgreSQL and Redis connections are active.
- **System Capabilities**: `GET /api/v1/system/status`  
  Returns AI provider mode, active version, uptime, and database metrics.

---

## 2. Emergency Policy Rollback Procedure

When a published security policy bundle introduces an unexpected false positive or edge client issue, follow this procedure to execute an authoritative, signed rollback.

> **CRITICAL RULE**: Never manually delete release records or alter sequence numbers in the database. Edge clients will reject any update with a sequence number lower than or equal to their currently installed sequence number. Rollbacks MUST be published as a **new, signed release** with an incremented sequence number and the `is_rollback=True` flag set.

### 2.1 Triggering Rollback via Release CLI
```bash
# Inspect currently staged and published releases
python scripts/release_cli.py list-releases

# Execute emergency rollback targeting previous known-good version (e.g. 2026.10.1)
python scripts/release_cli.py emergency-rollback \
  --target-version "2026.10.1" \
  --channel "stable" \
  --reason "CRITICAL: Widespread false positives on corporate intranet domains" \
  --operator "secops-lead"
```

### 2.2 Triggering Rollback via REST API
```http
POST /api/v1/releases/emergency-rollback HTTP/1.1
Host: api.cyberduel.ai
Authorization: Bearer <SECOPS_ADMIN_TOKEN>
Content-Type: application/json

{
  "target_version": "2026.10.1",
  "channel": "stable",
  "reason": "Intranet routing false positive identified in telemetry",
  "operator": "secops-oncall"
}
```

### 2.3 Rollout Circuit Breaker (Automatic Pause)
If edge client update telemetry reports an installation failure rate exceeding **5.0%** (`failure_rate > 0.05`), the `RolloutManager` automatically transitions the rollout state to `paused` and raises a high-priority incident alert.

To manually pause an active rollout:
```bash
python scripts/release_cli.py pause-rollout --release-id "<RELEASE_UUID>"
```

---

## 3. Cryptographic Key Management & Revocation

### 3.1 Normal Scheduled Key Rotation
Every 90 days, the primary release signing key must be rotated:
```bash
# 1. Generate new active key and transition old key to 'rotated'
python scripts/release_cli.py rotate-key \
  --current-key-id "cyberduel-prod-2026-k1" \
  --new-key-id "cyberduel-prod-2026-k2"

# 2. Export updated Trust Anchor Set for distribution to client updates
python scripts/release_cli.py export-trust-anchors --output "infrastructure/keys/trust_anchors.json"
```

### 3.2 Emergency Key Revocation (Compromise Response)
If an authority signing key is suspected of compromise:
```bash
# 1. Immediately revoke the compromised key
python scripts/release_cli.py revoke-key \
  --key-id "cyberduel-prod-2026-k1" \
  --reason "Credential exposure detected in external audit"

# 2. Generate and promote new uncompromised key
python scripts/release_cli.py create-key --key-id "cyberduel-prod-2026-k3-emergency"

# 3. Publish emergency policy release signed with new key
# All edge clients with the updated trust anchor set will reject any bundle signed by k1.
```

---

## 4. Database Migration Operations

CyberDuel uses Alembic for declarative schema evolution across 7 historical revisions (`0001` through `0007`).

### 4.1 Applying Migrations
```bash
# Verify pending revisions
alembic current
alembic check

# Apply all migrations to head
python scripts/run_migrations.py
# Or:
alembic upgrade head
```

### 4.2 Rollback of Migration Revision
```bash
# Roll back single revision
alembic downgrade -1

# Roll back to specific revision
alembic downgrade 0006
```

---

## 5. Backup & Disaster Recovery Protocols

### 5.1 PostgreSQL Full Database Backup
```bash
# Export compressed binary backup
pg_dump -U cyberduel -h $DB_HOST -p 5432 -d cyberduel_db -Fc -f "/backups/cyberduel_$(date +%Y%m%d_%H%M%S).dump"

# Restore database from dump
pg_restore -U cyberduel -h $DB_HOST -p 5432 -d cyberduel_db --clean "/backups/cyberduel_target.dump"
```

### 5.2 Release Artifact Storage Volume Backup
Release artifacts stored under `/app/storage/releases` are content-addressed by SHA-256 digest and immutable.
```bash
# Sync releases storage to secure cold backup
rsync -avz --checksum /app/storage/releases/ backup-server:/storage/cyberduel-releases/
```

