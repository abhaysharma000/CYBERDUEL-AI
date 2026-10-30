# CyberDuel AI — Security Operations & Cryptographic Runbook

**Document Version:** 1.0.0  
**Classification:** Confidential / Operations Manual  
**Applies To:** Core API Gateway, Security Officers, Release Authorities, and Endpoint Clients  

---

## 1. Cryptographic Key Architecture & Storage Isolation

### 1.1 Invariants
1. **Never Reuse Development Keys in Production:** The bootstrap key `cyberduel-prod-2026-k1` used in development testing must never be deployed as the active production signing authority.
2. **Ephemeral Image Isolation:** Private keys (`*.priv.pem`) must NEVER be baked into container images, committed to Git repositories, or logged in server telemetry.
3. **Volume Isolation:** In production on Railway, private keys are generated and stored exclusively within the persistent volume directory specified by `CYBERDUEL_KEYSTORE_DIR` (e.g. `/app/storage/releases/keystore/`).
4. **Public Trust Distribution:** Clients (Browser Extension and Android Companion) receive only public keys formatted as `TrustAnchorSet` models.

---

## 2. Production Signing Key Generation & Rotation

### 2.1 Dedicated Production Key Generation
To bootstrap a new dedicated production signing key on the production authority container:

```bash
# Execute within secure production container or isolated provisioning script
python -c "
from apps.api.app.services.releases.key_manager import SigningKeyManager
import asyncio

async def generate():
    km = SigningKeyManager(keystore_dir='/app/storage/releases/keystore')
    # Keypair generation and registration
    key_record = await km.generate_and_register_key(session, key_id='cyberduel-prod-2026-v1')
    print('Generated key:', key_record.key_id)
    print('Public PEM:\n', key_record.public_key_pem)

asyncio.run(generate())
"
```

### 2.2 Scheduled Key Rotation Runbook
Keys should be rotated every 90 days or whenever operational policies require:

1. **Invoke Rotation API:**
   ```http
   POST /api/v1/releases/keys/rotate
   Host: api.cyberduel.ai
   Authorization: Bearer <Admin_JWT_Token>
   Content-Type: application/json

   {
     "old_key_id": "cyberduel-prod-2026-v1",
     "new_key_id": "cyberduel-prod-2027-v1",
     "reason": "Scheduled 90-day rotation"
   }
   ```
2. **System Response:**
   - Old key status transitions to `ROTATED` with `valid_until` set to `now()`.
   - New key `cyberduel-prod-2027-v1` is generated with status `ACTIVE`.
   - Immutable audit log records event `releases.key.rotate`.
3. **Client Verification Update:**
   - Active trust anchors are updated automatically via `GET /api/v1/updates/trust-anchors`.

---

## 3. Emergency Release Revocation & Rollback Protocol

When an active production policy exhibits anomalous behavior (e.g., false positive spikes in edge telemetry):

### 3.1 Step 1: Immediate Rollout Pause
Halt all fleet ingestion immediately:
```http
POST /api/v1/releases/{release_id}/pause
Host: api.cyberduel.ai
Authorization: Bearer <Release_Operator_Token>
Content-Type: application/json

{
  "reason": "Investigating reported false-positive spike"
}
```
*Effect:* `RolloutStateRecord.is_paused = True`. Subsequent `/updates/check` requests from edge clients receive `update_available = False`.

### 3.2 Step 2: Atomic Rollback Trigger
If the release is determined to be defective:
```http
POST /api/v1/releases/{release_id}/rollback
Host: api.cyberduel.ai
Authorization: Bearer <Release_Operator_Token>
Content-Type: application/json

{
  "target_version": "2026.10.1",
  "reason": "Rollback to last verified stable policy"
}
```
*Effect:*
1. The backend locates target policy `2026.10.1`.
2. A new rollback release manifest is constructed with `is_rollback = True`.
3. The manifest is signed with the active production signing authority.
4. An incremented monotonic sequence number is assigned ($S_{\text{rollback}} = S_{\text{faulty}} + 1$).
5. Clients querying `/updates/check` receive `is_rollback = True` with the target manifest, downgrade their declarative rule table, and emit an acknowledgement.

---

## 4. Key Revocation (Compromise Response)

If a private signing key is suspected of compromise:

1. **Revoke Compromised Key:**
   ```http
   POST /api/v1/releases/keys/{key_id}/revoke
   Host: api.cyberduel.ai
   Authorization: Bearer <Admin_JWT_Token>
   Content-Type: application/json

   {
     "reason": "Suspected key material compromise"
   }
   ```
2. **Revocation Propagation:**
   - Key status transitions to `REVOKED`.
   - The key is added to `trust_anchors.revoked_keys`.
   - All edge clients verifying updates immediately reject any manifest signed by the revoked key ID (Check 1 of 7-step verification).
3. **Generate Replacement Key:**
   Immediately generate and activate a clean keypair.

---

## 5. Security Invariants & Fail-Closed Enforcement

1. **Independent Evaluator Isolation:**
   - The Independent Evaluator operates deterministically without LLMs.
   - Evaluator verdict `pass` is required for release eligibility. Any candidate with verdict `fail` or accuracy below threshold (0.80) cannot be authorized.
2. **Strict Production AI Policy:**
   - `AI_PROVIDER_TYPE` cannot be `mock` in production.
   - Live inference failures (HTTP 401, 429, 500) raise typed exceptions (`ProviderInferenceError`, `ProviderRateLimitError`, `ProviderUnavailableError`) and fail closed.
   - No silent mock or procedural fallbacks occur in production mode.
3. **Immutable Audit Trail:**
   - Every administrative login, policy proposal, evaluation run, release authorization, rollout advance, rollback, and key operation is recorded to `audit_log_records`.
   - Audit records are immutable; no update or delete endpoints exist.

