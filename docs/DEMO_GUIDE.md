# CyberDuel AI — Interactive Demonstration & End-to-End Walkthrough Guide

**Document Version:** 1.0.0  
**Target Audience:** Evaluators, Security Architects, Developers, Solution Reviewers  
**Prerequisites:** Python 3.12+, Node.js 20+, Google Chrome / Microsoft Edge  

---

## 1. Quick-Start Demonstration (30 Seconds)

To verify the complete autonomous defense lifecycle from synthetic attack scenario generation to Ed25519 signing and client tamper defense in a single command:

```bash
# Execute the authoritative end-to-end lifecycle verification test
.venv/Scripts/pytest tests/integration/test_e2e_research_to_release.py -v
```

This test executes all 11 stages:
1. Red AI generates synthetic homograph phishing scenario.
2. Defensive baseline detects gap.
3. Blue AI synthesizes declarative AST rule `RULE-PHISH-XXXX`.
4. Independent Evaluator validates against regression benchmark (0 regressions, passes gate).
5. Release eligibility verified.
6. Authority Ed25519 keypair generated, policy bundle compiled and signed.
7. Edge client executes 7-step cryptographic verification protocol (Passes).
8. Edge client rejects tampered artifact bundle bytes (Digest mismatch).
9. Edge client rejects forged or corrupted Ed25519 signature.
10. Edge client rejects replay attack with stale sequence number.
11. Edge client rejects expired release package.

---

## 2. Interactive Monorepo Walkthrough

### Step 1: Start Core API Service
In Terminal 1:
```bash
# Start the FastAPI backend with database migrations
python scripts/run_migrations.py
uvicorn apps.api.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify the API is running by navigating to `http://127.0.0.1:8000/health/live` or viewing Swagger UI at `http://127.0.0.1:8000/docs`.

---

### Step 2: Launch the Command Center Operations Dashboard
In Terminal 2:
```bash
cd apps/dashboard
npm install
npm run dev
```
Open your browser to `http://localhost:5173`.
The Command Center displays:
- **Operations Dashboard:** Live detector health, candidate progression, and active rollouts.
- **Red AI Lab:** Synthetic threat generator, adversarial scenario families, and discrepancy findings.
- **Blue AI Defense:** Synthesized declarative candidate rules, hypotheses, and tuning parameters.
- **Independent Evaluator:** Benchmark metrics, confusion matrices, and zero-regression audit trails.
- **Release Manager:** Staged channels (`stable`, `canary`), cryptographic manifests, and emergency rollback controls.
- **Client Fleet Telemetry:** Connected Browser Extension and Android client states.

---

### Step 3: Load the PC Browser Extension (Google Chrome / Microsoft Edge)
1. Build the extension bundle:
   ```bash
   cd apps/browser-extension
   npm run build
   ```
2. Open Chrome or Edge and navigate to:
   - Chrome: `chrome://extensions`
   - Edge: `edge://extensions`
3. Enable **Developer mode** (toggle in upper right).
4. Click **Load unpacked** and select the directory:
   `apps/browser-extension/dist`
5. The **CyberDuel AI Protection Guard** shield icon will appear in your browser toolbar.
6. Click the extension icon to view the popup:
   - Active Policy Version
   - Sequence Number
   - Number of Compiled AST Rules
   - Live Threat Blocking Toggle
   - Last Checked Timestamp

---

### Step 4: Test Link Guard & Navigation Protection Live
With the extension active:
1. Click the extension icon and select **Open Options / Settings**.
2. Trigger **Check for Policy Updates**:
   The extension fetches `/api/v1/updates/manifest`, validates the Ed25519 signature against its built-in trust anchors, downloads the bundle, verifies the SHA-256 digest, and atomically loads the declarative rules.
3. Attempt navigating to a test threat URL:
   `http://test-phishing-login.secure-bank.example/`
4. The extension intercepts the navigation request, blocks the connection, and displays the red CyberDuel AI warning screen (`warning.html`) with explainable evidence.

---

### Step 5: Android Mobile Companion Demo
To inspect and test the Android mobile client:
```bash
cd apps/mobile
./gradlew testDebugUnitTest
```
All 39 unit tests execute, verifying:
- URL canonicalization and token redaction parity with Python backend.
- Ed25519 signature verification using Java cryptography.
- Local AST declarative rule matching.
- Anti-replay sequence enforcement.

---

## 3. Automated Monorepo Test Suite Verification

To execute all tests across all components in the monorepo:

```bash
# 1. Backend & Integration Tests (158 passed)
.venv/Scripts/pytest

# 2. Browser Extension Tests (39 passed)
npm --prefix apps/browser-extension run test

# 3. Dashboard Tests (7 passed)
npm --prefix apps/dashboard run test

# 4. Android Unit Tests (39 passed)
cd apps/mobile && ./gradlew testDebugUnitTest --no-daemon

# 5. Railway Production Preflight Check (PASS)
python scripts/railway_preflight.py --dry-run
```
Total: **243 automated tests passing, 0 failed, 0 skipped.**

Or run everything with a single command on Windows:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev_local.ps1 -Action test
```

