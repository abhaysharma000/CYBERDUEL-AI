# CyberDuel AI — System Threat Model (STRIDE Methodology)

## 1. Threat Actors & Adversary Profile

| Adversary Profile | Motivation | Capabilities |
| :--- | :--- | :--- |
| **Commodity Cybercriminal** | Deploy credential harvesting & phishing campaigns | Uses homographs, bulletproof hosting, fast-flux DNS, obfuscated DOM |
| **Targeted APT Actor** | Circumvent defensive detection; poison models | Discovers evasion techniques; attempts telemetry poisoning |
| **Malicious Client Submitter** | Discredit defense; cause denial-of-service to benign sites | Submits false reports claiming legitimate services are malicious |
| **Compromised Edge Client** | Probe API limits; inject telemetry noise | Controls local client storage; alters reported engine version |
| **Malicious Synthetic Payload** | Break out of research sandbox | Explores container escape vulnerabilities or kernel exploits |

---

## 2. Threat Analysis & Mitigations

### 2.1 Spoofing & Identity
- **Threat:** An attacker spoofs a release update to deploy malicious rules or disables defenses on edge clients.
- **Mitigation:** Release manifests are cryptographically signed using Ed25519 with private keys isolated outside the application. Edge clients pin the public verification key. Clients reject unsigned updates or updates signed with untrusted keys.

### 2.2 Tampering & Telemetry Poisoning
- **Threat:** An adversary sends thousands of fake `ThreatObservationReport` payloads claiming `google.com` or `bank.com` is phishing to trick the AI into generating a blocking rule (Adversarial Data Poisoning).
- **Mitigation:**
  1. **Strict Non-Reliance:** Ingested observations are **never** treated as automatic ground truth.
  2. **Golden Regression Gate:** The Independent Evaluator executes an immutable golden suite of benign services (Tranco top 10k). Any candidate rule that blocks a golden benign service is immediately rejected.
  3. **Clustering & Rate Limiting:** Telemetry is clustered and subjected to rate limits.

### 2.3 Repudiation & Audit Trail
- **Threat:** An unauthorized or defective defensive rule is deployed without provenance.
- **Mitigation:** All candidate defenses and releases are recorded in persistent PostgreSQL tables (`candidate_defenses`, `evaluation_runs`, `policy_releases`) with UUID identifiers, author agent names, timestamps, and test metrics.

### 2.4 Information Disclosure & Telemetry Privacy
- **Threat:** Telemetry leaks user browsing history, corporate intranet URLs, or session credentials.
- **Mitigation:**
  - Raw URLs with query parameters or session tokens are normalized into SHA-256 cryptographic digests or privacy-preserving domain-only strings before leaving the client.
  - The API rejects unhashed full URLs containing known credential patterns.
  - No raw personal browsing history is persisted by default.

### 2.5 Denial of Service (DoS)
- **Threat:** Flooding the API with massive payloads or excessive requests to exhaust memory.
- **Mitigation:**
  - `RequestBodySizeLimitMiddleware` terminates requests larger than 1MB with HTTP 413 before memory allocation.
  - `InMemoryRateLimiter` throttles high-frequency callers with HTTP 429.
  - Request timeouts configured across all endpoints.

### 2.6 Elevation of Privilege & Container Escape
- **Threat:** A synthetic payload generated in the laboratory attempts to break out of the container to infect the host machine.
- **Mitigation:**
  - Red AI and lab workers are unprivileged (`UID 20001`), possess no Linux capabilities (`cap_drop: [ALL]`), and have `no-new-privileges: true`.
  - The host Docker socket is **never** mounted inside the container.
  - Outbound internet is disabled on the lab network (`internal: true`).

### 2.7 Path Traversal & Arbitrary File Access (Hardened in Phase 10)
- **Threat:** An adversary passes traversal sequences (`../../etc/passwd` or encoded `%2e%2e/`) in artifact retrieval endpoints.
- **Mitigation:**
  - Route-level parameter regex validation in `GET /api/v1/updates/artifacts/{digest}` enforces `FastApiPath(pattern=r"^[a-fA-F0-9]{64}$")`.
  - Storage-level boundary validation in `ArtifactStorageService` validates that resolved paths are strictly contained within the base release storage directory.

### 2.8 Replay & Downgrade Attacks (Hardened in Phase 10)
- **Threat:** An on-path attacker intercepts an older, vulnerable policy bundle and replays it to edge clients to resurrect an exploitable detection gap.
- **Mitigation:**
  - Every release manifest contains a strictly monotonic sequence number ($S_{n+1} > S_n$).
  - Edge clients reject any package where `sequence_number <= local_current_sequence_number` unless an explicit, cryptographically signed `is_rollback=True` flag is present.

---

## 3. Comprehensive Security Findings & Hardening Register

For detailed itemized findings, severity rankings, and verified remediations, refer to the authoritative [Security Findings & Hardening Register](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/SECURITY_FINDINGS.md).


