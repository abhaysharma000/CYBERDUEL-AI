# CyberDuel AI — Architecture Decision Records (ADRs)

## ADR-001: Pinned Python 3.12 Runtime & Monorepo Layout
- **Status:** Accepted
- **Context:** The platform requires asynchronous high-performance API routing, modern type hints, fast dependency management, and strict compatibility between cloud agents, services, and shared libraries.
- **Decision:** Standardize and pin Python 3.12 across all services, Docker images, and virtual environments. Organize code into a clean modular monorepo (`apps/`, `services/`, `packages/`).
- **Consequences:** Ensures consistency across development and production; simplifies shared contract imports; eliminates runtime drift between microservices.

---

## ADR-002: Canonical Shared Contracts Package (`packages/shared-contracts`)
- **Status:** Accepted
- **Context:** Multiple edge clients (browser extension, mobile app) and backend services must exchange structured data without contract divergence or runtime type errors.
- **Decision:** Define canonical data contracts as Pydantic v2 frozen models with `extra="forbid"`.
- **Consequences:** Disallows malformed or rogue parameters; guarantees that downstream edge clients and cloud API serialize and deserialize identical schemas.

---

## ADR-003: Deterministic Mock AI Provider for Offline CI & Local Development
- **Status:** Accepted
- **Context:** Testing and developing an AI-driven platform must not require paid API keys, active internet access, or slow cloud model inference.
- **Decision:** Implement a `DeterministicMockProvider` conforming to all provider protocols (`BaseThreatClassificationProvider`, `BaseReasoningProvider`, `BaseScenarioGeneratorProvider`, `BaseEvaluationProvider`).
- **Consequences:** All unit, integration, and CI tests run deterministically in sub-second time with zero cloud charges and zero credentials required.

---

## ADR-004: Strict Gatekeeping of Research Lab from Production Defenses
- **Status:** Accepted
- **Context:** Continuous generative AI learning without rigorous validation risks introducing severe regressions, hallucinatory false positives, and self-reinforcing blind spots.
- **Decision:** Blue AI candidate defenses must be formally evaluated by an independent evaluator against a golden benchmark before being authorized for release signing.
- **Consequences:** Protects production edge devices from unverified model degradation.

---

## ADR-005: Declarative Updates Over Executable Code
- **Status:** Accepted
- **Context:** Delivering compiled binaries or dynamic JavaScript to client browsers/devices as threat intelligence updates represents a critical supply-chain and remote-code-execution risk.
- **Decision:** All policy releases consist exclusively of declarative rule definitions (regex expressions, bloom filters, IOC lists, threshold weights) verified with cryptographic signatures (Ed25519).
- **Consequences:** Prevents remote code execution vectors on user endpoints.

---

## ADR-006: Safe URL Normalization, Structural Validation & Privacy Redaction
- **Status:** Accepted (Phase 2)
- **Context:** Malicious URLs employ homoglyphs, punycode, non-standard ports, IP-address literals, userinfo authentication tokens, percent-encoding obfuscation, and deep subdomains to bypass perimeter and local filters. Furthermore, logging raw URLs containing auth tokens or passwords violates user privacy and security standards.
- **Decision:** Implement `URLNormalizer` and `URLValidator` in `cyberduel_threat_intel`:
  1. Strip embedded userinfo credentials from canonical representations while flagging their presence as a suspicious feature.
  2. Normalize internationalized domain names (IDN) to Punycode `xn--` ASCII while retaining unicode representations for homoglyph detection.
  3. Strip default protocol ports (HTTP 80, HTTPS 443) and validate explicit ports.
  4. Redact known sensitive query parameter values (`token`, `api_key`, `session_id`, `password`) in persistent logs, evidence payloads, and telemetry digests.
  5. Enforce strict scheme validation (`http`, `https` only), length ceilings (4096 chars), and bracketed IPv6 verification.
- **Consequences:** Provides immune defense against encoding tricks, homoglyphs, and SSRF bypasses without transmitting private user credentials in diagnostic observations.

---

## ADR-007: Explainable Soft Independence Saturation Risk Scoring
- **Status:** Accepted (Phase 2)
- **Context:** Additive linear risk scoring produces artificial score saturation exceeding 1.0 or permits high-volume low-severity noise to masquerade as critical threats. Conversely, single-threshold overrides lack explainability across compound attacks.
- **Decision:** Use an explainable, probabilistic soft independence saturation formula:
  $$S = 1.0 - \prod_{i=1}^{k} (1 - w_i)$$
  where $w_i = \text{rule\_weight} \times \text{confidence}$. Apply strict evidence deduplication (keeping the highest-severity instance per category). Enforce deterministic decision thresholds (`allow` $< 0.40$, `warn` $[0.40, 0.70)$, `block` $\ge 0.70$) with a hard override for verified threat-intelligence feeds and fail-safe logic for malformed inputs.
- **Consequences:** Generates strictly bounded scores in $[0.0, 1.0]$, guarantees explainability with per-rule justification strings, eliminates duplicate penalty compounding, and provides a clear audit trail.

---

## ADR-008: Deterministic Adversarial Scenario Generation, Bounded Mutation Lineage & Separation of Concerns
- **Status:** Accepted (Phase 3)
- **Context:** Automated red teaming requires generating diverse, reproducible threat scenarios without deploying real-world malware, triggering live exploits, or corrupting ground-truth benchmarks through uncontrolled recursive mutation. Furthermore, Red AI must not approve its own findings or alter production policies directly.
- **Decision:**
  1. Restrict all synthetic scenarios to reserved documentation domains (`.test`, `.example`, `example.com`) and documentation IP ranges (RFC 5737 / RFC 3849). Prohibit live external network requests during generation and testing.
  2. Implement `ScenarioGenerator` with deterministic seeding so that identical seeds produce identical test corpora.
  3. Implement `ScenarioMutationEngine` with explicit lineage tracking (`mutation_parent_id`, `transformation_history`). Mutations that alter threat semantics flag `preserved_semantics = False` and set `expected_class = "uncertain"`, preventing silent ground-truth corruption. Enforce maximum mutation depth of 5.
  4. Separate observed detection discrepancies from explanatory hypotheses: `FailureAnalyzer` groups discrepancies and formulates hypotheses clearly labeled as hypotheses for investigation.
  5. Enforce strict architectural separation: Red AI packages findings into `EvaluationHandoffPackage` for the Independent Evaluator and future Blue AI. It possesses zero capability to stage, sign, or deploy production policy changes.
- **Consequences:** Guarantees fully reproducible, safe adversarial testing inside an isolated cyber range while maintaining strict architectural boundaries.

---

## ADR-010: Independent Evaluation Engine, Leakage-Resistant Benchmarks & Autonomous Self-Improvement Controller
- **Status:** Accepted (Phase 5)
- **Context:** An autonomous AI self-improvement system in cybersecurity must solve two acute challenges:
  1. Candidate defense proposals formulated by Blue AI must be rigorously, objectively audited by an independent engine without data leakage, label visibility, or self-approval bias.
  2. The research loop connecting Red AI adversarial discoveries, Blue AI countermeasures, and the Independent Evaluator must run autonomously under strict resource bounds, avoiding runaway compute, infinite loops, and premature production releases.
- **Decision:**
  1. **Strict Architectural Separation:** The Independent Evaluation Engine (`services/evaluator/`) operates completely separately from Red AI and Blue AI. It does not train, prompt, generate rules, or formulate hypotheses; it only executes the actual `CandidateDetectorSandbox` alongside the baseline detector across verified, immutable benchmark suites. Ground-truth benchmark labels remain hidden from candidate code.
  2. **Leakage-Resistant Benchmark Partitioning:** Datasets are structured into five disjoint, versioned splits: `development`, `validation`, `regression`, `held_out`, and `benign_control`. The `BenchmarkRegistry` enforces group-aware isolation: scenarios sharing the same `group_id` (domain root or mutation lineage) must never cross between training (`development`/`validation`) and evaluation (`held_out`/`regression`), eliminating trivial memorization and data contamination.
  3. **Multi-Gate Acceptance Policy Engine:** `AcceptancePolicyEngine` enforces configurable hard gates before a candidate defense can be approved:
     - Integrity Gate: Schema and allowlist validation, safe regex, digest verification.
     - Zero Regressions Gate: New regressions must not exceed `max_allowed_regressions` (default 0).
     - False Positive Ceiling Gate: FPR must not exceed `max_allowed_fpr` (default 0.05).
     - Target Failure Resolution Gate: Must resolve at least `min_failures_resolved` target failures.
     - Generalization Gate: Held-out $F_1$ must satisfy `min_held_out_f1` (default 0.70).
     - Operational Budget Gate: Mean latency overhead $\le 25\text{ ms}$, zero runtime errors.
  4. **10-Step Bounded Autonomous Improvement Loop:** The `SelfImprovementController` coordinates:
     (1) Select research opportunities -> (2) Request candidate defenses -> (3) Validate candidate schema & digest -> (4) Preliminary sandbox checks -> (5) Request independent evaluation -> (6) Record evaluation report & metrics -> (7) Update research priorities & provide learning feedback -> (8) Decide next steps -> (9) Enforce resource bounds & timeouts -> (10) Safe stopping & cycle finalization.
  5. **Core Operating Boundary:** Production defenses change only after independent validation and controlled release. The Self-Improvement Controller marks accepted candidates as `approved` / `eligible_for_release`, but possesses zero capability to sign or publish production releases (reserved for Prompt 7).
- **Consequences:** Guarantees objective, leak-free evaluation metrics, prevents runaway autonomous compute with clear stopping states (`STOPPED_BUDGET_EXHAUSTED`, `STOPPED_NO_PROGRESS`), maintains an auditable step-by-step checkpoint trail, and ensures only thoroughly verified candidate defenses are eligible for downstream release packaging.

---

## ADR-011: Cryptographic Supply-Chain Security, Ed25519 Manifest Signing, Staged Rollouts, and Verifiable Rollback
- **Status:** Accepted (Phase 6)
- **Context:** Delivering security intelligence and policy updates to distributed edge clients (future PC browser extension, mobile app) presents critical supply-chain security challenges:
  1. Passing automated lab evaluation must not automatically authorize production deployment.
  2. Edge updates must never contain executable code (preventing RCE vectors).
  3. Update manifests must be cryptographically authenticated, tamper-proof, and immune to replay attacks.
  4. Phased rollouts must protect the fleet from unobserved regressions, with automated safety circuit-breakers.
  5. The system must support immediate, verifiable rollbacks to known-good versions when incidents occur.
- **Decision:**
  1. **Strict Release Authorization Gate:** Passing evaluation makes a candidate eligible for release consideration; it does not authorize deployment. An explicit administrative or deployment workflow authorization (`ReleaseApprovalService`) is required, recording the authorizer identity, rationale, target channel, and timestamp.
  2. **Isolated Ed25519 Cryptographic Authority:** Release manifests are canonicalized per RFC 8785 (sorted keys, compact delimiters, UTF-8 encoded) and signed with Ed25519 private keys strictly isolated on the release authority server (`SigningKeyManager`). Private keys are never committed, never packaged in clients, and never exposed via APIs. Public keys are distributed as verifiable `TrustAnchorSet` packages.
  3. **Strictly Monotonic Sequence Numbers & Anti-Replay:** Every release is assigned an incrementally monotonic `sequence_number`. Edge clients reject any update where `manifest.sequence_number <= current_sequence_number`, unless explicit `is_rollback=True` authorization is cryptographically verified with a higher monotonic sequence number.
  4. **Multi-Channel Staged Rollouts & Deterministic Bucketing:** Release progression moves through defined channels (`development`, `canary`, `stable`, `emergency`) and stages (`internal` 0% -> `canary_10` 10% -> `canary_25` 25% -> `canary_50` 50% -> `general_availability` 100%). Client cohort targeting uses deterministic hash bucketing (`hash(client_id) % 100 < rollout_percentage`), ensuring consistent cohort membership. An automated circuit breaker trips and halts rollout if failure rates exceed 5%.
  5. **Emergency Rollback Protocol:** The `RollbackService` re-packages verified known-good historical policy bundles under a new monotonic sequence number with `is_rollback=True` and `is_mandatory=True`, immediately superseding the regressed release and commanding edge clients to revert safely.
  6. **7-Step Client Verification Reference Standard:** Edge clients enforce a mandatory 7-step pre-installation pipeline: (1) Active Trust Anchor Verification, (2) Ed25519 Digital Signature Verification, (3) Monotonic Sequence Anti-Replay Check, (4) Freshness / Expiry Check, (5) Compatibility & Platform Constraints Check, (6) Artifact SHA-256 Digest Verification, and (7) Declarative AST Schema Validation.
- **Consequences:** Eliminates remote code execution vulnerabilities from updates, prevents supply-chain tampering and rollback attacks, isolates release authority from autonomous learning loops, and enables safe, gradual fleet deployment with verifiable emergency containment.

---

## ADR-012: PC Browser Extension Manifest V3 Architecture, Synchronous DNR Filtering, Link Guard Navigation Interception, and Local Cryptographic Policy Verification
- **Status:** Accepted (Phase 7)
- **Context:** Delivering real-time edge navigation security across Chromium browsers (Google Chrome, Microsoft Edge) within the modern Manifest V3 security model imposes strict constraints:
  1. Synchronous request interception cannot run arbitrary remote or dynamic JavaScript in Manifest V3.
  2. Edge clients must remain resilient and fully protective even during extended network offline periods or cloud outages.
  3. User privacy must be preserved by default: page HTML, forms, credentials, and full browsing histories must never be collected or sent to the cloud.
  4. Updating edge defense policies requires strict local verification of Ed25519 digital signatures, canonical JSON digests, and monotonic sequence anti-replay checks before committing updates to the browser.
- **Decision:**
  1. **Dual-Layer Enforcement (DNR + Link Guard):**
     - Layer 1 (Synchronous Network Filtering): Compiles confirmed malicious threat indicators into native `chrome.declarativeNetRequest` dynamic rules. Operates directly within the browser network stack with sub-millisecond execution and zero JS runtime overhead.
     - Layer 2 (Link Guard Content Script): Intercepts user-initiated left-clicks on `<a>` tags. Respects modifier keys (Ctrl/Cmd/Shift/Alt), download attributes, and same-page anchor jumps. Applies fast local cached policy checks, routing suspicious destinations to an internal warning interface (`warning.html`).
  2. **100% Offline-Capable Local Threat Engine:** Ports the backend's URL normalization, indicator lookup, declarative AST rule evaluation, and heuristics to TypeScript. Operates completely offline using cached policies stored in `chrome.storage.local`.
  3. **Strict 7-Step Client Update Verifier:** The browser extension implements the reference 7-step cryptographic verification pipeline before activating any downloaded update: (1) Active Trust Anchor Verification, (2) Ed25519 Detached Signature Verification over RFC 8785 Canonical JSON, (3) Monotonic Sequence Anti-Replay ($S_{new} > S_{current}$), (4) Client & Engine Version Compatibility, (5) Expiration Cutoff, (6) Artifact Canonical SHA-256 Digest Verification, and (7) Declarative AST Safety & Quota Inspection.
  4. **Atomic Rollback & Quota Management:** Dynamic DNR rules are updated atomically via `updateDynamicRules({ removeRuleIds, addRules })` bounded to a maximum of 5,000 rules. If DNR installation fails, the previous trusted rules are restored and the policy commit is aborted.
  5. **Privacy by Default:** Telemetry mode defaults to `minimal`, which sends only irreversible SHA-256 target digests, domain, and rule verdicts. Sensitive query parameters (`token`, `auth`, `password`, `key`, `session`) are redacted prior to hashing or reporting. Full browsing history and DOM contents are never captured.
  6. **Warning and Continuation Security:** Confirmed malicious destinations (`block`) have no casual bypass. For lower-confidence heuristic warnings (`warn`), an explicit one-time continuation token is generated by the service worker, bound strictly to the destination SHA-256 digest, and expires in 60 seconds.
- **Consequences:** Provides ultra-low-latency, zero-cloud-dependent browsing protection, complies strictly with Chrome Web Store and Edge Add-ons Manifest V3 review guidelines, eliminates remote code execution vectors, and maintains cryptographic supply-chain integrity at the client edge.

---

## ADR-013: Android Mobile Security Architecture, Local URL Protection, Share-to-Check Integration, and Cryptographic Policy Verification
- **Status:** Accepted (Phase 8)
- **Context:** Delivering CyberDuel AI threat protection to mobile endpoints running Android requires addressing specific mobile constraints:
  1. Threat evaluation must run locally and offline with low latency and minimal battery consumption.
  2. Updates must never contain executable code or dynamic bytecode (preventing remote code execution and Google Play policy violations).
  3. Client must enforce the identical 7-step cryptographic verification pipeline (RFC 8785 canonical JSON, SHA-256 digests, detached Ed25519 signatures, monotonic sequence numbers) established in Prompts 6 and 7.
  4. The app must integrate naturally into Android user workflows (Share-to-Check from messaging apps, browsers, email) without leaking user private messages.
  5. The platform scope must be transparent and honest, providing user-initiated inspection and share workflows without making misleading claims about whole-device VPN interception.
- **Decision:**
  1. **Native Android Stack:** Kotlin 1.9.24, Jetpack Compose (BOM 2024.06.00), Material 3, AndroidX Lifecycle/ViewModel, OkHttp 4.12.0, Kotlinx Serialization 1.6.3, BouncyCastle (`bcprov-jdk18on:1.78.1`) for Ed25519 crypto, and WorkManager 2.9.1. Targeting Android 14 (API 34), Min SDK 26.
  2. **100% Offline-Capable Local Threat Engine:** Directly evaluates URLs on-device using:
     - Canonical WHATWG/RFC 3986 URL normalization, port stripping, credential extraction, and sensitive query parameter redaction.
     - 19 extracted lexical and structural features including Shannon host entropy.
     - Offline exact threat indicator matching (SHA-256 URL hash, domain hash, domain literal).
     - Safe declarative AST rule predicate evaluation (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `in`, `matches_regex`) with zero dynamic code evaluation.
     - Calibrated heuristic scoring (brand mimicry across 17 high-value brands, punycode homographs, IP literals, suspicious TLDs, and trusted top-domain whitelist bypass).
  3. **Share-to-Check Integration & Privacy Boundary:** Registers an `android.intent.action.SEND` (`text/plain`) intent filter on `MainActivity`. The `ShareLinkParser` extracts candidate URLs via regex, strips trailing punctuation, bounds extraction (max 5 URLs, 4096 characters per URL), and strictly discards surrounding message text to ensure user chat content never leaks into telemetry or disk storage.
  4. **Strict 7-Step Client Update Verification Pipeline:** The `ClientUpdateVerifier` enforces the reference 7-step verification sequence before activating any update:
     - Step 1: Active Trust Anchor & Key Status check.
     - Step 2: Detached Ed25519 signature verification over RFC 8785 canonical manifest JSON payload.
     - Step 3: Anti-replay monotonic sequence check ($S_{new} > S_{current}$ unless authorized rollback).
     - Step 4: Client and engine version compatibility (`mobile_app`, `android`, `all`).
     - Step 5: Manifest expiration cutoff check.
     - Step 6: Artifact canonical SHA-256 digest integrity verification.
     - Step 7: Pure declarative AST safety inspection (only permitted fields and operators, weights $\le 1.0$, zero executable code).
  5. **Atomic Policy Storage & Emergency Rollback:** Stores policy bundles and release manifests in internal app storage with atomic file rename operations (`active_policy.tmp` $\to$ `active_policy.json`). Automatically creates `backup_policy.json` before applying updates, enabling immediate on-device or remote-commanded rollback.
  6. **Privacy-Conscious Telemetry & Cloud Synchronization:** Interfaces with `/api/v1/updates/*` routes for update checking, manifest download, artifact retrieval, trust anchor synchronization, and honest delivery acknowledgement receipts. Telemetry to `/api/v1/telemetry/observations` sends strictly minimized data (SHA-256 target digests, domain, rule IDs, and verdicts), with zero cookies, passwords, or personal browsing history. Supports user false-positive dispute submissions.
  7. **Honest Architectural Scope:** Transparently discloses in-app and in UI settings that protection is performed via on-device local scanning and user-initiated Share-to-Check inspection, avoiding misleading claims about root privileges or whole-device VPN tunneling.
- **Consequences:** Provides robust, battery-efficient, offline-capable mobile link security, eliminates supply-chain update tampering risks, preserves user privacy, and maintains 100% cryptographic and protocol parity with the cloud research laboratory and PC browser extension.

---

## ADR-014: Unified Security Command Center Architecture, Role-Based Access Control (RBAC), Immutable Audit Logging, and Zero-Fabrication Presentation
- **Status:** Accepted (Phase 9)
- **Context:** Managing an autonomous, continuous defensive cybersecurity system requires a centralized, authoritative command center (`apps/dashboard`) for security operators and researchers. Key requirements:
  1. The interface must provide zero-fabrication visibility into real operational metrics directly queried from backend services.
  2. Actions must be governed by strict server-side Role-Based Access Control (RBAC) across `viewer`, `research_operator`, `defense_reviewer`, `release_operator`, and `admin`.
  3. Sensitive client data (e.g. passwords, authentication tokens, session identifiers) must be redacted before presentation.
  4. All high-impact operational decisions (release authorization, rollback, key rotation) must produce immutable audit log records.
- **Decision:** Build `apps/dashboard` with React 18, Vite 6, TypeScript, and Tailwind CSS. Expose real-time query endpoints in `apps/api/app/api/v1/dashboard.py`. Enforce RBAC in dependency injections. Record all operational events into `AuditLogRecord` via Alembic migration `0007_audit_log_records.py`.
- **Consequences:** Eliminates simulated dashboards; provides verifiable audit trails for enterprise security compliance; maintains strict privacy boundaries for client telemetry.

---

## ADR-015: Production Hardening, Multi-Service Railway Deployment Topology, Secret Containment, and Authoritative End-to-End Verification Pipeline
- **Status:** Accepted (Phase 10)
- **Context:** Transitioning the monorepo from active research and development to production deployment on Railway requires rigorous defense against real-world attack vectors:
  1. Path traversal risks in artifact downloads must be mitigated at the routing layer.
  2. Denial-of-service memory exhaustion attacks via oversized request bodies must be prevented.
  3. Continuous integration must execute tests across all languages (Python, TypeScript, Kotlin) with zero simulated passes.
  4. Railway monorepo deployment requires independent service definitions for public API, background worker, and static dashboard, backed by managed PostgreSQL and Redis plugins.
  5. Deployment scripts must validate environment and storage volume writability without printing or leaking secrets into logs.
- **Decision:**
  1. **Strict Path Parameter Regex Validation:** In `apps/api/app/api/v1/updates.py`, bound the artifact digest parameter to `FastApiPath(pattern="^[a-fA-F0-9]{64}$")`. Non-hex or directory-traversal attempts fail fast with HTTP 422 before touching the filesystem.
  2. **Streaming Body Size Limiter:** Enforce `RequestBodySizeLimitMiddleware` capping payloads at 1 MB (returning HTTP 413) to mitigate memory exhaustion DoS.
  3. **Multi-Job GitHub Actions CI Pipeline (`.github/workflows/ci.yml`):** Runs backend lint, mypy, pytest, database migrations, browser extension vitest and build, dashboard vitest and build, Android unit tests (`gradlew testDebugUnitTest`), secret scanning, and the e2e integration test.
  4. **Multi-Service Railway Deployment Topology:** Configure root `railway.json`, `apps/api/railway.json`, `services/lab-worker/railway.json`, and `apps/dashboard/railway.json`. Serve the dashboard using a multi-stage NGINX Alpine container with security headers. Mount persistent volume `/app/storage/releases` on `cyberduel-api`.
  5. **Preflight Verification Script (`scripts/railway_preflight.py`):** Automatically validates environment variables, storage volume read/write permissions, database connectivity, and Ed25519 cryptographic health, while redacting all secrets from console logs (`mask_secret`, `mask_url_credentials`).
  6. **Authoritative 11-Stage End-to-End Lifecycle Verification:** `tests/integration/test_e2e_research_to_release.py` exercises the complete pipeline: Red AI attack scenario -> Defensive analysis gap -> Blue AI candidate rule formulation -> Evaluator zero-regression audit -> Release eligibility -> Release authorization -> Ed25519 signing -> 7-step client verification -> 5 negative tampering tests (digest mismatch, bad signature, replay sequence, expired release, revoked key).
- **Consequences:** Ensures enterprise-grade security posture, eliminates supply-chain secret leakage, provides reproducible multi-service deployment on Railway, and mathematically verifies protection against tampering, replay, and downgrade attacks.








