# CyberDuel AI — Android Mobile Security Application Architecture

## 1. Executive Summary & Vision

The CyberDuel AI Android Mobile Security Application (`apps/mobile`) brings the platform's defense capabilities directly to Android mobile devices. Operating as a decentralized, privacy-preserving edge guardian, the application provides instantaneous local threat evaluation for destinations encountered in messaging, web browsing, emails, and SMS.

The mobile client adheres to the fundamental monorepo design invariants:
1. **100% Offline-Capable Local Detection:** Detection does not rely on per-request cloud API calls. All evaluation is performed on-device against declarative AST rules, exact threat indicators, and calibrated heuristics.
2. **Zero Executable Code Delivery:** Security updates delivered to the device contain declarative data artifacts only (AST rules and indicator digests). No dynamic bytecode, dex loading, or scripting evaluation is ever executed.
3. **End-to-End Cryptographic Supply-Chain Security:** Policy bundles and release manifests are authenticated via detached Ed25519 digital signatures computed over RFC 8785 canonical JSON payloads, with monotonic sequence anti-replay protection.
4. **Transparent & Honest Scope:** The application implements explicit user-initiated and Share-to-Check inspection workflows. It avoids false marketing claims regarding whole-device VPN network capture or kernel-level packet inspection.
5. **Zero Private Data Leakage:** The application extracts candidate URLs from shared texts, bounds parsing, and discards all surrounding message body content. Telemetry reports to `/api/v1/telemetry/observations` send only irreversible SHA-256 target digests, domain strings, and rule verdicts.

---

## 2. System Architecture & Topology

```
+-----------------------------------------------------------------------------------------+
|                                CYBERDUEL AI CLOUD LAB                                   |
|   +-------------------+       +--------------------+       +------------------------+   |
|   |  Red AI Research  | ----> |   Blue AI Defense  | ----> | Independent Evaluator  |   |
|   +-------------------+       +--------------------+       +------------------------+   |
|                                                                         |               |
|                                                                         v               |
|                                                            +------------------------+   |
|                                                            | Release Authority API  |   |
|                                                            |  (/api/v1/updates/*)   |   |
+-----------------------------------------------------------------------------------------+
                                                                         |
                                              Signed Release Manifest    |
                                              + Declarative AST Policy   |
                                              (Ed25519 Detached Sig)     |
                                                                         v
+-----------------------------------------------------------------------------------------+
|                               ANDROID MOBILE APPLICATION                                |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  |                            JETPACK COMPOSE UI LAYER                               |  |
|  |   HomeScreen   |   AnalysisScreen   |   UpdateScreen   |   ThreatHistoryScreen   |  |
|  +-----------------------------------------------------------------------------------+  |
|                                          |                                              |
|  +-----------------------------------------------------------------------------------+  |
|  |                           ANDROID SYSTEM INTEGRATION                              |  |
|  |   - MainActivity (SingleTask)                                                     |  |
|  |   - android.intent.action.SEND (text/plain) Share-to-Check Filter                 |  |
|  |   - ShareLinkParser (bounded extraction, zero message leakage)                    |  |
|  +-----------------------------------------------------------------------------------+  |
|                                          |                                              |
|  +---------------------------------------v-------------------------------------------+  |
|  |                      LOCAL THREAT DETECTION ENGINE                                |  |
|  |   - URLNormalizer: RFC 3986 normalization, userinfo stripping, query redaction    |  |
|  |   - FeatureExtractor: 19 lexical/structural features + Shannon host entropy      |  |
|  |   - Threat Intelligence Lookup: O(1) hash & domain lookup                         |  |
|  |   - DeclarativeRuleEvaluator: Safe AST predicates (eq, gt, in, matches_regex)     |  |
|  |   - HeuristicAnalyzer: Brand mimicry, punycode, IP literals, TLDs, whitelist      |  |
|  |   - ThreatDecision: Aggregated score calibration (ALLOW, WARN, BLOCK)             |  |
|  +-----------------------------------------------------------------------------------+  |
|                                          |                                              |
|  +---------------------------------------v-------------------------------------------+  |
|  |                      7-STEP CLIENT UPDATE VERIFIER                                |  |
|  |   1. Active Trust Anchor Check         5. Expiration Cutoff Check                 |  |
|  |   2. Detached Ed25519 Signature Check  6. Artifact SHA-256 Digest Verification    |  |
|  |   3. Monotonic Sequence Check          7. Declarative AST Safety & Quotas         |  |
|  |   4. Platform & Engine Compatibility                                              |  |
|  +-----------------------------------------------------------------------------------+  |
|                                          |                                              |
|  +---------------------------------------v-------------------------------------------+  |
|  |                          STORAGE & NETWORKING LAYER                               |  |
|  |   - PolicyStorage: Atomic write (active_policy.tmp -> json), backup & rollback    |  |
|  |   - SettingsRepository: SharedPreferences, offline telemetry buffer               |  |
|  |   - ApiClient: OkHttp 4.12, timeouts, TLS 1.3, JSON serialization                 |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 3. Technology Stack & Platform Capabilities

| Layer | Component / Library | Specification / Purpose |
| :--- | :--- | :--- |
| **Language & Tooling** | Kotlin 1.9.24 / JVM 17 | Strictly typed, coroutine-native modern mobile stack |
| **Android SDK** | API 34 (Android 14) / Min SDK 26 (Android 8.0) | Covers >95% of active Android devices worldwide |
| **Build System** | Gradle 8.9 / AGP 8.5.1 | Reproducible wrapper build, configuration cache, R8 |
| **UI Framework** | Jetpack Compose BOM 2024.06.00 | Declarative UI, Material Design 3, reactive state |
| **Architecture** | MVVM + Clean Architecture | AndroidX Lifecycle 2.8.4, ViewModel, StateFlow |
| **Async & Concurrency**| Kotlinx Coroutines 1.8.1 | Structured concurrency, Dispatchers.Default / IO |
| **Serialization** | Kotlinx Serialization 1.6.3 | Reflection-free compile-time JSON encoding |
| **Cryptography** | BouncyCastle 1.78.1 (`bcprov-jdk18on`) | ASN.1 DER decoding, Ed25519 digital signature verification |
| **Networking** | Square OkHttp 4.12.0 | HTTP/2, connection pooling, configurable timeouts |
| **Background Sync** | AndroidX WorkManager 2.9.1 | Opportunistic battery-aware background update sync |
| **Testing** | JUnit 4.13.2 / Kotlinx Coroutines Test | Local JVM unit tests, cross-language test vectors |

---

## 4. Canonical URL Normalization & Feature Extraction

### 4.1 URL Normalizer (`URLNormalizer.kt`)
The mobile normalizer enforces cross-language behavioral parity with the Python backend (`cyberduel_threat_intel.normalizer`) and TypeScript browser extension (`apps/browser-extension/src/engine/normalizer.ts`):
1. **Protocol Normalization:** Lowercases scheme (`HTTP` $\to$ `http`, `HTTPS` $\to$ `https`). Rejects unsupported schemes (`file://`, `javascript:`, `data:`).
2. **Host Normalization:** Strips trailing dot, lowercases ASCII host, converts IDN/Punycode representations (`xn--...`), and flags IP address literals (IPv4/IPv6).
3. **Port Normalization:** Strips default scheme ports (`:80` for HTTP, `:443` for HTTPS). Retains non-default ports (e.g. `:8080`, `:8000`).
4. **Authority Userinfo Credential Stripping:** Extracts embedded authentication credentials (`username:password@`), redacts passwords to `[REDACTED]`, removes userinfo from the canonical URL, and flags `has_embedded_credentials = true`.
5. **Path Normalization:** Collapses dot segments (`/a/b/../c/./d` $\to$ `/a/c/d`) and collapses consecutive slashes (`//` $\to$ `/`).
6. **Query Parameter Sanitization:** Sensitive security parameter values (`token`, `api_key`, `key`, `password`, `secret`, `auth`, `access_token`) are redacted to `%5BREDACTED%5D` in canonical URL outputs and evidence metadata.
7. **Canonical Digest Generation:** Computes canonical SHA-256 digests over the normalized URL string (`url_sha256`) and domain string (`domain_sha256`).

### 4.2 Feature Extraction (`FeatureExtractor.kt`)
Extracts 19 structural and lexical features:
- Length metrics: `url_length`, `host_length`, `path_length`, `query_length`.
- Hierarchical metrics: `subdomain_count`, `path_depth`.
- Behavioral flags: `has_embedded_credentials`, `is_ip_literal`, `is_punycode`, `brand_token_detected`, `has_non_standard_port`.
- Phishing heuristics: `phish_keyword_count`, `is_whitelisted`.
- Information entropy: Shannon entropy calculation over host characters:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

---

## 5. Threat Decision Framework & Declarative AST Rules

### 5.1 Threat Decision Pipeline (`LocalThreatEngine.kt`)
The engine executes a 6-stage decision pipeline:
1. **Normalization:** Parses and standardizes the input URL. Non-web or unparseable URLs return `allow` with low confidence.
2. **Threat Intelligence Exact Match:** Compares `url_sha256`, `domain_sha256`, and domain literal against the active policy's threat indicators. Matching items produce immediate high-confidence (0.99) verdicts with `provenance = threat_intelligence`.
3. **Feature Extraction:** Extracts structural, lexical, and statistical attributes.
4. **Declarative Rule Evaluation:** Evaluates active AST defensive rules. If any rule triggers an explicit `block` action, the engine returns `block` with `provenance = rule_engine`.
5. **Heuristic Analysis:** Analyzes brand mimicry (17 high-value financial, cloud, and tech brands), punycode homographs, IP literals with phishing tokens, and suspicious top-level domains (`.tk`, `.ml`, `.icu`, `.top`). Verified top-tier domains bypass heuristic penalties.
6. **Aggregated Score Calibration:**
   $$\text{Score} = \min(1.0, \max(\text{HeuristicScore}, \sum \text{RuleWeights}))$$
   - $\text{Score} \ge \text{BlockThreshold} \ (0.85) \implies \mathbf{BLOCK}$
   - $\text{Score} \ge \text{WarnThreshold} \ (0.50) \implies \mathbf{WARN}$
   - Otherwise $\implies \mathbf{ALLOW}$

---

## 6. 7-Step Cryptographic Client Verification Pipeline

The client guarantees cryptographic supply-chain security by verifying updates against 7 mandatory checkpoints before committing them to persistent storage (`ClientUpdateVerifier.kt`):

```
       [ Downloaded Update Manifest & Artifact Bundle ]
                             |
                             v
   +----------------------------------------------------+
   | Step 1: Active Trust Anchor Check                  |
   | - Publisher key in active trust anchors?           |
   | - Publisher key revoked? Valid validity dates?     |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 2: Detached Ed25519 Signature Check           |
   | - RFC 8785 canonical JSON payload extracted        |
   | - Ed25519 verification over canonical bytes        |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 3: Anti-Replay Monotonic Sequence Check       |
   | - Sequence > current sequence? (Prevent downgrade) |
   | - If is_rollback=true, verified higher sequence?   |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 4: Platform & Version Compatibility Check     |
   | - Supports 'mobile_app', 'android', or 'all'?      |
   | - Client & engine version >= minimum required?     |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 5: Expiration Cutoff Check                    |
   | - Current time < manifest expires_at?              |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 6: SHA-256 Artifact Integrity Check           |
   | - SHA-256(artifact_raw_bytes) == artifact_digest?  |
   +----------------------------------------------------+
                             | Passed
                             v
   +----------------------------------------------------+
   | Step 7: Declarative AST Safety & Quotas            |
   | - Predicate operators strictly in allowed set?     |
   | - Weight per rule in [0.0, 1.0]?                   |
   | - Zero executable scripts or dynamic bytecode?     |
   +----------------------------------------------------+
                             | Passed
                             v
             [ ATOMICALLY INSTALL POLICY BUNDLE ]
```

---

## 7. Staged Security Updates, Rollback & Trust Anchor Management

### 7.1 Lifecycle State Machine
Updates transition through a deterministic state machine:
$$\text{IDLE} \longrightarrow \text{CHECKING} \longrightarrow \text{AVAILABLE} \longrightarrow \text{DOWNLOADING} \longrightarrow \text{VERIFYING} \longrightarrow \text{INSTALLED}$$
Upon any verification failure:
$$\text{VERIFYING} \longrightarrow \text{FAILED} \longrightarrow \text{ACKNOWLEDGEMENT(FAILURE)}$$

### 7.2 Atomic Rollback Mechanism
Before an update is committed, the current `active_policy.json` is cloned to `backup_policy.json`. If an incident occurs or a rollback is triggered:
1. `PolicyStorage.rollback()` atomically replaces `active_policy.json` with `backup_policy.json`.
2. The local threat engine is immediately refreshed with the restored policy bundle.
3. An acknowledgement with `status = "rolled_back"` and `is_rollback_applied = true` is transmitted to the cloud research lab.

---

## 8. Android Share-to-Check Workflow & Privacy Boundary

### 8.1 Intent Integration
Registered on `MainActivity`:
```xml
<intent-filter>
    <action android:name="android.intent.action.SEND" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:mimeType="text/plain" />
</intent-filter>
```
When a user selects "Share" on a link or message containing a link in WhatsApp, Signal, SMS, Gmail, or Chrome, CyberDuel AI appears in the system Share sheet.

### 8.2 Privacy Boundary Sanitization (`ShareLinkParser.kt`)
User messages frequently contain confidential personal text alongside links. The `ShareLinkParser`:
1. Scans the plain text using strict URL patterns (`(?:https?://|www\.)[^\s<>"'{}|\\^`\\[\\]]+`).
2. Strips surrounding punctuation marks (`.`, `,`, `!`, `?`, `)`, `]`).
3. Bounds output to a maximum of 5 URLs and 4,096 characters per URL.
4. **Strict Privacy Boundary:** Completely discards all message text. The application never stores, analyzes, logs, or transmits the user's message body.

---

## 9. Privacy-Conscious Telemetry & Dispute Reporting

### 9.1 Anonymous Threat Observation (`ThreatObservationReport`)
When threat protection detects a malicious or suspicious destination (`Decision != ALLOW`) and the user has telemetry enabled:
- `normalized_identifier`: 64-character SHA-256 digest of the canonical URL (`url_sha256`).
- `observed_url`: `null` (raw query parameters with user tokens are omitted).
- `detected_features`: Domain, domain SHA-256, structural flags.
- `context`: Anonymous client UUID, provenance, matched rule IDs.

### 9.2 False-Positive Dispute Pipeline
Users can contest an evaluation directly from `AnalysisScreen`:
- Submits an anonymous report containing the disputed decision and user explanation.
- Transmitted to `/api/v1/telemetry/observations` for review by the Red/Blue AI research lab.

---

## 10. Security Boundaries, Threat Model & Honest Capability Disclosure

### 10.1 Honest Security Scope
- **On-Device Inspection:** The app operates strictly within standard Android application sandboxes.
- **No Deceptive VPN Claims:** Unlike rogue security apps that promise "100% full-device network protection" by running fake local VPN servers, CyberDuel AI honestly discloses that it inspects links shared into the app or entered manually.
- **Zero Root Privileges:** Operates with standard unprivileged Android permissions (`INTERNET`, `ACCESS_NETWORK_STATE`, `POST_NOTIFICATIONS`).

### 10.2 Threat Model Mitigations

| Threat Vector | Mitigation Strategy |
| :--- | :--- |
| **Tampered Update Bundle** | Step 6 verifies SHA-256 digest against manifest signed with publisher Ed25519 key. |
| **Rogue Update Authority** | Step 1 validates publisher key ID against bundled root trust anchors. |
| **Replay / Rollback Attack** | Step 3 enforces strictly increasing monotonic sequence numbers ($S_{new} > S_{current}$). |
| **Remote Code Execution (RCE)**| Policy bundles are purely declarative JSON AST trees. Zero dynamic bytecode evaluation. |
| **User Privacy Violation** | Sensitive query parameters redacted; message text discarded; telemetry digests only. |

---

## 11. Verification & Testing Matrix

The mobile application is thoroughly verified by automated test suites matching cross-language test vectors:

| Test Class | Test Target | Verification Checkpoints | Status |
| :--- | :--- | :--- | :--- |
| `CanonicalJsonTest` | `CanonicalJson` | RFC 8785 lexicographical key ordering, compact formatting, signature exclusion | **PASSED** (2/2) |
| `DigestUtilTest` | `DigestUtil` | Standard SHA-256 digests, hex conversion | **PASSED** (2/2) |
| `Ed25519VerifierTest` | `Ed25519Verifier` | ASN.1 SubjectPublicKeyInfo DER decoding, detached Ed25519 signature checks | **PASSED** (3/3) |
| `URLNormalizerTest` | `URLNormalizer` | 9 cross-language vectors, credential stripping, dot segment collapsing, redaction | **PASSED** (9/9) |
| `HeuristicsAndRulesTest` | `Engine` | Brand mimicry, whitelist bypass, declarative AST rule evaluation (`eq`, `in`, `regex`)| **PASSED** (5/5) |
| `LocalThreatEngineTest` | `LocalThreatEngine` | Exact indicators, rule engine blocks, heuristic warnings, benign allow | **PASSED** (5/5) |
| `ShareLinkParserTest` | `ShareLinkParser` | Direct links, sentence extraction, punctuation trimming, bounded parsing | **PASSED** (6/6) |
| `ClientUpdateVerifierTest`| `UpdateVerifier` | 7-step pipeline: valid pass, unknown key, revoked key, tampered sig, anti-replay | **PASSED** (7/7) |
| **Total Test Suite** | **Mobile App** | **39 tests covering crypto, engine, updates, sharing, and models** | **100% GREEN** |

