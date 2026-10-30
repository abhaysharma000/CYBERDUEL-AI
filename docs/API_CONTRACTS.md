# CyberDuel AI — Canonical API Contracts Specification (v1)

## 1. Global Conventions

- **Base URL:** `/api/v1`
- **Content Type:** `application/json`
- **Correlation ID Header:** `X-Request-ID` (returned in every response for distributed tracing)
- **Execution Latency Header:** `X-Process-Time-Ms`
- **Error Response Envelope:** All errors return `StandardErrorResponse`

---

## 2. Health & System Endpoints

### 2.1 Liveness Probe
- **Method & Path:** `GET /health/live`
- **Description:** Verifies that the server process is responsive.
- **Success Status:** `200 OK`
- **Response Example:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "checks": {
    "process": "alive"
  },
  "timestamp": "2026-10-28T22:00:00Z"
}
```

### 2.2 Readiness Probe
- **Method & Path:** `GET /health/ready`
- **Description:** Verifies availability of required downstream dependencies (PostgreSQL, Redis).
- **Success Status:** `200 OK` (or `503 Service Unavailable` if database is down)
- **Response Example:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "checks": {
    "database": "reachable",
    "ai_provider": "configured (mock)"
  },
  "timestamp": "2026-10-28T22:00:00Z"
}
```

### 2.3 System Operational Status
- **Method & Path:** `GET /api/v1/system/status`
- **Description:** Returns operational state, runtime AI provider, and active platform capabilities.
- **Success Status:** `200 OK`
- **Response Example:**
```json
{
  "app_name": "CyberDuel AI",
  "version": "0.1.0",
  "environment": "development",
  "status": "operational",
  "ai_provider_mode": "mock",
  "active_capabilities": [
    "threat_classification",
    "privacy_preserving_telemetry",
    "declarative_policy_distribution",
    "sandboxed_laboratory_scenarios",
    "adversarial_lab_worker"
  ],
  "timestamp": "2026-10-28T22:00:00Z"
}
```

---

## 3. Threat Analysis & Evaluation Endpoints

### 3.1 Resource Evaluation
- **Method & Path:** `POST /api/v1/analysis/evaluate`
- **Request Headers:**
  - `Content-Type: application/json`
  - `X-Client-ID: <anonymous-client-uuid>`
- **Request Payload (`ResourceAnalysisRequest`):**
```json
{
  "normalized_identifier": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "resource_url": "https://secure-login.suspicious-phish.com",
  "resource_type": "url",
  "client_id": "client-uuid-101",
  "client_version": "0.1.0",
  "context": {
    "source_protocol": "https",
    "top_level_domain": "com"
  }
}
```

- **Response Payload (`ThreatAnalysisResult`):**
```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "normalized_identifier": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "threat_score": 0.92,
  "decision": "block",
  "evidence": [
    {
      "category": "reputation",
      "reason": "Target indicator matched synthetic malicious signature blacklist",
      "severity": "critical",
      "confidence": 0.98
    }
  ],
  "engine_version": "0.1.0-mock",
  "policy_version": "2026.10.1",
  "confidence": 0.95,
  "provenance": "model_inference",
  "created_at": "2026-10-28T22:00:00Z",
  "expires_at": null
}
```

---

## 4. Telemetry Endpoints

### 4.1 Ingest Edge Observation
- **Method & Path:** `POST /api/v1/telemetry/observations`
- **Status:** `202 Accepted`
- **Request Payload (`ThreatObservationReport`):**
```json
{
  "observation_id": "a3bb189e-8bf9-3888-9912-ace4e6543000",
  "source": "browser_extension",
  "normalized_target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "observed_at": "2026-10-28T22:00:00Z",
  "local_action_taken": "warn",
  "engine_version": "0.1.0",
  "policy_version": "2026.10.1",
  "telemetry_summary": {
    "has_idna_homograph": true,
    "levenshtein_distance_from_popular_brand": 1
  }
}
```

---

## 5. Policy Updates Endpoints

### 5.1 Check for Updates
- **Method & Path:** `POST /api/v1/updates/check`
- **Request Payload (`UpdateCheckRequest`):**
```json
{
  "client_id": "client-uuid-101",
  "client_type": "browser_extension",
  "current_policy_version": "2026.09.1",
  "engine_version": "0.1.0",
  "platform": "Chrome-130"
}
```
- **Response Payload (`UpdateCheckResponse`):**
```json
{
  "update_available": true,
  "target_version": "2026.10.1",
  "manifest_url": "/api/v1/updates/manifests/2026.10.1",
  "rules_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature": "mock_ed25519_signed_manifest_payload_signature_hash_data",
  "mandatory": false
}
```

### 5.2 Acknowledge Update Application
- **Method & Path:** `POST /api/v1/updates/ack`
- **Request Payload (`UpdateAcknowledgement`):**
```json
{
  "acknowledgement_id": "b1b2b3b4-1234-5678-9abc-def012345678",
  "client_id": "client-uuid-101",
  "policy_version": "2026.10.1",
  "status": "applied",
  "error_message": null,
  "applied_at": "2026-10-28T22:05:00Z"
}
```

---

## 6. Threat Analysis & Detection Endpoints (Phase 2)

### 6.1 Analyze URL
- **Method & Path:** `POST /api/v1/analyze/url`
- **Description:** Normalizes input URL, runs threat intelligence lookup, evaluates 11 heuristic rules, extracts features, and calculates an explainable risk score using soft independence saturation.
- **Request Payload (`URLAnalysisRequest`):**
```json
{
  "url": "https://paypal.com@secure-login-account-update.attacker-domain.com:8080/signin?session=xyz",
  "include_heuristics": true,
  "include_ml": true,
  "metadata": {
    "client_platform": "browser_extension",
    "correlation_id": "ext-test-101"
  }
}
```
- **Response Payload (`URLAnalysisResponse`):**
```json
{
  "analysis_id": "48995543-5772-4682-bb3a-a5f1a5ba8575",
  "url": "https://secure-login-account-update.attacker-domain.com:8080/signin?session=xyz",
  "normalized_url": "https://secure-login-account-update.attacker-domain.com:8080/signin?session=xyz",
  "threat_score": 0.98,
  "decision": "block",
  "confidence": 0.95,
  "evidence": [
    {
      "category": "authority_spoof",
      "reason": "URL authority section contains embedded userinfo credentials ('paypal.com@')",
      "severity": "critical",
      "confidence": 0.98
    },
    {
      "category": "brand_impersonation",
      "reason": "Target hostname embeds high-value brand token 'paypal'",
      "severity": "high",
      "confidence": 0.92
    }
  ],
  "engine_version": "0.2.0-heuristic",
  "policy_version": "2026.10.2",
  "provenance": "heuristic_rule",
  "explanation": "Blocked: Critical threat indicators detected (Score: 0.98).",
  "created_at": "2026-10-28T23:00:00Z"
}
```

### 6.2 Retrieve Past Analysis
- **Method & Path:** `GET /api/v1/analyze/{analysis_id}`
- **Description:** Retrieves persistent threat analysis record by UUID.
- **Response Payload:** `URLAnalysisResponse` (or HTTP 404 `StandardErrorResponse` if non-existent).

---

## 7. Threat Intelligence & Policy Management Endpoints (Phase 2)

### 7.1 Threat Intelligence Engine Status
- **Method & Path:** `GET /api/v1/intelligence/status`
- **Response Payload:**
```json
{
  "status": "healthy",
  "indicator_count": 142,
  "last_updated": "2026-10-28T23:00:00Z",
  "engine_version": "0.2.0-heuristic",
  "policy_version": "2026.10.2",
  "active_rules_count": 11
}
```

### 7.2 Ingest Threat Intelligence Indicators
- **Method & Path:** `POST /api/v1/intelligence/import`
- **Headers:** `X-Admin-Key` (in production)
- **Request Payload:**
```json
{
  "indicators": [
    {
      "type": "domain",
      "value": "malicious-phish-domain.xyz",
      "classification": "phishing",
      "source": "curated_feed",
      "severity": "high"
    }
  ]
}
```

### 7.3 Submit Privacy-Conscious Threat Report
- **Method & Path:** `POST /api/v1/threat-reports`
- **Request Payload:**
```json
{
  "url": "http://192.168.1.1:8080/login?pwd=secretpassword",
  "local_action_taken": "warn",
  "telemetry": {
    "ip_host": true,
    "non_standard_port": true
  }
}
```
- **Response Payload:**
```json
{
  "status": "received",
  "observation_id": "58e13d9f-d31e-42c2-8495-eebe1e3fe1a7",
  "target_digest": "4a71d79868962...sha256",
  "duplicate": false
}
```

### 7.4 Export Active Protection Policy Bundle
- **Method & Path:** `GET /api/v1/policy/export`
- **Description:** Generates an integrity-hashed declarative policy bundle for edge caching by browser extensions and mobile apps.
- **Response Payload:**
```json
{
  "version": "2026.10.2",
  "generated_at": "2026-10-28T23:00:00Z",
  "heuristics": [
    {
      "rule_id": "HR-HOMOGLYPH-01",
      "category": "homoglyph",
      "weight": 0.85,
      "severity": "high",
      "description": "IDN Punycode host contains confusable homoglyphs mimicking target brand."
    }
  ],
  "thresholds": {
    "warn": 0.4,
    "block": 0.7
  },
  "whitelist_domains": ["google.com", "microsoft.com", "apple.com", "github.com"],
  "integrity_digest": "f295b99f30b9bb85973e8e2fa5342d3d0f0c0ee422cbff4e650c8227bda25f54"
}
```

---

## 8. Research Laboratory Endpoints (Phase 3)

### 8.1 Discover Laboratory Status
- **Method & Path:** `GET /api/v1/lab/status`
- **Description:** Returns laboratory execution status, active experiment counts, sandbox constraints, and supported scenario families.
- **Response Payload (`LabStatusResponse`):**
```json
{
  "status": "healthy",
  "active_experiments": 0,
  "completed_experiments": 3,
  "total_scenarios_cataloged": 100,
  "sandboxed": true,
  "external_network_blocked": true,
  "worker_version": "0.1.0",
  "supported_families": [
    "authority_spoofing",
    "benign_lookalike",
    "brand_impersonation",
    "dga_entropy",
    "double_encoding",
    "homograph_mimicry",
    "ip_host",
    "length_anomaly",
    "normalization_edge_case",
    "phishing_keywords",
    "stale_intelligence",
    "subdomain_flooding",
    "suspicious_port",
    "whitelist_control"
  ]
}
```

### 8.2 Generate Synthetic Scenarios Batch
- **Method & Path:** `POST /api/v1/lab/scenarios/generate`
- **Request Payload (`ScenarioGenerationRequest`):**
```json
{
  "goal": "Test Cyrillic Homoglyphs and Benign Controls",
  "count": 10,
  "families": ["homograph_mimicry", "benign_lookalike"],
  "mutation_depth": 1,
  "seed": 42
}
```
- **Response Payload:** List of `ScenarioContract` objects.

### 8.3 Execute Adversarial Experiment
- **Method & Path:** `POST /api/v1/lab/experiments`
- **Request Payload (`ExperimentConfig`):**
```json
{
  "experiment_name": "Adversarial Homoglyphs and Benign Controls",
  "goal": "Evaluate defensive detection rate on homoglyph attacks and measure false positives",
  "scenario_count": 50,
  "seed": 42,
  "selected_families": [],
  "mutation_depth": 1,
  "fail_on_first_error": false,
  "timeout_seconds": 300,
  "created_by": "RedAI-Agent"
}
```
- **Response Payload (`ExperimentRunSummary`):**
```json
{
  "experiment_id": "94affe62-cd66-4693-9127-ef0f82f097df",
  "experiment_name": "Adversarial Homoglyphs and Benign Controls",
  "goal": "Evaluate defensive detection rate on homoglyph attacks and measure false positives",
  "status": "completed",
  "seed": 42,
  "scenario_count": 50,
  "executed_count": 50,
  "discrepancy_count": 15,
  "metrics": {
    "total_scenarios": 50,
    "evaluable_scenarios": 48,
    "true_positives": 33,
    "false_positives": 3,
    "true_negatives": 12,
    "false_negatives": 0,
    "accuracy": 0.9375,
    "precision": 0.9167,
    "recall": 1.0,
    "f1": 0.9565,
    "false_positive_rate": 0.20,
    "average_latency_ms": 0.17
  },
  "family_breakdown": {
    "homograph_mimicry": { "total": 4, "discrepancies": 1, "accuracy": 0.75 },
    "benign_lookalike": { "total": 4, "discrepancies": 2, "accuracy": 0.50 }
  },
  "detector_version": "0.2.0-heuristic-intel",
  "policy_version": "2026.10.1",
  "started_at": "2026-10-28T23:50:50Z",
  "completed_at": "2026-10-28T23:50:52Z",
  "findings": [
    {
      "finding_id": "c1a2b3c4-1234-5678-9abc-def012345678",
      "experiment_id": "94affe62-cd66-4693-9127-ef0f82f097df",
      "failure_category": "over_detection",
      "discrepancy_type": "false_positive",
      "hypothesis": "Hypothesis: Over-detection in family 'benign_lookalike'. Legitimate controls containing benign tokens were penalized beyond acceptable threshold.",
      "affected_scenarios_count": 2,
      "representative_scenario_ids": ["81a2b3c4-..."],
      "suggested_remedy": "Calibrate heuristic rules associated with 'benign_lookalike' to require compounding evidence.",
      "severity": "high"
    }
  ]
}
```

### 8.4 Retrieve Scenario Execution Results
- **Method & Path:** `GET /api/v1/lab/experiments/{experiment_id}/results`
- **Response Payload:** List of `ScenarioExecutionResult` objects.

### 8.5 Laboratory Aggregate Metrics
- **Method & Path:** `GET /api/v1/lab/metrics`
- **Response Payload (`LabMetricsResponse`):** Macro-averaged detection and discrepancy metrics across all completed experiments.

---

## 9. Blue AI Defense Engine Endpoints

### 9.1 Blue AI Operational Status
- **Method & Path:** `GET /api/v1/blue/status`
- **Success Status:** `200 OK`
- **Response Schema:** `BlueStatusResponse`
- **Response Example:**
```json
{
  "status": "ready",
  "active_research_tasks": 1,
  "total_candidates_built": 4,
  "accepted_candidates": 3,
  "rejected_candidates": 1,
  "candidate_acceptance_rate": 0.75,
  "available_proposal_types": ["declarative_rule", "threshold_tuning"]
}
```

### 9.2 Initiate Research Task
- **Method & Path:** `POST /api/v1/blue/research`
- **Success Status:** `201 Created`
- **Request Schema:** `ResearchInitiateRequest` (either `handoff_package` or `experiment_id`)
- **Response Example:**
```json
{
  "task_id": "42ff5be6-30f6-442d-993e-e079a0673355",
  "name": "ResearchTask-Exp-94affe62",
  "status": "active",
  "findings_count": 2,
  "top_priority": "Target homoglyph_spoofing"
}
```

### 9.3 Retrieve Research Task
- **Method & Path:** `GET /api/v1/blue/research/{task_id}`
- **Success Status:** `200 OK`
- **Response:** Research task details, ranked failure groups, and synthesized hypotheses.

### 9.4 List Prioritized Failure Groups
- **Method & Path:** `GET /api/v1/blue/failure-groups`
- **Success Status:** `200 OK`
- **Response:** Ranked array of failure clusters across recent research tasks.

### 9.5 Synthesize Candidate Defense & Run Sandbox
- **Method & Path:** `POST /api/v1/blue/candidates`
- **Success Status:** `201 Created`
- **Request Schema:** `CandidateCreateRequest` (`task_id`, `failure_category`, `proposal_type`, `auto_sandbox`)
- **Response Schema:** `CandidateBuildResponse` (candidate, hypothesis, proposal, comparison report, evidence fingerprint).

### 9.6 Retrieve Candidate Defense
- **Method & Path:** `GET /api/v1/blue/candidates/{candidate_id}`
- **Success Status:** `200 OK`
- **Response Schema:** `CandidateDefense`

### 9.7 Retrieve Candidate Sandbox Comparison Report
- **Method & Path:** `GET /api/v1/blue/candidates/{candidate_id}/comparison`
- **Success Status:** `200 OK`
- **Response Schema:** `BaselineComparisonReport`

### 9.8 Submit Candidate Defense to Independent Evaluation
- **Method & Path:** `POST /api/v1/blue/candidates/{candidate_id}/evaluate`
- **Success Status:** `200 OK`
- **Request Schema:** `CandidateEvaluateRequest` (`suite_id`)
- **Response Schema:** `CandidateEvaluateResponse` (`evaluation`, `feedback`, `updated_candidate_status`)

### 9.9 Retrieve Candidate History Audit Trail
- **Method & Path:** `GET /api/v1/blue/history`
- **Success Status:** `200 OK`
- **Response:** Array of historical candidate defenses, author agents, statuses, and creation timestamps.

---

## 10. Release Management & Cryptographic Updates

### 10.1 Check for Available Updates
- **Method & Path:** `POST /api/v1/updates/check`
- **Request Schema:** `UpdateCheckRequest` (`client_id`, `client_version`, `engine_version`, `current_policy_version`, `current_sequence_number`, `channel`, `platform`)
- **Response Schema:** `UpdateCheckResponse` (`update_available`, `latest_version`, `latest_sequence_number`, `manifest_url`, `is_mandatory`, `is_rollback`, `rollback_target_version`, `checked_at`)

### 10.2 Retrieve Signed Release Manifest
- **Method & Path:** `GET /api/v1/updates/manifests/{version_or_id}`
- **Success Status:** `200 OK`
- **Response Schema:** `ReleaseManifest` (canonical RFC 8785 metadata, detached Ed25519 signature, artifact digest, publisher key ID)

### 10.3 Download Immutable Policy Bundle Artifact
- **Method & Path:** `GET /api/v1/updates/artifacts/{digest}`
- **Path Parameter:** `digest` (String, required): Exactly 64 hexadecimal characters (`pattern=r"^[a-fA-F0-9]{64}$"`). Rejects invalid format or path traversal attempts (`../`) with `422 Unprocessable Entity`.
- **Success Status:** `200 OK`
- **Headers:** `Content-Type: application/json`, `ETag: "{digest}"`, `Cache-Control: public, max-age=31536000, immutable`
- **Response:** Raw UTF-8 bytes of canonical JSON `LocalProtectionPolicyBundle`

### 10.4 Acknowledge Update Installation Outcome
- **Method & Path:** `POST /api/v1/updates/ack`
- **Request Schema:** `UpdateAcknowledgement` (`acknowledgement_id`, `client_id`, `release_id`, `policy_version`, `sequence_number`, `status`, `error_message`, `is_rollback_applied`, `channel`, `reported_at`)
- **Success Status:** `200 OK`

### 10.5 Retrieve Public Trust Anchors
- **Method & Path:** `GET /api/v1/updates/trust-anchors`
- **Success Status:** `200 OK`
- **Response Schema:** `TrustAnchorSet` (`active_keys`, `revoked_keys`, `timestamp`)

---

## 11. Browser Extension Internal Runtime Protocol

Communication between Extension Content Scripts, Action Popup, Options Portal, and Background Service Worker uses strictly typed message contracts:

| Message Type | Direction | Payload Contract | Description |
| :--- | :--- | :--- | :--- |
| `EVALUATE_URL_REQUEST` | CS/Popup $\to$ SW | `{ url: string, source: string }` | Requests synchronous local URL threat evaluation against cached policy. |
| `EVALUATE_URL_RESPONSE` | SW $\to$ CS/Popup | `{ url: string, result: LocalThreatResult }` | Returns decision (`allow`, `warn`, `block`), risk score, explanation, evidence, provenance. |
| `GET_PROTECTION_STATUS_REQUEST` | Popup/Options $\to$ SW | `{}` | Requests current engine status, active DNR rule count, stale state, and sync status. |
| `TRIGGER_UPDATE_CHECK_REQUEST` | Popup/Options $\to$ SW | `{}` | Triggers immediate 7-step update check cycle with release authority. |
| `GET_SETTINGS_REQUEST` / `UPDATE_SETTINGS_REQUEST` | Options $\to$ SW | `{ settings: Partial<ExtensionSettings> }` | Retrieves or mutates privacy, channel, and telemetry settings. |
| `SUBMIT_FALSE_POSITIVE_REQUEST` | Warning $\to$ SW | `{ targetUrl: string, reportedDecision: string, reason: string }` | Dispatches false positive report to `/api/v1/telemetry/observations`. |
| `CREATE_CONTINUATION_TOKEN_REQUEST` | Warning $\to$ SW | `{ targetUrl: string }` | Generates a single-use 60-second continuation token tied strictly to target SHA-256. |
| `VALIDATE_CONTINUATION_TOKEN_REQUEST` | Warning $\to$ SW | `{ token: string, targetUrl: string }` | Validates and consumes the continuation token for warning override. |
| `RESET_FACTORY_POLICY_REQUEST` | Options $\to$ SW | `{}` | Reverts local policy to factory bootstrap version (2026.10.1, Seq 1) and reinstalls DNR rules. |

---

## 12. Command Center & Operator Management APIs

### 12.1 Operator Authentication & Profile
- **Method & Path:** `POST /api/v1/auth/login`
- **Request:** `{ "username": "string", "password": "string" }`
- **Response:** `{ "token": "string", "token_type": "Bearer", "expires_in_seconds": 86400, "user": UserProfile }`

- **Method & Path:** `GET /api/v1/auth/me`
- **Headers:** `Authorization: Bearer <token>`
- **Response:** `UserProfile` (`username`, `display_name`, `role`, `permissions`, `email`)

- **Method & Path:** `GET /api/v1/auth/operators`
- **Response:** `list[OperatorOption]` (preconfigured personas for development & testing)

### 12.2 Consolidated Dashboard Overview
- **Method & Path:** `GET /api/v1/dashboard/overview`
- **Headers:** `Authorization: Bearer <token>`
- **Response:** `DashboardOverviewResponse` (consolidated aggregation of `health`, `research`, `defense`, `evaluations`, `releases`, `clients`, and `recent_events`)

### 12.3 Client Fleet Telemetry
- **Method & Path:** `GET /api/v1/clients`
- **Query Params:** `client_type`, `channel`, `policy_version`, `limit`, `offset`
- **Response:** `list[ClientSummary]` (device identifiers, platform, versions, cohort buckets, last seen, status)

- **Method & Path:** `GET /api/v1/clients/metrics`
- **Response:** `ClientMetrics` (`total_registered`, `active_last_24h`, `by_type`, `by_channel`, `by_policy_version`, `acknowledgements_breakdown`)

- **Method & Path:** `GET /api/v1/clients/{client_id}`
- **Response:** Detailed device status and chronological acknowledgement records.

### 12.4 Immutable Security Audit Log
- **Method & Path:** `GET /api/v1/audit/events`
- **Query Params:** `actor`, `action`, `target_type`, `outcome`, `limit`, `offset`
- **Response:** `AuditQueryResponse` (`events`: `list[AuditEventResponse]`, `total`, `limit`, `offset`)






