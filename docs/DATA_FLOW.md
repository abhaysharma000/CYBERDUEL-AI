# CyberDuel AI — End-to-End Data Flow Architecture

## 1. Real-Time Detection Data Flow

```mermaid
flowchart TD
    User["User Navigation / URL Encountered"] --> Client["Edge Client (Browser / Mobile)"]
    Client --> LocalEngine{"Check Cached Policy"}
    
    LocalEngine -- "Known Benign / Whitelist" --> ActionAllow["Allow Navigation"]
    LocalEngine -- "Known Malicious / Blacklist" --> ActionBlock["Block & Display Warning"]
    LocalEngine -- "Indeterminate / Unseen Indicator" --> FallbackCheck{"Online & Opted In?"}
    
    FallbackCheck -- No --> ActionWarn["Present Caution Warning"]
    FallbackCheck -- Yes --> Hash["Compute Canonical SHA-256 Digest"]
    Hash --> CloudAPI["POST /api/v1/analysis/evaluate"]
    CloudAPI --> Classifier["AI Threat Classifier Service"]
    Classifier --> Verdict["ThreatAnalysisResult (Score, Decision, Evidence)"]
    Verdict --> Client
    Client --> Cache["Cache Verdict Locally"]
    Cache --> Enforce["Enforce Decision (Allow / Warn / Block)"]
```

---

## 2. Telemetry Ingestion & Laboratory Research Flow

```mermaid
flowchart TD
    Client["Edge Client"] -- "Observed Suspicious Indicator" --> TelemetryReport["ThreatObservationReport (Hashed Target, Meta)"]
    TelemetryReport --> Ingress["POST /api/v1/telemetry/observations"]
    Ingress --> DB[("PostgreSQL: threat_observations (Unverified)")]
    DB --> LabQueue["Redis Task Queue: lab_triage"]
    
    subgraph Lab["Isolated Research Laboratory"]
        LabQueue --> RedAI["Red AI Scenario Generator"]
        RedAI --> SynthScenario["Synthesize Harmless Test Scenarios"]
        SynthScenario --> BlueAI["Blue AI Defense Formulator"]
        BlueAI --> Candidate["Formulate CandidateDefense (New Rules / Weights)"]
        Candidate --> Evaluator["Independent Benchmark Evaluator"]
        Evaluator -- "Compare Against" --> Golden["Golden Benign & Regression Corpora"]
    end
    
    Evaluator -- "Passes Criteria" --> Approved["Promote to Approved Candidate"]
    Evaluator -- "Fails Criteria" --> Rejected["Record Failure Findings for Retraining"]
```

---

## 3. Cryptographic Policy Release & Distribution Flow

```mermaid
flowchart TD
    Approved["Approved Candidate"] --> Signer["Release Signer Service (HSM / KMS)"]
    Signer --> Manifest["PolicyReleaseManifest (Compiled Rules + Ed25519 Sig)"]
    Manifest --> ReleaseDB[("PostgreSQL: policy_releases")]
    
    EdgeClient["Edge Client Poll"] --> Check["POST /api/v1/updates/check"]
    Check --> ReleaseDB
    Check -- "New Version Available" --> ClientVerify["Client Downloads Manifest"]
    ClientVerify --> VerifySig{"Verify Ed25519 Signature"}
    
    VerifySig -- "Invalid" --> Rollback["Reject & Retain Prior Policy"]
    VerifySig -- "Valid" --> Apply["Atomic Policy Activation"]
    Apply --> Ack["POST /api/v1/updates/ack (Applied)"]
```

---

## 4. Explainable URL Analysis & Observation Flow (Phase 2)

```mermaid
flowchart TD
    Client["Client / User"] --> RawURL["Raw URL Target"]
    RawURL --> Validate["URLValidator (Scheme, Length, Structural Checks)"]
    Validate --> Normalize["URLNormalizer (IDN to Punycode, Port, Redact Secrets)"]
    
    Normalize --> Lookup["ThreatIntelRepository (Exact SHA-256 Match)"]
    Normalize --> Heuristics["URLHeuristicAnalyzer (11 Explainable Rules)"]
    Normalize --> FeatureExt["URLFeatureExtractor (18 Features)"]
    FeatureExt --> MLScore["LightweightLinearModel (Sigmoid ML Score)"]
    
    Lookup --> ScoringEngine["RiskScoringEngine (Soft Independence Saturation)"]
    Heuristics --> ScoringEngine
    MLScore --> ScoringEngine
    
    ScoringEngine --> Threshold{"Decision Thresholds\nallow: < 0.40\nwarn: 0.40 - 0.69\nblock: >= 0.70"}
    Threshold --> Result["ThreatAnalysisRecord (Persisted with UUID)"]
    Result --> Response["JSON Response with Full Evidence Chain"]
```

---

## 5. Red AI Adversarial Testing & Failure Handoff Flow (Phase 3)

```mermaid
flowchart TD
    Config["ExperimentConfig (Goal, Seed, Families, Count)"] --> Agent["RedResearchAgent"]
    Agent --> Gen["ScenarioGenerator (ThreatPatternLibrary + Seeding)"]
    Gen --> Mut["ScenarioMutationEngine (Safe Perturbations + Lineage)"]
    Mut --> Val["ScenarioValidator (Strict Safety & Bounds Check)"]
    
    Val --> ScenariosDB[("PostgreSQL: scenarios")]
    Val --> Runner["DefensiveTestRunner"]
    
    Runner --> AnalysisSvc["URLAnalysisService.analyze_url()"]
    AnalysisSvc --> ActualResult["Real Defensive Output (Score, Decision, Evidence)"]
    ActualResult --> ExecDB[("PostgreSQL: scenario_executions")]
    
    ActualResult --> Analyzer["FailureAnalyzer"]
    Analyzer --> Discrepancies{"Is Discrepancy?\n(FP, FN, Overly Aggressive, Underconfident)"}
    
    Discrepancies -- "Yes" --> Hypotheses["Synthesize FailureFindings (Structured Hypotheses)"]
    Discrepancies -- "No" --> Metrics["Compute Aggregate Defensive Metrics"]
    
    Hypotheses --> FindingsDB[("PostgreSQL: failure_findings")]
    Hypotheses --> HandoffPkg["EvaluationHandoffPackage"]
    Metrics --> Summary["ExperimentRunSummary"]
    
    HandoffPkg --> BlueAI["Blue AI & Independent Evaluator"]
```

---

## 6. Blue AI Autonomous Research & Candidate Submission Flow (Phase 4)

```mermaid
flowchart TD
    Handoff["EvaluationHandoffPackage (Red AI Findings & Scenarios)"] --> ResearchSvc["DefensiveResearchService"]
    ResearchSvc --> Cluster["Cluster Failure Findings by Category & Family"]
    Cluster --> TasksDB[("PostgreSQL: research_tasks")]
    
    Cluster --> Prioritize["DefensePrioritizationEngine\nScore = (Sev x Impact) + log(Count) - Penalty"]
    Prioritize --> TopGap["Top-Priority Failure Gap"]
    
    TopGap --> HypEngine["DefenseHypothesisEngine\n(URL Feature Invariance Analysis)"]
    HypEngine --> HypRecord[("PostgreSQL: defense_hypotheses")]
    
    HypEngine --> PropGen["DefenseProposalGenerator"]
    PropGen --> RuleEngine["DeclarativeRuleEngine.validate_rule()\n(Allowlist, ReDoS Bounds, AST Verification)"]
    RuleEngine --> PropRecord[("PostgreSQL: defense_proposals")]
    
    PropRecord --> CandBuilder["CandidateDefenseBuilder\n(Assembles rules + SHA-256 Digest)"]
    CandBuilder --> CandDB[("PostgreSQL: candidate_defenses")]
    
    CandBuilder --> Sandbox["CandidateDetectorSandbox / CandidateSandboxRunner"]
    Sandbox --> CompReport["BaselineComparisonReport\n(Fixed Failures, 0 Regressions, FPR <= 5%)"]
    CompReport --> CompDB[("PostgreSQL: sandbox_comparisons")]
    
    CompReport --> EvidenceSvc["DefenseEvidenceService\n(Compile Tamper-Evident Dossier + Fingerprint)"]
    
    EvidenceSvc --> HandoffSvc["EvaluationHandoffService"]
    HandoffSvc --> Evaluator["BenchmarkEvaluator (Independent Gatekeeper)"]
    
    Evaluator --> Verdict{"Evaluator Verdict\nPASS / FAIL"}
    Verdict -- "PASS" --> Approved["Candidate Status: APPROVED\n(Ready for Release Signer)"]
    Verdict -- "FAIL" --> Rejected["Candidate Status: REJECTED"]
    
    Verdict --> FeedbackSvc["LearningFeedbackService"]
    FeedbackSvc --> FeedbackDB[("PostgreSQL: candidate_feedbacks")]
    FeedbackDB -.-> Prioritize
```

---

## 7. Authoritative Research-to-Release Lifecycle & Client Verification Flow (Phase 10)

```mermaid
sequenceDiagram
    autonumber
    participant Red as Red AI Generator
    participant Scoring as Baseline Detector
    participant Blue as Blue AI Synthesizer
    participant Eval as Independent Evaluator
    participant Eligibility as Release Eligibility Service
    participant Signer as Release Signing Authority
    participant Verifier as Edge Client Verifier
    
    Red->>Scoring: Generate Synthetic Threat Scenario (e.g. homograph phishing)
    Scoring->>Blue: Detection gap identified (Threat allowed by baseline)
    Blue->>Blue: Synthesize declarative AST rule (RULE-PHISH-XXXX)
    Blue->>Eval: Submit Candidate Defense (rule_spec)
    Eval->>Eval: Execute benchmark audit (Zero Regressions, FPR <= 5%)
    Eval->>Eligibility: Verdict: PASS (Candidate eligible for release)
    Eligibility->>Signer: Explicit administrative authorization
    Signer->>Signer: Compile PolicyBundle, compute SHA-256 digest, Ed25519 sign
    Signer->>Verifier: Distribute ReleaseManifest + Bundle Bytes
    Verifier->>Verifier: 7-Step Verification (Trust anchor, Sig, Expiry, Monotonic seq, Platform, Digest)
    Verifier-->>Verifier: Atomic Activation & Tamper Defense
```





