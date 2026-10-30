# CyberDuel AI — Complete AI Architecture & Provider Audit

**Audit Date:** October 2026  
**Auditor:** Principal AI & Security Systems Engineer  
**Document Purpose:** Authoritative, unvarnished baseline audit of all AI-provider paths, deterministic components, mock implementations, and training pipelines across the CyberDuel AI monorepo.

---

## 1. Executive Summary

A comprehensive line-by-line inspection of the CyberDuel AI codebase reveals that **no real-time neural network or Large Language Model (LLM) inference is currently operational in the default configuration**.

All automated workflows previously demonstrated (adversarial scenario generation, heuristic evaluation, and candidate rule formulation) have been executed by **deterministic algorithms, procedural string templates, or offline mock providers**.

While the deterministic security components (URL normalizer, heuristic detection rules, risk scoring saturation engine, independent benchmark evaluator, and Ed25519 cryptographic release signer) are genuine, robust, and production-grade, the AI-agent reasoning layer relies on `DeterministicMockProvider` and procedural code.

---

## 2. Component-by-Component Classification

Every subsystem and file touching threat intelligence, scenario generation, rule formulation, evaluation, and release management has been audited and classified into one of four strict categories:

1. **Production implementation:** Real, robust, production-ready code with no mock stand-ins.
2. **Development-only mock:** Synthetic, hardcoded, or canned mock classes intended strictly for offline unit testing.
3. **Deterministic non-LLM component:** Purely algorithmic, mathematical, or procedural security controls that do not and should not rely on an LLM.
4. **Missing or unverified functionality:** Planned capabilities (such as model fine-tuning, training scripts, or real inference endpoints) that do not yet exist.

### 2.1 Audit Matrix

| Subsystem / Path | Primary Files | Classification | Reality of Implementation |
| :--- | :--- | :--- | :--- |
| **AI Provider Factory** | `apps/api/app/providers/factory.py` | **Production implementation** | Supports `AI_PROVIDER_TYPE="qwen"` and strictly rejects mock provider in production mode (`ENVIRONMENT="production"`). |
| **AI Provider Base Interfaces** | `apps/api/app/providers/base.py` | **Production implementation** | Abstract base classes (`BaseReasoningProvider`, `BaseThreatClassificationProvider`, `BaseScenarioGeneratorProvider`, `BaseEvaluationProvider`). |
| **Qwen AI Provider** | `apps/api/app/providers/qwen_provider.py` | **Production implementation** | OpenAI-compatible Qwen client with strict JSON schema validation, fail-closed typed errors, connectivity probe, and AST rule synthesis. |
| **Mock Provider Implementation** | `apps/api/app/providers/mock_provider.py` | **Development-only mock** | Hardcoded canned JSON responses returning static scores and descriptions tagged `0.1.0-mock`. Forbidden in production. |
| **URL Threat Normalizer** | `packages/threat-intelligence/cyberduel_threat_intel/normalizer.py` | **Deterministic non-LLM component** | RFC 3986 URL parsing, IDN punycode resolution, port stripping, and credential redaction (`[REDACTED]`). |
| **Deterministic Heuristic Rules** | `packages/threat-intelligence/cyberduel_threat_intel/heuristics/` | **Deterministic non-LLM component** | 11 deterministic detection rules (Shannon entropy, homoglyph mimicry, brand keywords, raw IP hosts, suspicious TLDs). |
| **Risk Scoring Engine** | `packages/threat-intelligence/cyberduel_threat_intel/heuristics/scoring.py` | **Deterministic non-LLM component** | Non-linear soft-independence saturation scoring: $S = 1 - \prod (1 - w_i \cdot c_i)$. Pure mathematics. |
| **Red AI Scenario Generation** | `services/lab-worker/app/red_ai/generator.py` | **Production implementation (Qwen-Integrated)** | Async Qwen generator synthesizing safe RFC 2606 scenarios (`.test`, `.example`). Procedural generator preserved as explicit fallback. Fails closed in production. |
| **Red AI Mutation Engine** | `services/lab-worker/app/red_ai/mutator.py` | **Deterministic non-LLM component** | Bounded string transformation rules (homoglyph substitution, subdomain prepending) preserving RFC 2606 safety with lineage tracking. |
| **Blue AI Hypothesis Engine** | `apps/api/app/services/blue_ai/hypothesis.py` | **Production implementation (Qwen-Integrated)** | Async Qwen reasoning over failure clusters to formulate structured `DefensiveHypothesis` and AST predicates. Procedural heuristic mode preserved. Fails closed in production. |
| **Blue AI Proposal Generator** | `apps/api/app/services/blue_ai/proposals.py` | **Production implementation (AST-Validated)** | Synthesizes `DeclarativeRuleModel` and strictly enforces `DeclarativeRuleEngine.validate_rule()`. Rejects unallowlisted fields, operators, or ReDoS regexes. |
| **Independent Benchmark Evaluator**| `services/evaluator/app/benchmark_runner.py` | **Deterministic non-LLM component** | Statistical confusion matrix calculator (Accuracy, Recall, FPR, F1) testing AST rules against golden manifests. **No LLM used.** |
| **Cryptographic Release Signer** | `apps/api/app/services/releases/signing.py` | **Production implementation** | Pure Ed25519 signature generation and RFC 8785 canonical JSON formatting. |
| **Client Release Verifier** | `packages/policy-engine/cyberduel_policy_engine/verifier.py` | **Production implementation** | 7-step cryptographic verification (signature, digest, monotonic sequence, schema validation). |
| **Model Fine-Tuning Recipe** | `scripts/train_qwen_lora.py` | **Production implementation (Dry-run verified)** | PEFT/LoRA training recipe (`qwen_lora_config.yaml`) with ChatML validation and held-out test isolation. Actual training not yet run. |
| **Security Training Dataset Pipeline** | `scripts/dataset_pipeline.py` | **Production implementation** | Ingests ISCX-URL2016 and OpenPhish feeds into domain-grouped splits (60/20/20) with SHA-256 manifests. |
| **Task SFT Generator** | `scripts/generate_agent_tasks.py` | **Production implementation** | Formats training splits into ChatML SFT datasets for classification, Blue AI, and Red AI. Strictly isolates test data. |
| **Health Probe (`/health/ready`)**| `apps/api/app/api/router.py` | **Production implementation** | Truthfully reports AI status (`connected: qwen (<model>)` or `configured: qwen (<model>), endpoint unreachable` or mock). |
| **Operations Dashboard** | `apps/dashboard/src/` | **Production implementation** | React 18 SPA rendering backend data. Empty states occurred because `cyberduel_dev.db` had no seeded records. |

---

## 3. Detailed Findings on Simulated AI Logic

### 3.1 Red AI Adversarial Testing
In `services/lab-worker/app/red_ai/generator.py`:
- Red AI does not query a language model to "think like an attacker."
- Instead, it selects from a dictionary of 14 hardcoded pattern families (e.g. `homoglyph_mimicry`, `credential_harvesting_path`, `subdomain_flooding`) and populates random strings using Python's `random.Random(seed)`.
- **Verdict:** Safe and reproducible, but purely procedural. A real Qwen model can enhance Red AI by generating complex, realistic, multi-layered phishing lures and novel evasion techniques while remaining constrained to safe test domains.

### 3.2 Blue AI Defense Proposal
In `apps/api/app/services/blue_ai/hypothesis.py` and `proposals.py`:
- Blue AI does not query a language model to "reason about defensive architecture."
- Instead, it inspects failing URLs, counts common TLDs or substring matches, and emits a standard `DeclarativeRuleModel` with an equality predicate (e.g. `domain_suffix == "bank-sec-verify-2026.example.test"`).
- **Verdict:** Highly deterministic and safe, but lacks broad pattern generalization. A real Qwen model can act as the defense intelligence engine, formulating nuanced regex patterns and multi-attribute predicates from threat clusters.

### 3.3 The Role of the Independent Evaluator
- **Critical Architectural Boundary:** The Independent Evaluator (`services/evaluator`) does NOT use an LLM, nor should it ever use one.
- The evaluator's mission is to execute candidate rules against held-out benchmark splits and calculate mathematical pass/fail metrics (zero false positive regressions, accuracy >= 95%).
- **Invariant:** An LLM must NEVER grade or validate its own defensive rules. Model outputs must be treated as unverified candidate proposals until approved by the deterministic evaluator.

---

## 4. Remediation Plan

1. **Implement `QwenProvider`:** Create an OpenAI-compatible client abstraction targeting open-source Qwen 2.5 models (e.g., `Qwen/Qwen2.5-Coder-7B-Instruct`).
2. **Fail-Closed Semantics:** Eliminate silent fallbacks to `DeterministicMockProvider` in production or staging configurations. If Qwen inference fails, errors must be explicitly surfaced.
3. **Dataset Ingestion:** Ingest a documented open dataset (e.g., Kaggle/ISCXURL2016) with strict 60/20/20 train/validation/test splits.
4. **Reproducible LoRA Training:** Provide reproducible training recipes (`scripts/train_qwen_lora.py`) evaluated against the held-out split.

