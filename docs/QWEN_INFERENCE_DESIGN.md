# CyberDuel AI — Real-Qwen Model & Inference Deployment Design

**Design Date:** October 2026  
**Status:** Approved Architecture Specification  
**Model Family:** Alibaba Cloud Qwen 2.5 Open-Source Series  
**Target Roles:** Red AI (Scenario Generation) & Blue AI (Defensive Rule Synthesis)  

---

## 1. Concrete Model Selection

### Recommended Model: **`Qwen/Qwen2.5-Coder-7B-Instruct`** (or `Qwen/Qwen2.5-7B-Instruct`)

#### Technical Rationale:
1. **Permissive Open-Source License:** Apache 2.0 license permits open defensive cybersecurity research, modification, and commercial deployment without restrictive usage riders.
2. **Superior Structured JSON & Code Synthesis:** Qwen 2.5 Coder is explicitly fine-tuned on code, AST syntax, and structured reasoning. It outperforms general-purpose models on outputting strict, valid Pydantic JSON schemas and regular expressions required for declarative rules.
3. **Context Length vs. Latency:** Supports up to 32k/128k context. For CyberDuel AI, prompts are tightly bounded to $\le 4,096$ tokens, yielding generation latencies of $<1.5$ seconds per cycle on standard GPU endpoints.
4. **Parameter Size Balance:** At 7B parameters, the model provides deep cybersecurity reasoning while maintaining cost efficiency and low memory overhead compared to 14B or 72B models.

---

## 2. Infrastructure & Deployment Topology

### 2.1 The Railway Constraint Reality
- Railway standard containers provide up to 8 GB RAM and 4–8 vCPUs with **NO GPU hardware**.
- Loading a 7B parameter model in FP16 requires ~15 GB VRAM. Even a 4-bit quantized GGUF/AWQ model requires ~5–6 GB RAM and would run at ~2–4 tokens/sec on shared CPU, causing request timeouts (>45s) and memory crashes (OOM).
- **Rule:** Do NOT attempt to load Qwen weights into the Railway `cyberduel-api` or `cyberduel-worker` container processes.

### 2.2 Dual-Route Inference Architecture

```
                                  ┌──────────────────────────────────────────────┐
                                  │            CyberDuel AI Monorepo             │
                                  │                                              │
                                  │  ┌────────────────┐      ┌────────────────┐  │
                                  │  │     RED AI     │      │    BLUE AI     │  │
                                  │  │ Scenario Agent │      │ Defense Agent  │  │
                                  │  └───────┬────────┘      └────────┬───────┘  │
                                  └──────────┼────────────────────────┼──────────┘
                                             │                        │
                                             ▼                        ▼
                                ┌───────────────────────────────────────────┐
                                │               QwenProvider                │
                                │  - Enforces Strict JSON Schemas           │
                                │  - Hard Timeout (15s) & Rate-Limit Retries│
                                │  - Fails Closed (No silent mock fallback) │
                                └─────────────────────┬─────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
         [Production / Staging / CI]                                   [Local Air-Gapped Dev]
        Hosted Qwen-Compatible API                                    Local vLLM or Ollama Server
    (e.g., DeepInfra / Together / vLLM)                            `http://localhost:11434/v1`
 - Low latency GPU inference (<1.2s)                          - Zero external network dependency
 - Standard OpenAI-compatible `/v1/chat/completions`          - Runs quantized Qwen 2.5 7B locally
```

#### Route A: Hosted OpenAI-Compatible Inference Endpoint (Production & Staging)
- **Target Provider:** Hosted serverless API supporting open-source Qwen (e.g. DeepInfra, Together AI, or a private vLLM instance on RunPod/AWS).
- **Cost:** ~$0.10 to $0.20 per million tokens (extremely cost-effective; $< \$1.00 for thousands of research cycles).
- **Protocol:** Standard OpenAI-compatible HTTP POST `/v1/chat/completions`.

#### Route B: Local Self-Hosted Endpoint (Air-Gapped Local Development)
- **Engine:** Ollama (`ollama run qwen2.5-coder:7b`) or local vLLM.
- **Base URL:** `http://localhost:11434/v1` (Ollama) or `http://localhost:8000/v1` (vLLM).
- **Compatibility:** Uses the exact same `QwenProvider` code with zero changes, simply toggling `QWEN_API_BASE`.

---

## 3. Provider Contract & Security Boundaries

### 3.1 Strict Fail-Closed Semantics
- In production (`ENVIRONMENT="production"`) or staging (`ENVIRONMENT="staging"`), if the Qwen endpoint is unreachable, times out, or exceeds rate limits, the system **FAILS CLOSED**.
- It raises `ProviderUnavailableError` or `ProviderRateLimitError`.
- It **NEVER** silently falls back to `DeterministicMockProvider`. Faking an AI response in a security context is strictly prohibited.

### 3.2 Structured Output Schema Enforcement
Prompts to Qwen enforce structured JSON outputs corresponding to canonical Pydantic schemas:
- **Red AI:** Emits `ScenarioContract` with fields: `scenario_id`, `url`, `threat_family`, `attack_type`, `evasion_techniques`, `synthetic_payload`.
- **Blue AI:** Emits `DeclarativeRuleModel` with fields: `rule_id`, `target_family`, `predicates`, `action`, `severity`, `weight`.

Any response that fails JSON decoding or Pydantic validation is immediately rejected with `ProviderInferenceError`.

### 3.4 Live Endpoint Connectivity & Truthful Health Probes
The `QwenProvider` includes a truthful endpoint health probe:
- `check_endpoint_connectivity(timeout_seconds=3.0) -> tuple[bool, str, dict]`:
  Queries the endpoint's `/models` resource without issuing billing generation requests.
- The backend `/health/ready` probe reports:
  - `"connected: qwen (<model>)"` if the probe succeeds.
  - `"configured: qwen (<model>), endpoint unreachable"` if the endpoint is not responding, without crashing the server.
- If no credentials or local daemon are available, status is reported truthfully as `LIVE INFERENCE BLOCKED`.

### 3.5 Blue AI AST Rule Formulation & Hypothesis Reasoning
- `generate_defense_rule`: Accepts observed failure clusters and defanged sample URLs, querying Qwen to synthesize atomic predicates and strictly validating the response against `DeclarativeRuleModel`.
- `formulate_hypothesis`: Reasons over failure clusters, generating structured `DefensiveHypothesis` objects. Predicates are verified against `DeclarativeRuleEngine.ALLOWED_FEATURES` and `ALLOWED_OPERATORS`. Unallowlisted fields or arbitrary code execution attempts trigger immediate `ProviderInferenceError`.

### 3.6 Red AI Scenario Synthesis & RFC 2606 Safety
- `generate_scenario_contract`: Synthesizes controlled `ScenarioContract` objects via Qwen.
- Strict Safety Boundary: Model output URLs are strictly checked to terminate in RFC 2606 reserved domains (`.test`, `.example`, `.invalid`, `.localhost`). Any attempt to output live domains (e.g. `google.com`) is rejected with `ProviderInferenceError`.
- Fail-Closed: Production mode strictly fails closed upon Qwen errors, without silent procedural fallback.

---

## 4. Supervised Fine-Tuning (SFT) & Dataset Pipeline Integration
The Qwen inference model can be specialized via parameter-efficient fine-tuning (LoRA) using the dataset pipeline:
- Ingestion & Splitting: `scripts/dataset_pipeline.py` (domain-grouped, zero-leakage splits)
- ChatML Task Generator: `scripts/generate_agent_tasks.py` (produces `blue_defense_sft.jsonl`, `red_adversary_sft.jsonl`, `classification_sft.jsonl`)
- LoRA Recipe & Dry-Run: `scripts/train_qwen_lora.py` and `infrastructure/training/qwen_lora_config.yaml`
- Held-out test set (`datasets/splits/test_held_out.jsonl`) is strictly isolated and guarded against inclusion in any SFT or training recipe.


