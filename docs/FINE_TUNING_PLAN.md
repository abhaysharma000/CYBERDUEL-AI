# CyberDuel AI — Qwen Fine-Tuning Recipe and Architecture Plan

## 1. Overview and Scope

This document specifies the Parameter-Efficient Fine-Tuning (PEFT/LoRA) architecture for adapting open-source **Qwen2.5** models for CyberDuel AI's specialized cybersecurity roles.

The pipeline establishes a verified, reproducible training recipe that transforms defensive security datasets into structured Supervised Fine-Tuning (SFT) examples while enforcing strict data hygiene and zero-leakage isolation.

> [!IMPORTANT]
> **Status:** The training recipe, configuration schemas, dataset transformations, and dry-run validators are fully implemented and verified. Actual GPU fine-tuning has **not** been executed yet; no synthetic weights, fake loss curves, or benchmark claims are fabricated.

---

## 2. Agent Specialization Tasks

Fine-tuning adapts Qwen into three task-specific capabilities using the ChatML format:

```
<|im_start|>system
{System Instruction}<|im_end|>
<|im_start|>user
{Task Prompt and Context}<|im_end|>
<|im_start|>assistant
{Structured JSON Output}<|im_end|>
```

### A. Classification & Evidence Extraction (`classification_sft.jsonl`)
- **System Role:** Inert URL threat classification engine.
- **Input:** Defanged URL string, domain, and lexical context.
- **Output:** Strict JSON containing `threat_score` (0.0 to 1.0), `decision` (`allow`, `warn`, `block`), `threat_family`, `lexical_indicators` list, and `explanation`.
- **Constraint:** Model must output rational explanations without attempting active network operations.

### B. Blue AI Defense Rule Synthesis (`blue_defense_sft.jsonl`)
- **System Role:** Blue AI Defensive Defense Engine.
- **Input:** Observed attack indicators, threat category, and defanged sample URLs.
- **Output:** Strictly validated JSON conforming to the `DeclarativeRuleModel` Pydantic schema:
  - `rule_id`, `rule_version`, `description`, `author`, `purpose`, `target_family`
  - Atomic `predicates` with valid operators (`contains`, `matches_regex`, `gt`, `eq`)
  - Evaluated `action` (`warn`, `block`), `severity`, and `weight`
- **Constraint:** Output must be parseable by `DeclarativeRuleModel.model_validate_json()`.

### C. Red AI Controlled Scenario Generation (`red_adversary_sft.jsonl`)
- **System Role:** Red AI Controlled Scenario Generator.
- **Input:** Target brand and requested attack vector.
- **Output:** Structured test scenario with synthetic deceptive attributes.
- **Constraint:** Synthetic URLs **must strictly use RFC 2606 reserved domains** (`.test`, `.example`, `.invalid`). Live registered domains are strictly forbidden.

---

## 3. PEFT / LoRA Hyperparameter Recipe

The canonical configuration is defined in [`infrastructure/training/qwen_lora_config.yaml`](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/infrastructure/training/qwen_lora_config.yaml).

```yaml
model:
  base_model_name_or_path: "Qwen/Qwen2.5-7B-Instruct"
  torch_dtype: "bfloat16"
  quantization:
    load_in_4bit: true
    bnb_4bit_quant_type: "nf4"
    bnb_4bit_compute_dtype: "bfloat16"
    bnb_4bit_use_double_quant: true

lora:
  r: 16
  lora_alpha: 32
  lora_dropout: 0.05
  bias: "none"
  task_type: "CAUSAL_LM"
  target_modules:
    - "q_proj"
    - "k_proj"
    - "v_proj"
    - "o_proj"
    - "gate_proj"
    - "up_proj"
    - "down_proj"

training_arguments:
  num_train_epochs: 3
  per_device_train_batch_size: 4
  gradient_accumulation_steps: 4
  learning_rate: 0.0002
  lr_scheduler_type: "cosine"
  warmup_ratio: 0.05
  max_seq_length: 2048
  optim: "paged_adamw_8bit"
  bf16: true
```

### Rationale
- **4-Bit NF4 Quantization:** Reduces base model memory from 14GB+ to ~4.5GB VRAM, allowing fine-tuning on consumer/workstation GPUs.
- **Target Modules:** Adapting all linear projection layers (attention + MLP) ensures complete downstream representation alignment with fewer than 0.5% trainable parameters.
- **Paged AdamW 8-bit:** Prevents out-of-memory spikes during gradient backpropagation.

---

## 4. Hardware and Environment Requirements

| Requirement | Minimum Specification | Recommended Production Specification |
| :--- | :--- | :--- |
| **GPU Hardware** | 1x NVIDIA GPU with $\ge$ 16 GB VRAM (RTX 4080, RTX 3090, A10G) | 1x NVIDIA A100 (40GB/80GB) or H100 |
| **System RAM** | 32 GB DDR4/DDR5 | 64 GB DDR5 |
| **CUDA Toolkit** | CUDA 12.1+ | CUDA 12.4+ |
| **Python Packages** | `torch>=2.2.0`, `transformers>=4.40.0`, `peft>=0.10.0`, `trl>=0.8.0`, `bitsandbytes>=0.43.0` | Same, with FlashAttention-2 enabled |

---

## 5. Held-Out Test Set Isolation Protocol

To guarantee scientific rigor:
1. `datasets/splits/test_held_out.jsonl` contains 10 domain-isolated records.
2. Fine-tuning code (`scripts/train_qwen_lora.py`) and data preparation (`scripts/generate_agent_tasks.py`) raise a `PermissionError` if the test set is referenced.
3. Post-training candidate evaluation must be executed exclusively by the independent `EvaluationEngine`. Model self-reporting is rejected.

---

## 6. Execution Commands

```powershell
# 1. Generate SFT tasks from train split (zero test access):
.venv\Scripts\python.exe scripts/generate_agent_tasks.py

# 2. Validate ChatML formatting and token counts:
.venv\Scripts\python.exe scripts/train_qwen_lora.py --validate-data-only

# 3. Perform LoRA recipe dry-run:
.venv\Scripts\python.exe scripts/train_qwen_lora.py --dry-run
```

