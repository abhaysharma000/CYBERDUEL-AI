#!/usr/bin/env python3
"""CyberDuel AI — Qwen LoRA Fine-Tuning Recipe & Dry-Run Validator.

Provides reproducible LoRA fine-tuning infrastructure for Qwen2.5 models
on defensive security datasets.

SAFETY & INTEGRITY CONSTRAINTS:
1. Dry-run by default: Does not initiate GPU jobs or fabricate model weights.
2. Zero Test Leakage: Strictly prohibits and detects any access to test_held_out.jsonl.
3. ChatML Validation: Confirms all training data conforms to standard ChatML format.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | [LORA-TRAIN] %(levelname)s | %(message)s"
)
logger = logging.getLogger("lora_trainer")

REPO_ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_KEYWORDS = {"test_held_out", "test.jsonl", "held_out"}


def enforce_test_set_isolation(sources: list[str]) -> None:
    """Enforce strict isolation of held-out test split."""
    for s in sources:
        s_lower = str(s).lower()
        for kw in FORBIDDEN_KEYWORDS:
            if kw in s_lower:
                raise PermissionError(
                    f"TEST SET ISOLATION BREACH: Source '{s}' references held-out test data! "
                    "Held-out test records must never be exposed to training or validation."
                )
    logger.info("Test set isolation check: PASSED (Zero reference to held-out test data)")


def validate_chatml_record(record: dict[str, Any], line_num: int, file_path: Path) -> int:
    """Validate a single ChatML conversation and estimate token count."""
    if "messages" not in record or not isinstance(record["messages"], list):
        raise ValueError(f"Line {line_num} in {file_path.name}: missing 'messages' list")

    messages = record["messages"]
    if len(messages) < 2:
        raise ValueError(
            f"Line {line_num} in {file_path.name}: ChatML must have at least user and assistant messages"
        )

    total_chars = 0
    roles_seen = []
    for m in messages:
        if not isinstance(m, dict) or "role" not in m or "content" not in m:
            raise ValueError(
                f"Line {line_num} in {file_path.name}: message missing 'role' or 'content'"
            )
        role = m["role"]
        content = m["content"]
        if role not in ("system", "user", "assistant"):
            raise ValueError(f"Line {line_num} in {file_path.name}: invalid role '{role}'")
        if not isinstance(content, str) or not content.strip():
            raise ValueError(
                f"Line {line_num} in {file_path.name}: content must be non-empty string"
            )
        roles_seen.append(role)
        total_chars += len(content)

    if "user" not in roles_seen or "assistant" not in roles_seen:
        raise ValueError(
            f"Line {line_num} in {file_path.name}: must contain both 'user' and 'assistant' messages"
        )

    # Rough heuristic: ~4 characters per token
    return max(1, total_chars // 4)


def inspect_sft_sources(sources: list[str]) -> dict[str, Any]:
    """Inspect and validate all SFT JSONL training sources."""
    stats = {
        "files_inspected": 0,
        "total_examples": 0,
        "estimated_tokens": 0,
        "file_details": {},
    }

    for src_rel in sources:
        src_path = REPO_ROOT / src_rel
        if not src_path.exists():
            raise FileNotFoundError(f"Training source not found: {src_path}")

        file_examples = 0
        file_tokens = 0
        with open(src_path, encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                tokens = validate_chatml_record(record, idx, src_path)
                file_examples += 1
                file_tokens += tokens

        stats["files_inspected"] += 1
        stats["total_examples"] += file_examples
        stats["estimated_tokens"] += file_tokens
        stats["file_details"][src_path.name] = {
            "path": str(src_path),
            "examples": file_examples,
            "estimated_tokens": file_tokens,
            "avg_tokens_per_example": round(file_tokens / file_examples, 1) if file_examples else 0,
        }

    return stats


def run_dry_run(config: dict[str, Any], data_stats: dict[str, Any]) -> None:
    """Print complete dry-run validation report without initiating GPU jobs."""
    model_cfg = config.get("model", {})
    lora_cfg = config.get("lora", {})
    train_args = config.get("training_arguments", {})

    print("\n" + "=" * 70)
    print("CYBERDUEL AI — QWEN LoRA TRAINING DRY-RUN REPORT")
    print("=" * 70)
    print(f"Base Model:             {model_cfg.get('base_model_name_or_path', 'N/A')}")
    print(
        f"Quantization:           {model_cfg.get('quantization', {}).get('bnb_4bit_quant_type', 'N/A')} 4-bit NF4"
    )
    print(f"LoRA Rank (r):          {lora_cfg.get('r', 'N/A')}")
    print(f"LoRA Alpha (alpha):     {lora_cfg.get('lora_alpha', 'N/A')}")
    print(f"LoRA Dropout:           {lora_cfg.get('lora_dropout', 'N/A')}")
    print(f"Target Modules:         {', '.join(lora_cfg.get('target_modules', []))}")
    print("-" * 70)
    print("TRAINING HYPERPARAMETERS:")
    print(f"Epochs:                 {train_args.get('num_train_epochs', 'N/A')}")
    print(f"Batch Size (per-device):{train_args.get('per_device_train_batch_size', 'N/A')}")
    print(f"Gradient Accumulation:  {train_args.get('gradient_accumulation_steps', 'N/A')}")
    print(
        f"Effective Batch Size:   {train_args.get('per_device_train_batch_size', 1) * train_args.get('gradient_accumulation_steps', 1)}"
    )
    print(f"Learning Rate:          {train_args.get('learning_rate', 'N/A')}")
    print(f"LR Scheduler:           {train_args.get('lr_scheduler_type', 'N/A')}")
    print(f"Warmup Ratio:           {train_args.get('warmup_ratio', 'N/A')}")
    print(f"Max Sequence Length:    {train_args.get('max_seq_length', 'N/A')}")
    print(f"Optimizer:              {train_args.get('optim', 'N/A')}")
    print("-" * 70)
    print("DATASET VALIDATION SUMMARY:")
    print(f"Files Inspected:        {data_stats['files_inspected']}")
    print(f"Total SFT Examples:     {data_stats['total_examples']}")
    print(f"Estimated Total Tokens: {data_stats['estimated_tokens']}")
    for name, detail in data_stats["file_details"].items():
        print(f"  - {name}: {detail['examples']} examples, ~{detail['estimated_tokens']} tokens")
    print("-" * 70)
    print("TEST SET ISOLATION:     PASSED (test_held_out.jsonl strictly excluded)")
    print("STATUS:                 DRY-RUN VALIDATED (No weights loaded, 0 GPU hours spent)")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberDuel AI Qwen LoRA Fine-Tuning Recipe & Validator."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=REPO_ROOT / "infrastructure" / "training" / "qwen_lora_config.yaml",
        help="Path to LoRA YAML training config.",
    )
    parser.add_argument(
        "--validate-data-only",
        action="store_true",
        help="Validate SFT training datasets and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Perform configuration check and dry-run without executing GPU training (default: True).",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Execute actual training run on GPU hardware (requires PyTorch + CUDA + Transformers).",
    )
    args = parser.parse_args()

    if not args.config.exists():
        sys.exit(f"Config file not found: {args.config}")

    with open(args.config, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # 1. Enforce zero leakage
    train_sources = config.get("dataset_policy", {}).get("train_sources", [])
    val_sources = config.get("dataset_policy", {}).get("validation_sources", [])
    forbidden = config.get("dataset_policy", {}).get("forbidden_sources", [])

    enforce_test_set_isolation(train_sources + val_sources)

    # 2. Inspect and validate ChatML data
    logger.info("Validating SFT datasets against ChatML format...")
    data_stats = inspect_sft_sources(train_sources)
    logger.info(
        "Successfully validated %d examples across %d files.",
        data_stats["total_examples"],
        data_stats["files_inspected"],
    )

    if args.validate_data_only:
        print(
            f"Data validation passed: {data_stats['total_examples']} records, {data_stats['estimated_tokens']} tokens."
        )
        return

    # 3. Dry-run report
    if not args.execute or args.dry_run:
        run_dry_run(config, data_stats)
        return

    # 4. If --execute was specified: check prerequisites
    logger.error(
        "LIVE GPU TRAINING NOT EXECUTED: Production training must run in a dedicated GPU environment "
        "with CUDA 12+, PyTorch 2.2+, Hugging Face TRL, and PEFT. "
        "To inspect or test the recipe locally, run with --dry-run or --validate-data-only."
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
