"""Integration tests for the Security Dataset Pipeline and Qwen Inference Architecture.

Tests:
1. Dataset split integrity and cryptographic SHA-256 verification against the manifest.
2. Zero cross-split domain leakage (train vs val vs held-out test).
3. Strict isolation enforcement of held-out test data in SFT and LoRA scripts.
4. Schema validation of generated ChatML SFT datasets (DeclarativeRuleModel & RFC 2606).
5. Truthful Qwen connectivity probe and /health/ready probe reporting.
6. Guarded live inference execution (skips when credentials/local daemon absent).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.app.core.config import Settings, get_settings
from apps.api.app.main import create_app
from apps.api.app.providers.base import ProviderInferenceError
from apps.api.app.providers.qwen_provider import QwenProvider
from cyberduel_contracts.policy import DeclarativeRuleModel
from scripts.generate_agent_tasks import check_forbidden_path
from scripts.train_qwen_lora import enforce_test_set_isolation, validate_chatml_record

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ==============================================================================
# 1. Dataset Integrity & Zero-Leakage Tests
# ==============================================================================


def test_dataset_manifest_and_sha256_digests() -> None:
    """Verify that dataset splits exist and match the SHA-256 digests in manifest."""
    manifest_path = REPO_ROOT / "datasets" / "manifests" / "dataset_manifest.json"
    assert manifest_path.exists(), f"Manifest file missing: {manifest_path}"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    splits = manifest.get("splits", {})
    assert "train" in splits
    assert "validation" in splits
    assert "held_out_test" in splits

    for split_key, split_info in splits.items():
        file_path = REPO_ROOT / split_info["file"]
        assert file_path.exists(), f"Split file missing: {file_path}"

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            hasher.update(f.read())
        computed_hash = hasher.hexdigest()

        assert computed_hash == split_info["sha256"], (
            f"Digest mismatch in split '{split_key}': {computed_hash} != {split_info['sha256']}"
        )


def test_zero_cross_split_domain_leakage() -> None:
    """Verify strictly zero domain overlap across train, validation, and held-out test splits."""
    def extract_domains(rel_path: str) -> set[str]:
        p = REPO_ROOT / rel_path
        domains = set()
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    domains.add(item["domain"].lower())
        return domains

    train_domains = extract_domains("datasets/splits/train.jsonl")
    val_domains = extract_domains("datasets/splits/val.jsonl")
    test_domains = extract_domains("datasets/splits/test_held_out.jsonl")

    assert len(train_domains) > 0
    assert len(val_domains) > 0
    assert len(test_domains) > 0

    train_val_overlap = train_domains.intersection(val_domains)
    train_test_overlap = train_domains.intersection(test_domains)
    val_test_overlap = val_domains.intersection(test_domains)

    assert not train_val_overlap, f"Domain leakage between Train and Val: {train_val_overlap}"
    assert not train_test_overlap, f"Domain leakage between Train and Test: {train_test_overlap}"
    assert not val_test_overlap, f"Domain leakage between Val and Test: {val_test_overlap}"


# ==============================================================================
# 2. Test Set Isolation Protocol Tests
# ==============================================================================


def test_sft_generator_rejects_held_out_test_set() -> None:
    """Verify that the SFT generator raises a fatal PermissionError if test split is supplied."""
    held_out_path = REPO_ROOT / "datasets" / "splits" / "test_held_out.jsonl"
    with pytest.raises(PermissionError, match="DATA LEAKAGE VIOLATION"):
        check_forbidden_path(held_out_path)


def test_lora_training_enforces_test_isolation() -> None:
    """Verify that the LoRA training script rejects any file list referencing test data."""
    clean_sources = ["datasets/sft/classification_sft.jsonl", "datasets/sft/blue_defense_sft.jsonl"]
    # Should pass without error
    enforce_test_set_isolation(clean_sources)

    # Should raise PermissionError when contaminated
    contaminated_sources = ["datasets/sft/classification_sft.jsonl", "datasets/splits/test_held_out.jsonl"]
    with pytest.raises(PermissionError, match="TEST SET ISOLATION BREACH"):
        enforce_test_set_isolation(contaminated_sources)


# ==============================================================================
# 3. ChatML SFT Dataset Quality & Schema Validation
# ==============================================================================


def test_classification_sft_chatml_structure() -> None:
    """Verify classification SFT examples conform to ChatML and valid JSON assistant payload."""
    path = REPO_ROOT / "datasets" / "sft" / "classification_sft.jsonl"
    assert path.exists()

    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            validate_chatml_record(record, idx, path)

            # Check assistant payload
            assistant_msg = [m for m in record["messages"] if m["role"] == "assistant"][0]
            parsed = json.loads(assistant_msg["content"])
            assert "threat_score" in parsed
            assert "decision" in parsed
            assert parsed["decision"] in ("allow", "warn", "block")


def test_blue_defense_sft_validates_declarative_rule_model() -> None:
    """Verify that every Blue AI SFT example emits a valid DeclarativeRuleModel."""
    path = REPO_ROOT / "datasets" / "sft" / "blue_defense_sft.jsonl"
    assert path.exists()

    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            validate_chatml_record(record, idx, path)

            assistant_msg = [m for m in record["messages"] if m["role"] == "assistant"][0]
            # Must strictly validate against Pydantic AST schema
            rule = DeclarativeRuleModel.model_validate_json(assistant_msg["content"])
            assert rule.rule_id
            assert len(rule.predicates) >= 1
            assert rule.action.value in ("warn", "block")


def test_red_adversary_sft_rfc2606_compliance() -> None:
    """Verify that every Red AI SFT example uses strictly RFC 2606 reserved domains."""
    path = REPO_ROOT / "datasets" / "sft" / "red_adversary_sft.jsonl"
    assert path.exists()

    rfc_suffixes = (".test", ".example", ".invalid", ".localhost")
    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            validate_chatml_record(record, idx, path)

            assistant_msg = [m for m in record["messages"] if m["role"] == "assistant"][0]
            payload = json.loads(assistant_msg["content"])
            assert "synthetic_url" in payload
            assert "rfc2606_domain" in payload
            domain = payload["rfc2606_domain"]
            assert any(domain.endswith(sfx) for sfx in rfc_suffixes), (
                f"Red AI sample violation: '{domain}' is not an RFC 2606 domain"
            )


# ==============================================================================
# 4. Truthful Qwen Readiness Probe & Endpoint Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_qwen_endpoint_connectivity_probe_failure() -> None:
    """Verify check_endpoint_connectivity gracefully handles unreachable endpoint."""
    provider = QwenProvider(
        api_base="http://127.0.0.1:59999/v1",  # Non-existent local port
        api_key=None,
        model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
    )
    reachable, msg, _ = await provider.check_endpoint_connectivity(timeout_seconds=0.5)
    assert reachable is False
    assert any(term in msg.lower() for term in ("timeout", "error", "unreachable", "failed"))


@pytest.mark.asyncio
async def test_truthful_readiness_probe_with_qwen() -> None:
    """Verify /health/ready probe reports configured vs unreachable without claiming mock."""
    # 1. Test environment mode: fast-path test mode report
    test_settings = Settings(
        ENVIRONMENT="test",
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        DATABASE_URL_SYNC="sqlite:///:memory:",
        AI_PROVIDER_TYPE="qwen",
        QWEN_API_BASE="http://127.0.0.1:59999/v1",
        SECRET_KEY="test_secret_key_for_readiness_probe_01",
        RATE_LIMIT_ENABLED=False,
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] in ("healthy", "ready")
        ai_status = data["checks"]["ai_provider"]
        assert "qwen" in ai_status
        assert "[test-mode]" in ai_status
        assert "mock" not in ai_status

    # 2. Non-test environment: executes real connectivity check
    dev_settings = Settings(
        ENVIRONMENT="development",
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        DATABASE_URL_SYNC="sqlite:///:memory:",
        AI_PROVIDER_TYPE="qwen",
        QWEN_API_BASE="http://127.0.0.1:59999/v1",
        SECRET_KEY="test_secret_key_for_readiness_probe_01",
        RATE_LIMIT_ENABLED=False,
    )
    app_dev = create_app()
    app_dev.dependency_overrides[get_settings] = lambda: dev_settings
    transport_dev = ASGITransport(app=app_dev)

    async with AsyncClient(transport=transport_dev, base_url="http://testserver") as client:
        res = await client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        ai_status = data["checks"]["ai_provider"]
        assert "qwen" in ai_status
        assert "endpoint" in ai_status
        assert "mock" not in ai_status


# ==============================================================================
# 5. Blue AI Defense AST Rule Generation & Fail-Closed Errors
# ==============================================================================


@pytest.mark.asyncio
async def test_qwen_generate_defense_rule_success() -> None:
    """Verify generate_defense_rule validates output against DeclarativeRuleModel."""
    provider = QwenProvider(
        api_base="https://mock.qwen.endpoint/v1",
        api_key="secret-key",
        model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
    )

    valid_rule_dict = {
        "rule_id": "rule_test_001",
        "rule_version": "1.0.0",
        "description": "Block phishing test pattern",
        "author": "BlueAI-DefenseEngine",
        "purpose": "Mitigate test attack",
        "target_family": "credential_harvesting",
        "predicates": [
            {"field": "path", "operator": "contains", "value": "/login/verify"},
        ],
        "action": "block",
        "severity": "high",
        "weight": 0.85,
    }

    with patch.object(provider, "generate_structured_json", new_callable=AsyncMock) as mock_json:
        mock_json.return_value = valid_rule_dict

        rule = await provider.generate_defense_rule(
            failure_cluster_description="Credential harvesting paths",
            target_family="credential_harvesting",
            sample_urls=["hxxps://fake-bank[.]example/login/verify"],
        )

        assert isinstance(rule, DeclarativeRuleModel)
        assert rule.rule_id == "rule_test_001"
        assert rule.action.value == "block"


@pytest.mark.asyncio
async def test_qwen_generate_defense_rule_fails_closed_on_invalid_schema() -> None:
    """Verify generate_defense_rule raises ProviderInferenceError when model emits invalid AST."""
    provider = QwenProvider(
        api_base="https://mock.qwen.endpoint/v1",
        api_key="secret-key",
        model_name="Qwen/Qwen2.5-Coder-7B-Instruct",
    )

    invalid_rule_dict = {
        "rule_id": "rule_bad_001",
        # Missing required predicates!
        "action": "invalid_action",
    }

    with patch.object(provider, "generate_structured_json", new_callable=AsyncMock) as mock_json:
        mock_json.return_value = invalid_rule_dict

        with pytest.raises(ProviderInferenceError, match="invalid DeclarativeRuleModel"):
            await provider.generate_defense_rule(
                failure_cluster_description="Bad cluster",
                target_family="malware",
                sample_urls=["hxxps://malware[.]example/test"],
            )


# ==============================================================================
# 6. Guarded Live Inference Test
# ==============================================================================


@pytest.mark.skipif(
    not os.getenv("RUN_LIVE_QWEN_TESTS"),
    reason="LIVE INFERENCE BLOCKED: Live Qwen endpoint or credentials not configured in environment.",
)
@pytest.mark.asyncio
async def test_live_qwen_inference_execution() -> None:
    """Only executed when RUN_LIVE_QWEN_TESTS=1 and real endpoint is provided."""
    provider = QwenProvider()
    reachable, msg, _ = await provider.check_endpoint_connectivity(timeout_seconds=5.0)
    assert reachable is True, f"Configured live Qwen endpoint unreachable: {msg}"

    res = await provider.generate_response(prompt="Output the single word 'VERIFIED'.")
    assert "VERIFIED" in res.upper()
