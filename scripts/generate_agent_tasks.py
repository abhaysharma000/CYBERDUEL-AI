#!/usr/bin/env python3
"""CyberDuel AI — Task-Specific SFT Dataset Generator for Qwen Models.

Transforms split training data (train.jsonl) into structured, ChatML-format
supervised fine-tuning datasets for:
1. Classification SFT: Inert lexical URL classification and evidence explanation.
2. Blue AI Defense SFT: Declarative AST rule generation adhering to DeclarativeRuleModel.
3. Red AI Adversary SFT: Controlled synthetic attack scenarios adhering to RFC 2606 (.test, .example).

CRITICAL POLICY:
- STRICT ISOLATION: The held-out test set (test_held_out.jsonl) MUST NEVER be read, referenced, or included.
- URLs are processed as inert strings. Zero live network resolution.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any

# Ensure cyberduel_contracts can be imported
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages" / "shared-contracts"))

try:
    from cyberduel_contracts.policy import DeclarativeRuleModel, RulePredicateModel
    from cyberduel_contracts.enums import Decision, ThreatSeverity
except ImportError as err:
    sys.exit(f"Failed to import cyberduel_contracts: {err}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | [SFT-GEN] %(levelname)s | %(message)s")
logger = logging.getLogger("sft_generator")

FORBIDDEN_FILES = {"test_held_out.jsonl", "test.jsonl", "held_out.jsonl"}
RFC_2606_TLDS = (".test", ".example", ".invalid", ".localhost")


def check_forbidden_path(file_path: Path) -> None:
    """Enforce strict separation: Raise fatal exception if test set is accessed."""
    name = file_path.name.lower()
    for forbidden in FORBIDDEN_FILES:
        if forbidden in name:
            raise PermissionError(
                f"DATA LEAKAGE VIOLATION: Access to held-out test split '{file_path}' is strictly prohibited during training data generation!"
            )


def load_train_records(train_path: Path) -> list[dict[str, Any]]:
    """Safely load training records with isolation checks."""
    check_forbidden_path(train_path)
    if not train_path.exists():
        raise FileNotFoundError(f"Training split not found: {train_path}")

    records = []
    with open(train_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    logger.info("Loaded %d records from %s", len(records), train_path)
    return records


def generate_classification_sft(train_records: list[dict[str, Any]], output_path: Path) -> int:
    """Generate ChatML records for lexical threat classification."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        for r in train_records:
            is_phish = r["label"] == "phishing"
            score = 0.92 if is_phish else 0.05
            decision = "block" if is_phish else "allow"
            family = r.get("threat_category", "benign")

            # Extract sample lexical indicators
            url = r["url"]
            indicators = []
            if "@" in url:
                indicators.append("contains_userinfo_delimiter")
            if any(char in url for char in ["-login", "-verify", "secure-", "update-"]):
                indicators.append("deceptive_keyword_slug")
            if url.count(".") > 3:
                indicators.append("excessive_subdomain_depth")
            if is_phish and not indicators:
                indicators.append("suspicious_path_structure")
            if not is_phish:
                indicators.append("legitimate_brand_or_educational_structure")

            explanation = (
                f"Defensive lexical analysis identified pattern consistent with {family}."
                if is_phish
                else "URL displays legitimate structural and domain characteristics with no threat indicators."
            )

            assistant_payload = {
                "threat_score": score,
                "decision": decision,
                "threat_family": family,
                "lexical_indicators": indicators,
                "explanation": explanation,
            }

            chat = {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are the CyberDuel AI URL classification engine. "
                            "Analyze URLs purely based on inert lexical indicators. "
                            "Never attempt to resolve, crawl, or execute URLs. Return strict JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Analyze the following URL for security threats.\n"
                            f"URL: {r['url']}\n"
                            f"Registrable Domain: {r['domain']}\n"
                            f"Provide JSON assessment with: threat_score, decision, threat_family, lexical_indicators, explanation."
                        ),
                    },
                    {
                        "role": "assistant",
                        "content": json.dumps(assistant_payload, indent=2),
                    },
                ]
            }
            f.write(json.dumps(chat) + "\n")
            count += 1

    logger.info("Generated %d classification SFT examples in %s", count, output_path)
    return count


def generate_blue_defense_sft(train_records: list[dict[str, Any]], output_path: Path) -> int:
    """Generate ChatML records for Blue AI declarative AST rule synthesis."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    # Group phishing records by category
    categories: dict[str, list[dict[str, Any]]] = {}
    for r in train_records:
        if r["label"] == "phishing":
            cat = r.get("threat_category", "credential_harvesting")
            categories.setdefault(cat, []).append(r)

    # Create synthesized training examples for Blue AI
    rule_templates = [
        {
            "category": "credential_harvesting",
            "rule_id": "rule_blue_cred_harvest_01",
            "description": "Block URL paths containing deceptive login/verification sequences with external redirection.",
            "purpose": "Neutralize generic credential harvesting login phishing pages.",
            "predicates": [
                RulePredicateModel(field="path", operator="contains", value="/login/verify"),
                RulePredicateModel(field="url_length", operator="gt", value=45),
            ],
            "action": Decision.BLOCK,
            "severity": ThreatSeverity.HIGH,
            "weight": 0.88,
        },
        {
            "category": "brand_impersonation",
            "rule_id": "rule_blue_brand_slug_02",
            "description": "Detect brand name impersonation slugs combined with security verification keywords.",
            "purpose": "Prevent fraudulent brand spoofing on dynamic cloud or secondary domains.",
            "predicates": [
                RulePredicateModel(field="domain", operator="contains", value="-security-"),
                RulePredicateModel(field="path", operator="contains", value="update"),
            ],
            "action": Decision.BLOCK,
            "severity": ThreatSeverity.CRITICAL,
            "weight": 0.95,
        },
        {
            "category": "crypto_drainer",
            "rule_id": "rule_blue_crypto_drainer_03",
            "description": "Flag crypto wallet connection prompts paired with claim or airdrop slugs.",
            "purpose": "Mitigate deceptive web3 wallet authorization attacks.",
            "predicates": [
                RulePredicateModel(field="path", operator="contains", value="airdrop-claim"),
                RulePredicateModel(field="query_params", operator="contains", value="wallet="),
            ],
            "action": Decision.BLOCK,
            "severity": ThreatSeverity.CRITICAL,
            "weight": 0.92,
        },
        {
            "category": "banking_trojan",
            "rule_id": "rule_blue_banking_app_04",
            "description": "Warn on simulated mobile banking apk or direct binary downloads disguised as updates.",
            "purpose": "Prevent rogue banking trojan apk distribution.",
            "predicates": [
                RulePredicateModel(field="path", operator="contains", value="banking_app_security.apk"),
            ],
            "action": Decision.BLOCK,
            "severity": ThreatSeverity.CRITICAL,
            "weight": 0.99,
        },
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        for tpl in rule_templates:
            cat = tpl["category"]
            sample_group = categories.get(cat, [r for r in train_records if r["label"] == "phishing"][:2])
            samples = [s["url"] for s in sample_group[:3]]

            rule_model = DeclarativeRuleModel(
                rule_id=tpl["rule_id"],
                rule_version="1.0.0",
                description=tpl["description"],
                author="BlueAI-DefenseEngine",
                purpose=tpl["purpose"],
                target_family=cat,
                feature_names=["path", "domain"],
                predicates=tpl["predicates"],
                logical_operator="AND",
                action=tpl["action"],
                severity=tpl["severity"],
                weight=tpl["weight"],
                false_positive_risk="low",
            )

            # Strict verification of AST model serialization
            rule_json_str = rule_model.model_dump_json(indent=2)
            # Verify it parses back
            DeclarativeRuleModel.model_validate_json(rule_json_str)

            chat = {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are Blue AI, a defensive security intelligence model synthesizing declarative AST rules. "
                            "Formulate declarative rules that generalize against attack patterns while strictly preventing "
                            "false positives on legitimate traffic. Output strict JSON matching DeclarativeRuleModel."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Synthesize a declarative detection rule to mitigate the following attack pattern.\n"
                            f"Target Threat Family: {cat}\n"
                            f"Observed Attack Indicators: Attackers utilizing {cat} techniques with suspicious path tokens.\n"
                            f"Sample Attack URLs (defanged): {samples}\n"
                            f"Requirements:\n"
                            f"1. Generate atomic predicates using allowed fields (e.g. domain, path, query_params).\n"
                            f"2. Set action to 'block' or 'warn'.\n"
                            f"3. Return strict JSON matching DeclarativeRuleModel schema."
                        ),
                    },
                    {
                        "role": "assistant",
                        "content": rule_json_str,
                    },
                ]
            }
            f.write(json.dumps(chat) + "\n")
            count += 1

    logger.info("Generated %d Blue AI defense SFT examples in %s", count, output_path)
    return count


def generate_red_adversary_sft(output_path: Path) -> int:
    """Generate ChatML records for Red AI controlled scenario generation.

    SAFETY CONSTRAINT:
    All generated scenarios MUST use RFC 2606 reserved domains (.test, .example, .invalid).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    scenarios = [
        {
            "target": "Microsoft 365",
            "technique": "homoglyph_subdomain_spoofing",
            "scenario": {
                "scenario_id": "scen_red_msft_01",
                "title": "Synthetic Microsoft 365 Re-authentication Phish",
                "target_brand": "Microsoft",
                "threat_category": "credential_harvesting",
                "synthetic_url": "hxxps://login-microsoftonline[.]accounts-portal[.]test/oauth2/v2.0/authorize",
                "rfc2606_domain": "accounts-portal.test",
                "obfuscation_technique": "Subdomain stacking with authentic-looking OAuth path tokens",
                "expected_decision": "block",
                "safety_classification": "harmless_synthetic",
            },
        },
        {
            "target": "PayPal",
            "technique": "urgent_account_suspension_alert",
            "scenario": {
                "scenario_id": "scen_red_paypal_02",
                "title": "Synthetic Urgent Security Escalation Phish",
                "target_brand": "PayPal",
                "threat_category": "credential_harvesting",
                "synthetic_url": "hxxps://service-security-resolution[.]example/webapps/mpp/account-recovery",
                "rfc2606_domain": "service-security-resolution.example",
                "obfuscation_technique": "Urgent appeal path with brand name token placement",
                "expected_decision": "block",
                "safety_classification": "harmless_synthetic",
            },
        },
        {
            "target": "Metamask",
            "technique": "crypto_airdrop_drainer",
            "scenario": {
                "scenario_id": "scen_red_crypto_03",
                "title": "Synthetic Web3 Airdrop Drainer Simulation",
                "target_brand": "Metamask",
                "threat_category": "crypto_drainer",
                "synthetic_url": "hxxps://claim-foundation-reward[.]test/connect?provider=injected",
                "rfc2606_domain": "claim-foundation-reward.test",
                "obfuscation_technique": "Web3 injection simulation with reward incentive",
                "expected_decision": "block",
                "safety_classification": "harmless_synthetic",
            },
        },
        {
            "target": "Google Workspace",
            "technique": "quarantine_release_simulation",
            "scenario": {
                "scenario_id": "scen_red_google_04",
                "title": "Synthetic Email Quarantine Release Notification",
                "target_brand": "Google",
                "threat_category": "credential_harvesting",
                "synthetic_url": "hxxps://admin-portal-verify[.]example/quarantine/release-msg",
                "rfc2606_domain": "admin-portal-verify.example",
                "obfuscation_technique": "IT admin quarantine impersonation slug",
                "expected_decision": "block",
                "safety_classification": "harmless_synthetic",
            },
        },
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        for item in scenarios:
            scen = item["scenario"]
            # Verify RFC 2606 domain compliance
            domain = scen["rfc2606_domain"]
            if not any(domain.endswith(tld) for tld in RFC_2606_TLDS):
                raise ValueError(f"Safety violation: Domain '{domain}' does not comply with RFC 2606 reserved TLDs!")

            chat = {
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are Red AI, a cybersecurity scenario generator for testing defensive security mechanisms. "
                            "You must ONLY generate safe, synthetic test scenarios using RFC 2606 reserved domains "
                            "(.test, .example, .invalid, .localhost). NEVER use real live domain names. Return strict JSON."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"Generate a controlled synthetic attack scenario testing defensive capability against:\n"
                            f"Target Brand: {item['target']}\n"
                            f"Attack Technique: {item['technique']}\n"
                            f"Constraint: synthetic_url must strictly use an RFC 2606 domain."
                        ),
                    },
                    {
                        "role": "assistant",
                        "content": json.dumps(scen, indent=2),
                    },
                ]
            }
            f.write(json.dumps(chat) + "\n")
            count += 1

    logger.info("Generated %d Red AI adversary SFT examples in %s", count, output_path)
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ChatML SFT datasets for Qwen models.")
    parser.add_argument(
        "--train-split",
        type=Path,
        default=REPO_ROOT / "datasets" / "splits" / "train.jsonl",
        help="Path to training split (train.jsonl). Never use test_held_out.jsonl.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "datasets" / "sft",
        help="Output directory for generated ChatML JSONL files.",
    )
    args = parser.parse_args()

    # Pre-flight check against leakage
    check_forbidden_path(args.train_split)

    records = load_train_records(args.train_split)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    c_count = generate_classification_sft(records, args.output_dir / "classification_sft.jsonl")
    b_count = generate_blue_defense_sft(records, args.output_dir / "blue_defense_sft.jsonl")
    r_count = generate_red_adversary_sft(args.output_dir / "red_adversary_sft.jsonl")

    logger.info("Task SFT generation complete! Classification: %d | Blue AI: %d | Red AI: %d", c_count, b_count, r_count)


if __name__ == "__main__":
    main()

