"""Defensive hypothesis formulation engine.

Analyzes detection gaps, extracts common feature invariants across failing URLs,
explains detector blindspots, and synthesizes structured, testable hypotheses.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import Decision, HypothesisStatus
from cyberduel_contracts.policy import DefensiveHypothesis
from cyberduel_threat_intel.feature_extractor import URLFeatureExtractor
from cyberduel_threat_intel.validator import URLValidator
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import DefenseHypothesisRecord
from apps.api.app.services.blue_ai.prioritizer import PrioritizedFailureGroup

try:
    from cyberduel_policy_engine.rules import DeclarativeRuleEngine

    from apps.api.app.core.config import get_settings
    from apps.api.app.providers.base import (
        ProviderInferenceError,
        ProviderUnavailableError,
    )
    from apps.api.app.providers.factory import get_ai_provider
except ImportError:
    get_settings = None  # type: ignore
    get_ai_provider = None  # type: ignore
    ProviderInferenceError = Exception  # type: ignore
    ProviderUnavailableError = Exception  # type: ignore
    DeclarativeRuleEngine = None  # type: ignore

logger = logging.getLogger("blue_ai.hypothesis")


class DefenseHypothesisEngine:
    """Synthesizes evidence-driven defensive hypotheses from failure clusters."""

    # Benign control samples for counterexample reference
    BENIGN_CONTROLS = [
        {"url": "https://www.google.com/search?q=cybersecurity", "label": "benign"},
        {"url": "https://github.com/organization/project", "label": "benign"},
        {"url": "https://en.wikipedia.org/wiki/Computer_security", "label": "benign"},
        {"url": "https://docs.python.org/3/library/urllib.parse.html", "label": "benign"},
        {"url": "https://cloudflare.com/learning/access-management/", "label": "benign"},
    ]

    @classmethod
    def analyze_cluster_features(
        cls,
        urls: list[str],
    ) -> dict[str, Any]:
        """Extract and aggregate feature invariants from failing URLs."""
        if not urls:
            return {
                "common_tlds": [],
                "has_punycode_ratio": 0.0,
                "avg_subdomains": 1.0,
                "avg_entropy": 3.0,
                "has_ip_ratio": 0.0,
                "avg_keywords": 0.0,
                "extracted_samples": [],
            }

        extracted_list: list[dict[str, Any]] = []
        tld_counts: dict[str, int] = {}
        punycode_count = 0
        ip_count = 0
        total_subdomains = 0
        total_entropy = 0.0
        total_keywords = 0

        valid_count = 0
        for raw_url in urls[:10]:
            val_res = URLValidator.validate(raw_url)
            if not val_res.is_valid or not val_res.normalized:
                continue

            valid_count += 1
            norm = val_res.normalized
            feats = URLFeatureExtractor.extract_features(norm)
            extracted_list.append(feats)

            host = norm.host
            tld = host.split(".")[-1] if "." in host else ""
            if tld:
                tld_counts[tld] = tld_counts.get(tld, 0) + 1
            if feats.get("is_punycode", 0) == 1:
                punycode_count += 1
            if feats.get("is_ip_literal", 0) == 1:
                ip_count += 1
            total_subdomains += int(feats.get("subdomain_count", 0))
            total_entropy += float(feats.get("host_entropy", 0.0))
            total_keywords += int(feats.get("phish_keyword_count", 0))

        n = max(1, valid_count)
        return {
            "common_tlds": sorted(tld_counts.keys(), key=lambda k: tld_counts[k], reverse=True),
            "has_punycode_ratio": punycode_count / n,
            "avg_subdomains": round(total_subdomains / n, 2),
            "avg_entropy": round(total_entropy / n, 2),
            "has_ip_ratio": ip_count / n,
            "avg_keywords": round(total_keywords / n, 2),
            "extracted_samples": extracted_list,
        }

    @classmethod
    def formulate_hypothesis(
        cls,
        task_id: UUID,
        priority_group: PrioritizedFailureGroup,
    ) -> DefensiveHypothesis:
        """Formulate a structured DefensiveHypothesis from a prioritized failure cluster."""
        cluster = priority_group.cluster
        analysis = cls.analyze_cluster_features(cluster.sample_urls)

        # Determine the primary evasion invariant
        predicates_spec: list[dict[str, Any]] = []
        possible_explanation: str
        predicted_benefit: str
        potential_risks: str

        if analysis["has_punycode_ratio"] >= 0.5:
            possible_explanation = (
                "The baseline detector failed to detect internationalized domain name (IDN) "
                "punycode evasion because standard lexical heuristic rules only inspect ASCII "
                "surface strings without evaluating punycode prefixes or homoglyph risk."
            )
            predicates_spec.append({"field": "is_punycode", "operator": "eq", "value": 1})
            predicates_spec.append({"field": "phish_keyword_count", "operator": "gte", "value": 1})
            predicted_benefit = (
                "Intercepts punycode brand spoofing with zero impact on standard ASCII URLs."
            )
            potential_risks = "May increase warnings on legitimate internationalized domains lacking reputational history."

        elif analysis["has_ip_ratio"] >= 0.5:
            possible_explanation = (
                "Adversary bypassed domain reputation lookups by directly utilizing numeric IPv4 "
                "host addresses in URL targets. Baseline heuristics did not assign sufficient penalty "
                "to raw IP hosts containing high-entropy path endpoints."
            )
            predicates_spec.append({"field": "is_ip_literal", "operator": "eq", "value": 1})
            predicates_spec.append({"field": "path_length", "operator": "gte", "value": 8})
            predicted_benefit = "Stops direct-IP phishing and malware drop endpoints."
            potential_risks = "Could flag internal administrative IP URLs if accessed without local intranet exclusions."

        elif analysis["avg_subdomains"] >= 3.0:
            possible_explanation = (
                "Attackers leveraged deep multi-level subdomain chains (>= 3 subdomains) to push "
                "malicious keyword tokens into left-hand labels while retaining benign parent TLDs, "
                "evading simple domain-level blocklists."
            )
            predicates_spec.append({"field": "subdomain_count", "operator": "gte", "value": 3})
            predicates_spec.append({"field": "phish_keyword_count", "operator": "gte", "value": 1})
            predicted_benefit = "Detects subdomain stuffing attacks used in cloud hosting evasion."
            potential_risks = "Complex enterprise subdomains (e.g. dev.staging.corp.com) must be protected by allowlisting."

        elif analysis["common_tlds"] and analysis["common_tlds"][0] in {
            "xyz",
            "top",
            "buzz",
            "club",
            "work",
            "tk",
        }:
            top_tld = analysis["common_tlds"][0]
            possible_explanation = (
                f"Adversary exploited low-reputation top-level domain (.{top_tld}) coupled with "
                "elevated URL entropy and phishing keyword tokens, slipping below the baseline's "
                "generic threat threshold."
            )
            predicates_spec.append(
                {"field": "host", "operator": "contains", "value": f".{top_tld}"}
            )
            predicates_spec.append({"field": "phish_keyword_count", "operator": "gte", "value": 1})
            predicted_benefit = (
                f"Filters high-frequency phishing hosted on cheap disposable TLDs like .{top_tld}."
            )
            potential_risks = (
                "Legitimate startups on modern TLDs may require manual or allowlisted overrides."
            )

        else:
            # General high-entropy / keyword compound evasion
            possible_explanation = (
                "The detector failed because the malicious indicators were distributed across both "
                "host entropy and credential-harvesting tokens, requiring a compound declarative rule."
            )
            predicates_spec.append({"field": "phish_keyword_count", "operator": "gte", "value": 2})
            predicates_spec.append({"field": "host_entropy", "operator": "gte", "value": 3.0})
            predicted_benefit = (
                "Catches credential-harvesting pages with obfuscated session parameters."
            )
            potential_risks = "Slight risk on complex analytics links containing tracking keywords."

        sev_str = (
            cluster.severity.value if hasattr(cluster.severity, "value") else str(cluster.severity)
        )
        target_action = Decision.BLOCK if sev_str in ("critical", "high") else Decision.WARN
        confidence = 0.88 if sev_str in ("critical", "high") else 0.80

        hypothesis = DefensiveHypothesis(
            hypothesis_id=uuid4(),
            research_task_id=task_id,
            failure_category=cluster.failure_category,
            target_family=cluster.target_family,
            observed_behavior=(
                f"Baseline detector assigned {cluster.discrepancy_type.upper()} "
                f"to {cluster.affected_count} scenarios in category '{cluster.failure_category}'."
            ),
            expected_behavior=f"Expected {target_action.value.upper()} decision with confidence >= 0.75.",
            possible_explanation=possible_explanation,
            supporting_evidence=[
                {
                    "url": u,
                    "category": cluster.failure_category,
                    "discrepancy": cluster.discrepancy_type,
                }
                for u in cluster.sample_urls[:5]
            ],
            counterexamples=cls.BENIGN_CONTROLS,
            proposed_intervention={
                "proposal_type": "declarative_rule",
                "target_action": target_action.value,
                "predicates": predicates_spec,
                "logical_operator": "AND",
                "recommended_weight": 0.85,
            },
            predicted_benefit=predicted_benefit,
            potential_risks=potential_risks,
            test_plan="Run candidate sandbox evaluation against failure fixtures, benign controls, and regression benchmarks.",
            status=HypothesisStatus.PROPOSED,
            confidence=confidence,
            created_at=datetime.now(UTC),
        )

        return hypothesis

    @classmethod
    async def formulate_hypothesis_async(
        cls,
        task_id: UUID,
        priority_group: PrioritizedFailureGroup,
        provider: Any | None = None,
        provider_mode: str | None = None,
    ) -> DefensiveHypothesis:
        """Formulate a DefensiveHypothesis asynchronously, querying Qwen if configured or procedural heuristics."""
        mode = provider_mode
        if not mode:
            if get_settings:
                try:
                    mode = get_settings().AI_PROVIDER_TYPE
                except Exception:
                    mode = "procedural"
            else:
                mode = "procedural"

        if mode == "qwen":
            ai_prov = provider
            if not ai_prov and get_ai_provider:
                try:
                    ai_prov = get_ai_provider("qwen")
                except Exception as exc:
                    is_prod = get_settings().is_production if get_settings else False
                    if is_prod:
                        raise ProviderUnavailableError(
                            f"Production mode requires active QwenProvider: {exc}"
                        ) from exc
                    logger.warning(f"Could not load QwenProvider, failing closed: {exc}")
                    raise

            if not ai_prov:
                is_prod = get_settings().is_production if get_settings else False
                if is_prod:
                    raise ProviderUnavailableError("QwenProvider is required in production mode.")
                raise ProviderUnavailableError("QwenProvider not available.")

            try:
                cluster = priority_group.cluster
                hypothesis = await ai_prov.formulate_hypothesis(
                    task_id=task_id,
                    failure_category=cluster.failure_category,
                    target_family=cluster.target_family,
                    discrepancy_type=cluster.discrepancy_type,
                    affected_count=cluster.affected_count,
                    sample_urls=cluster.sample_urls,
                )

                # Validate predicates against DeclarativeRuleEngine allowlists
                intervention = hypothesis.proposed_intervention or {}
                raw_preds = intervention.get("predicates", [])
                if DeclarativeRuleEngine:
                    for p in raw_preds:
                        f = p.get("field")
                        op = p.get("operator")
                        if f not in DeclarativeRuleEngine.ALLOWED_FEATURES:
                            raise ProviderInferenceError(
                                f"Qwen emitted unallowlisted feature '{f}'. "
                                f"Allowed features: {DeclarativeRuleEngine.ALLOWED_FEATURES}"
                            )
                        if op not in DeclarativeRuleEngine.ALLOWED_OPERATORS:
                            raise ProviderInferenceError(
                                f"Qwen emitted unallowlisted operator '{op}'. "
                                f"Allowed operators: {DeclarativeRuleEngine.ALLOWED_OPERATORS}"
                            )

                logger.info(
                    f"Synthesized hypothesis via QwenProvider for category '{cluster.failure_category}'"
                )
                return hypothesis

            except Exception as exc:
                is_prod = (get_settings().is_production if get_settings else False) or (
                    os.getenv("ENVIRONMENT") == "production"
                )
                if is_prod:
                    raise ProviderInferenceError(
                        f"Qwen hypothesis formulation failed in production: {exc}"
                    ) from exc
                logger.error(
                    f"Qwen hypothesis formulation failed: {exc}. Failing closed per policy."
                )
                raise

        # Procedural fallback
        return cls.formulate_hypothesis(task_id=task_id, priority_group=priority_group)

    @classmethod
    async def save_hypothesis(
        cls,
        hypothesis: DefensiveHypothesis,
        session: AsyncSession,
    ) -> DefenseHypothesisRecord:
        """Persist hypothesis to database."""
        record = DefenseHypothesisRecord(
            id=hypothesis.hypothesis_id,
            research_task_id=hypothesis.research_task_id,
            failure_category=hypothesis.failure_category,
            target_family=hypothesis.target_family,
            hypothesis_text=hypothesis.possible_explanation,
            status=hypothesis.status.value,
            confidence=hypothesis.confidence,
            evidence_payload={
                "observed": hypothesis.observed_behavior,
                "expected": hypothesis.expected_behavior,
                "supporting_evidence": hypothesis.supporting_evidence,
                "counterexamples": hypothesis.counterexamples,
                "predicted_benefit": hypothesis.predicted_benefit,
                "potential_risks": hypothesis.potential_risks,
                "test_plan": hypothesis.test_plan,
            },
            intervention_payload=hypothesis.proposed_intervention,
            created_at=hypothesis.created_at,
            updated_at=hypothesis.created_at,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record
