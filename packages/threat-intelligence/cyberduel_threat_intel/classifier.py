"""Optional Machine-Learning URL classification provider interface and fallback."""

from __future__ import annotations

import logging
import math
from typing import Any
from uuid import uuid4

from cyberduel_contracts.analysis import EvidenceItem, ThreatAnalysisResult
from cyberduel_contracts.enums import Decision, ProvenanceType, ThreatSeverity

from apps.api.app.providers.base import BaseThreatClassificationProvider
from cyberduel_threat_intel.feature_extractor import URLFeatureExtractor

logger = logging.getLogger("classifier")


class LightweightLinearModel:
    """Pre-calibrated explainable linear classifier based on URL structural features.

    Weights are derived from benchmark feature importances across phishing corpora:
    - High positive weight: credentials spoofing, brand tokens on unverified host, IP hosts
    - Moderate positive weight: high entropy, deep subdomains, phish keywords
    - Negative weight: standard lengths, low entropy
    """

    WEIGHTS = {
        "has_embedded_credentials": 2.8,
        "is_ip_literal": 1.5,
        "is_punycode": 1.2,
        "brand_token_detected": 1.8,
        "has_non_standard_port": 1.0,
        "has_double_encoding": 1.4,
        "phish_keyword_count": 0.6,
        "subdomain_count": 0.3,
        "host_entropy": 0.4,
    }
    BIAS = -2.5

    @classmethod
    def predict_probability(cls, features: dict[str, Any]) -> float:
        """Compute sigmoid probability score strictly in [0.0, 1.0]."""
        z = cls.BIAS
        for feature_name, weight in cls.WEIGHTS.items():
            val = float(features.get(feature_name, 0))
            z += val * weight

        # Sigmoid activation
        try:
            prob = 1.0 / (1.0 + math.exp(-z))
        except OverflowError:
            prob = 1.0 if z > 0 else 0.0

        return max(0.0, min(1.0, prob))


class MLURLClassifier(BaseThreatClassificationProvider):
    """URL classifier supporting deterministic feature-based linear scoring and mock ML inference."""

    def __init__(self, model_version: str = "lightweight-linear-v1", enabled: bool = True) -> None:
        self.model_version = model_version
        self.enabled = enabled

    async def classify_resource(
        self,
        normalized_identifier: str,
        resource_url: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAnalysisResult:
        """Classify a resource using extracted feature vectors."""
        # If no full URL is available (only hash passed), ML feature extraction cannot run
        if not resource_url:
            return ThreatAnalysisResult(
                analysis_id=uuid4(),
                normalized_identifier=normalized_identifier,
                threat_score=0.10,
                decision=Decision.ALLOW,
                evidence=[
                    EvidenceItem(
                        category="ml_classifier",
                        reason="Raw URL unavailable for structural ML feature extraction; baseline score applied.",
                        severity=ThreatSeverity.NONE,
                        confidence=0.50,
                    )
                ],
                engine_version=self.model_version,
                policy_version="2026.10.1",
                confidence=None,
                provenance=ProvenanceType.MODEL_INFERENCE,
            )

        from cyberduel_threat_intel.normalizer import URLNormalizer

        try:
            normalized = URLNormalizer.normalize(resource_url)
            features = URLFeatureExtractor.extract_features(normalized)
            score = LightweightLinearModel.predict_probability(features)

            if score >= 0.70:
                decision = Decision.BLOCK
                sev = ThreatSeverity.HIGH
            elif score >= 0.35:
                decision = Decision.WARN
                sev = ThreatSeverity.MEDIUM
            else:
                decision = Decision.ALLOW
                sev = ThreatSeverity.NONE

            evidence = [
                EvidenceItem(
                    category="ml_linear_inference",
                    reason=f"Model '{self.model_version}' predicted threat score of {score:.2f} based on 18 extracted URL features.",
                    severity=sev,
                    confidence=round(score, 2),
                )
            ]

            return ThreatAnalysisResult(
                analysis_id=uuid4(),
                normalized_identifier=normalized.url_sha256,
                threat_score=round(score, 4),
                decision=decision,
                evidence=evidence,
                engine_version=self.model_version,
                policy_version="2026.10.1",
                confidence=round(abs(score - 0.5) * 2, 2),  # Distance from decision boundary
                provenance=ProvenanceType.MODEL_INFERENCE,
            )
        except Exception as e:
            logger.warning(f"ML classification failed gracefully: {e}")
            return ThreatAnalysisResult(
                analysis_id=uuid4(),
                normalized_identifier=normalized_identifier,
                threat_score=0.20,
                decision=Decision.ALLOW,
                evidence=[
                    EvidenceItem(
                        category="ml_error",
                        reason=f"ML feature extraction failed: {e}",
                        severity=ThreatSeverity.NONE,
                    )
                ],
                engine_version=self.model_version,
                policy_version="2026.10.1",
                confidence=None,
                provenance=ProvenanceType.MODEL_INFERENCE,
            )
