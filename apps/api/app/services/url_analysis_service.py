"""Service coordinating URL normalization, intelligence lookups, heuristics, and scoring."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from cyberduel_contracts.analysis import EvidenceItem, ThreatAnalysisResult
from cyberduel_contracts.enums import Decision, ProvenanceType, ThreatSeverity
from cyberduel_threat_intel.heuristics import URLHeuristicAnalyzer
from cyberduel_threat_intel.scoring import RiskScoringEngine, ScoringPolicyConfig
from cyberduel_threat_intel.validator import URLValidator
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.analysis import ThreatAnalysisRecord
from apps.api.app.repositories.threat_intel_repository import ThreatIntelRepository

logger = logging.getLogger("url_analysis")


class URLAnalysisService:
    """End-to-end URL threat analysis coordinator."""

    ENGINE_VERSION = "0.2.0-heuristic-intel"
    POLICY_VERSION = "2026.10.1"

    def __init__(
        self,
        session: AsyncSession | None = None,
        scoring_config: ScoringPolicyConfig | None = None,
    ) -> None:
        self.session = session
        self.repository = ThreatIntelRepository(session=session)
        self.heuristic_analyzer = URLHeuristicAnalyzer()
        self.scoring_engine = RiskScoringEngine(config=scoring_config)

    async def analyze_url(
        self,
        raw_url: str,
        client_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> ThreatAnalysisResult:
        """Execute complete explainable URL threat analysis pipeline."""
        # 1. Structural Validation & Safe Normalization
        val_result = URLValidator.validate(raw_url)
        if not val_result.is_valid or not val_result.normalized:
            # Note: A malformed URL is NOT automatically evidence of maliciousness
            return ThreatAnalysisResult(
                analysis_id=uuid4(),
                normalized_identifier="malformed_url_" + uuid4().hex[:16],
                threat_score=0.0,
                decision=Decision.ALLOW,
                evidence=[
                    EvidenceItem(
                        category="validation",
                        reason=f"URL rejected during structural validation: {val_result.error_message}",
                        severity=ThreatSeverity.NONE,
                    )
                ],
                engine_version=self.ENGINE_VERSION,
                policy_version=self.POLICY_VERSION,
                confidence=None,
                provenance=ProvenanceType.LOCAL_RULE,
            )

        url = val_result.normalized

        # 2. Local Threat Intelligence Lookup (URL hash and domain hash)
        hashes_to_query = [url.url_sha256, url.domain_sha256]
        indicator_matches = await self.repository.lookup_by_hashes(hashes_to_query)

        # 3. Defensive Heuristic Rules Execution
        heuristic_evidence = self.heuristic_analyzer.analyze(url)

        # 4. Check if Destination is Whitelisted
        is_whitelisted = self.heuristic_analyzer._is_whitelisted(url)

        # 5. Risk Scoring & Decision
        scoring = self.scoring_engine.evaluate(
            indicator_matches=indicator_matches,
            heuristic_evidence=heuristic_evidence,
            is_whitelisted=is_whitelisted,
        )

        result = ThreatAnalysisResult(
            analysis_id=uuid4(),
            normalized_identifier=url.url_sha256,
            threat_score=scoring.threat_score,
            decision=scoring.decision,
            evidence=scoring.evidence,
            engine_version=self.ENGINE_VERSION,
            policy_version=self.POLICY_VERSION,
            confidence=scoring.confidence,
            provenance=scoring.provenance,
            created_at=datetime.now(UTC),
        )

        # 6. Persistence & Audit Trail (if DB session active)
        if self.session is not None:
            try:
                record = ThreatAnalysisRecord(
                    id=result.analysis_id,
                    normalized_identifier=result.normalized_identifier,
                    threat_score=result.threat_score,
                    decision=result.decision.value,
                    confidence=result.confidence,
                    provenance=result.provenance.value,
                    engine_version=result.engine_version,
                    policy_version=result.policy_version,
                    evidence_payload=[e.model_dump(mode="json") for e in result.evidence],
                )
                self.session.add(record)
                await self.session.commit()
            except Exception as e:
                logger.warning(f"Failed to persist ThreatAnalysisRecord: {e}")

        return result
