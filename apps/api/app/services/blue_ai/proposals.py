"""Defense proposal generator for Blue AI.

Transforms validated defensive hypotheses into concrete, evaluable proposals,
synthesizing declarative detection rules or safe threshold tuning specifications.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from uuid import uuid4

from cyberduel_contracts.enums import Decision, ProposalType, ThreatSeverity
from cyberduel_contracts.policy import (
    DeclarativeRuleModel,
    DefenseProposal,
    DefensiveHypothesis,
    RulePredicateModel,
)
from cyberduel_policy_engine.rules import DeclarativeRuleEngine
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import DefenseProposalRecord

logger = logging.getLogger("blue_ai.proposals")


class DefenseProposalGenerator:
    """Generates strictly validated defense proposals from defensive hypotheses."""

    @classmethod
    def generate_proposal(
        cls,
        hypothesis: DefensiveHypothesis,
    ) -> DefenseProposal:
        """Synthesize and validate a concrete DefenseProposal from a DefensiveHypothesis."""
        intervention = hypothesis.proposed_intervention or {}
        proposal_type_str = intervention.get("proposal_type", "declarative_rule")
        proposal_type = (
            ProposalType.DECLARATIVE_RULE
            if proposal_type_str == "declarative_rule"
            else ProposalType.THRESHOLD_TUNING
        )

        title = f"Mitigation for {hypothesis.failure_category} ({hypothesis.target_family})"
        rationale = (
            f"Synthesized from hypothesis {hypothesis.hypothesis_id}: "
            f"{hypothesis.possible_explanation[:250]}"
        )

        proposal_id = uuid4()
        now = datetime.now(UTC)

        if proposal_type == ProposalType.DECLARATIVE_RULE:
            raw_predicates = intervention.get("predicates", [])
            predicates: list[RulePredicateModel] = []
            feature_names: list[str] = []

            for p in raw_predicates:
                pred = RulePredicateModel(
                    field=p["field"],
                    operator=p["operator"],
                    value=p["value"],
                )
                predicates.append(pred)
                if p["field"] not in feature_names:
                    feature_names.append(p["field"])

            if not predicates:
                # Default safe fallback predicate
                predicates = [
                    RulePredicateModel(
                        field="suspicious_keywords_count",
                        operator="gte",
                        value=2,
                    )
                ]
                feature_names = ["suspicious_keywords_count"]

            clean_cat = re.sub(r"[^A-Za-z0-9]", "-", hypothesis.failure_category).upper()[:24]
            rule_id = f"RULE-BLUE-{clean_cat}-{str(proposal_id)[:6].upper()}"

            action_val = intervention.get("target_action", "warn")
            action = Decision.BLOCK if action_val.lower() == "block" else Decision.WARN

            rule = DeclarativeRuleModel(
                rule_id=rule_id,
                rule_version="1.0.0",
                description=f"Auto-synthesized rule targeting {hypothesis.failure_category}",
                author="BlueAI-DefenseEngine",
                purpose=hypothesis.predicted_benefit[:250],
                target_family=hypothesis.target_family,
                feature_names=feature_names,
                predicates=predicates,
                logical_operator=intervention.get("logical_operator", "AND"),
                action=action,
                severity=ThreatSeverity.HIGH if action == Decision.BLOCK else ThreatSeverity.MEDIUM,
                weight=float(intervention.get("recommended_weight", 0.85)),
                false_positive_risk="low",
                source_hypothesis_id=hypothesis.hypothesis_id,
                created_at=now,
            )

            # Strict validation against AST, allowlist, and ReDoS ceilings
            DeclarativeRuleEngine.validate_rule(rule)

            proposal = DefenseProposal(
                proposal_id=proposal_id,
                hypothesis_id=hypothesis.hypothesis_id,
                proposal_type=proposal_type,
                title=title,
                rationale=rationale,
                declarative_rule=rule,
                tuning_spec=None,
                status="built",
                created_at=now,
            )

        else:
            # Threshold tuning proposal
            tuning_spec = {
                "suspicious_threshold": 0.45,
                "malicious_threshold": 0.70,
                "heuristic_weight_adjustment": {
                    hypothesis.target_family: 1.25,
                },
            }
            proposal = DefenseProposal(
                proposal_id=proposal_id,
                hypothesis_id=hypothesis.hypothesis_id,
                proposal_type=proposal_type,
                title=title,
                rationale=rationale,
                declarative_rule=None,
                tuning_spec=tuning_spec,
                status="built",
                created_at=now,
            )

        return proposal

    @classmethod
    async def generate_proposal_async(
        cls,
        hypothesis: DefensiveHypothesis,
    ) -> DefenseProposal:
        """Asynchronously generate and strictly validate defense proposal from hypothesis."""
        return cls.generate_proposal(hypothesis)

    @classmethod
    async def save_proposal(
        cls,
        proposal: DefenseProposal,
        session: AsyncSession,
    ) -> DefenseProposalRecord:
        """Persist defense proposal to database."""
        spec_payload: dict = {}
        if proposal.declarative_rule:
            spec_payload = proposal.declarative_rule.model_dump(mode="json")
        elif proposal.tuning_spec:
            spec_payload = proposal.tuning_spec

        record = DefenseProposalRecord(
            id=proposal.proposal_id,
            hypothesis_id=proposal.hypothesis_id,
            proposal_type=proposal.proposal_type.value,
            title=proposal.title,
            rationale=proposal.rationale,
            spec=spec_payload,
            status=proposal.status,
            created_at=proposal.created_at,
            updated_at=proposal.created_at,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record
