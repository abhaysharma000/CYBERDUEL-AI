"""Candidate defense builder service for Blue AI.

Assembles, versions, and digests candidate defenses comprising declarative rules
and tuning parameters into an immutable CandidateDefense contract.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cyberduel_contracts.enums import DefenseStatus
from cyberduel_contracts.policy import CandidateDefense, DefenseProposal
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.policies import CandidateDefenseRecord

logger = logging.getLogger("blue_ai.builder")


class CandidateDefenseBuilder:
    """Builds, versions, and persists CandidateDefense packages for sandbox evaluation."""

    @classmethod
    def compute_spec_digest(cls, spec_data: dict[str, Any]) -> str:
        """Calculate canonical SHA-256 fingerprint over serialized rule specifications."""
        canonical_json = json.dumps(spec_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @classmethod
    def assemble_candidate(
        cls,
        proposals: list[DefenseProposal],
        baseline_version: str = "1.0.0",
        candidate_sequence: int = 1,
    ) -> CandidateDefense:
        """Assemble a complete CandidateDefense contract from one or more proposals."""
        rules_payload: list[dict[str, Any]] = []
        tuning_payload: dict[str, Any] = {}
        proposal_ids: list[str] = []
        descriptions: list[str] = []

        for p in proposals:
            proposal_ids.append(str(p.proposal_id))
            descriptions.append(p.title)
            if p.declarative_rule:
                rules_payload.append(p.declarative_rule.model_dump(mode="json"))
            if p.tuning_spec:
                tuning_payload.update(p.tuning_spec)

        defense_id = uuid4()
        version = f"v{baseline_version}-blue.{candidate_sequence:03d}"

        spec_core = {
            "baseline_version": baseline_version,
            "rules": rules_payload,
            "tuning": tuning_payload,
        }
        digest = cls.compute_spec_digest(spec_core)

        rule_spec = {
            **spec_core,
            "digest": digest,
            "proposal_ids": proposal_ids,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        desc = f"Candidate defense {version}: " + "; ".join(descriptions)
        if len(desc) > 1000:
            desc = desc[:997] + "..."

        return CandidateDefense(
            defense_id=defense_id,
            version=version,
            author_agent="BlueAI-v1",
            description=desc,
            rule_spec=rule_spec,
            status=DefenseStatus.CANDIDATE,
            created_at=datetime.now(UTC),
        )

    @classmethod
    async def save_candidate(
        cls,
        candidate: CandidateDefense,
        session: AsyncSession,
    ) -> CandidateDefenseRecord:
        """Persist CandidateDefense to database."""
        record = CandidateDefenseRecord(
            id=candidate.defense_id,
            version=candidate.version,
            author_agent=candidate.author_agent,
            description=candidate.description,
            rule_spec=candidate.rule_spec,
            status=candidate.status.value,
            created_at=candidate.created_at,
            updated_at=candidate.created_at,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record

    @classmethod
    async def get_candidate(
        cls,
        candidate_id: UUID,
        session: AsyncSession,
    ) -> CandidateDefenseRecord | None:
        """Retrieve candidate defense record by primary key."""
        stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == candidate_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
