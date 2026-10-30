"""Blue AI Defense Engine package.

Autonomous defensive intelligence, failure clustering, evidence-driven hypothesis formulation,
declarative candidate rule generation, and benchmark evaluation integration.
"""

from apps.api.app.services.blue_ai.agent import BlueCycleResult, BlueResearchAgent
from apps.api.app.services.blue_ai.builder import CandidateDefenseBuilder
from apps.api.app.services.blue_ai.evidence import DefenseEvidenceService
from apps.api.app.services.blue_ai.feedback import LearningFeedbackService
from apps.api.app.services.blue_ai.handoff import EvaluationHandoffService
from apps.api.app.services.blue_ai.hypothesis import DefenseHypothesisEngine
from apps.api.app.services.blue_ai.prioritizer import (
    DefensePrioritizationEngine,
    FailureCluster,
    PrioritizedFailureGroup,
)
from apps.api.app.services.blue_ai.proposals import DefenseProposalGenerator
from apps.api.app.services.blue_ai.research import DefensiveResearchService
from apps.api.app.services.blue_ai.sandbox_runner import CandidateSandboxRunner

__all__ = [
    "BlueCycleResult",
    "BlueResearchAgent",
    "CandidateDefenseBuilder",
    "CandidateSandboxRunner",
    "DefenseEvidenceService",
    "DefenseHypothesisEngine",
    "DefensePrioritizationEngine",
    "DefenseProposalGenerator",
    "DefensiveResearchService",
    "EvaluationHandoffService",
    "FailureCluster",
    "LearningFeedbackService",
    "PrioritizedFailureGroup",
]
