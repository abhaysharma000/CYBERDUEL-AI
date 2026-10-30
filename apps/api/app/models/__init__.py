"""Canonical domain models registration for CyberDuel AI."""

from apps.api.app.models.analysis import DetectionOutcomeRecord, ThreatAnalysisRecord
from apps.api.app.models.audit import AuditLogRecord
from apps.api.app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from apps.api.app.models.devices import DeviceRegistration, UpdateDeliveryRecord
from apps.api.app.models.evaluations import (
    AcceptancePolicyRecord,
    BenchmarkManifestRecord,
    CycleCheckpointRecord,
    CycleFeedbackRecord,
    EvaluationProtocolRecord,
    EvaluationReportRecord,
    EvaluationRequestRecord,
    ImprovementCycleRecord,
)
from apps.api.app.models.feedback import FeedbackSubmission
from apps.api.app.models.indicators import ThreatIndicatorRecord
from apps.api.app.models.lab import (
    EvaluationRunRecord,
    FailureFindingRecord,
    LabExperimentRecord,
    LaboratoryScenarioRun,
    ScenarioExecutionRecord,
    ScenarioRecord,
)
from apps.api.app.models.observations import ThreatObservation
from apps.api.app.models.policies import (
    CandidateDefenseRecord,
    CandidateFeedbackRecord,
    DefenseHypothesisRecord,
    DefenseProposalRecord,
    PolicyReleaseRecord,
    ResearchTaskRecord,
    SandboxComparisonRecord,
)
from apps.api.app.models.releases import (
    ClientAcknowledgementRecord,
    ClientDeviceRecord,
    ReleaseAuthorizationRecord,
    ReleaseRecord,
    RolloutStateRecord,
    SigningKeyRecord,
)

__all__ = [
    "AcceptancePolicyRecord",
    "AuditLogRecord",
    "Base",
    "BenchmarkManifestRecord",
    "CandidateDefenseRecord",
    "CandidateFeedbackRecord",
    "ClientAcknowledgementRecord",
    "ClientDeviceRecord",
    "CycleCheckpointRecord",
    "CycleFeedbackRecord",
    "DefenseHypothesisRecord",
    "DefenseProposalRecord",
    "DetectionOutcomeRecord",
    "DeviceRegistration",
    "EvaluationProtocolRecord",
    "EvaluationReportRecord",
    "EvaluationRequestRecord",
    "EvaluationRunRecord",
    "FailureFindingRecord",
    "FeedbackSubmission",
    "ImprovementCycleRecord",
    "LabExperimentRecord",
    "LaboratoryScenarioRun",
    "PolicyReleaseRecord",
    "ReleaseAuthorizationRecord",
    "ReleaseRecord",
    "ResearchTaskRecord",
    "RolloutStateRecord",
    "SandboxComparisonRecord",
    "ScenarioExecutionRecord",
    "ScenarioRecord",
    "SigningKeyRecord",
    "ThreatAnalysisRecord",
    "ThreatIndicatorRecord",
    "ThreatObservation",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "UpdateDeliveryRecord",
]
