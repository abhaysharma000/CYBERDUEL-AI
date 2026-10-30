"""Canonical enums used across CyberDuel AI services and contracts."""

from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class ThreatSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProvenanceType(StrEnum):
    LOCAL_RULE = "local_rule"
    MODEL_INFERENCE = "model_inference"
    CLOUD_ANALYSIS = "cloud_analysis"


class ObservationSource(StrEnum):
    BROWSER_EXTENSION = "browser_extension"
    MOBILE_APP = "mobile_app"
    LAB_SCENARIO = "lab_scenario"
    EXTERNAL_FEED = "external_feed"


class ScenarioStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DefenseStatus(StrEnum):
    CANDIDATE = "candidate"
    EVALUATING = "evaluating"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEPRECATED = "deprecated"


class ReleaseStatus(StrEnum):
    DRAFT = "draft"
    ELIGIBLE = "eligible"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    STAGED = "staged"
    PUBLISHED = "published"
    PAUSED = "paused"
    REVOKED = "revoked"
    ROLLED_BACK = "rolled_back"
    SUPERSEDED = "superseded"


class ReleaseChannel(StrEnum):
    DEVELOPMENT = "development"
    CANARY = "canary"
    STABLE = "stable"
    EMERGENCY = "emergency"


class RolloutStage(StrEnum):
    INTERNAL = "internal"
    CANARY_10 = "canary_10"
    CANARY_25 = "canary_25"
    CANARY_50 = "canary_50"
    GENERAL_AVAILABILITY = "general_availability"
    PAUSED = "paused"
    HALTED = "halted"
    ROLLED_BACK = "rolled_back"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


class ClientPlatform(StrEnum):
    BROWSER_EXTENSION = "browser_extension"
    MOBILE_APP = "mobile_app"
    AGENT_NODE = "agent_node"
    DESKTOP = "desktop"


class EvaluationVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EvaluationStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DatasetSplitType(StrEnum):
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    REGRESSION = "regression"
    HELD_OUT = "held_out"
    BENIGN_CONTROL = "benign_control"


class CycleStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    STOPPED_BUDGET_EXHAUSTED = "stopped_budget_exhausted"
    STOPPED_NO_PROGRESS = "stopped_no_progress"
    CANCELLED = "cancelled"


class EvaluationOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED_REGRESSION = "rejected_regression"
    REJECTED_HIGH_FPR = "rejected_high_fpr"
    REJECTED_LOW_RECALL = "rejected_low_recall"
    REJECTED_INEFFECTIVE = "rejected_ineffective"
    REJECTED_OVERHEAD = "rejected_overhead"
    REJECTED_INTEGRITY = "rejected_integrity"
    INCONCLUSIVE = "inconclusive"


class AgentRole(StrEnum):
    RED_AI = "red_ai"
    BLUE_AI = "blue_ai"
    EVALUATOR = "evaluator"


class ExpectedClass(StrEnum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNCERTAIN = "uncertain"


class ScenarioFamily(StrEnum):
    HOMOGRAPH_MIMICRY = "homograph_mimicry"
    AUTHORITY_SPOOFING = "authority_spoofing"
    IP_HOST = "ip_host"
    BRAND_IMPERSONATION = "brand_impersonation"
    SUSPICIOUS_PORT = "suspicious_port"
    DOUBLE_ENCODING = "double_encoding"
    DGA_ENTROPY = "dga_entropy"
    SUBDOMAIN_FLOODING = "subdomain_flooding"
    LENGTH_ANOMALY = "length_anomaly"
    PHISHING_KEYWORDS = "phishing_keywords"
    BENIGN_LOOKALIKE = "benign_lookalike"
    WHITELIST_CONTROL = "whitelist_control"
    NORMALIZATION_EDGE_CASE = "normalization_edge_case"
    STALE_INTELLIGENCE = "stale_intelligence"


class ExperimentStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscrepancyType(StrEnum):
    NONE = "none"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    OVERLY_AGGRESSIVE = "overly_aggressive"
    UNDERCONFIDENT = "underconfident"
    PARSING_ERROR = "parsing_error"
    UNCERTAIN_OUTCOME = "uncertain_outcome"


class FailureCategory(StrEnum):
    EVASION = "evasion"
    OVER_DETECTION = "over_detection"
    PARSING_INCONSISTENCY = "parsing_inconsistency"
    POLICY_MISCALIBRATION = "policy_miscalibration"
    INTELLIGENCE_STALENESS = "intelligence_staleness"
    UNKNOWN = "unknown"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    UNDER_TEST = "under_test"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ProposalType(StrEnum):
    DECLARATIVE_RULE = "declarative_rule"
    CLASSIFIER_TUNING = "classifier_tuning"
    THRESHOLD_TUNING = "threshold_tuning"


class CandidateLifecycleStatus(StrEnum):
    DRAFT = "draft"
    BUILT = "built"
    SANDBOX_TESTING = "sandbox_testing"
    AWAITING_EVALUATION = "awaiting_evaluation"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    SUPERSEDED = "superseded"
