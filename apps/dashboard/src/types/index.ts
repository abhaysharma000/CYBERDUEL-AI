export type Role = "viewer" | "research_operator" | "defense_reviewer" | "release_operator" | "admin";

export interface UserProfile {
  username: string;
  display_name: string;
  role: Role;
  permissions: string[];
  email?: string;
}

export interface OperatorOption {
  username: string;
  display_name: string;
  role: Role;
  description: string;
}

export interface SystemHealthInfo {
  status: string;
  version: string;
  environment: string;
  database_connected: boolean;
  active_workers: number;
  timestamp: string;
}

export interface ResearchOverview {
  total_experiments: number;
  completed_experiments: number;
  active_experiments: number;
  total_discrepancies: number;
  failure_finding_count: number;
}

export interface DefenseOverview {
  total_candidates: number;
  approved_candidates: number;
  pending_review_candidates: number;
  rejected_candidates: number;
  total_hypotheses: number;
}

export interface EvaluationOverview {
  total_evaluations: number;
  passed_evaluations: number;
  failed_evaluations: number;
  regressions_prevented: number;
}

export interface ReleaseOverview {
  total_releases: number;
  active_production_version: string | null;
  staged_version: string | null;
  current_rollout_percentage: number;
  rollout_state: string;
  active_signing_keys: number;
}

export interface ClientOverview {
  total_devices: number;
  browser_extensions: number;
  mobile_devices: number;
  active_last_24h: number;
  fleet_adoption_rate: number;
}

export interface RecentEvent {
  event_id: string;
  timestamp: string;
  category: string;
  title: string;
  actor: string;
  outcome: string;
}

export interface DashboardOverviewResponse {
  health: SystemHealthInfo;
  research: ResearchOverview;
  defense: DefenseOverview;
  evaluations: EvaluationOverview;
  releases: ReleaseOverview;
  clients: ClientOverview;
  recent_events: RecentEvent[];
}

export interface FailureFinding {
  finding_id: string;
  experiment_id: string;
  failure_category: string;
  discrepancy_type: string;
  hypothesis: string;
  affected_scenarios_count: number;
  representative_scenario_ids: string[];
  suggested_remedy?: string;
  severity: "low" | "medium" | "high" | "critical";
}

export interface LabExperiment {
  experiment_id: string;
  experiment_name: string;
  goal: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  seed: number;
  scenario_count: number;
  executed_count: number;
  discrepancy_count: number;
  metrics: Record<string, any>;
  family_breakdown: Record<string, number>;
  detector_version: string;
  policy_version: string;
  started_at: string;
  completed_at?: string;
  findings: FailureFinding[];
}

export interface ScenarioContract {
  scenario_id: string;
  scenario_family: string;
  scenario_name: string;
  description: string;
  expected_decision: string;
  difficulty: string;
  tags: string[];
  input_fixture: {
    raw_url: string;
    normalized_url?: string;
  };
}

export interface ScenarioExecutionResult {
  execution_id: string;
  scenario_id: string;
  scenario_name: string;
  scenario_family: string;
  raw_url: string;
  expected_decision: string;
  actual_decision: string;
  actual_threat_score: number;
  is_discrepancy: boolean;
  discrepancy_type?: string;
  duration_ms: number;
  executed_at: string;
}

export interface CandidateDefense {
  id: string;
  candidate_version: string;
  defense_type: "rule_update" | "heuristic_weights" | "model_parameters" | "hybrid";
  status: "draft" | "submitted" | "approved" | "rejected" | "superseded";
  target_findings: string[];
  changes_summary: string;
  review_notes?: string;
  evaluated_report_id?: string;
  created_at: string;
  updated_at: string;
}

export interface FailureGroupSummary {
  group_id: string;
  category: string;
  total_failures: number;
  primary_hypothesis: string;
  candidates_proposed: number;
}

export interface EvaluationReport {
  id: string;
  request_id: string;
  candidate_id: string;
  candidate_version: string;
  baseline_version: string;
  benchmark_manifest_id: string;
  verdict: "accept" | "reject" | "inconclusive";
  status: string;
  verdict_rationale: string;
  acceptance_reasons: string[];
  rejection_reasons: string[];
  candidate_metrics: {
    precision?: number;
    recall?: number;
    f1?: number;
    latency_p95_ms?: number;
    false_positive_rate?: number;
  };
  baseline_metrics: {
    precision?: number;
    recall?: number;
    f1?: number;
    latency_p95_ms?: number;
    false_positive_rate?: number;
  };
  improvement_metrics: {
    precision_delta?: number;
    recall_delta?: number;
    regressions_detected?: number;
  };
  report_digest: string;
  evaluated_at: string;
}

export interface ImprovementCycle {
  id: string;
  cycle_number: number;
  status: string;
  trigger_reason: string;
  candidates_evaluated: number;
  accepted_candidate_version?: string;
  summary_metrics: Record<string, any>;
  created_at: string;
}

export interface ReleaseSummary {
  release_id: string;
  policy_version: string;
  sequence_number: number;
  status: string;
  channel: string;
  publisher_key_id: string;
  artifact_digest: string;
  artifact_size_bytes: number;
  current_rollout_percentage: number;
  rollout_phase: string;
  created_at: string;
  published_at?: string;
}

export interface ClientDevice {
  client_id: string;
  client_type: string;
  platform: string;
  engine_version: string;
  current_policy_version: string;
  channel: string;
  cohort_bucket: number;
  last_seen_at: string;
  acknowledgements_count: number;
  latest_status: "nominal" | "updated" | "error" | "rolled_back";
}

export interface ClientMetrics {
  total_registered: number;
  active_last_24h: number;
  by_type: Record<string, number>;
  by_channel: Record<string, number>;
  by_policy_version: Record<string, number>;
  acknowledgements_breakdown: Record<string, number>;
}

export interface ThreatObservationItem {
  id: string;
  raw_url: string;
  redacted_url: string;
  domain: string;
  decision: string;
  confidence_score: number;
  threat_types: string[];
  source: string;
  created_at: string;
}

export interface AuditEventItem {
  event_id: string;
  actor: string;
  action: string;
  target_type: string;
  target_id?: string;
  outcome: string;
  reason?: string;
  metadata?: Record<string, any>;
  client_ip?: string;
  correlation_id?: string;
  created_at: string;
}

export interface AuditQueryResponse {
  events: AuditEventItem[];
  total: number;
  limit: number;
  offset: number;
}

export type GuardianState =
  | "idle"
  | "researching"
  | "analyzing"
  | "defending"
  | "evaluating"
  | "approval_pending"
  | "released"
  | "failed"
  | "rolled_back";

export interface AgentHealthStatus {
  role?: string;
  status: "online" | "degraded" | "offline" | string;
  agent_name?: string;
  model?: string;
  provider_type?: string;
  last_active_at?: string;
  last_heartbeat?: string;
  current_task?: string;
  latency_ms?: number;
  processed_count?: number;
  details?: Record<string, any>;
}

export interface GuardianActivityEvent {
  id?: string;
  event_id?: string;
  mission_id?: string | null;
  step_name?: string;
  stage?: GuardianState | string;
  state?: GuardianState | string;
  message?: string;
  summary?: string;
  actor?: string;
  evidence?: Record<string, any>;
  created_at?: string;
  timestamp?: string;
  event_type?: string;
  details?: Record<string, any>;
}

export interface GuardianDecisionExplanation {
  selected_candidate_id?: string | null;
  selected_candidate_version?: string | null;
  decision_id?: string;
  candidate_id?: string;
  candidate_version?: string;
  outcome?: string;
  threat_priority?: string;
  research_priority?: string;
  candidate_priority?: string;
  expected_detection_benefit?: string;
  false_positive_concerns?: string;
  evaluator_verdict?: string;
  release_recommendation?: string | boolean;
  user_impact?: string;
  confidence: number;
  uncertainty?: string;
  recommended_next_action?: string;
  reasoning_summary: string;
  comparative_analysis?: Record<string, any>;
  created_at?: string;
}

export interface GuardianMissionContract {
  mission_id: string;
  mission_name: string;
  goal: string;
  state: GuardianState | string;
  trigger_source?: string;
  target_family?: string;
  experiment_id?: string;
  candidate_id?: string;
  candidate_version?: string;
  evaluation_id?: string;
  release_id?: string;
  policy_version?: string;
  initial_threat_url?: string;
  initial_decision?: string;
  final_decision?: string;
  benign_control_url?: string;
  benign_control_decision?: string;
  terminal_reason?: string;
  decision_explanation?: GuardianDecisionExplanation;
  timeline?: GuardianActivityEvent[];
  started_at?: string;
  created_at?: string;
  completed_at?: string;
}

export interface GuardianStatusResponse {
  guardian_name?: string;
  version?: string;
  state?: GuardianState | string;
  guardian_state?: GuardianState | string;
  active_mission_id?: string | null;
  agent_health?: Record<string, AgentHealthStatus>;
  agents?: Record<string, AgentHealthStatus>;
  qwen_status?: Record<string, any>;
  active_policy_version?: string;
  total_missions_executed?: number;
  latest_decision?: GuardianDecisionExplanation | null;
  active_mission?: GuardianMissionContract | null;
  registered_clients_count?: number;
  qwen_connected?: boolean;
  qwen_model?: string;
  last_updated?: string;
}


