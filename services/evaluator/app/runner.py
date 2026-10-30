"""Independent Evaluation Runner executing real candidate detector sandbox on verified benchmarks."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any
from uuid import uuid4

from cyberduel_contracts.evaluation import (
    ConfusionMatrix,
    EvaluationReport,
    EvaluationRequest,
)
from cyberduel_contracts.policy import CandidateDefense, DeclarativeRuleModel
from cyberduel_policy_engine.sandbox import CandidateDetectorSandbox
from cyberduel_threat_intel.scoring import ScoringPolicyConfig

from services.evaluator.app.acceptance import AcceptancePolicyEngine
from services.evaluator.app.benchmarks import BenchmarkManifest, BenchmarkRegistry
from services.evaluator.app.metrics import MetricsEngine

logger = logging.getLogger("evaluator.runner")


class EvaluationRunner:
    """Executes real, leakage-resistant benchmark audits of candidate defenses."""

    def __init__(self, benchmark_registry: BenchmarkRegistry | None = None) -> None:
        self.benchmark_registry = benchmark_registry or BenchmarkRegistry()

    @classmethod
    def _parse_candidate_rules(cls, candidate: CandidateDefense) -> list[DeclarativeRuleModel]:
        """Extract DeclarativeRuleModel objects from CandidateDefense rule_spec."""
        rules_data = candidate.rule_spec.get("rules", [])
        rules: list[DeclarativeRuleModel] = []

        if isinstance(rules_data, list):
            for r_item in rules_data:
                try:
                    if isinstance(r_item, dict):
                        rules.append(DeclarativeRuleModel.model_validate(r_item))
                    elif isinstance(r_item, DeclarativeRuleModel):
                        rules.append(r_item)
                except Exception as e:
                    logger.warning(f"Skipping malformed declarative rule: {e}")

        # Check for legacy regex dictionary (e.g. from Prompt 1 tests)
        if not rules and "regex" in candidate.rule_spec:
            try:
                from cyberduel_contracts.policy import RulePredicateModel

                rule = DeclarativeRuleModel(
                    rule_id=f"rule-{candidate.version[:20]}",
                    rule_version="1.0.0",
                    description=candidate.description,
                    purpose="Legacy Regex Spec Adaptation",
                    target_family="regex_pattern",
                    predicates=[
                        RulePredicateModel(
                            field="raw_url",
                            operator="matches_regex",
                            value=str(candidate.rule_spec["regex"]),
                        )
                    ],
                    weight=0.75,
                )
                rules.append(rule)
            except Exception as e:
                logger.warning(f"Could not adapt regex spec to DeclarativeRuleModel: {e}")

        return rules

    async def run_evaluation(
        self,
        request: EvaluationRequest,
        candidate: CandidateDefense,
        manifest: BenchmarkManifest | None = None,
        baseline_service: Any = None,
    ) -> EvaluationReport:
        """Run independent evaluation of candidate defense against verified benchmark suite."""
        logger.info(
            f"Starting independent evaluation {request.request_id} for candidate {candidate.version}"
        )

        # 1. Resolve benchmark manifest
        if manifest is None:
            manifest = self.benchmark_registry.get_manifest(request.benchmark_manifest_version)
            if manifest is None:
                raise ValueError(
                    f"Benchmark manifest '{request.benchmark_manifest_version}' not found in registry"
                )

        # 2. Instantiate isolated sandbox
        rules = self._parse_candidate_rules(candidate)
        tuning = candidate.rule_spec.get("tuning")
        scoring_config = None
        if tuning and isinstance(tuning, dict):
            warn_val = tuning.get("warn_threshold") or tuning.get("suspicious_threshold") or 0.35
            block_val = tuning.get("block_threshold") or tuning.get("malicious_threshold") or 0.70
            scoring_config = ScoringPolicyConfig(
                warn_threshold=float(warn_val),
                block_threshold=float(block_val),
            )

        sandbox = CandidateDetectorSandbox(
            candidate_rules=rules,
            candidate_scoring_config=scoring_config,
            baseline_service=baseline_service,
        )

        baseline_records: list[dict[str, Any]] = []
        candidate_records: list[dict[str, Any]] = []
        split_records: dict[str, list[dict[str, Any]]] = {}
        durations_ms: list[float] = []
        error_count = 0
        timeout_count = 0

        target_scenario_ids = (
            set(request.target_scenario_ids) if request.target_scenario_ids else None
        )

        # 3. Execute detector across benchmark scenarios (labels remain hidden from candidate)
        for item in manifest.scenarios:
            t0 = time.perf_counter()
            try:
                outcome = await sandbox.evaluate_url(
                    raw_url=item.url,
                    expected_class=item.expected_class.value,
                    expected_decision=item.expected_decision,
                )
                dur_ms = (time.perf_counter() - t0) * 1000.0
                durations_ms.append(dur_ms)

                b_entry = {
                    "scenario_id": item.scenario_id,
                    "url": item.url,
                    "expected_class": item.expected_class,
                    "expected_decision": item.expected_decision,
                    "scenario_family": item.scenario_family,
                    "split": item.split.value,
                    "actual_decision": outcome.baseline_decision,
                    "threat_score": outcome.baseline_score,
                }
                c_entry = {
                    "scenario_id": item.scenario_id,
                    "url": item.url,
                    "expected_class": item.expected_class,
                    "expected_decision": item.expected_decision,
                    "scenario_family": item.scenario_family,
                    "split": item.split.value,
                    "actual_decision": outcome.candidate_decision,
                    "threat_score": outcome.candidate_score,
                }

                baseline_records.append(b_entry)
                candidate_records.append(c_entry)
                split_records.setdefault(item.split.value, []).append(c_entry)

            except Exception as ex:
                logger.error(f"Error evaluating scenario {item.scenario_id} ({item.url}): {ex}")
                error_count += 1
                dur_ms = (time.perf_counter() - t0) * 1000.0
                durations_ms.append(dur_ms)

        # 4. Compute metrics
        baseline_metrics = MetricsEngine.compute_confusion_matrix(baseline_records)
        candidate_metrics = MetricsEngine.compute_confusion_matrix(candidate_records)

        split_metrics: dict[str, ConfusionMatrix] = {}
        for split_key, c_split_entries in split_records.items():
            split_metrics[split_key] = MetricsEngine.compute_confusion_matrix(c_split_entries)

        improvement_metrics = MetricsEngine.compute_improvement_metrics(
            baseline_records=baseline_records,
            candidate_records=candidate_records,
            target_scenario_ids=target_scenario_ids,
        )

        operational_metrics = MetricsEngine.compute_operational_metrics(
            durations_ms=durations_ms,
            error_count=error_count,
            timeout_count=timeout_count,
        )

        # 5. Acceptance Policy Gate Evaluation
        verdict, status, rationale, acceptance_reasons, rejection_reasons = (
            AcceptancePolicyEngine.evaluate(
                candidate=candidate,
                candidate_metrics=candidate_metrics,
                baseline_metrics=baseline_metrics,
                split_metrics=split_metrics,
                improvement_metrics=improvement_metrics,
                operational_metrics=operational_metrics,
                policy=request.acceptance_policy,
            )
        )

        # 6. Generate cryptographic digest of report
        report_payload = {
            "request_id": str(request.request_id),
            "candidate_id": str(request.candidate_id),
            "candidate_version": request.candidate_version,
            "verdict": verdict.value,
            "candidate_metrics": candidate_metrics.model_dump(),
            "operational_metrics": operational_metrics.model_dump(),
            "improvement_metrics": improvement_metrics.model_dump(),
        }
        report_digest = hashlib.sha256(
            json.dumps(report_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return EvaluationReport(
            report_id=uuid4(),
            request_id=request.request_id,
            candidate_id=request.candidate_id,
            candidate_version=candidate.version,
            baseline_version=request.baseline_detector_version,
            benchmark_manifest_version=manifest.manifest_id,
            verdict=verdict,
            status=status,
            verdict_rationale=rationale,
            acceptance_reasons=acceptance_reasons,
            rejection_reasons=rejection_reasons,
            baseline_metrics=baseline_metrics,
            candidate_metrics=candidate_metrics,
            split_metrics=split_metrics,
            improvement_metrics=improvement_metrics,
            operational_metrics=operational_metrics,
            report_digest=report_digest,
        )
