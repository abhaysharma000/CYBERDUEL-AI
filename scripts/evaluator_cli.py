"""CyberDuel AI Independent Evaluation Engine Command Line Interface (CLI).

Provides verification, benchmark auditing, group isolation verification,
and independent evaluation reporting without exposing ground-truth labels.
"""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "apps" / "api"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "services" / "evaluator"))

from cyberduel_contracts.enums import Decision, DefenseStatus
from cyberduel_contracts.evaluation import (
    AcceptancePolicyConfig,
    EvaluationRequest,
)
from cyberduel_contracts.policy import CandidateDefense, DeclarativeRuleModel

from services.evaluator.app.benchmarks import BenchmarkRegistry
from services.evaluator.app.runner import EvaluationRunner


def cmd_list_benchmarks(args: argparse.Namespace) -> None:
    """List registered benchmark manifests."""
    reg = BenchmarkRegistry()
    manifests = reg.list_manifests()

    if args.json:
        print(json.dumps([m.model_dump(mode="json") for m in manifests], indent=2))
        return

    print("=" * 80)
    print("CYBERDUEL AI - REGISTERED BENCHMARK SUITES")
    print("=" * 80)
    for m in manifests:
        print(f"\nManifest ID : {m.manifest_id}")
        print(f"Name        : {m.name} (v{m.version})")
        print(f"Description : {m.description}")
        print(f"Scenarios   : {m.scenario_count} total")
        print(f"Splits      : {m.split_counts}")
        print(f"Families    : {m.family_counts}")
        print(f"Integrity   : SHA-256:{m.integrity_hash[:16]}...")
    print("=" * 80)


def cmd_validate_splits(args: argparse.Namespace) -> None:
    """Verify group isolation and zero leakage across benchmark splits."""
    reg = BenchmarkRegistry()
    manifest = reg.get_manifest(args.manifest_id)
    if not manifest:
        print(f"Error: Manifest '{args.manifest_id}' not found.", file=sys.stderr)
        sys.exit(1)

    is_valid, violations = reg.validate_split_isolation(manifest)

    if args.json:
        print(
            json.dumps(
                {
                    "manifest_id": manifest.manifest_id,
                    "is_isolated": is_valid,
                    "violations": violations,
                },
                indent=2,
            )
        )
        return

    print("=" * 80)
    print(f"SPLIT ISOLATION AUDIT: {manifest.manifest_id}")
    print("=" * 80)
    print(f"Total Scenarios Evaluated: {manifest.scenario_count}")
    print(f"Splits Present: {list(manifest.split_counts.keys())}")
    print("-" * 80)
    if is_valid:
        print("RESULT: PASS - Zero data leakage detected.")
        print("  [OK] No duplicate URLs between any distinct splits.")
        print("  [OK] No group/lineage domain overlap between training and held-out/regression.")
    else:
        print(f"RESULT: FAIL - {len(violations)} leakage violations identified:")
        for v in violations:
            print(f"  [FAIL] {v}")
    print("=" * 80)


async def cmd_evaluate(args: argparse.Namespace) -> None:
    """Run an independent evaluation of a candidate defense against a benchmark suite."""
    reg = BenchmarkRegistry()
    runner = EvaluationRunner(benchmark_registry=reg)

    manifest_id = args.manifest_id or "benchmark-golden-v1"
    manifest = reg.get_manifest(manifest_id)
    if not manifest:
        print(f"Error: Manifest '{manifest_id}' not found.", file=sys.stderr)
        sys.exit(1)

    # Formulate sample candidate defense if none provided via file
    rules: list[DeclarativeRuleModel] = []
    if args.rule_file:
        with open(args.rule_file, encoding="utf-8") as f:
            data = json.load(f)
        rules = [DeclarativeRuleModel.model_validate(r) for r in data]
    else:
        # Default sample rule
        from cyberduel_contracts.enums import ThreatSeverity
        from cyberduel_contracts.policy import RulePredicateModel

        rule = DeclarativeRuleModel(
            rule_id=f"rule-punycode-homograph-{manifest_id[:16]}",
            rule_version="1.0.0",
            description="Flag punycode / homograph mimicked domains",
            purpose="Mitigate punycode homograph mimicry",
            target_family="homograph_mimicry",
            predicates=[
                RulePredicateModel(
                    field="is_punycode",
                    operator="eq",
                    value=True,
                )
            ],
            action=Decision.BLOCK,
            severity=ThreatSeverity.HIGH,
            weight=0.90,
        )
        rules.append(rule)

    candidate = CandidateDefense(
        version=args.version or "0.3.0-candidate-cli",
        author_agent="EvaluatorCLI",
        description=args.description or "CLI test candidate defense",
        rule_spec={"rules": [r.model_dump(mode="json") for r in rules]},
        status=DefenseStatus.CANDIDATE,
    )

    policy = AcceptancePolicyConfig(
        max_allowed_fpr=args.max_fpr,
        max_allowed_regressions=args.max_regressions,
        min_detection_rate=args.min_recall,
    )

    request = EvaluationRequest(
        candidate_id=candidate.defense_id,
        candidate_version=candidate.version,
        benchmark_manifest_version=manifest_id,
        acceptance_policy=policy,
        requested_by="EvaluatorCLI",
    )

    print(
        f"Running independent evaluation for candidate '{candidate.version}' on '{manifest_id}'..."
    )
    report = await runner.run_evaluation(request=request, candidate=candidate, manifest=manifest)

    if args.json:
        print(json.dumps(report.model_dump(mode="json"), indent=2))
        return

    print("=" * 80)
    print("INDEPENDENT EVALUATION ENGINE AUDIT REPORT")
    print("=" * 80)
    print(f"Candidate Version : {report.candidate_version}")
    print(f"Baseline Version  : {report.baseline_version}")
    print(f"Benchmark Suite   : {report.benchmark_manifest_version}")
    print(f"Audit Digest      : SHA-256:{report.report_digest[:16]}...")
    print("-" * 80)
    print(f"FINAL VERDICT     : {report.verdict.value.upper()} ({report.status.value.upper()})")
    print(f"Rationale         : {report.verdict_rationale}")
    print("-" * 80)
    print("CLASSIFICATION PERFORMANCE METRICS:")
    print(f"  * Candidate Recall (Detection Rate) : {report.candidate_metrics.recall:.2%}")
    print(
        f"  * Candidate False Positive Rate     : {report.candidate_metrics.false_positive_rate:.2%}"
    )
    print(f"  * Candidate F1 Score                : {report.candidate_metrics.f1:.4f}")
    print(f"  * Candidate Overall Accuracy        : {report.candidate_metrics.accuracy:.2%}")
    print(
        f"  * Confusion Matrix (TP / FP / TN / FN) : {report.candidate_metrics.tp} / {report.candidate_metrics.fp} / {report.candidate_metrics.tn} / {report.candidate_metrics.fn}"
    )
    print("-" * 80)
    print("DELTA IMPROVEMENTS & REGRESSIONS:")
    print(
        f"  * Target Failures Resolved          : {report.improvement_metrics.original_failures_resolved}"
    )
    print(f"  * New Regressions Introduced        : {report.improvement_metrics.new_regressions}")
    print(
        f"  * New False Positives Introduced    : {report.improvement_metrics.new_false_positives}"
    )
    print(f"  * Delta F1 (Candidate - Baseline)   : {report.improvement_metrics.delta_f1:+.4f}")
    print("-" * 80)
    print("OPERATIONAL IMPACT:")
    print(
        f"  * Mean Latency                      : {report.operational_metrics.mean_latency_ms:.2f} ms"
    )
    print(
        f"  * P95 Latency                       : {report.operational_metrics.p95_latency_ms:.2f} ms"
    )
    print(
        f"  * Audit Errors / Timeouts           : {report.operational_metrics.error_count} / {report.operational_metrics.timeout_count}"
    )
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberDuel AI Independent Evaluation Engine CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: benchmarks
    subparsers.add_parser("benchmarks", help="List registered benchmark manifests")

    # Subcommand: validate-splits
    val_p = subparsers.add_parser(
        "validate-splits", help="Validate split isolation and data leakage"
    )
    val_p.add_argument(
        "--manifest-id",
        type=str,
        default="benchmark-golden-v1",
        help="Benchmark manifest ID",
    )

    # Subcommand: evaluate
    eval_p = subparsers.add_parser(
        "evaluate", help="Audit candidate defense against benchmark suite"
    )
    eval_p.add_argument(
        "--version", type=str, default="0.3.0-candidate-cli", help="Candidate version"
    )
    eval_p.add_argument(
        "--description", type=str, default="CLI candidate defense test", help="Description"
    )
    eval_p.add_argument(
        "--manifest-id", type=str, default="benchmark-golden-v1", help="Benchmark manifest ID"
    )
    eval_p.add_argument(
        "--rule-file", type=str, default=None, help="Path to JSON file with DeclarativeRuleModel"
    )
    eval_p.add_argument("--max-fpr", type=float, default=0.05, help="Maximum allowed FPR")
    eval_p.add_argument(
        "--max-regressions", type=int, default=0, help="Maximum allowed regressions"
    )
    eval_p.add_argument(
        "--min-recall", type=float, default=0.60, help="Minimum required detection rate"
    )

    args = parser.parse_args()

    if args.command == "benchmarks":
        cmd_list_benchmarks(args)
    elif args.command == "validate-splits":
        cmd_validate_splits(args)
    elif args.command == "evaluate":
        asyncio.run(cmd_evaluate(args))


if __name__ == "__main__":
    main()
