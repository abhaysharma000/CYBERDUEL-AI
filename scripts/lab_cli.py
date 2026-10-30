"""Research Laboratory Command Line Interface (CLI).

Provides documented administrative and researcher commands to generate synthetic scenario
corpora, validate schemas, execute adversarial experiments, inspect reports, and reproduce runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cyberduel_contracts.lab import ExperimentConfig, ScenarioContract

from services.lab_worker.app.red_ai.agent import RedResearchAgent
from services.lab_worker.app.red_ai.generator import ScenarioGenerator
from services.lab_worker.app.red_ai.validator import ScenarioValidator


def cmd_generate(args: argparse.Namespace) -> None:
    """Generate a deterministic synthetic scenario corpus."""
    print(f"[*] Generating {args.count} synthetic scenarios (Seed: {args.seed})...")
    generator = ScenarioGenerator(seed=args.seed)
    corpus = generator.generate_corpus(
        count=args.count,
        families=args.families,
        mutation_depth=args.mutation_depth,
        goal=args.goal,
    )
    print(
        f"[+] Successfully generated {len(corpus)} scenarios across {len({s.scenario_family for s in corpus})} families."
    )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        data = [s.model_dump(mode="json") for s in corpus]
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[+] Saved corpus manifest to: {out_path}")


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate a synthetic scenario corpus manifest against strict schema and safety bounds."""
    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[-] Error: Input file '{in_path}' does not exist.")
        sys.exit(1)

    print(f"[*] Loading and validating scenario corpus from '{in_path}'...")
    raw_data = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(raw_data, list):
        print("[-] Error: Manifest must contain a JSON list of scenario objects.")
        sys.exit(1)

    passed = 0
    failed = 0
    for idx, item in enumerate(raw_data):
        try:
            scenario = ScenarioContract.model_validate(item)
            val_res = ScenarioValidator.validate(scenario)
            if val_res.is_valid:
                passed += 1
            else:
                failed += 1
                print(f"[-] Validation error [Item {idx}]: {val_res.error_message}")
        except Exception as e:
            failed += 1
            print(f"[-] Schema parse error [Item {idx}]: {e}")

    print("\n=== Scenario Validation Results ===")
    print(f"  Total inspected: {len(raw_data)}")
    print(f"  Valid scenarios: {passed}")
    print(f"  Failed scenarios: {failed}")
    if failed > 0:
        sys.exit(1)
    print("[+] All scenarios strictly conform to laboratory invariants.")


async def _run_experiment_async(args: argparse.Namespace) -> None:
    config = ExperimentConfig(
        experiment_name=args.name,
        goal=args.goal,
        scenario_count=args.count,
        seed=args.seed,
        selected_families=args.families or [],
        mutation_depth=args.mutation_depth,
        timeout_seconds=getattr(args, "timeout", 60),
    )
    print(f"[*] Initializing Red AI experiment: '{config.experiment_name}'")
    print(f"[*] Goal: {config.goal} | Seed: {config.seed} | Count: {config.scenario_count}")

    agent = RedResearchAgent(session=None)
    summary, handoff, executions = await agent.run_experiment(config)

    print("\n=== Experiment Execution Complete ===")
    print(f"  Experiment ID:      {summary.experiment_id}")
    print(f"  Status:             {summary.status}")
    print(f"  Scenarios Tested:   {summary.executed_count}")
    print(f"  Discrepancies:      {summary.discrepancy_count}")
    print(f"  Failure Findings:   {len(summary.findings)}")
    print(f"  Detector Version:   {summary.detector_version}")
    print(f"  Policy Version:     {summary.policy_version}")

    m = summary.metrics
    print("\n=== Defensive Performance Metrics ===")
    print(f"  Accuracy:           {m.get('accuracy', 0.0):.2%}")
    print(f"  Precision:          {m.get('precision', 0.0):.2%}")
    print(f"  Recall (Detection): {m.get('recall', 0.0):.2%}")
    print(f"  F1 Score:           {m.get('f1', 0.0):.4f}")
    print(f"  False Positive Rate:{m.get('false_positive_rate', 0.0):.2%}")
    print(f"  Avg Latency:        {m.get('average_latency_ms', 0.0):.2f} ms")

    if summary.findings:
        print("\n=== Failure Findings & Hypotheses ===")
        for f in summary.findings:
            print(f"  - [{f.severity.upper()}] {f.failure_category}: {f.hypothesis}")
            print(f"    Suggested Remedy: {f.suggested_remedy}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "summary": summary.model_dump(mode="json"),
            "handoff": handoff.model_dump(mode="json"),
        }
        out_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        print(f"\n[+] Full experiment report and handoff package saved to: {out_path}")


def cmd_run(args: argparse.Namespace) -> None:
    """Execute an adversarial experiment locally."""
    asyncio.run(_run_experiment_async(args))


def cmd_report(args: argparse.Namespace) -> None:
    """Inspect and format a saved experiment report."""
    path = Path(args.file)
    if not path.exists():
        print(f"[-] Error: Report file '{path}' does not exist.")
        sys.exit(1)

    data = json.loads(path.read_text(encoding="utf-8"))
    summary = data.get("summary", data)
    print(f"=== Research Experiment Report: {summary.get('experiment_name')} ===")
    print(f"  Experiment ID:    {summary.get('experiment_id')}")
    print(f"  Goal:             {summary.get('goal')}")
    print(f"  Executed Count:   {summary.get('executed_count')}")
    print(f"  Discrepancies:    {summary.get('discrepancy_count')}")
    m = summary.get("metrics", {})
    print(f"  Accuracy:         {m.get('accuracy', 0.0):.2%}")
    print(f"  Recall:           {m.get('recall', 0.0):.2%}")
    print(f"  FPR:              {m.get('false_positive_rate', 0.0):.2%}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lab_cli",
        description="CyberDuel AI — Red Research Laboratory CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Generate
    gen_parser = subparsers.add_parser("generate", help="Generate synthetic scenario corpus")
    gen_parser.add_argument(
        "--count", type=int, default=100, help="Number of scenarios to generate"
    )
    gen_parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    gen_parser.add_argument("--families", nargs="*", help="Filter to specific scenario families")
    gen_parser.add_argument("--mutation-depth", type=int, default=1, help="Max mutation depth")
    gen_parser.add_argument(
        "--goal", type=str, default="general_exploration", help="Experiment goal"
    )
    gen_parser.add_argument(
        "--output", type=str, help="Destination JSON path for generated manifest"
    )
    gen_parser.set_defaults(func=cmd_generate)

    # 2. Validate
    val_parser = subparsers.add_parser(
        "validate", help="Validate scenario corpus against laboratory constraints"
    )
    val_parser.add_argument(
        "--input", type=str, required=True, help="Path to scenario JSON manifest"
    )
    val_parser.set_defaults(func=cmd_validate)

    # 3. Run
    run_parser = subparsers.add_parser(
        "run", help="Execute an adversarial experiment against defensive engine"
    )
    run_parser.add_argument(
        "--name", type=str, default="Adversarial Exploration Run", help="Experiment name"
    )
    run_parser.add_argument(
        "--goal", type=str, default="General defensive evaluation", help="Experiment goal"
    )
    run_parser.add_argument("--count", type=int, default=50, help="Number of scenarios to evaluate")
    run_parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    run_parser.add_argument("--families", nargs="*", help="Specific scenario families to include")
    run_parser.add_argument(
        "--mutation-depth", type=int, default=1, help="Mutation depth for test scenarios"
    )
    run_parser.add_argument(
        "--output", type=str, help="Destination JSON path for experiment report"
    )
    run_parser.set_defaults(func=cmd_run)

    # 4. Report
    rep_parser = subparsers.add_parser("report", help="Inspect a saved experiment report")
    rep_parser.add_argument(
        "--file", type=str, required=True, help="Path to saved experiment report JSON"
    )
    rep_parser.set_defaults(func=cmd_report)

    # 5. Reproduce
    repro_parser = subparsers.add_parser(
        "reproduce", help="Reproduce a previous experiment from seed"
    )
    repro_parser.add_argument("--seed", type=int, required=True, help="Original seed")
    repro_parser.add_argument("--count", type=int, default=50, help="Number of scenarios")
    repro_parser.add_argument(
        "--name", type=str, default="Reproduced Experiment", help="Experiment name"
    )
    repro_parser.add_argument("--goal", type=str, default="Reproduced experiment run", help="Goal")
    repro_parser.add_argument("--families", nargs="*", help="Specific scenario families")
    repro_parser.add_argument("--mutation-depth", type=int, default=1, help="Mutation depth")
    repro_parser.add_argument("--output", type=str, help="Destination JSON path")
    repro_parser.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
