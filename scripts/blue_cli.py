"""Blue AI Defense Engine Command Line Interface (CLI).

Provides administrative and researcher commands to execute defensive investigations,
formulate declarative rules, run candidate sandbox comparisons, submit for independent
benchmark evaluation, and inspect continuous learning metrics.
"""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from uuid import uuid4

# Add project root and services to path
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "apps" / "api"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "services" / "lab-worker"))
sys.path.insert(0, str(ROOT_DIR / "services" / "evaluator"))

from cyberduel_contracts.enums import Decision, ExpectedClass
from cyberduel_contracts.lab import (
    EvaluationHandoffPackage,
    FailureFinding,
    ScenarioContract,
)
from cyberduel_contracts.policy import (
    CandidateDefense,
)

from apps.api.app.services.blue_ai import (
    BlueResearchAgent,
    CandidateDefenseBuilder,
    CandidateSandboxRunner,
    DefenseHypothesisEngine,
    DefensePrioritizationEngine,
    DefenseProposalGenerator,
    DefensiveResearchService,
    EvaluationHandoffService,
    LearningFeedbackService,
)


def _create_sample_handoff() -> EvaluationHandoffPackage:
    """Generate a realistic synthetic evaluation handoff package for standalone CLI testing."""
    s1_id = uuid4()
    s2_id = uuid4()
    s3_id = uuid4()

    scenarios = [
        ScenarioContract(
            scenario_id=s1_id,
            scenario_family="homograph_mimicry",
            scenario_name="IDN-Paypal-Homoglyph",
            description="Punycode spoofing PayPal with cyrillic 'a'",
            expected_class=ExpectedClass.MALICIOUS.value,
            expected_decision=Decision.BLOCK,
            difficulty="adversarial",
            tags=["homoglyph", "punycode"],
            seed=101,
            generator_version="red-1.0.0",
            input_fixture={
                "raw_url": "https://xn--pypal-4ve.com/signin?verify=account",
                "method": "GET",
            },
            expected_evidence=["homoglyph_spoofing"],
            provenance={"generator": "RedAI"},
            safety_classification="harmless_synthetic",
        ),
        ScenarioContract(
            scenario_id=s2_id,
            scenario_family="homograph_mimicry",
            scenario_name="IDN-Apple-Lookalike",
            description="Punycode spoofing Apple ID login",
            expected_class=ExpectedClass.MALICIOUS.value,
            expected_decision=Decision.BLOCK,
            difficulty="adversarial",
            tags=["homoglyph", "punycode"],
            seed=102,
            generator_version="red-1.0.0",
            input_fixture={
                "raw_url": "https://xn--pple-43d.com/auth/login?session=update",
                "method": "GET",
            },
            expected_evidence=["homoglyph_spoofing"],
            provenance={"generator": "RedAI"},
            safety_classification="harmless_synthetic",
        ),
        ScenarioContract(
            scenario_id=s3_id,
            scenario_family="subdomain_stuffing",
            scenario_name="Deep-Subdomain-Spoof",
            description="Deep multi-label subdomain phishing chain",
            expected_class=ExpectedClass.MALICIOUS.value,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            tags=["subdomains", "evasion"],
            seed=103,
            generator_version="red-1.0.0",
            input_fixture={
                "raw_url": "https://login.verify.account.secure.example-cloud-host.top/auth",
                "method": "GET",
            },
            expected_evidence=["subdomain_stuffing"],
            provenance={"generator": "RedAI"},
            safety_classification="harmless_synthetic",
        ),
    ]

    findings = [
        FailureFinding(
            finding_id=uuid4(),
            experiment_id=uuid4(),
            failure_category="homoglyph_spoofing",
            discrepancy_type="false_negative",
            hypothesis="Baseline detector missed IDN punycode domain spoofing attacks",
            affected_scenarios_count=2,
            representative_scenario_ids=[s1_id, s2_id],
            suggested_remedy="Synthesize declarative rule evaluating is_punycode and phishing keywords",
            severity="critical",
        ),
        FailureFinding(
            finding_id=uuid4(),
            experiment_id=uuid4(),
            failure_category="subdomain_stuffing",
            discrepancy_type="false_negative",
            hypothesis="Deep subdomain nesting bypassed shallow label heuristic checks",
            affected_scenarios_count=1,
            representative_scenario_ids=[s3_id],
            suggested_remedy="Enforce rule on subdomain_count >= 3 with suspicious keyword",
            severity="high",
        ),
    ]

    return EvaluationHandoffPackage(
        handoff_id=uuid4(),
        experiment_id=uuid4(),
        candidate_id=uuid4(),
        detector_version="1.0.0",
        policy_version="1.0.0",
        total_failures=3,
        findings=findings,
        representative_scenarios=scenarios,
        reproduction_config={"seed": 42},
    )


def cmd_research(args: argparse.Namespace) -> None:
    """Ingest findings, cluster detection failures, and prioritize defensive focus."""
    if args.input:
        in_path = Path(args.input)
        if not in_path.exists():
            print(f"[-] Error: Input file '{in_path}' does not exist.")
            sys.exit(1)
        data = json.loads(in_path.read_text(encoding="utf-8"))
        handoff = EvaluationHandoffPackage.model_validate(data)
    else:
        print("[*] No input handoff specified; generating representative Red AI failure package...")
        handoff = _create_sample_handoff()

    print(f"[*] Ingesting evaluation findings for handoff {handoff.handoff_id}...")
    clusters = DefensiveResearchService.cluster_findings(
        findings=handoff.findings,
        scenarios=handoff.representative_scenarios,
    )
    ranked = DefensePrioritizationEngine.rank_clusters(clusters)

    print(f"\n[+] Successfully clustered {len(clusters)} failure groups:")
    for group in ranked:
        sev_str = (
            group.cluster.severity.value
            if hasattr(group.cluster.severity, "value")
            else str(group.cluster.severity)
        )
        print(
            f"    Rank #{group.urgency_rank}: Category='{group.cluster.failure_category}' "
            f"| Severity={sev_str.upper()} "
            f"| Score={group.priority_score:.2f} "
            f"| Affected={group.cluster.affected_count}"
        )
        print(f"       Rationale: {group.rationale}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_data = {
            "handoff_id": str(handoff.handoff_id),
            "total_clusters": len(clusters),
            "top_priority": ranked[0].recommended_focus if ranked else None,
            "ranked_groups": [
                {
                    "cluster_id": g.cluster.cluster_id,
                    "failure_category": g.cluster.failure_category,
                    "target_family": g.cluster.target_family,
                    "discrepancy_type": g.cluster.discrepancy_type,
                    "severity": g.cluster.severity.value
                    if hasattr(g.cluster.severity, "value")
                    else str(g.cluster.severity),
                    "priority_score": g.priority_score,
                    "urgency_rank": g.urgency_rank,
                    "affected_count": g.cluster.affected_count,
                    "rationale": g.rationale,
                }
                for g in ranked
            ],
        }
        out_path.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
        print(f"\n[+] Research task summary saved to: {out_path}")


def cmd_propose(args: argparse.Namespace) -> None:
    """Synthesize hypothesis and declarative defense rule from failure findings."""
    if args.input:
        in_path = Path(args.input)
        data = json.loads(in_path.read_text(encoding="utf-8"))
        handoff = EvaluationHandoffPackage.model_validate(data)
    else:
        handoff = _create_sample_handoff()

    clusters = DefensiveResearchService.cluster_findings(
        findings=handoff.findings,
        scenarios=handoff.representative_scenarios,
    )
    ranked = DefensePrioritizationEngine.rank_clusters(clusters)

    target_group = ranked[0]
    if args.category:
        for g in ranked:
            if g.cluster.failure_category == args.category:
                target_group = g
                break

    print(
        f"[*] Formulating hypothesis for priority gap '{target_group.cluster.failure_category}'..."
    )
    hypothesis = DefenseHypothesisEngine.formulate_hypothesis(
        task_id=uuid4(),
        priority_group=target_group,
    )

    print(f"[+] Hypothesis: {hypothesis.possible_explanation}")
    print(f"    Confidence: {hypothesis.confidence:.2f}")

    print("[*] Synthesizing declarative defense rule...")
    proposal = DefenseProposalGenerator.generate_proposal(hypothesis)
    if proposal.declarative_rule:
        rule = proposal.declarative_rule
        print(f"[+] Synthesized Rule ID: {rule.rule_id}")
        print(f"    Target Action: {rule.action.value.upper()}")
        print(f"    Predicates ({rule.logical_operator}):")
        for p in rule.predicates:
            print(f"      - {p.field} {p.operator} {p.value}")

    candidate = CandidateDefenseBuilder.assemble_candidate([proposal])
    print(f"\n[+] Built Candidate Defense: {candidate.version}")
    print(f"    Rule Digest (SHA-256): {candidate.rule_spec.get('digest')}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(candidate.model_dump(mode="json"), indent=2), encoding="utf-8"
        )
        print(f"[+] Saved candidate defense to: {out_path}")


def cmd_sandbox(args: argparse.Namespace) -> None:
    """Execute isolated side-by-side sandbox comparison between candidate and baseline."""
    in_path = Path(args.candidate)
    if not in_path.exists():
        print(f"[-] Error: Candidate file '{in_path}' does not exist.")
        sys.exit(1)

    candidate_data = json.loads(in_path.read_text(encoding="utf-8"))
    candidate = CandidateDefense.model_validate(candidate_data)

    failing_scenarios = None
    if args.scenarios:
        s_path = Path(args.scenarios)
        if s_path.exists():
            s_data = json.loads(s_path.read_text(encoding="utf-8"))
            failing_scenarios = [ScenarioContract.model_validate(item) for item in s_data]

    print(f"[*] Running Candidate Sandbox comparative audit for {candidate.version}...")
    report = asyncio.run(
        CandidateSandboxRunner.run_comparison(
            candidate=candidate,
            failing_scenarios=failing_scenarios,
        )
    )

    print("\n=== Sandbox Comparative Audit Results ===")
    print(f"Preliminary Verdict: {report.preliminary_verdict.upper()}")
    print(f"Total Scenarios Evaluated: {report.total_scenarios_evaluated}")
    print(
        f"Baseline Accuracy:  {report.baseline_accuracy:.2%} -> Candidate Accuracy:  {report.candidate_accuracy:.2%}"
    )
    print(
        f"Baseline Recall:    {report.baseline_recall:.2%} -> Candidate Recall:    {report.candidate_recall:.2%}"
    )
    print(
        f"Baseline FPR:       {report.baseline_fpr:.2%} -> Candidate FPR:       {report.candidate_fpr:.2%}"
    )
    print(f"Original Failures Resolved: {report.original_failures_resolved}")
    print(f"New Regressions Detected:   {report.new_regressions}")
    print(f"New False Positives:        {report.new_false_positives}")
    print(f"Trade-off Analysis: {report.trade_off_analysis}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
        print(f"\n[+] Saved comparison report to: {out_path}")


def cmd_evaluate(args: argparse.Namespace) -> None:
    """Submit candidate defense to independent benchmark evaluator."""
    in_path = Path(args.candidate)
    if not in_path.exists():
        print(f"[-] Error: Candidate file '{in_path}' does not exist.")
        sys.exit(1)

    candidate_data = json.loads(in_path.read_text(encoding="utf-8"))
    candidate = CandidateDefense.model_validate(candidate_data)

    print(
        f"[*] Submitting candidate {candidate.version} to independent benchmark evaluator (Suite: {args.suite})..."
    )
    handoff_svc = EvaluationHandoffService()
    result = asyncio.run(handoff_svc.submit_candidate(candidate, suite_id=args.suite))

    print("\n=== Independent Benchmark Evaluation Outcome ===")
    print(f"Verdict:           {result.verdict.value.upper()}")
    print(f"Rationale:         {result.verdict_rationale}")
    print(f"Passed Scenarios:  {result.passed_scenarios}/{result.total_scenarios}")
    print(f"Detection Rate:    {result.detection_rate:.2%}")
    print(f"False Pos. Rate:   {result.false_positive_rate:.2%}")
    print(f"Regression Count:  {result.regression_count}")
    print(f"Updated Status:    {candidate.status.value.upper()}")


def cmd_cycle(args: argparse.Namespace) -> None:
    """Execute complete 10-stage Blue AI research-to-evaluation cycle end-to-end."""
    if args.handoff:
        in_path = Path(args.handoff)
        data = json.loads(in_path.read_text(encoding="utf-8"))
        handoff = EvaluationHandoffPackage.model_validate(data)
    else:
        print("[*] Generating representative Red AI failure package for autonomous cycle...")
        handoff = _create_sample_handoff()

    agent = BlueResearchAgent()
    print(
        f"[*] Launching 10-stage autonomous Blue AI defensive cycle on handoff {handoff.handoff_id}..."
    )
    res = asyncio.run(agent.run_cycle(handoff))

    print("\n=== Blue AI Autonomous Cycle Summary ===")
    print(f"Task ID:             {res.task_id}")
    print(f"Candidate Version:   {res.candidate.version}")
    print(f"Target Gap Category: {res.hypothesis.failure_category}")
    print(
        f"Synthesized Rule:    {res.proposal.declarative_rule.rule_id if res.proposal.declarative_rule else 'None'}"
    )
    print(f"Sandbox Verdict:     {res.comparison_report.preliminary_verdict.upper()}")
    print(f"Failures Fixed:      {res.comparison_report.original_failures_resolved}")
    print(f"Regressions:         {res.comparison_report.new_regressions}")
    print(f"Evaluator Verdict:   {res.evaluation_result.verdict.value.upper()}")
    print(f"Evidence Fingerprint:{res.evidence_dossier.get('dossier_fingerprint')}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        summary_data = {
            "summary": res.summary,
            "evidence_dossier": res.evidence_dossier,
            "evaluation_result": res.evaluation_result.model_dump(mode="json"),
        }
        out_path.write_text(json.dumps(summary_data, indent=2), encoding="utf-8")
        print(f"\n[+] Full cycle dossier saved to: {out_path}")


def cmd_status(_args: argparse.Namespace) -> None:
    """Inspect Blue AI learning summary and evaluation metrics."""
    summary = asyncio.run(LearningFeedbackService.get_learning_summary())
    print("\n=== Blue AI Engine & Learning Memory Status ===")
    print(f"Total Evaluations Recorded: {summary['total_feedbacks']}")
    print(f"Approved Candidates:       {summary['approved_candidates']}")
    print(f"Rejected Candidates:       {summary['rejected_candidates']}")
    print(f"Candidate Acceptance Rate: {summary['acceptance_rate']:.2%}")
    print(f"Regressions Observed:      {summary['total_regressions_observed']}")
    print(f"Average Candidate FPR:     {summary['average_candidate_fpr']:.2%}")


def main() -> None:
    """CLI entrypoint and argument parser."""
    parser = argparse.ArgumentParser(
        prog="blue_cli",
        description="CyberDuel AI — Blue AI Defense Engine CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. research
    p_research = subparsers.add_parser(
        "research", help="Ingest findings, cluster gaps, and rank priorities"
    )
    p_research.add_argument("--input", "-i", help="Path to EvaluationHandoffPackage JSON")
    p_research.add_argument("--output", "-o", help="Path to write research task summary JSON")
    p_research.set_defaults(func=cmd_research)

    # 2. propose
    p_propose = subparsers.add_parser(
        "propose", help="Synthesize hypothesis and declarative defense rule"
    )
    p_propose.add_argument("--input", "-i", help="Path to EvaluationHandoffPackage JSON")
    p_propose.add_argument("--category", "-c", help="Target failure category")
    p_propose.add_argument("--output", "-o", help="Path to write candidate defense package JSON")
    p_propose.set_defaults(func=cmd_propose)

    # 3. test-sandbox
    p_sandbox = subparsers.add_parser(
        "test-sandbox", help="Run isolated side-by-side sandbox comparison"
    )
    p_sandbox.add_argument("--candidate", "-c", required=True, help="Path to CandidateDefense JSON")
    p_sandbox.add_argument("--scenarios", "-s", help="Path to scenarios JSON file")
    p_sandbox.add_argument("--output", "-o", help="Path to write comparison report JSON")
    p_sandbox.set_defaults(func=cmd_sandbox)

    # 4. evaluate
    p_eval = subparsers.add_parser(
        "evaluate", help="Submit candidate defense to independent benchmark evaluation"
    )
    p_eval.add_argument("--candidate", "-c", required=True, help="Path to CandidateDefense JSON")
    p_eval.add_argument("--suite", default="curated-golden-v1", help="Evaluation suite ID")
    p_eval.set_defaults(func=cmd_evaluate)

    # 5. cycle
    p_cycle = subparsers.add_parser(
        "cycle", help="Execute complete 10-stage autonomous Blue AI cycle"
    )
    p_cycle.add_argument("--handoff", "-i", help="Path to EvaluationHandoffPackage JSON")
    p_cycle.add_argument("--output", "-o", help="Path to write full cycle dossier JSON")
    p_cycle.set_defaults(func=cmd_cycle)

    # 6. status
    p_status = subparsers.add_parser(
        "status", help="Display Blue AI learning metrics and memory status"
    )
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
