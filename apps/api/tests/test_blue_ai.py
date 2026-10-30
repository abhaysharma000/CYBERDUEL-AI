"""Unit and integration tests for Blue AI Defense Engine services and components."""

from uuid import uuid4

import pytest
from cyberduel_contracts.enums import (
    Decision,
    DefenseStatus,
    EvaluationVerdict,
    ExpectedClass,
    ProposalType,
)
from cyberduel_contracts.evaluation import EvaluationResult
from cyberduel_contracts.lab import (
    EvaluationHandoffPackage,
    FailureFinding,
    ScenarioContract,
)
from cyberduel_contracts.policy import (
    CandidateDefense,
    DeclarativeRuleModel,
    DefenseProposal,
    DefensiveHypothesis,
    RulePredicateModel,
)

from apps.api.app.services.blue_ai import (
    BlueResearchAgent,
    CandidateDefenseBuilder,
    CandidateSandboxRunner,
    DefenseEvidenceService,
    DefenseHypothesisEngine,
    DefensePrioritizationEngine,
    DefenseProposalGenerator,
    DefensiveResearchService,
    EvaluationHandoffService,
    FailureCluster,
    LearningFeedbackService,
)


@pytest.fixture
def sample_handoff() -> EvaluationHandoffPackage:
    s1_id = uuid4()
    s2_id = uuid4()
    scenarios = [
        ScenarioContract(
            scenario_id=s1_id,
            scenario_family="homograph_mimicry",
            scenario_name="IDN-Paypal-Phish",
            description="Punycode spoofing PayPal",
            expected_class=ExpectedClass.MALICIOUS.value,
            expected_decision=Decision.BLOCK,
            difficulty="adversarial",
            tags=["homoglyph", "punycode"],
            seed=1,
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
            scenario_family="direct_ip_evasion",
            scenario_name="Direct-IP-Drop",
            description="Numeric IP malware landing page",
            expected_class=ExpectedClass.MALICIOUS.value,
            expected_decision=Decision.BLOCK,
            difficulty="intermediate",
            tags=["ip", "direct"],
            seed=2,
            generator_version="red-1.0.0",
            input_fixture={
                "raw_url": "http://192.168.1.1/malware/download.exe",
                "method": "GET",
            },
            expected_evidence=["ip_literal"],
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
            hypothesis="Baseline detector allowed IDN punycode domain spoofing attack",
            affected_scenarios_count=10,
            representative_scenario_ids=[s1_id],
            suggested_remedy="Synthesize declarative rule evaluating is_punycode",
            severity="critical",
        ),
        FailureFinding(
            finding_id=uuid4(),
            experiment_id=uuid4(),
            failure_category="direct_ip_evasion",
            discrepancy_type="false_negative",
            hypothesis="Baseline detector missed direct-IP drop",
            affected_scenarios_count=3,
            representative_scenario_ids=[s2_id],
            suggested_remedy="Add rule on is_ip_literal",
            severity="high",
        ),
    ]

    return EvaluationHandoffPackage(
        handoff_id=uuid4(),
        experiment_id=uuid4(),
        candidate_id=uuid4(),
        detector_version="1.0.0",
        policy_version="1.0.0",
        total_failures=13,
        findings=findings,
        representative_scenarios=scenarios,
        reproduction_config={"seed": 42},
    )


def test_prioritization_engine_ranks_severity_and_prevalence() -> None:
    c_critical = FailureCluster(
        cluster_id="c1",
        failure_category="homoglyph_spoofing",
        target_family="homograph_mimicry",
        discrepancy_type="false_negative",
        severity="critical",
        affected_count=20,
    )
    c_low = FailureCluster(
        cluster_id="c2",
        failure_category="minor_typo",
        target_family="typosquatting",
        discrepancy_type="false_positive",
        severity="low",
        affected_count=1,
    )

    ranked = DefensePrioritizationEngine.rank_clusters([c_low, c_critical])
    assert len(ranked) == 2
    assert ranked[0].cluster.failure_category == "homoglyph_spoofing"
    assert ranked[0].priority_score > ranked[1].priority_score
    assert ranked[0].urgency_rank == 1


def test_prioritization_engine_applies_historical_rejection_penalty() -> None:
    c1 = FailureCluster(
        cluster_id="c1",
        failure_category="subdomain_stuffing",
        target_family="subdomains",
        discrepancy_type="false_negative",
        severity="high",
        affected_count=5,
    )

    score_normal, _ = DefensePrioritizationEngine.score_cluster(c1)
    score_penalized, rationale = DefensePrioritizationEngine.score_cluster(
        c1, negative_feedback_categories={"subdomain_stuffing"}
    )

    assert score_penalized < score_normal
    assert "HistoricalRejectionPenalty" in rationale


def test_research_service_clusters_findings(sample_handoff: EvaluationHandoffPackage) -> None:
    clusters = DefensiveResearchService.cluster_findings(
        findings=sample_handoff.findings,
        scenarios=sample_handoff.representative_scenarios,
    )
    assert len(clusters) == 2
    cats = {c.failure_category for c in clusters}
    assert "homoglyph_spoofing" in cats
    assert "direct_ip_evasion" in cats


def test_hypothesis_engine_formulates_valid_hypothesis(
    sample_handoff: EvaluationHandoffPackage,
) -> None:
    clusters = DefensiveResearchService.cluster_findings(
        findings=sample_handoff.findings,
        scenarios=sample_handoff.representative_scenarios,
    )
    ranked = DefensePrioritizationEngine.rank_clusters(clusters)
    top = ranked[0]

    hypothesis = DefenseHypothesisEngine.formulate_hypothesis(
        task_id=uuid4(),
        priority_group=top,
    )

    assert isinstance(hypothesis, DefensiveHypothesis)
    assert hypothesis.failure_category == top.cluster.failure_category
    assert hypothesis.confidence >= 0.75
    assert len(hypothesis.counterexamples) > 0
    assert "predicates" in hypothesis.proposed_intervention


def test_proposal_generator_synthesizes_safe_declarative_rule() -> None:
    hypothesis = DefensiveHypothesis(
        hypothesis_id=uuid4(),
        research_task_id=uuid4(),
        failure_category="homoglyph_spoofing",
        target_family="homograph_mimicry",
        observed_behavior="Baseline allowed punycode phishing attack",
        expected_behavior="Expected BLOCK decision",
        possible_explanation="Detector ignored punycode prefix",
        supporting_evidence=[{"url": "https://xn--pypal-4ve.com/signin"}],
        counterexamples=[{"url": "https://google.com"}],
        proposed_intervention={
            "proposal_type": "declarative_rule",
            "target_action": "block",
            "predicates": [
                {"field": "is_punycode", "operator": "eq", "value": 1},
                {"field": "phish_keyword_count", "operator": "gte", "value": 1},
            ],
            "logical_operator": "AND",
            "recommended_weight": 0.88,
        },
        predicted_benefit="Intercepts 95%+ of IDN spoofing",
        potential_risks="Low risk on ASCII URLs",
        test_plan="Run benchmark evaluation",
        confidence=0.88,
    )

    proposal = DefenseProposalGenerator.generate_proposal(hypothesis)
    assert isinstance(proposal, DefenseProposal)
    assert proposal.proposal_type == ProposalType.DECLARATIVE_RULE
    assert proposal.declarative_rule is not None
    assert proposal.declarative_rule.action == Decision.BLOCK
    assert len(proposal.declarative_rule.predicates) == 2


def test_candidate_builder_assembles_versioned_package() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-BLUE-TEST-1",
        description="Test rule",
        author="BlueAI",
        purpose="Testing",
        target_family="test",
        feature_names=["is_punycode"],
        predicates=[RulePredicateModel(field="is_punycode", operator="eq", value=1)],
        action=Decision.BLOCK,
    )
    proposal = DefenseProposal(
        hypothesis_id=uuid4(),
        proposal_type=ProposalType.DECLARATIVE_RULE,
        title="Test Proposal",
        rationale="Test Rationale",
        declarative_rule=rule,
    )

    candidate = CandidateDefenseBuilder.assemble_candidate(
        proposals=[proposal],
        baseline_version="1.0.0",
        candidate_sequence=5,
    )

    assert isinstance(candidate, CandidateDefense)
    assert candidate.version == "v1.0.0-blue.005"
    assert candidate.status == DefenseStatus.CANDIDATE
    assert "digest" in candidate.rule_spec
    assert len(candidate.rule_spec["rules"]) == 1


@pytest.mark.asyncio
async def test_candidate_sandbox_runs_comparative_audit() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-BLUE-HOMOGLYPH-TEST",
        description="Block punycode with keyword",
        author="BlueAI",
        purpose="Homoglyph defense",
        target_family="homograph_mimicry",
        feature_names=["is_punycode", "phish_keyword_count"],
        predicates=[
            RulePredicateModel(field="is_punycode", operator="eq", value=1),
            RulePredicateModel(field="phish_keyword_count", operator="gte", value=1),
        ],
        action=Decision.BLOCK,
    )
    proposal = DefenseProposal(
        hypothesis_id=uuid4(),
        proposal_type=ProposalType.DECLARATIVE_RULE,
        title="Homoglyph Rule",
        rationale="Fix homoglyph evasion",
        declarative_rule=rule,
    )
    candidate = CandidateDefenseBuilder.assemble_candidate([proposal])

    failing_scenario = ScenarioContract(
        scenario_id=uuid4(),
        scenario_family="homograph_mimicry",
        scenario_name="Paypal-Punycode-Attack",
        description="Attacking Paypal with cyrillic a",
        expected_class=ExpectedClass.MALICIOUS.value,
        expected_decision=Decision.BLOCK,
        generator_version="red-generator-1.0.0",
        input_fixture={"raw_url": "https://xn--pypal-4ve.com/signin?verify=account"},
    )

    report = await CandidateSandboxRunner.run_comparison(
        candidate=candidate,
        failing_scenarios=[failing_scenario],
    )

    assert report.total_scenarios_evaluated > 0
    assert report.new_regressions == 0
    assert report.candidate_fpr <= 0.05
    assert report.preliminary_verdict in {"promoted_for_evaluation", "inconclusive"}


def test_evidence_service_compiles_fingerprinted_dossier() -> None:
    rule = DeclarativeRuleModel(
        rule_id="RULE-BLUE-TEST",
        description="Test",
        author="BlueAI",
        purpose="Test",
        target_family="test",
        feature_names=["is_punycode"],
        predicates=[RulePredicateModel(field="is_punycode", operator="eq", value=1)],
        action=Decision.BLOCK,
    )
    proposal = DefenseProposal(
        hypothesis_id=uuid4(),
        proposal_type=ProposalType.DECLARATIVE_RULE,
        title="Proposal 1",
        rationale="Rationale 1",
        declarative_rule=rule,
    )
    candidate = CandidateDefenseBuilder.assemble_candidate([proposal])
    hyp = DefensiveHypothesis(
        hypothesis_id=uuid4(),
        research_task_id=uuid4(),
        failure_category="test_cat",
        target_family="test_fam",
        observed_behavior="Observed",
        expected_behavior="Expected",
        possible_explanation="Expl",
        predicted_benefit="Benefit",
        potential_risks="Risks",
        test_plan="Test plan",
    )

    from datetime import UTC, datetime

    from cyberduel_contracts.policy import BaselineComparisonReport

    comp = BaselineComparisonReport(
        candidate_id=candidate.defense_id,
        candidate_version=candidate.version,
        baseline_version="1.0.0",
        total_scenarios_evaluated=10,
        baseline_accuracy=0.8,
        candidate_accuracy=0.9,
        baseline_recall=0.8,
        candidate_recall=0.9,
        baseline_fpr=0.01,
        candidate_fpr=0.01,
        baseline_f1=0.88,
        candidate_f1=0.94,
        original_failures_resolved=2,
        new_regressions=0,
        new_false_positives=0,
        trade_off_analysis="Tradeoff",
        preliminary_verdict="promoted_for_evaluation",
        created_at=datetime.now(UTC),
    )

    dossier = DefenseEvidenceService.compile_dossier(
        candidate=candidate,
        hypotheses=[hyp],
        proposals=[proposal],
        comparison=comp,
    )

    assert "dossier_fingerprint" in dossier
    assert len(dossier["dossier_fingerprint"]) == 64
    assert dossier["safety_verification_checklist"]["safe_declarative_rules_only"] is True
    assert dossier["safety_verification_checklist"]["production_mutation_prohibited"] is True


@pytest.mark.asyncio
async def test_evaluation_handoff_and_learning_feedback() -> None:
    candidate = CandidateDefense(
        version="v1.0.0-cand.001",
        author_agent="BlueAI-v1",
        description="Candidate for testing",
        rule_spec={"rules": []},
    )

    handoff_svc = EvaluationHandoffService()
    result = await handoff_svc.submit_candidate(candidate)

    assert isinstance(result, EvaluationResult)
    assert result.verdict in {EvaluationVerdict.PASS, EvaluationVerdict.FAIL}
    assert candidate.status in {DefenseStatus.APPROVED, DefenseStatus.REJECTED}

    feedback = await LearningFeedbackService.record_feedback(candidate, result)
    assert feedback.candidate_id == candidate.defense_id
    assert feedback.evaluator_verdict == result.verdict

    summary = await LearningFeedbackService.get_learning_summary()
    assert summary["total_feedbacks"] >= 1


@pytest.mark.asyncio
async def test_blue_research_agent_end_to_end_cycle(
    sample_handoff: EvaluationHandoffPackage,
) -> None:
    agent = BlueResearchAgent()
    res = await agent.run_cycle(sample_handoff)

    assert res.task_id is not None
    assert res.candidate is not None
    assert res.hypothesis is not None
    assert res.proposal is not None
    assert res.comparison_report is not None
    assert res.evaluation_result is not None
    assert res.feedback is not None
    assert "dossier_fingerprint" in res.evidence_dossier
