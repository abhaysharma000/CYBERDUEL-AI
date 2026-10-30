"""Service verifying candidate defense eligibility for release consideration based on genuine evaluation reports."""

from datetime import UTC, datetime
from uuid import UUID

from cyberduel_contracts.enums import EvaluationVerdict
from cyberduel_contracts.releases import ReleaseEligibilityReport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.evaluations import EvaluationReportRecord
from apps.api.app.models.policies import CandidateDefenseRecord


class ReleaseEligibilityService:
    """Verifies that candidate defenses have genuinely passed independent evaluation before release consideration."""

    MAX_PERMISSIBLE_FPR = 0.05
    MIN_PERMISSIBLE_ACCURACY = 0.80
    MAX_PERMISSIBLE_REGRESSIONS = 0

    async def check_eligibility(
        self,
        session: AsyncSession,
        candidate_id: UUID,
        evaluation_report_id: UUID,
    ) -> ReleaseEligibilityReport:
        """Inspect the evaluation report and candidate defense to verify release eligibility.

        Rule: Passing evaluation makes a candidate eligible for release consideration.
        It does not automatically authorize production deployment.
        """
        reasons: list[str] = []

        # 1. Fetch Candidate Defense Record
        cand_stmt = select(CandidateDefenseRecord).where(CandidateDefenseRecord.id == candidate_id)
        cand_result = await session.execute(cand_stmt)
        candidate = cand_result.scalar_one_or_none()

        if candidate is None:
            return ReleaseEligibilityReport(
                candidate_id=candidate_id,
                evaluation_report_id=evaluation_report_id,
                is_eligible=False,
                evaluation_verdict="not_found",
                reasons=[f"Candidate defense '{candidate_id}' does not exist"],
                metrics={},
                checked_at=datetime.now(UTC),
            )

        # 2. Fetch Evaluation Report Record
        eval_stmt = select(EvaluationReportRecord).where(
            EvaluationReportRecord.id == evaluation_report_id
        )
        eval_result = await session.execute(eval_stmt)
        report = eval_result.scalar_one_or_none()

        if report is None:
            return ReleaseEligibilityReport(
                candidate_id=candidate_id,
                evaluation_report_id=evaluation_report_id,
                is_eligible=False,
                evaluation_verdict="not_found",
                reasons=[f"Evaluation report '{evaluation_report_id}' does not exist"],
                metrics={},
                checked_at=datetime.now(UTC),
            )

        # 3. Verify Candidate linkage
        if report.candidate_id != candidate_id:
            reasons.append(
                f"Evaluation report targets candidate '{report.candidate_id}', not '{candidate_id}'"
            )

        # 4. Check Evaluation Verdict
        verdict = report.verdict.lower()
        if verdict != EvaluationVerdict.PASS.value and verdict != "accepted":
            reasons.append(
                f"Evaluation report verdict is '{verdict}', required is '{EvaluationVerdict.PASS.value}'"
            )

        # 5. Check Quantitative Acceptance Criteria from candidate_metrics and improvement_metrics
        cand_metrics = report.candidate_metrics or {}
        imp_metrics = report.improvement_metrics or {}

        accuracy = float(cand_metrics.get("accuracy", 0.0))
        recall = float(cand_metrics.get("recall", 0.0))
        fpr = float(cand_metrics.get("false_positive_rate", 0.0))
        f1 = float(cand_metrics.get("f1_score", 0.0))
        regressions = int(imp_metrics.get("regression_count", 0))

        metrics_summary = {
            "accuracy": accuracy,
            "recall": recall,
            "false_positive_rate": fpr,
            "f1_score": f1,
            "regressions_detected": regressions,
            "benchmark_manifest_id": report.benchmark_manifest_id,
        }

        if regressions > self.MAX_PERMISSIBLE_REGRESSIONS:
            reasons.append(
                f"Candidate introduced {regressions} regressions (max allowed: {self.MAX_PERMISSIBLE_REGRESSIONS})"
            )

        if fpr > self.MAX_PERMISSIBLE_FPR:
            reasons.append(
                f"Candidate false positive rate ({fpr:.4f}) exceeds threshold ({self.MAX_PERMISSIBLE_FPR})"
            )

        if accuracy < self.MIN_PERMISSIBLE_ACCURACY:
            reasons.append(
                f"Candidate accuracy ({accuracy:.4f}) is below minimum threshold ({self.MIN_PERMISSIBLE_ACCURACY})"
            )

        # 6. Verify Candidate rule specification contains non-empty declarative content
        rule_spec = candidate.rule_spec or {}
        if not rule_spec:
            reasons.append("Candidate rule specification is empty")

        is_eligible = len(reasons) == 0
        return ReleaseEligibilityReport(
            candidate_id=candidate_id,
            evaluation_report_id=evaluation_report_id,
            is_eligible=is_eligible,
            evaluation_verdict=verdict,
            reasons=reasons
            if not is_eligible
            else ["All benchmark and regression criteria satisfied"],
            metrics=metrics_summary,
            checked_at=datetime.now(UTC),
        )
