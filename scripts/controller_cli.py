"""CyberDuel AI Autonomous Self-Improvement Controller Command Line Interface (CLI).

Coordinates bounded Red AI -> Blue AI -> Evaluator self-improvement loops,
tracks progress checkpoints, and displays longitudinal trend reports.
"""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from uuid import UUID

ROOT_DIR = Path(__file__).parent.parent
# Ensure persistent SQLite file for CLI commands if not explicitly provided
db_path = (ROOT_DIR / "cyberduel_dev.db").resolve().as_posix()
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")

sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "apps" / "api"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "services" / "evaluator"))

from apps.api.app.db.session import get_engine, get_session_factory
from apps.api.app.models.base import Base
from apps.api.app.services.improvement.analytics import ImprovementAnalyticsService
from apps.api.app.services.improvement.controller import SelfImprovementController
from apps.api.app.services.improvement.policy import ControllerPolicyConfig


async def _ensure_db_schema() -> None:
    """Ensure database schema is initialized for CLI usage."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def cmd_run_cycle(args: argparse.Namespace) -> None:
    """Run an autonomous self-improvement loop cycle."""
    await _ensure_db_schema()
    config = ControllerPolicyConfig(
        max_candidates_per_cycle=args.max_candidates,
        cycle_timeout_seconds=args.timeout,
        benchmark_manifest_version=args.manifest_id,
    )

    session_maker = get_session_factory()
    async with session_maker() as session:
        controller = SelfImprovementController(session=session)
        print(
            f"Launching Self-Improvement Cycle (max candidates: {args.max_candidates}, timeout: {args.timeout}s)..."
        )
        summary = await controller.execute_cycle(
            config=config,
            trigger_reason=args.reason or "cli_triggered_experiment",
        )

    if args.json:
        print(json.dumps(summary.model_dump(mode="json"), indent=2))
        return

    print("=" * 80)
    print(f"SELF-IMPROVEMENT CYCLE #{summary.cycle_number} COMPLETE")
    print("=" * 80)
    print(f"Cycle ID          : {summary.cycle_id}")
    print(f"Status            : {summary.status.value.upper()}")
    print(f"Trigger Reason    : {summary.trigger_reason}")
    print(f"Execution Time    : {summary.duration_seconds:.2f} seconds")
    print(f"Findings Selected : {summary.findings_selected}")
    print(f"Candidates Tested : {summary.candidates_evaluated}")
    print(f"Accepted Defense  : {summary.accepted_candidate_version or 'None (Rejected)'}")
    print(f"Budget Used       : {summary.budget_used_pct:.1f}%")
    print("-" * 80)
    print(f"Terminal Rationale: {summary.terminal_reason}")
    print("-" * 80)
    print("AUDIT TRAIL CHECKPOINTS:")
    for chk in summary.checkpoints:
        print(f"  Step {chk.step_number:2d}: [{chk.step_name:<24}] -> {json.dumps(chk.details)}")
    print("=" * 80)


async def cmd_list_cycles(args: argparse.Namespace) -> None:
    """List historical self-improvement cycles."""
    await _ensure_db_schema()
    session_maker = get_session_factory()
    async with session_maker() as session:
        cycles = await ImprovementAnalyticsService.list_cycles(session, limit=args.limit)

    if args.json:
        print(json.dumps([c.model_dump(mode="json") for c in cycles], indent=2))
        return

    print("=" * 80)
    print("CYBERDUEL AI - HISTORICAL IMPROVEMENT CYCLES")
    print("=" * 80)
    if not cycles:
        print("No improvement cycles recorded yet.")
        print("=" * 80)
        return

    for c in cycles:
        accepted = c.accepted_candidate_version or "None"
        print(
            f"Cycle #{c.cycle_number:<3} | ID: {str(c.cycle_id)[:8]}.. | "
            f"Status: {c.status.value:<24} | Candidates: {c.candidates_evaluated} | "
            f"Accepted: {accepted:<16} | Duration: {c.duration_seconds:.1f}s"
        )
    print("=" * 80)


async def cmd_cycle_details(args: argparse.Namespace) -> None:
    """Show details and checkpoints for a specific cycle."""
    await _ensure_db_schema()
    cycle_uuid = UUID(args.cycle_id)
    session_maker = get_session_factory()
    async with session_maker() as session:
        summary = await ImprovementAnalyticsService.get_cycle_summary(session, cycle_uuid)

    if not summary:
        print(f"Error: Cycle '{args.cycle_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(summary.model_dump(mode="json"), indent=2))
        return

    print("=" * 80)
    print(f"IMPROVEMENT CYCLE #{summary.cycle_number} DETAILS")
    print("=" * 80)
    print(f"Cycle ID       : {summary.cycle_id}")
    print(f"Status         : {summary.status.value.upper()}")
    print(f"Duration       : {summary.duration_seconds:.2f}s")
    print(f"Accepted       : {summary.accepted_candidate_version or 'None'}")
    print(f"Terminal Reason: {summary.terminal_reason}")
    print("-" * 80)
    print("STEP-BY-STEP CHECKPOINTS:")
    for chk in summary.checkpoints:
        print(f"  Step {chk.step_number:2d}: [{chk.step_name:<22}] ({chk.timestamp.isoformat()})")
        for k, v in chk.details.items():
            print(f"         * {k}: {v}")
    print("=" * 80)


async def cmd_trend_report(args: argparse.Namespace) -> None:
    """Display longitudinal trends across self-improvement cycles."""
    await _ensure_db_schema()
    session_maker = get_session_factory()
    async with session_maker() as session:
        trend = await ImprovementAnalyticsService.get_trend_report(session, limit=args.limit)

    if args.json:
        print(json.dumps(trend.model_dump(mode="json"), indent=2))
        return

    print("=" * 80)
    print("CYBERDUEL AI - SELF-IMPROVEMENT LONGITUDINAL TREND REPORT")
    print("=" * 80)
    print(f"Total Cycles Run             : {trend.total_cycles}")
    print(f"Successful Cycles (Accepted) : {trend.successful_cycles}")
    succ_rate = (trend.successful_cycles / trend.total_cycles) if trend.total_cycles > 0 else 0.0
    print(f"Cycle Success Rate           : {succ_rate:.1%}")
    print(f"Total Candidates Evaluated   : {trend.total_candidates_evaluated}")
    print(f"Total Defenses Promoted      : {trend.total_candidates_accepted}")
    print(f"Cumulative Failures Resolved : {trend.cumulative_failures_resolved}")
    print(f"Mean Cycle Duration          : {trend.mean_cycle_duration_seconds:.2f} seconds")
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberDuel AI Self-Improvement Controller CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: run-cycle
    rc_p = subparsers.add_parser("run-cycle", help="Launch a bounded self-improvement loop cycle")
    rc_p.add_argument("--max-candidates", type=int, default=3, help="Max candidates per cycle")
    rc_p.add_argument("--timeout", type=float, default=90.0, help="Cycle timeout in seconds")
    rc_p.add_argument(
        "--manifest-id", type=str, default="benchmark-golden-v1", help="Benchmark manifest ID"
    )
    rc_p.add_argument(
        "--reason", type=str, default="cli_triggered_experiment", help="Trigger reason"
    )

    # Subcommand: list-cycles
    lc_p = subparsers.add_parser("list-cycles", help="List past improvement cycles")
    lc_p.add_argument("--limit", type=int, default=20, help="Max cycles to return")

    # Subcommand: cycle-details
    cd_p = subparsers.add_parser(
        "cycle-details", help="Inspect step-by-step checkpoints for a cycle"
    )
    cd_p.add_argument("--cycle-id", type=str, required=True, help="Improvement cycle UUID")

    # Subcommand: trend-report
    tr_p = subparsers.add_parser("trend-report", help="View aggregate improvement trends")
    tr_p.add_argument("--limit", type=int, default=20, help="Cycles to include in trend report")

    args = parser.parse_args()

    if args.command == "run-cycle":
        asyncio.run(cmd_run_cycle(args))
    elif args.command == "list-cycles":
        asyncio.run(cmd_list_cycles(args))
    elif args.command == "cycle-details":
        asyncio.run(cmd_cycle_details(args))
    elif args.command == "trend-report":
        asyncio.run(cmd_trend_report(args))


if __name__ == "__main__":
    main()
