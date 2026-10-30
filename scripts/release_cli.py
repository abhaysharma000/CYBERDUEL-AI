"""CyberDuel AI Release Management and Cryptographic Verification CLI.

Enforces release eligibility gates, administrative deployment authorizations,
Ed25519 digital signing, staged rollout advancement, and client-side verification.
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
db_path = (ROOT_DIR / "cyberduel_dev.db").resolve().as_posix()
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")

sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "apps" / "api"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "shared-contracts"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "policy-engine"))
sys.path.insert(0, str(ROOT_DIR / "packages" / "threat-intelligence"))
sys.path.insert(0, str(ROOT_DIR / "services" / "evaluator"))

from cyberduel_contracts.enums import ReleaseChannel, RolloutStage
from sqlalchemy import select

from apps.api.app.db.session import get_engine, get_session_factory
from apps.api.app.models.base import Base
from apps.api.app.models.policies import CandidateDefenseRecord
from apps.api.app.models.releases import ReleaseRecord, RolloutStateRecord
from apps.api.app.services.releases import (
    ClientUpdateVerifier,
    ReleaseApprovalService,
    ReleaseEligibilityService,
    RollbackService,
    RolloutManager,
    SigningKeyManager,
)


async def _ensure_db_schema() -> None:
    """Ensure database schema is initialized for CLI usage."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def cmd_init_keys(args: argparse.Namespace) -> None:
    """Generate or retrieve the primary Ed25519 signing keypair."""
    await _ensure_db_schema()
    key_mgr = SigningKeyManager()
    session_maker = get_session_factory()
    async with session_maker() as session:
        key_record = await key_mgr.get_or_create_primary_key(
            session=session,
            key_id=args.key_id or "cyberduel-prod-2026-k1",
        )
        await session.commit()
        print("=" * 80)
        print("CYBERDUEL AI - SIGNING KEY INITIALIZATION")
        print("=" * 80)
        print(f"Key ID     : {key_record.key_id}")
        print(f"Algorithm  : {key_record.algorithm}")
        print(f"Status     : {key_record.status}")
        print(f"Valid From : {key_record.valid_from.isoformat()}")
        print("\nPublic Key PEM (Trust Anchor):")
        print(key_record.public_key_pem)
        print("=" * 80)


async def cmd_trust_anchors(args: argparse.Namespace) -> None:
    """Display all active and revoked public trust anchors."""
    await _ensure_db_schema()
    key_mgr = SigningKeyManager()
    session_maker = get_session_factory()
    async with session_maker() as session:
        anchors = await key_mgr.get_trust_anchors(session)
        if args.json:
            print(json.dumps(anchors.model_dump(mode="json"), indent=2))
            return

        print("=" * 80)
        print("CYBERDUEL AI - TRUST ANCHORS & REVOCATIONS")
        print("=" * 80)
        print(f"Timestamp: {anchors.timestamp.isoformat()}\n")
        print(f"Active Keys ({len(anchors.active_keys)}):")
        for k in anchors.active_keys:
            print(f"  - Key ID: {k.key_id} | Alg: {k.algorithm} | Valid: {k.valid_from.date()}")
        print(f"\nRevoked Keys ({len(anchors.revoked_keys)}):")
        for k in anchors.revoked_keys:
            print(
                f"  - Key ID: {k.key_id} | Revoked: {k.revoked_at} | Reason: {k.revocation_reason}"
            )
        print("=" * 80)


async def cmd_check_eligibility(args: argparse.Namespace) -> None:
    """Check if a candidate defense satisfies release eligibility criteria."""
    await _ensure_db_schema()
    eligibility_svc = ReleaseEligibilityService()
    session_maker = get_session_factory()
    async with session_maker() as session:
        report = await eligibility_svc.check_eligibility(
            session=session,
            candidate_id=UUID(args.candidate_id),
            evaluation_report_id=UUID(args.report_id),
        )

        if args.json:
            print(json.dumps(report.model_dump(mode="json"), indent=2))
            return

        status_tag = "[OK] ELIGIBLE FOR RELEASE" if report.is_eligible else "[FAIL] INELIGIBLE"
        print("=" * 80)
        print(f"RELEASE ELIGIBILITY REPORT: {status_tag}")
        print("=" * 80)
        print(f"Candidate ID   : {report.candidate_id}")
        print(f"Report ID      : {report.evaluation_report_id}")
        print(f"Verdict        : {report.evaluation_verdict}")
        print("\nDecision Reasons:")
        for r in report.reasons:
            print(f"  - {r}")
        print("\nEvaluation Metrics:")
        for k, v in report.metrics.items():
            print(f"  - {k:22}: {v}")
        print("=" * 80)


async def cmd_authorize(args: argparse.Namespace) -> None:
    """Explicitly authorize, compile, sign, and stage a release."""
    await _ensure_db_schema()
    approval_svc = ReleaseApprovalService()
    session_maker = get_session_factory()
    async with session_maker() as session:
        # Load rule spec from candidate record if available
        cand_stmt = select(CandidateDefenseRecord).where(
            CandidateDefenseRecord.id == UUID(args.candidate_id)
        )
        cand = (await session.execute(cand_stmt)).scalar_one_or_none()
        rule_spec = cand.rule_spec if cand else {"rules": []}

        try:
            rel, auth = await approval_svc.authorize_and_stage_release(
                session=session,
                candidate_id=UUID(args.candidate_id),
                evaluation_report_id=UUID(args.report_id),
                policy_version=args.version,
                target_channel=ReleaseChannel(args.channel),
                authorized_by=args.authorizer,
                rationale=args.rationale,
                rule_spec=rule_spec,
                release_notes=args.notes or f"Release authorized by {args.authorizer}",
            )
            await session.commit()

            print("=" * 80)
            print("[OK] RELEASE AUTHORIZED AND STAGED")
            print("=" * 80)
            print(f"Release ID      : {rel.id}")
            print(f"Policy Version  : {rel.policy_version}")
            print(f"Sequence Number : {rel.sequence_number}")
            print(f"Channel         : {rel.channel}")
            print(f"Status          : {rel.status}")
            print(f"Publisher Key   : {rel.publisher_key_id}")
            print(f"Artifact Digest : SHA-256:{rel.artifact_digest}")
            print(f"Signature       : {rel.signature[:32]}...")
            print(f"Authorized By   : {auth.authorized_by}")
            print(f"Rationale       : {auth.rationale}")
            print("=" * 80)
        except Exception as e:
            await session.rollback()
            print(f"[FAIL] Release authorization rejected: {e}", file=sys.stderr)
            sys.exit(1)


async def cmd_advance(args: argparse.Namespace) -> None:
    """Advance staged rollout progression."""
    await _ensure_db_schema()
    rollout_mgr = RolloutManager()
    session_maker = get_session_factory()
    async with session_maker() as session:
        # Lookup release by ID or version
        try:
            rel_uuid = UUID(args.release)
            stmt = select(ReleaseRecord).where(ReleaseRecord.id == rel_uuid)
        except ValueError:
            stmt = select(ReleaseRecord).where(ReleaseRecord.policy_version == args.release)
        rel = (await session.execute(stmt)).scalar_one_or_none()
        if not rel:
            print(f"[FAIL] Release '{args.release}' not found", file=sys.stderr)
            sys.exit(1)

        target_stage = RolloutStage(args.stage) if args.stage else None
        state = await rollout_mgr.advance_stage(session, rel.id, target_stage=target_stage)
        await session.commit()

        print("=" * 80)
        print("[OK] ROLLOUT ADVANCED")
        print("=" * 80)
        print(f"Release ID   : {state.release_id}")
        print(f"Channel      : {state.channel.value}")
        print(f"Stage        : {state.stage.value}")
        print(f"Coverage     : {state.rollout_percentage:.1f}%")
        print(f"Installs OK  : {state.successful_installs}")
        print(f"Failures     : {state.failed_installs} (rate: {state.failure_rate:.2%})")
        print("=" * 80)


async def cmd_rollback(args: argparse.Namespace) -> None:
    """Trigger an emergency rollback to a known-good policy version."""
    await _ensure_db_schema()
    rollback_svc = RollbackService()
    session_maker = get_session_factory()
    async with session_maker() as session:
        rel_uuid: UUID | None = None
        try:
            rel_uuid = UUID(args.regressed_release)
        except ValueError:
            stmt = select(ReleaseRecord.id).where(
                ReleaseRecord.policy_version == args.regressed_release
            )
            rel_uuid = (await session.execute(stmt)).scalar_one_or_none()

        if not rel_uuid:
            print(
                f"[FAIL] Regressed release '{args.regressed_release}' not found",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            rb_release = await rollback_svc.execute_rollback(
                session=session,
                regressed_release_id=rel_uuid,
                target_version=args.target_version,
                authorized_by=args.authorizer,
                reason=args.reason,
            )
            await session.commit()

            print("=" * 80)
            print("[OK] EMERGENCY ROLLBACK RELEASE CREATED & PUBLISHED")
            print("=" * 80)
            print(f"Rollback Release ID : {rb_release.id}")
            print(f"Rollback Version    : {rb_release.policy_version}")
            print(f"Target Good Version : {rb_release.rollback_target_version}")
            print(f"Monotonic Sequence  : {rb_release.sequence_number}")
            print(f"Mandatory           : {rb_release.is_mandatory}")
            print(f"Channel             : {rb_release.channel}")
            print(f"Status              : {rb_release.status}")
            print(f"Artifact Digest     : SHA-256:{rb_release.artifact_digest}")
            print("=" * 80)
        except Exception as e:
            await session.rollback()
            print(f"[FAIL] Rollback execution failed: {e}", file=sys.stderr)
            sys.exit(1)


async def cmd_verify(args: argparse.Namespace) -> None:
    """Simulate client-side cryptographic and integrity verification."""
    await _ensure_db_schema()
    key_mgr = SigningKeyManager()
    session_maker = get_session_factory()
    async with session_maker() as session:
        anchors = await key_mgr.get_trust_anchors(session)

        # Find release
        try:
            rel_uuid = UUID(args.release)
            stmt = select(ReleaseRecord).where(ReleaseRecord.id == rel_uuid)
        except ValueError:
            stmt = select(ReleaseRecord).where(ReleaseRecord.policy_version == args.release)
        rel = (await session.execute(stmt)).scalar_one_or_none()
        if not rel:
            print(f"[FAIL] Release '{args.release}' not found", file=sys.stderr)
            sys.exit(1)

        # Read artifact bytes from storage
        bundle_path = Path(rel.artifact_path)
        if not bundle_path.exists():
            print(f"[FAIL] Artifact file '{bundle_path}' missing from storage", file=sys.stderr)
            sys.exit(1)
        bundle_bytes = bundle_path.read_bytes()

        # Perform 7-step client verification
        res = ClientUpdateVerifier.verify_update(
            manifest=rel.manifest_payload,
            bundle_bytes=bundle_bytes,
            trust_anchors=anchors,
            client_version=args.client_version or "0.1.0",
            engine_version=args.engine_version or "1.0.0",
            client_platform=args.platform or "browser_extension",
            current_sequence_number=args.current_sequence,
        )

        print("=" * 80)
        if res.is_valid:
            print("[OK] CLIENT UPDATE VERIFICATION PASSED")
            print("=" * 80)
            print("All 7 verification checkpoints passed:")
            print("  1. [OK] Trust anchor authorized (key is active and non-revoked)")
            print("  2. [OK] Ed25519 digital signature verified over canonical manifest")
            print("  3. [OK] Monotonic anti-replay check passed (seq > current)")
            print("  4. [OK] Freshness verified (manifest not expired)")
            print("  5. [OK] Compatibility satisfied (engine, client, platform)")
            print("  6. [OK] Artifact SHA-256 integrity verified")
            print("  7. [OK] Declarative AST schema validated (zero executable code)")
            if res.bundle:
                print(
                    f"\nBundle Details: Version={res.bundle.policy_version}, Rules={len(res.bundle.rules)}"
                )
        else:
            print("[FAIL] CLIENT UPDATE VERIFICATION FAILED")
            print("=" * 80)
            print(f"Error: {res.error}")
        print("=" * 80)


async def cmd_list(args: argparse.Namespace) -> None:
    """List all releases and their rollout states."""
    await _ensure_db_schema()
    session_maker = get_session_factory()
    async with session_maker() as session:
        stmt = (
            select(ReleaseRecord, RolloutStateRecord)
            .outerjoin(RolloutStateRecord, RolloutStateRecord.release_id == ReleaseRecord.id)
            .order_by(ReleaseRecord.sequence_number.desc())
        )
        results = (await session.execute(stmt)).all()

        print("=" * 80)
        print("CYBERDUEL AI - REGISTERED SECURITY POLICY RELEASES")
        print("=" * 80)
        if not results:
            print("No releases found.")
        for rel, rollout in results:
            stage_str = f"{rollout.stage} ({rollout.rollout_percentage:.0f}%)" if rollout else "n/a"
            paused_str = " [PAUSED]" if rollout and rollout.is_paused else ""
            rb_tag = " [ROLLBACK]" if rel.is_rollback else ""
            print(
                f"Seq #{rel.sequence_number:3d} | Ver: {rel.policy_version:18s} | "
                f"Chan: {rel.channel:10s} | Status: {rel.status:10s} | "
                f"Stage: {stage_str}{paused_str}{rb_tag}"
            )
        print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="release_cli.py",
        description="CyberDuel AI Release Management, Cryptographic Signing, and Rollout Controller CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-keys
    p_init = subparsers.add_parser(
        "init-keys", help="Initialize or retrieve primary signing keypair"
    )
    p_init.add_argument("--key-id", default=None, help="Optional explicit key ID")

    # trust-anchors
    p_anchors = subparsers.add_parser(
        "trust-anchors", help="List public trust anchors and revocations"
    )
    p_anchors.add_argument("--json", action="store_true", help="Output JSON")

    # check-eligibility
    p_elig = subparsers.add_parser("check-eligibility", help="Check candidate release eligibility")
    p_elig.add_argument("--candidate-id", required=True, help="Candidate defense UUID")
    p_elig.add_argument("--report-id", required=True, help="Evaluation report UUID")
    p_elig.add_argument("--json", action="store_true", help="Output JSON")

    # authorize
    p_auth = subparsers.add_parser(
        "authorize", help="Authorize, compile, sign, and stage a release"
    )
    p_auth.add_argument("--candidate-id", required=True, help="Candidate defense UUID")
    p_auth.add_argument("--report-id", required=True, help="Evaluation report UUID")
    p_auth.add_argument(
        "--version", required=True, help="Semantic policy version string (e.g. 2026.10.2)"
    )
    p_auth.add_argument(
        "--channel", default="stable", choices=["development", "canary", "stable", "emergency"]
    )
    p_auth.add_argument(
        "--authorizer", required=True, help="Administrator / deployment authority identity"
    )
    p_auth.add_argument(
        "--rationale", required=True, help="Release rationale and audit justification"
    )
    p_auth.add_argument("--notes", default="", help="Optional release notes")

    # advance
    p_adv = subparsers.add_parser("advance", help="Advance staged rollout progression")
    p_adv.add_argument("--release", required=True, help="Release UUID or policy version")
    p_adv.add_argument(
        "--stage",
        choices=["internal", "canary_10", "canary_25", "canary_50", "general_availability"],
    )

    # rollback
    p_rb = subparsers.add_parser("rollback", help="Execute emergency rollback release")
    p_rb.add_argument(
        "--regressed-release", required=True, help="Regressed release UUID or version"
    )
    p_rb.add_argument(
        "--target-version", required=True, help="Target known-good version string to restore"
    )
    p_rb.add_argument("--authorizer", required=True, help="Authorizing security officer")
    p_rb.add_argument("--reason", required=True, help="Detailed justification for rollback")

    # verify
    p_ver = subparsers.add_parser("verify", help="Simulate client-side verification of a release")
    p_ver.add_argument("--release", required=True, help="Release UUID or policy version")
    p_ver.add_argument("--client-version", default="0.1.0")
    p_ver.add_argument("--engine-version", default="1.0.0")
    p_ver.add_argument("--platform", default="browser_extension")
    p_ver.add_argument("--current-sequence", type=int, default=0)

    # list
    subparsers.add_parser("list", help="List all security policy releases")

    args = parser.parse_args()

    commands = {
        "init-keys": cmd_init_keys,
        "trust-anchors": cmd_trust_anchors,
        "check-eligibility": cmd_check_eligibility,
        "authorize": cmd_authorize,
        "advance": cmd_advance,
        "rollback": cmd_rollback,
        "verify": cmd_verify,
        "list": cmd_list,
    }

    fn = commands[args.command]
    asyncio.run(fn(args))


if __name__ == "__main__":
    main()
