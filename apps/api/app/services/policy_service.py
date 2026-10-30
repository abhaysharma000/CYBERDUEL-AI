"""Service for generating and verifying edge protection policy bundles."""

from __future__ import annotations

from cyberduel_policy_engine.exporter import (
    LocalProtectionPolicyBundle,
    PolicyBundleExporter,
)


class PolicyService:
    """Provides exportable defensive policy bundles for browser extensions and mobile apps."""

    @classmethod
    def export_active_policy(
        cls,
        policy_version: str = "2026.10.1",
        ttl_days: int = 14,
    ) -> LocalProtectionPolicyBundle:
        """Compile and return the active policy bundle with verified integrity digest."""
        # Baseline whitelisted and blacklisted domain seeds
        whitelisted = [
            "google.com",
            "apple.com",
            "microsoft.com",
            "amazon.com",
            "github.com",
            "cloudflare.com",
        ]
        blacklisted = [
            "attacker-domain.com",
            "xn--pypal-4ve.com",
            "microsoft-verify-account.top",
            "amazon-account-billing.work",
            "secure-apple-id-verify.buzz",
        ]

        return PolicyBundleExporter.create_bundle(
            policy_version=policy_version,
            ttl_days=ttl_days,
            blacklisted_domains=blacklisted,
            whitelisted_domains=whitelisted,
        )
