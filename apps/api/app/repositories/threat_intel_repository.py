"""Repository interface for threat intelligence indicators."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.indicators import ThreatIndicatorRecord


class ThreatIntelRepository:
    """Manages threat intelligence indicator lookups, caching, and persistence."""

    # Built-in local fallback intelligence indicators for offline execution
    _LOCAL_CACHE: dict[str, dict[str, Any]] = {}

    def __init__(self, session: AsyncSession | None = None) -> None:
        self.session = session
        if not self._LOCAL_CACHE:
            self._seed_local_cache()

    @classmethod
    def _seed_local_cache(cls) -> None:
        """Seed default known indicators for local offline defense evaluation."""
        sample_malicious = [
            (
                "url",
                "https://paypal.com@secure-login-account-update.attacker-domain.com/signin",
                "phishing",
                "curated_feed",
                "critical",
            ),
            ("domain", "attacker-domain.com", "phishing", "curated_feed", "high"),
            ("domain", "xn--pypal-4ve.com", "phishing", "curated_feed", "high"),
            ("domain", "microsoft-verify-account.top", "phishing", "curated_feed", "high"),
            ("domain", "amazon-account-billing.work", "phishing", "curated_feed", "high"),
            ("domain", "secure-apple-id-verify.buzz", "phishing", "curated_feed", "high"),
        ]
        for itype, val, classification, source, severity in sample_malicious:
            v_hash = hashlib.sha256(val.encode("utf-8")).hexdigest()
            cls._LOCAL_CACHE[v_hash] = {
                "indicator_type": itype,
                "normalized_value": val,
                "value_hash": v_hash,
                "classification": classification,
                "source": source,
                "severity": severity,
                "confidence": 0.98,
                "verification_status": "verified",
                "observed_at": datetime.now(UTC),
                "expires_at": None,
            }

    async def lookup_by_hashes(self, hashes: list[str]) -> list[dict[str, Any]]:
        """Look up active, verified indicators by their SHA-256 hashes."""
        results: list[dict[str, Any]] = []
        now = datetime.now(UTC)

        # 1. Check in-memory cache first
        for h in hashes:
            if h in self._LOCAL_CACHE:
                cached = self._LOCAL_CACHE[h]
                exp = cached.get("expires_at")
                if exp is None or exp > now:
                    results.append(cached)

        # 2. Check persistent database if session is available
        if self.session is not None:
            try:
                stmt = select(ThreatIndicatorRecord).where(
                    ThreatIndicatorRecord.value_hash.in_(hashes),
                    ThreatIndicatorRecord.verification_status == "verified",
                )
                db_results = (await self.session.execute(stmt)).scalars().all()
                for rec in db_results:
                    if (rec.expires_at is None or rec.expires_at > now) and not any(
                        r["value_hash"] == rec.value_hash for r in results
                    ):
                        results.append(
                            {
                                "indicator_type": rec.indicator_type,
                                "normalized_value": rec.normalized_value,
                                "value_hash": rec.value_hash,
                                "classification": rec.classification,
                                "source": rec.source,
                                "severity": rec.severity,
                                "confidence": rec.confidence,
                                "verification_status": rec.verification_status,
                                "observed_at": rec.observed_at,
                                "expires_at": rec.expires_at,
                            }
                        )
            except Exception:
                pass  # Fall back cleanly to local memory cache if database query fails

        return results

    async def add_indicator(
        self,
        indicator_type: str,
        normalized_value: str,
        classification: str,
        source: str,
        severity: str = "high",
        confidence: float | None = 0.95,
        verification_status: str = "verified",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add an indicator to cache and database idempotently."""
        v_hash = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
        data: dict[str, Any] = {
            "indicator_type": indicator_type,
            "normalized_value": normalized_value,
            "value_hash": v_hash,
            "classification": classification,
            "source": source,
            "severity": severity,
            "confidence": confidence,
            "verification_status": verification_status,
            "observed_at": datetime.now(UTC),
            "expires_at": None,
            "metadata_payload": metadata or {},
        }

        # Update in-memory cache
        self._LOCAL_CACHE[v_hash] = data

        # Persist to database if available
        if self.session is not None:
            stmt = select(ThreatIndicatorRecord).where(
                ThreatIndicatorRecord.value_hash == v_hash,
                ThreatIndicatorRecord.indicator_type == indicator_type,
            )
            existing = (await self.session.execute(stmt)).scalar_one_or_none()
            if existing:
                existing.classification = classification
                existing.source = source
                existing.severity = severity
                existing.confidence = confidence
                existing.verification_status = verification_status
            else:
                record = ThreatIndicatorRecord(
                    id=uuid4(),
                    indicator_type=indicator_type,
                    normalized_value=normalized_value,
                    value_hash=v_hash,
                    classification=classification,
                    source=source,
                    severity=severity,
                    confidence=confidence,
                    verification_status=verification_status,
                    metadata_payload=metadata or {},
                )
                self.session.add(record)
            await self.session.commit()

        return data

    async def count(self) -> int:
        """Return total active indicators."""
        if self.session is not None:
            try:
                stmt = select(func.count(ThreatIndicatorRecord.id))
                val = (await self.session.execute(stmt)).scalar_one()
                if val and val > 0:
                    return int(val)
            except Exception:
                pass
        return len(self._LOCAL_CACHE)
