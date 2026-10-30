"""Cryptographic key lifecycle management: generation, activation, rotation, revocation, and trust anchors."""

import contextlib
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cyberduel_contracts.crypto import generate_ed25519_keypair
from cyberduel_contracts.enums import KeyStatus
from cyberduel_contracts.releases import SigningKeyMetadata, TrustAnchorSet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.releases import SigningKeyRecord

# Directory where private signing keys are securely isolated on the release authority server.
# NEVER committed to source control, NEVER packaged into client applications.
KEYSTORE_DIR = Path(os.environ.get("CYBERDUEL_KEYSTORE_DIR", "infrastructure/keys"))


class SigningKeyManager:
    """Manages release-signing Ed25519 keypairs, rotation, revocation, and public trust anchors."""

    def __init__(self, keystore_dir: Path | str | None = None) -> None:
        self.keystore_dir = Path(keystore_dir) if keystore_dir else KEYSTORE_DIR
        self.keystore_dir.mkdir(parents=True, exist_ok=True)

    def _private_key_path(self, key_id: str) -> Path:
        # Sanitize key_id to prevent path traversal
        safe_key = "".join(c for c in key_id if c.isalnum() or c in ("-", "_", "."))
        return self.keystore_dir / f"{safe_key}.priv.pem"

    async def get_or_create_primary_key(
        self,
        session: AsyncSession,
        key_id: str = "cyberduel-prod-2026-k1",
    ) -> SigningKeyRecord:
        """Retrieve existing active key or bootstrap a new keypair if none exists."""
        stmt = select(SigningKeyRecord).where(SigningKeyRecord.key_id == key_id)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()

        if record is not None:
            return record

        return await self.generate_and_register_key(session, key_id=key_id)

    async def generate_and_register_key(
        self,
        session: AsyncSession,
        key_id: str | None = None,
        valid_until: datetime | None = None,
    ) -> SigningKeyRecord:
        """Generate a new Ed25519 keypair, store the private key in secure local keystore, and register public key."""
        if not key_id:
            key_id = f"cyberduel-key-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"

        priv_pem, pub_pem = generate_ed25519_keypair()

        # Save private key securely in keystore with restricted permissions
        priv_path = self._private_key_path(key_id)
        priv_path.write_text(priv_pem, encoding="utf-8")
        with contextlib.suppress(AttributeError, PermissionError):
            os.chmod(priv_path, 0o600)

        now = datetime.now(UTC)
        record = SigningKeyRecord(
            key_id=key_id,
            algorithm="ed25519",
            public_key_pem=pub_pem,
            status=KeyStatus.ACTIVE.value,
            valid_from=now,
            valid_until=valid_until,
            revoked_at=None,
            revocation_reason=None,
        )
        session.add(record)
        await session.flush()
        return record

    async def rotate_key(
        self,
        session: AsyncSession,
        old_key_id: str,
        new_key_id: str | None = None,
    ) -> tuple[SigningKeyRecord, SigningKeyRecord]:
        """Rotate an active key: mark old key as rotated and create a new active key."""
        stmt = select(SigningKeyRecord).where(SigningKeyRecord.key_id == old_key_id)
        result = await session.execute(stmt)
        old_record = result.scalar_one_or_none()
        if not old_record:
            raise ValueError(f"Signing key '{old_key_id}' not found for rotation")

        old_record.status = KeyStatus.ROTATED.value
        old_record.valid_until = datetime.now(UTC)

        new_record = await self.generate_and_register_key(session, key_id=new_key_id)
        return old_record, new_record

    async def revoke_key(
        self,
        session: AsyncSession,
        key_id: str,
        reason: str,
    ) -> SigningKeyRecord:
        """Revoke a compromised or retired signing key immediately."""
        stmt = select(SigningKeyRecord).where(SigningKeyRecord.key_id == key_id)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()
        if not record:
            raise ValueError(f"Signing key '{key_id}' not found")

        record.status = KeyStatus.REVOKED.value
        record.revoked_at = datetime.now(UTC)
        record.revocation_reason = reason
        await session.flush()
        return record

    async def get_active_key(self, session: AsyncSession) -> SigningKeyRecord:
        """Get the current active signing key for release publishing."""
        stmt = (
            select(SigningKeyRecord)
            .where(SigningKeyRecord.status == KeyStatus.ACTIVE.value)
            .order_by(SigningKeyRecord.created_at.desc())
        )
        result = await session.execute(stmt)
        record = result.scalars().first()
        if not record:
            return await self.get_or_create_primary_key(session)
        return record

    def load_private_key_pem(self, key_id: str) -> str:
        """Load private key PEM from keystore. Isolated to release signing authority only."""
        priv_path = self._private_key_path(key_id)
        if not priv_path.exists():
            raise FileNotFoundError(
                f"Private signing key for key_id '{key_id}' not found in secure keystore at {priv_path}"
            )
        return priv_path.read_text(encoding="utf-8")

    async def get_trust_anchors(self, session: AsyncSession) -> TrustAnchorSet:
        """Assemble all active and revoked public keys for distribution to edge clients."""
        stmt = select(SigningKeyRecord).order_by(SigningKeyRecord.created_at.asc())
        result = await session.execute(stmt)
        records = list(result.scalars().all())

        active_keys: list[SigningKeyMetadata] = []
        revoked_keys: list[SigningKeyMetadata] = []

        for r in records:
            meta = SigningKeyMetadata(
                key_id=r.key_id,
                algorithm=r.algorithm,
                public_key_pem=r.public_key_pem,
                status=KeyStatus(r.status),
                valid_from=r.valid_from,
                valid_until=r.valid_until,
                revoked_at=r.revoked_at,
                revocation_reason=r.revocation_reason,
            )
            if r.status == KeyStatus.REVOKED.value:
                revoked_keys.append(meta)
            else:
                active_keys.append(meta)

        return TrustAnchorSet(
            active_keys=active_keys,
            revoked_keys=revoked_keys,
            timestamp=datetime.now(UTC),
        )
