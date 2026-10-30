"""Cryptographic utilities, Ed25519 digital signatures, and RFC-compliant canonical serialization."""

import hashlib
import json
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel


def _normalize_for_canonicalization(obj: Any) -> Any:
    """Recursively normalize objects into pure JSON-serializable types with consistent representations."""
    if isinstance(obj, BaseModel):
        return _normalize_for_canonicalization(obj.model_dump(mode="json"))
    if isinstance(obj, dict):
        return {
            str(k): _normalize_for_canonicalization(v)
            for k, v in sorted(obj.items(), key=lambda item: str(item[0]))
        }
    if isinstance(obj, (list, tuple, set)):
        return [_normalize_for_canonicalization(item) for item in obj]
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        if isinstance(obj, datetime):
            obj = obj.replace(tzinfo=UTC) if obj.tzinfo is None else obj.astimezone(UTC)
            return obj.isoformat().replace("+00:00", "Z")
        return obj.isoformat()
    if isinstance(obj, str) and obj.endswith("+00:00"):
        return obj[:-6] + "Z"
    return obj


def canonicalize_json(data: Any) -> bytes:
    """Serialize arbitrary data structures into canonical deterministic UTF-8 JSON bytes (RFC 8785 subset).

    Keys are sorted recursively, compact separators without whitespace (',', ':') are used,
    and numbers/strings/booleans are standard JSON.
    """
    normalized = _normalize_for_canonicalization(data)
    json_str = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return json_str.encode("utf-8")


def compute_sha256(data: bytes | str) -> str:
    """Compute standard lowercase SHA-256 hexadecimal digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_canonical_sha256(data: Any) -> str:
    """Canonicalize JSON data and compute its SHA-256 digest."""
    return compute_sha256(canonicalize_json(data))


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 signing keypair in PEM format.

    Returns:
        (private_key_pem, public_key_pem)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def sign_detached(private_key_pem: str, data: bytes) -> str:
    """Generate a detached Ed25519 signature over arbitrary binary data.

    Returns:
        Hexadecimal encoded signature string (128 hex chars / 64 bytes).
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Provided private key is not an Ed25519 private key")

    signature_bytes = private_key.sign(data)
    return signature_bytes.hex()


def verify_detached(public_key_pem: str, data: bytes, signature_hex: str) -> bool:
    """Verify a detached Ed25519 signature against data.

    Returns:
        True if the signature is valid, False if invalid or malformed.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
        )
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False

        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(signature_bytes, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def get_manifest_signing_payload(manifest_data: dict[str, Any]) -> bytes:
    """Extract deterministic canonical bytes of a manifest, excluding the signature itself."""
    payload = {k: v for k, v in manifest_data.items() if k != "signature"}
    return canonicalize_json(payload)


def sign_manifest(manifest_data: dict[str, Any], private_key_pem: str) -> str:
    """Canonicalize manifest data (excluding existing signature field) and sign with Ed25519."""
    canonical_bytes = get_manifest_signing_payload(manifest_data)
    return sign_detached(private_key_pem, canonical_bytes)


def verify_manifest(
    manifest_data: dict[str, Any],
    signature_hex: str,
    public_key_pem: str,
) -> bool:
    """Canonicalize manifest data (excluding existing signature) and verify Ed25519 signature."""
    canonical_bytes = get_manifest_signing_payload(manifest_data)
    return verify_detached(public_key_pem, canonical_bytes, signature_hex)
