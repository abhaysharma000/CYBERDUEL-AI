"""Tests for cryptographic utilities, Ed25519 signing, and canonical JSON serialization."""

from cyberduel_contracts.crypto import (
    canonicalize_json,
    compute_canonical_sha256,
    compute_sha256,
    generate_ed25519_keypair,
    sign_detached,
    sign_manifest,
    verify_detached,
    verify_manifest,
)


def test_canonicalize_json_order_independence() -> None:
    """Ensure key ordering does not affect canonical JSON output."""
    data1 = {"z": 1, "a": 2, "m": {"c": 3, "b": 4}}
    data2 = {"a": 2, "m": {"b": 4, "c": 3}, "z": 1}

    bytes1 = canonicalize_json(data1)
    bytes2 = canonicalize_json(data2)

    assert bytes1 == bytes2
    assert bytes1 == b'{"a":2,"m":{"b":4,"c":3},"z":1}'


def test_compute_sha256() -> None:
    """Verify SHA-256 digest computation."""
    data = b"CyberDuel AI Defense Update"
    digest = compute_sha256(data)
    assert len(digest) == 64
    assert digest == compute_sha256("CyberDuel AI Defense Update")


def test_compute_canonical_sha256_consistency() -> None:
    """Verify canonical SHA-256 produces identical hash regardless of dict key ordering."""
    dict_a = {"beta": 2, "alpha": 1}
    dict_b = {"alpha": 1, "beta": 2}
    assert compute_canonical_sha256(dict_a) == compute_canonical_sha256(dict_b)


def test_ed25519_keypair_generation() -> None:
    """Verify valid PEM formatting of generated Ed25519 keypairs."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    assert "BEGIN PRIVATE KEY" in priv_pem
    assert "END PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    assert "END PUBLIC KEY" in pub_pem


def test_detached_signing_and_verification() -> None:
    """Test standard digital signature generation and verification."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    payload = b"security_policy_bundle_v2026.10.2"

    sig_hex = sign_detached(priv_pem, payload)
    assert len(sig_hex) == 128  # 64 bytes in hex

    # Verification passes with correct key and payload
    assert verify_detached(pub_pem, payload, sig_hex) is True


def test_tampering_fails_verification() -> None:
    """Verify that any tampering of payload causes signature verification failure."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    payload = b"original_legitimate_policy"
    sig_hex = sign_detached(priv_pem, payload)

    # 1-bit / 1-byte alteration
    tampered_payload = b"original_legitimate_policZ"
    assert verify_detached(pub_pem, tampered_payload, sig_hex) is False


def test_different_key_fails_verification() -> None:
    """Verify that signature fails if verified against a different public key."""
    priv_a, pub_a = generate_ed25519_keypair()
    _, pub_b = generate_ed25519_keypair()

    payload = b"critical_threat_intelligence"
    sig_hex = sign_detached(priv_a, payload)

    assert verify_detached(pub_a, payload, sig_hex) is True
    assert verify_detached(pub_b, payload, sig_hex) is False


def test_corrupted_signature_format() -> None:
    """Verify malformed signatures do not crash the verifier and safely return False."""
    _, pub_pem = generate_ed25519_keypair()
    payload = b"test_payload"

    assert verify_detached(pub_pem, payload, "not_a_valid_hex_string") is False
    assert verify_detached(pub_pem, payload, "001122") is False  # too short
    assert verify_detached("invalid_pem_header", payload, "aa" * 64) is False


def test_manifest_signing_and_verification() -> None:
    """Verify manifest signing ignores existing signature field and validates canonical payload."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    manifest = {
        "release_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "policy_version": "2026.10.2",
        "sequence_number": 42,
        "channel": "stable",
        "artifact_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "publisher_key_id": "cyberduel-prod-2026-k1",
    }

    sig_hex = sign_manifest(manifest, priv_pem)
    assert len(sig_hex) == 128

    # Add signature into dictionary
    manifest_with_sig = dict(manifest)
    manifest_with_sig["signature"] = sig_hex

    # Verifies cleanly
    assert verify_manifest(manifest_with_sig, sig_hex, pub_pem) is True

    # Mutating any field in manifest fails verification
    tampered = dict(manifest_with_sig)
    tampered["sequence_number"] = 43
    assert verify_manifest(tampered, sig_hex, pub_pem) is False
