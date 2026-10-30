"""Cross-language test vector verification test.
Ensures that the test vectors shared between Python and the TypeScript browser extension
are 100% compliant with Python normalization and Ed25519 canonical verification.
"""

import json
from pathlib import Path

from cyberduel_contracts.crypto import canonicalize_json, compute_sha256, verify_detached
from cyberduel_threat_intel.normalizer import URLNormalizer


def test_cross_language_vectors_consistency() -> None:
    vectors_path = Path("datasets/test_vectors/cross_language_vectors.json")
    assert vectors_path.exists(), "cross_language_vectors.json must exist"

    data = json.loads(vectors_path.read_text(encoding="utf-8"))

    # 1. Verify Crypto Vectors
    crypto_vec = data["crypto_vector"]
    pub_pem = crypto_vec["public_key_pem"]
    payload = crypto_vec["payload"]
    sig_hex = crypto_vec["signature_hex"]
    expected_canon_str = crypto_vec["canonical_json_str"]

    # Canonical serialization must match
    py_canon_bytes = canonicalize_json(payload)
    assert py_canon_bytes.decode("utf-8") == expected_canon_str

    # Signature verification must pass
    assert verify_detached(pub_pem, py_canon_bytes, sig_hex) is True

    # Corrupted signature must fail
    corrupted_sig = sig_hex[:60] + "ff" + sig_hex[62:]
    assert verify_detached(pub_pem, py_canon_bytes, corrupted_sig) is False

    # 2. Verify Normalization Vectors
    for vec in data["normalization_vectors"]:
        raw_input = vec["raw_input"]
        norm = URLNormalizer.normalize(raw_input)

        assert norm.scheme == vec["scheme"]
        assert norm.host == vec["host"]
        assert norm.canonical_url == vec["canonical_url"]
        assert norm.domain == vec["domain"]
        assert norm.url_sha256 == vec["url_sha256"]
        assert norm.domain_sha256 == vec["domain_sha256"]
        assert norm.has_embedded_credentials == vec["has_embedded_credentials"]
        assert norm.is_ip_literal == vec["is_ip_literal"]
        assert norm.url_sha256 == compute_sha256(norm.canonical_url)
