"""Isolated cryptographic signing service with access to Ed25519 authority private keys."""

from typing import Any

from cyberduel_contracts.crypto import sign_manifest, verify_manifest

from apps.api.app.services.releases.key_manager import SigningKeyManager


class ReleaseSigningService:
    """Performs cryptographic signing operations on release manifests under strict privilege boundary."""

    def __init__(self, key_manager: SigningKeyManager | None = None) -> None:
        self.key_manager = key_manager or SigningKeyManager()

    def sign_manifest_payload(self, manifest_dict: dict[str, Any], key_id: str) -> str:
        """Sign canonical manifest payload using the specified key_id private key.

        Returns:
            Detached hexadecimal signature string.
        """
        private_pem = self.key_manager.load_private_key_pem(key_id)
        return sign_manifest(manifest_dict, private_pem)

    def verify_manifest_payload(
        self,
        manifest_dict: dict[str, Any],
        signature_hex: str,
        public_key_pem: str,
    ) -> bool:
        """Verify the integrity and authenticity of a signed manifest."""
        return verify_manifest(manifest_dict, signature_hex, public_key_pem)
