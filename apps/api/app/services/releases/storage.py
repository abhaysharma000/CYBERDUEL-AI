"""Immutable artifact storage service with path-traversal protection and SHA-256 verification."""

import contextlib
import os
from pathlib import Path

from cyberduel_contracts.crypto import compute_sha256

DEFAULT_STORAGE_DIR = Path("storage/releases")


class ArtifactStorageError(Exception):
    """Raised on artifact storage failures, tampering, or traversal violations."""


class ArtifactStorageService:
    """Stores and retrieves immutable release artifacts with cryptographic integrity checks."""

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir = Path(base_dir).resolve() if base_dir else DEFAULT_STORAGE_DIR.resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, filename: str) -> Path:
        """Resolve path and verify it stays strictly inside the designated artifact directory."""
        if ".." in filename or filename.startswith(("/", "\\")):
            resolved = (self.base_dir / filename).resolve()
            if not str(resolved).startswith(str(self.base_dir)):
                raise ArtifactStorageError(f"Path traversal detected for filename '{filename}'")

        safe_name = os.path.basename(filename)
        resolved = (self.base_dir / safe_name).resolve()

        if not str(resolved).startswith(str(self.base_dir)):
            raise ArtifactStorageError(f"Path traversal detected for filename '{filename}'")
        return resolved

    def store_artifact(
        self,
        artifact_bytes: bytes,
        expected_digest: str,
        filename_hint: str,
    ) -> tuple[Path, str]:
        """Store immutable binary artifact. Verifies hash before writing.

        Returns:
            (saved_path, confirmed_sha256_digest)
        """
        computed_digest = compute_sha256(artifact_bytes)
        if computed_digest.lower() != expected_digest.lower():
            raise ArtifactStorageError(
                f"Artifact digest mismatch: computed {computed_digest} != expected {expected_digest}"
            )

        # Standard deterministic filename based on digest
        filename = filename_hint if filename_hint else f"policy-{expected_digest[:16]}.json"
        dest_path = self._resolve_safe_path(filename)

        if dest_path.exists():
            # If already exists, verify existing content matches
            existing_content = dest_path.read_bytes()
            if compute_sha256(existing_content).lower() != expected_digest.lower():
                raise ArtifactStorageError(
                    f"Integrity violation: existing artifact at {dest_path} is corrupted or tampered"
                )
            return dest_path, computed_digest

        # Write file atomically using temp file in same directory
        temp_path = dest_path.with_suffix(".tmp")
        temp_path.write_bytes(artifact_bytes)
        temp_path.replace(dest_path)

        # Set read-only permissions if supported
        with contextlib.suppress(AttributeError, PermissionError):
            os.chmod(dest_path, 0o444)

        return dest_path, computed_digest

    def read_artifact(
        self, path_or_filename: Path | str, expected_digest: str | None = None
    ) -> bytes:
        """Read artifact and verify SHA-256 digest against expected digest or tamper check."""
        if isinstance(path_or_filename, Path) and path_or_filename.is_absolute():
            resolved = path_or_filename.resolve()
            if not str(resolved).startswith(str(self.base_dir)):
                raise ArtifactStorageError("Attempted to read artifact outside storage directory")
        else:
            resolved = self._resolve_safe_path(str(path_or_filename))

        if not resolved.exists():
            raise FileNotFoundError(f"Artifact not found at {resolved}")

        data = resolved.read_bytes()
        if expected_digest is not None:
            actual = compute_sha256(data)
            if actual.lower() != expected_digest.lower():
                raise ArtifactStorageError(
                    f"Artifact content tampered! Expected SHA-256 {expected_digest}, got {actual}"
                )

        return data
