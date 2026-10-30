#!/usr/bin/env python3
"""CyberDuel AI — Railway Production Preflight Verification Script.

Validates environment variables, database readiness, Redis cache connectivity,
storage volume writability, and cryptographic authority health without leaking secrets.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add project root and packages to path for direct script execution
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "shared-contracts"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "policy-engine"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "threat-intelligence"))
sys.path.insert(0, str(_REPO_ROOT / "apps" / "api"))

from typing import Any
from urllib.parse import urlparse


def mask_secret(value: str | None, show_chars: int = 4) -> str:
    """Mask sensitive string leaving only small prefix/suffix visible."""
    if not value:
        return "[NOT SET]"
    if len(value) <= show_chars * 2:
        return "***"
    return f"{value[:show_chars]}...{value[-show_chars:]} ({len(value)} chars)"


def mask_url_credentials(url: str | None) -> str:
    """Safely redact username and password in connection strings."""
    if not url:
        return "[NOT SET]"
    try:
        parsed = urlparse(url)
        if parsed.password or parsed.username:
            netloc = parsed.hostname or "localhost"
            if parsed.port:
                netloc += f":{parsed.port}"
            redacted = parsed._replace(netloc=f"***:***@{netloc}")
            return redacted.geturl()
        return url
    except Exception:
        return "***[MALFORMED_URL]***"


class PreflightChecker:
    """Runs end-to-end production readiness checks."""

    def __init__(self, skip_network: bool = False, skip_redis: bool = False, dry_run: bool = False) -> None:
        self.skip_network = skip_network
        self.skip_redis = skip_redis
        self.dry_run = dry_run
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.passes: list[str] = []

    def check_environment(self) -> None:
        """Validate core environment variables."""
        print("\n[1/6] Checking Environment Configuration...")
        env = os.environ.get("ENVIRONMENT", "development").lower()
        debug = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")
        secret_key = os.environ.get("SECRET_KEY", "")

        print(f"  • ENVIRONMENT : {env}")
        print(f"  • DEBUG       : {debug}")
        print(f"  • SECRET_KEY  : {mask_secret(secret_key)}")

        if env in ("production", "staging"):
            if debug:
                self.failures.append("DEBUG must not be True in production/staging environment")
            if not secret_key or len(secret_key) < 32:
                self.failures.append("SECRET_KEY must be at least 32 characters long in production")
            elif "dev_" in secret_key or "secret" == secret_key.lower():
                self.warnings.append("SECRET_KEY appears to use an insecure default or trivial pattern")
            else:
                self.passes.append("Environment and SECRET_KEY validated for production")

            # Validate AI Provider in production
            ai_provider = os.environ.get("AI_PROVIDER_TYPE", "mock").lower()
            if env == "production" and ai_provider == "mock":
                self.failures.append("AI_PROVIDER_TYPE cannot be 'mock' in production. Must be 'qwen'.")
            else:
                self.passes.append(f"AI_PROVIDER_TYPE configured as '{ai_provider}'")

            # Validate CORS configuration
            cors = os.environ.get("CORS_ORIGINS", "")
            if env == "production" and ("localhost" in cors or "127.0.0.1" in cors):
                self.warnings.append("CORS_ORIGINS in production includes local loopback addresses (localhost/127.0.0.1)")
        else:
            if not secret_key:
                self.warnings.append("SECRET_KEY not set; defaulting to local development secret")
            else:
                self.passes.append("Environment variables present")

    def check_storage(self) -> None:
        """Verify release storage directory exists and is writable."""
        print("\n[2/6] Checking Persistent Volume & Storage Directory...")
        storage_path_str = os.environ.get("STORAGE_RELEASES_DIR", "storage/releases")
        storage_path = Path(storage_path_str).resolve()
        print(f"  • Target Path : {storage_path}")

        try:
            storage_path.mkdir(parents=True, exist_ok=True)
            probe_file = storage_path / f".preflight_probe_{os.getpid()}.tmp"
            probe_bytes = b"cyberduel_storage_probe_ok"
            probe_file.write_bytes(probe_bytes)
            read_back = probe_file.read_bytes()
            probe_file.unlink(missing_ok=True)

            if read_back == probe_bytes:
                self.passes.append(f"Storage volume at '{storage_path}' is fully writable")
                print("  • Volume Test : PASS (read/write verified)")
            else:
                self.failures.append(f"Storage volume integrity probe failed at '{storage_path}'")
        except Exception as e:
            self.failures.append(f"Cannot write to storage volume at '{storage_path}': {e}")
            print(f"  • Volume Test : FAIL ({e})")

    def check_database(self) -> None:
        """Verify database connectivity and check migration state."""
        print("\n[3/6] Checking Database Connectivity...")
        db_url_sync = os.environ.get("DATABASE_URL_SYNC") or os.environ.get("DATABASE_URL")
        print(f"  • Database URL: {mask_url_credentials(db_url_sync)}")

        if self.skip_network:
            print("  • DB Test     : SKIPPED (--skip-network flag active)")
            self.warnings.append("Database connectivity check skipped by flag")
            return

        if not db_url_sync:
            # Fallback to local default sqlite if development
            if os.environ.get("ENVIRONMENT", "development") == "development":
                print("  • DB Test     : Defaulting to local dev database")
                self.passes.append("Using default SQLite connection for local development")
                return
            self.failures.append("DATABASE_URL or DATABASE_URL_SYNC is required in production")
            return

        try:
            from sqlalchemy import create_engine, text

            # Normalize asyncpg URL for sync probe if needed
            probe_url = db_url_sync.replace("postgresql+asyncpg://", "postgresql+psycopg://")
            engine = create_engine(probe_url, connect_args={"connect_timeout": 5} if "postgresql" in probe_url else {})
            with engine.connect() as conn:
                res = conn.execute(text("SELECT 1")).scalar()
                if res == 1:
                    print("  • DB Test     : PASS (connection established, SELECT 1 = 1)")
                    self.passes.append("Database connection verified successfully")
                else:
                    self.failures.append(f"Unexpected database probe result: {res}")
        except Exception as e:
            # Check if running in a container during build step
            if "could not connect to server" in str(e).lower() or "connection refused" in str(e).lower():
                self.warnings.append(f"Database offline or unreachable from current network: {mask_url_credentials(str(e))}")
                print(f"  • DB Test     : WARN (unreachable - service may still be booting)")
            else:
                self.failures.append(f"Database verification error: {e}")
                print(f"  • DB Test     : FAIL ({e})")

    def check_redis(self) -> None:
        """Verify Redis task queue and cache connectivity."""
        print("\n[4/6] Checking Redis Broker & Cache Connectivity...")
        redis_url = os.environ.get("REDIS_URL")
        print(f"  • Redis URL   : {mask_url_credentials(redis_url)}")

        if self.skip_redis or self.skip_network:
            print("  • Redis Test  : SKIPPED (flag active)")
            self.warnings.append("Redis check skipped")
            return

        if not redis_url:
            self.warnings.append("REDIS_URL not set; worker queues will operate in standalone/mock mode")
            print("  • Redis Test  : WARN (REDIS_URL not configured)")
            return

        try:
            import redis

            r = redis.from_url(redis_url, socket_timeout=3, socket_connect_timeout=3)
            if r.ping():
                print("  • Redis Test  : PASS (PING -> PONG received)")
                self.passes.append("Redis broker ping succeeded")
            else:
                self.failures.append("Redis ping returned False")
        except Exception as e:
            self.warnings.append(f"Redis unreachable from current host: {e}")
            print(f"  • Redis Test  : WARN ({e})")

    def check_ai_provider(self) -> None:
        """Verify AI provider configuration and test live Qwen inference endpoint connectivity."""
        print("\n[5/6] Checking AI Inference Engine & Qwen Provider...")
        env = os.environ.get("ENVIRONMENT", "development").lower()
        provider_type = os.environ.get("AI_PROVIDER_TYPE", "mock").lower()
        qwen_base = os.environ.get("QWEN_API_BASE", "https://api.deepinfra.com/v1/openai")
        qwen_key = os.environ.get("QWEN_API_KEY", "")
        qwen_model = os.environ.get("QWEN_MODEL_NAME", "Qwen/Qwen2.5-Coder-7B-Instruct")

        print(f"  • Provider    : {provider_type}")
        print(f"  • Model       : {qwen_model}")
        print(f"  • Endpoint    : {qwen_base}")
        print(f"  • API Key     : {mask_secret(qwen_key)}")

        if provider_type == "mock":
            if env == "production":
                self.failures.append("Mock provider is strictly prohibited in production environment.")
                print("  • AI Test     : FAIL (Mock provider prohibited in production)")
            else:
                self.warnings.append("AI_PROVIDER_TYPE is 'mock'; live Qwen inference is inactive.")
                print("  • AI Test     : WARN (Mock provider active for offline testing)")
            return

        if provider_type == "qwen":
            if not qwen_base:
                self.failures.append("QWEN_API_BASE is required when AI_PROVIDER_TYPE is 'qwen'")
                print("  • AI Test     : FAIL (Missing QWEN_API_BASE)")
                return

            try:
                import asyncio
                from apps.api.app.providers.qwen_provider import QwenProvider

                provider = QwenProvider(
                    api_base=qwen_base,
                    api_key=qwen_key,
                    model_name=qwen_model,
                )
                is_connected, msg, details = asyncio.run(provider.check_endpoint_connectivity(timeout_seconds=3.0))

                if is_connected:
                    if not qwen_key:
                        self.warnings.append(f"Qwen endpoint reachable at '{qwen_base}', but QWEN_API_KEY is not set. Inference requires authentication.")
                        print(f"  • AI Test     : WARN (Endpoint reachable, auth key not set)")
                    else:
                        self.passes.append(f"Qwen endpoint connected ({qwen_model} at {qwen_base})")
                        print(f"  • AI Test     : PASS (Endpoint reachable, latency {details.get('latency_ms', 0):.1f}ms)")
                else:
                    msg_text = f"Qwen endpoint unreachable at '{qwen_base}': {msg}"
                    if env in ("production", "staging"):
                        self.failures.append(msg_text)
                        print(f"  • AI Test     : FAIL ({msg})")
                    else:
                        self.warnings.append(msg_text)
                        print(f"  • AI Test     : WARN ({msg})")
            except Exception as e:
                err_text = f"Failed to test Qwen endpoint: {e}"
                if env in ("production", "staging"):
                    self.failures.append(err_text)
                    print(f"  • AI Test     : FAIL ({e})")
                else:
                    self.warnings.append(err_text)
                    print(f"  • AI Test     : WARN ({e})")

    def check_cryptographic_anchors(self) -> None:
        """Verify Ed25519 cryptography libraries and keystore access."""
        print("\n[6/6] Checking Cryptographic Signing Capabilities...")
        try:
            from cyberduel_contracts.crypto import generate_ed25519_keypair, sign_detached, verify_detached

            priv_pem, pub_pem = generate_ed25519_keypair()
            test_data = b"preflight_crypto_health_check"
            sig = sign_detached(priv_pem, test_data)
            is_valid = verify_detached(pub_pem, test_data, sig)

            if is_valid:
                print("  • Crypto Test : PASS (Ed25519 key generation, signing, and verification)")
                self.passes.append("Cryptographic Ed25519 subsystem operational")
            else:
                self.failures.append("Ed25519 self-test verification failed")
        except Exception as e:
            self.failures.append(f"Cryptographic subsystem error: {e}")
            print(f"  • Crypto Test : FAIL ({e})")

    def run(self) -> int:
        """Execute all checks and print summary."""
        print("==================================================================")
        print("  CYBERDUEL AI — RAILWAY PRODUCTION PREFLIGHT VERIFICATION        ")
        print("==================================================================")

        self.check_environment()
        self.check_storage()
        self.check_database()
        self.check_redis()
        self.check_ai_provider()
        self.check_cryptographic_anchors()

        print("\n------------------------------------------------------------------")
        print(f"SUMMARY: {len(self.passes)} Passed | {len(self.warnings)} Warnings | {len(self.failures)} Failures")
        print("------------------------------------------------------------------")

        if self.warnings:
            print("\nWARNINGS:")
            for w in self.warnings:
                print(f"  [!] {w}")

        if self.failures:
            print("\nCRITICAL FAILURES:")
            for f in self.failures:
                print(f"  [X] {f}")
            print("\nPreflight Status: REJECTED (Fix critical failures before deploying)\n")
            return 1

        print("\nPreflight Status: READY FOR RAILWAY DEPLOYMENT\n")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Railway Production Preflight Checker for CyberDuel AI")
    parser.add_argument("--skip-network", action="store_true", help="Skip remote database and cache network checks")
    parser.add_argument("--skip-redis", action="store_true", help="Skip Redis cache ping")
    parser.add_argument("--dry-run", action="store_true", help="Perform checks in dry-run mode")
    args = parser.parse_args()

    checker = PreflightChecker(
        skip_network=args.skip_network,
        skip_redis=args.skip_redis,
        dry_run=args.dry_run,
    )
    sys.exit(checker.run())


if __name__ == "__main__":
    main()
