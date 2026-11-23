"""Environment configuration and PBKDF2 password hashing for NS8-AdvancedPolicyManager."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

BACKEND_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PBKDF2_ITERATIONS = 260_000


def hash_password_pbkdf2(
    password: str,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: str | None = None,
) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 in `pbkdf2:sha256:<iter>$<salt>$<hex>` format."""
    actual_salt = salt if salt is not None else secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        actual_salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2:sha256:{iterations}${actual_salt}${dk.hex()}"


def _digest_matches(
    password: str,
    salt_str: str,
    iterations: int,
    expected_digest: str,
) -> bool:
    """Verify PBKDF2-HMAC-SHA256 against hex or base64 digest (utf-8 salt or hex-decoded salt)."""
    salt_candidates: list[bytes] = [salt_str.encode("utf-8")]
    try:
        if len(salt_str) % 2 == 0:
            raw_hex_salt = bytes.fromhex(salt_str)
            if raw_hex_salt not in salt_candidates:
                salt_candidates.append(raw_hex_salt)
    except ValueError:
        pass

    expected_clean = expected_digest.strip()
    expected_bytes_list: list[bytes] = []
    try:
        if len(expected_clean) % 2 == 0:
            expected_bytes_list.append(bytes.fromhex(expected_clean))
    except ValueError:
        pass
    try:
        padded = expected_clean + "=" * (-len(expected_clean) % 4)
        b64_decoded = base64.b64decode(padded, validate=False)
        if b64_decoded:
            expected_bytes_list.append(b64_decoded)
    except Exception:
        pass

    for salt_bytes in salt_candidates:
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
        if hmac.compare_digest(dk.hex(), expected_clean.lower()):
            return True
        for exp_b in expected_bytes_list:
            if len(exp_b) == len(dk) and hmac.compare_digest(dk, exp_b):
                return True
    return False


def verify_password_pbkdf2(password: str, stored_hash: str) -> bool:
    """Verify password against PBKDF2-HMAC-SHA256 hash strings (`$` or `:` delimited)."""
    if not password or not stored_hash:
        return False

    try:
        if stored_hash.startswith("pbkdf2:sha256:"):
            rest = stored_hash[len("pbkdf2:sha256:") :]
            if "$" in rest:
                parts = rest.split("$")
                if len(parts) == 3:
                    iterations = int(parts[0])
                    return _digest_matches(password, parts[1], iterations, parts[2])
                if len(parts) == 2:
                    return _digest_matches(password, parts[0], DEFAULT_PBKDF2_ITERATIONS, parts[1])
            elif ":" in rest:
                parts = rest.split(":")
                if len(parts) == 3:
                    iterations = int(parts[0])
                    return _digest_matches(password, parts[1], iterations, parts[2])
                if len(parts) == 2:
                    return _digest_matches(password, parts[0], DEFAULT_PBKDF2_ITERATIONS, parts[1])
        elif stored_hash.startswith("pbkdf2_sha256$"):
            parts = stored_hash.split("$")
            if len(parts) == 4:
                iterations = int(parts[1])
                return _digest_matches(password, parts[2], iterations, parts[3])
    except (ValueError, TypeError):
        return False

    return False


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("true", "1", "yes", "on")


def _parse_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _parse_csv(value: str | None, default: list[str]) -> list[str]:
    if value is None or value.strip() == "":
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class Settings:
    """Application settings mapped from Section 1 of docs/contracts/api-and-policy-contract.md."""

    apm_port: int = 8080
    apm_data_dir: str = "./data"
    apm_static_dir: str = "../web/dist"
    apm_agent_artifacts_dir: str = "../agent"
    apm_public_url: str = "http://localhost:8080"
    jwt_secret: str = "dev-local-jwt-secret-0123456789abcdef0123456789abcdef0123456789ab"
    jwt_expires_seconds: int = 28800

    ldap_mode: str = "mock"
    ldap_domain: str = "firma.local"
    ldap_schema: str = "ad"
    ldap_host: str = ""
    ldap_port: int = 389
    ldap_tls: bool = False
    ldap_base_dn: str = "dc=firma,dc=local"
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""

    admin_groups: list[str] = field(
        default_factory=lambda: ["Domain Admins", "admins", "IT-Admins"]
    )

    bootstrap_admin_enabled: bool = True
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password_hash: str = field(
        default_factory=lambda: hash_password_pbkdf2("Admin123!", salt="apm-dev-bootstrap-salt")
    )

    apm_seed_demo: bool = True
    poll_interval_seconds: int = 120

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        src = env if env is not None else os.environ

        ldap_host = src.get("LDAP_HOST", "").strip()
        raw_ldap_mode = src.get("LDAP_MODE", "").strip().lower()
        if raw_ldap_mode in ("ldapproxy", "mock"):
            ldap_mode = raw_ldap_mode
        else:
            ldap_mode = "ldapproxy" if ldap_host else "mock"

        raw_schema = src.get("LDAP_SCHEMA", "ad").strip().lower()
        ldap_schema = raw_schema if raw_schema in ("ad", "rfc2307") else "ad"

        ldap_domain = src.get("LDAP_DOMAIN", "").strip() or "firma.local"
        default_base_dn = ",".join(f"dc={part}" for part in ldap_domain.split(".") if part)
        ldap_base_dn = src.get("LDAP_BASE_DN", "").strip() or default_base_dn or "dc=firma,dc=local"

        pw_hash = src.get("BOOTSTRAP_ADMIN_PASSWORD_HASH", "").strip()
        if not pw_hash:
            fallback_pw = src.get("BOOTSTRAP_ADMIN_PASSWORD", "Admin123!")
            pw_hash = hash_password_pbkdf2(fallback_pw, salt="apm-dev-bootstrap-salt")

        raw_seed = src.get("APM_SEED_DEMO")
        if raw_seed is None or raw_seed.strip() == "":
            apm_seed_demo = ldap_mode == "mock"
        else:
            apm_seed_demo = _parse_bool(raw_seed, default=(ldap_mode == "mock"))

        public_url = src.get("APM_PUBLIC_URL", "").strip() or "http://localhost:8080"

        return cls(
            apm_port=_parse_int(src.get("APM_PORT"), 8080),
            apm_data_dir=src.get("APM_DATA_DIR", "").strip() or "./data",
            apm_static_dir=src.get("APM_STATIC_DIR", "").strip() or "../web/dist",
            apm_agent_artifacts_dir=src.get("APM_AGENT_ARTIFACTS_DIR", "").strip() or "../agent",
            apm_public_url=public_url.rstrip("/"),
            jwt_secret=src.get("JWT_SECRET", "").strip()
            or "dev-local-jwt-secret-0123456789abcdef0123456789abcdef0123456789ab",
            jwt_expires_seconds=_parse_int(src.get("JWT_EXPIRES_SECONDS"), 28800),
            ldap_mode=ldap_mode,
            ldap_domain=ldap_domain,
            ldap_schema=ldap_schema,
            ldap_host=ldap_host,
            ldap_port=_parse_int(src.get("LDAP_PORT"), 389),
            ldap_tls=_parse_bool(src.get("LDAP_TLS"), False),
            ldap_base_dn=ldap_base_dn,
            ldap_bind_dn=src.get("LDAP_BIND_DN", "").strip(),
            ldap_bind_password=src.get("LDAP_BIND_PASSWORD", ""),
            admin_groups=_parse_csv(
                src.get("ADMIN_GROUPS"),
                ["Domain Admins", "admins", "IT-Admins"],
            ),
            bootstrap_admin_enabled=_parse_bool(src.get("BOOTSTRAP_ADMIN_ENABLED"), True),
            bootstrap_admin_username=src.get("BOOTSTRAP_ADMIN_USERNAME", "").strip() or "admin",
            bootstrap_admin_password_hash=pw_hash,
            apm_seed_demo=apm_seed_demo,
            poll_interval_seconds=_parse_int(src.get("APM_POLL_INTERVAL_SECONDS"), 120),
        )

    def resolve_data_dir(self) -> Path:
        path = Path(self.apm_data_dir)
        if path.is_absolute():
            return path
        if self.apm_data_dir == "./data":
            return (BACKEND_ROOT / "data").resolve()
        return path.resolve()

    def resolve_static_dir(self) -> Path:
        path = Path(self.apm_static_dir)
        if path.is_absolute():
            return path
        cwd_candidate = path.resolve()
        if cwd_candidate.exists():
            return cwd_candidate
        backend_candidate = (BACKEND_ROOT / path).resolve()
        if backend_candidate.exists():
            return backend_candidate
        return backend_candidate

    def resolve_agent_artifacts_dir(self) -> Path:
        path = Path(self.apm_agent_artifacts_dir)
        if path.is_absolute():
            return path
        cwd_candidate = path.resolve()
        if cwd_candidate.exists():
            return cwd_candidate
        backend_candidate = (BACKEND_ROOT / path).resolve()
        if backend_candidate.exists():
            return backend_candidate
        return backend_candidate
