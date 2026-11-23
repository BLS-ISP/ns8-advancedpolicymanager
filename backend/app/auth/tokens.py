"""HMAC-SHA256 signed Bearer token creation and verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from app.errors import ApiError


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


@dataclass(frozen=True)
class AdminTokenClaims:
    username: str
    display_name: str
    groups: list[str]
    auth_source: str  # "LDAP" | "BOOTSTRAP"
    jti: str
    iat: int
    exp: int


def create_access_token(
    *,
    username: str,
    display_name: str,
    groups: list[str],
    auth_source: str,
    secret: str,
    expires_in: int = 28800,
    now: int | None = None,
) -> tuple[str, AdminTokenClaims]:
    issued_at = int(now if now is not None else time.time())
    expires_at = issued_at + int(expires_in)
    jti = secrets.token_hex(16)

    header_bytes = json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8")
    payload_dict: dict[str, Any] = {
        "sub": username,
        "displayName": display_name,
        "groups": list(groups),
        "authSource": auth_source,
        "jti": jti,
        "iat": issued_at,
        "exp": expires_at,
    }
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")

    signing_input = f"{_b64url_encode(header_bytes)}.{_b64url_encode(payload_bytes)}"
    sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    token = f"{signing_input}.{_b64url_encode(sig)}"

    claims = AdminTokenClaims(
        username=username,
        display_name=display_name,
        groups=list(groups),
        auth_source=auth_source,
        jti=jti,
        iat=issued_at,
        exp=expires_at,
    )
    return token, claims


def verify_access_token(
    token: str,
    secret: str,
    revoked_jtis: set[str] | None = None,
    now: int | None = None,
) -> AdminTokenClaims:
    if not token:
        raise ApiError(401, "UNAUTHORIZED", "Zugriffstoken fehlt")

    parts = token.split(".")
    if len(parts) != 3:
        raise ApiError(401, "UNAUTHORIZED", "Ungültiges Token-Format")

    signing_input = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()

    try:
        provided_sig = _b64url_decode(parts[2])
    except Exception as exc:
        raise ApiError(401, "UNAUTHORIZED", "Ungültige Token-Signatur") from exc

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ApiError(401, "UNAUTHORIZED", "Ungültige Token-Signatur")

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception as exc:
        raise ApiError(401, "UNAUTHORIZED", "Token-Inhalt konnte nicht gelesen werden") from exc

    if header.get("alg") != "HS256":
        raise ApiError(401, "UNAUTHORIZED", "Nicht unterstützter Signaturalgorithmus")

    current_time = int(now if now is not None else time.time())
    exp = int(payload.get("exp", 0))
    if exp <= current_time:
        raise ApiError(401, "TOKEN_EXPIRED", "Sitzung abgelaufen – bitte erneut anmelden")

    jti = str(payload.get("jti", ""))
    if revoked_jtis and jti in revoked_jtis:
        raise ApiError(401, "UNAUTHORIZED", "Sitzung wurde bereits abgemeldet")

    username = str(payload.get("sub", ""))
    if not username:
        raise ApiError(401, "UNAUTHORIZED", "Ungültiger Token-Benutzer")

    raw_groups = payload.get("groups")
    groups = [str(g) for g in raw_groups] if isinstance(raw_groups, list) else []
    auth_source = str(payload.get("authSource", "LDAP"))
    if auth_source not in ("LDAP", "BOOTSTRAP"):
        auth_source = "LDAP"

    return AdminTokenClaims(
        username=username,
        display_name=str(payload.get("displayName", username)),
        groups=groups,
        auth_source=auth_source,
        jti=jti,
        iat=int(payload.get("iat", 0)),
        exp=exp,
    )
