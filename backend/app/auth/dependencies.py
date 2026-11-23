"""FastAPI request dependencies for settings, database, directory, and RBAC auth."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

from app.auth.tokens import AdminTokenClaims, verify_access_token
from app.config import Settings
from app.directory.base import DirectoryProvider
from app.errors import ApiError

if TYPE_CHECKING:
    from app.db.connection import DatabaseManager


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_directory_provider(request: Request) -> DirectoryProvider:
    return request.app.state.directory_provider


def get_db(request: Request) -> "DatabaseManager":
    db: "DatabaseManager" = request.app.state.db
    db.ensure_initialized()
    return db


def extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "").strip()
    if not auth_header:
        raise ApiError(401, "UNAUTHORIZED", "Authorization-Header fehlt")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise ApiError(401, "UNAUTHORIZED", "Ungültiges Authorization-Bearer-Format")
    return parts[1].strip()


def require_admin(request: Request) -> AdminTokenClaims:
    token = extract_bearer_token(request)
    settings = get_settings(request)
    revoked_jtis: set[str] = getattr(request.app.state, "revoked_jtis", set())
    return verify_access_token(
        token,
        secret=settings.jwt_secret,
        revoked_jtis=revoked_jtis,
    )
