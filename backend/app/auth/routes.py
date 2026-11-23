"""Authentication and Directory REST endpoints (`/api/v1/auth/*` and `/api/v1/directory/*`)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import (
     get_directory_provider,
    get_settings,
    require_admin,
)
from app.auth.tokens import AdminTokenClaims, create_access_token
from app.config import Settings, verify_password_pbkdf2
from app.directory.base import DirectoryProvider, DirectoryUnavailableError
from app.errors import ApiError, build_paginated_response

router = APIRouter(prefix="/api/v1", tags=["auth-directory"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)


@router.post("/auth/login")
def login(
    payload: LoginRequest,
    settings: Settings = Depends(get_settings),
    directory: DirectoryProvider = Depends(get_directory_provider),
) -> dict[str, Any]:
    username = payload.username.strip()
    password = payload.password

    if not username or not password:
        raise ApiError(401, "INVALID_CREDENTIALS", "Ungültiger Benutzername oder Passwort")

    # 1. Bootstrap Admin authentication (emergency local admin)
    if (
        settings.bootstrap_admin_enabled
        and username.lower() == settings.bootstrap_admin_username.lower()
    ):
        if verify_password_pbkdf2(password, settings.bootstrap_admin_password_hash):
            groups = ["BOOTSTRAP_ADMIN"]
            token, _ = create_access_token(
                username=settings.bootstrap_admin_username,
                display_name="Bootstrap Admin",
                groups=groups,
                auth_source="BOOTSTRAP",
                secret=settings.jwt_secret,
                expires_in=settings.jwt_expires_seconds,
            )
            return {
                "accessToken": token,
                "expiresIn": settings.jwt_expires_seconds,
                "user": {
                    "username": settings.bootstrap_admin_username,
                    "displayName": "Bootstrap Admin",
                    "groups": groups,
                    "authSource": "BOOTSTRAP",
                },
            }

    # 2. Directory (Samba AD / OpenLDAP / Mock) authentication + RBAC check
    try:
        dir_user = directory.authenticate(username, password)
    except DirectoryUnavailableError as exc:
        raise ApiError(503, "DIRECTORY_UNAVAILABLE", str(exc)) from exc

    if dir_user is None:
        raise ApiError(401, "INVALID_CREDENTIALS", "Ungültiger Benutzername oder Passwort")

    allowed_lower = {grp.lower() for grp in settings.admin_groups if grp.strip()}
    user_groups_lower = {grp.lower() for grp in dir_user.groups}
    if not (user_groups_lower & allowed_lower):
        raise ApiError(
            403,
            "FORBIDDEN",
            "Zugriff verweigert: Benutzer gehört keiner berechtigten Admin-Gruppe an",
            details={
                "requiredGroups": settings.admin_groups,
                "userGroups": dir_user.groups,
            },
        )

    token, _ = create_access_token(
        username=dir_user.username,
        display_name=dir_user.display_name,
        groups=dir_user.groups,
        auth_source="LDAP",
        secret=settings.jwt_secret,
        expires_in=settings.jwt_expires_seconds,
    )
    return {
        "accessToken": token,
        "expiresIn": settings.jwt_expires_seconds,
        "user": {
            "username": dir_user.username,
            "displayName": dir_user.display_name,
            "groups": list(dir_user.groups),
            "authSource": "LDAP",
        },
    }


@router.get("/auth/me")
def get_me(
    claims: AdminTokenClaims = Depends(require_admin),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    return {
        "username": claims.username,
        "displayName": claims.display_name,
        "groups": list(claims.groups),
        "authSource": claims.auth_source,
        "ldapDomain": settings.ldap_domain,
    }


@router.post("/auth/logout", status_code=204)
def logout(
    request: Request,
    claims: AdminTokenClaims = Depends(require_admin),
) -> Response:
    revoked: set[str] = getattr(request.app.state, "revoked_jtis", None)
    if revoked is not None and claims.jti:
        revoked.add(claims.jti)
    return Response(status_code=204)


@router.get("/directory/users")
def list_directory_users(
    search: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=25, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    directory: DirectoryProvider = Depends(get_directory_provider),
) -> dict[str, Any]:
    try:
        users, total = directory.search_users(search=search, page=page, page_size=pageSize)
    except DirectoryUnavailableError as exc:
        raise ApiError(503, "DIRECTORY_UNAVAILABLE", str(exc)) from exc

    return build_paginated_response(
        items=[u.to_dict() for u in users],
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.get("/directory/groups")
def list_directory_groups(
    search: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=25, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    directory: DirectoryProvider = Depends(get_directory_provider),
) -> dict[str, Any]:
    try:
        groups, total = directory.search_groups(search=search, page=page, page_size=pageSize)
    except DirectoryUnavailableError as exc:
        raise ApiError(503, "DIRECTORY_UNAVAILABLE", str(exc)) from exc

    return build_paginated_response(
        items=[g.to_dict() for g in groups],
        page=page,
        page_size=pageSize,
        total_items=total,
    )
