"""Policies CRUD endpoints (`/api/v1/policies`)."""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import get_db, require_admin
from app.auth.tokens import AdminTokenClaims
from app.db.connection import DatabaseManager
from app.db.idempotency import run_idempotent
from app.db.schema import bump_cluster_revision
from app.engine.schema_registry import validate_policy_rules
from app.errors import ApiError, build_paginated_response, utc_now_iso

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


class CreatePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    isEnabled: bool = True
    rules: list[dict[str, Any]] = Field(default_factory=list)


class PatchPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    isEnabled: bool | None = None
    rules: list[dict[str, Any]] | None = None


def row_to_policy_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "isEnabled": bool(row["is_enabled"]),
        "revision": int(row["revision"]),
        "rules": json.loads(row["rules_json"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


@router.get("")
def list_policies(
    search: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=25, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    q = search.strip()
    offset = (page - 1) * pageSize

    with db.connection() as conn:
        if q:
            pattern = f"%{q}%"
            total = int(
                conn.execute(
                    "SELECT COUNT(*) AS cnt FROM policies WHERE name LIKE ? OR description LIKE ?",
                    (pattern, pattern),
                ).fetchone()["cnt"]
            )
            rows = conn.execute(
                """
                SELECT * FROM policies
                WHERE name LIKE ? OR description LIKE ?
                ORDER BY updated_at DESC, name ASC
                LIMIT ? OFFSET ?
                """,
                (pattern, pattern, pageSize, offset),
            ).fetchall()
        else:
            total = int(conn.execute("SELECT COUNT(*) AS cnt FROM policies").fetchone()["cnt"])
            rows = conn.execute(
                """
                SELECT * FROM policies
                ORDER BY updated_at DESC, name ASC
                LIMIT ? OFFSET ?
                """,
                (pageSize, offset),
            ).fetchall()

    return build_paginated_response(
        items=[row_to_policy_dict(r) for r in rows],
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.post("", status_code=201)
def create_policy(
    payload: CreatePolicyRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> JSONResponse:
    raw_dict = payload.model_dump(mode="json")

    def _create() -> tuple[int, dict[str, Any]]:
        validated_rules = validate_policy_rules(payload.rules)
        policy_id = f"pol-{secrets.token_hex(6)}"
        now = utc_now_iso()
        with db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO policies
                    (id, name, description, is_enabled, revision, rules_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    policy_id,
                    payload.name.strip(),
                    payload.description.strip(),
                    1 if payload.isEnabled else 0,
                    json.dumps(validated_rules, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            bump_cluster_revision(conn)
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        return 201, row_to_policy_dict(row)

    return run_idempotent(
        db=db,
        idempotency_key=idempotency_key,
        endpoint="POST:/api/v1/policies",
        payload_for_hash=raw_dict,
        action=_create,
    )


@router.get("/{policy_id}")
def get_policy(
    policy_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND", f"Richtlinie '{policy_id}' wurde nicht gefunden")
    return row_to_policy_dict(row)


@router.patch("/{policy_id}")
def update_policy(
    policy_id: str,
    payload: PatchPolicyRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.transaction() as conn:
        existing = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Richtlinie '{policy_id}' wurde nicht gefunden")

        new_name = payload.name.strip() if payload.name is not None else str(existing["name"])
        new_desc = (
            payload.description.strip()
            if payload.description is not None
            else str(existing["description"])
        )
        new_enabled = (
            bool(payload.isEnabled)
            if payload.isEnabled is not None
            else bool(existing["is_enabled"])
        )

        existing_rules = json.loads(existing["rules_json"])
        revision = int(existing["revision"])
        rules_changed = False

        if payload.rules is not None:
            new_rules = validate_policy_rules(payload.rules)
            if new_rules != existing_rules:
                revision += 1
                rules_changed = True
        else:
            new_rules = existing_rules

        enabled_changed = new_enabled != bool(existing["is_enabled"])
        now = utc_now_iso()

        conn.execute(
            """
            UPDATE policies
            SET name = ?, description = ?, is_enabled = ?, revision = ?, rules_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_name,
                new_desc,
                1 if new_enabled else 0,
                revision,
                json.dumps(new_rules, ensure_ascii=False),
                now,
                policy_id,
            ),
        )
        if rules_changed or enabled_changed:
            bump_cluster_revision(conn)

        updated = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    return row_to_policy_dict(updated)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(
    policy_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> Response:
    with db.transaction() as conn:
        existing = conn.execute("SELECT id FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Richtlinie '{policy_id}' wurde nicht gefunden")
        conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
        bump_cluster_revision(conn)
    return Response(status_code=204)
