"""Device Groups and Fleet Devices CRUD endpoints (`/api/v1/device-groups` & `/api/v1/devices`)."""

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
from app.errors import ApiError, build_paginated_response, utc_now_iso

router = APIRouter(prefix="/api/v1", tags=["devices"])


class CreateDeviceGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=1000)
    tags: list[str] = Field(default_factory=list)


class PatchDeviceGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    tags: list[str] | None = None


class PatchDeviceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deviceGroupIds: list[str] = Field(default_factory=list)


def _row_to_device_group(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "tags": json.loads(row["tags_json"]),
        "deviceCount": int(row["device_count"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def load_device_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    grp_rows = conn.execute(
        """
        SELECT dg.id, dg.name
        FROM device_group_memberships m
        JOIN device_groups dg ON dg.id = m.device_group_id
        WHERE m.device_id = ?
        ORDER BY dg.name ASC
        """,
        (row["id"],),
    ).fetchall()

    return {
        "id": row["id"],
        "hostname": row["hostname"],
        "osFamily": row["os_family"],
        "osVersion": row["os_version"],
        "arch": row["arch"],
        "agentVersion": row["agent_version"],
        "currentUser": row["current_user"],
        "deviceGroupIds": [str(g["id"]) for g in grp_rows],
        "deviceGroupNames": [str(g["name"]) for g in grp_rows],
        "appliedRevision": int(row["applied_revision"]),
        "complianceStatus": row["compliance_status"],
        "lastSeenAt": row["last_seen_at"],
        "complianceItems": json.loads(row["compliance_items_json"]),
        "createdAt": row["created_at"],
    }


# --- Device Groups ---
@router.get("/device-groups")
def list_device_groups(
    search: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=50, ge=1, le=200),
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
                    "SELECT COUNT(*) AS cnt FROM device_groups WHERE name LIKE ? OR description LIKE ?",
                    (pattern, pattern),
                ).fetchone()["cnt"]
            )
            rows = conn.execute(
                """
                SELECT dg.*,
                       (SELECT COUNT(*) FROM device_group_memberships m WHERE m.device_group_id = dg.id) AS device_count
                FROM device_groups dg
                WHERE dg.name LIKE ? OR dg.description LIKE ?
                ORDER BY dg.name ASC
                LIMIT ? OFFSET ?
                """,
                (pattern, pattern, pageSize, offset),
            ).fetchall()
        else:
            total = int(conn.execute("SELECT COUNT(*) AS cnt FROM device_groups").fetchone()["cnt"])
            rows = conn.execute(
                """
                SELECT dg.*,
                       (SELECT COUNT(*) FROM device_group_memberships m WHERE m.device_group_id = dg.id) AS device_count
                FROM device_groups dg
                ORDER BY dg.name ASC
                LIMIT ? OFFSET ?
                """,
                (pageSize, offset),
            ).fetchall()

    return build_paginated_response(
        items=[_row_to_device_group(r) for r in rows],
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.post("/device-groups", status_code=201)
def create_device_group(
    payload: CreateDeviceGroupRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> JSONResponse:
    raw_dict = payload.model_dump(mode="json")

    def _create() -> tuple[int, dict[str, Any]]:
        clean_name = payload.name.strip()
        clean_tags = [t.strip() for t in payload.tags if t.strip()]
        grp_id = f"grp-{secrets.token_hex(6)}"
        now = utc_now_iso()

        with db.transaction() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO device_groups (id, name, description, tags_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        grp_id,
                        clean_name,
                        payload.description.strip(),
                        json.dumps(clean_tags, ensure_ascii=False),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ApiError(
                    409,
                    "CONFLICT",
                    f"Eine Gerätegruppe mit dem Namen '{clean_name}' existiert bereits",
                ) from exc

            row = conn.execute(
                """
                SELECT dg.*,
                       0 AS device_count
                FROM device_groups dg
                WHERE dg.id = ?
                """,
                (grp_id,),
            ).fetchone()
        return 201, _row_to_device_group(row)

    return run_idempotent(
        db=db,
        idempotency_key=idempotency_key,
        endpoint="POST:/api/v1/device-groups",
        payload_for_hash=raw_dict,
        action=_create,
    )


@router.get("/device-groups/{group_id}")
def get_device_group(
    group_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute(
            """
            SELECT dg.*,
                   (SELECT COUNT(*) FROM device_group_memberships m WHERE m.device_group_id = dg.id) AS device_count
            FROM device_groups dg
            WHERE dg.id = ?
            """,
            (group_id,),
        ).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND", f"Gerätegruppe '{group_id}' wurde nicht gefunden")
    return _row_to_device_group(row)


@router.patch("/device-groups/{group_id}")
def update_device_group(
    group_id: str,
    payload: PatchDeviceGroupRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT * FROM device_groups WHERE id = ?", (group_id,)
        ).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Gerätegruppe '{group_id}' wurde nicht gefunden")

        new_name = payload.name.strip() if payload.name is not None else str(existing["name"])
        new_desc = (
            payload.description.strip()
            if payload.description is not None
            else str(existing["description"])
        )
        new_tags = (
            [t.strip() for t in payload.tags if t.strip()]
            if payload.tags is not None
            else json.loads(existing["tags_json"])
        )
        now = utc_now_iso()

        try:
            conn.execute(
                """
                UPDATE device_groups
                SET name = ?, description = ?, tags_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    new_name,
                    new_desc,
                    json.dumps(new_tags, ensure_ascii=False),
                    now,
                    group_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ApiError(
                409,
                "CONFLICT",
                f"Eine Gerätegruppe mit dem Namen '{new_name}' existiert bereits",
            ) from exc

        updated = conn.execute(
            """
            SELECT dg.*,
                   (SELECT COUNT(*) FROM device_group_memberships m WHERE m.device_group_id = dg.id) AS device_count
            FROM device_groups dg
            WHERE dg.id = ?
            """,
            (group_id,),
        ).fetchone()
    return _row_to_device_group(updated)


@router.delete("/device-groups/{group_id}", status_code=204)
def delete_device_group(
    group_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> Response:
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT id FROM device_groups WHERE id = ?", (group_id,)
        ).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Gerätegruppe '{group_id}' wurde nicht gefunden")

        conn.execute(
            "DELETE FROM assignments WHERE target_device_type = 'DEVICE_GROUP' AND target_device_ref = ?",
            (group_id,),
        )
        conn.execute("DELETE FROM device_groups WHERE id = ?", (group_id,))
        bump_cluster_revision(conn)
    return Response(status_code=204)


# --- Devices ---
@router.get("/devices")
def list_devices(
    search: str = Query(default=""),
    osFamily: str = Query(default=""),
    complianceStatus: str = Query(default=""),
    deviceGroupId: str = Query(default=""),
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=25, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    where_clauses: list[str] = []
    params: list[Any] = []

    if search.strip():
        pat = f"%{search.strip()}%"
        where_clauses.append(
            "(d.hostname LIKE ? OR COALESCE(d.current_user, '') LIKE ? OR d.os_version LIKE ?)"
        )
        params.extend([pat, pat, pat])

    if osFamily.strip():
        where_clauses.append("UPPER(d.os_family) = ?")
        params.append(osFamily.strip().upper())

    if complianceStatus.strip():
        where_clauses.append("UPPER(d.compliance_status) = ?")
        params.append(complianceStatus.strip().upper())

    if deviceGroupId.strip():
        where_clauses.append(
            "EXISTS (SELECT 1 FROM device_group_memberships m WHERE m.device_id = d.id AND m.device_group_id = ?)"
        )
        params.append(deviceGroupId.strip())

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    offset = (page - 1) * pageSize

    with db.connection() as conn:
        total = int(
            conn.execute(
                f"SELECT COUNT(*) AS cnt FROM devices d {where_sql}",
                params,
            ).fetchone()["cnt"]
        )
        rows = conn.execute(
            f"""
            SELECT d.*
            FROM devices d
            {where_sql}
            ORDER BY d.hostname ASC, d.created_at DESC
            LIMIT ? OFFSET ?
            """,
            [*params, pageSize, offset],
        ).fetchall()
        items = [load_device_dict(conn, r) for r in rows]

    return build_paginated_response(
        items=items,
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.get("/devices/{device_id}")
def get_device(
    device_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", f"Gerät '{device_id}' wurde nicht gefunden")
        return load_device_dict(conn, row)


@router.patch("/devices/{device_id}")
def update_device_groups(
    device_id: str,
    payload: PatchDeviceRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    unique_group_ids: list[str] = []
    for gid in payload.deviceGroupIds:
        cleaned = gid.strip()
        if cleaned and cleaned not in unique_group_ids:
            unique_group_ids.append(cleaned)

    with db.transaction() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", f"Gerät '{device_id}' wurde nicht gefunden")

        for gid in unique_group_ids:
            grp = conn.execute("SELECT id FROM device_groups WHERE id = ?", (gid,)).fetchone()
            if grp is None:
                raise ApiError(404, "NOT_FOUND", f"Gerätegruppe '{gid}' existiert nicht")

        conn.execute("DELETE FROM device_group_memberships WHERE device_id = ?", (device_id,))
        for gid in unique_group_ids:
            conn.execute(
                "INSERT INTO device_group_memberships (device_id, device_group_id) VALUES (?, ?)",
                (device_id, gid),
            )
        bump_cluster_revision(conn)
        refreshed = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return load_device_dict(conn, refreshed)


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(
    device_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> Response:
    with db.transaction() as conn:
        existing = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Gerät '{device_id}' wurde nicht gefunden")
        conn.execute(
            "DELETE FROM assignments WHERE target_device_type = 'DEVICE' AND target_device_ref = ?",
            (device_id,),
        )
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        bump_cluster_revision(conn)
    return Response(status_code=204)
