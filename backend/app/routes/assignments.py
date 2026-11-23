"""Priority Assignments & Reorder endpoints (`/api/v1/assignments`)."""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import get_db, require_admin
from app.auth.tokens import AdminTokenClaims
from app.db.connection import DatabaseManager
from app.db.idempotency import run_idempotent
from app.db.schema import bump_cluster_revision
from app.engine.schema_registry import ALL_PLATFORMS, OsFamily
from app.errors import ApiError, build_paginated_response, utc_now_iso

router = APIRouter(prefix="/api/v1/assignments", tags=["assignments"])

TargetUserType = Literal["ALL", "USER", "GROUP"]
TargetDeviceType = Literal["ALL", "DEVICE", "DEVICE_GROUP"]


class CreateAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyId: str = Field(min_length=1, max_length=128)
    priority: int | None = Field(default=None, ge=1, le=100000)
    isEnabled: bool = True
    targetUserType: TargetUserType = "ALL"
    targetUserRef: str | None = Field(default=None, max_length=256)
    targetDeviceType: TargetDeviceType = "ALL"
    targetDeviceRef: str | None = Field(default=None, max_length=256)
    osFilter: list[OsFamily] = Field(default_factory=lambda: list(ALL_PLATFORMS), min_length=1)


class PatchAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyId: str | None = Field(default=None, min_length=1, max_length=128)
    priority: int | None = Field(default=None, ge=1, le=100000)
    isEnabled: bool | None = None
    targetUserType: TargetUserType | None = None
    targetUserRef: str | None = Field(default=None, max_length=256)
    targetDeviceType: TargetDeviceType | None = None
    targetDeviceRef: str | None = Field(default=None, max_length=256)
    osFilter: list[OsFamily] | None = Field(default=None, min_length=1)


class ReorderAssignmentsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    orderedAssignmentIds: list[str] = Field(min_length=0)


ASSIGNMENT_SELECT_SQL = """
SELECT
    a.*,
    p.name AS policy_name,
    dg.name AS target_device_group_name
FROM assignments a
JOIN policies p ON p.id = a.policy_id
LEFT JOIN device_groups dg
    ON a.target_device_type = 'DEVICE_GROUP' AND dg.id = a.target_device_ref
"""


def row_to_assignment_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "policyId": row["policy_id"],
        "policyName": row["policy_name"],
        "priority": int(row["priority"]),
        "isEnabled": bool(row["is_enabled"]),
        "targetUserType": row["target_user_type"],
        "targetUserRef": row["target_user_ref"],
        "targetDeviceType": row["target_device_type"],
        "targetDeviceRef": row["target_device_ref"],
        "targetDeviceGroupName": row["target_device_group_name"],
        "osFilter": json.loads(row["os_filter_json"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _validate_scope_refs(
    conn: sqlite3.Connection,
    *,
    policy_id: str,
    target_user_type: str,
    target_user_ref: str | None,
    target_device_type: str,
    target_device_ref: str | None,
) -> tuple[str | None, str | None]:
    pol = conn.execute("SELECT id FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if pol is None:
        raise ApiError(404, "NOT_FOUND", f"Richtlinie '{policy_id}' existiert nicht")

    if target_user_type == "ALL":
        clean_user_ref = None
    else:
        clean_user_ref = (target_user_ref or "").strip()
        if not clean_user_ref:
            raise ApiError(
                422,
                "VALIDATION_ERROR",
                f"targetUserRef ist erforderlich wenn targetUserType='{target_user_type}'",
            )

    if target_device_type == "ALL":
        clean_device_ref = None
    else:
        clean_device_ref = (target_device_ref or "").strip()
        if not clean_device_ref:
            raise ApiError(
                422,
                "VALIDATION_ERROR",
                f"targetDeviceRef ist erforderlich wenn targetDeviceType='{target_device_type}'",
            )
        if target_device_type == "DEVICE_GROUP":
            grp = conn.execute(
                "SELECT id FROM device_groups WHERE id = ?", (clean_device_ref,)
            ).fetchone()
            if grp is None:
                raise ApiError(
                    404,
                    "NOT_FOUND",
                    f"Gerätegruppe '{clean_device_ref}' existiert nicht",
                )

    return clean_user_ref, clean_device_ref


def _dedupe_os(os_list: list[OsFamily]) -> list[OsFamily]:
    result: list[OsFamily] = []
    for p in os_list:
        if p not in result:
            result.append(p)
    return result


@router.get("")
def list_assignments(
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=50, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    offset = (page - 1) * pageSize
    with db.connection() as conn:
        total = int(conn.execute("SELECT COUNT(*) AS cnt FROM assignments").fetchone()["cnt"])
        rows = conn.execute(
            f"""
            {ASSIGNMENT_SELECT_SQL}
            ORDER BY a.priority ASC, a.created_at ASC, a.id ASC
            LIMIT ? OFFSET ?
            """,
            (pageSize, offset),
        ).fetchall()

    return build_paginated_response(
        items=[row_to_assignment_dict(r) for r in rows],
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.post("", status_code=201)
def create_assignment(
    payload: CreateAssignmentRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> JSONResponse:
    raw_dict = payload.model_dump(mode="json")

    def _create() -> tuple[int, dict[str, Any]]:
        with db.transaction() as conn:
            clean_user_ref, clean_dev_ref = _validate_scope_refs(
                conn,
                policy_id=payload.policyId,
                target_user_type=payload.targetUserType,
                target_user_ref=payload.targetUserRef,
                target_device_type=payload.targetDeviceType,
                target_device_ref=payload.targetDeviceRef,
            )

            if payload.priority is None:
                max_row = conn.execute(
                    "SELECT COALESCE(MAX(priority), 0) AS max_p FROM assignments"
                ).fetchone()
                assigned_priority = int(max_row["max_p"]) + 1
            else:
                assigned_priority = int(payload.priority)

            asg_id = f"asg-{secrets.token_hex(6)}"
            now = utc_now_iso()
            os_filter = _dedupe_os(payload.osFilter)

            conn.execute(
                """
                INSERT INTO assignments (
                    id, policy_id, priority, is_enabled,
                    target_user_type, target_user_ref,
                    target_device_type, target_device_ref,
                    os_filter_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asg_id,
                    payload.policyId,
                    assigned_priority,
                    1 if payload.isEnabled else 0,
                    payload.targetUserType,
                    clean_user_ref,
                    payload.targetDeviceType,
                    clean_dev_ref,
                    json.dumps(os_filter),
                    now,
                    now,
                ),
            )
            bump_cluster_revision(conn)
            row = conn.execute(
                f"{ASSIGNMENT_SELECT_SQL} WHERE a.id = ?",
                (asg_id,),
            ).fetchone()
        return 201, row_to_assignment_dict(row)

    return run_idempotent(
        db=db,
        idempotency_key=idempotency_key,
        endpoint="POST:/api/v1/assignments",
        payload_for_hash=raw_dict,
        action=_create,
    )


@router.post("/reorder")
def reorder_assignments(
    payload: ReorderAssignmentsRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    ordered_ids = payload.orderedAssignmentIds
    if len(set(ordered_ids)) != len(ordered_ids):
        raise ApiError(422, "VALIDATION_ERROR", "orderedAssignmentIds enthält doppelte Einträge")

    with db.transaction() as conn:
        all_rows = conn.execute(
            "SELECT id FROM assignments ORDER BY priority ASC, created_at ASC, id ASC"
        ).fetchall()
        existing_ids = [str(r["id"]) for r in all_rows]
        existing_set = set(existing_ids)

        unknown = [aid for aid in ordered_ids if aid not in existing_set]
        if unknown:
            raise ApiError(
                404,
                "NOT_FOUND",
                f"Unbekannte Zuweisungs-ID(s): {', '.join(unknown)}",
            )

        remaining = [aid for aid in existing_ids if aid not in set(ordered_ids)]
        final_sequence = list(ordered_ids) + remaining
        now = utc_now_iso()

        for index, aid in enumerate(final_sequence, start=1):
            conn.execute(
                "UPDATE assignments SET priority = ?, updated_at = ? WHERE id = ?",
                (index, now, aid),
            )

        bump_cluster_revision(conn)
        updated_rows = conn.execute(
            f"{ASSIGNMENT_SELECT_SQL} ORDER BY a.priority ASC, a.created_at ASC, a.id ASC"
        ).fetchall()

    return {"data": [row_to_assignment_dict(r) for r in updated_rows]}


@router.get("/{assignment_id}")
def get_assignment(
    assignment_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.connection() as conn:
        row = conn.execute(
            f"{ASSIGNMENT_SELECT_SQL} WHERE a.id = ?",
            (assignment_id,),
        ).fetchone()
    if row is None:
        raise ApiError(404, "NOT_FOUND", f"Zuweisung '{assignment_id}' wurde nicht gefunden")
    return row_to_assignment_dict(row)


@router.patch("/{assignment_id}")
def update_assignment(
    assignment_id: str,
    payload: PatchAssignmentRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT * FROM assignments WHERE id = ?",
            (assignment_id,),
        ).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Zuweisung '{assignment_id}' wurde nicht gefunden")

        fields_set = payload.model_fields_set
        new_policy_id = payload.policyId if "policyId" in fields_set and payload.policyId else str(existing["policy_id"])
        new_priority = int(payload.priority) if "priority" in fields_set and payload.priority is not None else int(existing["priority"])
        new_enabled = bool(payload.isEnabled) if "isEnabled" in fields_set and payload.isEnabled is not None else bool(existing["is_enabled"])
        new_user_type = payload.targetUserType if "targetUserType" in fields_set and payload.targetUserType else str(existing["target_user_type"])
        raw_user_ref = payload.targetUserRef if "targetUserRef" in fields_set else existing["target_user_ref"]
        new_dev_type = payload.targetDeviceType if "targetDeviceType" in fields_set and payload.targetDeviceType else str(existing["target_device_type"])
        raw_dev_ref = payload.targetDeviceRef if "targetDeviceRef" in fields_set else existing["target_device_ref"]

        clean_user_ref, clean_dev_ref = _validate_scope_refs(
            conn,
            policy_id=new_policy_id,
            target_user_type=new_user_type,
            target_user_ref=raw_user_ref,
            target_device_type=new_dev_type,
            target_device_ref=raw_dev_ref,
        )

        if "osFilter" in fields_set and payload.osFilter is not None:
            new_os_filter = _dedupe_os(payload.osFilter)
        else:
            new_os_filter = json.loads(existing["os_filter_json"])

        now = utc_now_iso()
        conn.execute(
            """
            UPDATE assignments
            SET policy_id = ?, priority = ?, is_enabled = ?,
                target_user_type = ?, target_user_ref = ?,
                target_device_type = ?, target_device_ref = ?,
                os_filter_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_policy_id,
                new_priority,
                1 if new_enabled else 0,
                new_user_type,
                clean_user_ref,
                new_dev_type,
                clean_dev_ref,
                json.dumps(new_os_filter),
                now,
                assignment_id,
            ),
        )
        bump_cluster_revision(conn)
        updated = conn.execute(
            f"{ASSIGNMENT_SELECT_SQL} WHERE a.id = ?",
            (assignment_id,),
        ).fetchone()

    return row_to_assignment_dict(updated)


@router.delete("/{assignment_id}", status_code=204)
def delete_assignment(
    assignment_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> Response:
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT id FROM assignments WHERE id = ?",
            (assignment_id,),
        ).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Zuweisung '{assignment_id}' wurde nicht gefunden")
        conn.execute("DELETE FROM assignments WHERE id = ?", (assignment_id,))
        bump_cluster_revision(conn)
    return Response(status_code=204)
