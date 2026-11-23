"""Interactive Effective-Policy Simulator endpoint (`/api/v1/simulator/evaluate`)."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import get_db, get_directory_provider, require_admin
from app.auth.tokens import AdminTokenClaims
from app.db.connection import DatabaseManager
from app.directory.base import DirectoryProvider, DirectoryUnavailableError
from app.engine.resolver import AssignmentRecord, PolicyRecord, PolicyResolver
from app.engine.schema_registry import OsFamily
from app.errors import ApiError

router = APIRouter(prefix="/api/v1/simulator", tags=["simulator"])


class SimulatorEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, max_length=256)
    deviceId: str | None = Field(default=None, max_length=128)
    osFamilyOverride: OsFamily | None = None
    deviceGroupIds: list[str] | None = None


def load_engine_records(
    conn: sqlite3.Connection,
) -> tuple[dict[str, PolicyRecord], list[AssignmentRecord]]:
    pol_rows = conn.execute("SELECT * FROM policies").fetchall()
    policies_by_id: dict[str, PolicyRecord] = {}
    for prow in pol_rows:
        policies_by_id[str(prow["id"])] = PolicyRecord(
            id=str(prow["id"]),
            name=str(prow["name"]),
            is_enabled=bool(prow["is_enabled"]),
            revision=int(prow["revision"]),
            rules=json.loads(prow["rules_json"]),
        )

    asg_rows = conn.execute(
        "SELECT * FROM assignments ORDER BY priority ASC, created_at ASC, id ASC"
    ).fetchall()
    assignments: list[AssignmentRecord] = [
        AssignmentRecord(
            id=str(arow["id"]),
            policy_id=str(arow["policy_id"]),
            priority=int(arow["priority"]),
            is_enabled=bool(arow["is_enabled"]),
            target_user_type=str(arow["target_user_type"]),
            target_user_ref=arow["target_user_ref"],
            target_device_type=str(arow["target_device_type"]),
            target_device_ref=arow["target_device_ref"],
            os_filter=json.loads(arow["os_filter_json"]),
            created_at=str(arow["created_at"]),
        )
        for arow in asg_rows
    ]
    return policies_by_id, assignments


@router.post("/evaluate")
def evaluate_simulation(
    payload: SimulatorEvaluateRequest,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
    directory: DirectoryProvider = Depends(get_directory_provider),
) -> dict[str, Any]:
    clean_username = payload.username.strip() if payload.username and payload.username.strip() else None
    clean_device_id = payload.deviceId.strip() if payload.deviceId and payload.deviceId.strip() else None

    if not clean_device_id and payload.osFamilyOverride is None:
        raise ApiError(
            422,
            "VALIDATION_ERROR",
            "Entweder 'deviceId' oder 'osFamilyOverride' muss angegeben werden",
        )

    resolved_user_groups: list[str] = []
    if clean_username:
        try:
            resolved_user_groups = directory.get_user_groups(clean_username)
        except DirectoryUnavailableError as exc:
            raise ApiError(503, "DIRECTORY_UNAVAILABLE", str(exc)) from exc

    with db.connection() as conn:
        if clean_device_id:
            dev_row = conn.execute(
                "SELECT * FROM devices WHERE id = ?", (clean_device_id,)
            ).fetchone()
            if dev_row is None:
                raise ApiError(404, "NOT_FOUND", f"Gerät '{clean_device_id}' wurde nicht gefunden")

            target_os = payload.osFamilyOverride or str(dev_row["os_family"]).upper()
            device_hostname = str(dev_row["hostname"])

            if payload.deviceGroupIds is not None:
                dev_group_ids = [g.strip() for g in payload.deviceGroupIds if g.strip()]
            else:
                m_rows = conn.execute(
                    "SELECT device_group_id FROM device_group_memberships WHERE device_id = ?",
                    (clean_device_id,),
                ).fetchall()
                dev_group_ids = [str(m["device_group_id"]) for m in m_rows]
        else:
            assert payload.osFamilyOverride is not None
            target_os = payload.osFamilyOverride
            device_hostname = "SIMULATOR-HOST"
            dev_group_ids = [g.strip() for g in (payload.deviceGroupIds or []) if g.strip()]

        dev_group_names: list[str] = []
        if dev_group_ids:
            placeholders = ",".join("?" for _ in dev_group_ids)
            g_rows = conn.execute(
                f"SELECT id, name FROM device_groups WHERE id IN ({placeholders}) ORDER BY name ASC",
                dev_group_ids,
            ).fetchall()
            dev_group_names = [str(g["name"]) for g in g_rows]

        policies_by_id, assignments = load_engine_records(conn)

    eval_result = PolicyResolver.evaluate(
        assignments=assignments,
        policies_by_id=policies_by_id,
        target_os=target_os,
        username=clean_username,
        resolved_user_groups=resolved_user_groups,
        device_id=clean_device_id,
        device_hostname=device_hostname,
        device_group_ids=dev_group_ids,
    )

    return {
        "username": clean_username or "",
        "resolvedUserGroups": resolved_user_groups,
        "device": {
            "id": clean_device_id or "sim-virtual",
            "hostname": device_hostname,
            "osFamily": target_os,
            "deviceGroupNames": dev_group_names,
        },
        "effectiveRules": eval_result.effective_rules,
        "trace": eval_result.trace,
    }
