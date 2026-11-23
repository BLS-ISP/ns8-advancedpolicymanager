"""Agent Enrollment, Check-in, and Compliance Reporting endpoints (`/api/v1/agent/*`)."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.adapters.delivery import AgentBundleDeliveryAdapter
from app.auth.dependencies import (
    extract_bearer_token,
    get_db,
    get_directory_provider,
    get_settings,
)
from app.config import Settings
from app.db.connection import DatabaseManager
from app.db.idempotency import run_idempotent
from app.db.schema import get_cluster_revision
from app.directory.base import DirectoryProvider, DirectoryUnavailableError
from app.engine.resolver import PolicyResolver
from app.engine.schema_registry import OsFamily
from app.errors import ApiError, utc_now_iso
from app.routes.simulator import load_engine_records

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])

_agent_bundle_adapter = AgentBundleDeliveryAdapter()


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enrollmentToken: str = Field(min_length=1, max_length=512)
    hostname: str = Field(min_length=1, max_length=255)
    osFamily: OsFamily
    osVersion: str = Field(default="", max_length=255)
    arch: str = Field(default="x86_64", min_length=1, max_length=64)
    agentVersion: str = Field(default="1.0.0", min_length=1, max_length=64)
    machineId: str | None = Field(default=None, max_length=255)


class AgentCheckinRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=255)
    osFamily: OsFamily
    osVersion: str = Field(default="", max_length=255)
    agentVersion: str = Field(default="1.0.0", min_length=1, max_length=64)
    currentUser: str | None = Field(default=None, max_length=255)
    appliedRevision: int = Field(default=0, ge=0)


class ComplianceItemInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ruleType: str = Field(min_length=1, max_length=128)
    action: Literal["ENFORCED", "ROLLED_BACK"] = "ENFORCED"
    status: Literal["APPLIED", "SKIPPED_UNSUPPORTED", "FAILED"]
    message: str = Field(default="", max_length=2000)


class AgentComplianceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    appliedRevision: int = Field(ge=0)
    status: Literal["COMPLIANT", "DEGRADED", "ERROR"]
    items: list[ComplianceItemInput] = Field(default_factory=list)


def _authenticate_device(request: Request, conn: sqlite3.Connection) -> sqlite3.Row:
    raw_token = extract_bearer_token(request)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    dev_row = conn.execute(
        "SELECT * FROM devices WHERE device_token_hash = ?",
        (token_hash,),
    ).fetchone()
    if dev_row is None:
        raise ApiError(401, "UNAUTHORIZED", "Ungültiges oder widerrufenes Geräte-Token")
    return dev_row


@router.post("/enroll", status_code=201)
def agent_enroll(
    payload: AgentEnrollRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
) -> JSONResponse:
    raw_dict = payload.model_dump(mode="json")

    def _enroll() -> tuple[int, dict[str, Any]]:
        enroll_hash = hashlib.sha256(payload.enrollmentToken.strip().encode("utf-8")).hexdigest()
        now_dt = datetime.now(timezone.utc).replace(microsecond=0)
        now_iso = now_dt.isoformat().replace("+00:00", "Z")

        with db.transaction(immediate=True) as conn:
            tok_row = conn.execute(
                "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
                (enroll_hash,),
            ).fetchone()
            if tok_row is None:
                raise ApiError(401, "INVALID_ENROLLMENT_TOKEN", "Ungültiges Enrollment-Token")

            expires_dt = datetime.fromisoformat(str(tok_row["expires_at"]).replace("Z", "+00:00"))
            if expires_dt <= now_dt:
                raise ApiError(401, "ENROLLMENT_TOKEN_EXPIRED", "Enrollment-Token ist abgelaufen")

            if int(tok_row["use_count"]) >= int(tok_row["max_uses"]):
                raise ApiError(
                    403,
                    "ENROLLMENT_TOKEN_EXHAUSTED",
                    "Maximale Anzahl an Registrierungen für dieses Enrollment-Token erreicht",
                )

            conn.execute(
                "UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = ?",
                (tok_row["id"],),
            )

            device_id = f"dev-{secrets.token_hex(6)}"
            plain_device_token = f"apm_dev_{secrets.token_hex(24)}"
            device_token_hash = hashlib.sha256(plain_device_token.encode("utf-8")).hexdigest()

            conn.execute(
                """
                INSERT INTO devices (
                    id, hostname, os_family, os_version, arch, agent_version, machine_id,
                    current_user, device_token_hash, applied_revision, compliance_status,
                    compliance_items_json, last_seen_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 0, 'COMPLIANT', '[]', ?, ?)
                """,
                (
                    device_id,
                    payload.hostname.strip(),
                    payload.osFamily,
                    payload.osVersion.strip(),
                    payload.arch.strip(),
                    payload.agentVersion.strip(),
                    payload.machineId.strip() if payload.machineId else None,
                    device_token_hash,
                    now_iso,
                    now_iso,
                ),
            )

            default_grp = tok_row["default_device_group_id"]
            if default_grp:
                conn.execute(
                    "INSERT OR IGNORE INTO device_group_memberships (device_id, device_group_id) VALUES (?, ?)",
                    (device_id, default_grp),
                )

            conn.execute(
                """
                INSERT INTO compliance_events (id, timestamp, device_id, device_hostname, status, message)
                VALUES (?, ?, ?, ?, 'COMPLIANT', ?)
                """,
                (
                    f"evt-{secrets.token_hex(6)}",
                    now_iso,
                    device_id,
                    payload.hostname.strip(),
                    f"Gerät neu registriert ({payload.osFamily})",
                ),
            )

        return (
            201,
            {
                "deviceId": device_id,
                "deviceToken": plain_device_token,
                "pollIntervalSeconds": settings.poll_interval_seconds,
            },
        )

    return run_idempotent(
        db=db,
        idempotency_key=idempotency_key,
        endpoint="POST:/api/v1/agent/enroll",
        payload_for_hash=raw_dict,
        action=_enroll,
    )


@router.post("/checkin")
def agent_checkin(
    request: Request,
    payload: AgentCheckinRequest,
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
    directory: DirectoryProvider = Depends(get_directory_provider),
) -> dict[str, Any]:
    clean_user = (
        payload.currentUser.strip()
        if payload.currentUser and payload.currentUser.strip()
        else None
    )
    now_iso = utc_now_iso()

    with db.transaction() as conn:
        dev_row = _authenticate_device(request, conn)
        device_id = str(dev_row["id"])

        conn.execute(
            """
            UPDATE devices
            SET hostname = ?, os_family = ?, os_version = ?, agent_version = ?,
                current_user = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (
                payload.hostname.strip(),
                payload.osFamily,
                payload.osVersion.strip(),
                payload.agentVersion.strip(),
                clean_user,
                now_iso,
                device_id,
            ),
        )

        m_rows = conn.execute(
            "SELECT device_group_id FROM device_group_memberships WHERE device_id = ?",
            (device_id,),
        ).fetchall()
        dev_group_ids = [str(m["device_group_id"]) for m in m_rows]

        policies_by_id, assignments = load_engine_records(conn)
        bundle_revision = get_cluster_revision(conn)

    resolved_groups: list[str] = []
    if clean_user:
        try:
            resolved_groups = directory.get_user_groups(clean_user)
        except DirectoryUnavailableError:
            resolved_groups = []

    eval_result = PolicyResolver.evaluate(
        assignments=assignments,
        policies_by_id=policies_by_id,
        target_os=payload.osFamily,
        username=clean_user,
        resolved_user_groups=resolved_groups,
        device_id=device_id,
        device_hostname=payload.hostname.strip(),
        device_group_ids=dev_group_ids,
    )

    return _agent_bundle_adapter.render_delivery_artifact(
        device_id=device_id,
        bundle_revision=bundle_revision,
        effective_rules=eval_result.effective_rules,
        poll_interval_seconds=settings.poll_interval_seconds,
    )


@router.post("/compliance")
def agent_compliance(
    request: Request,
    payload: AgentComplianceRequest,
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    recorded_at = utc_now_iso()
    items_dicts = [item.model_dump(mode="json") for item in payload.items]

    enforced_count = sum(1 for it in items_dicts if it["action"] == "ENFORCED")
    rolled_back_count = sum(1 for it in items_dicts if it["action"] == "ROLLED_BACK")

    if rolled_back_count > 0:
        summary_msg = (
            f"{enforced_count} Regeln aktiv, {rolled_back_count} zurückgerollt "
            f"(Revision {payload.appliedRevision})"
        )
    else:
        summary_msg = f"{enforced_count} Regeln aktiv (Revision {payload.appliedRevision})"

    with db.transaction() as conn:
        dev_row = _authenticate_device(request, conn)
        device_id = str(dev_row["id"])
        device_hostname = str(dev_row["hostname"])

        conn.execute(
            """
            UPDATE devices
            SET applied_revision = ?, compliance_status = ?, compliance_items_json = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (
                payload.appliedRevision,
                payload.status,
                json.dumps(items_dicts, ensure_ascii=False),
                recorded_at,
                device_id,
            ),
        )

        conn.execute(
            """
            INSERT INTO compliance_events (id, timestamp, device_id, device_hostname, status, message)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"evt-{secrets.token_hex(6)}",
                recorded_at,
                device_id,
                device_hostname,
                payload.status,
                summary_msg,
            ),
        )

        conn.execute(
            """
            DELETE FROM compliance_events
            WHERE id NOT IN (
                SELECT id FROM compliance_events ORDER BY timestamp DESC, rowid DESC LIMIT 200
            )
            """
        )

    return {
        "acknowledged": True,
        "recordedAt": recorded_at,
    }
