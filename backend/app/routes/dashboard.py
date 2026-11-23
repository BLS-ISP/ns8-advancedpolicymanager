"""Health, Dashboard Summary, and Schema Catalog endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends

from app import __version__
from app.adapters.delivery import DELIVERY_ADAPTERS
from app.auth.dependencies import get_db, get_settings, require_admin
from app.auth.tokens import AdminTokenClaims
from app.config import Settings
from app.db.connection import DatabaseManager
from app.engine.schema_registry import ALL_CATEGORIES, ALL_PLATFORMS, RULE_REGISTRY

router = APIRouter(prefix="/api/v1", tags=["system-dashboard"])


def _is_device_offline(compliance_status: str, last_seen_at: str) -> bool:
    if compliance_status.upper() == "OFFLINE":
        return True
    try:
        parsed = datetime.fromisoformat(last_seen_at.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - parsed > timedelta(hours=24):
            return True
    except Exception:
        pass
    return False


@router.get("/health")
def health(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "ldapMode": settings.ldap_mode,
        "ldapDomain": settings.ldap_domain,
    }


@router.get("/dashboard/summary")
def dashboard_summary(
    _claims: AdminTokenClaims = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    with db.connection() as conn:
        dev_rows = conn.execute(
            "SELECT os_family, compliance_status, last_seen_at FROM devices"
        ).fetchall()

        total_devices = len(dev_rows)
        compliant_devices = 0
        degraded_devices = 0
        error_devices = 0
        offline_devices = 0
        device_by_os: dict[str, int] = {"WINDOWS": 0, "LINUX": 0, "MACOS": 0}

        for row in dev_rows:
            os_fam = str(row["os_family"]).upper()
            device_by_os[os_fam] = device_by_os.get(os_fam, 0) + 1

            status = str(row["compliance_status"]).upper()
            if _is_device_offline(status, str(row["last_seen_at"])):
                offline_devices += 1
            elif status == "COMPLIANT":
                compliant_devices += 1
            elif status == "DEGRADED":
                degraded_devices += 1
            elif status == "ERROR":
                error_devices += 1
            else:
                compliant_devices += 1

        active_policies = int(
            conn.execute("SELECT COUNT(*) AS cnt FROM policies WHERE is_enabled = 1").fetchone()["cnt"]
        )
        active_assignments = int(
            conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM assignments a
                JOIN policies p ON p.id = a.policy_id
                WHERE a.is_enabled = 1 AND p.is_enabled = 1
                """
            ).fetchone()["cnt"]
        )

        event_rows = conn.execute(
            """
            SELECT id, timestamp, device_hostname, status, message
            FROM compliance_events
            ORDER BY timestamp DESC, rowid DESC
            LIMIT 15
            """
        ).fetchall()

    recent_events = [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "deviceHostname": row["device_hostname"],
            "status": row["status"],
            "message": row["message"],
        }
        for row in event_rows
    ]

    return {
        "totalDevices": total_devices,
        "compliantDevices": compliant_devices,
        "degradedDevices": degraded_devices,
        "errorDevices": error_devices,
        "offlineDevices": offline_devices,
        "activePolicies": active_policies,
        "activeAssignments": active_assignments,
        "deviceByOs": device_by_os,
        "ldapDomain": settings.ldap_domain,
        "ldapSchema": settings.ldap_schema,
        "recentEvents": recent_events,
    }


@router.get("/schema/catalog")
def schema_catalog(
    _claims: AdminTokenClaims = Depends(require_admin),
) -> dict[str, Any]:
    entries = [defn.to_catalog_entry() for defn in RULE_REGISTRY.values()]
    return {
        "schemaVersion": 1,
        "categories": list(ALL_CATEGORIES),
        "platforms": list(ALL_PLATFORMS),
        "rules": entries,
        "ruleTypes": entries,
        "deliveryAdapters": [adapter.to_catalog_entry() for adapter in DELIVERY_ADAPTERS],
    }
