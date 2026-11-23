"""Enrollment Tokens CRUD and OS Installer / Binary delivery endpoints."""

from __future__ import annotations

import hashlib
import platform as py_platform
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth.dependencies import get_db, get_settings, require_admin
from app.auth.tokens import AdminTokenClaims
from app.config import Settings
from app.db.connection import DatabaseManager
from app.db.idempotency import run_idempotent
from app.errors import ApiError, build_paginated_response, utc_now_iso

router = APIRouter(prefix="/api/v1", tags=["enrollment-installers"])

ALLOWED_SCRIPTS = {"install.ps1", "install-linux.sh", "install-macos.sh"}
ALLOWED_PLATFORMS = {"windows", "linux", "macos"}
ALLOWED_ARCHS = {"x86_64", "aarch64", "arm64"}

FALLBACK_SCRIPT_TEMPLATES: dict[str, str] = {
    "install.ps1": """# NS8 Policy Agent - Windows Rollout Script
param(
    [string]$ServerUrl = "{{SERVER_URL}}",
    [string]$Token = $env:APM_TOKEN
)
$ErrorActionPreference = "Stop"
if (-not $Token) { throw "Enrollment token required (-Token or $env:APM_TOKEN)" }
$InstallDir = "$env:ProgramFiles\\NS8PolicyAgent"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$BinPath = Join-Path $InstallDir "ns8-policy-agent.exe"
Invoke-WebRequest -Uri "$ServerUrl/api/v1/installers/binaries/windows/x86_64" -OutFile $BinPath
& $BinPath enroll --server $ServerUrl --token $Token
sc.exe create NS8PolicyAgent binPath= "`"$BinPath`" daemon" start= auto | Out-Null
sc.exe start NS8PolicyAgent | Out-Null
Write-Host "NS8 Policy Agent enrolled and started successfully."
""",
    "install-linux.sh": """#!/usr/bin/env bash
set -euo pipefail
SERVER_URL="${APM_SERVER_URL:-{{SERVER_URL}}}"
TOKEN="${APM_TOKEN:-${2:-}}"
if [[ "${1:-}" == "--token" && -n "${2:-}" ]]; then TOKEN="$2"; fi
if [[ -z "$TOKEN" ]]; then echo "Error: APM_TOKEN or --token required" >&2; exit 1; fi
ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then ARCH="aarch64"; fi
install -d -m 0755 /usr/local/bin /var/lib/ns8-policy-agent
curl -fsSL "${SERVER_URL}/api/v1/installers/binaries/linux/${ARCH}" -o /usr/local/bin/ns8-policy-agent
chmod 0755 /usr/local/bin/ns8-policy-agent
/usr/local/bin/ns8-policy-agent enroll --server "${SERVER_URL}" --token "${TOKEN}"
cat >/etc/systemd/system/ns8-policy-agent.service <<'EOF'
[Unit]
Description=NS8 Cross-Platform Policy Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ns8-policy-agent daemon
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ns8-policy-agent.service
echo "NS8 Policy Agent enrolled and active."
""",
    "install-macos.sh": """#!/usr/bin/env zsh
set -euo pipefail
SERVER_URL="${APM_SERVER_URL:-{{SERVER_URL}}}"
TOKEN="${APM_TOKEN:-${2:-}}"
if [[ "${1:-}" == "--token" && -n "${2:-}" ]]; then TOKEN="$2"; fi
if [[ -z "$TOKEN" ]]; then echo "Error: APM_TOKEN or --token required" >&2; exit 1; fi
ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then ARCH="aarch64"; fi
mkdir -p /usr/local/bin /Library/Application\\ Support/NS8PolicyAgent
curl -fsSL "${SERVER_URL}/api/v1/installers/binaries/macos/${ARCH}" -o /usr/local/bin/ns8-policy-agent
chmod 0755 /usr/local/bin/ns8-policy-agent
/usr/local/bin/ns8-policy-agent enroll --server "${SERVER_URL}" --token "${TOKEN}"
cat >/Library/LaunchDaemons/org.nethserver.policyagent.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.nethserver.policyagent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ns8-policy-agent</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
EOF
launchctl load -w /Library/LaunchDaemons/org.nethserver.policyagent.plist
echo "NS8 Policy Agent enrolled and loaded."
""",
}


class CreateEnrollmentTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    defaultDeviceGroupId: str | None = Field(default=None, max_length=128)
    expiresInHours: int = Field(default=168, ge=1, le=8760)
    maxUses: int = Field(default=50, ge=1, le=100000)


def _resolve_public_url(settings: Settings, request: Request) -> str:
    if settings.apm_public_url and settings.apm_public_url != "http://localhost:8080":
        return settings.apm_public_url.rstrip("/")
    base = str(request.base_url).rstrip("/")
    return base or settings.apm_public_url.rstrip("/")


def _build_install_commands(public_url: str, token_placeholder: str) -> dict[str, str]:
    return {
        "windowsPowershell": (
            f'$env:APM_TOKEN="{token_placeholder}"; '
            f'irm "{public_url}/api/v1/installers/install.ps1" | iex'
        ),
        "linuxBash": (
            f'curl -fsSL "{public_url}/api/v1/installers/install-linux.sh" | '
            f'sudo APM_TOKEN="{token_placeholder}" bash -s -- --token "{token_placeholder}"'
        ),
        "macosZsh": (
            f'curl -fsSL "{public_url}/api/v1/installers/install-macos.sh" | '
            f'sudo APM_TOKEN="{token_placeholder}" zsh -s -- --token "{token_placeholder}"'
        ),
    }


def _row_to_token_dict(
    row: sqlite3.Row,
    public_url: str,
    plain_token: str | None = None,
) -> dict[str, Any]:
    token_for_cmd = plain_token if plain_token else "<ENROLL_TOKEN>"
    result: dict[str, Any] = {
        "id": row["id"],
        "name": row["name"],
        "plainToken": plain_token,
        "tokenPrefix": row["token_prefix"],
        "defaultDeviceGroupId": row["default_device_group_id"],
        "defaultDeviceGroupName": row["default_device_group_name"],
        "expiresAt": row["expires_at"],
        "maxUses": int(row["max_uses"]),
        "useCount": int(row["use_count"]),
        "createdAt": row["created_at"],
        "installCommands": _build_install_commands(public_url, token_for_cmd),
    }
    return result


TOKEN_SELECT_SQL = """
SELECT
    t.*,
    dg.name AS default_device_group_name
FROM enrollment_tokens t
LEFT JOIN device_groups dg ON dg.id = t.default_device_group_id
"""


@router.get("/enrollment-tokens")
def list_enrollment_tokens(
    request: Request,
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=25, ge=1, le=200),
    _claims: AdminTokenClaims = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
) -> dict[str, Any]:
    offset = (page - 1) * pageSize
    public_url = _resolve_public_url(settings, request)
    with db.connection() as conn:
        total = int(
            conn.execute("SELECT COUNT(*) AS cnt FROM enrollment_tokens").fetchone()["cnt"]
        )
        rows = conn.execute(
            f"""
            {TOKEN_SELECT_SQL}
            ORDER BY t.created_at DESC, t.id DESC
            LIMIT ? OFFSET ?
            """,
            (pageSize, offset),
        ).fetchall()

    return build_paginated_response(
        items=[_row_to_token_dict(r, public_url, plain_token=None) for r in rows],
        page=page,
        page_size=pageSize,
        total_items=total,
    )


@router.post("/enrollment-tokens", status_code=201)
def create_enrollment_token(
    request: Request,
    payload: CreateEnrollmentTokenRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _claims: AdminTokenClaims = Depends(require_admin),
    settings: Settings = Depends(get_settings),
    db: DatabaseManager = Depends(get_db),
) -> JSONResponse:
    raw_dict = payload.model_dump(mode="json")
    public_url = _resolve_public_url(settings, request)

    def _create() -> tuple[int, dict[str, Any]]:
        clean_grp_id = (
            payload.defaultDeviceGroupId.strip()
            if payload.defaultDeviceGroupId and payload.defaultDeviceGroupId.strip()
            else None
        )
        with db.transaction() as conn:
            if clean_grp_id is not None:
                grp = conn.execute(
                    "SELECT id FROM device_groups WHERE id = ?",
                    (clean_grp_id,),
                ).fetchone()
                if grp is None:
                    raise ApiError(
                        404,
                        "NOT_FOUND",
                        f"Gerätegruppe '{clean_grp_id}' existiert nicht",
                    )

            tok_id = f"tok-{secrets.token_hex(6)}"
            plain_token = f"apm_enroll_{secrets.token_hex(18)}"
            token_prefix = plain_token[:15]
            token_hash = hashlib.sha256(plain_token.encode("utf-8")).hexdigest()

            now_dt = datetime.now(timezone.utc).replace(microsecond=0)
            expires_dt = now_dt + timedelta(hours=payload.expiresInHours)
            now_iso = now_dt.isoformat().replace("+00:00", "Z")
            expires_iso = expires_dt.isoformat().replace("+00:00", "Z")

            conn.execute(
                """
                INSERT INTO enrollment_tokens (
                    id, name, token_hash, token_prefix, default_device_group_id,
                    expires_at, max_uses, use_count, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    tok_id,
                    payload.name.strip(),
                    token_hash,
                    token_prefix,
                    clean_grp_id,
                    expires_iso,
                    payload.maxUses,
                    now_iso,
                ),
            )
            row = conn.execute(
                f"{TOKEN_SELECT_SQL} WHERE t.id = ?",
                (tok_id,),
            ).fetchone()

        return 201, _row_to_token_dict(row, public_url, plain_token=plain_token)

    return run_idempotent(
        db=db,
        idempotency_key=idempotency_key,
        endpoint="POST:/api/v1/enrollment-tokens",
        payload_for_hash=raw_dict,
        action=_create,
    )


@router.delete("/enrollment-tokens/{token_id}", status_code=204)
def delete_enrollment_token(
    token_id: str,
    _claims: AdminTokenClaims = Depends(require_admin),
    db: DatabaseManager = Depends(get_db),
) -> Response:
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT id FROM enrollment_tokens WHERE id = ?", (token_id,)
        ).fetchone()
        if existing is None:
            raise ApiError(404, "NOT_FOUND", f"Enrollment-Token '{token_id}' wurde nicht gefunden")
        conn.execute("DELETE FROM enrollment_tokens WHERE id = ?", (token_id,))
    return Response(status_code=204)


@router.get("/installers/binaries/{platform}/{arch}")
def download_agent_binary(
    platform: str,
    arch: str,
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    plat = platform.strip().lower()
    clean_arch = arch.strip().lower()
    if clean_arch == "arm64":
        norm_archs = ["aarch64", "arm64"]
    elif clean_arch == "aarch64":
        norm_archs = ["aarch64", "arm64"]
    else:
        norm_archs = [clean_arch]

    if plat not in ALLOWED_PLATFORMS or clean_arch not in ALLOWED_ARCHS:
        raise ApiError(
            404,
            "BINARY_NOT_BUILT",
            f"Kein vorkompiliertes Agent-Binary für {plat}/{clean_arch} verfügbar",
            details={"platform": plat, "arch": clean_arch},
        )

    bin_name = "ns8-policy-agent.exe" if plat == "windows" else "ns8-policy-agent"
    artifacts_dir = settings.resolve_agent_artifacts_dir()

    candidates: list[Path] = []
    for a in norm_archs:
        candidates.append(artifacts_dir / "binaries" / plat / a / bin_name)

    # Local dev fallback (`agent/target/release/ns8-policy-agent[.exe]`) when host OS & arch match
    sys_os = py_platform.system().lower()
    host_plat = "macos" if sys_os == "darwin" else sys_os
    raw_machine = py_platform.machine().lower()
    host_arch = "x86_64" if raw_machine in ("amd64", "x86_64") else ("aarch64" if raw_machine in ("arm64", "aarch64") else raw_machine)

    if plat == host_plat and host_arch in norm_archs:
        candidates.append(artifacts_dir / "target" / "release" / bin_name)

    for candidate in candidates:
        if candidate.is_file():
            return FileResponse(
                path=str(candidate),
                media_type="application/octet-stream",
                filename=bin_name,
            )

    raise ApiError(
        404,
        "BINARY_NOT_BUILT",
        f"Agent-Binary für {plat}/{clean_arch} ist lokal nicht vorgebaut",
        details={"platform": plat, "arch": clean_arch},
    )


@router.get("/installers/{script_name}")
def download_installer_script(
    script_name: str,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> PlainTextResponse:
    clean_name = script_name.strip()
    if clean_name not in ALLOWED_SCRIPTS:
        raise ApiError(404, "NOT_FOUND", f"Installationsskript '{clean_name}' existiert nicht")

    artifacts_dir = settings.resolve_agent_artifacts_dir()
    script_candidates = [
        artifacts_dir / "installers" / clean_name,
        artifacts_dir / clean_name,
    ]

    content: str | None = None
    for path in script_candidates:
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            break

    if content is None:
        content = FALLBACK_SCRIPT_TEMPLATES[clean_name]

    public_url = _resolve_public_url(settings, request)
    rendered = (
        content.replace("{{SERVER_URL}}", public_url)
        .replace("{{APM_PUBLIC_URL}}", public_url)
        .replace("__APM_PUBLIC_URL__", public_url)
    )
    if clean_name.endswith(".sh"):
        rendered = rendered.replace("\r\n", "\n")

    return PlainTextResponse(content=rendered, media_type="text/plain; charset=utf-8")
