"""Full-stack live integration test: FastAPI + SQLite + Vue SPA + compiled Rust Agent binary."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _agent_binary() -> Path:
    exe_name = "ns8-policy-agent.exe" if os.name == "nt" else "ns8-policy-agent"
    path = REPO_ROOT / "agent" / "target" / "release" / exe_name
    assert path.is_file(), f"Compiled Rust agent binary missing at {path}"
    return path


@pytest.fixture()
def live_server(tmp_path: Path):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    settings = Settings.from_env(
        {
            "APM_PORT": str(port),
            "APM_DATA_DIR": str(tmp_path / "data"),
            "APM_STATIC_DIR": str(REPO_ROOT / "web" / "dist"),
            "APM_AGENT_ARTIFACTS_DIR": str(REPO_ROOT / "agent"),
            "APM_PUBLIC_URL": base_url,
            "LDAP_MODE": "mock",
            "APM_SEED_DEMO": "false",
        }
    )
    app = create_app(settings=settings)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/api/v1/health", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("Live test server did not start in time")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5.0)


def test_full_stack_spa_installers_and_rust_agent_lifecycle(
    live_server: str, tmp_path: Path
) -> None:
    agent_bin = _agent_binary()

    with httpx.Client(base_url=live_server, timeout=10.0) as client:
        # 1. Verify built Vue 3 SPA is served at / and SPA deep links (/policies)
        root_html = client.get("/")
        assert root_html.status_code == 200
        assert "<!doctype html>" in root_html.text.lower()

        spa_route = client.get("/simulator")
        assert spa_route.status_code == 200
        assert "<!doctype html>" in spa_route.text.lower()

        # 2. Verify installer scripts & compiled native binary delivery
        ps1 = client.get("/api/v1/installers/install.ps1")
        assert ps1.status_code == 200
        assert live_server in ps1.text

        linux_sh = client.get("/api/v1/installers/install-linux.sh")
        assert linux_sh.status_code == 200
        assert "\r\n" not in linux_sh.text
        assert live_server in linux_sh.text

        if os.name == "nt":
            bin_resp = client.get("/api/v1/installers/binaries/windows/x86_64")
            assert bin_resp.status_code == 200
            assert len(bin_resp.content) > 100_000

        # 3. Admin Login via AD/LDAP mock provider
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "administrator", "password": "Admin123!"},
        )
        assert login.status_code == 200, login.text
        token = login.json()["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}

        # 4. Create Device Group, Cross-Platform Policy, Priority Assignment, and Enrollment Token
        grp = client.post(
            "/api/v1/device-groups",
            headers=headers,
            json={
                "name": "Büro Buchhaltung",
                "description": "Verwaltete Arbeitsplätze Buchhaltung",
                "tags": ["finance", "office"],
            },
        )
        assert grp.status_code == 201, grp.text
        grp_id = grp.json()["id"]

        pol = client.post(
            "/api/v1/policies",
            headers=headers,
            json={
                "name": "Buchhaltung Cross-Platform Schutz",
                "description": "Shares, USB-Block, Bildschirmsperre & Browser",
                "isEnabled": True,
                "rules": [
                    {
                        "ruleId": "r-admins",
                        "category": "ACCESS",
                        "ruleType": "access.local_admins",
                        "schemaVersion": 1,
                        "platforms": ["WINDOWS", "LINUX", "MACOS"],
                        "mergeStrategy": "APPEND_UNIQUE",
                        "config": {
                            "adminGroups": ["IT-Admins"],
                            "adminUsers": [],
                            "passwordlessSudo": False,
                        },
                    },
                    {
                        "ruleId": "r-shares",
                        "category": "WORKSPACE",
                        "ruleType": "workspace.network_shares",
                        "schemaVersion": 1,
                        "platforms": ["WINDOWS", "LINUX", "MACOS"],
                        "mergeStrategy": "APPEND_UNIQUE",
                        "config": {
                            "mounts": [
                                {
                                    "id": "m-fin",
                                    "name": "Finanzen",
                                    "protocol": "SMB",
                                    "remotePath": "\\\\files.firma.local\\finanzen",
                                    "windowsDriveLetter": "X:",
                                    "unixMountPath": "/mnt/finanzen",
                                    "reconnectAtLogon": True,
                                }
                            ]
                        },
                    },
                    {
                        "ruleId": "r-usb",
                        "category": "SECURITY",
                        "ruleType": "security.usb_storage",
                        "schemaVersion": 1,
                        "platforms": ["WINDOWS", "LINUX", "MACOS"],
                        "mergeStrategy": "OVERRIDE",
                        "config": {"mode": "BLOCK"},
                    },
                    {
                        "ruleId": "r-browser",
                        "category": "DESKTOP",
                        "ruleType": "desktop.browser",
                        "schemaVersion": 1,
                        "platforms": ["WINDOWS", "LINUX", "MACOS"],
                        "mergeStrategy": "OVERRIDE",
                        "config": {
                            "targets": ["CHROME", "EDGE", "FIREFOX"],
                            "homepageUrl": "https://intranet.firma.local",
                            "restoreOnStartup": "HOMEPAGE",
                            "disableIncognito": True,
                            "disablePasswordManager": False,
                            "forceExtensions": [],
                        },
                    },
                ],
            },
        )
        assert pol.status_code == 201, pol.text
        pol_id = pol.json()["id"]

        asg = client.post(
            "/api/v1/assignments",
            headers=headers,
            json={
                "policyId": pol_id,
                "priority": 1,
                "isEnabled": True,
                "targetUserType": "GROUP",
                "targetUserRef": "Buchhaltung",
                "targetDeviceType": "DEVICE_GROUP",
                "targetDeviceRef": grp_id,
                "osFilter": ["WINDOWS", "LINUX", "MACOS"],
            },
        )
        assert asg.status_code == 201, asg.text
        asg_id = asg.json()["id"]

        enroll_tok_resp = client.post(
            "/api/v1/enrollment-tokens",
            headers=headers,
            json={
                "name": "E2E Rollout Buchhaltung",
                "defaultDeviceGroupId": grp_id,
                "expiresInHours": 24,
                "maxUses": 10,
            },
        )
        assert enroll_tok_resp.status_code == 201, enroll_tok_resp.text
        enroll_token = enroll_tok_resp.json()["plainToken"]

        # 5. Enroll & Sync real Rust agent across WINDOWS, LINUX, and MACOS!
        state_dirs: dict[str, Path] = {}
        for os_family, hostname in [
            ("WINDOWS", "E2E-WIN-FIN01"),
            ("LINUX", "e2e-ubuntu-fin02"),
            ("MACOS", "e2e-macbook-fin03"),
        ]:
            sdir = tmp_path / f"agent-{os_family.lower()}"
            sdir.mkdir(parents=True, exist_ok=True)
            state_dirs[os_family] = sdir

            res_enroll = subprocess.run(
                [
                    str(agent_bin),
                    "enroll",
                    "--server",
                    live_server,
                    "--token",
                    enroll_token,
                    "--hostname",
                    hostname,
                    "--os-override",
                    os_family,
                    "--state-dir",
                    str(sdir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res_enroll.returncode == 0, f"{os_family} enroll failed: {res_enroll.stderr}\n{res_enroll.stdout}"

            res_sync = subprocess.run(
                [
                    str(agent_bin),
                    "sync",
                    "--once",
                    "--dry-run",
                    "--current-user",
                    "m.mueller",
                    "--os-override",
                    os_family,
                    "--state-dir",
                    str(sdir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res_sync.returncode == 0, f"{os_family} sync failed: {res_sync.stderr}\n{res_sync.stdout}"

        # 6. Verify all 3 computers are COMPLIANT in Backend & Simulator matches!
        devices = client.get("/api/v1/devices", headers=headers).json()["data"]
        assert len(devices) == 3
        for dev in devices:
            assert dev["complianceStatus"] == "COMPLIANT", dev
            assert len(dev["complianceItems"]) == 4
            assert all(item["action"] == "ENFORCED" and item["status"] == "APPLIED" for item in dev["complianceItems"])

        win_dev = next(d for d in devices if d["osFamily"] == "WINDOWS")
        sim = client.post(
            "/api/v1/simulator/evaluate",
            headers=headers,
            json={"username": "m.mueller", "deviceId": win_dev["id"]},
        )
        assert sim.status_code == 200
        assert len(sim.json()["effectiveRules"]) == 4

        # 7. Delete Assignment -> Re-sync all 3 Rust agents -> Verify clean ROLLED_BACK!
        del_resp = client.delete(f"/api/v1/assignments/{asg_id}", headers=headers)
        assert del_resp.status_code == 204

        for os_family, sdir in state_dirs.items():
            res_rb = subprocess.run(
                [
                    str(agent_bin),
                    "sync",
                    "--once",
                    "--dry-run",
                    "--current-user",
                    "m.mueller",
                    "--os-override",
                    os_family,
                    "--state-dir",
                    str(sdir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res_rb.returncode == 0, f"{os_family} rollback sync failed: {res_rb.stderr}\n{res_rb.stdout}"

        devices_after = client.get("/api/v1/devices", headers=headers).json()["data"]
        for dev in devices_after:
            assert dev["complianceStatus"] == "COMPLIANT", dev
            assert len(dev["complianceItems"]) == 4
            assert all(
                item["action"] == "ROLLED_BACK" and item["status"] == "APPLIED"
                for item in dev["complianceItems"]
            ), dev["complianceItems"]
