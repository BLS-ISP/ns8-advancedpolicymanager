"""Tests for Priority Conflict Resolution, Simulator Trace, Installers, SPA, and Agent Lifecycle."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_priority_conflict_resolution_override_append_unique_and_simulator(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    # Create Device Group "Büro Buchhaltung"
    grp_res = client.post(
        "/api/v1/device-groups",
        headers=admin_headers,
        json={"name": "Büro Buchhaltung", "description": "2. OG", "tags": ["finance"]},
    )
    grp_id = grp_res.json()["id"]

    # Policy A (Priority 1 - IT & Finance Specific):
    # - OVERRIDE security.usb_storage -> READ_ONLY
    # - APPEND_UNIQUE workspace.network_shares -> [share-1 (override X:), share-2]
    # - APPEND_UNIQUE access.local_admins -> [IT-Admins]
    # - APPEND_UNIQUE custom.raw_setting -> [raw-win-1, raw-lnx-1]
    pol_high = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "Abteilungs-Regeln",
            "isEnabled": True,
            "rules": [
                {
                    "ruleId": "high-usb",
                    "category": "SECURITY",
                    "ruleType": "security.usb_storage",
                    "mergeStrategy": "OVERRIDE",
                    "config": {"mode": "READ_ONLY"},
                },
                {
                    "ruleId": "high-shares",
                    "category": "WORKSPACE",
                    "ruleType": "workspace.network_shares",
                    "mergeStrategy": "APPEND_UNIQUE",
                    "config": {
                        "mounts": [
                            {
                                "id": "share-common",
                                "name": "Common-Prio1",
                                "protocol": "SMB",
                                "remotePath": "\\\\files.firma.local\\common-prio1",
                                "windowsDriveLetter": "Z:",
                                "unixMountPath": "/mnt/common",
                            },
                            {
                                "id": "share-buchhaltung",
                                "name": "Buchhaltung",
                                "protocol": "SMB",
                                "remotePath": "\\\\files.firma.local\\buchhaltung",
                                "windowsDriveLetter": "X:",
                                "unixMountPath": "/mnt/buchhaltung",
                            },
                        ]
                    },
                },
                {
                    "ruleId": "high-admins",
                    "category": "ACCESS",
                    "ruleType": "access.local_admins",
                    "mergeStrategy": "APPEND_UNIQUE",
                    "config": {
                        "adminGroups": ["IT-Admins"],
                        "adminUsers": ["s.weber"],
                        "passwordlessSudo": True,
                    },
                },
                {
                    "ruleId": "high-raw",
                    "category": "CUSTOM_FINETUNING",
                    "ruleType": "custom.raw_setting",
                    "mergeStrategy": "APPEND_UNIQUE",
                    "config": {
                        "items": [
                            {
                                "id": "raw-win",
                                "targetOs": "WINDOWS",
                                "engine": "REGISTRY",
                                "path": "HKLM\\SOFTWARE\\Policies\\Custom",
                                "key": "WinFlag",
                                "valueType": "INT",
                                "value": "1",
                            },
                            {
                                "id": "raw-lnx",
                                "targetOs": "LINUX",
                                "engine": "SYSCTL",
                                "path": "/etc/sysctl.d/99-apm.conf",
                                "key": "kernel.yama.ptrace_scope",
                                "valueType": "INT",
                                "value": "1",
                            },
                        ]
                    },
                },
            ],
        },
    ).json()

    # Policy B (Priority 2 - Global Base):
    # - OVERRIDE security.usb_storage -> BLOCK (should be OVERRIDDEN by Priority 1)
    # - APPEND_UNIQUE workspace.network_shares -> [share-common (lower prio ignored), share-public (merged!)]
    # - APPEND_UNIQUE access.local_admins -> [Domain Admins, it-admins (ci duplicate)]
    # - OVERRIDE security.screen_lock -> 300s (inherited uncontested)
    pol_low = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "Globale Basis",
            "isEnabled": True,
            "rules": [
                {
                    "ruleId": "low-usb",
                    "category": "SECURITY",
                    "ruleType": "security.usb_storage",
                    "mergeStrategy": "OVERRIDE",
                    "config": {"mode": "BLOCK"},
                },
                {
                    "ruleId": "low-shares",
                    "category": "WORKSPACE",
                    "ruleType": "workspace.network_shares",
                    "mergeStrategy": "APPEND_UNIQUE",
                    "config": {
                        "mounts": [
                            {
                                "id": "share-common",
                                "name": "Common-Prio2-Shadowed",
                                "protocol": "SMB",
                                "remotePath": "\\\\files.firma.local\\old",
                                "windowsDriveLetter": "Z:",
                            },
                            {
                                "id": "share-public",
                                "name": "Public",
                                "protocol": "SMB",
                                "remotePath": "\\\\files.firma.local\\public",
                                "windowsDriveLetter": "P:",
                            },
                        ]
                    },
                },
                {
                    "ruleId": "low-admins",
                    "category": "ACCESS",
                    "ruleType": "access.local_admins",
                    "mergeStrategy": "APPEND_UNIQUE",
                    "config": {
                        "adminGroups": ["it-admins", "Domain Admins"],
                        "adminUsers": [],
                        "passwordlessSudo": False,
                    },
                },
                {
                    "ruleId": "low-screenlock",
                    "category": "SECURITY",
                    "ruleType": "security.screen_lock",
                    "mergeStrategy": "OVERRIDE",
                    "config": {"idleTimeoutSeconds": 300, "requirePasswordOnWake": True, "lockDelaySeconds": 5},
                },
            ],
        },
    ).json()

    # Assignment 1 (Priority 1): Group Buchhaltung + Device Group grp_id
    client.post(
        "/api/v1/assignments",
        headers=admin_headers,
        json={
            "policyId": pol_high["id"],
            "priority": 1,
            "isEnabled": True,
            "targetUserType": "GROUP",
            "targetUserRef": "Buchhaltung",
            "targetDeviceType": "DEVICE_GROUP",
            "targetDeviceRef": grp_id,
            "osFilter": ["WINDOWS", "LINUX"],
        },
    )
    # Assignment 2 (Priority 2): ALL users + ALL devices
    client.post(
        "/api/v1/assignments",
        headers=admin_headers,
        json={
            "policyId": pol_low["id"],
            "priority": 2,
            "isEnabled": True,
            "targetUserType": "ALL",
            "targetDeviceType": "ALL",
            "osFilter": ["WINDOWS", "LINUX", "MACOS"],
        },
    )

    # Evaluate Simulator for m.mueller (in Buchhaltung) on WINDOWS in grp_id
    sim_res = client.post(
        "/api/v1/simulator/evaluate",
        headers=admin_headers,
        json={
            "username": "m.mueller",
            "osFamilyOverride": "WINDOWS",
            "deviceGroupIds": [grp_id],
        },
    )
    assert sim_res.status_code == 200
    sim = sim_res.json()
    assert "Buchhaltung" in sim["resolvedUserGroups"]
    assert sim["device"]["deviceGroupNames"] == ["Büro Buchhaltung"]

    by_type = {r["ruleType"]: r for r in sim["effectiveRules"]}
    trace_by_type = {t["ruleType"]: t for t in sim["trace"]}

    # 1. OVERRIDE check: usb_storage == READ_ONLY, shadowed == pol_low (OVERRIDDEN)
    assert by_type["security.usb_storage"]["config"]["mode"] == "READ_ONLY"
    usb_trace = trace_by_type["security.usb_storage"]
    assert usb_trace["winningPolicyId"] == pol_high["id"]
    assert usb_trace["winningPriority"] == 1
    assert usb_trace["shadowedPolicies"] == [
        {
            "policyId": pol_low["id"],
            "policyName": "Globale Basis",
            "priority": 2,
            "action": "OVERRIDDEN",
        }
    ]

    # 2. APPEND_UNIQUE check on network_shares: share-common keeps Prio1 version, share-public appended
    mounts = by_type["workspace.network_shares"]["config"]["mounts"]
    assert [m["id"] for m in mounts] == ["share-common", "share-buchhaltung", "share-public"]
    assert mounts[0]["name"] == "Common-Prio1"
    assert trace_by_type["workspace.network_shares"]["shadowedPolicies"][0]["action"] == "MERGED"

    # 3. APPEND_UNIQUE check on local_admins: case-insensitive dedupe + top scalar wins
    admins_cfg = by_type["access.local_admins"]["config"]
    assert admins_cfg["adminGroups"] == ["IT-Admins", "Domain Admins"]
    assert admins_cfg["adminUsers"] == ["s.weber"]
    assert admins_cfg["passwordlessSudo"] is True

    # 4. OS filtering on custom.raw_setting: WINDOWS evaluation gets ONLY raw-win
    raw_items = by_type["custom.raw_setting"]["config"]["items"]
    assert [it["id"] for it in raw_items] == ["raw-win"]

    # 5. Evaluate for t.fischer (Schulung, not Buchhaltung) on MACOS -> gets ONLY Global Base
    sim_mac = client.post(
        "/api/v1/simulator/evaluate",
        headers=admin_headers,
        json={"username": "t.fischer", "osFamilyOverride": "MACOS"},
    ).json()
    mac_by_type = {r["ruleType"]: r for r in sim_mac["effectiveRules"]}
    assert mac_by_type["security.usb_storage"]["config"]["mode"] == "BLOCK"
    assert "custom.raw_setting" not in mac_by_type


def test_full_agent_enroll_checkin_compliance_policy_removal_and_revocation(
    client: TestClient,
    admin_headers: dict[str, str],
    test_settings: Settings,
) -> None:
    # 1. Create Device Group + Policy + Assignment + Enrollment Token (maxUses=1)
    grp = client.post(
        "/api/v1/device-groups",
        headers=admin_headers,
        json={"name": "Workstations", "description": "Desktop-PCs"},
    ).json()

    pol = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "USB & Wallpaper",
            "isEnabled": True,
            "rules": [
                {
                    "ruleId": "r-usb",
                    "category": "SECURITY",
                    "ruleType": "security.usb_storage",
                    "config": {"mode": "BLOCK"},
                },
                {
                    "ruleId": "r-wall",
                    "category": "DESKTOP",
                    "ruleType": "desktop.wallpaper",
                    "config": {
                        "imageUrl": "https://intranet.firma.local/bg.jpg",
                        "fitMode": "FILL",
                        "isLocked": True,
                    },
                },
            ],
        },
    ).json()

    asg = client.post(
        "/api/v1/assignments",
        headers=admin_headers,
        json={
            "policyId": pol["id"],
            "priority": 1,
            "isEnabled": True,
            "targetUserType": "GROUP",
            "targetUserRef": "Buchhaltung",
            "targetDeviceType": "DEVICE_GROUP",
            "targetDeviceRef": grp["id"],
            "osFilter": ["WINDOWS"],
        },
    ).json()

    tok_res = client.post(
        "/api/v1/enrollment-tokens",
        headers=admin_headers,
        json={
            "name": "Single-Use Rollout",
            "defaultDeviceGroupId": grp["id"],
            "expiresInHours": 24,
            "maxUses": 1,
        },
    )
    assert tok_res.status_code == 201
    tok_body = tok_res.json()
    plain_enroll_token = tok_body["plainToken"]
    assert plain_enroll_token.startswith("apm_enroll_")
    assert "https://policies.firma.local" in tok_body["installCommands"]["windowsPowershell"]

    # 2. Verify Installer Scripts & Binary endpoints
    ps1 = client.get("/api/v1/installers/install.ps1")
    assert ps1.status_code == 200
    assert "https://policies.firma.local" in ps1.text

    sh_linux = client.get("/api/v1/installers/install-linux.sh")
    assert sh_linux.status_code == 200
    assert "\r" not in sh_linux.text
    assert "https://policies.firma.local" in sh_linux.text

    # Binary before build -> 404 BINARY_NOT_BUILT
    missing_bin = client.get("/api/v1/installers/binaries/linux/aarch64")
    assert missing_bin.status_code == 404
    assert missing_bin.json()["error"]["code"] == "BINARY_NOT_BUILT"

    # Place dummy binary in artifacts dir -> 200 octet-stream
    bin_path = Path(test_settings.apm_agent_artifacts_dir) / "binaries" / "linux" / "aarch64" / "ns8-policy-agent"
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_bytes(b"\x7fELF-mock-agent-binary")
    found_bin = client.get("/api/v1/installers/binaries/linux/aarch64")
    assert found_bin.status_code == 200
    assert found_bin.content == b"\x7fELF-mock-agent-binary"

    # 3. Enroll Agent -> 201
    bad_enroll = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollmentToken": "apm_enroll_invalid",
            "hostname": "WIN-BUCH-01",
            "osFamily": "WINDOWS",
            "osVersion": "Windows 11 Pro 24H2",
            "arch": "x86_64",
            "agentVersion": "1.0.0",
            "machineId": "hw-uuid-1234",
        },
    )
    assert bad_enroll.status_code == 401
    assert bad_enroll.json()["error"]["code"] == "INVALID_ENROLLMENT_TOKEN"

    enroll_ok = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollmentToken": plain_enroll_token,
            "hostname": "WIN-BUCH-01",
            "osFamily": "WINDOWS",
            "osVersion": "Windows 11 Pro 24H2",
            "arch": "x86_64",
            "agentVersion": "1.0.0",
            "machineId": "hw-uuid-1234",
        },
    )
    assert enroll_ok.status_code == 201
    enroll_data = enroll_ok.json()
    device_id = enroll_data["deviceId"]
    device_token = enroll_data["deviceToken"]
    dev_headers = {"Authorization": f"Bearer {device_token}"}

    # Second use of maxUses=1 token -> 403 ENROLLMENT_TOKEN_EXHAUSTED
    exhausted = client.post(
        "/api/v1/agent/enroll",
        json={
            "enrollmentToken": plain_enroll_token,
            "hostname": "WIN-BUCH-02",
            "osFamily": "WINDOWS",
        },
    )
    assert exhausted.status_code == 403
    assert exhausted.json()["error"]["code"] == "ENROLLMENT_TOKEN_EXHAUSTED"

    # 4. Agent Check-in #1 -> receives 2 effectiveRules
    checkin_1 = client.post(
        "/api/v1/agent/checkin",
        headers=dev_headers,
        json={
            "hostname": "WIN-BUCH-01",
            "osFamily": "WINDOWS",
            "osVersion": "Windows 11 Pro 24H2",
            "agentVersion": "1.0.0",
            "currentUser": "m.mueller",
            "appliedRevision": 0,
        },
    )
    assert checkin_1.status_code == 200
    bundle_1 = checkin_1.json()
    rev_1 = bundle_1["bundleRevision"]
    assert rev_1 >= 1
    assert len(bundle_1["effectiveRules"]) == 2

    # 5. Agent Compliance #1 -> reports ENFORCED / APPLIED
    comp_1 = client.post(
        "/api/v1/agent/compliance",
        headers=dev_headers,
        json={
            "appliedRevision": rev_1,
            "status": "COMPLIANT",
            "items": [
                {
                    "ruleType": "security.usb_storage",
                    "action": "ENFORCED",
                    "status": "APPLIED",
                    "message": "USBSTOR Start set to 4",
                },
                {
                    "ruleType": "desktop.wallpaper",
                    "action": "ENFORCED",
                    "status": "APPLIED",
                    "message": "Wallpaper configured",
                },
            ],
        },
    )
    assert comp_1.status_code == 200
    assert comp_1.json()["acknowledged"] is True

    dev_detail = client.get(f"/api/v1/devices/{device_id}", headers=admin_headers).json()
    assert dev_detail["complianceStatus"] == "COMPLIANT"
    assert dev_detail["appliedRevision"] == rev_1
    assert dev_detail["deviceGroupIds"] == [grp["id"]]
    assert len(dev_detail["complianceItems"]) == 2

    # 6. Admin removes assignment -> Agent Check-in #2 receives 0 rules + incremented bundleRevision!
    del_asg = client.delete(f"/api/v1/assignments/{asg['id']}", headers=admin_headers)
    assert del_asg.status_code == 204

    checkin_2 = client.post(
        "/api/v1/agent/checkin",
        headers=dev_headers,
        json={
            "hostname": "WIN-BUCH-01",
            "osFamily": "WINDOWS",
            "osVersion": "Windows 11 Pro 24H2",
            "agentVersion": "1.0.0",
            "currentUser": "m.mueller",
            "appliedRevision": rev_1,
        },
    )
    assert checkin_2.status_code == 200
    bundle_2 = checkin_2.json()
    assert bundle_2["bundleRevision"] > rev_1
    assert bundle_2["stateHash"] != bundle_1["stateHash"]
    assert bundle_2["effectiveRules"] == []

    # 7. Agent Compliance #2 -> reports ROLLED_BACK
    comp_2 = client.post(
        "/api/v1/agent/compliance",
        headers=dev_headers,
        json={
            "appliedRevision": bundle_2["bundleRevision"],
            "status": "COMPLIANT",
            "items": [
                {
                    "ruleType": "security.usb_storage",
                    "action": "ROLLED_BACK",
                    "status": "APPLIED",
                    "message": "Restored USBSTOR Start",
                },
                {
                    "ruleType": "desktop.wallpaper",
                    "action": "ROLLED_BACK",
                    "status": "APPLIED",
                    "message": "Removed managed wallpaper policy",
                },
            ],
        },
    )
    assert comp_2.status_code == 200

    # 8. Admin deletes device -> revokes deviceToken immediately
    del_dev = client.delete(f"/api/v1/devices/{device_id}", headers=admin_headers)
    assert del_dev.status_code == 204

    revoked_checkin = client.post(
        "/api/v1/agent/checkin",
        headers=dev_headers,
        json={
            "hostname": "WIN-BUCH-01",
            "osFamily": "WINDOWS",
            "osVersion": "Windows 11 Pro 24H2",
            "agentVersion": "1.0.0",
            "currentUser": "m.mueller",
            "appliedRevision": bundle_2["bundleRevision"],
        },
    )
    assert revoked_checkin.status_code == 401
    assert revoked_checkin.json()["error"]["code"] == "UNAUTHORIZED"


def test_spa_static_serving_and_history_fallback(tmp_path: Path) -> None:
    web_dist = tmp_path / "web_dist"
    assets_dir = web_dist / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    (web_dist / "index.html").write_text("<!doctype html><title>NS8 Policy Web</title>", encoding="utf-8")
    (assets_dir / "main.js").write_text("console.log('apm');", encoding="utf-8")

    spa_settings = Settings.from_env(
        {
            "APM_DATA_DIR": str(tmp_path / "spa_data"),
            "APM_STATIC_DIR": str(web_dist),
            "LDAP_MODE": "mock",
            "APM_SEED_DEMO": "false",
        }
    )
    with TestClient(create_app(settings=spa_settings)) as c:
        # Root & deep SPA routes serve index.html
        root_res = c.get("/")
        assert root_res.status_code == 200
        assert "NS8 Policy Web" in root_res.text

        deep_res = c.get("/policies/builder")
        assert deep_res.status_code == 200
        assert "NS8 Policy Web" in deep_res.text

        # Static asset serves exact file
        asset_res = c.get("/assets/main.js")
        assert asset_res.status_code == 200
        assert "console.log('apm');" in asset_res.text

        # Unknown /api/* route returns structured JSON 404 NOT_FOUND (not index.html!)
        api_404 = c.get("/api/v1/does-not-exist")
        assert api_404.status_code == 404
        assert api_404.json()["error"]["code"] == "NOT_FOUND"
