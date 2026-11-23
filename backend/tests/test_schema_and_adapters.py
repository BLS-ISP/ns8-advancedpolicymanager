"""Tests for all 11 v1 ruleTypes + custom.raw_setting v2 hook and Delivery Adapters."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.adapters.delivery import (
    AgentBundleDeliveryAdapter,
    MobileMdmProfileAdapter,
    SambaSysvolExporterAdapter,
)
from app.engine.schema_registry import validate_policy_rule, validate_policy_rules
from app.errors import ApiError

ALL_12_VALID_RULES = [
    {
        "ruleId": "r-login",
        "category": "ACCESS",
        "ruleType": "access.login_access",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "OVERRIDE",
        "config": {
            "mode": "ALLOW_LIST",
            "allowedGroups": ["Buchhaltung", "IT-Admins"],
            "allowedUsers": [],
            "denyGroups": [],
        },
    },
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
                    "id": "share-buchhaltung",
                    "name": "Buchhaltung",
                    "protocol": "SMB",
                    "remotePath": "\\\\files.firma.local\\buchhaltung",
                    "windowsDriveLetter": "X:",
                    "unixMountPath": "/mnt/buchhaltung",
                    "reconnectAtLogon": True,
                }
            ]
        },
    },
    {
        "ruleId": "r-printers",
        "category": "WORKSPACE",
        "ruleType": "workspace.printers",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "APPEND_UNIQUE",
        "config": {
            "printers": [
                {
                    "id": "prn-og1",
                    "name": "Buerodrucker-OG1",
                    "uri": "ipp://print.firma.local/ipp/og1",
                    "isDefault": True,
                    "driverModel": "everywhere",
                }
            ]
        },
    },
    {
        "ruleId": "r-scripts",
        "category": "WORKSPACE",
        "ruleType": "workspace.scripts",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "APPEND_UNIQUE",
        "config": {
            "scripts": [
                {
                    "id": "scr-logon-env",
                    "name": "Arbeitsplatz-Initialisierung",
                    "trigger": "LOGON",
                    "runAs": "USER",
                    "timeoutSeconds": 60,
                    "windowsPowershell": "Write-Output 'Ready'",
                    "linuxBash": "echo 'Ready'",
                    "macosZsh": "echo 'Ready'",
                }
            ]
        },
    },
    {
        "ruleId": "r-screenlock",
        "category": "SECURITY",
        "ruleType": "security.screen_lock",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "OVERRIDE",
        "config": {
            "idleTimeoutSeconds": 300,
            "requirePasswordOnWake": True,
            "lockDelaySeconds": 5,
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
        "ruleId": "r-firewall",
        "category": "SECURITY",
        "ruleType": "security.firewall",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "OVERRIDE",
        "config": {
            "isEnabled": True,
            "defaultInbound": "BLOCK",
            "allowStealthMode": True,
            "allowedTcpPorts": [22, 3389],
            "allowedUdpPorts": [],
        },
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
    {
        "ruleId": "r-wallpaper",
        "category": "DESKTOP",
        "ruleType": "desktop.wallpaper",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "OVERRIDE",
        "config": {
            "imageUrl": "https://intranet.firma.local/wallpaper.jpg",
            "fitMode": "FILL",
            "isLocked": True,
        },
    },
    {
        "ruleId": "r-restrictions",
        "category": "DESKTOP",
        "ruleType": "desktop.system_restrictions",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "OVERRIDE",
        "config": {
            "disableControlPanel": True,
            "disableRegistryTools": True,
            "disableTerminalForStandardUsers": False,
        },
    },
    {
        "ruleId": "r-raw",
        "category": "CUSTOM_FINETUNING",
        "ruleType": "custom.raw_setting",
        "schemaVersion": 1,
        "platforms": ["WINDOWS", "LINUX", "MACOS"],
        "mergeStrategy": "APPEND_UNIQUE",
        "config": {
            "items": [
                {
                    "id": "raw-1",
                    "targetOs": "WINDOWS",
                    "engine": "REGISTRY",
                    "path": "HKLM\\SOFTWARE\\Policies\\Custom",
                    "key": "EnableFeature",
                    "valueType": "INT",
                    "value": "1",
                }
            ]
        },
    },
]


def test_all_12_rule_types_validate_cleanly() -> None:
    validated = validate_policy_rules(ALL_12_VALID_RULES)
    assert len(validated) == 12
    assert [r["ruleType"] for r in validated] == [r["ruleType"] for r in ALL_12_VALID_RULES]


@pytest.mark.parametrize(
    "bad_rule",
    [
        # Unknown ruleType
        {"ruleType": "security.non_existent", "category": "SECURITY", "config": {}},
        # Category mismatch
        {"ruleType": "security.usb_storage", "category": "DESKTOP", "config": {"mode": "BLOCK"}},
        # Extra forbidden field in config
        {
            "ruleType": "security.usb_storage",
            "category": "SECURITY",
            "config": {"mode": "BLOCK", "unknownKey": True},
        },
        # Invalid enum value
        {"ruleType": "security.usb_storage", "category": "SECURITY", "config": {"mode": "DESTROY"}},
        # Invalid TCP port out of range
        {
            "ruleType": "security.firewall",
            "category": "SECURITY",
            "config": {"allowedTcpPorts": [70000]},
        },
        # Duplicate mount IDs inside single rule
        {
            "ruleType": "workspace.network_shares",
            "category": "WORKSPACE",
            "config": {
                "mounts": [
                    {"id": "dup", "name": "A", "protocol": "SMB", "remotePath": "\\\\srv\\a"},
                    {"id": "dup", "name": "B", "protocol": "SMB", "remotePath": "\\\\srv\\b"},
                ]
            },
        },
    ],
)
def test_invalid_rule_configurations_rejected(bad_rule: dict) -> None:
    with pytest.raises(ApiError) as err:
        validate_policy_rule(bad_rule)
    assert err.value.status_code == 422
    assert err.value.code == "VALIDATION_ERROR"


def test_schema_catalog_endpoint_and_delivery_adapters(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    res = client.get("/api/v1/schema/catalog", headers=admin_headers)
    assert res.status_code == 200
    catalog = res.json()
    assert len(catalog["ruleTypes"]) == 12
    adapter_ids = [a["adapterId"] for a in catalog["deliveryAdapters"]]
    assert adapter_ids == ["AGENT_PULL", "SAMBA_SYSVOL", "MOBILE_MDM"]

    sample_rules = [validate_policy_rule(ALL_12_VALID_RULES[6])]
    agent_bundle = AgentBundleDeliveryAdapter().render_delivery_artifact(
        device_id="dev-1", bundle_revision=4, effective_rules=sample_rules, poll_interval_seconds=120
    )
    assert agent_bundle["stateHash"].startswith("sha256:")
    assert agent_bundle["bundleRevision"] == 4

    sysvol_preview = SambaSysvolExporterAdapter().render_delivery_artifact(
        device_id="dev-1", bundle_revision=4, effective_rules=sample_rules
    )
    assert sysvol_preview["adapterId"] == "SAMBA_SYSVOL"
    assert sysvol_preview["gpoRuleCount"] == 1

    mdm_preview = MobileMdmProfileAdapter().render_delivery_artifact(
        device_id="dev-1", bundle_revision=4, effective_rules=sample_rules
    )
    assert mdm_preview["adapterId"] == "MOBILE_MDM"
    assert mdm_preview["payloadVersion"] == 4
