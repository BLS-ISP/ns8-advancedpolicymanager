"""Realistic enterprise demo seeder for mock mode when the database is empty."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone


def _iso_offset(minutes_delta: int = 0) -> str:
    dt = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=minutes_delta)
    return dt.isoformat().replace("+00:00", "Z")


def seed_demo_data_if_empty(conn: sqlite3.Connection) -> None:
    """Seed 3 device groups, 3 policies (all 4 categories), 3 assignments, and 4 devices if empty."""
    existing_count = conn.execute("SELECT COUNT(*) AS cnt FROM policies").fetchone()["cnt"]
    if existing_count > 0:
        return

    existing_groups = conn.execute("SELECT COUNT(*) AS cnt FROM device_groups").fetchone()["cnt"]
    if existing_groups > 0:
        return

    now = _iso_offset(0)
    earlier = _iso_offset(-120)

    # 1. Three Device Groups
    device_groups = [
        (
            "grp-office",
            "Büro Buchhaltung",
            "Arbeitsplätze Finanzbuchhaltung & Controlling (2. OG)",
            json.dumps(["office", "finance"]),
            earlier,
            now,
        ),
        (
            "grp-training",
            "Schulungsraum",
            "Gemeinsam genutzte Schulungs- und Prüfungsrechner (EG)",
            json.dumps(["training", "shared"]),
            earlier,
            now,
        ),
        (
            "grp-field",
            "Außendienst & Mobil",
            "Mobile Notebooks für Vertrieb und Projektleitung",
            json.dumps(["laptop", "remote"]),
            earlier,
            now,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO device_groups (id, name, description, tags_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        device_groups,
    )

    # 2. Three Policies covering ACCESS, WORKSPACE, SECURITY, DESKTOP
    pol_base_rules = [
        {
            "ruleId": "rule-base-screenlock",
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
            "ruleId": "rule-base-usb",
            "category": "SECURITY",
            "ruleType": "security.usb_storage",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "OVERRIDE",
            "config": {
                "mode": "BLOCK",
            },
        },
        {
            "ruleId": "rule-base-firewall",
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
            "ruleId": "rule-base-browser",
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
            "ruleId": "rule-base-wallpaper",
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
    ]

    pol_finance_rules = [
        {
            "ruleId": "rule-fin-login",
            "category": "ACCESS",
            "ruleType": "access.login_access",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "OVERRIDE",
            "config": {
                "mode": "ALLOW_LIST",
                "allowedGroups": ["Buchhaltung", "IT-Admins", "Domain Admins"],
                "allowedUsers": [],
                "denyGroups": ["Schulung"],
            },
        },
        {
            "ruleId": "rule-fin-shares",
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
                ],
            },
        },
        {
            "ruleId": "rule-fin-printers",
            "category": "WORKSPACE",
            "ruleType": "workspace.printers",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "APPEND_UNIQUE",
            "config": {
                "printers": [
                    {
                        "id": "prn-og2",
                        "name": "Buerodrucker-OG2",
                        "uri": "ipp://print.firma.local/ipp/og2",
                        "isDefault": True,
                        "driverModel": "everywhere",
                    }
                ],
            },
        },
        {
            "ruleId": "rule-fin-restrictions",
            "category": "DESKTOP",
            "ruleType": "desktop.system_restrictions",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "OVERRIDE",
            "config": {
                "disableControlPanel": True,
                "disableRegistryTools": True,
                "disableTerminalForStandardUsers": True,
            },
        },
    ]

    pol_it_rules = [
        {
            "ruleId": "rule-it-admins",
            "category": "ACCESS",
            "ruleType": "access.local_admins",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "APPEND_UNIQUE",
            "config": {
                "adminGroups": ["IT-Admins", "Domain Admins"],
                "adminUsers": [],
                "passwordlessSudo": False,
            },
        },
        {
            "ruleId": "rule-it-usb-readonly",
            "category": "SECURITY",
            "ruleType": "security.usb_storage",
            "schemaVersion": 1,
            "platforms": ["WINDOWS", "LINUX", "MACOS"],
            "mergeStrategy": "OVERRIDE",
            "config": {
                "mode": "READ_ONLY",
            },
        },
        {
            "ruleId": "rule-it-logon-script",
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
                        "windowsPowershell": "Write-Output 'NS8 Policy Ready'",
                        "linuxBash": "echo 'NS8 Policy Ready'",
                        "macosZsh": "echo 'NS8 Policy Ready'",
                    }
                ],
            },
        },
    ]

    policies = [
        (
            "pol-it-exceptions",
            "IT-Administration & Ausnahmen",
            "Lokale Admin-Rechte und Lesezugriff für USB-Medien des IT-Teams",
            1,
            1,
            json.dumps(pol_it_rules, ensure_ascii=False),
            earlier,
            now,
        ),
        (
            "pol-finance-workspace",
            "Arbeitsumgebung Buchhaltung",
            "Netzlaufwerke, Abteilungsdrucker und Anmeldebeschränkungen für die Buchhaltung",
            1,
            3,
            json.dumps(pol_finance_rules, ensure_ascii=False),
            earlier,
            now,
        ),
        (
            "pol-base-security",
            "Basis-Sicherheit Alle Geräte",
            "Unternehmensweite Bildschirmsperre, USB-Sperre, Firewall und Browser-Standards",
            1,
            2,
            json.dumps(pol_base_rules, ensure_ascii=False),
            earlier,
            now,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO policies (id, name, description, is_enabled, revision, rules_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        policies,
    )

    # 3. Three Priority Assignments (1 = highest priority)
    all_os = json.dumps(["WINDOWS", "LINUX", "MACOS"])
    assignments = [
        (
            "asg-it-override",
            "pol-it-exceptions",
            1,
            1,
            "GROUP",
            "IT-Admins",
            "ALL",
            None,
            all_os,
            earlier,
            now,
        ),
        (
            "asg-finance-office",
            "pol-finance-workspace",
            2,
            1,
            "GROUP",
            "Buchhaltung",
            "DEVICE_GROUP",
            "grp-office",
            all_os,
            earlier,
            now,
        ),
        (
            "asg-global-base",
            "pol-base-security",
            3,
            1,
            "ALL",
            None,
            "ALL",
            None,
            all_os,
            earlier,
            now,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO assignments (
            id, policy_id, priority, is_enabled,
            target_user_type, target_user_ref, target_device_type, target_device_ref,
            os_filter_json, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        assignments,
    )

    # 4. Four realistic Windows / Linux / macOS Devices
    devices = [
        (
            "dev-win-buch-01",
            "WIN-BUCH-01",
            "WINDOWS",
            "Windows 11 Pro 24H2",
            "x86_64",
            "1.0.0",
            "hw-win-buch-001",
            "m.mueller",
            hashlib.sha256(b"apm_dev_demo_win_buch_01").hexdigest(),
            3,
            "COMPLIANT",
            json.dumps(
                [
                    {
                        "ruleType": "access.login_access",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Anmeldegruppen Buchhaltung & IT-Admins aktiv",
                    },
                    {
                        "ruleType": "workspace.network_shares",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Netzlaufwerk X: (\\\\files.firma.local\\buchhaltung) verbunden",
                    },
                    {
                        "ruleType": "security.usb_storage",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "USB-Massenspeicher blockiert (USBSTOR=4)",
                    },
                    {
                        "ruleType": "security.firewall",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Windows Defender Firewall aktiv",
                    },
                ],
                ensure_ascii=False,
            ),
            _iso_offset(-2),
            earlier,
        ),
        (
            "dev-lnx-admin-01",
            "LNX-ADMIN-01",
            "LINUX",
            "Ubuntu 24.04.1 LTS",
            "x86_64",
            "1.0.0",
            "hw-lnx-admin-001",
            "s.weber",
            hashlib.sha256(b"apm_dev_demo_lnx_admin_01").hexdigest(),
            3,
            "COMPLIANT",
            json.dumps(
                [
                    {
                        "ruleType": "access.local_admins",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Sudoers-Regel für IT-Admins aktiv",
                    },
                    {
                        "ruleType": "security.usb_storage",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "USB-Speicher auf READ_ONLY gesetzt (udev)",
                    },
                    {
                        "ruleType": "security.firewall",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "ufw/nftables Eingangsregeln angewendet",
                    },
                ],
                ensure_ascii=False,
            ),
            _iso_offset(-4),
            earlier,
        ),
        (
            "dev-mac-sales-01",
            "MAC-VERTRIEB-01",
            "MACOS",
            "macOS Sequoia 15.2",
            "aarch64",
            "1.0.0",
            "hw-mac-sales-001",
            "l.schmidt",
            hashlib.sha256(b"apm_dev_demo_mac_sales_01").hexdigest(),
            2,
            "DEGRADED",
            json.dumps(
                [
                    {
                        "ruleType": "security.screen_lock",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Bildschirmsperre nach 300s aktiv",
                    },
                    {
                        "ruleType": "desktop.wallpaper",
                        "action": "ENFORCED",
                        "status": "SKIPPED_UNSUPPORTED",
                        "message": "Hintergrundbild wartet auf Benutzeranmeldung",
                    },
                ],
                ensure_ascii=False,
            ),
            _iso_offset(-9),
            earlier,
        ),
        (
            "dev-win-train-01",
            "WIN-SCHULUNG-01",
            "WINDOWS",
            "Windows 11 Education 23H2",
            "x86_64",
            "1.0.0",
            "hw-win-train-001",
            "t.fischer",
            hashlib.sha256(b"apm_dev_demo_win_train_01").hexdigest(),
            3,
            "COMPLIANT",
            json.dumps(
                [
                    {
                        "ruleType": "security.usb_storage",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "USB-Massenspeicher blockiert",
                    },
                    {
                        "ruleType": "desktop.browser",
                        "action": "ENFORCED",
                        "status": "APPLIED",
                        "message": "Browser-Startseite & Inkognito-Sperre gesetzt",
                    },
                ],
                ensure_ascii=False,
            ),
            _iso_offset(-5),
            earlier,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO devices (
            id, hostname, os_family, os_version, arch, agent_version, machine_id,
            current_user, device_token_hash, applied_revision, compliance_status,
            compliance_items_json, last_seen_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        devices,
    )

    memberships = [
        ("dev-win-buch-01", "grp-office"),
        ("dev-lnx-admin-01", "grp-office"),
        ("dev-mac-sales-01", "grp-field"),
        ("dev-win-train-01", "grp-training"),
    ]
    conn.executemany(
        "INSERT INTO device_group_memberships (device_id, device_group_id) VALUES (?, ?)",
        memberships,
    )

    events = [
        (
            "evt-demo-1",
            _iso_offset(-2),
            "dev-win-buch-01",
            "WIN-BUCH-01",
            "COMPLIANT",
            "9 Regeln aktiv (Revision 3)",
        ),
        (
            "evt-demo-2",
            _iso_offset(-4),
            "dev-lnx-admin-01",
            "LNX-ADMIN-01",
            "COMPLIANT",
            "7 Regeln aktiv inkl. IT-Override (Revision 3)",
        ),
        (
            "evt-demo-3",
            _iso_offset(-5),
            "dev-win-train-01",
            "WIN-SCHULUNG-01",
            "COMPLIANT",
            "5 Basis-Regeln aktiv (Revision 3)",
        ),
        (
            "evt-demo-4",
            _iso_offset(-9),
            "dev-mac-sales-01",
            "MAC-VERTRIEB-01",
            "DEGRADED",
            "1 Hinweis bei desktop.wallpaper (Revision 2)",
        ),
    ]
    conn.executemany(
        """
        INSERT INTO compliance_events (id, timestamp, device_id, device_hostname, status, message)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        events,
    )

    conn.execute(
        """
        INSERT INTO enrollment_tokens (
            id, name, token_hash, token_prefix, default_device_group_id,
            expires_at, max_uses, use_count, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "tok-demo-office",
            "Standard-Rollout Büro Buchhaltung",
            hashlib.sha256(b"apm_enroll_demo_office_token_secret").hexdigest(),
            "apm_enroll_demo",
            "grp-office",
            _iso_offset(60 * 24 * 7),
            50,
            2,
            earlier,
        ),
    )

    conn.execute("UPDATE system_state SET int_value = 3 WHERE key = 'cluster_revision'")
    conn.commit()
