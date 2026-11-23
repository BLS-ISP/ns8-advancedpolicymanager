"""Tests for Policies, Assignments, Reordering, SQLite WAL, Demo Seeding, and Idempotency-Key."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.errors import utc_now_iso
from app.main import create_app


def test_sqlite_wal_foreign_keys_and_demo_seeder(tmp_path: Path) -> None:
    seeded_settings = Settings.from_env(
        {
            "APM_DATA_DIR": str(tmp_path / "seeded_db"),
            "LDAP_MODE": "mock",
            "APM_SEED_DEMO": "true",
        }
    )
    app = create_app(settings=seeded_settings)
    with TestClient(app) as c:
        login = c.post(
            "/api/v1/auth/login",
            json={"username": "administrator", "password": "Admin123!"},
        )
        headers = {"Authorization": f"Bearer {login.json()['accessToken']}"}

        # Verify WAL mode & foreign_keys=ON on the underlying SQLite DB
        with app.state.db.connection() as conn:
            journal = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
            assert str(journal).lower() == "wal"
            assert int(fk) == 1

        # Verify seeded counts in dashboard summary
        summary = c.get("/api/v1/dashboard/summary", headers=headers)
        assert summary.status_code == 200
        s_data = summary.json()
        assert s_data["totalDevices"] == 4
        assert s_data["activePolicies"] == 3
        assert s_data["activeAssignments"] == 3
        assert s_data["deviceByOs"] == {"WINDOWS": 2, "LINUX": 1, "MACOS": 1}
        assert len(s_data["recentEvents"]) >= 4


def test_policies_revision_increment_and_assignments_reorder(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    # 1. Reject policy with invalid rule payload (never stored)
    bad_pol = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "Kaputte Richtlinie",
            "rules": [{"ruleType": "security.usb_storage", "config": {"mode": "INVALID"}}],
        },
    )
    assert bad_pol.status_code == 422
    assert bad_pol.json()["error"]["code"] == "VALIDATION_ERROR"

    # 2. Create Policy 1 & Policy 2
    p1 = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "Basis-Sicherheit",
            "description": "Standard USB Block",
            "isEnabled": True,
            "rules": [
                {
                    "ruleId": "rule-usb-block",
                    "category": "SECURITY",
                    "ruleType": "security.usb_storage",
                    "schemaVersion": 1,
                    "platforms": ["WINDOWS", "LINUX", "MACOS"],
                    "mergeStrategy": "OVERRIDE",
                    "config": {"mode": "BLOCK"},
                }
            ],
        },
    )
    assert p1.status_code == 201
    pol1 = p1.json()
    assert pol1["revision"] == 1

    # Metadata-only PATCH keeps revision == 1
    p1_meta = client.patch(
        f"/api/v1/policies/{pol1['id']}",
        headers=admin_headers,
        json={"description": "Aktualisierte Beschreibung"},
    )
    assert p1_meta.status_code == 200
    assert p1_meta.json()["revision"] == 1

    # Rule change PATCH increments revision -> 2
    p1_rules = client.patch(
        f"/api/v1/policies/{pol1['id']}",
        headers=admin_headers,
        json={
            "rules": [
                {
                    "ruleId": "rule-usb-block",
                    "category": "SECURITY",
                    "ruleType": "security.usb_storage",
                    "schemaVersion": 1,
                    "platforms": ["WINDOWS", "LINUX", "MACOS"],
                    "mergeStrategy": "OVERRIDE",
                    "config": {"mode": "READ_ONLY"},
                }
            ]
        },
    )
    assert p1_rules.status_code == 200
    assert p1_rules.json()["revision"] == 2

    p2 = client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={"name": "IT-Ausnahme", "description": "", "isEnabled": True, "rules": []},
    )
    assert p2.status_code == 201
    pol2 = p2.json()

    # 3. Device group + Assignments + atomic reorder
    grp = client.post(
        "/api/v1/device-groups",
        headers=admin_headers,
        json={"name": "Büro Buchhaltung", "description": "2. OG", "tags": ["office"]},
    )
    assert grp.status_code == 201
    grp_id = grp.json()["id"]

    # Duplicate group name returns 409 CONFLICT
    dup_grp = client.post(
        "/api/v1/device-groups",
        headers=admin_headers,
        json={"name": "Büro Buchhaltung", "description": "Dup"},
    )
    assert dup_grp.status_code == 409
    assert dup_grp.json()["error"]["code"] == "CONFLICT"

    a1 = client.post(
        "/api/v1/assignments",
        headers=admin_headers,
        json={
            "policyId": pol1["id"],
            "priority": 1,
            "isEnabled": True,
            "targetUserType": "GROUP",
            "targetUserRef": "Buchhaltung",
            "targetDeviceType": "DEVICE_GROUP",
            "targetDeviceRef": grp_id,
            "osFilter": ["WINDOWS", "LINUX"],
        },
    )
    assert a1.status_code == 201
    asg1 = a1.json()
    assert asg1["policyName"] == "Basis-Sicherheit"
    assert asg1["targetDeviceGroupName"] == "Büro Buchhaltung"

    a2 = client.post(
        "/api/v1/assignments",
        headers=admin_headers,
        json={
            "policyId": pol2["id"],
            "priority": 2,
            "isEnabled": True,
            "targetUserType": "ALL",
            "targetDeviceType": "ALL",
            "osFilter": ["WINDOWS", "LINUX", "MACOS"],
        },
    )
    assert a2.status_code == 201
    asg2 = a2.json()

    # Reorder [asg2, asg1] -> priorities become 1, 2
    reordered = client.post(
        "/api/v1/assignments/reorder",
        headers=admin_headers,
        json={"orderedAssignmentIds": [asg2["id"], asg1["id"]]},
    )
    assert reordered.status_code == 200
    items = reordered.json()["data"]
    assert [x["id"] for x in items] == [asg2["id"], asg1["id"]]
    assert [x["priority"] for x in items] == [1, 2]


def test_idempotency_key_replay_mismatch_and_in_progress_conflict(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    payload = {
        "name": "Idempotente Richtlinie",
        "description": "Test",
        "isEnabled": True,
        "rules": [],
    }
    headers = {**admin_headers, "Idempotency-Key": "idem-key-001"}

    # 1. Initial call creates resource
    first = client.post("/api/v1/policies", headers=headers, json=payload)
    assert first.status_code == 201
    created_id = first.json()["id"]

    # 2. Replay with identical key + identical body returns exact same resource without duplicating
    second = client.post("/api/v1/policies", headers=headers, json=payload)
    assert second.status_code == 201
    assert second.json()["id"] == created_id

    listed = client.get("/api/v1/policies", headers=admin_headers).json()
    assert listed["pagination"]["totalItems"] == 1

    # 3. Same key + different body -> 422 IDEMPOTENCY_KEY_REUSED
    mismatch = client.post(
        "/api/v1/policies",
        headers=headers,
        json={**payload, "name": "Abweichender Name"},
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"

    # 4. Same key on a DIFFERENT endpoint (`POST:/api/v1/enrollment-tokens`) is scoped per endpoint
    tok_res = client.post(
        "/api/v1/enrollment-tokens",
        headers=headers,
        json={"name": "Rollout Token", "expiresInHours": 24, "maxUses": 5},
    )
    assert tok_res.status_code == 201
    tok_replay = client.post(
        "/api/v1/enrollment-tokens",
        headers=headers,
        json={"name": "Rollout Token", "expiresInHours": 24, "maxUses": 5},
    )
    assert tok_replay.status_code == 201
    assert tok_replay.json()["id"] == tok_res.json()["id"]
    assert tok_replay.json()["plainToken"] == tok_res.json()["plainToken"]

    # 5. Concurrent IN_PROGRESS record returns 409 IDEMPOTENCY_IN_PROGRESS
    from app.db.idempotency import compute_request_hash

    inflight_payload = {"name": "InFlight", "description": "", "isEnabled": True, "rules": []}
    inflight_hash = compute_request_hash(inflight_payload)
    with client.app.state.db.transaction(immediate=True) as conn:
        conn.execute(
            """
            INSERT INTO idempotency_records
                (idempotency_key, endpoint, request_hash, state, status_code, response_json, created_at)
            VALUES (?, 'POST:/api/v1/policies', ?, 'IN_PROGRESS', NULL, NULL, ?)
            """,
            ("idem-inflight", inflight_hash, utc_now_iso()),
        )

    conflict = client.post(
        "/api/v1/policies",
        headers={**admin_headers, "Idempotency-Key": "idem-inflight"},
        json=inflight_payload,
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_IN_PROGRESS"
