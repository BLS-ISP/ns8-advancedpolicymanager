"""Shared pytest fixtures with isolated temporary SQLite databases (`APM_SEED_DEMO=false`)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def test_settings(tmp_path: Path) -> Settings:
    data_dir = tmp_path / "data"
    static_dir = tmp_path / "web_dist"
    artifacts_dir = tmp_path / "agent_artifacts"
    return Settings.from_env(
        {
            "APM_DATA_DIR": str(data_dir),
            "APM_STATIC_DIR": str(static_dir),
            "APM_AGENT_ARTIFACTS_DIR": str(artifacts_dir),
            "APM_PUBLIC_URL": "https://policies.firma.local",
            "JWT_SECRET": "test-jwt-secret-0123456789abcdef0123456789abcdef0123456789abcdef",
            "LDAP_MODE": "mock",
            "LDAP_DOMAIN": "firma.local",
            "LDAP_SCHEMA": "ad",
            "LDAP_BASE_DN": "dc=firma,dc=local",
            "ADMIN_GROUPS": "Domain Admins,admins,IT-Admins",
            "BOOTSTRAP_ADMIN_ENABLED": "true",
            "BOOTSTRAP_ADMIN_USERNAME": "admin",
            "BOOTSTRAP_ADMIN_PASSWORD": "Admin123!",
            "APM_SEED_DEMO": "false",
        }
    )


@pytest.fixture()
def client(test_settings: Settings) -> TestClient:
    app = create_app(settings=test_settings)
    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def admin_headers(client: TestClient) -> dict[str, str]:
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": "Admin123!"},
    )
    assert res.status_code == 200, res.text
    token = res.json()["accessToken"]
    return {"Authorization": f"Bearer {token}"}
