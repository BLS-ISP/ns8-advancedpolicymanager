"""Comprehensive unit and HTTP tests for `directory-auth` (AD, OpenLDAP, Mock, RBAC, Tokens)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from app.auth.tokens import create_access_token, verify_access_token
from app.config import Settings, hash_password_pbkdf2, verify_password_pbkdf2
from app.directory.base import DirectoryUnavailableError
from app.directory.ldap_provider import AD_MATCHING_RULE_IN_CHAIN, Ldap3DirectoryProvider
from app.directory.mock_provider import InMemoryDirectoryProvider
from app.errors import ApiError
from app.main import create_app


# --- Configuration & PBKDF2 Tests ---
def test_settings_env_autodetect_and_pbkdf2_formats() -> None:
    # Unset LDAP_HOST defaults to mock mode + demo seed true
    s_local = Settings.from_env({})
    assert s_local.ldap_mode == "mock"
    assert s_local.apm_seed_demo is True
    assert s_local.bootstrap_admin_enabled is True
    assert verify_password_pbkdf2("Admin123!", s_local.bootstrap_admin_password_hash)

    # Setting LDAP_HOST switches default LDAP_MODE to ldapproxy and seed_demo to False
    s_ns8 = Settings.from_env({"LDAP_HOST": "10.0.2.2", "LDAP_PORT": "40123", "LDAP_SCHEMA": "rfc2307"})
    assert s_ns8.ldap_mode == "ldapproxy"
    assert s_ns8.ldap_schema == "rfc2307"
    assert s_ns8.ldap_port == 40123
    assert s_ns8.apm_seed_demo is False

    # Dollar-delimited PBKDF2 hash
    dollar_hash = hash_password_pbkdf2("S3cretPass!", iterations=12000, salt="salt1234")
    assert verify_password_pbkdf2("S3cretPass!", dollar_hash) is True
    assert verify_password_pbkdf2("WrongPass", dollar_hash) is False

    # Colon-delimited PBKDF2 hash with hex-decoded salt (compatibility with shell/python scripts)
    hex_salt = "aabbccddeeff00112233445566778899"
    dk = hashlib.pbkdf2_hmac("sha256", b"EmergencyPw!", bytes.fromhex(hex_salt), 20000)
    colon_hash = f"pbkdf2:sha256:20000:{hex_salt}:{dk.hex()}"
    assert verify_password_pbkdf2("EmergencyPw!", colon_hash) is True
    assert verify_password_pbkdf2("BadPw", colon_hash) is False


# --- InMemoryDirectoryProvider Tests ---
def test_in_memory_directory_provider_users_groups_and_no_plaintext() -> None:
    provider = InMemoryDirectoryProvider(domain="firma.local", base_dn="dc=firma,dc=local")

    # Ensure no plaintext password is stored anywhere on account seeds
    for acc in provider._accounts:
        assert "Admin123!" not in repr(acc)
        assert acc.password_hash.startswith("pbkdf2:sha256:")

    # Valid logins including DOMAIN\user and UPN
    admin = provider.authenticate("administrator", "Admin123!")
    assert admin is not None
    assert admin.username == "administrator"
    assert "Domain Admins" in admin.groups
    assert "IT-Admins" in admin.groups

    assert provider.authenticate("FIRMA\\administrator", "Admin123!") is not None
    assert provider.authenticate("administrator@firma.local", "Admin123!") is not None

    # Rejects empty password, wrong password, unknown user
    assert provider.authenticate("administrator", "") is None
    assert provider.authenticate("administrator", "wrong") is None
    assert provider.authenticate("nobody", "Admin123!") is None

    # Search & pagination
    users, total_u = provider.search_users(search="mueller", page=1, page_size=10)
    assert total_u == 1
    assert users[0].username == "m.mueller"
    assert "Buchhaltung" in users[0].groups

    page1, total_all = provider.search_users(search="", page=1, page_size=2)
    assert total_all == 5
    assert len(page1) == 2

    groups, total_g = provider.search_groups(search="buch", page=1, page_size=10)
    assert total_g == 1
    assert groups[0].name == "Buchhaltung"
    assert groups[0].member_count >= 1


# --- Fake ldap3 Harness for Ldap3DirectoryProvider Unit Tests ---
class FakeLdapConnection:
    def __init__(
        self,
        server: Any,
        user: str | None = None,
        password: str | None = None,
        auto_bind: bool = False,
        *,
        search_responder: Any = None,
        valid_user_passwords: dict[str, str] | None = None,
        fail_socket: bool = False,
    ) -> None:
        if fail_socket:
            raise LDAPSocketOpenError("connection refused")
        self.server = server
        self.user = user
        self.password = password
        self.auto_bind = auto_bind
        self.entries: list[dict[str, Any]] = []
        self.recorded_searches: list[tuple[str, str]] = []
        self._search_responder = search_responder
        self._valid_passwords = valid_user_passwords or {}
        self.unbound = False

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: Any = None,
        attributes: Any = None,
    ) -> bool:
        self.recorded_searches.append((search_base, search_filter))
        if self._search_responder:
            self.entries = self._search_responder(search_base, search_filter, attributes)
        else:
            self.entries = []
        return True

    def bind(self) -> bool:
        expected = self._valid_passwords.get(self.user or "")
        if expected is None or expected != self.password:
            raise LDAPBindError("invalidCredentials")
        return True

    def unbind(self) -> None:
        self.unbound = True


def test_ldap3_provider_samba_ad_nested_groups_and_filter_escaping() -> None:
    created_conns: list[FakeLdapConnection] = []
    user_dn = "CN=Sabine Weber,CN=Users,DC=ad,DC=firma,DC=local"

    def ad_responder(_base: str, flt: str, _attrs: Any) -> list[dict[str, Any]]:
        if "(!(objectClass=computer))" in flt and ("s.weber" in flt or "objectClass=user" in flt):
            if "nobody" in flt or "\\2a" in flt:
                return []
            return [
                {
                    "dn": user_dn,
                    "attributes": {
                        "sAMAccountName": "s.weber",
                        "userPrincipalName": "s.weber@ad.firma.local",
                        "displayName": "Sabine Weber",
                        "mail": "s.weber@firma.local",
                        "memberOf": ["CN=Helpdesk,CN=Users,DC=ad,DC=firma,DC=local"],
                    },
                }
            ]
        if AD_MATCHING_RULE_IN_CHAIN in flt:
            # Simulates nested group membership: Helpdesk -> IT-Admins -> Domain Admins
            return [
                {"dn": "CN=Helpdesk,CN=Users,DC=ad,DC=firma,DC=local", "attributes": {"cn": "Helpdesk"}},
                {"dn": "CN=IT-Admins,CN=Users,DC=ad,DC=firma,DC=local", "attributes": {"cn": "IT-Admins"}},
                {"dn": "CN=Domain Admins,CN=Users,DC=ad,DC=firma,DC=local", "attributes": {"cn": "Domain Admins"}},
            ]
        if "(objectClass=group)" in flt:
            return [
                {
                    "dn": "CN=Domain Admins,CN=Users,DC=ad,DC=firma,DC=local",
                    "attributes": {
                        "cn": "Domain Admins",
                        "description": "Administratoren der Domäne",
                        "member": [user_dn, "CN=Administrator,CN=Users,DC=ad,DC=firma,DC=local"],
                    },
                }
            ]
        return []

    def conn_factory(server: Any, **kwargs: Any) -> FakeLdapConnection:
        c = FakeLdapConnection(
            server,
            **kwargs,
            search_responder=ad_responder,
            valid_user_passwords={user_dn: "CorrectADPassword!"},
        )
        created_conns.append(c)
        return c

    provider = Ldap3DirectoryProvider(
        host="10.0.2.2",
        port=40123,
        schema="ad",
        base_dn="DC=ad,DC=firma,DC=local",
        bind_dn="CN=ldapservice,CN=Users,DC=ad,DC=firma,DC=local",
        bind_password="svc-secret",
        server_factory=lambda host, **kw: {"host": host, **kw},
        connection_factory=conn_factory,
    )

    # 1. Successful authentication resolves nested AD groups via 1.2.840.113556.1.4.1941
    authed = provider.authenticate("s.weber", "CorrectADPassword!")
    assert authed is not None
    assert authed.username == "s.weber"
    assert authed.groups == ["Helpdesk", "IT-Admins", "Domain Admins"]

    # 2. Wrong password & empty password return None
    assert provider.authenticate("s.weber", "WrongPassword") is None
    assert provider.authenticate("s.weber", "") is None

    # 3. Filter injection characters are strictly escaped via escape_filter_chars
    injection_input = "admin*)(|(sAMAccountName=*"
    assert provider.get_user(injection_input) is None
    last_filter = created_conns[-1].recorded_searches[0][1]
    assert "\\2a\\29\\28|\\28sAMAccountName=\\2a" in last_filter

    # 4. Group search returns memberCount
    groups, total = provider.search_groups(search="Domain")
    assert total == 1
    assert groups[0].name == "Domain Admins"
    assert groups[0].member_count == 2


def test_ldap3_provider_openldap_rfc2307_posix_and_group_of_names() -> None:
    user_dn = "uid=m.mueller,ou=People,dc=firma,dc=local"

    def rfc2307_responder(_base: str, flt: str, _attrs: Any) -> list[dict[str, Any]]:
        if "inetOrgPerson" in flt:
            return [
                {
                    "dn": user_dn,
                    "attributes": {
                        "uid": ["m.mueller"],
                        "cn": ["Max Müller"],
                        "displayName": ["Max Müller"],
                        "mail": ["m.mueller@firma.local"],
                    },
                }
            ]
        if "posixGroup" in flt or "groupOfNames" in flt:
            return [
                {
                    "dn": "cn=Buchhaltung,ou=Groups,dc=firma,dc=local",
                    "attributes": {
                        "cn": ["Buchhaltung"],
                        "description": ["Finanzbuchhaltung"],
                        "memberUid": ["m.mueller", "k.schulz"],
                    },
                },
                {
                    "dn": "cn=admins,ou=Groups,dc=firma,dc=local",
                    "attributes": {
                        "cn": ["admins"],
                        "description": ["OpenLDAP Admins"],
                        "member": [user_dn],
                    },
                },
            ]
        return []

    provider = Ldap3DirectoryProvider(
        host="10.0.2.2",
        port=40124,
        schema="rfc2307",
        base_dn="dc=firma,dc=local",
        server_factory=lambda host, **kw: {"host": host, **kw},
        connection_factory=lambda server, **kw: FakeLdapConnection(
            server,
            **kw,
            search_responder=rfc2307_responder,
            valid_user_passwords={user_dn: "OpenLdapPass!"},
        ),
    )

    user = provider.authenticate("m.mueller", "OpenLdapPass!")
    assert user is not None
    assert user.username == "m.mueller"
    # Resolves BOTH posixGroup (memberUid) and groupOfNames (member)
    assert set(user.groups) == {"Buchhaltung", "admins"}

    users, total_u = provider.search_users(search="mueller")
    assert total_u == 1
    assert set(users[0].groups) == {"Buchhaltung", "admins"}

    groups, total_g = provider.search_groups()
    assert total_g == 2
    by_name = {g.name: g for g in groups}
    assert by_name["Buchhaltung"].member_count == 2
    assert by_name["admins"].member_count == 1


def test_auth_rbac_bootstrap_logout_and_directory_endpoints(
    client: TestClient,
    test_settings: Settings,
    tmp_path: Path,
) -> None:
    # 1. Authorized AD admin login -> 200
    res_ok = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": "Admin123!"},
    )
    assert res_ok.status_code == 200
    body_ok = res_ok.json()
    assert body_ok["expiresIn"] == 28800
    assert body_ok["user"]["username"] == "administrator"
    assert body_ok["user"]["authSource"] == "LDAP"
    token = body_ok["accessToken"]

    # 2. /auth/me returns profile + ldapDomain
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["ldapDomain"] == "firma.local"
    assert me.json()["authSource"] == "LDAP"

    # 3. Valid AD user NOT in ADMIN_GROUPS -> 403 FORBIDDEN
    res_forbidden = client.post(
        "/api/v1/auth/login",
        json={"username": "m.mueller", "password": "Mueller123!"},
    )
    assert res_forbidden.status_code == 403
    assert res_forbidden.json()["error"]["code"] == "FORBIDDEN"

    # 4. Wrong password -> 401 INVALID_CREDENTIALS
    res_bad = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": "WrongPassword!"},
    )
    assert res_bad.status_code == 401
    assert res_bad.json()["error"]["code"] == "INVALID_CREDENTIALS"

    # 5. Directory users & groups endpoints require auth and support search + pagination
    unauth = client.get("/api/v1/directory/users")
    assert unauth.status_code == 401
    assert unauth.json()["error"]["code"] == "UNAUTHORIZED"

    dir_users = client.get(
        "/api/v1/directory/users?search=weber&page=1&pageSize=10",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert dir_users.status_code == 200
    assert dir_users.json()["pagination"]["totalItems"] == 1
    assert dir_users.json()["data"][0]["username"] == "s.weber"

    dir_groups = client.get(
        "/api/v1/directory/groups?page=1&pageSize=3",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert dir_groups.status_code == 200
    assert len(dir_groups.json()["data"]) == 3
    assert dir_groups.json()["pagination"]["totalPages"] == 2

    # 6. Logout revokes token immediately -> 204 then 401
    out = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert out.status_code == 204
    me_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_after.status_code == 401

    # 7. Bootstrap Emergency Admin still works even when LDAP directory is unreachable!
    down_provider = Ldap3DirectoryProvider(
        host="10.0.2.2",
        port=40123,
        schema="ad",
        base_dn="dc=firma,dc=local",
        server_factory=lambda host, **kw: {"host": host},
        connection_factory=lambda server, **kw: FakeLdapConnection(server, fail_socket=True),
    )
    offline_settings = Settings.from_env(
        {
            "APM_DATA_DIR": str(tmp_path / "offline_data"),
            "LDAP_MODE": "ldapproxy",
            "LDAP_HOST": "10.0.2.2",
            "BOOTSTRAP_ADMIN_ENABLED": "true",
            "BOOTSTRAP_ADMIN_USERNAME": "admin",
            "BOOTSTRAP_ADMIN_PASSWORD": "EmergencyAdmin99!",
            "APM_SEED_DEMO": "false",
        }
    )
    with TestClient(create_app(settings=offline_settings, directory_provider=down_provider)) as c2:
        # LDAP user login returns 503 DIRECTORY_UNAVAILABLE
        ldap_fail = c2.post(
            "/api/v1/auth/login",
            json={"username": "administrator", "password": "Admin123!"},
        )
        assert ldap_fail.status_code == 503
        assert ldap_fail.json()["error"]["code"] == "DIRECTORY_UNAVAILABLE"

        # Bootstrap Admin login succeeds (200)
        boot_ok = c2.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "EmergencyAdmin99!"},
        )
        assert boot_ok.status_code == 200
        assert boot_ok.json()["user"]["authSource"] == "BOOTSTRAP"


def test_token_expiration_and_tamper_detection() -> None:
    token, _ = create_access_token(
        username="administrator",
        display_name="Domain Admin",
        groups=["Domain Admins"],
        auth_source="LDAP",
        secret="secret-key-123",
        expires_in=60,
        now=1_700_000_000,
    )
    claims = verify_access_token(token, secret="secret-key-123", now=1_700_000_030)
    assert claims.username == "administrator"

    with pytest.raises(ApiError) as exp_err:
        verify_access_token(token, secret="secret-key-123", now=1_700_000_061)
    assert exp_err.value.code == "TOKEN_EXPIRED"

    with pytest.raises(ApiError) as sig_err:
        verify_access_token(token, secret="wrong-secret", now=1_700_000_030)
    assert sig_err.value.code == "UNAUTHORIZED"
