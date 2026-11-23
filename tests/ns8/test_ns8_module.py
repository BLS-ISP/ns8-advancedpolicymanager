"""Comprehensive NethServer 8 packaging, action, and Cockpit UI compliance tests."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import runpy
import subprocess
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGEROOT = REPO_ROOT / "imageroot"
UI_DIR = REPO_ROOT / "ui"


class MockNs8Env:
    """In-memory mock for NethServer 8 `agent` and `agent.ldapproxy` Python packages."""

    def __init__(
        self,
        *,
        initial_env: dict[str, str] | None = None,
        route_in_use: bool = False,
        traefik_id: str | None = "traefik1",
        domains_list: list[str] | None = None,
        domains_detail: dict[str, dict[str, Any]] | None = None,
        task_exit_code: int = 0,
    ) -> None:
        self.env: dict[str, str] = dict(initial_env or {})
        self.flushed_env: dict[str, str] = {}
        self.call_log: list[str] = []
        self.status_history: list[str] = []
        self.bound_domains_history: list[list[str]] = []
        self.tasks_calls: list[dict[str, Any]] = []
        self.route_in_use = route_in_use
        self.traefik_id = traefik_id
        self.domains_list = list(domains_list if domains_list is not None else ["ad.example.org"])
        self.domains_detail = dict(
            domains_detail
            or {
                "ad.example.org": {
                    "name": "ad.example.org",
                    "host": "127.0.0.1",
                    "port": 40123,
                    "schema": "ad",
                    "tls": False,
                    "base_dn": "dc=ad,dc=example,dc=org",
                    "bind_dn": "cn=ldapservice,cn=Users,dc=ad,dc=example,dc=org",
                    "bind_password": "secret-bind-password",
                },
                "ldap.example.org": {
                    "name": "ldap.example.org",
                    "host": "127.0.0.1",
                    "port": 40124,
                    "schema": "rfc2307",
                    "tls": True,
                    "base_dn": "dc=ldap,dc=example,dc=org",
                    "bind_dn": "",
                    "bind_password": "",
                },
            }
        )
        self.task_exit_code = task_exit_code
        self.ldapproxy_get_domains_called = 0
        self.ldapproxy_get_domain_calls: list[str] = []

    def build_modules(self) -> tuple[types.ModuleType, types.ModuleType, types.ModuleType]:
        env_self = self

        agent_mod = types.ModuleType("agent")
        tasks_mod = types.ModuleType("agent.tasks")
        ldapproxy_mod = types.ModuleType("agent.ldapproxy")

        def set_env(key: str, value: str) -> None:
            env_self.call_log.append(f"set_env:{key}")
            env_self.env[key] = str(value)

        def dump_env() -> None:
            env_self.call_log.append("dump_env")
            env_self.flushed_env = dict(env_self.env)
            os.environ.update(env_self.flushed_env)

        def set_status(status: str) -> None:
            env_self.call_log.append(f"set_status:{status}")
            env_self.status_history.append(status)

        def http_route_in_use(domain: str) -> bool:
            env_self.call_log.append(f"http_route_in_use:{domain}")
            return env_self.route_in_use

        def bind_user_domains(domains: list[str]) -> None:
            env_self.call_log.append("bind_user_domains")
            env_self.bound_domains_history.append(list(domains))

        def resolve_agent_id(pattern: str) -> str | None:
            env_self.call_log.append(f"resolve_agent_id:{pattern}")
            if pattern == "traefik@node":
                return env_self.traefik_id
            return pattern

        def assert_exp(expr: bool, msg: str = "Assertion failed") -> None:
            if not expr:
                raise AssertionError(msg)

        def tasks_run(*, agent_id: str, action: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
            env_self.call_log.append(f"tasks.run:{agent_id}:{action}")
            env_self.tasks_calls.append(
                {"agent_id": agent_id, "action": action, "data": data}
            )
            return {"exit_code": env_self.task_exit_code, "output": ""}

        class Ldapproxy:
            def get_domains_list(self) -> list[str]:
                env_self.ldapproxy_get_domains_called += 1
                return list(env_self.domains_list)

            def get_domain(self, name: str) -> dict[str, Any]:
                env_self.ldapproxy_get_domain_calls.append(name)
                if name not in env_self.domains_detail:
                    raise KeyError(f"Unknown domain: {name}")
                return dict(env_self.domains_detail[name])

        tasks_mod.run = tasks_run
        ldapproxy_mod.Ldapproxy = Ldapproxy

        agent_mod.set_env = set_env
        agent_mod.dump_env = dump_env
        agent_mod.set_status = set_status
        agent_mod.http_route_in_use = http_route_in_use
        agent_mod.bind_user_domains = bind_user_domains
        agent_mod.resolve_agent_id = resolve_agent_id
        agent_mod.assert_exp = assert_exp
        agent_mod.tasks = tasks_mod
        agent_mod.ldapproxy = ldapproxy_mod

        return agent_mod, tasks_mod, ldapproxy_mod


def run_imageroot_script(
    monkeypatch: pytest.MonkeyPatch,
    rel_path: str,
    mock_ns8: MockNs8Env,
    *,
    stdin_data: Any = None,
    subprocess_handler: Any = None,
) -> tuple[str, int]:
    """Execute an imageroot Python script in-process with mocked NS8 modules & clean env."""
    script_path = IMAGEROOT / rel_path
    assert script_path.is_file(), f"Missing script: {script_path}"

    agent_mod, tasks_mod, ldapproxy_mod = mock_ns8.build_modules()
    monkeypatch.setitem(sys.modules, "agent", agent_mod)
    monkeypatch.setitem(sys.modules, "agent.tasks", tasks_mod)
    monkeypatch.setitem(sys.modules, "agent.ldapproxy", ldapproxy_mod)

    # Isolate relevant environment variables
    managed_prefixes = ("APM_", "LDAP_", "TRAEFIK_", "BOOTSTRAP_", "JWT_", "ADMIN_GROUPS", "TCP_PORT", "MODULE_ID", "ADVANCEDPOLICYMANAGER_")
    for key in list(os.environ.keys()):
        if key.startswith(managed_prefixes):
            monkeypatch.delenv(key, raising=False)
    for key, val in mock_ns8.env.items():
        monkeypatch.setenv(key, str(val))

    if stdin_data is None:
        raw_in = ""
    elif isinstance(stdin_data, str):
        raw_in = stdin_data
    else:
        raw_in = json.dumps(stdin_data)

    stdout_buf = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw_in))
    monkeypatch.setattr(sys, "stdout", stdout_buf)

    if subprocess_handler is not None:
        monkeypatch.setattr(subprocess, "run", subprocess_handler)

    exit_code = 0
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as exc:
        exit_code = int(exc.code) if exc.code is not None else 0

    return stdout_buf.getvalue(), exit_code


# ---------------------------------------------------------------------------
# 1. NS8 Architectural & Static Compliance Rules
# ---------------------------------------------------------------------------


def test_never_overrides_core_get_status() -> None:
    """NS8 Rule #1: imageroot/actions/get-status MUST NEVER exist."""
    assert not (IMAGEROOT / "actions" / "get-status").exists()


def test_strict_lf_line_endings_across_imageroot_and_container_files() -> None:
    """NS8 Rule #8: All imageroot/ files, Containerfiles, and build-images.sh must use LF only."""
    targets = [p for p in IMAGEROOT.rglob("*") if p.is_file()]
    for root_file in ("Containerfile", "Containerfile.app", "build-images.sh"):
        path = REPO_ROOT / root_file
        assert path.is_file(), f"Missing {root_file}"
        targets.append(path)

    crlf_files = [str(p.relative_to(REPO_ROOT)) for p in targets if b"\r" in p.read_bytes()]
    assert crlf_files == [], f"Files contain CRLF (\\r) bytes: {crlf_files}"


def test_all_executable_scripts_have_clean_shebang_and_dump_env_discipline() -> None:
    """NS8 Rule #2 & #8: Clean LF shebangs and agent.dump_env() after every agent.set_env()."""
    script_globs = [
        "actions/*/[0-9]*",
        "events/*/[0-9]*",
        "bin/*",
        "update-module.d/*",
    ]
    found_scripts: list[Path] = []
    for pattern in script_globs:
        found_scripts.extend(p for p in IMAGEROOT.glob(pattern) if p.is_file())

    assert len(found_scripts) >= 12
    for script in found_scripts:
        text = script.read_text(encoding="utf-8")
        first_line = text.split("\n", 1)[0]
        assert first_line.startswith("#!/"), f"Missing shebang in {script}"
        if "agent.set_env(" in text:
            assert "agent.dump_env()" in text, (
                f"{script.relative_to(REPO_ROOT)} calls agent.set_env() without agent.dump_env()"
            )


def test_systemd_unit_rootless_podman_compliance() -> None:
    """NS8 Rules #3 & #5: Bind strictly to 127.0.0.1:${TCP_PORT}:8080, --pull=missing, slirp4netns."""
    unit_path = IMAGEROOT / "systemd" / "user" / "advancedpolicymanager.service"
    assert unit_path.is_file()
    content = unit_path.read_text(encoding="utf-8")

    assert "--pull=missing" in content
    assert "--pull=always" not in content
    assert "--network=slirp4netns:allow_host_loopback=true" in content
    assert "-p 127.0.0.1:${TCP_PORT}:8080" in content
    assert "0.0.0.0:${TCP_PORT}" not in content
    assert "-v apm-data:/data:Z" in content
    assert "--env-file=%S/state/environment" in content
    assert "${ADVANCEDPOLICYMANAGER_APP_IMAGE}" in content


def test_containerfiles_and_build_script_compliance() -> None:
    """Verify Containerfile (FROM scratch + Rule #8), Containerfile.app, and build-images.sh."""
    cf_module = (REPO_ROOT / "Containerfile").read_text(encoding="utf-8")
    assert "FROM scratch" in cf_module
    assert "sed -i 's/\\r$//'" in cf_module
    assert "chmod +x" in cf_module
    assert "/imageroot" in cf_module
    assert "/ui" in cf_module
    assert "traefik@node:routeadm" in cf_module
    assert "cluster:accountconsumer" in cf_module
    assert 'org.nethserver.tcp-ports-demand="1"' in cf_module
    assert 'org.nethserver.rootfull="0"' in cf_module
    assert "org.nethserver.images=" in cf_module

    cf_app = (REPO_ROOT / "Containerfile.app").read_text(encoding="utf-8")
    assert "/app/web_dist" in cf_app
    assert "/app/agent_artifacts/binaries/linux/x86_64/ns8-policy-agent" in cf_app
    assert "/app/agent_artifacts/installers/" in cf_app
    assert '"uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"' in cf_app

    build_sh = (REPO_ROOT / "build-images.sh").read_text(encoding="utf-8")
    assert build_sh.startswith("#!/bin/bash\n")
    assert "Containerfile.app" in build_sh
    assert "Containerfile" in build_sh


def test_validate_input_schema_is_valid() -> None:
    schema_path = IMAGEROOT / "actions" / "configure-module" / "validate-input.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["type"] == "object"
    assert set(schema["required"]) >= {"host", "http2https", "lets_encrypt"}
    expected_props = {
        "host",
        "http2https",
        "lets_encrypt",
        "ldap_domain",
        "admin_groups",
        "bootstrap_admin_enabled",
        "bootstrap_admin_username",
        "bootstrap_admin_password",
    }
    assert expected_props.issubset(schema["properties"].keys())


def test_cockpit_ui_compliance_and_i18n_keys() -> None:
    """Verify NS8 Cockpit UI rules (no createSuccessNotificationForApp, en+de i18n, Launch20)."""
    main_js = (UI_DIR / "src" / "main.js").read_text(encoding="utf-8")
    assert 'fallbackLocale: "en"' in main_js
    assert "en:" in main_js and "de:" in main_js

    required_keys = [
        ("action", "list-installed-modules"),
        ("task", "cannot_create_task"),
        ("error", "cannot_retrieve_installed_modules"),
        ("error", "cannot_retrieve_module_info"),
    ]
    for lang in ("en", "de"):
        i18n_file = UI_DIR / "public" / "i18n" / lang / "translation.json"
        assert i18n_file.is_file(), f"Missing {lang} translation.json"
        data = json.loads(i18n_file.read_text(encoding="utf-8"))
        for section, key in required_keys:
            assert section in data and key in data[section], (
                f"Missing required NS8 i18n key {section}.{key} in {lang}/translation.json"
            )

    # Never call createSuccessNotificationForApp anywhere in ui/src
    for src_file in (UI_DIR / "src").rglob("*"):
        if src_file.is_file():
            txt = src_file.read_text(encoding="utf-8")
            assert "createSuccessNotificationForApp" not in txt, (
                f"Forbidden createSuccessNotificationForApp found in {src_file}"
            )

    status_vue = (UI_DIR / "src" / "views" / "Status.vue").read_text(encoding="utf-8")
    assert '"get-status"' in status_vue
    assert '"get-configuration"' in status_vue
    assert "<Launch20" in status_vue
    assert re.search(r"components\s*:\s*\{[^}]*Launch20", status_vue)

    settings_vue = (UI_DIR / "src" / "views" / "Settings.vue").read_text(encoding="utf-8")
    assert '"configure-module"' in settings_vue
    for field_name in (
        "host",
        "lets_encrypt",
        "http2https",
        "ldap_domain",
        "admin_groups",
        "bootstrap_admin_enabled",
        "bootstrap_admin_username",
        "bootstrap_admin_password",
    ):
        assert field_name in settings_vue


# ---------------------------------------------------------------------------
# 2. Action & Event Behavioral Unit Tests
# ---------------------------------------------------------------------------


def test_create_module_20initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_ns8 = MockNs8Env()
    _, exit_code = run_imageroot_script(
        monkeypatch,
        "actions/create-module/20initialize",
        mock_ns8,
    )
    assert exit_code == 0
    assert mock_ns8.call_log[-1] == "dump_env"

    flushed = mock_ns8.flushed_env
    assert re.fullmatch(r"[0-9a-f]{64}", flushed["JWT_SECRET"])
    assert flushed["ADMIN_GROUPS"] == "Domain Admins,admins"
    assert flushed["BOOTSTRAP_ADMIN_ENABLED"] == "true"
    assert flushed["BOOTSTRAP_ADMIN_USERNAME"] == "admin"
    assert flushed["APM_PORT"] == "8080"
    assert flushed["APM_DATA_DIR"] == "/data"
    assert flushed["APM_STATIC_DIR"] == "/app/web_dist"
    assert flushed["APM_AGENT_ARTIFACTS_DIR"] == "/app/agent_artifacts"


def test_get_configuration_20read(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_ns8 = MockNs8Env(
        initial_env={
            "TRAEFIK_HOST": "policies.example.org",
            "TRAEFIK_HTTP2HTTPS": "true",
            "TRAEFIK_LETS_ENCRYPT": "false",
            "LDAP_DOMAIN": "ad.example.org",
            "ADMIN_GROUPS": "Domain Admins,IT-Admins",
            "BOOTSTRAP_ADMIN_ENABLED": "true",
            "BOOTSTRAP_ADMIN_USERNAME": "emergency-admin",
            "APM_PUBLIC_URL": "https://policies.example.org",
        },
        domains_list=["ad.example.org", "ldap.example.org"],
    )
    stdout, exit_code = run_imageroot_script(
        monkeypatch,
        "actions/get-configuration/20read",
        mock_ns8,
    )
    assert exit_code == 0
    assert mock_ns8.ldapproxy_get_domains_called == 1

    payload = json.loads(stdout)
    assert payload["host"] == "policies.example.org"
    assert payload["http2https"] is True
    assert payload["lets_encrypt"] is False
    assert payload["ldap_domain"] == "ad.example.org"
    assert payload["admin_groups"] == "Domain Admins,IT-Admins"
    assert payload["bootstrap_admin_enabled"] is True
    assert payload["bootstrap_admin_username"] == "emergency-admin"
    assert payload["app_url"] == "https://policies.example.org"
    assert payload["user_domains"] == ["ad.example.org", "ldap.example.org"]


def test_configure_module_01hostname_validation_collision_exits_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_ns8 = MockNs8Env(
        initial_env={"TRAEFIK_HOST": ""},
        route_in_use=True,
    )
    stdout, exit_code = run_imageroot_script(
        monkeypatch,
        "actions/configure-module/01hostname-validation",
        mock_ns8,
        stdin_data={"host": "taken.example.org", "http2https": True, "lets_encrypt": False},
    )
    assert exit_code == 2
    assert mock_ns8.status_history == ["validation-failed"]
    errors = json.loads(stdout)
    assert isinstance(errors, list) and len(errors) == 1
    assert errors[0]["field"] == "host"
    assert errors[0]["value"] == "taken.example.org"
    assert errors[0]["error"] == "hostname_already_used_in_traefik"


def test_configure_module_01hostname_validation_allows_unchanged_or_free_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Unchanged own hostname does not fail even if route_in_use=True
    mock_same = MockNs8Env(
        initial_env={"TRAEFIK_HOST": "policies.example.org"},
        route_in_use=True,
    )
    stdout_same, code_same = run_imageroot_script(
        monkeypatch,
        "actions/configure-module/01hostname-validation",
        mock_same,
        stdin_data={"host": "policies.example.org", "http2https": True, "lets_encrypt": False},
    )
    assert code_same == 0
    assert stdout_same == ""

    # New unused hostname passes cleanly
    mock_free = MockNs8Env(
        initial_env={"TRAEFIK_HOST": "old.example.org"},
        route_in_use=False,
    )
    stdout_free, code_free = run_imageroot_script(
        monkeypatch,
        "actions/configure-module/01hostname-validation",
        mock_free,
        stdin_data={"host": "new.example.org", "http2https": True, "lets_encrypt": False},
    )
    assert code_free == 0
    assert stdout_free == ""


def test_configure_module_20configure_rewrites_10_0_2_2_and_sets_contract_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_jwt = "a" * 64
    mock_ns8 = MockNs8Env(
        initial_env={
            "MODULE_ID": "advancedpolicymanager1",
            "TCP_PORT": "20145",
            "JWT_SECRET": existing_jwt,
            "APM_PORT": "8080",
            "APM_DATA_DIR": "/data",
        }
    )

    _, exit_code = run_imageroot_script(
        monkeypatch,
        "actions/configure-module/20configure",
        mock_ns8,
        stdin_data={
            "host": "policies.example.org",
            "http2https": True,
            "lets_encrypt": True,
            "ldap_domain": "ad.example.org",
            "admin_groups": "Domain Admins,IT-Admins",
            "bootstrap_admin_enabled": True,
            "bootstrap_admin_username": "admin",
            "bootstrap_admin_password": "StrongEmergencyPassword!99",
        },
    )
    assert exit_code == 0
    assert mock_ns8.bound_domains_history == [["ad.example.org"]]
    assert mock_ns8.ldapproxy_get_domain_calls == ["ad.example.org"]
    assert "dump_env" in mock_ns8.call_log

    flushed = mock_ns8.flushed_env
    assert flushed["LDAP_MODE"] == "ldapproxy"
    assert flushed["LDAP_DOMAIN"] == "ad.example.org"
    assert flushed["LDAP_SCHEMA"] == "ad"
    assert flushed["LDAP_HOST"] == "10.0.2.2"  # Rewritten from 127.0.0.1!
    assert flushed["LDAP_PORT"] == "40123"
    assert flushed["LDAP_TLS"] == "false"
    assert flushed["LDAP_BASE_DN"] == "dc=ad,dc=example,dc=org"
    assert flushed["LDAP_BIND_DN"] == "cn=ldapservice,cn=Users,dc=ad,dc=example,dc=org"
    assert flushed["LDAP_BIND_PASSWORD"] == "secret-bind-password"
    assert flushed["APM_PUBLIC_URL"] == "https://policies.example.org"
    assert flushed["ADMIN_GROUPS"] == "Domain Admins,IT-Admins"
    assert flushed["BOOTSTRAP_ADMIN_ENABLED"] == "true"
    assert flushed["BOOTSTRAP_ADMIN_USERNAME"] == "admin"
    assert "BOOTSTRAP_ADMIN_PASSWORD" not in flushed  # Never store plaintext password

    # Verify PBKDF2-HMAC-SHA256 hash format compatibility with backend
    pw_hash = flushed["BOOTSTRAP_ADMIN_PASSWORD_HASH"]
    assert pw_hash.startswith("pbkdf2:sha256:260000$")
    _, _, rest = pw_hash.split(":", 2)
    iters_str, salt, digest_hex = rest.split("$")
    expected_dk = hashlib.pbkdf2_hmac(
        "sha256",
        b"StrongEmergencyPassword!99",
        salt.encode("utf-8"),
        int(iters_str),
    ).hex()
    assert digest_hex == expected_dk

    # Verify Traefik set-route call
    assert len(mock_ns8.tasks_calls) == 1
    route_call = mock_ns8.tasks_calls[0]
    assert route_call == {
        "agent_id": "traefik1",
        "action": "set-route",
        "data": {
            "instance": "advancedpolicymanager1",
            "url": "http://127.0.0.1:20145",
            "host": "policies.example.org",
            "lets_encrypt": True,
            "http2https": True,
        },
    }


def test_configure_module_80start_services(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run_inactive(cmd: list[str], **kwargs: Any) -> MagicMock:
        calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 3 if "is-active" in cmd else 0
        return res

    mock_ns8 = MockNs8Env()
    _, code = run_imageroot_script(
        monkeypatch,
        "actions/configure-module/80start_services",
        mock_ns8,
        subprocess_handler=fake_run_inactive,
    )
    assert code == 0
    assert ["systemctl", "--user", "enable", "--now", "advancedpolicymanager.service"] in calls


def test_destroy_module_20destroy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        return res

    mock_ns8 = MockNs8Env(initial_env={"MODULE_ID": "advancedpolicymanager1"})
    _, code = run_imageroot_script(
        monkeypatch,
        "actions/destroy-module/20destroy",
        mock_ns8,
        subprocess_handler=fake_run,
    )
    assert code == 0
    assert mock_ns8.bound_domains_history == [[]]
    assert mock_ns8.tasks_calls == [
        {
            "agent_id": "traefik1",
            "action": "delete-route",
            "data": {"instance": "advancedpolicymanager1"},
        }
    ]
    assert ["systemctl", "--user", "disable", "--now", "advancedpolicymanager.service"] in calls


def test_restore_module_06copyenv_and_50configure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Step 1: 06copyenv
    mock_copy = MockNs8Env(
        initial_env={
            "MODULE_ID": "advancedpolicymanager2",
            "TCP_PORT": "20999",
        }
    )
    backed_up_env = {
        "MODULE_ID": "advancedpolicymanager1",
        "TCP_PORT": "20111",
        "TRAEFIK_HOST": "policies.example.org",
        "TRAEFIK_HTTP2HTTPS": "true",
        "TRAEFIK_LETS_ENCRYPT": "false",
        "APM_PUBLIC_URL": "https://policies.example.org",
        "JWT_SECRET": "b" * 64,
        "LDAP_DOMAIN": "ldap.example.org",
        "ADMIN_GROUPS": "admins",
        "BOOTSTRAP_ADMIN_ENABLED": "true",
        "BOOTSTRAP_ADMIN_USERNAME": "admin",
        "BOOTSTRAP_ADMIN_PASSWORD_HASH": "pbkdf2:sha256:260000$salt$hash",
    }
    _, code_copy = run_imageroot_script(
        monkeypatch,
        "actions/restore-module/06copyenv",
        mock_copy,
        stdin_data={"environment": backed_up_env},
    )
    assert code_copy == 0
    assert mock_copy.flushed_env["MODULE_ID"] == "advancedpolicymanager2"
    assert mock_copy.flushed_env["TCP_PORT"] == "20999"
    assert mock_copy.flushed_env["JWT_SECRET"] == "b" * 64
    assert mock_copy.flushed_env["LDAP_DOMAIN"] == "ldap.example.org"

    # Step 2: 50configure with a present SQLite backup file
    backup_db = tmp_path / "apm.db.bak"
    backup_db.write_bytes(b"SQLite format 3\x00dummy")

    subproc_calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        subproc_calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        return res

    restore_env = dict(mock_copy.flushed_env)
    restore_env["ADVANCEDPOLICYMANAGER_APP_IMAGE"] = "ghcr.io/nethserver/advancedpolicymanager-app:latest"
    restore_env["APM_STATE_BACKUP_FILE"] = str(backup_db)

    mock_restore = MockNs8Env(initial_env=restore_env)
    _, code_restore = run_imageroot_script(
        monkeypatch,
        "actions/restore-module/50configure",
        mock_restore,
        subprocess_handler=fake_run,
    )
    assert code_restore == 0
    assert mock_restore.bound_domains_history == [["ldap.example.org"]]
    assert mock_restore.flushed_env["LDAP_HOST"] == "10.0.2.2"
    assert mock_restore.flushed_env["LDAP_SCHEMA"] == "rfc2307"
    assert mock_restore.flushed_env["LDAP_TLS"] == "true"
    assert not backup_db.exists()  # Cleaned up after volume restore
    assert any(cmd[0] == "podman" and "apm-data:/data:Z" in cmd for cmd in subproc_calls)
    assert len(mock_restore.tasks_calls) == 1
    assert mock_restore.tasks_calls[0]["action"] == "set-route"
    assert mock_restore.tasks_calls[0]["data"]["url"] == "http://127.0.0.1:20999"


def test_clone_module_50configure_rotates_jwt_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_jwt = "c" * 64
    subproc_calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        subproc_calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        return res

    mock_clone = MockNs8Env(
        initial_env={
            "MODULE_ID": "advancedpolicymanager3",
            "TCP_PORT": "20333",
            "JWT_SECRET": old_jwt,
            "LDAP_DOMAIN": "ad.example.org",
            "TRAEFIK_HTTP2HTTPS": "true",
            "TRAEFIK_LETS_ENCRYPT": "false",
        }
    )
    _, code = run_imageroot_script(
        monkeypatch,
        "actions/clone-module/50configure",
        mock_clone,
        stdin_data={"traefik_host": "policies-clone.example.org"},
        subprocess_handler=fake_run,
    )
    assert code == 0
    new_jwt = mock_clone.flushed_env["JWT_SECRET"]
    assert re.fullmatch(r"[0-9a-f]{64}", new_jwt)
    assert new_jwt != old_jwt
    assert mock_clone.bound_domains_history == [["ad.example.org"]]
    assert mock_clone.flushed_env["LDAP_HOST"] == "10.0.2.2"
    assert mock_clone.flushed_env["APM_PUBLIC_URL"] == "https://policies-clone.example.org"
    assert ["systemctl", "--user", "enable", "--now", "advancedpolicymanager.service"] in subproc_calls


def test_event_user_domain_changed_10reload(monkeypatch: pytest.MonkeyPatch) -> None:
    subproc_calls: list[list[str]] = []

    def fake_run_active(cmd: list[str], **kwargs: Any) -> MagicMock:
        subproc_calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        return res

    mock_ev = MockNs8Env(
        initial_env={"LDAP_DOMAIN": "ad.example.org"},
        domains_detail={
            "ad.example.org": {
                "name": "ad.example.org",
                "host": "127.0.0.1",
                "port": 49999,
                "schema": "ad",
                "tls": False,
                "base_dn": "dc=ad,dc=example,dc=org",
                "bind_dn": "cn=svc,dc=ad,dc=example,dc=org",
                "bind_password": "rotated-password",
            }
        },
    )
    _, code = run_imageroot_script(
        monkeypatch,
        "events/user-domain-changed/10reload",
        mock_ev,
        stdin_data={"domain": "ad.example.org"},
        subprocess_handler=fake_run_active,
    )
    assert code == 0
    assert mock_ev.flushed_env["LDAP_HOST"] == "10.0.2.2"
    assert mock_ev.flushed_env["LDAP_PORT"] == "49999"
    assert mock_ev.flushed_env["LDAP_BIND_PASSWORD"] == "rotated-password"
    assert ["systemctl", "--user", "restart", "advancedpolicymanager.service"] in subproc_calls


def test_backup_dump_cleanup_and_update_pull(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_inc = (IMAGEROOT / "etc" / "state-include.conf").read_text(encoding="utf-8")
    assert "state/environment" in state_inc
    assert "state/apm.db.bak" in state_inc

    backup_target = tmp_path / "apm.db.bak"
    dump_calls: list[list[str]] = []

    def fake_dump_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        dump_calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        res.stdout = "true\n"
        if cmd[:2] == ["podman", "cp"]:
            Path(cmd[3]).write_bytes(b"sqlite-online-backup")
        return res

    mock_ns8 = MockNs8Env(
        initial_env={
            "APM_STATE_BACKUP_FILE": str(backup_target),
            "ADVANCEDPOLICYMANAGER_APP_IMAGE": "ghcr.io/nethserver/advancedpolicymanager-app:1.0.0",
        }
    )
    _, code_dump = run_imageroot_script(
        monkeypatch,
        "bin/module-dump-state",
        mock_ns8,
        subprocess_handler=fake_dump_run,
    )
    assert code_dump == 0
    assert backup_target.is_file()
    assert any(
        cmd[:3] == ["podman", "exec", "advancedpolicymanager-app"]
        and any("sqlite3.connect" in arg and ".backup(" in arg for arg in cmd)
        for cmd in dump_calls
    )

    # Cleanup removes temporary state dump
    _, code_clean = run_imageroot_script(
        monkeypatch,
        "bin/module-cleanup-state",
        mock_ns8,
    )
    assert code_clean == 0
    assert not backup_target.exists()

    # update-module.d/20pull_images pulls new image and restarts active service
    pull_calls: list[list[str]] = []

    def fake_pull_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        pull_calls.append(list(cmd))
        res = MagicMock()
        res.returncode = 0
        return res

    _, code_pull = run_imageroot_script(
        monkeypatch,
        "update-module.d/20pull_images",
        mock_ns8,
        subprocess_handler=fake_pull_run,
    )
    assert code_pull == 0
    assert ["podman", "pull", "ghcr.io/nethserver/advancedpolicymanager-app:1.0.0"] in pull_calls
    assert ["systemctl", "--user", "restart", "advancedpolicymanager.service"] in pull_calls
