"""Live LDAP/AD directory provider supporting NS8 Samba AD (`ad`) and OpenLDAP (`rfc2307`)."""

from __future__ import annotations

import ssl
from typing import Any, Callable

from ldap3 import Connection, NONE, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from app.directory.base import (
    DirectoryGroup,
    DirectoryProvider,
    DirectoryUnavailableError,
    DirectoryUser,
    normalize_login_username,
)

AD_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
AD_WELL_KNOWN_PRIMARY_GROUP_RIDS = {
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
}


def extract_cn_from_dn(dn: str) -> str:
    """Safely extract the first CN/OU attribute value from a Distinguished Name."""
    if not dn:
        return ""
    try:
        parsed = parse_dn(dn)
        for attr, value, _ in parsed:
            if attr.lower() == "cn":
                return str(value)
    except Exception:
        pass
    first_rdn = dn.split(",", 1)[0].strip()
    if "=" in first_rdn:
        return first_rdn.split("=", 1)[1].strip()
    return first_rdn


def _entry_str(attrs: dict[str, Any], key: str, default: str = "") -> str:
    val = attrs.get(key)
    if val is None:
        for k, v in attrs.items():
            if k.lower() == key.lower():
                val = v
                break
    if val is None:
        return default
    if isinstance(val, (list, tuple)):
        return str(val[0]) if val else default
    return str(val)


def _entry_list(attrs: dict[str, Any], key: str) -> list[str]:
    val = attrs.get(key)
    if val is None:
        for k, v in attrs.items():
            if k.lower() == key.lower():
                val = v
                break
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x) for x in val if x is not None and str(x) != ""]
    s = str(val)
    return [s] if s else []


def _extract_entry_dict(entry: Any) -> tuple[str, dict[str, Any]]:
    """Support both ldap3 Entry objects and raw dict entries returned by mocks."""
    if isinstance(entry, dict):
        dn = str(entry.get("dn") or entry.get("entry_dn") or "")
        raw_attrs = entry.get("attributes") or entry.get("raw_attributes") or {}
        return dn, dict(raw_attrs)
    dn = str(getattr(entry, "entry_dn", "") or "")
    if hasattr(entry, "entry_attributes_as_dict"):
        return dn, dict(entry.entry_attributes_as_dict)
    raw_attrs = getattr(entry, "attributes", {})
    return dn, dict(raw_attrs) if isinstance(raw_attrs, dict) else {}


class Ldap3DirectoryProvider(DirectoryProvider):
    """Connects via NS8 ldapproxy to Samba AD (`schema=ad`) or OpenLDAP (`schema=rfc2307`)."""

    def __init__(
        self,
        host: str,
        port: int = 389,
        schema: str = "ad",
        base_dn: str = "",
        bind_dn: str = "",
        bind_password: str = "",
        use_tls: bool = False,
        domain: str = "",
        server_factory: Callable[..., Any] | None = None,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.host = host.strip()
        self.port = port
        self.schema = "rfc2307" if schema.strip().lower() == "rfc2307" else "ad"
        self.base_dn = base_dn.strip()
        self.bind_dn = bind_dn.strip()
        self.bind_password = bind_password
        self.use_tls = use_tls
        self.domain = domain.strip()
        self._server_factory = server_factory or Server
        self._connection_factory = connection_factory or Connection

    def _build_server(self) -> Any:
        if not self.host:
            raise DirectoryUnavailableError("LDAP_HOST ist nicht konfiguriert")
        use_ssl = bool(self.use_tls)
        tls_cfg = Tls(validate=ssl.CERT_NONE) if use_ssl else None
        return self._server_factory(
            self.host,
            port=self.port,
            use_ssl=use_ssl,
            tls=tls_cfg,
            get_info=NONE,
            connect_timeout=5,
        )

    def _open_service_connection(self) -> Any:
        server = self._build_server()
        try:
            if self.bind_dn:
                conn = self._connection_factory(
                    server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    auto_bind=True,
                )
            else:
                conn = self._connection_factory(server, auto_bind=True)
            return conn
        except (LDAPSocketOpenError, LDAPBindError, LDAPException, OSError) as exc:
            raise DirectoryUnavailableError(
                f"Verbindung zum LDAP/AD-Verzeichnis fehlgeschlagen: {exc.__class__.__name__}"
            ) from exc

    @staticmethod
    def _dedupe_preserve_order(items: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            cleaned = item.strip()
            if not cleaned:
                continue
            key = cleaned.lower()
            if key not in seen:
                seen.add(key)
                result.append(cleaned)
        return result

    def _resolve_ad_groups(self, conn: Any, user_dn: str, member_of_dns: list[str]) -> list[str]:
        groups: list[str] = []
        if user_dn:
            esc_dn = escape_filter_chars(user_dn)
            nested_filter = f"(&(objectClass=group)(member:{AD_MATCHING_RULE_IN_CHAIN}:={esc_dn}))"
            try:
                conn.search(
                    search_base=self.base_dn,
                    search_filter=nested_filter,
                    search_scope=SUBTREE,
                    attributes=["cn", "sAMAccountName"],
                )
                for entry in getattr(conn, "entries", []) or []:
                    _, attrs = _extract_entry_dict(entry)
                    cn = _entry_str(attrs, "cn") or _entry_str(attrs, "sAMAccountName")
                    if cn:
                        groups.append(cn)
            except LDAPException:
                # Fallback gracefully to memberOf parsing below
                pass

        for grp_dn in member_of_dns:
            cn = extract_cn_from_dn(grp_dn)
            if cn:
                groups.append(cn)

        return self._dedupe_preserve_order(groups)

    def _resolve_rfc2307_groups(
        self,
        conn: Any,
        uid: str,
        user_dn: str,
        member_of_dns: list[str],
    ) -> list[str]:
        groups: list[str] = []
        clauses: list[str] = []
        if uid:
            esc_uid = escape_filter_chars(uid)
            clauses.append(f"(&(objectClass=posixGroup)(memberUid={esc_uid}))")
        if user_dn:
            esc_dn = escape_filter_chars(user_dn)
            clauses.append(
                f"(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
                f"(|(member={esc_dn})(uniqueMember={esc_dn})))"
            )

        if clauses:
            group_filter = clauses[0] if len(clauses) == 1 else f"(|{''.join(clauses)})"
            try:
                conn.search(
                    search_base=self.base_dn,
                    search_filter=group_filter,
                    search_scope=SUBTREE,
                    attributes=["cn"],
                )
                for entry in getattr(conn, "entries", []) or []:
                    _, attrs = _extract_entry_dict(entry)
                    cn = _entry_str(attrs, "cn")
                    if cn:
                        groups.append(cn)
            except LDAPException:
                pass

        for grp_dn in member_of_dns:
            cn = extract_cn_from_dn(grp_dn)
            if cn:
                groups.append(cn)

        return self._dedupe_preserve_order(groups)

    def _find_user_with_conn(self, conn: Any, username: str) -> DirectoryUser | None:
        normalized = normalize_login_username(username)
        if not normalized:
            return None
        esc_user = escape_filter_chars(normalized)

        if self.schema == "ad":
            short_user = normalized.split("@", 1)[0] if "@" in normalized else normalized
            esc_short = escape_filter_chars(short_user)
            search_filter = (
                "(&(objectClass=user)(!(objectClass=computer))"
                f"(|(sAMAccountName={esc_user})(userPrincipalName={esc_user})"
                f"(sAMAccountName={esc_short})))"
            )
            attributes = [
                "sAMAccountName",
                "userPrincipalName",
                "cn",
                "displayName",
                "mail",
                "memberOf",
                "primaryGroupID",
                "distinguishedName",
            ]
        else:
            short_user = normalized.split("@", 1)[0] if "@" in normalized else normalized
            esc_short = escape_filter_chars(short_user)
            search_filter = (
                "(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))"
                f"(|(uid={esc_user})(mail={esc_user})(uid={esc_short})))"
            )
            attributes = ["uid", "cn", "displayName", "mail", "memberOf"]

        conn.search(
            search_base=self.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        entries = list(getattr(conn, "entries", []) or [])
        if not entries:
            return None

        dn, attrs = _extract_entry_dict(entries[0])
        if not dn:
            dn = _entry_str(attrs, "distinguishedName")

        if self.schema == "ad":
            resolved_username = (
                _entry_str(attrs, "sAMAccountName")
                or _entry_str(attrs, "cn")
                or normalized
            )
            display_name = (
                _entry_str(attrs, "displayName")
                or _entry_str(attrs, "cn")
                or resolved_username
            )
            email = _entry_str(attrs, "mail") or _entry_str(attrs, "userPrincipalName")
            member_of = _entry_list(attrs, "memberOf")
            groups = self._resolve_ad_groups(conn, dn, member_of)
            primary_rid = _entry_str(attrs, "primaryGroupID").strip()
            if primary_rid in AD_WELL_KNOWN_PRIMARY_GROUP_RIDS:
                groups = self._dedupe_preserve_order(
                    [*groups, AD_WELL_KNOWN_PRIMARY_GROUP_RIDS[primary_rid]]
                )
        else:
            resolved_username = (
                _entry_str(attrs, "uid")
                or _entry_str(attrs, "cn")
                or normalized
            )
            display_name = (
                _entry_str(attrs, "displayName")
                or _entry_str(attrs, "cn")
                or resolved_username
            )
            email = _entry_str(attrs, "mail")
            member_of = _entry_list(attrs, "memberOf")
            groups = self._resolve_rfc2307_groups(conn, resolved_username, dn, member_of)

        return DirectoryUser(
            username=resolved_username,
            display_name=display_name,
            email=email,
            dn=dn,
            groups=groups,
        )

    def authenticate(self, username: str, password: str) -> DirectoryUser | None:
        if not username or not username.strip() or not password:
            return None

        conn = self._open_service_connection()
        try:
            user = self._find_user_with_conn(conn, username)
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

        if user is None or not user.dn:
            return None

        server = self._build_server()
        try:
            user_conn = self._connection_factory(
                server,
                user=user.dn,
                password=password,
                auto_bind=False,
            )
            bound = bool(user_conn.bind())
            try:
                user_conn.unbind()
            except Exception:
                pass
            if not bound:
                return None
            return user
        except LDAPBindError:
            return None
        except LDAPSocketOpenError as exc:
            raise DirectoryUnavailableError(
                "LDAP/AD-Server während der Benutzeranmeldung nicht erreichbar"
            ) from exc
        except LDAPException:
            return None

    def get_user(self, username: str) -> DirectoryUser | None:
        if not username or not username.strip():
            return None
        conn = self._open_service_connection()
        try:
            return self._find_user_with_conn(conn, username)
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def search_users(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryUser], int]:
        conn = self._open_service_connection()
        try:
            q = search.strip()
            if self.schema == "ad":
                if q:
                    esc_q = escape_filter_chars(q)
                    search_filter = (
                        "(&(objectClass=user)(!(objectClass=computer))"
                        f"(|(sAMAccountName=*{esc_q}*)(displayName=*{esc_q}*)"
                        f"(cn=*{esc_q}*)(mail=*{esc_q}*)))"
                    )
                else:
                    search_filter = "(&(objectClass=user)(!(objectClass=computer)))"
                attributes = [
                    "sAMAccountName",
                    "userPrincipalName",
                    "cn",
                    "displayName",
                    "mail",
                    "memberOf",
                    "distinguishedName",
                ]
            else:
                if q:
                    esc_q = escape_filter_chars(q)
                    search_filter = (
                        "(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount))"
                        f"(|(uid=*{esc_q}*)(displayName=*{esc_q}*)(cn=*{esc_q}*)(mail=*{esc_q}*)))"
                    )
                else:
                    search_filter = "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))"
                attributes = ["uid", "cn", "displayName", "mail", "memberOf"]

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
            )
            raw_entries = [
                _extract_entry_dict(entry) for entry in (getattr(conn, "entries", []) or [])
            ]

            users: list[DirectoryUser] = []
            for dn, attrs in raw_entries:
                actual_dn = dn or _entry_str(attrs, "distinguishedName")
                if self.schema == "ad":
                    uname = _entry_str(attrs, "sAMAccountName") or _entry_str(attrs, "cn")
                    if not uname:
                        continue
                    dname = _entry_str(attrs, "displayName") or _entry_str(attrs, "cn") or uname
                    email = _entry_str(attrs, "mail") or _entry_str(attrs, "userPrincipalName")
                    member_of = _entry_list(attrs, "memberOf")
                    groups = self._dedupe_preserve_order(
                        [extract_cn_from_dn(g) for g in member_of if extract_cn_from_dn(g)]
                    )
                else:
                    uname = _entry_str(attrs, "uid") or _entry_str(attrs, "cn")
                    if not uname:
                        continue
                    dname = _entry_str(attrs, "displayName") or _entry_str(attrs, "cn") or uname
                    email = _entry_str(attrs, "mail")
                    member_of = _entry_list(attrs, "memberOf")
                    groups = self._resolve_rfc2307_groups(conn, uname, actual_dn, member_of)

                users.append(
                    DirectoryUser(
                        username=uname,
                        display_name=dname,
                        email=email,
                        dn=actual_dn,
                        groups=groups,
                    )
                )

            users.sort(key=lambda u: u.username.lower())
            total = len(users)
            safe_page = max(1, page)
            safe_size = max(1, page_size)
            start = (safe_page - 1) * safe_size
            return users[start : start + safe_size], total
        except LDAPException as exc:
            raise DirectoryUnavailableError(
                f"LDAP-Benutzersuche fehlgeschlagen: {exc.__class__.__name__}"
            ) from exc
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def search_groups(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryGroup], int]:
        conn = self._open_service_connection()
        try:
            q = search.strip()
            if self.schema == "ad":
                if q:
                    esc_q = escape_filter_chars(q)
                    search_filter = (
                        "(&(objectClass=group)"
                        f"(|(cn=*{esc_q}*)(sAMAccountName=*{esc_q}*)(description=*{esc_q}*)))"
                    )
                else:
                    search_filter = "(objectClass=group)"
                attributes = ["cn", "sAMAccountName", "description", "member"]
            else:
                base_cls = "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"
                if q:
                    esc_q = escape_filter_chars(q)
                    search_filter = f"(&{base_cls}(|(cn=*{esc_q}*)(description=*{esc_q}*)))"
                else:
                    search_filter = base_cls
                attributes = ["cn", "description", "memberUid", "member", "uniqueMember"]

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
            )

            groups: list[DirectoryGroup] = []
            for entry in getattr(conn, "entries", []) or []:
                dn, attrs = _extract_entry_dict(entry)
                name = _entry_str(attrs, "cn") or _entry_str(attrs, "sAMAccountName")
                if not name:
                    continue
                description = _entry_str(attrs, "description")
                members = set(_entry_list(attrs, "member"))
                members.update(_entry_list(attrs, "memberUid"))
                members.update(_entry_list(attrs, "uniqueMember"))
                groups.append(
                    DirectoryGroup(
                        name=name,
                        description=description,
                        dn=dn,
                        member_count=len(members),
                    )
                )

            groups.sort(key=lambda g: g.name.lower())
            total = len(groups)
            safe_page = max(1, page)
            safe_size = max(1, page_size)
            start = (safe_page - 1) * safe_size
            return groups[start : start + safe_size], total
        except LDAPException as exc:
            raise DirectoryUnavailableError(
                f"LDAP-Gruppensuche fehlgeschlagen: {exc.__class__.__name__}"
            ) from exc
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
