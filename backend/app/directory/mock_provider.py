"""Deterministic in-memory directory provider for local dev and offline tests."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import hash_password_pbkdf2, verify_password_pbkdf2
from app.directory.base import (
    DirectoryGroup,
    DirectoryProvider,
    DirectoryUser,
    normalize_login_username,
)

MOCK_HASH_ITERATIONS = 10_000


@dataclass(frozen=True)
class MockAccountSeed:
    username: str
    display_name: str
    email: str
    password_hash: str
    groups: list[str]


class InMemoryDirectoryProvider(DirectoryProvider):
    """Pre-populated realistic German SME AD/LDAP directory without storing plaintext passwords."""

    def __init__(
        self,
        domain: str = "firma.local",
        base_dn: str = "dc=firma,dc=local",
        accounts: list[MockAccountSeed] | None = None,
    ) -> None:
        self.domain = domain or "firma.local"
        self.base_dn = base_dn or "dc=firma,dc=local"

        if accounts is not None:
            self._accounts = list(accounts)
        else:
            self._accounts = [
                MockAccountSeed(
                    username="administrator",
                    display_name="Domain Administrator",
                    email=f"administrator@{self.domain}",
                    password_hash=hash_password_pbkdf2(
                        "Admin123!", iterations=MOCK_HASH_ITERATIONS, salt="mock-admin"
                    ),
                    groups=["Domain Admins", "IT-Admins"],
                ),
                MockAccountSeed(
                    username="m.mueller",
                    display_name="Max Müller",
                    email=f"m.mueller@{self.domain}",
                    password_hash=hash_password_pbkdf2(
                        "Mueller123!", iterations=MOCK_HASH_ITERATIONS, salt="mock-mueller"
                    ),
                    groups=["Buchhaltung", "Domain Users"],
                ),
                MockAccountSeed(
                    username="s.weber",
                    display_name="Sabine Weber",
                    email=f"s.weber@{self.domain}",
                    password_hash=hash_password_pbkdf2(
                        "Weber123!", iterations=MOCK_HASH_ITERATIONS, salt="mock-weber"
                    ),
                    groups=["IT-Admins", "Domain Users"],
                ),
                MockAccountSeed(
                    username="l.schmidt",
                    display_name="Lukas Schmidt",
                    email=f"l.schmidt@{self.domain}",
                    password_hash=hash_password_pbkdf2(
                        "Schmidt123!", iterations=MOCK_HASH_ITERATIONS, salt="mock-schmidt"
                    ),
                    groups=["Vertrieb", "Domain Users"],
                ),
                MockAccountSeed(
                    username="t.fischer",
                    display_name="Tom Fischer",
                    email=f"t.fischer@{self.domain}",
                    password_hash=hash_password_pbkdf2(
                        "Fischer123!", iterations=MOCK_HASH_ITERATIONS, salt="mock-fischer"
                    ),
                    groups=["Schulung", "Domain Users"],
                ),
            ]

        self._group_descriptions: dict[str, str] = {
            "Domain Admins": "Domänen-Administratoren mit Vollzugriff",
            "IT-Admins": "IT-Systemadministration und Support",
            "Buchhaltung": "Abteilung Finanzbuchhaltung und Controlling",
            "Vertrieb": "Außendienst und Kundenbetreuung",
            "Schulung": "Schulungsraum- und Trainingskonten",
            "Domain Users": "Alle Domänenbenutzer",
        }

    def _to_directory_user(self, seed: MockAccountSeed) -> DirectoryUser:
        return DirectoryUser(
            username=seed.username,
            display_name=seed.display_name,
            email=seed.email,
            dn=f"CN={seed.display_name},OU=Users,{self.base_dn}",
            groups=list(seed.groups),
        )

    def _find_seed(self, username: str) -> MockAccountSeed | None:
        if not username or not username.strip():
            return None
        normalized = normalize_login_username(username)
        candidates = {normalized.lower()}
        if "@" in normalized:
            candidates.add(normalized.split("@", 1)[0].lower())
        for seed in self._accounts:
            if seed.username.lower() in candidates or seed.email.lower() in candidates:
                return seed
        return None

    def authenticate(self, username: str, password: str) -> DirectoryUser | None:
        if not username or not password:
            return None
        seed = self._find_seed(username)
        if seed is None:
            return None
        if not verify_password_pbkdf2(password, seed.password_hash):
            return None
        return self._to_directory_user(seed)

    def get_user(self, username: str) -> DirectoryUser | None:
        seed = self._find_seed(username)
        if seed is None:
            return None
        return self._to_directory_user(seed)

    def search_users(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryUser], int]:
        q = search.strip().lower()
        users = [self._to_directory_user(s) for s in self._accounts]
        if q:
            users = [
                u
                for u in users
                if q in u.username.lower()
                or q in u.display_name.lower()
                or q in u.email.lower()
                or any(q in g.lower() for g in u.groups)
            ]
        users.sort(key=lambda u: u.username.lower())
        total = len(users)
        safe_page = max(1, page)
        safe_size = max(1, page_size)
        start = (safe_page - 1) * safe_size
        return users[start : start + safe_size], total

    def search_groups(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryGroup], int]:
        counts: dict[str, int] = {name: 0 for name in self._group_descriptions}
        for seed in self._accounts:
            for grp in seed.groups:
                counts[grp] = counts.get(grp, 0) + 1

        groups = [
            DirectoryGroup(
                name=name,
                description=self._group_descriptions.get(name, f"Gruppe {name}"),
                dn=f"CN={name},OU=Groups,{self.base_dn}",
                member_count=count,
            )
            for name, count in counts.items()
        ]
        q = search.strip().lower()
        if q:
            groups = [
                g
                for g in groups
                if q in g.name.lower() or q in g.description.lower()
            ]
        groups.sort(key=lambda g: g.name.lower())
        total = len(groups)
        safe_page = max(1, page)
        safe_size = max(1, page_size)
        start = (safe_page - 1) * safe_size
        return groups[start : start + safe_size], total
