"""Directory provider abstractions for Samba AD, OpenLDAP, and mock environments."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class DirectoryUnavailableError(Exception):
    """Raised when the configured LDAP/AD directory cannot be reached."""


@dataclass(frozen=True)
class DirectoryUser:
    username: str
    display_name: str
    email: str
    dn: str
    groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "displayName": self.display_name,
            "email": self.email,
            "dn": self.dn,
            "groups": list(self.groups),
        }


@dataclass(frozen=True)
class DirectoryGroup:
    name: str
    description: str
    dn: str
    member_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "dn": self.dn,
            "memberCount": self.member_count,
        }


def normalize_login_username(raw_username: str) -> str:
    """Normalize `DOMAIN\\user` or `user@domain` inputs down to canonical account name when needed."""
    cleaned = raw_username.strip()
    if "\\" in cleaned:
        cleaned = cleaned.split("\\", 1)[1].strip()
    return cleaned


class DirectoryProvider(ABC):
    """Interface implemented by Ldap3DirectoryProvider and InMemoryDirectoryProvider."""

    @abstractmethod
    def authenticate(self, username: str, password: str) -> DirectoryUser | None:
        """Verify credentials against the directory and return resolved user + groups, or None."""

    @abstractmethod
    def get_user(self, username: str) -> DirectoryUser | None:
        """Fetch a single directory user by username/UPN, or None if not found."""

    def get_user_groups(self, username: str) -> list[str]:
        """Return group names for username, or empty list if user is unknown."""
        user = self.get_user(username)
        return list(user.groups) if user is not None else []

    @abstractmethod
    def search_users(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryUser], int]:
        """Search directory users with pagination."""

    @abstractmethod
    def search_groups(
        self,
        search: str = "",
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DirectoryGroup], int]:
        """Search directory groups with pagination."""
