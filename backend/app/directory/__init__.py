"""Factory and exports for directory providers."""

from __future__ import annotations

from app.config import Settings
from app.directory.base import (
    DirectoryGroup,
    DirectoryProvider,
    DirectoryUnavailableError,
    DirectoryUser,
)
from app.directory.ldap_provider import Ldap3DirectoryProvider
from app.directory.mock_provider import InMemoryDirectoryProvider


def build_directory_provider(settings: Settings) -> DirectoryProvider:
    if settings.ldap_mode == "mock":
        return InMemoryDirectoryProvider(
            domain=settings.ldap_domain,
            base_dn=settings.ldap_base_dn,
        )
    return Ldap3DirectoryProvider(
        host=settings.ldap_host,
        port=settings.ldap_port,
        schema=settings.ldap_schema,
        base_dn=settings.ldap_base_dn,
        bind_dn=settings.ldap_bind_dn,
        bind_password=settings.ldap_bind_password,
        use_tls=settings.ldap_tls,
        domain=settings.ldap_domain,
    )


__all__ = [
    "DirectoryGroup",
    "DirectoryProvider",
    "DirectoryUnavailableError",
    "DirectoryUser",
    "InMemoryDirectoryProvider",
    "Ldap3DirectoryProvider",
    "build_directory_provider",
]
