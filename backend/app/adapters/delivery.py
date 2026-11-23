"""Policy Delivery Adapters (`AGENT_PULL` v1 active + `SAMBA_SYSVOL` & `MOBILE_MDM` v2 hooks)."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any


def compute_effective_state_hash(effective_rules: list[dict[str, Any]]) -> str:
    """Compute deterministic sha256:<hex> hash over canonical effective rules JSON."""
    canonical = json.dumps(effective_rules, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class PolicyDeliveryAdapter(ABC):
    """Base interface for consuming the resolved platform-neutral Effective Policy Tree."""

    adapter_id: str
    name: str
    status: str  # "ACTIVE" | "PLANNED_V2"
    supported_platforms: list[str]
    description: str

    def to_catalog_entry(self) -> dict[str, Any]:
        return {
            "id": self.adapter_id,
            "adapterId": self.adapter_id,
            "name": self.name,
            "status": self.status,
            "supportedPlatforms": list(self.supported_platforms),
            "description": self.description,
        }

    @abstractmethod
    def render_delivery_artifact(
        self,
        *,
        device_id: str,
        bundle_revision: int,
        effective_rules: list[dict[str, Any]],
        poll_interval_seconds: int = 120,
    ) -> dict[str, Any]:
        """Translate resolved effective rules into adapter-specific delivery payload."""


class AgentBundleDeliveryAdapter(PolicyDeliveryAdapter):
    """Active v1 pull-bundle adapter consumed by `ns8-policy-agent` on `/api/v1/agent/checkin`."""

    adapter_id = "AGENT_PULL"
    name = "Cross-Platform Policy Agent"
    status = "ACTIVE"
    supported_platforms = ["WINDOWS", "LINUX", "MACOS"]
    description = (
        "Pull-basierte Desired-State-Auslieferung inkl. chirurgischem Rollback für Windows, Linux und macOS."
    )

    def render_delivery_artifact(
        self,
        *,
        device_id: str,
        bundle_revision: int,
        effective_rules: list[dict[str, Any]],
        poll_interval_seconds: int = 120,
    ) -> dict[str, Any]:
        return {
            "deviceId": device_id,
            "bundleRevision": bundle_revision,
            "stateHash": compute_effective_state_hash(effective_rules),
            "pollIntervalSeconds": poll_interval_seconds,
            "effectiveRules": effective_rules,
        }


class SambaSysvolExporterAdapter(PolicyDeliveryAdapter):
    """Architectural v2 extension hook for exporting Effective Policies to Samba AD SYSVOL GPOs."""

    adapter_id = "SAMBA_SYSVOL"
    name = "Samba AD SYSVOL / GPO Exporter"
    status = "PLANNED_V2"
    supported_platforms = ["WINDOWS"]
    description = (
        "Vorbereiteter v2-Adapter zur Projektion aufgelöster Richtlinien in Samba AD SYSVOL (Registry.pol / GPT)."
    )

    def render_delivery_artifact(
        self,
        *,
        device_id: str,
        bundle_revision: int,
        effective_rules: list[dict[str, Any]],
        poll_interval_seconds: int = 120,
    ) -> dict[str, Any]:
        return {
            "adapterId": self.adapter_id,
            "status": self.status,
            "targetId": device_id,
            "gptVersion": bundle_revision,
            "stateHash": compute_effective_state_hash(effective_rules),
            "gpoRuleCount": len(effective_rules),
            "rules": effective_rules,
        }


class MobileMdmProfileAdapter(PolicyDeliveryAdapter):
    """Architectural v2 extension hook for Apple Declarative MDM / Mobileconfig profiles."""

    adapter_id = "MOBILE_MDM"
    name = "Mobile MDM Profile Adapter"
    status = "PLANNED_V2"
    supported_platforms = ["MACOS"]
    description = (
        "Vorbereiteter v2-Adapter für signierte Apple ConfigurationProfiles (.mobileconfig) und MDM-Kanäle."
    )

    def render_delivery_artifact(
        self,
        *,
        device_id: str,
        bundle_revision: int,
        effective_rules: list[dict[str, Any]],
        poll_interval_seconds: int = 120,
    ) -> dict[str, Any]:
        return {
            "adapterId": self.adapter_id,
            "status": self.status,
            "payloadIdentifier": f"org.nethserver.apm.profile.{device_id}",
            "payloadVersion": bundle_revision,
            "stateHash": compute_effective_state_hash(effective_rules),
            "payloadContent": effective_rules,
        }


DELIVERY_ADAPTERS: list[PolicyDeliveryAdapter] = [
    AgentBundleDeliveryAdapter(),
    SambaSysvolExporterAdapter(),
    MobileMdmProfileAdapter(),
]
