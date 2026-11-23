"""Typed policy schema registry for all 11 v1 ruleTypes + custom.raw_setting v2 hook."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.errors import ApiError

OsFamily = Literal["WINDOWS", "LINUX", "MACOS"]
PolicyCategory = Literal[
    "ACCESS",
    "WORKSPACE",
    "SECURITY",
    "DESKTOP",
    "CUSTOM_FINETUNING",
]
MergeStrategy = Literal["OVERRIDE", "APPEND_UNIQUE"]

ALL_PLATFORMS: list[OsFamily] = ["WINDOWS", "LINUX", "MACOS"]
ALL_CATEGORIES: list[PolicyCategory] = [
    "ACCESS",
    "WORKSPACE",
    "SECURITY",
    "DESKTOP",
    "CUSTOM_FINETUNING",
]


def _none_to_empty_str(val: Any) -> Any:
    return "" if val is None else val


def _check_unique_ids(items: list[Any], field_label: str) -> list[Any]:
    seen: set[str] = set()
    for item in items:
        item_id = getattr(item, "id", "")
        if item_id in seen:
            raise ValueError(f"Doppelte Element-ID '{item_id}' in {field_label}")
        seen.add(item_id)
    return items


# --- 1. access.login_access ---
class LoginAccessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["ALLOW_ALL", "ALLOW_LIST"] = "ALLOW_LIST"
    allowedGroups: list[str] = Field(default_factory=list)
    allowedUsers: list[str] = Field(default_factory=list)
    denyGroups: list[str] = Field(default_factory=list)


# --- 2. access.local_admins ---
class LocalAdminsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adminGroups: list[str] = Field(default_factory=list)
    adminUsers: list[str] = Field(default_factory=list)
    passwordlessSudo: bool = False


# --- 3. workspace.network_shares ---
class NetworkShareMount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    protocol: Literal["SMB", "NFS"] = "SMB"
    remotePath: str = Field(min_length=1, max_length=512)
    windowsDriveLetter: str = Field(default="", max_length=16)
    unixMountPath: str = Field(default="", max_length=512)
    reconnectAtLogon: bool = True

    @field_validator("windowsDriveLetter", "unixMountPath", mode="before")
    @classmethod
    def _coerce_null_paths(cls, v: Any) -> Any:
        return _none_to_empty_str(v)


class NetworkSharesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mounts: list[NetworkShareMount] = Field(default_factory=list)

    @field_validator("mounts")
    @classmethod
    def _unique_mount_ids(cls, v: list[NetworkShareMount]) -> list[NetworkShareMount]:
        return _check_unique_ids(v, "mounts")


# --- 4. workspace.printers ---
class PrinterItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    uri: str = Field(min_length=1, max_length=512)
    isDefault: bool = False
    driverModel: str = Field(default="everywhere", min_length=1, max_length=128)


class PrintersConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    printers: list[PrinterItem] = Field(default_factory=list)

    @field_validator("printers")
    @classmethod
    def _unique_printer_ids(cls, v: list[PrinterItem]) -> list[PrinterItem]:
        return _check_unique_ids(v, "printers")


# --- 5. workspace.scripts ---
class ScriptItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    trigger: Literal["LOGON", "STARTUP"] = "LOGON"
    runAs: Literal["USER", "SYSTEM"] = "USER"
    timeoutSeconds: int = Field(default=60, ge=1, le=3600)
    windowsPowershell: str = Field(default="", max_length=32768)
    linuxBash: str = Field(default="", max_length=32768)
    macosZsh: str = Field(default="", max_length=32768)

    @field_validator("windowsPowershell", "linuxBash", "macosZsh", mode="before")
    @classmethod
    def _coerce_null_scripts(cls, v: Any) -> Any:
        return _none_to_empty_str(v)


class ScriptsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scripts: list[ScriptItem] = Field(default_factory=list)

    @field_validator("scripts")
    @classmethod
    def _unique_script_ids(cls, v: list[ScriptItem]) -> list[ScriptItem]:
        return _check_unique_ids(v, "scripts")


# --- 6. security.screen_lock ---
class ScreenLockConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idleTimeoutSeconds: int = Field(default=300, ge=15, le=86400)
    requirePasswordOnWake: bool = True
    lockDelaySeconds: int = Field(default=5, ge=0, le=3600)


# --- 7. security.usb_storage ---
class UsbStorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["ALLOW", "READ_ONLY", "BLOCK"]


# --- 8. security.firewall ---
PortNumber = Annotated[int, Field(ge=1, le=65535)]


class FirewallConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    isEnabled: bool = True
    defaultInbound: Literal["BLOCK", "ALLOW"] = "BLOCK"
    allowStealthMode: bool = True
    allowedTcpPorts: list[PortNumber] = Field(default_factory=list)
    allowedUdpPorts: list[PortNumber] = Field(default_factory=list)


# --- 9. desktop.browser ---
BrowserTarget = Literal["CHROME", "EDGE", "FIREFOX"]


class BrowserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[BrowserTarget] = Field(
        default_factory=lambda: ["CHROME", "EDGE", "FIREFOX"],
        min_length=1,
    )
    homepageUrl: str = Field(default="", max_length=1024)
    restoreOnStartup: Literal["HOMEPAGE", "LAST_SESSION"] = "HOMEPAGE"
    disableIncognito: bool = False
    disablePasswordManager: bool = False
    forceExtensions: list[str] = Field(default_factory=list)


# --- 10. desktop.wallpaper ---
class WallpaperConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    imageUrl: str = Field(min_length=1, max_length=2048)
    fitMode: Literal["FILL", "FIT", "CENTER"] = "FILL"
    isLocked: bool = True


# --- 11. desktop.system_restrictions ---
class SystemRestrictionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disableControlPanel: bool = False
    disableRegistryTools: bool = False
    disableTerminalForStandardUsers: bool = False


# --- 12. custom.raw_setting (v2+ extension hook) ---
class RawSettingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    targetOs: OsFamily
    engine: Literal["REGISTRY", "DCONF", "SYSCTL", "PLIST", "DEFAULTS", "FILE", "COMMAND"]
    path: str = Field(min_length=1, max_length=1024)
    key: str = Field(min_length=1, max_length=512)
    valueType: Literal["STRING", "INT", "BOOL", "JSON", "DWORD"] = "STRING"
    value: str = Field(max_length=16384)


class CustomRawSettingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RawSettingItem] = Field(default_factory=list)

    @field_validator("items")
    @classmethod
    def _unique_raw_ids(cls, v: list[RawSettingItem]) -> list[RawSettingItem]:
        return _check_unique_ids(v, "items")


@dataclass(frozen=True)
class RuleTypeDefinition:
    rule_type: str
    category: PolicyCategory
    title: str
    description: str
    schema_version: int
    supported_platforms: list[OsFamily]
    default_merge_strategy: MergeStrategy
    config_model: type[BaseModel]
    default_config: dict[str, Any]
    is_extension_hook: bool = False

    def to_catalog_entry(self) -> dict[str, Any]:
        return {
            "ruleType": self.rule_type,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "schemaVersion": self.schema_version,
            "supportedPlatforms": list(self.supported_platforms),
            "defaultMergeStrategy": self.default_merge_strategy,
            "isExtensionHook": self.is_extension_hook,
            "defaultConfig": self.default_config,
            "jsonSchema": self.config_model.model_json_schema(),
        }


RULE_REGISTRY: dict[str, RuleTypeDefinition] = {
    "access.login_access": RuleTypeDefinition(
        rule_type="access.login_access",
        category="ACCESS",
        title="Anmeldezugriff steuern",
        description="Legt fest, welche AD/LDAP-Benutzer und Gruppen sich am Computer anmelden dürfen.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=LoginAccessConfig,
        default_config={
            "mode": "ALLOW_LIST",
            "allowedGroups": [],
            "allowedUsers": [],
            "denyGroups": [],
        },
    ),
    "access.local_admins": RuleTypeDefinition(
        rule_type="access.local_admins",
        category="ACCESS",
        title="Lokale Administratoren",
        description="Verwaltet zusätzliche lokale Admin-/Sudo-Berechtigungen mit chirurgischem Rollback.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="APPEND_UNIQUE",
        config_model=LocalAdminsConfig,
        default_config={
            "adminGroups": [],
            "adminUsers": [],
            "passwordlessSudo": False,
        },
    ),
    "workspace.network_shares": RuleTypeDefinition(
        rule_type="workspace.network_shares",
        category="WORKSPACE",
        title="Netzlaufwerke (SMB / NFS)",
        description="Verbindet automatisch Datei-Freigaben unter Windows, Linux und macOS.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="APPEND_UNIQUE",
        config_model=NetworkSharesConfig,
        default_config={"mounts": []},
    ),
    "workspace.printers": RuleTypeDefinition(
        rule_type="workspace.printers",
        category="WORKSPACE",
        title="Netzwerkdrucker",
        description="Richtet IPP/Netzwerkdrucker und Standarddrucker plattformübergreifend ein.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="APPEND_UNIQUE",
        config_model=PrintersConfig,
        default_config={"printers": []},
    ),
    "workspace.scripts": RuleTypeDefinition(
        rule_type="workspace.scripts",
        category="WORKSPACE",
        title="Anmelde- & Startskripte",
        description="Führt PowerShell-, Bash- oder Zsh-Skripte beim Systemstart oder Login aus.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="APPEND_UNIQUE",
        config_model=ScriptsConfig,
        default_config={"scripts": []},
    ),
    "security.screen_lock": RuleTypeDefinition(
        rule_type="security.screen_lock",
        category="SECURITY",
        title="Automatische Bildschirmsperre",
        description="Erzwingt Leerlauf-Timeout und Passwortabfrage nach dem Aufwachen.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=ScreenLockConfig,
        default_config={
            "idleTimeoutSeconds": 300,
            "requirePasswordOnWake": True,
            "lockDelaySeconds": 5,
        },
    ),
    "security.usb_storage": RuleTypeDefinition(
        rule_type="security.usb_storage",
        category="SECURITY",
        title="USB-Wechseldatenträger",
        description="Erlaubt, beschränkt auf Lesezugriff oder blockiert USB-Massenspeicher.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=UsbStorageConfig,
        default_config={"mode": "BLOCK"},
    ),
    "security.firewall": RuleTypeDefinition(
        rule_type="security.firewall",
        category="SECURITY",
        title="Host-Firewall",
        description="Aktiviert die lokale Betriebssystem-Firewall und steuert eingehende Portfreigaben.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=FirewallConfig,
        default_config={
            "isEnabled": True,
            "defaultInbound": "BLOCK",
            "allowStealthMode": True,
            "allowedTcpPorts": [],
            "allowedUdpPorts": [],
        },
    ),
    "desktop.browser": RuleTypeDefinition(
        rule_type="desktop.browser",
        category="DESKTOP",
        title="Browser-Vorgaben",
        description="Verwaltet Startseite, Inkognito-Modus, Passwortmanager und Erweiterungen.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=BrowserConfig,
        default_config={
            "targets": ["CHROME", "EDGE", "FIREFOX"],
            "homepageUrl": "https://intranet.firma.local",
            "restoreOnStartup": "HOMEPAGE",
            "disableIncognito": False,
            "disablePasswordManager": False,
            "forceExtensions": [],
        },
    ),
    "desktop.wallpaper": RuleTypeDefinition(
        rule_type="desktop.wallpaper",
        category="DESKTOP",
        title="Hintergrundbild",
        description="Setzt und sperrt ein einheitliches Unternehmens-Hintergrundbild.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=WallpaperConfig,
        default_config={
            "imageUrl": "https://intranet.firma.local/wallpaper.jpg",
            "fitMode": "FILL",
            "isLocked": True,
        },
    ),
    "desktop.system_restrictions": RuleTypeDefinition(
        rule_type="desktop.system_restrictions",
        category="DESKTOP",
        title="System-Einschränkungen",
        description="Sperrt Systemeinstellungen, Registry-Werkzeuge oder Terminal für Standardbenutzer.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="OVERRIDE",
        config_model=SystemRestrictionsConfig,
        default_config={
            "disableControlPanel": False,
            "disableRegistryTools": False,
            "disableTerminalForStandardUsers": False,
        },
    ),
    "custom.raw_setting": RuleTypeDefinition(
        rule_type="custom.raw_setting",
        category="CUSTOM_FINETUNING",
        title="Experten-Finetuning (v2 Hook)",
        description="Direkte Registry-, dconf-, sysctl- oder plist-Schlüssel für Spezialfälle.",
        schema_version=1,
        supported_platforms=list(ALL_PLATFORMS),
        default_merge_strategy="APPEND_UNIQUE",
        config_model=CustomRawSettingConfig,
        default_config={"items": []},
        is_extension_hook=True,
    ),
}


class PolicyRuleModel(BaseModel):
    """Strict PolicyRule validator matching Section 3 of the API contract."""

    model_config = ConfigDict(extra="forbid")

    ruleId: str = Field(default="", max_length=128)
    category: PolicyCategory | None = None
    ruleType: str = Field(min_length=1, max_length=128)
    schemaVersion: int = Field(default=1, ge=1)
    platforms: list[OsFamily] = Field(default_factory=lambda: list(ALL_PLATFORMS), min_length=1)
    mergeStrategy: MergeStrategy | None = None
    config: dict[str, Any]

    @model_validator(mode="after")
    def _validate_against_registry(self) -> "PolicyRuleModel":
        spec = RULE_REGISTRY.get(self.ruleType)
        if spec is None:
            raise ValueError(
                f"Unbekannter ruleType '{self.ruleType}'. Erlaubt: {', '.join(RULE_REGISTRY.keys())}"
            )

        if self.category is None:
            self.category = spec.category
        elif self.category != spec.category:
            raise ValueError(
                f"Kategorie '{self.category}' passt nicht zu '{self.ruleType}' (erwartet: '{spec.category}')"
            )

        if self.schemaVersion != spec.schema_version:
            raise ValueError(
                f"Nicht unterstützte schemaVersion {self.schemaVersion} für '{self.ruleType}' (erwartet: {spec.schema_version})"
            )

        if self.mergeStrategy is None:
            self.mergeStrategy = spec.default_merge_strategy

        if not self.ruleId or not self.ruleId.strip():
            self.ruleId = f"rule-{self.ruleType.replace('.', '-')}"
        else:
            self.ruleId = self.ruleId.strip()

        # Deduplicate platforms while preserving order
        deduped_platforms: list[OsFamily] = []
        for p in self.platforms:
            if p not in deduped_platforms:
                deduped_platforms.append(p)
        self.platforms = deduped_platforms

        validated_cfg = spec.config_model.model_validate(self.config)
        self.config = validated_cfg.model_dump(mode="json")
        return self


def validate_policy_rule(raw_rule: dict[str, Any] | PolicyRuleModel) -> dict[str, Any]:
    """Validate a single PolicyRule and return canonical camelCase dictionary."""
    try:
        model = (
            raw_rule
            if isinstance(raw_rule, PolicyRuleModel)
            else PolicyRuleModel.model_validate(raw_rule)
        )
        return model.model_dump(mode="json")
    except ValidationError as exc:
        raise ApiError(
            422,
            "VALIDATION_ERROR",
            f"Ungültige Regelkonfiguration: {exc.errors()[0].get('msg', 'Validierungsfehler')}",
            details=exc.errors(include_url=False),
        ) from exc


def validate_policy_rules(raw_rules: list[dict[str, Any] | PolicyRuleModel]) -> list[dict[str, Any]]:
    """Validate a list of PolicyRule objects and ensure ruleId uniqueness within the policy."""
    validated: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    for idx, raw in enumerate(raw_rules):
        rule_dict = validate_policy_rule(raw)
        rid = rule_dict["ruleId"]
        if rid in seen_rule_ids:
            # Disambiguate auto-generated IDs only if omitted, otherwise raise validation error
            raw_id = raw.ruleId if isinstance(raw, PolicyRuleModel) else str(raw.get("ruleId", ""))
            if raw_id.strip():
                raise ApiError(
                    422,
                    "VALIDATION_ERROR",
                    f"Doppelte ruleId '{rid}' innerhalb derselben Richtlinie (Index {idx})",
                )
            rid = f"{rid}-{idx + 1}"
            rule_dict["ruleId"] = rid
        seen_rule_ids.add(rid)
        validated.append(rule_dict)
    return validated
