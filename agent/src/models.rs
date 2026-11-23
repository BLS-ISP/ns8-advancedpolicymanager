use clap::ValueEnum;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum)]
pub enum OsFamily {
    #[serde(rename = "WINDOWS")]
    #[value(name = "WINDOWS", alias = "windows")]
    Windows,
    #[serde(rename = "LINUX")]
    #[value(name = "LINUX", alias = "linux")]
    Linux,
    #[serde(rename = "MACOS")]
    #[value(name = "MACOS", alias = "macos")]
    Macos,
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsFamily::Windows => write!(f, "WINDOWS"),
            OsFamily::Linux => write!(f, "LINUX"),
            OsFamily::Macos => write!(f, "MACOS"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCategory {
    #[serde(rename = "ACCESS")]
    Access,
    #[serde(rename = "WORKSPACE")]
    Workspace,
    #[serde(rename = "SECURITY")]
    Security,
    #[serde(rename = "DESKTOP")]
    Desktop,
    #[serde(rename = "CUSTOM_FINETUNING")]
    CustomFinetuning,
    #[serde(other, rename = "UNKNOWN")]
    Unknown,
}

fn default_category() -> PolicyCategory {
    PolicyCategory::Unknown
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    #[serde(rename = "OVERRIDE")]
    Override,
    #[serde(rename = "APPEND_UNIQUE")]
    AppendUnique,
}

fn default_merge_strategy() -> MergeStrategy {
    MergeStrategy::Override
}

fn default_schema_version() -> u32 {
    1
}

fn default_platforms() -> Vec<OsFamily> {
    vec![OsFamily::Windows, OsFamily::Linux, OsFamily::Macos]
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn default_true() -> bool {
    true
}

fn default_poll_interval() -> u64 {
    120
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default = "default_category")]
    pub category: PolicyCategory,
    pub rule_type: String,
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_platforms")]
    pub platforms: Vec<OsFamily>,
    #[serde(default = "default_merge_strategy")]
    pub merge_strategy: MergeStrategy,
    #[serde(default = "default_empty_object")]
    pub config: serde_json::Value,
}

// ============================================================================
// 1. access.login_access
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginAccessMode {
    #[serde(rename = "ALLOW_ALL")]
    AllowAll,
    #[serde(rename = "ALLOW_LIST")]
    AllowList,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoginAccessConfig {
    pub mode: LoginAccessMode,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub deny_groups: Vec<String>,
}

// ============================================================================
// 2. access.local_admins
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalAdminsConfig {
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub admin_users: Vec<String>,
    #[serde(default)]
    pub passwordless_sudo: bool,
}

// ============================================================================
// 3. workspace.network_shares
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareProtocol {
    #[serde(rename = "SMB")]
    Smb,
    #[serde(rename = "NFS")]
    Nfs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkShareMount {
    pub id: String,
    pub name: String,
    pub protocol: ShareProtocol,
    pub remote_path: String,
    #[serde(default)]
    pub windows_drive_letter: Option<String>,
    #[serde(default)]
    pub unix_mount_path: Option<String>,
    #[serde(default = "default_true")]
    pub reconnect_at_logon: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSharesConfig {
    #[serde(default)]
    pub mounts: Vec<NetworkShareMount>,
}

// ============================================================================
// 4. workspace.printers
// ============================================================================

fn default_driver_model() -> String {
    "everywhere".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrinterItem {
    pub id: String,
    pub name: String,
    pub uri: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default = "default_driver_model")]
    pub driver_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrintersConfig {
    #[serde(default)]
    pub printers: Vec<PrinterItem>,
}

// ============================================================================
// 5. workspace.scripts
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptTrigger {
    #[serde(rename = "LOGON")]
    Logon,
    #[serde(rename = "STARTUP")]
    Startup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptRunAs {
    #[serde(rename = "USER")]
    User,
    #[serde(rename = "SYSTEM")]
    System,
}

fn default_timeout_seconds() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceScriptItem {
    pub id: String,
    pub name: String,
    pub trigger: ScriptTrigger,
    pub run_as: ScriptRunAs,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub windows_powershell: Option<String>,
    #[serde(default)]
    pub linux_bash: Option<String>,
    #[serde(default)]
    pub macos_zsh: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScriptsConfig {
    #[serde(default)]
    pub scripts: Vec<WorkspaceScriptItem>,
}

// ============================================================================
// 6. security.screen_lock
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScreenLockConfig {
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub require_password_on_wake: bool,
    #[serde(default)]
    pub lock_delay_seconds: u64,
}

// ============================================================================
// 7. security.usb_storage
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsbStorageMode {
    #[serde(rename = "ALLOW")]
    Allow,
    #[serde(rename = "READ_ONLY")]
    ReadOnly,
    #[serde(rename = "BLOCK")]
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsbStorageConfig {
    pub mode: UsbStorageMode,
}

// ============================================================================
// 8. security.firewall
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallInboundPolicy {
    #[serde(rename = "BLOCK")]
    Block,
    #[serde(rename = "ALLOW")]
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallConfig {
    pub is_enabled: bool,
    pub default_inbound: FirewallInboundPolicy,
    #[serde(default)]
    pub allow_stealth_mode: bool,
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_udp_ports: Vec<u16>,
}

// ============================================================================
// 9. desktop.browser
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BrowserTarget {
    #[serde(rename = "CHROME")]
    Chrome,
    #[serde(rename = "EDGE")]
    Edge,
    #[serde(rename = "FIREFOX")]
    Firefox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserRestoreMode {
    #[serde(rename = "HOMEPAGE")]
    Homepage,
    #[serde(rename = "LAST_SESSION")]
    LastSession,
}

fn default_restore_mode() -> BrowserRestoreMode {
    BrowserRestoreMode::Homepage
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserConfig {
    #[serde(default)]
    pub targets: Vec<BrowserTarget>,
    #[serde(default)]
    pub homepage_url: Option<String>,
    #[serde(default = "default_restore_mode")]
    pub restore_on_startup: BrowserRestoreMode,
    #[serde(default)]
    pub disable_incognito: bool,
    #[serde(default)]
    pub disable_password_manager: bool,
    #[serde(default)]
    pub force_extensions: Vec<String>,
}

// ============================================================================
// 10. desktop.wallpaper
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WallpaperFitMode {
    #[serde(rename = "FILL")]
    Fill,
    #[serde(rename = "FIT")]
    Fit,
    #[serde(rename = "CENTER")]
    Center,
}

fn default_fit_mode() -> WallpaperFitMode {
    WallpaperFitMode::Fill
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WallpaperConfig {
    pub image_url: String,
    #[serde(default = "default_fit_mode")]
    pub fit_mode: WallpaperFitMode,
    #[serde(default)]
    pub is_locked: bool,
}

// ============================================================================
// 11. desktop.system_restrictions
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemRestrictionsConfig {
    #[serde(default)]
    pub disable_control_panel: bool,
    #[serde(default)]
    pub disable_registry_tools: bool,
    #[serde(default)]
    pub disable_terminal_for_standard_users: bool,
}

// ============================================================================
// 12. custom.raw_setting (v2+ extension hook)
// ============================================================================

fn default_value_type() -> String {
    "STRING".to_string()
}

fn deserialize_string_or_scalar<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let val = serde_json::Value::deserialize(deserializer)?;
    match val {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        serde_json::Value::Null => Ok(String::new()),
        other => Ok(other.to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawSettingItem {
    pub id: String,
    pub target_os: OsFamily,
    pub engine: String,
    pub path: String,
    #[serde(default)]
    pub key: String,
    #[serde(default = "default_value_type")]
    pub value_type: String,
    #[serde(default, deserialize_with = "deserialize_string_or_scalar")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RawSettingConfig {
    #[serde(default)]
    pub items: Vec<RawSettingItem>,
}

// ============================================================================
// Agent HTTP API Payloads (Section 4)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    pub enrollment_token: String,
    pub hostname: String,
    pub os_family: OsFamily,
    pub os_version: String,
    pub arch: String,
    pub agent_version: String,
    pub machine_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub device_id: String,
    pub device_token: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CheckinRequest {
    pub hostname: String,
    pub os_family: OsFamily,
    pub os_version: String,
    pub agent_version: String,
    pub current_user: Option<String>,
    pub applied_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CheckinResponse {
    #[serde(default)]
    pub device_id: String,
    pub bundle_revision: u64,
    #[serde(default)]
    pub state_hash: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default)]
    pub effective_rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceOverallStatus {
    #[serde(rename = "COMPLIANT")]
    Compliant,
    #[serde(rename = "DEGRADED")]
    Degraded,
    #[serde(rename = "ERROR")]
    Error,
}

impl fmt::Display for ComplianceOverallStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceOverallStatus::Compliant => write!(f, "COMPLIANT"),
            ComplianceOverallStatus::Degraded => write!(f, "DEGRADED"),
            ComplianceOverallStatus::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceAction {
    #[serde(rename = "ENFORCED")]
    Enforced,
    #[serde(rename = "ROLLED_BACK")]
    RolledBack,
}

impl fmt::Display for ComplianceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceAction::Enforced => write!(f, "ENFORCED"),
            ComplianceAction::RolledBack => write!(f, "ROLLED_BACK"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceItemStatus {
    #[serde(rename = "APPLIED")]
    Applied,
    #[serde(rename = "SKIPPED_UNSUPPORTED")]
    SkippedUnsupported,
    #[serde(rename = "FAILED")]
    Failed,
}

impl fmt::Display for ComplianceItemStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceItemStatus::Applied => write!(f, "APPLIED"),
            ComplianceItemStatus::SkippedUnsupported => write!(f, "SKIPPED_UNSUPPORTED"),
            ComplianceItemStatus::Failed => write!(f, "FAILED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceItem {
    pub rule_type: String,
    pub action: ComplianceAction,
    pub status: ComplianceItemStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportRequest {
    pub applied_revision: u64,
    pub status: ComplianceOverallStatus,
    pub items: Vec<ComplianceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportResponse {
    #[serde(default)]
    pub acknowledged: bool,
    #[serde(default)]
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorDetail,
}
