pub mod linux;
pub mod macos;
pub mod windows;

use crate::models::{
    BrowserConfig, BrowserRestoreMode, ComplianceItemStatus, OsFamily, PolicyRule,
};
use crate::runner::SystemRunner;
use crate::state::{AppliedRuleRecord, RollbackMetadata};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub status: ComplianceItemStatus,
    pub message: String,
    pub rollback_metadata: RollbackMetadata,
}

impl ApplyOutcome {
    pub fn applied(message: impl Into<String>, rollback_metadata: RollbackMetadata) -> Self {
        Self {
            status: ComplianceItemStatus::Applied,
            message: message.into(),
            rollback_metadata,
        }
    }

    pub fn skipped(message: impl Into<String>) -> Self {
        Self {
            status: ComplianceItemStatus::SkippedUnsupported,
            message: message.into(),
            rollback_metadata: RollbackMetadata::default(),
        }
    }
}

pub trait PlatformEnforcer: Send + Sync {
    fn os_family(&self) -> OsFamily;

    fn apply(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String>;

    fn rollback(
        &self,
        record: &AppliedRuleRecord,
        runner: &dyn SystemRunner,
    ) -> Result<String, String>;
}

pub fn enforcer_for_os(os_family: OsFamily) -> Box<dyn PlatformEnforcer> {
    match os_family {
        OsFamily::Windows => Box::new(windows::WindowsEnforcer::new()),
        OsFamily::Linux => Box::new(linux::LinuxEnforcer::new()),
        OsFamily::Macos => Box::new(macos::MacOsEnforcer::new()),
    }
}

/// Sanitizes an arbitrary ID/name for safe use in file paths, task names, and rule identifiers.
pub fn sanitize_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "item".to_string()
    } else {
        cleaned
    }
}

/// Applies generic rollback actions captured in `RollbackMetadata` (files, registry keys/values,
/// plist keys, and explicit rollback commands).
pub fn execute_metadata_cleanup(
    meta: &RollbackMetadata,
    runner: &dyn SystemRunner,
) -> Result<(), String> {
    for reg_val in &meta.registry_values {
        if let (Some(rtype), Some(rdata)) = (&reg_val.restore_type, &reg_val.restore_data) {
            runner.set_registry_value(&reg_val.key_path, &reg_val.value_name, rtype, rdata)?;
        } else {
            runner.delete_registry_value(&reg_val.key_path, &reg_val.value_name)?;
        }
    }

    for reg_key in &meta.registry_keys {
        runner.delete_registry_key(reg_key)?;
    }

    for plist in &meta.plist_keys {
        runner.delete_plist_key(&plist.domain_or_path, &plist.key)?;
    }

    for file_path in &meta.managed_files {
        runner.remove_file(file_path)?;
    }

    for cmd in &meta.rollback_commands {
        let arg_refs: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let _ = runner.run_cmd(&cmd.program, &arg_refs)?;
    }

    Ok(())
}

/// Builds Chromium/Edge managed JSON policy content (`chrome` / `edge` on Linux).
pub fn build_chromium_policy_json(cfg: &BrowserConfig) -> String {
    let mut map = Map::new();
    if let Some(url) = &cfg.homepage_url {
        if !url.trim().is_empty() {
            map.insert("HomepageLocation".to_string(), json!(url));
            map.insert("HomepageIsNewTabPage".to_string(), json!(false));
            if cfg.restore_on_startup == BrowserRestoreMode::Homepage {
                map.insert("RestoreOnStartupURLs".to_string(), json!([url]));
            }
        }
    }
    let startup_code = match cfg.restore_on_startup {
        BrowserRestoreMode::Homepage => 4,
        BrowserRestoreMode::LastSession => 1,
    };
    map.insert("RestoreOnStartup".to_string(), json!(startup_code));
    map.insert(
        "IncognitoModeAvailability".to_string(),
        json!(if cfg.disable_incognito { 1 } else { 0 }),
    );
    map.insert(
        "PasswordManagerEnabled".to_string(),
        json!(!cfg.disable_password_manager),
    );
    if !cfg.force_extensions.is_empty() {
        map.insert(
            "ExtensionInstallForcelist".to_string(),
            json!(cfg.force_extensions),
        );
    }
    serde_json::to_string_pretty(&Value::Object(map)).unwrap_or_else(|_| "{}".to_string())
}

/// Builds Mozilla Firefox enterprise `policies.json` content (Windows, Linux, macOS).
pub fn build_firefox_policies_json(cfg: &BrowserConfig) -> String {
    let mut policies = Map::new();
    if let Some(url) = &cfg.homepage_url {
        if !url.trim().is_empty() {
            let start_page = match cfg.restore_on_startup {
                BrowserRestoreMode::Homepage => "homepage",
                BrowserRestoreMode::LastSession => "previous-session",
            };
            policies.insert(
                "Homepage".to_string(),
                json!({
                    "URL": url,
                    "Locked": true,
                    "StartPage": start_page
                }),
            );
        }
    }
    policies.insert(
        "DisablePrivateBrowsing".to_string(),
        json!(cfg.disable_incognito),
    );
    policies.insert(
        "OfferToSaveLogins".to_string(),
        json!(!cfg.disable_password_manager),
    );
    policies.insert(
        "PasswordManagerEnabled".to_string(),
        json!(!cfg.disable_password_manager),
    );
    if !cfg.force_extensions.is_empty() {
        policies.insert("Extensions".to_string(), json!({ "Install": cfg.force_extensions }));
    }
    serde_json::to_string_pretty(&json!({ "policies": policies }))
        .unwrap_or_else(|_| "{\"policies\":{}}".to_string())
}

pub fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
