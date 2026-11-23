use crate::models::PolicyRule;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const STATE_FILE_NAME: &str = "applied_state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedRegistryValue {
    pub key_path: String,
    pub value_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPlistKey {
    pub domain_or_path: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalKind {
    #[serde(rename = "USER")]
    User,
    #[serde(rename = "GROUP")]
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ManagedPrincipal {
    pub name: String,
    pub kind: PrincipalKind,
    pub target_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedShare {
    pub id: String,
    pub mount_target: String,
    pub remote_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RollbackMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_values: Vec<ManagedRegistryValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plist_keys: Vec<ManagedPlistKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_principals: Vec<ManagedPrincipal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounted_shares: Vec<ManagedShare>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_printers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub firewall_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scheduled_tasks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollback_commands: Vec<ManagedCommand>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedRuleRecord {
    pub rule_type: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub applied_at: String,
    pub config_snapshot: serde_json::Value,
    #[serde(default)]
    pub rollback_metadata: RollbackMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedState {
    pub applied_revision: u64,
    #[serde(default)]
    pub state_hash: String,
    #[serde(default)]
    pub managed_rules: BTreeMap<String, AppliedRuleRecord>,
}

impl AppliedState {
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join(STATE_FILE_NAME)
    }

    pub fn load(state_dir: &Path) -> Result<Self, String> {
        let path = Self::state_path(state_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid JSON in '{}': {}", path.display(), e))
    }

    pub fn save(&self, state_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(state_dir).map_err(|e| {
            format!(
                "Failed to create state directory '{}': {}",
                state_dir.display(),
                e
            )
        })?;
        let path = Self::state_path(state_dir);
        let tmp_path = state_dir.join(format!("{}.tmp", STATE_FILE_NAME));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize applied state: {}", e))?;

        fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Failed to write '{}': {}", tmp_path.display(), e))?;

        fs::rename(&tmp_path, &path)
            .or_else(|_| {
                fs::copy(&tmp_path, &path)?;
                let _ = fs::remove_file(&tmp_path);
                Ok::<(), std::io::Error>(())
            })
            .map_err(|e| format!("Failed to finalize '{}': {}", path.display(), e))?;

        Ok(path)
    }
}

pub fn compute_rules_hash(rules: &[PolicyRule]) -> String {
    let serialized = serde_json::to_vec(rules).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    format!("sha256:{:x}", hasher.finalize())
}
