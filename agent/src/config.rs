use crate::models::OsFamily;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CONFIG_FILE_NAME: &str = "agent_config.json";
pub const MACHINE_ID_FILE_NAME: &str = "machine_id";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfig {
    pub server_url: String,
    pub device_id: String,
    pub device_token: String,
    pub poll_interval_seconds: u64,
    pub hostname: String,
    pub os_family: OsFamily,
}

impl AgentConfig {
    pub fn config_path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_FILE_NAME)
    }

    pub fn load(state_dir: &Path) -> Result<Self, String> {
        let path = Self::config_path(state_dir);
        let raw = fs::read_to_string(&path).map_err(|e| {
            format!(
                "Failed to read agent configuration at '{}' (is this device enrolled?): {}",
                path.display(),
                e
            )
        })?;
        serde_json::from_str(&raw).map_err(|e| {
            format!(
                "Invalid JSON in agent configuration '{}': {}",
                path.display(),
                e
            )
        })
    }

    pub fn save(&self, state_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(state_dir).map_err(|e| {
            format!(
                "Failed to create state directory '{}': {}",
                state_dir.display(),
                e
            )
        })?;
        let path = Self::config_path(state_dir);
        let tmp_path = state_dir.join(format!("{}.tmp", CONFIG_FILE_NAME));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize agent configuration: {}", e))?;

        fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Failed to write '{}': {}", tmp_path.display(), e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&tmp_path, &path).or_else(|_| {
            fs::copy(&tmp_path, &path)?;
            let _ = fs::remove_file(&tmp_path);
            Ok::<(), std::io::Error>(())
        }).map_err(|e| format!("Failed to finalize '{}': {}", path.display(), e))?;

        Ok(path)
    }
}

pub fn normalize_server_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

pub fn default_state_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("APM_AGENT_STATE_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\ProgramData\NS8PolicyAgent")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/NS8PolicyAgent")
    } else {
        PathBuf::from("/var/lib/ns8-policy-agent")
    }
}

pub fn detect_os_family() -> OsFamily {
    if cfg!(target_os = "windows") {
        OsFamily::Windows
    } else if cfg!(target_os = "macos") {
        OsFamily::Macos
    } else {
        OsFamily::Linux
    }
}

pub fn detect_arch() -> String {
    std::env::consts::ARCH.to_string()
}

pub fn detect_hostname() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Ok(etc_hostname) = fs::read_to_string("/etc/hostname") {
        let trimmed = etc_hostname.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(out) = Command::new("hostname").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "unknown-host".to_string()
}

pub fn detect_os_version(os_family: OsFamily) -> String {
    match os_family {
        OsFamily::Linux => {
            if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
                for line in os_release.lines() {
                    if let Some(rest) = line.strip_prefix("PRETTY_NAME=") {
                        let cleaned = rest.trim().trim_matches('"').to_string();
                        if !cleaned.is_empty() {
                            return cleaned;
                        }
                    }
                }
            }
            "Linux".to_string()
        }
        OsFamily::Macos => {
            if cfg!(target_os = "macos") {
                if let Ok(out) = Command::new("sw_vers").arg("-productVersion").output() {
                    if out.status.success() {
                        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if !ver.is_empty() {
                            return format!("macOS {}", ver);
                        }
                    }
                }
            }
            "macOS 15".to_string()
        }
        OsFamily::Windows => {
            if cfg!(target_os = "windows") {
                if let Ok(out) = Command::new("cmd").args(["/C", "ver"]).output() {
                    if out.status.success() {
                        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if !ver.is_empty() {
                            return ver;
                        }
                    }
                }
            }
            "Windows 11".to_string()
        }
    }
}

pub fn detect_current_user() -> Option<String> {
    for var in ["SUDO_USER", "USER", "USERNAME", "LOGNAME"] {
        if let Ok(val) = std::env::var(var) {
            let trimmed = val.trim();
            if !trimmed.is_empty()
                && !trimmed.eq_ignore_ascii_case("SYSTEM")
                && !trimmed.eq_ignore_ascii_case("root")
                && !trimmed.ends_with('$')
            {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub fn load_or_create_machine_id(state_dir: &Path, hostname: &str) -> String {
    let persisted = state_dir.join(MACHINE_ID_FILE_NAME);
    if let Ok(existing) = fs::read_to_string(&persisted) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    for sys_path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(id) = fs::read_to_string(sys_path) {
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                let _ = fs::create_dir_all(state_dir);
                let _ = fs::write(&persisted, trimmed);
                return trimmed.to_string();
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b":");
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(b":");
    hasher.update(std::env::consts::ARCH.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    let generated = format!("hw-{}", &hex[..24]);

    let _ = fs::create_dir_all(state_dir);
    let _ = fs::write(&persisted, &generated);
    generated
}
