use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn failure(exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedOp {
    RunCmd {
        program: String,
        args: Vec<String>,
    },
    WriteFile {
        path: String,
        content: String,
        mode: Option<u32>,
    },
    RemoveFile {
        path: String,
    },
    ReadFile {
        path: String,
    },
    SetRegistryValue {
        key_path: String,
        value_name: String,
        value_type: String,
        data: String,
    },
    DeleteRegistryValue {
        key_path: String,
        value_name: String,
    },
    DeleteRegistryKey {
        key_path: String,
    },
    WritePlist {
        domain_or_path: String,
        key: String,
        value_type: String,
        value: String,
    },
    DeletePlistKey {
        domain_or_path: String,
        key: String,
    },
}

/// Injectable operating system abstraction supporting both real OS execution
/// and deterministic dry-run / unit-test simulation.
pub trait SystemRunner: Send + Sync {
    fn run_cmd(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String>;
    fn write_file(&self, path: &str, content: &str, mode: Option<u32>) -> Result<(), String>;
    fn remove_file(&self, path: &str) -> Result<(), String>;
    fn read_file(&self, path: &str) -> Result<Option<String>, String>;
    fn set_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
        value_type: &str,
        data: &str,
    ) -> Result<(), String>;
    fn delete_registry_value(&self, key_path: &str, value_name: &str) -> Result<(), String>;
    fn delete_registry_key(&self, key_path: &str) -> Result<(), String>;
    fn get_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
    ) -> Result<Option<String>, String>;
    fn write_plist(
        &self,
        domain_or_path: &str,
        key: &str,
        value_type: &str,
        value: &str,
    ) -> Result<(), String>;
    fn delete_plist_key(&self, domain_or_path: &str, key: &str) -> Result<(), String>;
}

/// Executes real operating system operations.
#[derive(Debug, Default)]
pub struct RealSystemRunner;

impl RealSystemRunner {
    pub fn new() -> Self {
        Self
    }
}

impl SystemRunner for RealSystemRunner {
    fn run_cmd(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute '{} {}': {}", program, args.join(" "), e))?;

        Ok(CmdOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn write_file(&self, path: &str, content: &str, mode: Option<u32>) -> Result<(), String> {
        let p = Path::new(path);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create dir '{}': {}", parent.display(), e))?;
            }
        }
        fs::write(p, content.as_bytes())
            .map_err(|e| format!("Failed to write file '{}': {}", path, e))?;

        #[cfg(unix)]
        if let Some(m) = mode {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p, fs::Permissions::from_mode(m))
                .map_err(|e| format!("Failed to chmod '{}' to {:o}: {}", path, m, e))?;
        }
        #[cfg(not(unix))]
        let _ = mode;

        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), String> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Failed to remove file '{}': {}", path, e)),
        }
    }

    fn read_file(&self, path: &str) -> Result<Option<String>, String> {
        match fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Failed to read file '{}': {}", path, e)),
        }
    }

    fn set_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
        value_type: &str,
        data: &str,
    ) -> Result<(), String> {
        let out = self.run_cmd(
            "reg",
            &[
                "add",
                key_path,
                "/v",
                value_name,
                "/t",
                value_type,
                "/d",
                data,
                "/f",
            ],
        )?;
        if out.exit_code != 0 {
            return Err(format!(
                "reg add '{}' /v '{}' failed (code {}): {}",
                key_path,
                value_name,
                out.exit_code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    fn delete_registry_value(&self, key_path: &str, value_name: &str) -> Result<(), String> {
        let out = self.run_cmd("reg", &["delete", key_path, "/v", value_name, "/f"])?;
        if out.exit_code != 0 {
            // reg delete returns non-zero if key/value does not exist; treat missing key idempotently
            let combined = format!("{} {}", out.stdout, out.stderr).to_lowercase();
            if combined.contains("unable to find")
                || combined.contains("nicht gefunden")
                || out.exit_code == 1
            {
                return Ok(());
            }
            return Err(format!(
                "reg delete '{}' /v '{}' failed: {}",
                key_path,
                value_name,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    fn delete_registry_key(&self, key_path: &str) -> Result<(), String> {
        let out = self.run_cmd("reg", &["delete", key_path, "/f"])?;
        if out.exit_code != 0 && out.exit_code != 1 {
            return Err(format!(
                "reg delete '{}' failed: {}",
                key_path,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    fn get_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
    ) -> Result<Option<String>, String> {
        let out = self.run_cmd("reg", &["query", key_path, "/v", value_name])?;
        if out.exit_code != 0 {
            return Ok(None);
        }
        for line in out.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(value_name) {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Ok(Some(parts[2..].join(" ")));
                }
            }
        }
        Ok(None)
    }

    fn write_plist(
        &self,
        domain_or_path: &str,
        key: &str,
        value_type: &str,
        value: &str,
    ) -> Result<(), String> {
        let flag = format!("-{}", value_type.trim_start_matches('-'));
        let out = self.run_cmd("defaults", &["write", domain_or_path, key, &flag, value])?;
        if out.exit_code != 0 {
            return Err(format!(
                "defaults write '{}' '{}' failed (code {}): {}",
                domain_or_path,
                key,
                out.exit_code,
                out.stderr.trim()
            ));
        }
        Ok(())
    }

    fn delete_plist_key(&self, domain_or_path: &str, key: &str) -> Result<(), String> {
        let _ = self.run_cmd("defaults", &["delete", domain_or_path, key]);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MockState {
    ops: Vec<RecordedOp>,
    files: BTreeMap<String, String>,
    registry: BTreeMap<(String, String), (String, String)>,
    plists: BTreeMap<(String, String), (String, String)>,
    canned_cmd_outputs: BTreeMap<String, CmdOutput>,
    failing_programs: Vec<String>,
}

/// Records all system operations in memory and simulates file, registry, and plist state
/// for `--dry-run` mode and deterministic unit tests.
#[derive(Debug)]
pub struct DryRunOrMockRunner {
    state: Mutex<MockState>,
    log_operations: bool,
}

pub type MockSystemRunner = DryRunOrMockRunner;

impl Default for DryRunOrMockRunner {
    fn default() -> Self {
        Self::new(false)
    }
}

impl DryRunOrMockRunner {
    pub fn new(log_operations: bool) -> Self {
        Self {
            state: Mutex::new(MockState::default()),
            log_operations,
        }
    }

    pub fn operations(&self) -> Vec<RecordedOp> {
        self.state.lock().unwrap().ops.clone()
    }

    pub fn clear_operations(&self) {
        self.state.lock().unwrap().ops.clear();
    }

    pub fn seed_file(&self, path: impl Into<String>, content: impl Into<String>) {
        self.state
            .lock()
            .unwrap()
            .files
            .insert(path.into(), content.into());
    }

    pub fn get_file(&self, path: &str) -> Option<String> {
        self.state.lock().unwrap().files.get(path).cloned()
    }

    pub fn has_file(&self, path: &str) -> bool {
        self.state.lock().unwrap().files.contains_key(path)
    }

    pub fn seed_registry_value(
        &self,
        key_path: impl Into<String>,
        value_name: impl Into<String>,
        value_type: impl Into<String>,
        data: impl Into<String>,
    ) {
        self.state.lock().unwrap().registry.insert(
            (key_path.into(), value_name.into()),
            (value_type.into(), data.into()),
        );
    }

    pub fn get_registry(&self, key_path: &str, value_name: &str) -> Option<(String, String)> {
        self.state
            .lock()
            .unwrap()
            .registry
            .get(&(key_path.to_string(), value_name.to_string()))
            .cloned()
    }

    pub fn get_plist(&self, domain_or_path: &str, key: &str) -> Option<(String, String)> {
        self.state
            .lock()
            .unwrap()
            .plists
            .get(&(domain_or_path.to_string(), key.to_string()))
            .cloned()
    }

    /// Pre-configure output for a specific command line (`"<program> <arg1> <arg2>"` or `"<program>"`).
    pub fn set_cmd_output(&self, cmd_key: impl Into<String>, output: CmdOutput) {
        self.state
            .lock()
            .unwrap()
            .canned_cmd_outputs
            .insert(cmd_key.into(), output);
    }

    /// Force a program name to fail when invoked (for testing FAILED compliance handling).
    pub fn fail_program(&self, program: impl Into<String>) {
        self.state
            .lock()
            .unwrap()
            .failing_programs
            .push(program.into());
    }
}

impl SystemRunner for DryRunOrMockRunner {
    fn run_cmd(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        if self.log_operations {
            println!("[DRY-RUN] exec: {} {}", program, args.join(" "));
        }
        let mut guard = self.state.lock().unwrap();
        let arg_vec: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        guard.ops.push(RecordedOp::RunCmd {
            program: program.to_string(),
            args: arg_vec,
        });

        if guard.failing_programs.iter().any(|p| p == program) {
            return Err(format!("Simulated execution failure for '{}'", program));
        }

        let full_key = if args.is_empty() {
            program.to_string()
        } else {
            format!("{} {}", program, args.join(" "))
        };

        if let Some(out) = guard.canned_cmd_outputs.get(&full_key).cloned() {
            return Ok(out);
        }
        if let Some(out) = guard.canned_cmd_outputs.get(program).cloned() {
            return Ok(out);
        }

        Ok(CmdOutput::success(""))
    }

    fn write_file(&self, path: &str, content: &str, mode: Option<u32>) -> Result<(), String> {
        if self.log_operations {
            println!(
                "[DRY-RUN] write_file: {} ({} bytes)",
                path,
                content.len()
            );
        }
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::WriteFile {
            path: path.to_string(),
            content: content.to_string(),
            mode,
        });
        guard.files.insert(path.to_string(), content.to_string());
        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), String> {
        if self.log_operations {
            println!("[DRY-RUN] remove_file: {}", path);
        }
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::RemoveFile {
            path: path.to_string(),
        });
        guard.files.remove(path);
        Ok(())
    }

    fn read_file(&self, path: &str) -> Result<Option<String>, String> {
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::ReadFile {
            path: path.to_string(),
        });
        Ok(guard.files.get(path).cloned())
    }

    fn set_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
        value_type: &str,
        data: &str,
    ) -> Result<(), String> {
        if self.log_operations {
            println!(
                "[DRY-RUN] reg set: {}\\{} ({}) = {}",
                key_path, value_name, value_type, data
            );
        }
        let mut guard = self.state.lock().unwrap();
        if guard.failing_programs.iter().any(|p| p == "reg") {
            return Err(format!(
                "Simulated registry write failure for '{}\\{}'",
                key_path, value_name
            ));
        }
        guard.ops.push(RecordedOp::SetRegistryValue {
            key_path: key_path.to_string(),
            value_name: value_name.to_string(),
            value_type: value_type.to_string(),
            data: data.to_string(),
        });
        guard.registry.insert(
            (key_path.to_string(), value_name.to_string()),
            (value_type.to_string(), data.to_string()),
        );
        Ok(())
    }

    fn delete_registry_value(&self, key_path: &str, value_name: &str) -> Result<(), String> {
        if self.log_operations {
            println!("[DRY-RUN] reg delete value: {}\\{}", key_path, value_name);
        }
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::DeleteRegistryValue {
            key_path: key_path.to_string(),
            value_name: value_name.to_string(),
        });
        guard
            .registry
            .remove(&(key_path.to_string(), value_name.to_string()));
        Ok(())
    }

    fn delete_registry_key(&self, key_path: &str) -> Result<(), String> {
        if self.log_operations {
            println!("[DRY-RUN] reg delete key: {}", key_path);
        }
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::DeleteRegistryKey {
            key_path: key_path.to_string(),
        });
        let prefix = format!("{}\\", key_path);
        let keys_to_remove: Vec<(String, String)> = guard
            .registry
            .keys()
            .filter(|(k, _)| k == key_path || k.starts_with(&prefix))
            .cloned()
            .collect();
        for k in keys_to_remove {
            guard.registry.remove(&k);
        }
        Ok(())
    }

    fn get_registry_value(
        &self,
        key_path: &str,
        value_name: &str,
    ) -> Result<Option<String>, String> {
        let guard = self.state.lock().unwrap();
        Ok(guard
            .registry
            .get(&(key_path.to_string(), value_name.to_string()))
            .map(|(_, data)| data.clone()))
    }

    fn write_plist(
        &self,
        domain_or_path: &str,
        key: &str,
        value_type: &str,
        value: &str,
    ) -> Result<(), String> {
        if self.log_operations {
            println!(
                "[DRY-RUN] plist write: {} {} ({}) = {}",
                domain_or_path, key, value_type, value
            );
        }
        let mut guard = self.state.lock().unwrap();
        if guard.failing_programs.iter().any(|p| p == "defaults") {
            return Err(format!(
                "Simulated plist write failure for '{} {}'",
                domain_or_path, key
            ));
        }
        guard.ops.push(RecordedOp::WritePlist {
            domain_or_path: domain_or_path.to_string(),
            key: key.to_string(),
            value_type: value_type.to_string(),
            value: value.to_string(),
        });
        guard.plists.insert(
            (domain_or_path.to_string(), key.to_string()),
            (value_type.to_string(), value.to_string()),
        );
        Ok(())
    }

    fn delete_plist_key(&self, domain_or_path: &str, key: &str) -> Result<(), String> {
        if self.log_operations {
            println!("[DRY-RUN] plist delete: {} {}", domain_or_path, key);
        }
        let mut guard = self.state.lock().unwrap();
        guard.ops.push(RecordedOp::DeletePlistKey {
            domain_or_path: domain_or_path.to_string(),
            key: key.to_string(),
        });
        guard
            .plists
            .remove(&(domain_or_path.to_string(), key.to_string()));
        Ok(())
    }
}
