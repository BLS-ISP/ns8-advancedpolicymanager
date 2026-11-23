use crate::enforcers::{
    build_firefox_policies_json, execute_metadata_cleanup, sanitize_id, ApplyOutcome,
    PlatformEnforcer,
};
use crate::models::{
    BrowserConfig, BrowserRestoreMode, BrowserTarget, FirewallConfig, FirewallInboundPolicy,
    LocalAdminsConfig, LoginAccessConfig, LoginAccessMode, NetworkSharesConfig, OsFamily,
    PolicyRule, PrintersConfig, RawSettingConfig, ScreenLockConfig, ScriptRunAs, ScriptTrigger,
    ScriptsConfig, SystemRestrictionsConfig, UsbStorageConfig, UsbStorageMode, WallpaperConfig,
    WallpaperFitMode,
};
use crate::runner::SystemRunner;
use crate::state::{
    AppliedRuleRecord, ManagedPrincipal, ManagedRegistryValue, ManagedShare, PrincipalKind,
    RollbackMetadata,
};
use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub struct WindowsEnforcer;

impl WindowsEnforcer {
    pub fn new() -> Self {
        Self
    }

    fn set_tracked_reg(
        runner: &dyn SystemRunner,
        meta: &mut RollbackMetadata,
        key_path: &str,
        value_name: &str,
        value_type: &str,
        data: &str,
    ) -> Result<(), String> {
        runner.set_registry_value(key_path, value_name, value_type, data)?;
        meta.registry_values.push(ManagedRegistryValue {
            key_path: key_path.to_string(),
            value_name: value_name.to_string(),
            restore_type: None,
            restore_data: None,
        });
        Ok(())
    }

    fn write_tracked_file(
        runner: &dyn SystemRunner,
        meta: &mut RollbackMetadata,
        path: &str,
        content: &str,
    ) -> Result<(), String> {
        runner.write_file(path, content, None)?;
        if !meta.managed_files.iter().any(|p| p == path) {
            meta.managed_files.push(path.to_string());
        }
        Ok(())
    }

    fn cleanup_stale_files(
        previous: Option<&AppliedRuleRecord>,
        keep_files: &[String],
        runner: &dyn SystemRunner,
    ) -> Result<(), String> {
        if let Some(prev) = previous {
            for old_file in &prev.rollback_metadata.managed_files {
                if !keep_files.iter().any(|k| k == old_file) {
                    runner.remove_file(old_file)?;
                }
            }
        }
        Ok(())
    }

    fn cleanup_stale_reg_values(
        previous: Option<&AppliedRuleRecord>,
        keep_regs: &[ManagedRegistryValue],
        runner: &dyn SystemRunner,
    ) -> Result<(), String> {
        if let Some(prev) = previous {
            for old_reg in &prev.rollback_metadata.registry_values {
                let still_managed = keep_regs.iter().any(|r| {
                    r.key_path == old_reg.key_path && r.value_name == old_reg.value_name
                });
                if !still_managed {
                    runner.delete_registry_value(&old_reg.key_path, &old_reg.value_name)?;
                }
            }
        }
        Ok(())
    }

    fn apply_login_access(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: LoginAccessConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid access.login_access config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let inf_path = r"C:\ProgramData\NS8PolicyAgent\policies\secpol_login.inf";
        let sdb_path = r"C:\ProgramData\NS8PolicyAgent\policies\secpol_login.sdb";

        let allow_line = match cfg.mode {
            LoginAccessMode::AllowAll => "*S-1-5-32-544,*S-1-5-32-545".to_string(),
            LoginAccessMode::AllowList => {
                let mut entries = vec!["*S-1-5-32-544".to_string()]; // Always preserve local Administrators
                for g in &cfg.allowed_groups {
                    entries.push(g.clone());
                }
                for u in &cfg.allowed_users {
                    entries.push(u.clone());
                }
                entries.join(",")
            }
        };
        let deny_line = cfg.deny_groups.join(",");

        let inf_content = format!(
            "[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Privilege Rights]\r\nSeInteractiveLogonRight = {}\r\nSeDenyInteractiveLogonRight = {}\r\n",
            allow_line, deny_line
        );

        Self::write_tracked_file(runner, &mut meta, inf_path, &inf_content)?;
        let out = runner.run_cmd(
            "secedit",
            &[
                "/configure",
                "/db",
                sdb_path,
                "/cfg",
                inf_path,
                "/areas",
                "USER_RIGHTS",
            ],
        )?;
        if out.exit_code != 0 {
            return Err(format!("secedit configure failed: {}", out.stderr.trim()));
        }

        let mode_str = match cfg.mode {
            LoginAccessMode::AllowAll => "ALLOW_ALL",
            LoginAccessMode::AllowList => "ALLOW_LIST",
        };
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\NS8PolicyAgent\LoginAccess",
            "Mode",
            "REG_SZ",
            mode_str,
        )?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Configured Windows interactive logon policy ({})", mode_str),
            meta,
        ))
    }

    fn apply_local_admins(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: LocalAdminsConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid access.local_admins config: {}", e))?;

        let prev_added: BTreeSet<String> = previous
            .map(|p| {
                p.rollback_metadata
                    .added_principals
                    .iter()
                    .map(|m| m.name.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        let out = runner.run_cmd("net", &["localgroup", "Administrators"])?;
        let current_os_members = parse_windows_localgroup_members(&out.stdout);

        let mut desired_principals: Vec<(String, PrincipalKind)> = Vec::new();
        for g in &cfg.admin_groups {
            let trimmed = g.trim();
            if !trimmed.is_empty()
                && !desired_principals
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(trimmed))
            {
                desired_principals.push((trimmed.to_string(), PrincipalKind::Group));
            }
        }
        for u in &cfg.admin_users {
            let trimmed = u.trim();
            if !trimmed.is_empty()
                && !desired_principals
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(trimmed))
            {
                desired_principals.push((trimmed.to_string(), PrincipalKind::User));
            }
        }

        // Remove principals previously added by the agent that are no longer desired
        if let Some(prev) = previous {
            for prev_p in &prev.rollback_metadata.added_principals {
                let still_desired = desired_principals
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(&prev_p.name));
                if !still_desired {
                    let _ = runner.run_cmd(
                        "net",
                        &["localgroup", "Administrators", &prev_p.name, "/delete"],
                    )?;
                }
            }
        }

        let mut meta = RollbackMetadata::default();
        for (name, kind) in &desired_principals {
            let lower = name.to_lowercase();
            let short_lower = lower.rsplit('\\').next().unwrap_or(&lower);
            let is_preexisting_unmanaged = !prev_added.contains(&lower)
                && current_os_members.iter().any(|m| {
                    m == &lower || m.rsplit('\\').next().unwrap_or(m) == short_lower
                });

            if is_preexisting_unmanaged {
                // SAFETY: Never claim ownership of pre-existing local administrators!
                continue;
            }

            if !current_os_members.contains(&lower) {
                let add_out =
                    runner.run_cmd("net", &["localgroup", "Administrators", name, "/add"])?;
                if add_out.exit_code != 0 {
                    return Err(format!(
                        "Failed to add '{}' to local Administrators: {}",
                        name,
                        add_out.stderr.trim()
                    ));
                }
            }

            meta.added_principals.push(ManagedPrincipal {
                name: name.clone(),
                kind: *kind,
                target_group: "Administrators".to_string(),
            });
        }

        Ok(ApplyOutcome::applied(
            format!(
                "Synchronized local Administrators ({} agent-managed principal(s))",
                meta.added_principals.len()
            ),
            meta,
        ))
    }

    fn apply_network_shares(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: NetworkSharesConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid workspace.network_shares config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let mut desired_targets = Vec::new();

        for (idx, mount) in cfg.mounts.iter().enumerate() {
            let drive = mount
                .windows_drive_letter
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if s.ends_with(':') {
                        s.to_uppercase()
                    } else {
                        format!("{}:", s.to_uppercase())
                    }
                })
                .unwrap_or_else(|| {
                    let letter = (b'Z' - (idx as u8 % 20)) as char;
                    format!("{}:", letter)
                });
            desired_targets.push((mount.id.clone(), drive, mount.remote_path.clone(), mount.reconnect_at_logon));
        }

        // Unmount shares from previous revision that were removed or changed
        if let Some(prev) = previous {
            for old_share in &prev.rollback_metadata.mounted_shares {
                let unchanged = desired_targets.iter().any(|(id, drv, remote, _)| {
                    id == &old_share.id
                        && drv == &old_share.mount_target
                        && remote == &old_share.remote_path
                });
                if !unchanged {
                    let _ = runner.run_cmd("net", &["use", &old_share.mount_target, "/delete", "/y"])?;
                }
            }
        }

        for (id, drive, remote_path, reconnect) in desired_targets {
            let persist_flag = if reconnect {
                "/persistent:yes"
            } else {
                "/persistent:no"
            };
            let out = runner.run_cmd("net", &["use", &drive, &remote_path, persist_flag])?;
            if out.exit_code != 0 {
                return Err(format!(
                    "Failed to mount network share '{}' on {}: {}",
                    remote_path,
                    drive,
                    out.stderr.trim()
                ));
            }

            let safe_id = sanitize_id(&id);
            if reconnect {
                let reg_name = format!("NS8Share_{}", safe_id);
                let cmd_val = format!("cmd.exe /c net use {} \"{}\" /persistent:yes", drive, remote_path);
                Self::set_tracked_reg(
                    runner,
                    &mut meta,
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    &reg_name,
                    "REG_SZ",
                    &cmd_val,
                )?;
            }

            meta.mounted_shares.push(ManagedShare {
                id,
                mount_target: drive,
                remote_path,
            });
        }

        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Mounted {} Windows network share(s)", meta.mounted_shares.len()),
            meta,
        ))
    }

    fn apply_printers(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: PrintersConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid workspace.printers config: {}", e))?;

        if let Some(prev) = previous {
            for old_printer in &prev.rollback_metadata.managed_printers {
                if !cfg.printers.iter().any(|p| &p.name == old_printer) {
                    let rm_cmd = format!(
                        "Remove-Printer -Name '{}' -ErrorAction SilentlyContinue",
                        old_printer.replace('\'', "''")
                    );
                    let _ = runner.run_cmd(
                        "powershell",
                        &["-NoProfile", "-NonInteractive", "-Command", &rm_cmd],
                    )?;
                }
            }
        }

        let mut meta = RollbackMetadata::default();
        for prn in &cfg.printers {
            let escaped_name = prn.name.replace('\'', "''");
            let escaped_uri = prn.uri.replace('\'', "''");
            let add_cmd = format!(
                "if (-not (Get-Printer -Name '{name}' -ErrorAction SilentlyContinue)) {{ Add-Printer -Name '{name}' -PortName '{uri}' -DriverName 'Microsoft IPP Class Driver' }}",
                name = escaped_name,
                uri = escaped_uri
            );
            let out = runner.run_cmd(
                "powershell",
                &["-NoProfile", "-NonInteractive", "-Command", &add_cmd],
            )?;
            if out.exit_code != 0 {
                return Err(format!(
                    "Failed to install printer '{}': {}",
                    prn.name,
                    out.stderr.trim()
                ));
            }
            if prn.is_default {
                let _ = runner.run_cmd(
                    "rundll32",
                    &["printui.dll,PrintUIEntry", "/y", "/n", &prn.name],
                )?;
            }
            meta.managed_printers.push(prn.name.clone());
        }

        Ok(ApplyOutcome::applied(
            format!("Configured {} Windows printer(s)", meta.managed_printers.len()),
            meta,
        ))
    }

    fn apply_scripts(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: ScriptsConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid workspace.scripts config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        for scr in &cfg.scripts {
            let Some(ps_body) = scr.windows_powershell.as_deref() else {
                continue;
            };
            if ps_body.trim().is_empty() {
                continue;
            }
            let safe_id = sanitize_id(&scr.id);
            let script_path = format!(r"C:\ProgramData\NS8PolicyAgent\scripts\{}.ps1", safe_id);
            let wrapped = format!(
                "# Managed by NS8PolicyAgent: {} (timeout: {}s)\r\n{}\r\n",
                scr.name, scr.timeout_seconds, ps_body
            );
            Self::write_tracked_file(runner, &mut meta, &script_path, &wrapped)?;

            let task_name = format!("NS8Policy_{}", safe_id);
            let schedule = match scr.trigger {
                ScriptTrigger::Logon => "ONLOGON",
                ScriptTrigger::Startup => "ONSTART",
            };
            let run_user = match scr.run_as {
                ScriptRunAs::System => "SYSTEM",
                ScriptRunAs::User => "INTERACTIVE",
            };
            let tr = format!(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                script_path
            );
            let out = runner.run_cmd(
                "schtasks",
                &[
                    "/Create", "/TN", &task_name, "/TR", &tr, "/SC", schedule, "/RU", run_user,
                    "/F",
                ],
            )?;
            if out.exit_code != 0 {
                return Err(format!(
                    "Failed to schedule task '{}': {}",
                    task_name,
                    out.stderr.trim()
                ));
            }
            meta.scheduled_tasks.push(task_name);
        }

        if let Some(prev) = previous {
            for old_task in &prev.rollback_metadata.scheduled_tasks {
                if !meta.scheduled_tasks.iter().any(|t| t == old_task) {
                    let _ = runner.run_cmd("schtasks", &["/Delete", "/TN", old_task, "/F"])?;
                }
            }
        }
        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Registered {} Windows script task(s)", meta.scheduled_tasks.len()),
            meta,
        ))
    }

    fn apply_screen_lock(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: ScreenLockConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid security.screen_lock config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let timeout_str = cfg.idle_timeout_seconds.to_string();
        let secure_str = if cfg.require_password_on_wake { "1" } else { "0" };

        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "InactivityTimeoutSecs",
            "REG_DWORD",
            &timeout_str,
        )?;
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
            "ScreenSaveActive",
            "REG_SZ",
            "1",
        )?;
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
            "ScreenSaveTimeOut",
            "REG_SZ",
            &timeout_str,
        )?;
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop",
            "ScreenSaverIsSecure",
            "REG_SZ",
            secure_str,
        )?;

        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!(
                "Enforced Windows screen lock timeout ({}s, password={})",
                cfg.idle_timeout_seconds, cfg.require_password_on_wake
            ),
            meta,
        ))
    }

    fn apply_usb_storage(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: UsbStorageConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid security.usb_storage config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let usbstor_key = r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR";
        let storage_pol_key = r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
        let rem_key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";

        let msg = match cfg.mode {
            UsbStorageMode::Block => {
                runner.set_registry_value(usbstor_key, "Start", "REG_DWORD", "4")?;
                meta.registry_values.push(ManagedRegistryValue {
                    key_path: usbstor_key.to_string(),
                    value_name: "Start".to_string(),
                    restore_type: Some("REG_DWORD".to_string()),
                    restore_data: Some("3".to_string()),
                });
                Self::set_tracked_reg(runner, &mut meta, rem_key, "Deny_Read", "REG_DWORD", "1")?;
                Self::set_tracked_reg(runner, &mut meta, rem_key, "Deny_Write", "REG_DWORD", "1")?;
                "USBSTOR Start set to 4 (USB mass storage blocked)".to_string()
            }
            UsbStorageMode::ReadOnly => {
                runner.set_registry_value(usbstor_key, "Start", "REG_DWORD", "3")?;
                meta.registry_values.push(ManagedRegistryValue {
                    key_path: usbstor_key.to_string(),
                    value_name: "Start".to_string(),
                    restore_type: Some("REG_DWORD".to_string()),
                    restore_data: Some("3".to_string()),
                });
                Self::set_tracked_reg(
                    runner,
                    &mut meta,
                    storage_pol_key,
                    "WriteProtect",
                    "REG_DWORD",
                    "1",
                )?;
                Self::set_tracked_reg(runner, &mut meta, rem_key, "Deny_Read", "REG_DWORD", "0")?;
                Self::set_tracked_reg(runner, &mut meta, rem_key, "Deny_Write", "REG_DWORD", "1")?;
                "USB mass storage set to READ_ONLY (WriteProtect=1)".to_string()
            }
            UsbStorageMode::Allow => {
                runner.set_registry_value(usbstor_key, "Start", "REG_DWORD", "3")?;
                meta.registry_values.push(ManagedRegistryValue {
                    key_path: usbstor_key.to_string(),
                    value_name: "Start".to_string(),
                    restore_type: Some("REG_DWORD".to_string()),
                    restore_data: Some("3".to_string()),
                });
                Self::set_tracked_reg(
                    runner,
                    &mut meta,
                    storage_pol_key,
                    "WriteProtect",
                    "REG_DWORD",
                    "0",
                )?;
                "USB mass storage explicitly allowed (USBSTOR Start=3)".to_string()
            }
        };

        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(msg, meta))
    }

    fn apply_firewall(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: FirewallConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid security.firewall config: {}", e))?;

        // Clean up previous firewall rules before applying fresh desired set
        if let Some(prev) = previous {
            for rname in &prev.rollback_metadata.firewall_rules {
                let name_arg = format!("name={}", rname);
                let _ = runner.run_cmd(
                    "netsh",
                    &["advfirewall", "firewall", "delete", "rule", &name_arg],
                )?;
            }
        }

        let mut meta = RollbackMetadata::default();
        let state_str = if cfg.is_enabled { "on" } else { "off" };
        let out = runner.run_cmd(
            "netsh",
            &["advfirewall", "set", "allprofiles", "state", state_str],
        )?;
        if out.exit_code != 0 {
            return Err(format!("netsh firewall state failed: {}", out.stderr.trim()));
        }

        let policy_str = match cfg.default_inbound {
            FirewallInboundPolicy::Block => "blockinbound,allowoutbound",
            FirewallInboundPolicy::Allow => "allowinbound,allowoutbound",
        };
        runner.run_cmd(
            "netsh",
            &[
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                policy_str,
            ],
        )?;

        if cfg.is_enabled && cfg.allow_stealth_mode {
            let rule_name = "NS8Policy_Stealth_ICMP";
            let name_arg = format!("name={}", rule_name);
            runner.run_cmd(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &name_arg,
                    "dir=in",
                    "action=block",
                    "protocol=icmpv4:8,any",
                ],
            )?;
            meta.firewall_rules.push(rule_name.to_string());
        }

        for port in &cfg.allowed_tcp_ports {
            let rule_name = format!("NS8Policy_TCP_{}", port);
            let name_arg = format!("name={}", rule_name);
            let port_arg = format!("localport={}", port);
            runner.run_cmd(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &name_arg,
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    &port_arg,
                ],
            )?;
            meta.firewall_rules.push(rule_name);
        }

        for port in &cfg.allowed_udp_ports {
            let rule_name = format!("NS8Policy_UDP_{}", port);
            let name_arg = format!("name={}", rule_name);
            let port_arg = format!("localport={}", port);
            runner.run_cmd(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &name_arg,
                    "dir=in",
                    "action=allow",
                    "protocol=UDP",
                    &port_arg,
                ],
            )?;
            meta.firewall_rules.push(rule_name);
        }

        Ok(ApplyOutcome::applied(
            format!(
                "Configured Windows Defender Firewall (enabled={}, {} port/stealth rule(s))",
                cfg.is_enabled,
                meta.firewall_rules.len()
            ),
            meta,
        ))
    }

    fn apply_browser(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: BrowserConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid desktop.browser config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let startup_val = match cfg.restore_on_startup {
            BrowserRestoreMode::Homepage => "4",
            BrowserRestoreMode::LastSession => "1",
        };
        let pw_val = if cfg.disable_password_manager {
            "0"
        } else {
            "1"
        };

        for target in &cfg.targets {
            match target {
                BrowserTarget::Chrome => {
                    let base = r"HKLM\SOFTWARE\Policies\Google\Chrome";
                    if let Some(url) = cfg.homepage_url.as_deref().filter(|u| !u.is_empty()) {
                        Self::set_tracked_reg(runner, &mut meta, base, "HomepageLocation", "REG_SZ", url)?;
                    }
                    Self::set_tracked_reg(runner, &mut meta, base, "RestoreOnStartup", "REG_DWORD", startup_val)?;
                    Self::set_tracked_reg(
                        runner,
                        &mut meta,
                        base,
                        "IncognitoModeAvailability",
                        "REG_DWORD",
                        if cfg.disable_incognito { "1" } else { "0" },
                    )?;
                    Self::set_tracked_reg(runner, &mut meta, base, "PasswordManagerEnabled", "REG_DWORD", pw_val)?;
                    let ext_key = format!(r"{}\ExtensionInstallForcelist", base);
                    for (i, ext) in cfg.force_extensions.iter().enumerate() {
                        Self::set_tracked_reg(runner, &mut meta, &ext_key, &(i + 1).to_string(), "REG_SZ", ext)?;
                    }
                }
                BrowserTarget::Edge => {
                    let base = r"HKLM\SOFTWARE\Policies\Microsoft\Edge";
                    if let Some(url) = cfg.homepage_url.as_deref().filter(|u| !u.is_empty()) {
                        Self::set_tracked_reg(runner, &mut meta, base, "HomepageLocation", "REG_SZ", url)?;
                    }
                    Self::set_tracked_reg(runner, &mut meta, base, "RestoreOnStartup", "REG_DWORD", startup_val)?;
                    Self::set_tracked_reg(
                        runner,
                        &mut meta,
                        base,
                        "InPrivateModeAvailability",
                        "REG_DWORD",
                        if cfg.disable_incognito { "1" } else { "0" },
                    )?;
                    Self::set_tracked_reg(runner, &mut meta, base, "PasswordManagerEnabled", "REG_DWORD", pw_val)?;
                    let ext_key = format!(r"{}\ExtensionInstallForcelist", base);
                    for (i, ext) in cfg.force_extensions.iter().enumerate() {
                        Self::set_tracked_reg(runner, &mut meta, &ext_key, &(i + 1).to_string(), "REG_SZ", ext)?;
                    }
                }
                BrowserTarget::Firefox => {
                    let ff_path = r"C:\Program Files\Mozilla Firefox\distribution\policies.json";
                    let ff_json = build_firefox_policies_json(&cfg);
                    Self::write_tracked_file(runner, &mut meta, ff_path, &ff_json)?;
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Applied Windows browser policies for {} browser(s)", cfg.targets.len()),
            meta,
        ))
    }

    fn apply_wallpaper(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: WallpaperConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid desktop.wallpaper config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let csp_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP";
        Self::set_tracked_reg(runner, &mut meta, csp_key, "DesktopImageUrl", "REG_SZ", &cfg.image_url)?;
        Self::set_tracked_reg(runner, &mut meta, csp_key, "DesktopImagePath", "REG_SZ", &cfg.image_url)?;
        Self::set_tracked_reg(runner, &mut meta, csp_key, "DesktopImageStatus", "REG_DWORD", "1")?;

        let style_code = match cfg.fit_mode {
            WallpaperFitMode::Fill => "10",
            WallpaperFitMode::Fit => "6",
            WallpaperFitMode::Center => "0",
        };
        let sys_pol_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        Self::set_tracked_reg(runner, &mut meta, sys_pol_key, "Wallpaper", "REG_SZ", &cfg.image_url)?;
        Self::set_tracked_reg(runner, &mut meta, sys_pol_key, "WallpaperStyle", "REG_SZ", style_code)?;

        let active_key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop";
        Self::set_tracked_reg(
            runner,
            &mut meta,
            active_key,
            "NoChangingWallPaper",
            "REG_DWORD",
            if cfg.is_locked { "1" } else { "0" },
        )?;

        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Configured Windows desktop wallpaper ({})", cfg.image_url),
            meta,
        ))
    }

    fn apply_system_restrictions(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: SystemRestrictionsConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid desktop.system_restrictions config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoControlPanel",
            "REG_DWORD",
            if cfg.disable_control_panel { "1" } else { "0" },
        )?;
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "DisableRegistryTools",
            "REG_DWORD",
            if cfg.disable_registry_tools { "1" } else { "0" },
        )?;
        Self::set_tracked_reg(
            runner,
            &mut meta,
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "DisableCMD",
            "REG_DWORD",
            if cfg.disable_terminal_for_standard_users {
                "2"
            } else {
                "0"
            },
        )?;

        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            "Enforced Windows system & administrative tool restrictions",
            meta,
        ))
    }

    fn apply_raw_setting(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: RawSettingConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid custom.raw_setting config: {}", e))?;

        let matching: Vec<_> = cfg
            .items
            .iter()
            .filter(|i| i.target_os == OsFamily::Windows)
            .collect();

        if !cfg.items.is_empty() && matching.is_empty() {
            if let Some(prev) = previous {
                execute_metadata_cleanup(&prev.rollback_metadata, runner)?;
            }
            return Ok(ApplyOutcome::skipped(
                "No custom.raw_setting items target WINDOWS",
            ));
        }

        let mut meta = RollbackMetadata::default();
        for item in &matching {
            match item.engine.trim().to_uppercase().as_str() {
                "REGISTRY" => {
                    let reg_type = match item.value_type.trim().to_uppercase().as_str() {
                        "INT" | "DWORD" | "REG_DWORD" => "REG_DWORD",
                        "QWORD" | "REG_QWORD" => "REG_QWORD",
                        "BOOL" | "BOOLEAN" => "REG_DWORD",
                        "MULTI_SZ" | "REG_MULTI_SZ" => "REG_MULTI_SZ",
                        "EXPAND_SZ" | "REG_EXPAND_SZ" => "REG_EXPAND_SZ",
                        _ => "REG_SZ",
                    };
                    let reg_val = if item.value_type.eq_ignore_ascii_case("BOOL")
                        || item.value_type.eq_ignore_ascii_case("BOOLEAN")
                    {
                        if item.value.eq_ignore_ascii_case("true") || item.value == "1" {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        }
                    } else {
                        item.value.clone()
                    };
                    Self::set_tracked_reg(runner, &mut meta, &item.path, &item.key, reg_type, &reg_val)?;
                }
                "FILE" | "CONFIG_FILE" => {
                    Self::write_tracked_file(runner, &mut meta, &item.path, &item.value)?;
                }
                other => {
                    return Ok(ApplyOutcome::skipped(format!(
                        "Unsupported raw_setting engine '{}' on WINDOWS",
                        other
                    )));
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_reg_values(previous, &meta.registry_values, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Applied {} custom raw setting(s) on WINDOWS", matching.len()),
            meta,
        ))
    }
}

impl PlatformEnforcer for WindowsEnforcer {
    fn os_family(&self) -> OsFamily {
        OsFamily::Windows
    }

    fn apply(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        match rule.rule_type.as_str() {
            "access.login_access" => self.apply_login_access(rule, previous, runner),
            "access.local_admins" => self.apply_local_admins(rule, previous, runner),
            "workspace.network_shares" => self.apply_network_shares(rule, previous, runner),
            "workspace.printers" => self.apply_printers(rule, previous, runner),
            "workspace.scripts" => self.apply_scripts(rule, previous, runner),
            "security.screen_lock" => self.apply_screen_lock(rule, previous, runner),
            "security.usb_storage" => self.apply_usb_storage(rule, previous, runner),
            "security.firewall" => self.apply_firewall(rule, previous, runner),
            "desktop.browser" => self.apply_browser(rule, previous, runner),
            "desktop.wallpaper" => self.apply_wallpaper(rule, previous, runner),
            "desktop.system_restrictions" => self.apply_system_restrictions(rule, previous, runner),
            "custom.raw_setting" => self.apply_raw_setting(rule, previous, runner),
            unknown => Ok(ApplyOutcome::skipped(format!(
                "Unsupported ruleType '{}' on WINDOWS",
                unknown
            ))),
        }
    }

    fn rollback(
        &self,
        record: &AppliedRuleRecord,
        runner: &dyn SystemRunner,
    ) -> Result<String, String> {
        let meta = &record.rollback_metadata;

        match record.rule_type.as_str() {
            "access.login_access" => {
                let restore_inf = r"C:\ProgramData\NS8PolicyAgent\policies\secpol_restore.inf";
                let sdb_path = r"C:\ProgramData\NS8PolicyAgent\policies\secpol_login.sdb";
                let default_inf = "[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Privilege Rights]\r\nSeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545\r\nSeDenyInteractiveLogonRight = \r\n";
                runner.write_file(restore_inf, default_inf, None)?;
                let _ = runner.run_cmd(
                    "secedit",
                    &[
                        "/configure",
                        "/db",
                        sdb_path,
                        "/cfg",
                        restore_inf,
                        "/areas",
                        "USER_RIGHTS",
                    ],
                )?;
                runner.remove_file(restore_inf)?;
            }
            "access.local_admins" => {
                // SAFETY: Remove ONLY agent-added principals recorded in rollback_metadata!
                for principal in &meta.added_principals {
                    let out = runner.run_cmd(
                        "net",
                        &[
                            "localgroup",
                            &principal.target_group,
                            &principal.name,
                            "/delete",
                        ],
                    )?;
                    if out.exit_code != 0 {
                        return Err(format!(
                            "Failed to roll back added admin '{}': {}",
                            principal.name,
                            out.stderr.trim()
                        ));
                    }
                }
            }
            "workspace.network_shares" => {
                for share in &meta.mounted_shares {
                    let _ = runner.run_cmd("net", &["use", &share.mount_target, "/delete", "/y"])?;
                }
            }
            "workspace.printers" => {
                for prn_name in &meta.managed_printers {
                    let cmd = format!(
                        "Remove-Printer -Name '{}' -ErrorAction SilentlyContinue",
                        prn_name.replace('\'', "''")
                    );
                    let _ = runner.run_cmd(
                        "powershell",
                        &["-NoProfile", "-NonInteractive", "-Command", &cmd],
                    )?;
                }
            }
            "workspace.scripts" => {
                for task in &meta.scheduled_tasks {
                    let _ = runner.run_cmd("schtasks", &["/Delete", "/TN", task, "/F"])?;
                }
            }
            "security.firewall" => {
                for rname in &meta.firewall_rules {
                    let name_arg = format!("name={}", rname);
                    let _ = runner.run_cmd(
                        "netsh",
                        &["advfirewall", "firewall", "delete", "rule", &name_arg],
                    )?;
                }
            }
            _ => {}
        }

        execute_metadata_cleanup(meta, runner)?;

        Ok(format!(
            "Rolled back '{}' on WINDOWS",
            record.rule_type
        ))
    }
}

fn parse_windows_localgroup_members(stdout: &str) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    let mut in_members = false;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("---") {
            in_members = true;
            continue;
        }
        if !in_members || trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.starts_with("the command completed")
            || lower.starts_with("der befehl wurde")
        {
            break;
        }
        members.insert(lower);
    }
    members
}
