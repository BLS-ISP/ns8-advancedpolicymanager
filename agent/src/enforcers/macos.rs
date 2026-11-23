use crate::enforcers::{
    build_firefox_policies_json, execute_metadata_cleanup, sanitize_id, xml_escape, ApplyOutcome,
    PlatformEnforcer,
};
use crate::models::{
    BrowserConfig, BrowserRestoreMode, BrowserTarget, FirewallConfig, FirewallInboundPolicy,
    LocalAdminsConfig, LoginAccessConfig, LoginAccessMode, NetworkSharesConfig, OsFamily,
    PolicyRule, PrintersConfig, RawSettingConfig, ScreenLockConfig, ScriptRunAs, ScriptTrigger,
    ScriptsConfig, ShareProtocol, SystemRestrictionsConfig, UsbStorageConfig, UsbStorageMode,
    WallpaperConfig, WallpaperFitMode,
};
use crate::runner::SystemRunner;
use crate::state::{
    AppliedRuleRecord, ManagedPlistKey, ManagedPrincipal, ManagedShare, PrincipalKind,
    RollbackMetadata,
};
use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub struct MacOsEnforcer;

impl MacOsEnforcer {
    pub fn new() -> Self {
        Self
    }

    fn write_tracked_file(
        runner: &dyn SystemRunner,
        meta: &mut RollbackMetadata,
        path: &str,
        content: &str,
        mode: Option<u32>,
    ) -> Result<(), String> {
        runner.write_file(path, content, mode)?;
        if !meta.managed_files.iter().any(|p| p == path) {
            meta.managed_files.push(path.to_string());
        }
        Ok(())
    }

    fn write_tracked_plist(
        runner: &dyn SystemRunner,
        meta: &mut RollbackMetadata,
        domain: &str,
        key: &str,
        value_type: &str,
        value: &str,
    ) -> Result<(), String> {
        runner.write_plist(domain, key, value_type, value)?;
        meta.plist_keys.push(ManagedPlistKey {
            domain_or_path: domain.to_string(),
            key: key.to_string(),
        });
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

    fn cleanup_stale_plists(
        previous: Option<&AppliedRuleRecord>,
        keep_plists: &[ManagedPlistKey],
        runner: &dyn SystemRunner,
    ) -> Result<(), String> {
        if let Some(prev) = previous {
            for old_plist in &prev.rollback_metadata.plist_keys {
                let kept = keep_plists.iter().any(|k| {
                    k.domain_or_path == old_plist.domain_or_path && k.key == old_plist.key
                });
                if !kept {
                    runner.delete_plist_key(&old_plist.domain_or_path, &old_plist.key)?;
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
        match cfg.mode {
            LoginAccessMode::AllowAll => {
                let _ = runner.run_cmd(
                    "dseditgroup",
                    &["-o", "delete", "com.apple.access_loginwindow"],
                )?;
            }
            LoginAccessMode::AllowList => {
                let out = runner.run_cmd(
                    "dseditgroup",
                    &["-o", "create", "-q", "com.apple.access_loginwindow"],
                )?;
                if out.exit_code != 0 {
                    return Err(format!(
                        "dseditgroup create com.apple.access_loginwindow failed: {}",
                        out.stderr.trim()
                    ));
                }
                // Always keep local admin group permitted to avoid lockout
                runner.run_cmd(
                    "dseditgroup",
                    &[
                        "-o",
                        "edit",
                        "-a",
                        "admin",
                        "-t",
                        "group",
                        "com.apple.access_loginwindow",
                    ],
                )?;
                for g in &cfg.allowed_groups {
                    runner.run_cmd(
                        "dseditgroup",
                        &[
                            "-o",
                            "edit",
                            "-a",
                            g,
                            "-t",
                            "group",
                            "com.apple.access_loginwindow",
                        ],
                    )?;
                }
                for u in &cfg.allowed_users {
                    runner.run_cmd(
                        "dseditgroup",
                        &[
                            "-o",
                            "edit",
                            "-a",
                            u,
                            "-t",
                            "user",
                            "com.apple.access_loginwindow",
                        ],
                    )?;
                }
            }
        }

        for dg in &cfg.deny_groups {
            runner.run_cmd(
                "dseditgroup",
                &[
                    "-o",
                    "edit",
                    "-d",
                    dg,
                    "-t",
                    "group",
                    "com.apple.access_loginwindow",
                ],
            )?;
        }

        let marker_path = "/Library/Application Support/NS8PolicyAgent/policies/login_access.json";
        let snapshot = serde_json::to_string_pretty(&cfg).unwrap_or_default();
        Self::write_tracked_file(runner, &mut meta, marker_path, &snapshot, Some(0o644))?;
        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        let mode_label = match cfg.mode {
            LoginAccessMode::AllowAll => "ALLOW_ALL",
            LoginAccessMode::AllowList => "ALLOW_LIST",
        };
        Ok(ApplyOutcome::applied(
            format!("Configured macOS loginwindow SACL access ({})", mode_label),
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

        let prev_added: BTreeSet<(String, PrincipalKind)> = previous
            .map(|p| {
                p.rollback_metadata
                    .added_principals
                    .iter()
                    .map(|m| (m.name.to_lowercase(), m.kind))
                    .collect()
            })
            .unwrap_or_default();

        let dscl_out = runner.run_cmd("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])?;
        let existing_admin_users = parse_dscl_group_membership(&dscl_out.stdout);

        let mut desired: Vec<(String, PrincipalKind)> = Vec::new();
        for g in &cfg.admin_groups {
            let trimmed = g.trim();
            if !trimmed.is_empty() {
                desired.push((trimmed.to_string(), PrincipalKind::Group));
            }
        }
        for u in &cfg.admin_users {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                desired.push((trimmed.to_string(), PrincipalKind::User));
            }
        }

        // Remove principals previously added by the agent that are no longer desired
        if let Some(prev) = previous {
            for old_p in &prev.rollback_metadata.added_principals {
                let still_desired = desired.iter().any(|(n, k)| {
                    n.eq_ignore_ascii_case(&old_p.name) && *k == old_p.kind
                });
                if !still_desired {
                    let t_flag = match old_p.kind {
                        PrincipalKind::User => "user",
                        PrincipalKind::Group => "group",
                    };
                    let _ = runner.run_cmd(
                        "dseditgroup",
                        &["-o", "edit", "-d", &old_p.name, "-t", t_flag, "admin"],
                    )?;
                }
            }
        }

        let mut meta = RollbackMetadata::default();
        let sudo_spec = if cfg.passwordless_sudo {
            "ALL=(ALL) NOPASSWD: ALL"
        } else {
            "ALL=(ALL) ALL"
        };
        let mut sudoers_lines = vec!["# Managed by ns8-policy-agent".to_string()];

        for (name, kind) in &desired {
            let lower = name.to_lowercase();
            let is_preexisting_unmanaged = *kind == PrincipalKind::User
                && existing_admin_users.contains(&lower)
                && !prev_added.contains(&(lower.clone(), *kind));

            match kind {
                PrincipalKind::Group => {
                    sudoers_lines.push(format!("%\"{}\" {}", name, sudo_spec));
                }
                PrincipalKind::User => {
                    sudoers_lines.push(format!("{} {}", name, sudo_spec));
                }
            }

            if is_preexisting_unmanaged {
                // SAFETY: Never claim ownership of pre-existing macOS admin users!
                continue;
            }

            let t_flag = match kind {
                PrincipalKind::User => "user",
                PrincipalKind::Group => "group",
            };
            let out = runner.run_cmd(
                "dseditgroup",
                &["-o", "edit", "-a", name, "-t", t_flag, "admin"],
            )?;
            if out.exit_code != 0 {
                return Err(format!(
                    "dseditgroup failed adding '{}' to admin: {}",
                    name,
                    out.stderr.trim()
                ));
            }

            meta.added_principals.push(ManagedPrincipal {
                name: name.clone(),
                kind: *kind,
                target_group: "admin".to_string(),
            });
        }
        sudoers_lines.push(String::new());

        Self::write_tracked_file(
            runner,
            &mut meta,
            "/etc/sudoers.d/90-ns8-policy-admins",
            &sudoers_lines.join("\n"),
            Some(0o440),
        )?;
        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!(
                "Configured macOS admin group & sudoers ({} agent-managed principal(s))",
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
        let mut desired = Vec::new();
        for mount in &cfg.mounts {
            let mount_path = mount
                .unix_mount_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("/Volumes/{}", sanitize_id(&mount.name)));
            let remote_norm = if mount.protocol == ShareProtocol::Smb {
                let cleaned = mount.remote_path.trim_start_matches('\\').replace('\\', "/");
                if cleaned.starts_with("smb://") {
                    cleaned
                } else {
                    format!("smb://{}", cleaned.trim_start_matches('/'))
                }
            } else {
                mount.remote_path.clone()
            };
            desired.push((
                mount.id.clone(),
                mount.protocol,
                mount_path,
                remote_norm,
                mount.reconnect_at_logon,
            ));
        }

        if let Some(prev) = previous {
            for old_share in &prev.rollback_metadata.mounted_shares {
                let unchanged = desired.iter().any(|(id, _, mp, rem, _)| {
                    id == &old_share.id
                        && mp == &old_share.mount_target
                        && rem == &old_share.remote_path
                });
                if !unchanged {
                    let _ = runner.run_cmd("diskutil", &["unmount", "force", &old_share.mount_target])?;
                }
            }
        }

        for (id, protocol, mount_path, remote_norm, reconnect) in desired {
            runner.run_cmd("mkdir", &["-p", &mount_path])?;
            let mount_prog = match protocol {
                ShareProtocol::Smb => "mount_smbfs",
                ShareProtocol::Nfs => "mount_nfs",
            };
            let out = runner.run_cmd(mount_prog, &[&remote_norm, &mount_path])?;
            if out.exit_code != 0 {
                return Err(format!(
                    "{} failed for '{}' -> '{}': {}",
                    mount_prog,
                    remote_norm,
                    mount_path,
                    out.stderr.trim()
                ));
            }
            if reconnect {
                let safe_id = sanitize_id(&id);
                let plist_path = format!(
                    "/Library/LaunchAgents/org.nethserver.policyagent.share.{}.plist",
                    safe_id
                );
                let plist_xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>org.nethserver.policyagent.share.{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>/usr/bin/open</string>\n    <string>-g</string>\n    <string>{}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n",
                    xml_escape(&safe_id),
                    xml_escape(&remote_norm)
                );
                Self::write_tracked_file(runner, &mut meta, &plist_path, &plist_xml, Some(0o644))?;
            }
            meta.mounted_shares.push(ManagedShare {
                id,
                mount_target: mount_path,
                remote_path: remote_norm,
            });
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Mounted {} macOS network share(s)", meta.mounted_shares.len()),
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
            for old_prn in &prev.rollback_metadata.managed_printers {
                if !cfg.printers.iter().any(|p| &p.name == old_prn) {
                    let _ = runner.run_cmd("lpadmin", &["-x", old_prn])?;
                }
            }
        }

        let mut meta = RollbackMetadata::default();
        for prn in &cfg.printers {
            let out = runner.run_cmd(
                "lpadmin",
                &["-p", &prn.name, "-E", "-v", &prn.uri, "-m", &prn.driver_model],
            )?;
            if out.exit_code != 0 {
                return Err(format!(
                    "macOS lpadmin failed for '{}': {}",
                    prn.name,
                    out.stderr.trim()
                ));
            }
            if prn.is_default {
                let _ = runner.run_cmd("lpadmin", &["-d", &prn.name])?;
            }
            meta.managed_printers.push(prn.name.clone());
        }

        Ok(ApplyOutcome::applied(
            format!("Configured {} CUPS printer(s) on macOS", meta.managed_printers.len()),
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
            let Some(zsh_body) = scr.macos_zsh.as_deref() else {
                continue;
            };
            if zsh_body.trim().is_empty() {
                continue;
            }
            let safe_id = sanitize_id(&scr.id);
            let script_path = format!(
                "/Library/Application Support/NS8PolicyAgent/scripts/{}.zsh",
                safe_id
            );
            let script_content = format!(
                "#!/bin/zsh\n# Managed by ns8-policy-agent: {}\nset -e\n{}\n",
                scr.name, zsh_body
            );
            Self::write_tracked_file(runner, &mut meta, &script_path, &script_content, Some(0o755))?;

            let plist_dir = match (scr.trigger, scr.run_as) {
                (ScriptTrigger::Startup, _) | (_, ScriptRunAs::System) => "/Library/LaunchDaemons",
                _ => "/Library/LaunchAgents",
            };
            let label = format!("org.nethserver.policyagent.script.{}", safe_id);
            let plist_path = format!("{}/{}.plist", plist_dir, label);
            let plist_xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>/bin/zsh</string>\n    <string>{}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>TimeOut</key>\n  <integer>{}</integer>\n</dict>\n</plist>\n",
                xml_escape(&label),
                xml_escape(&script_path),
                scr.timeout_seconds
            );
            Self::write_tracked_file(runner, &mut meta, &plist_path, &plist_xml, Some(0o644))?;
            meta.scheduled_tasks.push(plist_path);
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Deployed {} macOS LaunchAgent/LaunchDaemon script(s)", meta.scheduled_tasks.len()),
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
        let domain = "/Library/Preferences/com.apple.screensaver";
        Self::write_tracked_plist(
            runner,
            &mut meta,
            domain,
            "idleTime",
            "int",
            &cfg.idle_timeout_seconds.to_string(),
        )?;
        Self::write_tracked_plist(
            runner,
            &mut meta,
            domain,
            "askForPassword",
            "int",
            if cfg.require_password_on_wake { "1" } else { "0" },
        )?;
        Self::write_tracked_plist(
            runner,
            &mut meta,
            domain,
            "askForPasswordDelay",
            "int",
            &cfg.lock_delay_seconds.to_string(),
        )?;

        let managed_plist = "/Library/Managed Preferences/com.apple.screensaver.plist";
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>idleTime</key>\n  <integer>{}</integer>\n  <key>askForPassword</key>\n  <{}/>\n  <key>askForPasswordDelay</key>\n  <integer>{}</integer>\n</dict>\n</plist>\n",
            cfg.idle_timeout_seconds,
            if cfg.require_password_on_wake { "true" } else { "false" },
            cfg.lock_delay_seconds
        );
        Self::write_tracked_file(runner, &mut meta, managed_plist, &xml, Some(0o644))?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_plists(previous, &meta.plist_keys, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Enforced macOS screen lock policy ({}s)", cfg.idle_timeout_seconds),
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
        let domain = "/Library/Preferences/com.apple.MCX";
        let mode_str = match cfg.mode {
            UsbStorageMode::Block => "BLOCK",
            UsbStorageMode::ReadOnly => "READ_ONLY",
            UsbStorageMode::Allow => "ALLOW",
        };
        Self::write_tracked_plist(runner, &mut meta, domain, "usbStorageMode", "string", mode_str)?;

        if cfg.mode != UsbStorageMode::Allow {
            let plist_path = "/Library/Managed Preferences/com.apple.diskarbitrationd.plist";
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>USBStoragePolicy</key>\n  <string>{}</string>\n</dict>\n</plist>\n",
                mode_str
            );
            Self::write_tracked_file(runner, &mut meta, plist_path, &xml, Some(0o644))?;
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_plists(previous, &meta.plist_keys, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Configured macOS USB external storage policy ({})", mode_str),
            meta,
        ))
    }

    fn apply_firewall(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: FirewallConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid security.firewall config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw";

        let state_flag = if cfg.is_enabled { "on" } else { "off" };
        let out = runner.run_cmd(fw_bin, &["--setglobalstate", state_flag])?;
        if out.exit_code != 0 {
            return Err(format!(
                "socketfilterfw --setglobalstate failed: {}",
                out.stderr.trim()
            ));
        }

        let stealth_flag = if cfg.is_enabled && cfg.allow_stealth_mode {
            "on"
        } else {
            "off"
        };
        runner.run_cmd(fw_bin, &["--setstealthmode", stealth_flag])?;

        let anchor_path = "/etc/pf.anchors/org.nethserver.policyagent";
        if cfg.is_enabled {
            let mut pf_lines = vec!["# Managed by ns8-policy-agent".to_string()];
            if cfg.default_inbound == FirewallInboundPolicy::Block
                && cfg.allowed_tcp_ports.is_empty()
                && cfg.allowed_udp_ports.is_empty()
            {
                pf_lines.push("block drop in quick on ! lo0 proto { tcp, udp }".to_string());
            } else {
                for port in &cfg.allowed_tcp_ports {
                    pf_lines.push(format!("pass in proto tcp from any to any port {}", port));
                }
                for port in &cfg.allowed_udp_ports {
                    pf_lines.push(format!("pass in proto udp from any to any port {}", port));
                }
            }
            pf_lines.push(String::new());
            Self::write_tracked_file(runner, &mut meta, anchor_path, &pf_lines.join("\n"), Some(0o644))?;
            runner.run_cmd("pfctl", &["-a", "org.nethserver.policyagent", "-f", anchor_path])?;
            meta.firewall_rules
                .push("org.nethserver.policyagent".to_string());
        } else {
            let _ = runner.run_cmd("pfctl", &["-a", "org.nethserver.policyagent", "-F", "all"])?;
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Configured macOS ALF & PF firewall (enabled={})", cfg.is_enabled),
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
        let chromium_xml = build_macos_chromium_plist(&cfg);

        for target in &cfg.targets {
            match target {
                BrowserTarget::Chrome => {
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/Library/Managed Preferences/com.google.Chrome.plist",
                        &chromium_xml,
                        Some(0o644),
                    )?;
                }
                BrowserTarget::Edge => {
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/Library/Managed Preferences/com.microsoft.Edge.plist",
                        &chromium_xml,
                        Some(0o644),
                    )?;
                }
                BrowserTarget::Firefox => {
                    let ff_json = build_firefox_policies_json(&cfg);
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/Library/Application Support/Mozilla/Policies/policies.json",
                        &ff_json,
                        Some(0o644),
                    )?;
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Applied macOS Managed Preferences browser policies ({} target(s))", cfg.targets.len()),
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
        let placement = match cfg.fit_mode {
            WallpaperFitMode::Fill => "Crop",
            WallpaperFitMode::Fit => "FitToScreen",
            WallpaperFitMode::Center => "Centered",
        };
        let domain = "/Library/Preferences/com.apple.desktop";
        Self::write_tracked_plist(runner, &mut meta, domain, "WallpaperUrl", "string", &cfg.image_url)?;
        Self::write_tracked_plist(runner, &mut meta, domain, "Placement", "string", placement)?;
        Self::write_tracked_plist(
            runner,
            &mut meta,
            domain,
            "Locked",
            "bool",
            if cfg.is_locked { "true" } else { "false" },
        )?;

        let managed_plist = "/Library/Managed Preferences/com.apple.desktop.plist";
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>override-picture-path</key>\n  <string>{}</string>\n  <key>placement</key>\n  <string>{}</string>\n  <key>locked</key>\n  <{}/>\n</dict>\n</plist>\n",
            xml_escape(&cfg.image_url),
            placement,
            if cfg.is_locked { "true" } else { "false" }
        );
        Self::write_tracked_file(runner, &mut meta, managed_plist, &xml, Some(0o644))?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_plists(previous, &meta.plist_keys, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Configured macOS desktop wallpaper ({})", cfg.image_url),
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
        if cfg.disable_control_panel {
            let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>DisableSystemSettings</key>\n  <true/>\n</dict>\n</plist>\n";
            Self::write_tracked_file(
                runner,
                &mut meta,
                "/Library/Managed Preferences/com.apple.systempreferences.plist",
                xml,
                Some(0o644),
            )?;
        }

        if cfg.disable_registry_tools || cfg.disable_terminal_for_standard_users {
            let mut disallowed = Vec::new();
            if cfg.disable_registry_tools {
                disallowed.push("com.apple.DirectoryUtility");
            }
            if cfg.disable_terminal_for_standard_users {
                disallowed.push("com.apple.Terminal");
            }
            let items_xml: String = disallowed
                .iter()
                .map(|b| format!("    <string>{}</string>\n", b))
                .collect();
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>familyControlsEnabled</key>\n  <true/>\n  <key>disallowBundleIDs</key>\n  <array>\n{}</array>\n</dict>\n</plist>\n",
                items_xml
            );
            Self::write_tracked_file(
                runner,
                &mut meta,
                "/Library/Managed Preferences/com.apple.applicationaccess.new.plist",
                &xml,
                Some(0o644),
            )?;
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            "Enforced macOS Managed Preferences system restrictions",
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
            .filter(|i| i.target_os == OsFamily::Macos)
            .collect();

        if !cfg.items.is_empty() && matching.is_empty() {
            if let Some(prev) = previous {
                execute_metadata_cleanup(&prev.rollback_metadata, runner)?;
            }
            return Ok(ApplyOutcome::skipped(
                "No custom.raw_setting items target MACOS",
            ));
        }

        let mut meta = RollbackMetadata::default();
        for item in &matching {
            match item.engine.trim().to_uppercase().as_str() {
                "PLIST" | "DEFAULTS" => {
                    let ptype = match item.value_type.trim().to_uppercase().as_str() {
                        "INT" | "INTEGER" => "int",
                        "BOOL" | "BOOLEAN" => "bool",
                        "FLOAT" => "float",
                        _ => "string",
                    };
                    Self::write_tracked_plist(runner, &mut meta, &item.path, &item.key, ptype, &item.value)?;
                }
                "SYSCTL" => {
                    let key_name = if item.key.trim().is_empty() {
                        &item.path
                    } else {
                        &item.key
                    };
                    let arg = format!("{}={}", key_name, item.value);
                    runner.run_cmd("sysctl", &["-w", &arg])?;
                }
                "FILE" | "CONFIG_FILE" => {
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        &item.path,
                        &item.value,
                        Some(0o644),
                    )?;
                }
                other => {
                    return Ok(ApplyOutcome::skipped(format!(
                        "Unsupported raw_setting engine '{}' on MACOS",
                        other
                    )));
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        Self::cleanup_stale_plists(previous, &meta.plist_keys, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Applied {} custom raw setting(s) on MACOS", matching.len()),
            meta,
        ))
    }
}

impl PlatformEnforcer for MacOsEnforcer {
    fn os_family(&self) -> OsFamily {
        OsFamily::Macos
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
                "Unsupported ruleType '{}' on MACOS",
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
                let _ = runner.run_cmd(
                    "dseditgroup",
                    &["-o", "delete", "com.apple.access_loginwindow"],
                )?;
            }
            "access.local_admins" => {
                // SAFETY: Remove ONLY agent-added principals recorded in rollback_metadata!
                for principal in &meta.added_principals {
                    let t_flag = match principal.kind {
                        PrincipalKind::User => "user",
                        PrincipalKind::Group => "group",
                    };
                    let out = runner.run_cmd(
                        "dseditgroup",
                        &[
                            "-o",
                            "edit",
                            "-d",
                            &principal.name,
                            "-t",
                            t_flag,
                            &principal.target_group,
                        ],
                    )?;
                    if out.exit_code != 0 {
                        return Err(format!(
                            "Failed to roll back macOS admin '{}': {}",
                            principal.name,
                            out.stderr.trim()
                        ));
                    }
                }
            }
            "workspace.network_shares" => {
                for share in &meta.mounted_shares {
                    let _ = runner.run_cmd("diskutil", &["unmount", "force", &share.mount_target])?;
                }
            }
            "workspace.printers" => {
                for prn in &meta.managed_printers {
                    let _ = runner.run_cmd("lpadmin", &["-x", prn])?;
                }
            }
            "security.firewall" => {
                for anchor in &meta.firewall_rules {
                    let _ = runner.run_cmd("pfctl", &["-a", anchor, "-F", "all"])?;
                }
            }
            _ => {}
        }

        execute_metadata_cleanup(meta, runner)?;

        Ok(format!("Rolled back '{}' on MACOS", record.rule_type))
    }
}

fn parse_dscl_group_membership(stdout: &str) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("GroupMembership:")
            .unwrap_or(trimmed);
        for token in rest.split_whitespace() {
            if !token.is_empty() && token != "GroupMembership:" {
                members.insert(token.to_lowercase());
            }
        }
    }
    members
}

fn build_macos_chromium_plist(cfg: &BrowserConfig) -> String {
    let startup_code = match cfg.restore_on_startup {
        BrowserRestoreMode::Homepage => 4,
        BrowserRestoreMode::LastSession => 1,
    };
    let mut entries = String::new();
    if let Some(url) = cfg.homepage_url.as_deref().filter(|s| !s.is_empty()) {
        entries.push_str(&format!(
            "  <key>HomepageLocation</key>\n  <string>{}</string>\n",
            xml_escape(url)
        ));
    }
    entries.push_str(&format!(
        "  <key>RestoreOnStartup</key>\n  <integer>{}</integer>\n",
        startup_code
    ));
    entries.push_str(&format!(
        "  <key>IncognitoModeAvailability</key>\n  <integer>{}</integer>\n",
        if cfg.disable_incognito { 1 } else { 0 }
    ));
    entries.push_str(&format!(
        "  <key>PasswordManagerEnabled</key>\n  <{}/>\n",
        if cfg.disable_password_manager {
            "false"
        } else {
            "true"
        }
    ));
    if !cfg.force_extensions.is_empty() {
        entries.push_str("  <key>ExtensionInstallForcelist</key>\n  <array>\n");
        for ext in &cfg.force_extensions {
            entries.push_str(&format!("    <string>{}</string>\n", xml_escape(ext)));
        }
        entries.push_str("  </array>\n");
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n{}</dict>\n</plist>\n",
        entries
    )
}
