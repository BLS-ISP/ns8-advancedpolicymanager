use crate::enforcers::{
    build_chromium_policy_json, build_firefox_policies_json, execute_metadata_cleanup, sanitize_id,
    ApplyOutcome, PlatformEnforcer,
};
use crate::models::{
    BrowserConfig, BrowserTarget, FirewallConfig, FirewallInboundPolicy, LocalAdminsConfig,
    LoginAccessConfig, LoginAccessMode, NetworkSharesConfig, OsFamily, PolicyRule, PrintersConfig,
    RawSettingConfig, ScreenLockConfig, ScriptTrigger, ScriptsConfig, ShareProtocol,
    SystemRestrictionsConfig, UsbStorageConfig, UsbStorageMode, WallpaperConfig, WallpaperFitMode,
};
use crate::runner::SystemRunner;
use crate::state::{
    AppliedRuleRecord, ManagedPrincipal, ManagedShare, PrincipalKind, RollbackMetadata,
};
use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub struct LinuxEnforcer;

impl LinuxEnforcer {
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

    fn apply_login_access(
        &self,
        rule: &PolicyRule,
        previous: Option<&AppliedRuleRecord>,
        runner: &dyn SystemRunner,
    ) -> Result<ApplyOutcome, String> {
        let cfg: LoginAccessConfig = serde_json::from_value(rule.config.clone())
            .map_err(|e| format!("Invalid access.login_access config: {}", e))?;

        let mut meta = RollbackMetadata::default();
        let pam_path = "/etc/security/access.d/90-ns8-policy.conf";
        let ssh_path = "/etc/ssh/sshd_config.d/90-ns8-policy-access.conf";

        let mut pam_lines = vec!["# Managed by ns8-policy-agent".to_string()];
        for dg in &cfg.deny_groups {
            pam_lines.push(format!("- : ({}) : ALL", dg));
        }
        pam_lines.push("+ : root : ALL".to_string());

        match cfg.mode {
            LoginAccessMode::AllowAll => {
                pam_lines.push("+ : ALL : ALL".to_string());
            }
            LoginAccessMode::AllowList => {
                for g in &cfg.allowed_groups {
                    pam_lines.push(format!("+ : ({}) : ALL", g));
                }
                for u in &cfg.allowed_users {
                    pam_lines.push(format!("+ : {} : ALL", u));
                }
                pam_lines.push("- : ALL : ALL".to_string());
            }
        }
        pam_lines.push(String::new());
        Self::write_tracked_file(runner, &mut meta, pam_path, &pam_lines.join("\n"), Some(0o644))?;

        let mut ssh_lines = vec!["# Managed by ns8-policy-agent".to_string()];
        if !cfg.deny_groups.is_empty() {
            ssh_lines.push(format!("DenyGroups {}", quote_ssh_principals(&cfg.deny_groups)));
        }
        if cfg.mode == LoginAccessMode::AllowList {
            if !cfg.allowed_groups.is_empty() {
                ssh_lines.push(format!(
                    "AllowGroups root sudo wheel {}",
                    quote_ssh_principals(&cfg.allowed_groups)
                ));
            }
            if !cfg.allowed_users.is_empty() {
                ssh_lines.push(format!(
                    "AllowUsers root {}",
                    quote_ssh_principals(&cfg.allowed_users)
                ));
            }
        }
        ssh_lines.push(String::new());
        Self::write_tracked_file(runner, &mut meta, ssh_path, &ssh_lines.join("\n"), Some(0o644))?;

        let _ = runner.run_cmd("systemctl", &["reload-or-restart", "sshd"])?;
        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        let mode_label = match cfg.mode {
            LoginAccessMode::AllowAll => "ALLOW_ALL",
            LoginAccessMode::AllowList => "ALLOW_LIST",
        };
        Ok(ApplyOutcome::applied(
            format!("Configured Linux PAM & SSH login access ({})", mode_label),
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

        let prev_added_users: BTreeSet<String> = previous
            .map(|p| {
                p.rollback_metadata
                    .added_principals
                    .iter()
                    .filter(|m| m.kind == PrincipalKind::User)
                    .map(|m| m.name.clone())
                    .collect()
            })
            .unwrap_or_default();

        let existing_sudo_members = read_linux_sudo_members(runner)?;

        // Remove previously added sudo users that are no longer desired
        if let Some(prev) = previous {
            for old_p in &prev.rollback_metadata.added_principals {
                if old_p.kind == PrincipalKind::User
                    && !cfg.admin_users.iter().any(|u| u.trim() == old_p.name)
                {
                    let _ = runner.run_cmd("gpasswd", &["-d", &old_p.name, &old_p.target_group])?;
                }
            }
        }

        let mut meta = RollbackMetadata::default();
        let sudo_spec = if cfg.passwordless_sudo {
            "ALL=(ALL:ALL) NOPASSWD: ALL"
        } else {
            "ALL=(ALL:ALL) ALL"
        };

        let mut sudoers_lines = vec![
            "# Managed by ns8-policy-agent - DO NOT EDIT".to_string(),
        ];
        for grp in &cfg.admin_groups {
            let trimmed = grp.trim();
            if !trimmed.is_empty() {
                sudoers_lines.push(format!("%\"{}\" {}", trimmed, sudo_spec));
            }
        }
        for usr in &cfg.admin_users {
            let trimmed = usr.trim();
            if trimmed.is_empty() {
                continue;
            }
            sudoers_lines.push(format!("{} {}", trimmed, sudo_spec));

            let is_preexisting_unmanaged =
                existing_sudo_members.contains(trimmed) && !prev_added_users.contains(trimmed);
            if is_preexisting_unmanaged {
                // SAFETY: Do not record pre-existing sudo members in rollbackMetadata!
                continue;
            }

            if !existing_sudo_members.contains(trimmed) {
                let out = runner.run_cmd("usermod", &["-aG", "sudo", trimmed])?;
                if out.exit_code != 0 {
                    return Err(format!(
                        "Failed to add user '{}' to sudo group: {}",
                        trimmed,
                        out.stderr.trim()
                    ));
                }
            }

            meta.added_principals.push(ManagedPrincipal {
                name: trimmed.to_string(),
                kind: PrincipalKind::User,
                target_group: "sudo".to_string(),
            });
        }
        sudoers_lines.push(String::new());

        let sudoers_path = "/etc/sudoers.d/90-ns8-policy-admins";
        Self::write_tracked_file(
            runner,
            &mut meta,
            sudoers_path,
            &sudoers_lines.join("\n"),
            Some(0o440),
        )?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!(
                "Configured Linux sudoers drop-in ({} group(s), {} agent-added user(s))",
                cfg.admin_groups.len(),
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
                .unwrap_or_else(|| format!("/mnt/{}", sanitize_id(&mount.name)));
            let remote_norm = if mount.protocol == ShareProtocol::Smb {
                mount.remote_path.replace('\\', "/")
            } else {
                mount.remote_path.clone()
            };
            desired.push((mount.id.clone(), mount.protocol, mount_path, remote_norm, mount.reconnect_at_logon));
        }

        if let Some(prev) = previous {
            for old_share in &prev.rollback_metadata.mounted_shares {
                let unchanged = desired.iter().any(|(id, _, mp, rem, _)| {
                    id == &old_share.id
                        && mp == &old_share.mount_target
                        && rem == &old_share.remote_path
                });
                if !unchanged {
                    let _ = runner.run_cmd("umount", &["-l", &old_share.mount_target])?;
                }
            }
        }

        let mut fstab_lines = vec!["# Managed by ns8-policy-agent".to_string()];
        for (id, protocol, mount_path, remote_norm, reconnect) in desired {
            runner.run_cmd("mkdir", &["-p", &mount_path])?;
            let fs_type = match protocol {
                ShareProtocol::Smb => "cifs",
                ShareProtocol::Nfs => "nfs",
            };
            let opts = match protocol {
                ShareProtocol::Smb => "rw,_netdev,nofail,sec=krb5i",
                ShareProtocol::Nfs => "rw,_netdev,nofail",
            };
            let out = runner.run_cmd(
                "mount",
                &["-t", fs_type, "-o", opts, &remote_norm, &mount_path],
            )?;
            if out.exit_code != 0 {
                return Err(format!(
                    "Failed to mount {} share '{}' at '{}': {}",
                    fs_type,
                    remote_norm,
                    mount_path,
                    out.stderr.trim()
                ));
            }
            if reconnect {
                fstab_lines.push(format!("{} {} {} {} 0 0", remote_norm, mount_path, fs_type, opts));
            }
            meta.mounted_shares.push(ManagedShare {
                id,
                mount_target: mount_path,
                remote_path: remote_norm,
            });
        }
        fstab_lines.push(String::new());
        Self::write_tracked_file(
            runner,
            &mut meta,
            "/etc/fstab.d/90-ns8-shares.fstab",
            &fstab_lines.join("\n"),
            Some(0o644),
        )?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Mounted {} Linux network share(s)", meta.mounted_shares.len()),
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
                    "lpadmin failed for '{}': {}",
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
            format!("Configured {} CUPS printer(s) on Linux", meta.managed_printers.len()),
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
            let Some(bash_body) = scr.linux_bash.as_deref() else {
                continue;
            };
            if bash_body.trim().is_empty() {
                continue;
            }
            let safe_id = sanitize_id(&scr.id);
            let script_path = format!("/etc/ns8-policy-agent/scripts/{}.sh", safe_id);
            let script_content = format!(
                "#!/usr/bin/env bash\n# Managed by ns8-policy-agent: {}\nset -e\n{}\n",
                scr.name, bash_body
            );
            Self::write_tracked_file(runner, &mut meta, &script_path, &script_content, Some(0o755))?;

            match scr.trigger {
                ScriptTrigger::Logon => {
                    let profile_hook = format!("/etc/profile.d/90-ns8-script-{}.sh", safe_id);
                    let hook_content = format!(
                        "#!/bin/sh\ntimeout {}s \"{}\" >/dev/null 2>&1 || true\n",
                        scr.timeout_seconds, script_path
                    );
                    Self::write_tracked_file(runner, &mut meta, &profile_hook, &hook_content, Some(0o644))?;
                }
                ScriptTrigger::Startup => {
                    let unit_name = format!("ns8-script-{}.service", safe_id);
                    let unit_path = format!("/etc/systemd/system/{}", unit_name);
                    let unit_content = format!(
                        "[Unit]\nDescription=NS8 Policy Script: {}\nAfter=network-online.target\n\n[Service]\nType=oneshot\nTimeoutStartSec={}\nExecStart={}\n\n[Install]\nWantedBy=multi-user.target\n",
                        scr.name, scr.timeout_seconds, script_path
                    );
                    Self::write_tracked_file(runner, &mut meta, &unit_path, &unit_content, Some(0o644))?;
                    runner.run_cmd("systemctl", &["enable", &unit_name])?;
                    meta.scheduled_tasks.push(unit_name);
                }
            }
        }

        if let Some(prev) = previous {
            for old_unit in &prev.rollback_metadata.scheduled_tasks {
                if !meta.scheduled_tasks.iter().any(|u| u == old_unit) {
                    let _ = runner.run_cmd("systemctl", &["disable", old_unit])?;
                }
            }
        }
        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Deployed {} Linux workspace script(s)", meta.managed_files.len()),
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
        let dconf_path = "/etc/dconf/db/local.d/90-ns8-screen-lock";
        let locks_path = "/etc/dconf/db/local.d/locks/90-ns8-screen-lock";

        let dconf_body = format!(
            "[org/gnome/desktop/session]\nidle-delay=uint32 {}\n\n[org/gnome/desktop/screensaver]\nlock-enabled={}\nlock-delay=uint32 {}\n",
            cfg.idle_timeout_seconds,
            if cfg.require_password_on_wake { "true" } else { "false" },
            cfg.lock_delay_seconds
        );
        let locks_body = "/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-enabled\n/org/gnome/desktop/screensaver/lock-delay\n";

        Self::write_tracked_file(runner, &mut meta, dconf_path, &dconf_body, Some(0o644))?;
        Self::write_tracked_file(runner, &mut meta, locks_path, locks_body, Some(0o644))?;
        runner.run_cmd("dconf", &["update"])?;

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Enforced Linux dconf screen lock ({}s)", cfg.idle_timeout_seconds),
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
        let modprobe_path = "/etc/modprobe.d/90-ns8-usb-storage.conf";
        let udev_path = "/etc/udev/rules.d/90-ns8-usb-storage.rules";

        let msg = match cfg.mode {
            UsbStorageMode::Block => {
                Self::write_tracked_file(
                    runner,
                    &mut meta,
                    modprobe_path,
                    "install usb-storage /bin/false\nblacklist usb-storage\nblacklist uas\n",
                    Some(0o644),
                )?;
                Self::write_tracked_file(
                    runner,
                    &mut meta,
                    udev_path,
                    "ACTION==\"add\", SUBSYSTEMS==\"usb\", DRIVERS==\"usb-storage\", ATTR{authorized}=\"0\"\n",
                    Some(0o644),
                )?;
                "Blocked Linux USB mass storage via modprobe & udev".to_string()
            }
            UsbStorageMode::ReadOnly => {
                Self::write_tracked_file(
                    runner,
                    &mut meta,
                    udev_path,
                    "SUBSYSTEM==\"block\", ENV{ID_BUS}==\"usb\", ATTR{ro}=\"1\"\n",
                    Some(0o644),
                )?;
                "Configured Linux USB mass storage as READ_ONLY via udev".to_string()
            }
            UsbStorageMode::Allow => {
                "Allowed Linux USB mass storage (removed block/ro rules)".to_string()
            }
        };

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        runner.run_cmd("udevadm", &["control", "--reload-rules"])?;

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

        let mut meta = RollbackMetadata::default();
        let nft_path = "/etc/nftables.d/90-ns8-firewall.nft";

        if !cfg.is_enabled {
            let _ = runner.run_cmd("nft", &["delete", "table", "inet", "ns8_policy_firewall"])?;
            Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
            return Ok(ApplyOutcome::applied("Disabled Linux nftables policy table", meta));
        }

        let policy_verdict = match cfg.default_inbound {
            FirewallInboundPolicy::Block => "drop",
            FirewallInboundPolicy::Allow => "accept",
        };

        let mut rules = Vec::new();
        rules.push("table inet ns8_policy_firewall {".to_string());
        rules.push("  chain input {".to_string());
        rules.push(format!(
            "    type filter hook input priority 0; policy {};",
            policy_verdict
        ));
        rules.push("    iif \"lo\" accept".to_string());
        rules.push("    ct state established,related accept".to_string());
        if cfg.allow_stealth_mode {
            rules.push("    ip protocol icmp icmp type echo-request drop".to_string());
            rules.push("    ip6 nexthdr icmpv6 icmpv6 type echo-request drop".to_string());
        }
        for port in &cfg.allowed_tcp_ports {
            rules.push(format!("    tcp dport {} accept", port));
        }
        for port in &cfg.allowed_udp_ports {
            rules.push(format!("    udp dport {} accept", port));
        }
        rules.push("  }".to_string());
        rules.push("}".to_string());
        rules.push(String::new());

        Self::write_tracked_file(runner, &mut meta, nft_path, &rules.join("\n"), Some(0o600))?;
        let out = runner.run_cmd("nft", &["-f", nft_path])?;
        if out.exit_code != 0 {
            return Err(format!("nft failed to load {}: {}", nft_path, out.stderr.trim()));
        }
        meta.firewall_rules.push("ns8_policy_firewall".to_string());

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!(
                "Loaded Linux nftables firewall policy (default={}, tcp={}, udp={})",
                policy_verdict,
                cfg.allowed_tcp_ports.len(),
                cfg.allowed_udp_ports.len()
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
        let chromium_json = build_chromium_policy_json(&cfg);

        for target in &cfg.targets {
            match target {
                BrowserTarget::Chrome => {
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/etc/opt/chrome/policies/managed/90-ns8-policy.json",
                        &chromium_json,
                        Some(0o644),
                    )?;
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/etc/chromium/policies/managed/90-ns8-policy.json",
                        &chromium_json,
                        Some(0o644),
                    )?;
                }
                BrowserTarget::Edge => {
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/etc/opt/edge/policies/managed/90-ns8-policy.json",
                        &chromium_json,
                        Some(0o644),
                    )?;
                }
                BrowserTarget::Firefox => {
                    let ff_json = build_firefox_policies_json(&cfg);
                    Self::write_tracked_file(
                        runner,
                        &mut meta,
                        "/etc/firefox/policies/policies.json",
                        &ff_json,
                        Some(0o644),
                    )?;
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            format!("Applied Linux managed browser policies ({} target(s))", cfg.targets.len()),
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
        let dconf_path = "/etc/dconf/db/local.d/90-ns8-wallpaper";
        let lock_path = "/etc/dconf/db/local.d/locks/90-ns8-wallpaper";

        let opt = match cfg.fit_mode {
            WallpaperFitMode::Fill => "zoom",
            WallpaperFitMode::Fit => "scaled",
            WallpaperFitMode::Center => "centered",
        };
        let content = format!(
            "[org/gnome/desktop/background]\npicture-uri='{}'\npicture-uri-dark='{}'\npicture-options='{}'\n",
            cfg.image_url, cfg.image_url, opt
        );
        Self::write_tracked_file(runner, &mut meta, dconf_path, &content, Some(0o644))?;

        if cfg.is_locked {
            let locks = "/org/gnome/desktop/background/picture-uri\n/org/gnome/desktop/background/picture-uri-dark\n/org/gnome/desktop/background/picture-options\n";
            Self::write_tracked_file(runner, &mut meta, lock_path, locks, Some(0o644))?;
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        runner.run_cmd("dconf", &["update"])?;

        Ok(ApplyOutcome::applied(
            format!("Configured Linux GNOME desktop wallpaper ({})", cfg.image_url),
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
            let polkit_rule = "polkit.addRule(function(action, subject) {\n  if (action.id.indexOf('org.gnome.controlcenter.') === 0 && !subject.isInGroup('sudo') && !subject.isInGroup('wheel')) {\n    return polkit.Result.NO;\n  }\n});\n";
            Self::write_tracked_file(
                runner,
                &mut meta,
                "/etc/polkit-1/rules.d/90-ns8-restrictions.rules",
                polkit_rule,
                Some(0o644),
            )?;
        }

        if cfg.disable_registry_tools {
            let dconf_restrict = "[ca/desrt/dconf-editor]\nshow-warning=true\n";
            Self::write_tracked_file(
                runner,
                &mut meta,
                "/etc/dconf/db/local.d/90-ns8-restrictions",
                dconf_restrict,
                Some(0o644),
            )?;
            runner.run_cmd("dconf", &["update"])?;
        }

        if cfg.disable_terminal_for_standard_users {
            let term_script = "# Managed by ns8-policy-agent\nif ! id -Gn 2>/dev/null | grep -qwE 'sudo|wheel|root'; then\n  export NS8_TERMINAL_RESTRICTED=1\nfi\n";
            Self::write_tracked_file(
                runner,
                &mut meta,
                "/etc/profile.d/90-ns8-terminal-restrict.sh",
                term_script,
                Some(0o644),
            )?;
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;

        Ok(ApplyOutcome::applied(
            "Enforced Linux desktop & polkit system restrictions",
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
            .filter(|i| i.target_os == OsFamily::Linux)
            .collect();

        if !cfg.items.is_empty() && matching.is_empty() {
            if let Some(prev) = previous {
                execute_metadata_cleanup(&prev.rollback_metadata, runner)?;
            }
            return Ok(ApplyOutcome::skipped(
                "No custom.raw_setting items target LINUX",
            ));
        }

        let mut meta = RollbackMetadata::default();
        let mut needs_dconf_update = false;
        let mut needs_sysctl_reload = false;

        for item in &matching {
            let safe_id = sanitize_id(&item.id);
            match item.engine.trim().to_uppercase().as_str() {
                "DCONF" => {
                    let section = item.path.trim_matches('/');
                    let formatted_val = match item.value_type.trim().to_uppercase().as_str() {
                        "INT" | "BOOL" | "BOOLEAN" => item.value.clone(),
                        _ => format!("'{}'", item.value),
                    };
                    let file_path = format!("/etc/dconf/db/local.d/95-ns8-raw-{}", safe_id);
                    let content = format!("[{}]\n{}={}\n", section, item.key, formatted_val);
                    Self::write_tracked_file(runner, &mut meta, &file_path, &content, Some(0o644))?;
                    needs_dconf_update = true;
                }
                "SYSCTL" => {
                    let sysctl_key = if item.key.trim().is_empty() {
                        &item.path
                    } else {
                        &item.key
                    };
                    let file_path = format!("/etc/sysctl.d/95-ns8-raw-{}.conf", safe_id);
                    let content = format!("{} = {}\n", sysctl_key, item.value);
                    Self::write_tracked_file(runner, &mut meta, &file_path, &content, Some(0o644))?;
                    needs_sysctl_reload = true;
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
                        "Unsupported raw_setting engine '{}' on LINUX",
                        other
                    )));
                }
            }
        }

        Self::cleanup_stale_files(previous, &meta.managed_files, runner)?;
        if needs_dconf_update {
            runner.run_cmd("dconf", &["update"])?;
        }
        if needs_sysctl_reload {
            runner.run_cmd("sysctl", &["--system"])?;
        }

        Ok(ApplyOutcome::applied(
            format!("Applied {} custom raw setting(s) on LINUX", matching.len()),
            meta,
        ))
    }
}

impl PlatformEnforcer for LinuxEnforcer {
    fn os_family(&self) -> OsFamily {
        OsFamily::Linux
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
                "Unsupported ruleType '{}' on LINUX",
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
        let had_dconf = meta
            .managed_files
            .iter()
            .any(|p| p.starts_with("/etc/dconf/"));

        match record.rule_type.as_str() {
            "access.local_admins" => {
                // SAFETY: Remove ONLY agent-added principals recorded in rollback_metadata!
                for principal in &meta.added_principals {
                    if principal.kind == PrincipalKind::User {
                        let out = runner.run_cmd(
                            "gpasswd",
                            &["-d", &principal.name, &principal.target_group],
                        )?;
                        if out.exit_code != 0 {
                            return Err(format!(
                                "Failed to roll back sudo user '{}': {}",
                                principal.name,
                                out.stderr.trim()
                            ));
                        }
                    }
                }
            }
            "workspace.network_shares" => {
                for share in &meta.mounted_shares {
                    let _ = runner.run_cmd("umount", &["-l", &share.mount_target])?;
                }
            }
            "workspace.printers" => {
                for prn in &meta.managed_printers {
                    let _ = runner.run_cmd("lpadmin", &["-x", prn])?;
                }
            }
            "workspace.scripts" => {
                for unit in &meta.scheduled_tasks {
                    let _ = runner.run_cmd("systemctl", &["disable", unit])?;
                }
            }
            "security.firewall" => {
                for table in &meta.firewall_rules {
                    let _ = runner.run_cmd("nft", &["delete", "table", "inet", table])?;
                }
            }
            _ => {}
        }

        execute_metadata_cleanup(meta, runner)?;

        match record.rule_type.as_str() {
            "access.login_access" => {
                let _ = runner.run_cmd("systemctl", &["reload-or-restart", "sshd"])?;
            }
            "security.usb_storage" => {
                let _ = runner.run_cmd("udevadm", &["control", "--reload-rules"])?;
            }
            _ => {}
        }

        if had_dconf {
            let _ = runner.run_cmd("dconf", &["update"])?;
        }

        Ok(format!("Rolled back '{}' on LINUX", record.rule_type))
    }
}

fn quote_ssh_principals(items: &[String]) -> String {
    items
        .iter()
        .map(|s| {
            if s.contains(' ') {
                format!("\"{}\"", s)
            } else {
                s.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_linux_sudo_members(runner: &dyn SystemRunner) -> Result<BTreeSet<String>, String> {
    let mut members = BTreeSet::new();
    if let Some(etc_group) = runner.read_file("/etc/group")? {
        for line in etc_group.lines() {
            if let Some(rest) = line
                .strip_prefix("sudo:")
                .or_else(|| line.strip_prefix("wheel:"))
            {
                if let Some(users_csv) = rest.rsplit(':').next() {
                    for u in users_csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        members.insert(u.to_string());
                    }
                }
            }
        }
    }
    let out = runner.run_cmd("getent", &["group", "sudo"])?;
    if out.exit_code == 0 {
        for line in out.stdout.lines() {
            if let Some(users_csv) = line.trim().rsplit(':').next() {
                for u in users_csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    members.insert(u.to_string());
                }
            }
        }
    }
    Ok(members)
}
