use clap::Parser;
use ns8_policy_agent::cli::{Cli, Commands};
use ns8_policy_agent::config::{default_state_dir, AgentConfig};
use ns8_policy_agent::state::AppliedState;
use ns8_policy_agent::{execute_enroll, execute_sync_once};
use serde_json::json;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Enroll {
            server,
            token,
            state_dir,
            hostname,
            os_override,
        } => {
            let dir = state_dir.unwrap_or_else(default_state_dir);
            let cfg = execute_enroll(
                &server,
                &token,
                &dir,
                hostname.as_deref(),
                os_override,
            )?;
            println!(
                "Enrolled successfully: deviceId={} hostname={} osFamily={} pollIntervalSeconds={}s (saved in {})",
                cfg.device_id,
                cfg.hostname,
                cfg.os_family,
                cfg.poll_interval_seconds,
                AgentConfig::config_path(&dir).display()
            );
            Ok(())
        }
        Commands::Sync {
            once: _,
            dry_run,
            state_dir,
            current_user,
            os_override,
        } => {
            let dir = state_dir.unwrap_or_else(default_state_dir);
            let result = execute_sync_once(
                &dir,
                dry_run,
                current_user.as_deref(),
                os_override,
            )?;
            println!(
                "Sync complete{}: revision={} status={} items={} acknowledged={}",
                if dry_run { " (dry-run)" } else { "" },
                result.report.applied_revision,
                result.report.status,
                result.report.items.len(),
                result.server_ack.acknowledged
            );
            for item in &result.report.items {
                println!(
                    "  - [{}] {} -> {}: {}",
                    item.action, item.rule_type, item.status, item.message
                );
            }
            Ok(())
        }
        Commands::Daemon {
            state_dir,
            dry_run,
            current_user,
            os_override,
        } => {
            let dir = state_dir.unwrap_or_else(default_state_dir);
            let initial_cfg = AgentConfig::load(&dir)?;
            let mut poll_secs = initial_cfg.poll_interval_seconds.max(5);
            println!(
                "Starting ns8-policy-agent daemon{} for deviceId={} (poll interval: {}s)",
                if dry_run { " (dry-run)" } else { "" },
                initial_cfg.device_id,
                poll_secs
            );

            loop {
                match execute_sync_once(
                    &dir,
                    dry_run,
                    current_user.as_deref(),
                    os_override,
                ) {
                    Ok(res) => {
                        poll_secs = res.poll_interval_seconds.max(5);
                        println!(
                            "[daemon] Sync OK: revision={} status={} items={} (next check-in in {}s)",
                            res.report.applied_revision,
                            res.report.status,
                            res.report.items.len(),
                            poll_secs
                        );
                    }
                    Err(err) => {
                        eprintln!(
                            "[daemon] Sync cycle failed: {} (retrying in {}s)",
                            err, poll_secs
                        );
                    }
                }
                thread::sleep(Duration::from_secs(poll_secs));
            }
        }
        Commands::Status { state_dir, json } => {
            let dir = state_dir.unwrap_or_else(default_state_dir);
            let cfg = AgentConfig::load(&dir)?;
            let state = AppliedState::load(&dir)?;

            if json {
                let payload = json!({
                    "enrolled": true,
                    "serverUrl": cfg.server_url,
                    "deviceId": cfg.device_id,
                    "hostname": cfg.hostname,
                    "osFamily": cfg.os_family,
                    "pollIntervalSeconds": cfg.poll_interval_seconds,
                    "appliedRevision": state.applied_revision,
                    "stateHash": state.state_hash,
                    "managedRules": state.managed_rules,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
                return Ok(());
            }

            println!("NS8 Policy Agent Status (v{})", ns8_policy_agent::version());
            println!("  State Directory : {}", dir.display());
            println!("  Server URL      : {}", cfg.server_url);
            println!("  Device ID       : {}", cfg.device_id);
            println!("  Hostname        : {}", cfg.hostname);
            println!("  OS Family       : {}", cfg.os_family);
            println!("  Poll Interval   : {}s", cfg.poll_interval_seconds);
            println!("  Applied Revision: {}", state.applied_revision);
            println!(
                "  State Hash      : {}",
                if state.state_hash.is_empty() {
                    "(none)"
                } else {
                    &state.state_hash
                }
            );
            println!("  Managed Rules   : {}", state.managed_rules.len());
            for (rule_type, rec) in &state.managed_rules {
                println!(
                    "    * {} (ruleId={}, appliedAt={})",
                    rule_type,
                    if rec.rule_id.is_empty() { "-" } else { &rec.rule_id },
                    rec.applied_at
                );
            }
            Ok(())
        }
    }
}
