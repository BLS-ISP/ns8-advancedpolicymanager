pub mod api;
pub mod cli;
pub mod config;
pub mod engine;
pub mod enforcers;
pub mod models;
pub mod runner;
pub mod state;

use crate::api::AgentApiClient;
use crate::config::{
    detect_arch, detect_current_user, detect_hostname, detect_os_family, detect_os_version,
    load_or_create_machine_id, normalize_server_url, AgentConfig,
};
use crate::engine::sync_desired_state;
use crate::models::{
    CheckinRequest, ComplianceReportRequest, ComplianceReportResponse, EnrollRequest, OsFamily,
};
use crate::runner::{DryRunOrMockRunner, RealSystemRunner, SystemRunner};
use crate::state::AppliedState;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Runs enrollment against `server_url` and persists `agent_config.json` inside `state_dir`.
pub fn execute_enroll(
    server_url: &str,
    enrollment_token: &str,
    state_dir: &Path,
    hostname_override: Option<&str>,
    os_override: Option<OsFamily>,
) -> Result<AgentConfig, String> {
    let normalized_url = normalize_server_url(server_url);
    let os_family = os_override.unwrap_or_else(detect_os_family);
    let hostname = hostname_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(detect_hostname);
    let os_version = detect_os_version(os_family);
    let arch = detect_arch();
    let machine_id = load_or_create_machine_id(state_dir, &hostname);

    let mut idem_hasher = Sha256::new();
    idem_hasher.update(enrollment_token.as_bytes());
    idem_hasher.update(b":");
    idem_hasher.update(hostname.as_bytes());
    idem_hasher.update(b":");
    idem_hasher.update(machine_id.as_bytes());
    let idem_key = format!("enroll-{:x}", idem_hasher.finalize());

    let req = EnrollRequest {
        enrollment_token: enrollment_token.trim().to_string(),
        hostname: hostname.clone(),
        os_family,
        os_version,
        arch,
        agent_version: version().to_string(),
        machine_id,
    };

    let client = AgentApiClient::new(&normalized_url);
    let resp = client.enroll(&req, Some(&idem_key[..32]))?;

    let cfg = AgentConfig {
        server_url: normalized_url,
        device_id: resp.device_id,
        device_token: resp.device_token,
        poll_interval_seconds: resp.poll_interval_seconds.max(5),
        hostname,
        os_family,
    };
    cfg.save(state_dir)?;
    Ok(cfg)
}

#[derive(Debug)]
pub struct SyncCycleResult {
    pub poll_interval_seconds: u64,
    pub report: ComplianceReportRequest,
    pub server_ack: ComplianceReportResponse,
}

/// Performs a complete check-in -> rollback -> enforce -> persist -> compliance report cycle.
pub fn execute_sync_once(
    state_dir: &Path,
    dry_run: bool,
    current_user_override: Option<&str>,
    os_override: Option<OsFamily>,
) -> Result<SyncCycleResult, String> {
    let mut cfg = AgentConfig::load(state_dir)?;
    let mut applied_state = AppliedState::load(state_dir)?;

    let effective_os = os_override.unwrap_or(cfg.os_family);
    let os_version = detect_os_version(effective_os);
    let current_user = current_user_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(detect_current_user);

    let client = AgentApiClient::new(&cfg.server_url);
    let checkin_req = CheckinRequest {
        hostname: cfg.hostname.clone(),
        os_family: effective_os,
        os_version,
        agent_version: version().to_string(),
        current_user,
        applied_revision: applied_state.applied_revision,
    };

    let bundle = client.checkin(&cfg.device_token, &checkin_req)?;

    let runner_box: Box<dyn SystemRunner> = if dry_run {
        Box::new(DryRunOrMockRunner::new(true))
    } else {
        Box::new(RealSystemRunner::new())
    };

    let report = sync_desired_state(effective_os, &bundle, &mut applied_state, runner_box.as_ref());

    applied_state.save(state_dir)?;

    let new_interval = bundle.poll_interval_seconds.max(5);
    if new_interval != cfg.poll_interval_seconds {
        cfg.poll_interval_seconds = new_interval;
        let _ = cfg.save(state_dir);
    }

    let server_ack = client.report_compliance(&cfg.device_token, &report)?;

    Ok(SyncCycleResult {
        poll_interval_seconds: new_interval,
        report,
        server_ack,
    })
}
