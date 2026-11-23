use crate::models::OsFamily;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ns8-policy-agent",
    version,
    about = "Cross-platform policy enforcement and compliance agent for NS8 AdvancedPolicyManager"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Enroll this computer with the NS8 AdvancedPolicyManager server
    Enroll {
        /// Base URL of the NS8 AdvancedPolicyManager server (e.g. https://policies.example.org)
        #[arg(long)]
        server: String,

        /// Enrollment token (apm_enroll_...)
        #[arg(long)]
        token: String,

        /// Directory to store agent_config.json and applied_state.json
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Override detected hostname
        #[arg(long)]
        hostname: Option<String>,

        /// Override detected OS family (WINDOWS, LINUX, MACOS)
        #[arg(long, value_enum)]
        os_override: Option<OsFamily>,
    },

    /// Perform policy check-in, surgical rollback, enforcement, and compliance reporting
    Sync {
        /// Run a single check-in and enforcement cycle
        #[arg(long, default_value_t = false)]
        once: bool,

        /// Simulate OS commands, registry, and file writes without mutating the host system
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Directory containing agent_config.json and applied_state.json
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Override currently logged-in user reported during check-in
        #[arg(long)]
        current_user: Option<String>,

        /// Override OS family used for check-in and rule enforcement (WINDOWS, LINUX, MACOS)
        #[arg(long, value_enum)]
        os_override: Option<OsFamily>,
    },

    /// Run continuous background check-in loop honoring pollIntervalSeconds
    Daemon {
        /// Directory containing agent_config.json and applied_state.json
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Simulate OS commands, registry, and file writes without mutating the host system
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Optional current user override
        #[arg(long)]
        current_user: Option<String>,

        /// Optional OS family override (WINDOWS, LINUX, MACOS)
        #[arg(long, value_enum)]
        os_override: Option<OsFamily>,
    },

    /// Display enrollment info, last applied revision, and currently managed rules
    Status {
        /// Directory containing agent_config.json and applied_state.json
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Print status as machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}
