use crate::enforcers::enforcer_for_os;
use crate::models::{
    CheckinResponse, ComplianceAction, ComplianceItem, ComplianceItemStatus,
    ComplianceOverallStatus, ComplianceReportRequest, OsFamily,
};
use crate::runner::SystemRunner;
use crate::state::{compute_rules_hash, AppliedRuleRecord, AppliedState};
use chrono::Utc;
use std::collections::BTreeSet;

/// Executes a full Desired-State synchronization cycle:
/// 1. **Rollback Phase:** Any `ruleType` present in `applied_state.managed_rules` that is no longer
///    present in `bundle.effective_rules` (or no longer targets `target_os`) is rolled back via
///    `enforcer.rollback(...)`, emitting a `ROLLED_BACK` compliance item.
/// 2. **Enforce Phase:** Every rule in `bundle.effective_rules` is enforced idempotently via
///    `enforcer.apply(...)`, emitting an `ENFORCED` compliance item and updating `applied_state`.
pub fn sync_desired_state(
    target_os: OsFamily,
    bundle: &CheckinResponse,
    applied_state: &mut AppliedState,
    runner: &dyn SystemRunner,
) -> ComplianceReportRequest {
    let enforcer = enforcer_for_os(target_os);
    let mut items: Vec<ComplianceItem> = Vec::new();

    let incoming_rule_types: BTreeSet<String> = bundle
        .effective_rules
        .iter()
        .map(|r| r.rule_type.clone())
        .collect();

    // ------------------------------------------------------------------------
    // Phase 1: Surgical Rollback of removed rules
    // ------------------------------------------------------------------------
    let existing_keys: Vec<String> = applied_state.managed_rules.keys().cloned().collect();
    for rule_type in existing_keys {
        if !incoming_rule_types.contains(&rule_type) {
            if let Some(record) = applied_state.managed_rules.get(&rule_type).cloned() {
                match enforcer.rollback(&record, runner) {
                    Ok(msg) => {
                        applied_state.managed_rules.remove(&rule_type);
                        items.push(ComplianceItem {
                            rule_type,
                            action: ComplianceAction::RolledBack,
                            status: ComplianceItemStatus::Applied,
                            message: msg,
                        });
                    }
                    Err(err) => {
                        items.push(ComplianceItem {
                            rule_type,
                            action: ComplianceAction::RolledBack,
                            status: ComplianceItemStatus::Failed,
                            message: err,
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------------
    // Phase 2: Idempotent Enforcement of effective rules
    // ------------------------------------------------------------------------
    for rule in &bundle.effective_rules {
        if !rule.platforms.is_empty() && !rule.platforms.contains(&target_os) {
            // If previously applied on this OS before platform filter changed, roll it back cleanly
            if let Some(prev_rec) = applied_state.managed_rules.get(&rule.rule_type).cloned() {
                if enforcer.rollback(&prev_rec, runner).is_ok() {
                    applied_state.managed_rules.remove(&rule.rule_type);
                }
            }
            items.push(ComplianceItem {
                rule_type: rule.rule_type.clone(),
                action: ComplianceAction::Enforced,
                status: ComplianceItemStatus::SkippedUnsupported,
                message: format!("Rule does not target platform {}", target_os),
            });
            continue;
        }

        let previous = applied_state.managed_rules.get(&rule.rule_type);
        match enforcer.apply(rule, previous, runner) {
            Ok(outcome) => {
                match outcome.status {
                    ComplianceItemStatus::Applied => {
                        let record = AppliedRuleRecord {
                            rule_type: rule.rule_type.clone(),
                            rule_id: rule.rule_id.clone(),
                            applied_at: Utc::now().to_rfc3339(),
                            config_snapshot: rule.config.clone(),
                            rollback_metadata: outcome.rollback_metadata,
                        };
                        applied_state
                            .managed_rules
                            .insert(rule.rule_type.clone(), record);
                    }
                    ComplianceItemStatus::SkippedUnsupported => {
                        applied_state.managed_rules.remove(&rule.rule_type);
                    }
                    ComplianceItemStatus::Failed => {}
                }

                items.push(ComplianceItem {
                    rule_type: rule.rule_type.clone(),
                    action: ComplianceAction::Enforced,
                    status: outcome.status,
                    message: outcome.message,
                });
            }
            Err(err) => {
                items.push(ComplianceItem {
                    rule_type: rule.rule_type.clone(),
                    action: ComplianceAction::Enforced,
                    status: ComplianceItemStatus::Failed,
                    message: err,
                });
            }
        }
    }

    let overall_status = compute_overall_status(&items);
    if overall_status != ComplianceOverallStatus::Error {
        applied_state.applied_revision = bundle.bundle_revision;
        applied_state.state_hash = if bundle.state_hash.trim().is_empty() {
            compute_rules_hash(&bundle.effective_rules)
        } else {
            bundle.state_hash.clone()
        };
    }

    ComplianceReportRequest {
        applied_revision: bundle.bundle_revision,
        status: overall_status,
        items,
    }
}

pub fn compute_overall_status(items: &[ComplianceItem]) -> ComplianceOverallStatus {
    if items
        .iter()
        .any(|i| i.status == ComplianceItemStatus::Failed)
    {
        ComplianceOverallStatus::Error
    } else if items
        .iter()
        .any(|i| i.status == ComplianceItemStatus::SkippedUnsupported)
    {
        ComplianceOverallStatus::Degraded
    } else {
        ComplianceOverallStatus::Compliant
    }
}
