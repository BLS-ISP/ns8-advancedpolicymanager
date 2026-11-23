use ns8_policy_agent::config::AgentConfig;
use ns8_policy_agent::engine::sync_desired_state;
use ns8_policy_agent::models::{
    CheckinResponse, ComplianceAction, ComplianceItemStatus, ComplianceOverallStatus,
    ComplianceReportRequest, EnrollRequest, MergeStrategy, OsFamily, PolicyCategory, PolicyRule,
};
use ns8_policy_agent::runner::{CmdOutput, DryRunOrMockRunner, RecordedOp};
use ns8_policy_agent::state::AppliedState;
use ns8_policy_agent::{execute_enroll, execute_sync_once};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

fn make_rule(rule_type: &str, category: PolicyCategory, config: Value) -> PolicyRule {
    PolicyRule {
        rule_id: format!("rule-{}", rule_type.replace('.', "-")),
        category,
        rule_type: rule_type.to_string(),
        schema_version: 1,
        platforms: vec![OsFamily::Windows, OsFamily::Linux, OsFamily::Macos],
        merge_strategy: MergeStrategy::Override,
        config,
    }
}

fn full_12_rule_suite(target_os: OsFamily) -> Vec<PolicyRule> {
    let raw_item = match target_os {
        OsFamily::Windows => json!({
            "id": "raw-win-1",
            "targetOs": "WINDOWS",
            "engine": "REGISTRY",
            "path": r"HKLM\SOFTWARE\Policies\Custom",
            "key": "EnableFeature",
            "valueType": "INT",
            "value": "1"
        }),
        OsFamily::Linux => json!({
            "id": "raw-lin-1",
            "targetOs": "LINUX",
            "engine": "DCONF",
            "path": "/org/gnome/desktop/interface",
            "key": "clock-show-seconds",
            "valueType": "BOOL",
            "value": "true"
        }),
        OsFamily::Macos => json!({
            "id": "raw-mac-1",
            "targetOs": "MACOS",
            "engine": "PLIST",
            "path": "/Library/Preferences/com.apple.finder",
            "key": "AppleShowAllExtensions",
            "valueType": "BOOL",
            "value": "true"
        }),
    };

    vec![
        make_rule(
            "access.login_access",
            PolicyCategory::Access,
            json!({
                "mode": "ALLOW_LIST",
                "allowedGroups": ["Buchhaltung", "IT-Admins"],
                "allowedUsers": ["m.mueller"],
                "denyGroups": ["Gesperrt"]
            }),
        ),
        make_rule(
            "access.local_admins",
            PolicyCategory::Access,
            json!({
                "adminGroups": ["IT-Admins"],
                "adminUsers": ["s.weber"],
                "passwordlessSudo": true
            }),
        ),
        make_rule(
            "workspace.network_shares",
            PolicyCategory::Workspace,
            json!({
                "mounts": [
                    {
                        "id": "share-buchhaltung",
                        "name": "Buchhaltung",
                        "protocol": "SMB",
                        "remotePath": r"\\files.firma.local\buchhaltung",
                        "windowsDriveLetter": "X:",
                        "unixMountPath": "/mnt/buchhaltung",
                        "reconnectAtLogon": true
                    }
                ]
            }),
        ),
        make_rule(
            "workspace.printers",
            PolicyCategory::Workspace,
            json!({
                "printers": [
                    {
                        "id": "prn-og1",
                        "name": "Buerodrucker-OG1",
                        "uri": "ipp://print.firma.local/ipp/og1",
                        "isDefault": true,
                        "driverModel": "everywhere"
                    }
                ]
            }),
        ),
        make_rule(
            "workspace.scripts",
            PolicyCategory::Workspace,
            json!({
                "scripts": [
                    {
                        "id": "scr-logon-env",
                        "name": "Arbeitsplatz-Initialisierung",
                        "trigger": "LOGON",
                        "runAs": "USER",
                        "timeoutSeconds": 60,
                        "windowsPowershell": "Write-Output 'Ready'",
                        "linuxBash": "echo 'Ready'",
                        "macosZsh": "echo 'Ready'"
                    }
                ]
            }),
        ),
        make_rule(
            "security.screen_lock",
            PolicyCategory::Security,
            json!({
                "idleTimeoutSeconds": 300,
                "requirePasswordOnWake": true,
                "lockDelaySeconds": 5
            }),
        ),
        make_rule(
            "security.usb_storage",
            PolicyCategory::Security,
            json!({
                "mode": "BLOCK"
            }),
        ),
        make_rule(
            "security.firewall",
            PolicyCategory::Security,
            json!({
                "isEnabled": true,
                "defaultInbound": "BLOCK",
                "allowStealthMode": true,
                "allowedTcpPorts": [22, 3389],
                "allowedUdpPorts": [5353]
            }),
        ),
        make_rule(
            "desktop.browser",
            PolicyCategory::Desktop,
            json!({
                "targets": ["CHROME", "EDGE", "FIREFOX"],
                "homepageUrl": "https://intranet.firma.local",
                "restoreOnStartup": "HOMEPAGE",
                "disableIncognito": true,
                "disablePasswordManager": false,
                "forceExtensions": ["cjpalhdlnbpafiamejdnhcphjbkeiagm"]
            }),
        ),
        make_rule(
            "desktop.wallpaper",
            PolicyCategory::Desktop,
            json!({
                "imageUrl": "https://intranet.firma.local/wallpaper.jpg",
                "fitMode": "FILL",
                "isLocked": true
            }),
        ),
        make_rule(
            "desktop.system_restrictions",
            PolicyCategory::Desktop,
            json!({
                "disableControlPanel": true,
                "disableRegistryTools": true,
                "disableTerminalForStandardUsers": true
            }),
        ),
        make_rule(
            "custom.raw_setting",
            PolicyCategory::CustomFinetuning,
            json!({
                "items": [raw_item]
            }),
        ),
    ]
}

#[test]
fn contract_json_camel_case_and_upper_snake_enums() {
    assert_eq!(serde_json::to_string(&OsFamily::Windows).unwrap(), "\"WINDOWS\"");
    assert_eq!(serde_json::to_string(&OsFamily::Linux).unwrap(), "\"LINUX\"");
    assert_eq!(serde_json::to_string(&OsFamily::Macos).unwrap(), "\"MACOS\"");

    let enroll_req = EnrollRequest {
        enrollment_token: "apm_enroll_123".to_string(),
        hostname: "WIN-BUCH-01".to_string(),
        os_family: OsFamily::Windows,
        os_version: "Windows 11 Pro 24H2".to_string(),
        arch: "x86_64".to_string(),
        agent_version: "1.0.0".to_string(),
        machine_id: "hw-uuid-1234".to_string(),
    };
    let val = serde_json::to_value(&enroll_req).unwrap();
    assert_eq!(val["enrollmentToken"], "apm_enroll_123");
    assert_eq!(val["osFamily"], "WINDOWS");
    assert_eq!(val["osVersion"], "Windows 11 Pro 24H2");
    assert_eq!(val["agentVersion"], "1.0.0");
    assert_eq!(val["machineId"], "hw-uuid-1234");
}

#[test]
fn windows_enforcer_applies_and_rolls_back_all_12_rules() {
    let runner = DryRunOrMockRunner::new(false);
    runner.set_cmd_output(
        "net localgroup Administrators",
        CmdOutput::success(
            "Alias name     Administrators\r\nMembers\r\n-------------------------------------------------------------------------------\r\nAdministrator\r\nThe command completed successfully.\r\n",
        ),
    );

    let mut state = AppliedState::default();
    let bundle = CheckinResponse {
        device_id: "dev-win-1".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:win1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: full_12_rule_suite(OsFamily::Windows),
    };

    let report = sync_desired_state(OsFamily::Windows, &bundle, &mut state, &runner);
    assert_eq!(report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(report.items.len(), 12);
    assert!(report
        .items
        .iter()
        .all(|i| i.action == ComplianceAction::Enforced && i.status == ComplianceItemStatus::Applied));
    assert_eq!(state.managed_rules.len(), 12);

    // Spot-check key Windows enforcement artifacts
    assert_eq!(
        runner.get_registry(r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"),
        Some(("REG_DWORD".to_string(), "4".to_string()))
    );
    assert_eq!(
        runner.get_registry(r"HKLM\SOFTWARE\Policies\Google\Chrome", "HomepageLocation"),
        Some(("REG_SZ".to_string(), "https://intranet.firma.local".to_string()))
    );
    assert_eq!(
        runner.get_registry(r"HKLM\SOFTWARE\Policies\Custom", "EnableFeature"),
        Some(("REG_DWORD".to_string(), "1".to_string()))
    );
    assert!(runner.has_file(r"C:\Program Files\Mozilla Firefox\distribution\policies.json"));

    // Roll back all 12 rules cleanly
    let empty_bundle = CheckinResponse {
        device_id: "dev-win-1".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:empty".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };
    let rb_report = sync_desired_state(OsFamily::Windows, &empty_bundle, &mut state, &runner);
    assert_eq!(rb_report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(rb_report.items.len(), 12);
    assert!(rb_report.items.iter().all(|i| {
        i.action == ComplianceAction::RolledBack && i.status == ComplianceItemStatus::Applied
    }));
    assert!(state.managed_rules.is_empty());

    // USBSTOR Start restored to 3, Chrome/Custom registry keys and Firefox file cleaned up
    assert_eq!(
        runner.get_registry(r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"),
        Some(("REG_DWORD".to_string(), "3".to_string()))
    );
    assert_eq!(
        runner.get_registry(r"HKLM\SOFTWARE\Policies\Google\Chrome", "HomepageLocation"),
        None
    );
    assert_eq!(
        runner.get_registry(r"HKLM\SOFTWARE\Policies\Custom", "EnableFeature"),
        None
    );
    assert!(!runner.has_file(r"C:\Program Files\Mozilla Firefox\distribution\policies.json"));
}

#[test]
fn linux_enforcer_applies_and_rolls_back_all_12_rules() {
    let runner = DryRunOrMockRunner::new(false);
    runner.seed_file("/etc/group", "root:x:0:\nsudo:x:27:ubuntu\n");

    let mut state = AppliedState::default();
    let bundle = CheckinResponse {
        device_id: "dev-lin-1".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:lin1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: full_12_rule_suite(OsFamily::Linux),
    };

    let report = sync_desired_state(OsFamily::Linux, &bundle, &mut state, &runner);
    assert_eq!(report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(report.items.len(), 12);
    assert_eq!(state.managed_rules.len(), 12);

    assert!(runner.has_file("/etc/security/access.d/90-ns8-policy.conf"));
    assert!(runner.has_file("/etc/sudoers.d/90-ns8-policy-admins"));
    assert!(runner.has_file("/etc/modprobe.d/90-ns8-usb-storage.conf"));
    assert!(runner.has_file("/etc/nftables.d/90-ns8-firewall.nft"));
    assert!(runner.has_file("/etc/firefox/policies/policies.json"));
    assert!(runner.has_file("/etc/dconf/db/local.d/90-ns8-wallpaper"));
    assert!(runner.has_file("/etc/dconf/db/local.d/95-ns8-raw-raw-lin-1"));

    // Roll back all 12 rules
    let empty_bundle = CheckinResponse {
        device_id: "dev-lin-1".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:empty".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };
    let rb_report = sync_desired_state(OsFamily::Linux, &empty_bundle, &mut state, &runner);
    assert_eq!(rb_report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(rb_report.items.len(), 12);
    assert!(state.managed_rules.is_empty());

    assert!(!runner.has_file("/etc/security/access.d/90-ns8-policy.conf"));
    assert!(!runner.has_file("/etc/sudoers.d/90-ns8-policy-admins"));
    assert!(!runner.has_file("/etc/modprobe.d/90-ns8-usb-storage.conf"));
    assert!(!runner.has_file("/etc/nftables.d/90-ns8-firewall.nft"));
    assert!(!runner.has_file("/etc/firefox/policies/policies.json"));
    assert!(!runner.has_file("/etc/dconf/db/local.d/95-ns8-raw-raw-lin-1"));
}

#[test]
fn macos_enforcer_applies_and_rolls_back_all_12_rules() {
    let runner = DryRunOrMockRunner::new(false);
    runner.set_cmd_output(
        "dscl . -read /Groups/admin GroupMembership",
        CmdOutput::success("GroupMembership: root localadmin\n"),
    );

    let mut state = AppliedState::default();
    let bundle = CheckinResponse {
        device_id: "dev-mac-1".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:mac1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: full_12_rule_suite(OsFamily::Macos),
    };

    let report = sync_desired_state(OsFamily::Macos, &bundle, &mut state, &runner);
    assert_eq!(report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(report.items.len(), 12);
    assert_eq!(state.managed_rules.len(), 12);

    assert!(runner.has_file("/Library/Managed Preferences/com.google.Chrome.plist"));
    assert!(runner.has_file("/Library/Managed Preferences/com.apple.screensaver.plist"));
    assert!(runner.has_file("/etc/pf.anchors/org.nethserver.policyagent"));
    assert_eq!(
        runner.get_plist("/Library/Preferences/com.apple.MCX", "usbStorageMode"),
        Some(("string".to_string(), "BLOCK".to_string()))
    );
    assert_eq!(
        runner.get_plist("/Library/Preferences/com.apple.finder", "AppleShowAllExtensions"),
        Some(("bool".to_string(), "true".to_string()))
    );

    let empty_bundle = CheckinResponse {
        device_id: "dev-mac-1".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:empty".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };
    let rb_report = sync_desired_state(OsFamily::Macos, &empty_bundle, &mut state, &runner);
    assert_eq!(rb_report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(rb_report.items.len(), 12);
    assert!(state.managed_rules.is_empty());

    assert!(!runner.has_file("/Library/Managed Preferences/com.google.Chrome.plist"));
    assert_eq!(
        runner.get_plist("/Library/Preferences/com.apple.MCX", "usbStorageMode"),
        None
    );
    assert_eq!(
        runner.get_plist("/Library/Preferences/com.apple.finder", "AppleShowAllExtensions"),
        None
    );
}

#[test]
fn desired_state_lifecycle_and_preexisting_local_admin_safety() {
    let runner = DryRunOrMockRunner::new(false);
    // Pre-existing local admins on Windows: Administrator and LocalSupport
    runner.set_cmd_output(
        "net localgroup Administrators",
        CmdOutput::success(
            "Alias name     Administrators\r\nMembers\r\n-------------------------------------------------------------------------------\r\nAdministrator\r\nLocalSupport\r\nThe command completed successfully.\r\n",
        ),
    );

    let mut state = AppliedState::default();

    // STEP 1: Initial Apply (2 network shares X: & Y:, USB BLOCK, LocalAdmins including pre-existing LocalSupport + new IT-Admins & m.mueller)
    let rev1 = CheckinResponse {
        device_id: "dev-lifecycle".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:rev1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![
            make_rule(
                "access.local_admins",
                PolicyCategory::Access,
                json!({
                    "adminGroups": ["IT-Admins"],
                    "adminUsers": ["LocalSupport", "m.mueller"],
                    "passwordlessSudo": false
                }),
            ),
            make_rule(
                "workspace.network_shares",
                PolicyCategory::Workspace,
                json!({
                    "mounts": [
                        {
                            "id": "share-1",
                            "name": "Buchhaltung",
                            "protocol": "SMB",
                            "remotePath": r"\\files.firma.local\buchhaltung",
                            "windowsDriveLetter": "X:",
                            "reconnectAtLogon": true
                        },
                        {
                            "id": "share-2",
                            "name": "Vertrieb",
                            "protocol": "SMB",
                            "remotePath": r"\\files.firma.local\vertrieb",
                            "windowsDriveLetter": "Y:",
                            "reconnectAtLogon": true
                        }
                    ]
                }),
            ),
            make_rule(
                "security.usb_storage",
                PolicyCategory::Security,
                json!({ "mode": "BLOCK" }),
            ),
        ],
    };

    let rep1 = sync_desired_state(OsFamily::Windows, &rev1, &mut state, &runner);
    assert_eq!(rep1.status, ComplianceOverallStatus::Compliant);
    assert_eq!(state.applied_revision, 1);

    // Verify ONLY IT-Admins and m.mueller are recorded in rollbackMetadata — NEVER Administrator or LocalSupport!
    let admin_rec = &state.managed_rules["access.local_admins"];
    let tracked_names: Vec<&str> = admin_rec
        .rollback_metadata
        .added_principals
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(tracked_names, vec!["IT-Admins", "m.mueller"]);

    // STEP 2: Config Update (remove share Y:, switch USB BLOCK -> READ_ONLY, remove m.mueller from policy)
    runner.clear_operations();
    runner.set_cmd_output(
        "net localgroup Administrators",
        CmdOutput::success(
            "Alias name     Administrators\r\nMembers\r\n-------------------------------------------------------------------------------\r\nAdministrator\r\nLocalSupport\r\nIT-Admins\r\nm.mueller\r\nThe command completed successfully.\r\n",
        ),
    );

    let rev2 = CheckinResponse {
        device_id: "dev-lifecycle".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:rev2".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![
            make_rule(
                "access.local_admins",
                PolicyCategory::Access,
                json!({
                    "adminGroups": ["IT-Admins"],
                    "adminUsers": [],
                    "passwordlessSudo": false
                }),
            ),
            make_rule(
                "workspace.network_shares",
                PolicyCategory::Workspace,
                json!({
                    "mounts": [
                        {
                            "id": "share-1",
                            "name": "Buchhaltung",
                            "protocol": "SMB",
                            "remotePath": r"\\files.firma.local\buchhaltung",
                            "windowsDriveLetter": "X:",
                            "reconnectAtLogon": true
                        }
                    ]
                }),
            ),
            make_rule(
                "security.usb_storage",
                PolicyCategory::Security,
                json!({ "mode": "READ_ONLY" }),
            ),
        ],
    };

    let rep2 = sync_desired_state(OsFamily::Windows, &rev2, &mut state, &runner);
    assert_eq!(rep2.status, ComplianceOverallStatus::Compliant);
    assert_eq!(state.applied_revision, 2);

    let ops2 = runner.operations();
    // Share Y: was unmounted
    assert!(ops2.contains(&RecordedOp::RunCmd {
        program: "net".to_string(),
        args: vec![
            "use".to_string(),
            "Y:".to_string(),
            "/delete".to_string(),
            "/y".to_string()
        ],
    }));
    // m.mueller was removed, LocalSupport was NOT removed
    assert!(ops2.contains(&RecordedOp::RunCmd {
        program: "net".to_string(),
        args: vec![
            "localgroup".to_string(),
            "Administrators".to_string(),
            "m.mueller".to_string(),
            "/delete".to_string()
        ],
    }));
    assert!(!ops2.iter().any(|op| matches!(
        op,
        RecordedOp::RunCmd { program, args }
            if program == "net" && args.iter().any(|a| a.eq_ignore_ascii_case("LocalSupport") || a.eq_ignore_ascii_case("Administrator")) && args.contains(&"/delete".to_string())
    )));
    // USB switched to READ_ONLY (Start=3, WriteProtect=1)
    assert_eq!(
        runner.get_registry(r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR", "Start"),
        Some(("REG_DWORD".to_string(), "3".to_string()))
    );
    assert_eq!(
        runner.get_registry(
            r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
            "WriteProtect"
        ),
        Some(("REG_DWORD".to_string(), "1".to_string()))
    );

    // STEP 3: Full Rule Removal -> Surgical Rollback without touching pre-existing admins
    runner.clear_operations();
    let rev3 = CheckinResponse {
        device_id: "dev-lifecycle".to_string(),
        bundle_revision: 3,
        state_hash: "sha256:rev3".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };

    let rep3 = sync_desired_state(OsFamily::Windows, &rev3, &mut state, &runner);
    assert_eq!(rep3.status, ComplianceOverallStatus::Compliant);
    assert_eq!(rep3.items.len(), 3);
    assert!(rep3
        .items
        .iter()
        .all(|i| i.action == ComplianceAction::RolledBack && i.status == ComplianceItemStatus::Applied));
    assert!(state.managed_rules.is_empty());

    let ops3 = runner.operations();
    // IT-Admins was removed on rollback
    assert!(ops3.contains(&RecordedOp::RunCmd {
        program: "net".to_string(),
        args: vec![
            "localgroup".to_string(),
            "Administrators".to_string(),
            "IT-Admins".to_string(),
            "/delete".to_string()
        ],
    }));
    // Pre-existing Administrator & LocalSupport were NEVER touched!
    assert!(!ops3.iter().any(|op| matches!(
        op,
        RecordedOp::RunCmd { program, args }
            if program == "net" && args.iter().any(|a| a.eq_ignore_ascii_case("LocalSupport") || a.eq_ignore_ascii_case("Administrator"))
    )));
}

#[test]
fn live_http_enroll_sync_status_and_rollback_e2e() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().unwrap();
    let server_url = format!("http://{}", addr);

    let captured_compliance: Arc<Mutex<Vec<ComplianceReportRequest>>> =
        Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured_compliance);

    // Handle 5 sequential HTTP requests:
    // 1. POST /api/v1/agent/enroll
    // 2. POST /api/v1/agent/checkin (rev 1: USB block + wallpaper)
    // 3. POST /api/v1/agent/compliance (rev 1: ENFORCED)
    // 4. POST /api/v1/agent/checkin (rev 2: empty -> triggers rollback)
    // 5. POST /api/v1/agent/compliance (rev 2: ROLLED_BACK)
    let server_handle = thread::spawn(move || {
        let mut checkin_count = 0usize;
        for _ in 0..5 {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut buf = vec![0u8; 65536];
            let mut total = 0usize;
            let mut header_end = None;
            let mut content_len = 0usize;

            loop {
                let n = stream.read(&mut buf[total..]).unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none() {
                    if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                        let hend = pos + 4;
                        header_end = Some(hend);
                        let headers_str = String::from_utf8_lossy(&buf[..hend]);
                        for line in headers_str.lines() {
                            if let Some(cl) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                content_len = cl.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(hend) = header_end {
                    if total >= hend + content_len {
                        break;
                    }
                }
            }

            let hend = header_end.unwrap_or(total);
            let headers_str = String::from_utf8_lossy(&buf[..hend]).to_string();
            let body_str = String::from_utf8_lossy(&buf[hend..total]).to_string();
            let first_line = headers_str.lines().next().unwrap_or("");

            let (status_line, resp_json) = if first_line.contains("/api/v1/agent/enroll") {
                assert!(headers_str.to_ascii_lowercase().contains("idempotency-key:"));
                let req_val: Value = serde_json::from_str(&body_str).unwrap();
                assert_eq!(req_val["enrollmentToken"], "apm_enroll_test_token");
                (
                    "HTTP/1.1 201 Created",
                    json!({
                        "deviceId": "dev-e2e-001",
                        "deviceToken": "apm_dev_secret_token",
                        "pollIntervalSeconds": 90
                    }),
                )
            } else if first_line.contains("/api/v1/agent/checkin") {
                assert!(headers_str.contains("Bearer apm_dev_secret_token"));
                checkin_count += 1;
                if checkin_count == 1 {
                    (
                        "HTTP/1.1 200 OK",
                        json!({
                            "deviceId": "dev-e2e-001",
                            "bundleRevision": 1,
                            "stateHash": "sha256:bundle1",
                            "pollIntervalSeconds": 90,
                            "effectiveRules": [
                                {
                                    "ruleId": "r1",
                                    "category": "SECURITY",
                                    "ruleType": "security.usb_storage",
                                    "schemaVersion": 1,
                                    "platforms": ["LINUX"],
                                    "mergeStrategy": "OVERRIDE",
                                    "config": { "mode": "BLOCK" }
                                },
                                {
                                    "ruleId": "r2",
                                    "category": "DESKTOP",
                                    "ruleType": "desktop.wallpaper",
                                    "schemaVersion": 1,
                                    "platforms": ["LINUX"],
                                    "mergeStrategy": "OVERRIDE",
                                    "config": {
                                        "imageUrl": "https://intranet.firma.local/bg.jpg",
                                        "fitMode": "FILL",
                                        "isLocked": true
                                    }
                                }
                            ]
                        }),
                    )
                } else {
                    (
                        "HTTP/1.1 200 OK",
                        json!({
                            "deviceId": "dev-e2e-001",
                            "bundleRevision": 2,
                            "stateHash": "sha256:bundle2",
                            "pollIntervalSeconds": 90,
                            "effectiveRules": []
                        }),
                    )
                }
            } else if first_line.contains("/api/v1/agent/compliance") {
                assert!(headers_str.contains("Bearer apm_dev_secret_token"));
                let report: ComplianceReportRequest = serde_json::from_str(&body_str).unwrap();
                captured_clone.lock().unwrap().push(report);
                (
                    "HTTP/1.1 200 OK",
                    json!({
                        "acknowledged": true,
                        "recordedAt": "2026-11-23T19:00:00Z"
                    }),
                )
            } else {
                panic!("Unexpected HTTP path: {}", first_line);
            };

            let body_bytes = serde_json::to_vec(&resp_json).unwrap();
            let http_resp = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status_line,
                body_bytes.len()
            );
            stream.write_all(http_resp.as_bytes()).unwrap();
            stream.write_all(&body_bytes).unwrap();
            stream.flush().unwrap();
        }
    });

    let temp_dir = TempDir::new().unwrap();
    let state_dir = temp_dir.path();

    // 1. Enroll
    let cfg = execute_enroll(
        &server_url,
        "apm_enroll_test_token",
        state_dir,
        Some("LIN-TEST-01"),
        Some(OsFamily::Linux),
    )
    .expect("enroll should succeed");
    assert_eq!(cfg.device_id, "dev-e2e-001");
    assert_eq!(cfg.os_family, OsFamily::Linux);
    let loaded_cfg = AgentConfig::load(state_dir).unwrap();
    assert_eq!(loaded_cfg, cfg);

    // 2. Sync #1 (Enforce 2 rules in dry-run)
    let sync1 = execute_sync_once(state_dir, true, Some("m.mueller"), Some(OsFamily::Linux))
        .expect("sync 1 should succeed");
    assert_eq!(sync1.report.applied_revision, 1);
    assert_eq!(sync1.report.status, ComplianceOverallStatus::Compliant);
    assert_eq!(sync1.report.items.len(), 2);

    // Verify CLI `status --json` command reads persisted state accurately
    let bin = env!("CARGO_BIN_EXE_ns8-policy-agent");
    let status_out = Command::new(bin)
        .args(["status", "--state-dir", state_dir.to_str().unwrap(), "--json"])
        .output()
        .expect("run status CLI");
    assert!(status_out.status.success());
    let status_json: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["deviceId"], "dev-e2e-001");
    assert_eq!(status_json["appliedRevision"], 1);
    assert!(status_json["managedRules"]["security.usb_storage"].is_object());

    // 3. Sync #2 (Empty rules -> Rollback both rules)
    let sync2 = execute_sync_once(state_dir, true, Some("m.mueller"), Some(OsFamily::Linux))
        .expect("sync 2 should succeed");
    assert_eq!(sync2.report.applied_revision, 2);
    assert_eq!(sync2.report.items.len(), 2);
    assert!(sync2
        .report
        .items
        .iter()
        .all(|i| i.action == ComplianceAction::RolledBack && i.status == ComplianceItemStatus::Applied));

    server_handle.join().unwrap();

    let reports = captured_compliance.lock().unwrap();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].items[0].action, ComplianceAction::Enforced);
    assert_eq!(reports[1].items[0].action, ComplianceAction::RolledBack);

    let final_state = AppliedState::load(state_dir).unwrap();
    assert_eq!(final_state.applied_revision, 2);
    assert!(final_state.managed_rules.is_empty());
}


#[test]
fn linux_and_macos_preexisting_admins_are_never_removed() {
    // --- LINUX ---
    let lin_runner = DryRunOrMockRunner::new(false);
    lin_runner.seed_file("/etc/group", "root:x:0:\nsudo:x:27:ubuntu,localadmin\n");

    let mut lin_state = AppliedState::default();
    let lin_rev1 = CheckinResponse {
        device_id: "dev-lin-safe".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![make_rule(
            "access.local_admins",
            PolicyCategory::Access,
            json!({
                "adminGroups": ["IT-Admins"],
                "adminUsers": ["ubuntu", "temp.admin"],
                "passwordlessSudo": false
            }),
        )],
    };
    let rep = sync_desired_state(OsFamily::Linux, &lin_rev1, &mut lin_state, &lin_runner);
    assert_eq!(rep.status, ComplianceOverallStatus::Compliant);
    let added_lin: Vec<&str> = lin_state.managed_rules["access.local_admins"]
        .rollback_metadata
        .added_principals
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(added_lin, vec!["temp.admin"]);

    lin_runner.clear_operations();
    let lin_rev2 = CheckinResponse {
        device_id: "dev-lin-safe".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:2".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };
    let rb_lin = sync_desired_state(OsFamily::Linux, &lin_rev2, &mut lin_state, &lin_runner);
    assert_eq!(rb_lin.status, ComplianceOverallStatus::Compliant);
    let lin_ops = lin_runner.operations();
    assert!(lin_ops.contains(&RecordedOp::RunCmd {
        program: "gpasswd".to_string(),
        args: vec!["-d".to_string(), "temp.admin".to_string(), "sudo".to_string()],
    }));
    assert!(!lin_ops.iter().any(|op| matches!(
        op,
        RecordedOp::RunCmd { program, args }
            if program == "gpasswd" && args.iter().any(|a| a == "ubuntu" || a == "localadmin")
    )));

    // --- MACOS ---
    let mac_runner = DryRunOrMockRunner::new(false);
    mac_runner.set_cmd_output(
        "dscl . -read /Groups/admin GroupMembership",
        CmdOutput::success("GroupMembership: root localadmin\n"),
    );

    let mut mac_state = AppliedState::default();
    let mac_rev1 = CheckinResponse {
        device_id: "dev-mac-safe".to_string(),
        bundle_revision: 1,
        state_hash: "sha256:1".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![make_rule(
            "access.local_admins",
            PolicyCategory::Access,
            json!({
                "adminGroups": ["IT-Admins"],
                "adminUsers": ["localadmin", "m.mueller"],
                "passwordlessSudo": false
            }),
        )],
    };
    let rep_mac = sync_desired_state(OsFamily::Macos, &mac_rev1, &mut mac_state, &mac_runner);
    assert_eq!(rep_mac.status, ComplianceOverallStatus::Compliant);
    let added_mac: Vec<&str> = mac_state.managed_rules["access.local_admins"]
        .rollback_metadata
        .added_principals
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(added_mac, vec!["IT-Admins", "m.mueller"]);

    mac_runner.clear_operations();
    let mac_rev2 = CheckinResponse {
        device_id: "dev-mac-safe".to_string(),
        bundle_revision: 2,
        state_hash: "sha256:2".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![],
    };
    let rb_mac = sync_desired_state(OsFamily::Macos, &mac_rev2, &mut mac_state, &mac_runner);
    assert_eq!(rb_mac.status, ComplianceOverallStatus::Compliant);
    let mac_ops = mac_runner.operations();
    assert!(!mac_ops.iter().any(|op| matches!(
        op,
        RecordedOp::RunCmd { program, args }
            if program == "dseditgroup" && args.contains(&"-d".to_string()) && args.iter().any(|a| a == "localadmin" || a == "root")
    )));
}

#[test]
fn degraded_and_error_compliance_statuses_and_cli_flags() {
    use clap::Parser;
    use ns8_policy_agent::cli::{Cli, Commands};

    // 1. CLI Flag Parsing Verification
    let parsed_sync = Cli::try_parse_from([
        "ns8-policy-agent",
        "sync",
        "--once",
        "--dry-run",
        "--state-dir",
        "/tmp/state",
        "--current-user",
        "m.mueller",
        "--os-override",
        "WINDOWS",
    ])
    .expect("parse sync CLI");
    assert!(matches!(
        parsed_sync.command,
        Commands::Sync {
            once: true,
            dry_run: true,
            os_override: Some(OsFamily::Windows),
            ..
        }
    ));

    let parsed_enroll = Cli::try_parse_from([
        "ns8-policy-agent",
        "enroll",
        "--server",
        "https://policies.example.org",
        "--token",
        "apm_enroll_abc",
        "--hostname",
        "PC-01",
        "--os-override",
        "MACOS",
    ])
    .expect("parse enroll CLI");
    assert!(matches!(
        parsed_enroll.command,
        Commands::Enroll {
            os_override: Some(OsFamily::Macos),
            ..
        }
    ));

    // 2. SKIPPED_UNSUPPORTED -> DEGRADED overall status
    let runner = DryRunOrMockRunner::new(false);
    let mut state = AppliedState::default();
    let degraded_bundle = CheckinResponse {
        device_id: "dev-1".to_string(),
        bundle_revision: 4,
        state_hash: "sha256:deg".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![make_rule(
            "future.unknown_v3_rule",
            PolicyCategory::Unknown,
            json!({ "foo": "bar" }),
        )],
    };
    let deg_rep = sync_desired_state(OsFamily::Linux, &degraded_bundle, &mut state, &runner);
    assert_eq!(deg_rep.status, ComplianceOverallStatus::Degraded);
    assert_eq!(deg_rep.items[0].status, ComplianceItemStatus::SkippedUnsupported);
    assert_eq!(state.applied_revision, 4);

    // 3. Command failure -> FAILED item & ERROR overall status (revision not advanced)
    let fail_runner = DryRunOrMockRunner::new(false);
    fail_runner.fail_program("nft");
    let err_bundle = CheckinResponse {
        device_id: "dev-1".to_string(),
        bundle_revision: 5,
        state_hash: "sha256:err".to_string(),
        poll_interval_seconds: 120,
        effective_rules: vec![make_rule(
            "security.firewall",
            PolicyCategory::Security,
            json!({
                "isEnabled": true,
                "defaultInbound": "BLOCK",
                "allowStealthMode": false,
                "allowedTcpPorts": [22],
                "allowedUdpPorts": []
            }),
        )],
    };
    let err_rep = sync_desired_state(OsFamily::Linux, &err_bundle, &mut state, &fail_runner);
    assert_eq!(err_rep.status, ComplianceOverallStatus::Error);
    assert_eq!(err_rep.items[0].status, ComplianceItemStatus::Failed);
    assert_eq!(state.applied_revision, 4); // Preserved prior applied revision on failure
}
