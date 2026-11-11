//! Read-only observations of the default Codex host prerequisites.

use std::{
    fmt::Display,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Result};
use serde::Serialize;

use crate::process_runner::STRICT_CONTAINMENT_HELPERS;

/// Collection is separate from evaluation so tests need no host access.
struct Snapshot {
    linux: bool,
    repository: Result<PathBuf, String>,
    runtime_executable: Result<PathBuf, String>,
    helpers_available: [bool; STRICT_CONTAINMENT_HELPERS.len()],
    delegated_cgroup: Result<PathBuf, String>,
    runtime_directory: Result<PathBuf, String>,
}

fn collect(repo: &Path) -> Snapshot {
    let repository = crate::artifacts::discover_repo_root(repo).map_err(first_line_reason);
    let runtime_executable =
        crate::external_agent::resolve_trusted_system_codex_executable_for_catalog(repo)
            .map_err(first_line_reason);

    #[cfg(target_os = "linux")]
    let (helpers_available, delegated_cgroup, runtime_directory) = (
        STRICT_CONTAINMENT_HELPERS.map(|(name, candidates)| {
            crate::process_runner::trusted_system_executable(name, candidates).is_ok()
        }),
        collect_delegated_cgroup().map_err(first_line_reason),
        crate::process_runner::trusted_linux_runtime_root().map_err(first_line_reason),
    );
    #[cfg(not(target_os = "linux"))]
    let (helpers_available, delegated_cgroup, runtime_directory) = (
        [false; STRICT_CONTAINMENT_HELPERS.len()],
        Err("not checked on this platform".to_owned()),
        Err("not checked on this platform".to_owned()),
    );

    Snapshot {
        linux: cfg!(target_os = "linux"),
        repository,
        runtime_executable,
        helpers_available,
        delegated_cgroup,
        runtime_directory,
    }
}

#[cfg(target_os = "linux")]
fn collect_delegated_cgroup() -> std::io::Result<PathBuf> {
    use std::io::Read;

    const MAX_CGROUP_BYTES: u64 = 64 * 1024;
    let mut contents = String::new();
    std::fs::File::open("/proc/self/cgroup")?
        .take(MAX_CGROUP_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_CGROUP_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cgroup membership exceeds the observation size limit",
        ));
    }
    let manager = crate::process_runner::delegated_systemd_user_manager_cgroup(&contents)?;
    let directory =
        Path::new("/sys/fs/cgroup").join(manager.strip_prefix("/").unwrap_or(manager.as_path()));
    if !directory.join("cgroup.controllers").is_file() || !directory.join("cgroup.kill").is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "systemd user manager cgroup {} does not expose cgroup v2 kill/verification controls",
                directory.display()
            ),
        ));
    }
    Ok(directory)
}

fn first_line_reason(error: impl Display) -> String {
    error
        .to_string()
        .lines()
        .next()
        .unwrap_or("unknown error")
        .to_owned()
}

fn one_line(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
            result.extend(character.escape_default());
        } else {
            result.push(character);
        }
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    reason: String,
    remedy: &'static str,
}

fn check(id: &'static str, status: Status, reason: &str, remedy: &'static str) -> Check {
    Check {
        id,
        status,
        reason: one_line(reason),
        remedy: if status == Status::Pass {
            "none"
        } else {
            remedy
        },
    }
}

fn path_check(
    id: &'static str,
    observation: &Result<PathBuf, String>,
    description: &str,
    remedy: &'static str,
) -> Check {
    match observation {
        Ok(path) => check(
            id,
            Status::Pass,
            &format!("{description}: {}", path.display()),
            remedy,
        ),
        Err(error) => check(id, Status::Fail, &first_line_reason(error), remedy),
    }
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u8,
    scope: &'static str,
    has_failures: bool,
    checks: Vec<Check>,
}

fn evaluate(snapshot: &Snapshot) -> Report {
    let mut checks = vec![
        check(
            "platform",
            if snapshot.linux {
                Status::Pass
            } else {
                Status::Fail
            },
            if snapshot.linux {
                "Linux"
            } else {
                "this platform is not Linux"
            },
            "use a Linux host with systemd and cgroup v2",
        ),
        path_check(
            "repository",
            &snapshot.repository,
            "Git checkout",
            "pass --repo pointing at a Git checkout owned by the current user",
        ),
        path_check(
            "runtime_executable",
            &snapshot.runtime_executable,
            "trusted Codex executable (file policy only)",
            "install a supported Codex at the trusted system location; PATH is not used",
        ),
    ];
    if snapshot.linux {
        let missing: Vec<_> = STRICT_CONTAINMENT_HELPERS
            .iter()
            .zip(snapshot.helpers_available)
            .filter_map(|((name, _), available)| (!available).then_some(*name))
            .collect();
        checks.push(check(
            "containment_helpers",
            if missing.is_empty() {
                Status::Pass
            } else {
                Status::Fail
            },
            &if missing.is_empty() {
                "all seven fixed-path helpers satisfy file policy".to_owned()
            } else {
                format!("missing trusted helpers: {}", missing.join(", "))
            },
            "provide root-owned, non-writable helpers at the fixed system paths",
        ));
        checks.push(path_check(
            "delegated_cgroup",
            &snapshot.delegated_cgroup,
            "delegated user manager cgroup with cgroup v2 controls",
            "run inside a delegated systemd user service on a cgroup v2 host",
        ));
        checks.push(path_check(
            "runtime_directory",
            &snapshot.runtime_directory,
            "private runtime directory",
            "use a session that provides a private /run/user/UID owned by the current user",
        ));
    } else {
        for id in [
            "containment_helpers",
            "delegated_cgroup",
            "runtime_directory",
        ] {
            checks.push(check(
                id,
                Status::Warn,
                "not checked on this platform",
                "verify separately",
            ));
        }
    }
    for (id, reason) in [
        (
            "runtime_contract",
            "not checked: the Codex version and protocol compatibility",
        ),
        (
            "live_qualification",
            "not checked: whether strict containment works for a real launch",
        ),
        (
            "authentication",
            "not checked: provider login and account authority",
        ),
        (
            "catalogs",
            "not checked: model catalogs and plan eligibility",
        ),
        (
            "launch_configuration",
            "not checked: custom runtime binaries, machine-global configuration and admission",
        ),
    ] {
        checks.push(check(id, Status::Warn, reason, "verify separately"));
    }
    Report {
        schema_version: 1,
        scope: "default_codex_host_prerequisites",
        has_failures: checks.iter().any(|check| check.status == Status::Fail),
        checks,
    }
}

fn render(report: &Report, json: bool, output: &mut impl Write) -> Result<()> {
    if json {
        serde_json::to_writer(&mut *output, report)?;
        writeln!(output)?;
    } else {
        writeln!(output, "default Codex host prerequisites")?;
        for check in &report.checks {
            writeln!(
                output,
                "{} {}: {}; remedy: {}",
                check.status.as_str(),
                check.id,
                check.reason,
                check.remedy
            )?;
        }
        let failures = report
            .checks
            .iter()
            .filter(|check| check.status == Status::Fail)
            .count();
        writeln!(
            output,
            "{failures} FAIL rows; readiness incomplete: WARN rows were not checked"
        )?;
    }
    Ok(())
}

fn write_report(snapshot: &Snapshot, json: bool, output: &mut impl Write) -> Result<()> {
    let report = evaluate(snapshot);
    render(&report, json, output)?;
    output.flush()?;
    ensure!(
        !report.has_failures,
        "doctor found failing default Codex host prerequisites"
    );
    Ok(())
}

pub(crate) fn run(repo: &Path, json: bool) -> Result<()> {
    write_report(&collect(repo), json, &mut std::io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCTOR_IDS: [&str; 11] = [
        "platform",
        "repository",
        "runtime_executable",
        "containment_helpers",
        "delegated_cgroup",
        "runtime_directory",
        "runtime_contract",
        "live_qualification",
        "authentication",
        "catalogs",
        "launch_configuration",
    ];

    fn healthy_doctor_snapshot() -> Snapshot {
        Snapshot {
            linux: true,
            repository: Ok(PathBuf::from("/checkout")),
            runtime_executable: Ok(PathBuf::from("/usr/bin/codex")),
            helpers_available: [true; STRICT_CONTAINMENT_HELPERS.len()],
            delegated_cgroup: Ok(PathBuf::from("/sys/fs/cgroup/user.slice/user@1000.service")),
            runtime_directory: Ok(PathBuf::from("/run/user/1000")),
        }
    }

    #[test]
    fn doctor_all_pass_snapshot_has_fixed_rows_and_succeeds() {
        let snapshot = healthy_doctor_snapshot();
        let report = evaluate(&snapshot);
        assert_eq!(
            report
                .checks
                .iter()
                .map(|check| check.id)
                .collect::<Vec<_>>(),
            DOCTOR_IDS
        );
        assert!(!report.has_failures);
        for check in &report.checks[..6] {
            assert_eq!(check.status, Status::Pass);
            assert_eq!(check.remedy, "none");
        }
        for check in &report.checks[6..] {
            assert_eq!(check.status, Status::Warn);
            assert!(check.reason.starts_with("not checked:"));
            assert_eq!(check.remedy, "verify separately");
        }
        assert!(report.checks[1].reason.contains("/checkout"));
        assert!(report.checks[2].reason.contains("/usr/bin/codex"));
        assert!(report.checks[2].reason.contains("file policy only"));
        assert!(write_report(&snapshot, false, &mut Vec::new()).is_ok());
        assert!(write_report(&snapshot, true, &mut Vec::new()).is_ok());
    }

    #[test]
    fn doctor_each_blocker_renders_all_rows_before_error() {
        let remedies = [
            "use a Linux host with systemd and cgroup v2",
            "pass --repo pointing at a Git checkout owned by the current user",
            "install a supported Codex at the trusted system location; PATH is not used",
            "provide root-owned, non-writable helpers at the fixed system paths",
            "run inside a delegated systemd user service on a cgroup v2 host",
            "use a session that provides a private /run/user/UID owned by the current user",
        ];
        for (index, remedy) in remedies.into_iter().enumerate() {
            let mut snapshot = healthy_doctor_snapshot();
            match index {
                0 => snapshot.linux = false,
                1 => snapshot.repository = Err("repository unavailable".to_owned()),
                2 => snapshot.runtime_executable = Err("Codex unavailable".to_owned()),
                3 => snapshot.helpers_available[0] = false,
                4 => snapshot.delegated_cgroup = Err("no delegated cgroup".to_owned()),
                5 => snapshot.runtime_directory = Err("no private runtime root".to_owned()),
                _ => unreachable!(),
            }
            let report = evaluate(&snapshot);
            assert_eq!(report.checks.len(), 11);
            assert!(report.has_failures);
            assert_eq!(report.checks[index].status, Status::Fail);
            assert_eq!(report.checks[index].remedy, remedy);
            assert_eq!(
                report
                    .checks
                    .iter()
                    .filter(|check| check.status == Status::Fail)
                    .count(),
                1
            );
            let mut text = Vec::new();
            assert!(write_report(&snapshot, false, &mut text).is_err());
            let text = String::from_utf8(text).unwrap();
            assert_eq!(text.lines().count(), 13);
            assert!(
                text.ends_with("1 FAIL rows; readiness incomplete: WARN rows were not checked\n")
            );
            for (line, id) in text.lines().skip(1).take(11).zip(DOCTOR_IDS) {
                assert!(line.contains(&format!(" {id}: ")));
            }
            let mut json = Vec::new();
            assert!(write_report(&snapshot, true, &mut json).is_err());
            let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(json["has_failures"], true);
            assert_eq!(json["checks"].as_array().unwrap().len(), 11);
            assert_eq!(json["checks"][index]["status"], "FAIL");
        }
    }

    #[test]
    fn doctor_missing_helpers_are_named_in_launcher_order() {
        let mut snapshot = healthy_doctor_snapshot();
        snapshot.helpers_available.fill(false);
        let report = evaluate(&snapshot);
        assert_eq!(report.checks[3].status, Status::Fail);
        assert_eq!(
            report.checks[3].reason,
            "missing trusted helpers: systemd-run, sh, systemctl, env, sleep, stat, findmnt"
        );
        snapshot.helpers_available = [true, false, true, false, true, true, false];
        assert_eq!(
            evaluate(&snapshot).checks[3].reason,
            "missing trusted helpers: sh, env, findmnt"
        );
    }

    #[test]
    fn doctor_non_linux_snapshot_skips_linux_checks() {
        let mut snapshot = healthy_doctor_snapshot();
        snapshot.linux = false;
        snapshot.helpers_available.fill(false);
        snapshot.delegated_cgroup = Err("not available".to_owned());
        snapshot.runtime_directory = Err("not available".to_owned());
        let report = evaluate(&snapshot);
        assert_eq!(report.checks[0].status, Status::Fail);
        for check in &report.checks[3..6] {
            assert_eq!(check.status, Status::Warn);
            assert_eq!(check.reason, "not checked on this platform");
        }
    }

    #[test]
    fn doctor_json_has_exact_schema_and_matches_text_rows() {
        let snapshot = healthy_doctor_snapshot();
        let mut json = Vec::new();
        write_report(&snapshot, true, &mut json).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            json.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["checks", "has_failures", "schema_version", "scope"]
        );
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["scope"], "default_codex_host_prerequisites");
        assert_eq!(json["has_failures"], false);
        let mut text = Vec::new();
        write_report(&snapshot, false, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 13);
        assert_eq!(lines[0], "default Codex host prerequisites");
        assert_eq!(
            lines[12],
            "0 FAIL rows; readiness incomplete: WARN rows were not checked"
        );
        let checks = json["checks"].as_array().unwrap();
        assert_eq!(checks.len(), DOCTOR_IDS.len());
        for (index, check) in checks.iter().enumerate() {
            assert_eq!(
                check
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["id", "reason", "remedy", "status"]
            );
            assert_eq!(check["id"], DOCTOR_IDS[index]);
            let status = check["status"].as_str().unwrap();
            assert!(matches!(status, "PASS" | "WARN" | "FAIL"));
            assert_eq!(
                lines[index + 1],
                format!(
                    "{status} {}: {}; remedy: {}",
                    check["id"].as_str().unwrap(),
                    check["reason"].as_str().unwrap(),
                    check["remedy"].as_str().unwrap()
                )
            );
        }
    }

    #[test]
    fn doctor_reasons_escape_controls_and_errors_use_first_line() {
        let mut snapshot = healthy_doctor_snapshot();
        snapshot.repository = Ok(PathBuf::from("/checkout\nline\t\u{1b}\r\u{2028}"));
        snapshot.runtime_executable = Err("unavailable\u{7}\nsecond error line".to_owned());
        let report = evaluate(&snapshot);
        assert_eq!(
            report.checks[1].reason,
            "Git checkout: /checkout\\nline\\t\\u{1b}\\r\\u{2028}"
        );
        assert_eq!(report.checks[2].reason, "unavailable\\u{7}");
        let mut text = Vec::new();
        assert!(write_report(&snapshot, false, &mut text).is_err());
        let text = String::from_utf8(text).unwrap();
        assert_eq!(text.lines().count(), 13);
        assert!(!text.contains("second error line"));
        assert!(report
            .checks
            .iter()
            .all(|check| !check.reason.chars().any(char::is_control)));
    }
}
