//! Frozen declarations and independently acquired file evidence for authored checks.
//!
//! This API does not grant preclaim admission or execute a command. Restoring a
//! normalized plan restores declarations only; receipts always require acquisition
//! against the current repository and semantic-risk inputs.

use super::{AgentRole, AssignmentPhase, OrchestratorAssignment, SupervisorPlan};
use crate::repo_semantic::SemanticRiskReport;
#[cfg(not(unix))]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

const MAX_CHECKS: usize = 8;
const MAX_PATH_BYTES: usize = 1024;

/// One exact Python check for one nested Worker, authored on its parent.
///
/// The initial command grammar is exactly `[absolute_python3, "-I", "-B",
/// check_path]`. No PATH lookup, shell, inline code, module selection, additional
/// arguments or environment overrides are accepted. The script need not have an
/// executable bit; the bound interpreter must be executable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoredIndependentCheck {
    pub worker_id: String,
    pub assigned_paths: Vec<String>,
    pub check_path: String,
    pub argv: Vec<String>,
}

fn exact_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= MAX_PATH_BYTES
            && !path.contains(['\\', ':'])
            && !path.chars().any(char::is_control)
            && path.split('/').all(|part| {
                !part.is_empty() && part != "." && part != ".." && !part.starts_with('.')
            }),
        "authored check requires an exact, non-hidden repository-relative path"
    );
    Ok(())
}

fn portable_path(path: &Path) -> Result<String> {
    let parts = path
        .components()
        .map(|component| {
            let std::path::Component::Normal(part) = component else {
                anyhow::bail!("authored check scope must be repository-relative");
            };
            part.to_str().context("authored check scope is not UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let portable = parts.join("/");
    exact_relative_path(&portable)?;
    Ok(portable)
}

pub(super) fn validate_declarations<'a>(
    plan: &'a SupervisorPlan,
    parent_id: &str,
    checks: &[AuthoredIndependentCheck],
) -> Result<&'a OrchestratorAssignment> {
    let mut parents = plan.assignments.iter().filter(|item| item.id == parent_id);
    let parent = parents.next().context("authored check parent is missing")?;
    ensure!(
        parents.next().is_none(),
        "authored check parent is ambiguous"
    );
    ensure!(
        parent.role == AgentRole::ChildOrchestrator
            && parent.phase == AssignmentPhase::Execution
            && !parent.category_is_operator_override()
            && !parent.worker_assignments.is_empty(),
        "authored checks require an execution parent with nested Workers"
    );
    ensure!(
        !checks.is_empty() && checks.len() <= MAX_CHECKS,
        "authored_independent_checks requires 1..={MAX_CHECKS} checks"
    );
    let mut worker_paths = BTreeSet::new();
    let mut worker_ids = BTreeSet::new();
    for worker in &parent.worker_assignments {
        ensure!(
            worker.role == AgentRole::Worker
                && !worker.category_is_operator_override()
                && !worker.assigned_paths.is_empty()
                && worker_ids.insert(&worker.id),
            "authored checks require distinct terminal Workers with explicit scopes"
        );
        for path in &worker.assigned_paths {
            portable_path(path)?;
            ensure!(
                worker_paths.iter().all(|existing: &&Path| {
                    !path.starts_with(existing) && !existing.starts_with(path)
                }),
                "authored check Worker scopes must be disjoint"
            );
            worker_paths.insert(path.as_path());
        }
    }
    let parent_paths = parent
        .assigned_paths
        .iter()
        .map(|p| p.as_path())
        .collect::<BTreeSet<_>>();
    ensure!(
        parent_paths == worker_paths && parent_paths.len() == parent.assigned_paths.len(),
        "authored check parent scope must equal the exact Worker union"
    );
    let mut subjects = BTreeSet::new();
    let mut check_paths = BTreeSet::new();
    for check in checks {
        let worker = parent
            .worker_assignments
            .iter()
            .find(|worker| worker.id == check.worker_id)
            .context("authored check names an unrelated Worker")?;
        let declared = check
            .assigned_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for path in &check.assigned_paths {
            exact_relative_path(path)?;
        }
        let assigned = worker
            .assigned_paths
            .iter()
            .map(|path| portable_path(path))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            declared == assigned
                && declared.len() == check.assigned_paths.len()
                && subjects.insert(&check.worker_id),
            "authored check must bind its Worker's exact assigned paths once"
        );
        exact_relative_path(&check.check_path)?;
        ensure!(
            check.check_path.ends_with(".py") && check_paths.insert(&check.check_path),
            "authored checks require distinct Python script paths"
        );
        let script = Path::new(&check.check_path);
        // Include every flattened assignment, so another writable assignment
        // cannot replace a check declared outside this parent's own union.
        ensure!(
            plan.assignments
                .iter()
                .filter(|assignment| {
                    matches!(
                        assignment.role,
                        AgentRole::Worker | AgentRole::ChildOrchestrator
                    )
                })
                .all(|assignment| {
                    assignment
                        .assigned_paths
                        .iter()
                        .chain(
                            assignment
                                .worker_assignments
                                .iter()
                                .flat_map(|w| &w.assigned_paths),
                        )
                        .all(|write| !script.starts_with(write) && !write.starts_with(script))
                }),
            "authored check overlaps a plan write scope"
        );
        ensure!(
            check.argv.len() == 4
                && check.argv[1] == "-I"
                && check.argv[2] == "-B"
                && check.argv[3] == check.check_path,
            "authored check argv must be absolute Python, -I, -B and the exact check path"
        );
        let program = &check.argv[0];
        let name = program.rsplit('/').next().unwrap_or_default();
        ensure!(
            program.starts_with('/')
                && program.len() <= MAX_PATH_BYTES
                && !program.contains(['\\', ':'])
                && !program.chars().any(char::is_control)
                && program
                    .split('/')
                    .skip(1)
                    .all(|p| !p.is_empty() && p != "." && p != "..")
                && (name == "python3"
                    || name.strip_prefix("python3.").is_some_and(|v| {
                        !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit())
                    })),
            "authored check interpreter must be an exact absolute Python 3 executable"
        );
    }
    ensure!(
        subjects.len() == worker_ids.len(),
        "authored checks must cover every nested Worker"
    );
    Ok(parent)
}

/// In-memory evidence acquired from current files, never serialized or restored.
/// A receipt is not a successful check result or permission to launch a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredAuthoredCheckEvidence {
    repository: std::path::PathBuf,
    parent_id: String,
    plan_sha256: String,
    risk_sha256: String,
    head: String,
    tree: String,
    files: Vec<BoundFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundFile {
    path: std::path::PathBuf,
    sha256: String,
    identity: (u64, u64),
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl AcquiredAuthoredCheckEvidence {
    /// Refuse any drift in the canonical plan, snapshot, risk or file identities.
    /// Callers must supply freshly acquired risk inputs from the same snapshot.
    pub fn revalidate(
        &self,
        repository: &Path,
        plan_document: &str,
        risk: &SemanticRiskReport,
    ) -> Result<()> {
        let current = acquire(repository, plan_document, &self.parent_id, risk)?;
        ensure!(current == *self, "authored check acquired evidence changed");
        Ok(())
    }
}

/// Acquire a fresh receipt from a normalized or operator-authored plan document.
/// Parsing a document alone never calls this function or restores a receipt.
/// Acquisition is currently supported only on Unix, where no-follow descriptors,
/// hard-link counts and executable identity are checked. Nothing is executed.
pub fn acquire(
    repository: &Path,
    plan_document: &str,
    parent_id: &str,
    risk: &SemanticRiskReport,
) -> Result<AcquiredAuthoredCheckEvidence> {
    #[cfg(unix)]
    {
        acquire_unix(repository, plan_document, parent_id, risk)
    }
    #[cfg(not(unix))]
    {
        let _ = (repository, plan_document, parent_id, risk);
        bail!("authored check file identity acquisition requires Unix")
    }
}

#[cfg(unix)]
fn acquire_unix(
    repository: &Path,
    plan_document: &str,
    parent_id: &str,
    risk: &SemanticRiskReport,
) -> Result<AcquiredAuthoredCheckEvidence> {
    use crate::artifacts::state_auth::sha256_hex;
    let loaded = super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
        plan_document,
        Some(repository),
    )?;
    let checks = loaded
        .assignment_metadata
        .authored_independent_checks
        .get(parent_id)
        .context("parent has no authored independent checks")?;
    let parent = validate_declarations(&loaded.plan, parent_id, checks)?;
    ensure!(
        risk.errors.is_empty(),
        "authored checks require semantic risk without scan errors"
    );
    let changed = risk.changed_paths.iter().collect::<BTreeSet<_>>();
    ensure!(
        changed == parent.assigned_paths.iter().collect::<BTreeSet<_>>()
            && changed.len() == risk.changed_paths.len(),
        "authored checks require semantic risk bound to the parent union"
    );
    let root = std::fs::canonicalize(repository)?;
    let repo = git2::Repository::open(&root)?;
    ensure!(
        repo.workdir()
            .is_some_and(|workdir| std::fs::canonicalize(workdir).is_ok_and(|dir| dir == root)),
        "authored check repository must be the exact worktree root"
    );
    let snapshot = || -> Result<(String, String)> {
        let index = repo.index()?;
        ensure!(
            index.len() <= 100_000,
            "authored check snapshot index exceeds its entry limit"
        );
        ensure!(index.iter().all(|entry| entry.flags & 0xf000 == 0 && entry.flags_extended == 0 && entry.mode != 0o040000),
            "authored check snapshot cannot use hidden, extended, conflicted or sparse index entries");
        let mut options = git2::StatusOptions::new();
        options
            .include_untracked(true)
            .recurse_untracked_dirs(true)
            .include_ignored(false);
        ensure!(
            repo.statuses(Some(&mut options))?.is_empty(),
            "authored checks require a clean Git snapshot"
        );
        let commit = repo.head()?.peel_to_commit()?;
        Ok((commit.id().to_string(), commit.tree_id().to_string()))
    };
    let (head, tree) = snapshot()?;
    let tree_object = repo.find_tree(tree.parse()?)?;
    let mut files = Vec::new();
    for check in checks {
        let relative = Path::new(&check.check_path);
        let entry = tree_object
            .get_path(relative)
            .context("authored check is not Git-visible")?;
        ensure!(
            matches!(entry.filemode(), 0o100644 | 0o100755),
            "authored check is not a tracked regular file"
        );
        let (blob_bytes, kind) = repo.odb()?.read_header(entry.id())?;
        ensure!(
            kind == git2::ObjectType::Blob && blob_bytes <= 1024 * 1024,
            "authored check snapshot exceeds its byte limit"
        );
        let path = crate::process_runner::resolve_existing_path_without_symlinks(&root, relative)?;
        let (file, bytes) = capture_file(&path, 1024 * 1024, false)?;
        ensure!(
            repo.find_blob(entry.id())?.content() == bytes,
            "authored check differs from its snapshot"
        );
        files.push(file);
        // System interpreter symlinks are resolved once and the resolved path,
        // descriptor identity and bytes are all compared on revalidation.
        let interpreter = std::fs::canonicalize(&check.argv[0])?;
        ensure!(
            !interpreter.starts_with(&root),
            "authored check interpreter must be outside the repository"
        );
        let (file, _) = capture_file(&interpreter, 32 * 1024 * 1024, true)?;
        files.push(file);
    }
    ensure!(
        snapshot()? == (head.clone(), tree.clone()),
        "authored check snapshot changed during acquisition"
    );
    let canonical = super::plan_api::supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )?;
    Ok(AcquiredAuthoredCheckEvidence {
        repository: root,
        parent_id: parent_id.to_string(),
        plan_sha256: sha256_hex(&serde_json::to_vec(&canonical)?),
        risk_sha256: sha256_hex(&serde_json::to_vec(risk)?),
        head,
        tree,
        files,
    })
}

#[cfg(unix)]
fn capture_file(path: &Path, cap: u64, executable: bool) -> Result<(BoundFile, Vec<u8>)> {
    use std::os::unix::fs::MetadataExt;
    let mut metadata = None;
    let bytes = crate::safe_state::BoundedRegularReader::read_tree_no_follow_validated(
        path,
        cap,
        |current| {
            ensure!(
                !executable || current.mode() & 0o111 != 0,
                "authored check interpreter is not executable"
            );
            ensure!(current.len() > 0, "authored check input is empty");
            metadata = Some(current.clone());
            Ok(())
        },
    )?;
    let after = metadata.context("authored check descriptor metadata is missing")?;
    Ok((
        BoundFile {
            path: path.to_path_buf(),
            sha256: crate::artifacts::state_auth::sha256_hex(&bytes),
            identity: (after.dev(), after.ino()),
            mode: after.mode(),
            modified: (after.mtime(), after.mtime_nsec()),
            changed: (after.ctime(), after.ctime_nsec()),
        },
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use serde_json::Value;
    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
    };

    #[test]
    fn declarations_preserve_portable_paths_without_acquiring_authority() -> Result<()> {
        let plan = json!({"task":"Repair source", "assignments":[{
            "id":"parent", "phase":"execution", "assigned_paths":["src/identifier.py"],
            "worker_assignments":[{"id":"identifier", "assigned_paths":["src/identifier.py"]}],
            "authored_independent_checks":[{
                "worker_id":"identifier", "assigned_paths":["src/identifier.py"],
                "check_path":"checks/check_identifier.py",
                "argv":["/usr/bin/python3", "-I", "-B", "checks/check_identifier.py"]
            }]
        }]});
        let loaded =
            super::super::plan_api::parse_supervisor_plan_with_consultant(&plan.to_string())?;
        assert_eq!(
            loaded.assignment_metadata.authored_independent_checks["parent"][0].assigned_paths,
            ["src/identifier.py"]
        );
        let mut metadata = loaded.assignment_metadata.clone();
        metadata.retain_assignment("another-parent");
        assert!(metadata.authored_independent_checks.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    fn commit(repo: &git2::Repository) -> Result<()> {
        let mut index = repo.index()?;
        index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = git2::Signature::now("Check tests", "checks@example.invalid")?;
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Snapshot",
            &tree,
            &parent.iter().collect::<Vec<_>>(),
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn fixture() -> Result<(tempfile::TempDir, Value, SemanticRiskReport)> {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        fs::create_dir(root.join("src"))?;
        fs::create_dir(root.join("checks"))?;
        for subject in ["identifier", "duration"] {
            fs::write(root.join(format!("src/{subject}.py")), "value = 1\n")?;
            fs::write(root.join(format!("checks/check_{subject}.py")), format!(
                "import importlib.util\nspec = importlib.util.spec_from_file_location('subject', 'src/{subject}.py')\nsubject = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(subject)\nassert subject.value == 1\n"
            ))?;
        }
        let repo = git2::Repository::init(root)?;
        commit(&repo)?;
        let interpreter = ["/usr/bin/python3", "/bin/python3"]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .context("Python 3 fixture interpreter is missing")?;
        let mut checks = Vec::new();
        let mut workers = Vec::new();
        for subject in ["identifier", "duration"] {
            let assigned = format!("src/{subject}.py");
            let check = format!("checks/check_{subject}.py");
            workers.push(json!({"id":subject, "assigned_paths":[assigned], "task":"Repair the declared source"}));
            checks.push(
                json!({"worker_id":subject, "assigned_paths":[assigned], "check_path":check,
                "argv":[interpreter, "-I", "-B", check]}),
            );
        }
        let plan = json!({"task":"Repair identifier and duration", "assignments":[{
            "id":"parent", "phase":"execution", "assigned_paths":["src/identifier.py", "src/duration.py"],
            "worker_assignments":workers, "authored_independent_checks":checks
        }]});
        let risk = SemanticRiskReport {
            changed_paths: vec!["src/identifier.py".into(), "src/duration.py".into()],
            touched_files: Vec::new(),
            touched_symbols: Vec::new(),
            dependency_impacts: Vec::new(),
            impacted_files: Vec::new(),
            errors: Vec::new(),
        };
        Ok((temp, plan, risk))
    }

    #[test]
    #[cfg(unix)]
    fn declarations_bind_exact_independent_files() -> Result<()> {
        let (temp, plan, risk) = fixture()?;
        assert!(risk.dependency_impacts.is_empty());
        let evidence = acquire(temp.path(), &plan.to_string(), "parent", &risk)?;
        assert_eq!(evidence.files.len(), 4);
        evidence.revalidate(temp.path(), &plan.to_string(), &risk)?;
        // Neither acquisition nor revalidation executes the Python checks.
        assert!(!temp.path().join("src/__pycache__").exists());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn declarations_reject_unrelated_commands_and_write_scopes() -> Result<()> {
        let (temp, plan, risk) = fixture()?;
        for case in 0..14 {
            let mut changed = plan.clone();
            let mut risk = risk.clone();
            let parent = &mut changed["assignments"][0];
            match case {
                0 => parent["authored_independent_checks"][0]["argv"][0] = json!("python3"),
                1 => parent["authored_independent_checks"][0]["argv"][0] = json!("/bin/sh"),
                2 => parent["authored_independent_checks"][0]["argv"][1] = json!("-c"),
                3 => {
                    parent["authored_independent_checks"][0]["argv"][3] =
                        json!("checks/check_duration.py")
                }
                4 => parent["authored_independent_checks"][0]["worker_id"] = json!("other"),
                5 => {
                    parent["authored_independent_checks"][0]["assigned_paths"] =
                        json!(["src/duration.py"])
                }
                6 => parent["authored_independent_checks"][0]["check_path"] = json!("../check.py"),
                7 => {
                    parent["authored_independent_checks"][0]["check_path"] =
                        json!("checks\\check.py")
                }
                8 => parent["authored_independent_checks"][0]["receipt"] = json!({"valid":true}),
                9 => {
                    parent["assigned_paths"] =
                        json!(["src/identifier.py", "src/duration.py", "checks"])
                }
                10 => parent["worker_assignments"][0]["authored_independent_checks"] = json!([]),
                11 => parent["authored_independent_checks"]
                    .as_array_mut()
                    .unwrap()
                    .truncate(1),
                12 => {
                    parent["worker_assignments"][0]["assigned_paths"] =
                        json!(["checks/check_identifier.py"]);
                    parent["assigned_paths"] =
                        json!(["checks/check_identifier.py", "src/duration.py"]);
                    parent["authored_independent_checks"][0]["assigned_paths"] =
                        json!(["checks/check_identifier.py"]);
                    risk.changed_paths = vec![
                        "checks/check_identifier.py".into(),
                        "src/duration.py".into(),
                    ];
                }
                13 => risk.errors.push(crate::repo_semantic::SemanticScanError {
                    file: "src/identifier.py".into(),
                    kind: crate::repo_semantic::SemanticScanErrorKind::Parse,
                    message: "injected parse error".into(),
                    span: None,
                }),
                _ => unreachable!(),
            }
            let error = acquire(temp.path(), &changed.to_string(), "parent", &risk)
                .expect_err("invalid authored check declaration must refuse");
            let expected = match case {
                12 => Some("authored check overlaps a plan write scope"),
                13 => Some("authored checks require semantic risk without scan errors"),
                _ => None,
            };
            if let Some(expected) = expected {
                assert!(
                    format!("{error:#}").contains(expected),
                    "case {case}: {error:#}"
                );
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn declarations_reject_sibling_write_scopes() -> Result<()> {
        let (temp, plan, risk) = fixture()?;
        for role in ["worker", "child_orchestrator"] {
            for scope in ["checks/check_identifier.py", "checks"] {
                let mut changed = plan.clone();
                changed["max_child_assignments"] = json!(2);
                let mut sibling = json!({
                    "id":"sibling", "phase":"execution", "role":role,
                    "assigned_paths":[scope]
                });
                if role == "worker" {
                    sibling["role_category"] = json!("non_delegating_terminal_worker");
                }
                changed["assignments"].as_array_mut().unwrap().push(sibling);
                let error = acquire(temp.path(), &changed.to_string(), "parent", &risk)
                    .expect_err("sibling cannot write an authored check");
                assert!(
                    format!("{error:#}").contains("authored check overlaps a plan write scope"),
                    "role={role}, scope={scope}: {error:#}"
                );
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn acquired_evidence_refuses_drift() -> Result<()> {
        for case in 0..9 {
            let (temp, mut plan, mut risk) = fixture()?;
            let evidence = acquire(temp.path(), &plan.to_string(), "parent", &risk)?;
            let check = temp.path().join("checks/check_identifier.py");
            match case {
                0 => fs::write(&check, "assert False\n")?,
                1 => plan["task"] = json!("Different task"),
                2 => {
                    plan["assignments"][0]["worker_assignments"][0]["task"] =
                        json!("Different Worker task")
                }
                3 => {
                    plan["assignments"][0]["authored_independent_checks"][0]["argv"][2] =
                        json!("-I")
                }
                4 => risk
                    .impacted_files
                    .push("checks/check_identifier.py".into()),
                5 => {
                    fs::write(temp.path().join("new.txt"), "changed snapshot")?;
                    commit(&git2::Repository::open(temp.path())?)?;
                }
                6 => {
                    let bytes = fs::read(&check)?;
                    let replacement = temp.path().join("replacement.py");
                    fs::write(&replacement, bytes)?;
                    fs::rename(replacement, &check)?;
                }
                7 => {
                    plan["assignments"][0]["assigned_paths"][0] = json!("src/other.py");
                }
                8 => {
                    // A fully valid new declaration still cannot reuse the old receipt.
                    let mut changed = plan["assignments"][0]["authored_independent_checks"]
                        .as_array()
                        .unwrap()
                        .clone();
                    changed.swap(0, 1);
                    plan["assignments"][0]["authored_independent_checks"] = json!(changed);
                }
                _ => unreachable!(),
            }
            assert!(
                evidence
                    .revalidate(temp.path(), &plan.to_string(), &risk)
                    .is_err(),
                "case {case}"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn checks_refuse_non_snapshot_files_and_identity_substitutions() -> Result<()> {
        for case in 0..9 {
            let (temp, mut plan, risk) = fixture()?;
            let aliases = tempfile::tempdir()?;
            let check = temp.path().join("checks/check_identifier.py");
            match case {
                0 => fs::remove_file(&check)?,
                1 => {
                    fs::remove_file(&check)?;
                    fs::create_dir(&check)?;
                }
                2 => {
                    fs::remove_file(&check)?;
                    symlink("check_duration.py", &check)?;
                    commit(&git2::Repository::open(temp.path())?)?;
                }
                3 => fs::hard_link(&check, aliases.path().join("alias.py"))?,
                4 => {
                    fs::write(&check, "")?;
                    commit(&git2::Repository::open(temp.path())?)?;
                }
                5 => {
                    let interpreter_dir = tempfile::tempdir()?;
                    let interpreter = interpreter_dir.path().join("python3");
                    fs::write(&interpreter, "unexecutable")?;
                    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o600))?;
                    plan["assignments"][0]["authored_independent_checks"][0]["argv"][0] =
                        json!(interpreter);
                    assert!(acquire(temp.path(), &plan.to_string(), "parent", &risk).is_err());
                    continue;
                }
                6 => {
                    fs::write(temp.path().join("checks/untracked.py"), "assert True\n")?;
                    plan["assignments"][0]["authored_independent_checks"][0]["check_path"] =
                        json!("checks/untracked.py");
                    plan["assignments"][0]["authored_independent_checks"][0]["argv"][3] =
                        json!("checks/untracked.py");
                }
                7 => {
                    let checks = temp.path().join("checks");
                    fs::rename(&checks, temp.path().join("original-checks"))?;
                    symlink("original-checks", checks)?;
                }
                8 => {
                    fs::write(&check, vec![b'x'; 1024 * 1024 + 1])?;
                    commit(&git2::Repository::open(temp.path())?)?;
                }
                _ => unreachable!(),
            }
            assert!(
                acquire(temp.path(), &plan.to_string(), "parent", &risk).is_err(),
                "case {case}"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn interpreter_identity_is_bound_without_execution() -> Result<()> {
        let (temp, mut plan, risk) = fixture()?;
        let runtime = tempfile::tempdir()?;
        let interpreter = runtime.path().join("python3");
        let source = fs::canonicalize(
            plan["assignments"][0]["authored_independent_checks"][0]["argv"][0]
                .as_str()
                .unwrap(),
        )?;
        fs::copy(&source, &interpreter)?;
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o755))?;
        for check in plan["assignments"][0]["authored_independent_checks"]
            .as_array_mut()
            .unwrap()
        {
            check["argv"][0] = json!(interpreter);
        }
        let evidence = acquire(temp.path(), &plan.to_string(), "parent", &risk)?;
        evidence.revalidate(temp.path(), &plan.to_string(), &risk)?;
        let replacement = runtime.path().join("replacement");
        fs::copy(&source, &replacement)?;
        fs::rename(replacement, &interpreter)?;
        assert!(evidence
            .revalidate(temp.path(), &plan.to_string(), &risk)
            .is_err());
        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o600))?;
        assert!(acquire(temp.path(), &plan.to_string(), "parent", &risk).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn index_flags_cannot_hide_snapshot_drift() -> Result<()> {
        let (temp, plan, risk) = fixture()?;
        let evidence = acquire(temp.path(), &plan.to_string(), "parent", &risk)?;
        let repo = git2::Repository::open(temp.path())?;
        let mut index = repo.index()?;
        let subject = Path::new("src/identifier.py");
        let mut entry = index
            .get_path(subject, 0)
            .context("indexed subject is missing")?;
        entry.flags |= 0x8000;
        index.add(&entry)?;
        index.write()?;
        assert_ne!(
            repo.index()?.get_path(subject, 0).unwrap().flags & 0x8000,
            0
        );
        fs::write(temp.path().join(subject), "value = 2\n")?;
        assert!(acquire(temp.path(), &plan.to_string(), "parent", &risk).is_err());
        assert!(evidence
            .revalidate(temp.path(), &plan.to_string(), &risk)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn plan_roundtrip_restores_declarations_only() -> Result<()> {
        let (temp, plan, risk) = fixture()?;
        let loaded = super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
            &plan.to_string(),
            Some(temp.path()),
        )?;
        let canonical = super::super::plan_api::supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )?;
        assert_eq!(
            canonical["assignments"][0]["authored_independent_checks"],
            plan["assignments"][0]["authored_independent_checks"]
        );
        let restored = super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
            &canonical.to_string(),
            Some(temp.path()),
        )?;
        assert_eq!(restored.assignment_metadata, loaded.assignment_metadata);
        let evidence = acquire(temp.path(), &canonical.to_string(), "parent", &risk)?;
        fs::write(
            temp.path().join("checks/check_identifier.py"),
            "assert False\n",
        )?;
        // Restoring declarations remains possible, but cannot restore authority.
        super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
            &canonical.to_string(),
            Some(temp.path()),
        )?;
        assert!(evidence
            .revalidate(temp.path(), &canonical.to_string(), &risk)
            .is_err());
        assert!(acquire(temp.path(), &canonical.to_string(), "parent", &risk).is_err());
        Ok(())
    }
}
