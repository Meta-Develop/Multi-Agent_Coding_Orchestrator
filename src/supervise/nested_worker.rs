//! Supervisor-owned admission, distinct from both process launch grants and wire reports.
//! A nested subject borrows the enclosing assignment's resources; it never acquires a
//! second worktree or claim. Admission does not launch a process or enable an IPC operation.

use super::*;

/// Only the assignment executor can construct this view of the current attempt.
/// Neither child JSON nor a messaging bearer can supply one of these resource leases.
pub(super) struct AssignmentAttemptAuthority<'a> {
    repo: &'a Path,
    run_id: &'a RunId,
    attempt: usize,
    parent: &'a OrchestratorAssignment,
    journal_parent_id: &'a str,
    worktree: &'a WorktreeRecord,
    lease: &'a ManagedWorktreeWriteLease,
    claim: &'a PathClaim,
    manager: &'a WorktreeManager,
    sync_store: &'a SyncStore,
    semantic_store: &'a SemanticIntentStore,
    held_semantic_token: Option<u64>,
    cancellation: &'a ProcessCancellation,
    run_cancellation: &'a ProcessCancellation,
}

impl<'a> AssignmentAttemptAuthority<'a> {
    pub(super) fn from_preflight(
        context: &'a AssignmentExecutionContext<'_, '_>,
        preflight: &'a AssignmentExecutionPreflight<'_>,
        attempt: usize,
    ) -> Result<Self> {
        if context.assignment.id != preflight.assignment.id {
            bail!("assignment admission parent differs from current execution context");
        }
        Ok(Self {
            repo: context.repo,
            run_id: &context.options.run_id,
            attempt,
            parent: &preflight.assignment,
            journal_parent_id: preflight.journal_parent_id,
            worktree: &preflight.worktree,
            lease: preflight
                .worktree_write_lease
                .as_ref()
                .context("assignment admission requires the parent's managed write lease")?,
            claim: &preflight.claim,
            manager: context.manager,
            sync_store: context.sync_store,
            semantic_store: context.semantic_store,
            held_semantic_token: if context.plan.semantic_coordination
                == SemanticCoordinationMode::Block
            {
                Some(
                    preflight
                        .semantic_token
                        .context("blocking semantic admission requires a held intent")?,
                )
            } else {
                None
            },
            cancellation: preflight.managed_process_cancellation.cancellation(),
            run_cancellation: &context.cancellation,
        })
    }

    /// `subject_id` is selected by the supervisor from its authored plan, never a child
    /// command description. Resolve the complete worker here rather than accepting a
    /// caller-supplied WorkerAssignment with a matching ID and widened scope.
    pub(super) fn admit(
        &self,
        subject_id: &str,
        command: &ExternalAgentCommand,
        runtime: SupervisorRuntime,
    ) -> Result<AssignmentCommandAdmission> {
        let semantic_intent = self.verify_resources()?;
        let (role, parent_id, paths) = if subject_id == self.parent.id {
            (
                self.parent.role,
                self.journal_parent_id,
                &self.parent.assigned_paths,
            )
        } else {
            if self.parent.role != AgentRole::ChildOrchestrator {
                bail!("nested worker admission requires a ChildOrchestrator resource owner");
            }
            let mut authored = self
                .parent
                .worker_assignments
                .iter()
                .filter(|worker| worker.id == subject_id);
            let worker = authored
                .next()
                .context("nested worker ID is not authored under this parent")?;
            if authored.next().is_some() || worker.role != AgentRole::Worker {
                bail!("nested worker admission requires one exact authored Worker");
            }
            if normalize_paths(worker.assigned_paths.clone())? != worker.assigned_paths
                || worker.assigned_paths.is_empty()
                || worker.assigned_paths.iter().any(|path| {
                    !self
                        .parent
                        .assigned_paths
                        .iter()
                        .any(|parent| path_is_covered_by_claim(path, parent))
                })
                || worker
                    .semantic_symbols
                    .iter()
                    .any(|symbol| !self.parent.semantic_symbols.contains(symbol))
                || worker
                    .semantic_modules
                    .iter()
                    .any(|module| !self.parent.semantic_modules.contains(module))
            {
                bail!("nested worker paths and semantic scope must be a canonical parent subset");
            }
            (
                AgentRole::Worker,
                self.parent.id.as_str(),
                &worker.assigned_paths,
            )
        };
        let identity = command
            .agent_lifecycle
            .as_ref()
            .context("assignment admission requires a supervisor-bound lifecycle identity")?;
        if identity.registry_repo != self.repo
            || identity.run_id != self.run_id.as_str()
            || identity.task_id != subject_id
            || identity.role != role.as_str()
            || identity.parent.as_deref() != Some(parent_id)
            || command.cwd != self.worktree.path
            || command.assignment_process_launch_attempt != Some(self.attempt)
        {
            bail!("assignment admission command does not bind the current run, parent, subject and attempt");
        }
        command.verify_assignment_child_admission_identity()?;
        if command.workspace_access != WorkspaceAccess::ReadWrite
            || command.writable_launch_target
                != crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree
        {
            bail!("assignment admission requires a writable managed worktree command");
        }
        if assignment_worktree_control_exceptions(paths)? != command.worktree_control_exceptions {
            bail!("assignment admission command widens its authored control path scope");
        }
        let expected_invocation = match runtime {
            SupervisorRuntime::Codex => {
                crate::external_agent::ExternalAgentInvocation::CodexSupervisor
            }
            SupervisorRuntime::Grok => crate::external_agent::ExternalAgentInvocation::Grok,
            SupervisorRuntime::Cursor => crate::external_agent::ExternalAgentInvocation::Cursor,
            SupervisorRuntime::ClaudeCode => {
                crate::external_agent::ExternalAgentInvocation::ClaudeCode
            }
            SupervisorRuntime::GeminiCli => {
                crate::external_agent::ExternalAgentInvocation::GeminiCli
            }
            SupervisorRuntime::Fake => bail!("assignment admission refuses a simulated runtime"),
        };
        if command.invocation != expected_invocation {
            bail!("assignment admission runtime differs from the selected command");
        }
        let capabilities = command.selected_writable_capabilities(runtime, Some(subject_id))?;
        if capabilities
            .writable_launch_refusal(command.writable_launch_target)
            .is_some()
            || capabilities.side_effect_confinement
                != crate::runtime_adapter::SideEffectConfinement::Verified
        {
            bail!("assignment admission requires verified native confinement");
        }
        Ok(AssignmentCommandAdmission {
            repo: self.repo.to_path_buf(),
            claims_state: self.sync_store.state_path().to_path_buf(),
            semantic_state: self.semantic_store.state_path().to_path_buf(),
            run_id: self.run_id.clone(),
            attempt: self.attempt,
            parent: self.parent.clone(),
            worktree: self.worktree.clone(),
            claim: self.claim.clone(),
            subject_id: subject_id.to_owned(),
            runtime,
            command: command.clone(),
            semantic_intent,
            cancellation: self.cancellation.clone(),
            run_cancellation: self.run_cancellation.clone(),
        })
    }

    fn verify_resources(&self) -> Result<Option<SemanticIntent>> {
        if self.attempt == 0 || self.parent.phase != AssignmentPhase::Execution {
            bail!("assignment admission requires a current execution attempt");
        }
        if self.cancellation.is_cancelled() || self.run_cancellation.is_cancelled() {
            bail!("assignment admission authority has been revoked");
        }
        if self.worktree != self.lease.record()
            || self.worktree.name != self.parent.id
            || self.claim.agent_id != self.parent.id
            || self.claim.paths != self.parent.assigned_paths
        {
            bail!("assignment admission resource owner binding changed");
        }
        self.manager
            .verify_write_execution_lease(&self.parent.id, self.lease)?;
        if !self.sync_store.status_snapshot()?.iter().any(|held| {
            held.claim == *self.claim && held.owner_run_id.as_deref() == Some(self.run_id.as_str())
        }) {
            bail!("assignment admission parent claim is no longer held by this run");
        }
        self.held_semantic_token
            .map(|token| {
                self.semantic_store
                    .snapshot()?
                    .into_iter()
                    .find(|intent| {
                        intent.token.get() == token
                            && intent.agent_id == self.parent.id
                            && intent.paths == self.parent.assigned_paths
                    })
                    .context("assignment admission parent semantic intent is no longer held")
            })
            .transpose()
    }
}

/// In-memory, non-serializable binding to an exact selected command. This is an
/// admission primitive, not a process-launch grant: a future nested dispatcher must
/// revalidate against its current attempt immediately before the existing launch gates.
/// The parent continues to own both resource leases and cancellation.
#[derive(Debug)]
pub(super) struct AssignmentCommandAdmission {
    repo: PathBuf,
    claims_state: PathBuf,
    semantic_state: PathBuf,
    run_id: RunId,
    attempt: usize,
    parent: OrchestratorAssignment,
    worktree: WorktreeRecord,
    claim: PathClaim,
    subject_id: String,
    runtime: SupervisorRuntime,
    command: ExternalAgentCommand,
    semantic_intent: Option<SemanticIntent>,
    cancellation: ProcessCancellation,
    run_cancellation: ProcessCancellation,
}

impl AssignmentCommandAdmission {
    pub(super) fn revalidate(
        &self,
        current: &AssignmentAttemptAuthority<'_>,
        subject_id: &str,
        command: &ExternalAgentCommand,
    ) -> Result<()> {
        if self.repo != current.repo
            || self.claims_state != current.sync_store.state_path()
            || self.semantic_state != current.semantic_store.state_path()
            || self.run_id != *current.run_id
            || self.attempt != current.attempt
            || self.parent != *current.parent
            || self.worktree != *current.worktree
            || self.claim != *current.claim
            || self.subject_id != subject_id
            || self.command != *command
        {
            bail!("assignment admission is stale or its parent, worker, attempt, resources or command were substituted");
        }
        if self.cancellation.is_cancelled() || self.run_cancellation.is_cancelled() {
            bail!("assignment admission original authority has been revoked");
        }
        let refreshed = current.admit(subject_id, command, self.runtime)?;
        if refreshed.semantic_intent != self.semantic_intent {
            bail!("assignment admission semantic authority changed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: PathBuf,
        manager: WorktreeManager,
        lease: ManagedWorktreeWriteLease,
        worktree: WorktreeRecord,
        sync_store: SyncStore,
        semantic_store: SemanticIntentStore,
        claim: PathClaim,
        run_id: RunId,
        parent: OrchestratorAssignment,
        cancellation: ProcessCancellation,
        run_cancellation: ProcessCancellation,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let temp = tempfile::tempdir()?;
            let repo = temp.path().join("repo");
            WorktreeManager::init_repository(&repo, "main")?;
            let git = crate::git_repository::open(&repo)?;
            std::fs::create_dir(repo.join("src"))?;
            std::fs::write(repo.join("src/lib.rs"), "pub fn selected() {}\n")?;
            let mut index = git.index()?;
            index.add_path(Path::new("src/lib.rs"))?;
            index.write()?;
            let tree = git.find_tree(index.write_tree()?)?;
            let signature = git2::Signature::now("test", "test@example.com")?;
            git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
            let parent: OrchestratorAssignment = serde_json::from_value(json!({
                "id": "parent", "phase": "execution", "role": "child_orchestrator",
                "assigned_paths": ["src"],
                "semantic_symbols": ["crate::selected"],
                "semantic_modules": ["crate"],
                "worker_assignments": [{
                    "id": "worker", "role": "worker", "assigned_paths": ["src/lib.rs"],
                    "semantic_symbols": ["crate::selected"], "semantic_modules": ["crate"]
                }, {
                    "id": "sibling", "role": "worker", "assigned_paths": ["src/other.rs"]
                }]
            }))?;
            let manager = WorktreeManager::new(&repo);
            let worktree = manager.create(crate::worktree::WorktreeCreateOptions {
                agent_id: parent.id.clone(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("worktrees")),
            })?;
            let lease = manager.acquire_write_execution_lease(&parent.id)?;
            let sync_store = SyncStore::open(&repo)?;
            let semantic_store = SemanticIntentStore::open(&repo)?;
            let run_id = RunId::new("admission-run")?;
            let claim =
                sync_store.claim_paths_for_run(&run_id, &parent.id, &parent.assigned_paths)?;
            Ok(Self {
                _temp: temp,
                repo,
                manager,
                lease,
                worktree,
                sync_store,
                semantic_store,
                claim,
                run_id,
                parent,
                cancellation: ProcessCancellation::new(),
                run_cancellation: ProcessCancellation::new(),
            })
        }

        fn authority(&self) -> AssignmentAttemptAuthority<'_> {
            AssignmentAttemptAuthority {
                repo: &self.repo,
                run_id: &self.run_id,
                attempt: 1,
                parent: &self.parent,
                journal_parent_id: self.run_id.as_str(),
                worktree: &self.worktree,
                lease: &self.lease,
                claim: &self.claim,
                manager: &self.manager,
                sync_store: &self.sync_store,
                semantic_store: &self.semantic_store,
                held_semantic_token: None,
                cancellation: &self.cancellation,
                run_cancellation: &self.run_cancellation,
            }
        }

        fn command(&self, subject: &str) -> Result<ExternalAgentCommand> {
            let (role, parent) = if subject == self.parent.id {
                (self.parent.role, self.run_id.as_str())
            } else {
                (AgentRole::Worker, self.parent.id.as_str())
            };
            let command = ExternalAgentCommand::codex(
                Path::new("unused-codex"),
                &self.worktree.path,
                Path::new("prompt.md"),
                Path::new("events.jsonl"),
                Path::new("report.json"),
                Duration::from_secs(30),
            )
            .with_agent_lifecycle(&self.repo, role.as_str(), self.run_id.as_str(), subject)
            .with_agent_parent(parent);
            let grant = admit_assignment_child_process_intent(
                self.run_id.as_str(),
                subject,
                1,
                Path::new("codex"),
                None,
                ASSIGNMENT_CHILD_PROCESS_DUTY,
            )?;
            Ok(command.with_assignment_process_launch(
                AssignmentProcessLaunchKind::AssignmentChild,
                grant,
            ))
        }
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_borrows_parent_resources_and_binds_exact_subject() -> Result<()> {
        let fixture = Fixture::new()?;
        let authority = fixture.authority();
        let before = fixture.sync_store.snapshot()?;
        let command = fixture.command("worker")?;
        let admission = authority.admit("worker", &command, SupervisorRuntime::Codex)?;
        assert_eq!(admission.subject_id, "worker");
        assert_eq!(admission.worktree.name, "parent");
        assert_eq!(admission.claim.agent_id, "parent");
        assert_eq!(
            admission.command, command,
            "admission must not mutate a launch"
        );
        admission.revalidate(&authority, "worker", &command)?;
        assert_eq!(
            fixture.sync_store.snapshot()?,
            before,
            "no worker claim is acquired"
        );
        assert_eq!(fixture.manager.list_managed_verified()?.len(), 1);
        assert!(admission
            .revalidate(&authority, "sibling", &fixture.command("sibling")?)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_refuses_unknown_or_substituted_lifecycle_and_intent() -> Result<()> {
        let fixture = Fixture::new()?;
        let authority = fixture.authority();
        let original = fixture.command("worker")?;
        assert!(authority
            .admit(
                "unknown",
                &fixture.command("unknown")?,
                SupervisorRuntime::Codex
            )
            .is_err());
        for field in [
            "parent", "worker", "run", "role", "repo", "attempt", "grant", "kind",
        ] {
            let mut command = original.clone();
            let identity = command.agent_lifecycle.as_mut().unwrap();
            match field {
                "parent" => identity.parent = Some("other-parent".into()),
                "worker" => identity.task_id = "sibling".into(),
                "run" => identity.run_id = "other-run".into(),
                "role" => identity.role = AgentRole::ChildOrchestrator.as_str().into(),
                "repo" => identity.registry_repo = fixture.repo.join("other"),
                "attempt" => command.assignment_process_launch_attempt = Some(2),
                "grant" => command.assignment_process_launch_grant = None,
                "kind" => command.assignment_process_launch_kind = None,
                _ => unreachable!(),
            }
            assert!(
                authority
                    .admit("worker", &command, SupervisorRuntime::Codex)
                    .is_err(),
                "accepted {field}"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_refuses_widened_paths_semantics_and_nonterminal_roles() -> Result<()> {
        let fixture = Fixture::new()?;
        let command = fixture.command("worker")?;
        for change in [
            "path",
            "escape",
            "root",
            "empty",
            "symbol",
            "module",
            "role",
            "duplicate",
            "parent-role",
            "phase",
        ] {
            let mut parent = fixture.parent.clone();
            match change {
                "path" => parent.worker_assignments[0].assigned_paths = vec!["src-other".into()],
                "escape" => {
                    parent.worker_assignments[0].assigned_paths = vec!["src/../README.md".into()]
                }
                "root" => parent.worker_assignments[0].assigned_paths = vec![".".into()],
                "empty" => parent.worker_assignments[0].assigned_paths.clear(),
                "symbol" => parent.worker_assignments[0]
                    .semantic_symbols
                    .push("crate::other".into()),
                "module" => parent.worker_assignments[0]
                    .semantic_modules
                    .push("crate_other".into()),
                "role" => parent.worker_assignments[0].role = AgentRole::ChildOrchestrator,
                "duplicate" => parent
                    .worker_assignments
                    .push(parent.worker_assignments[0].clone()),
                "parent-role" => parent.role = AgentRole::Worker,
                "phase" => parent.phase = AssignmentPhase::Planning,
                _ => unreachable!(),
            }
            let authority = AssignmentAttemptAuthority {
                parent: &parent,
                ..fixture.authority()
            };
            assert!(
                authority
                    .admit("worker", &command, SupervisorRuntime::Codex)
                    .is_err(),
                "accepted {change}"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_refuses_stale_command_and_attempt_replay() -> Result<()> {
        let fixture = Fixture::new()?;
        let authority = fixture.authority();
        let original = fixture.command("worker")?;
        let admission = authority.admit("worker", &original, SupervisorRuntime::Codex)?;
        for field in [
            "program",
            "cwd",
            "model",
            "effort",
            "prompt",
            "schema",
            "timeout",
            "paths",
            "role",
            "invocation",
        ] {
            let mut command = original.clone();
            match field {
                "program" => command.program = "other-program".into(),
                "cwd" => command.cwd = fixture.repo.clone(),
                "model" => command.model = Some("other-model".into()),
                "effort" => command.reasoning_effort = Some("low".into()),
                "prompt" => command.prompt = "other-prompt".into(),
                "schema" => command.output_schema = Some("other-schema".into()),
                "timeout" => command.timeout += Duration::from_secs(1),
                "paths" => command.worktree_control_exceptions.push("AGENTS.md".into()),
                "role" => {
                    command.agent_lifecycle.as_mut().unwrap().role = "child_orchestrator".into()
                }
                "invocation" => {
                    command.invocation = crate::external_agent::ExternalAgentInvocation::Grok
                }
                _ => unreachable!(),
            }
            assert!(
                admission
                    .revalidate(&authority, "worker", &command)
                    .is_err(),
                "accepted stale {field}"
            );
        }
        let next_attempt = AssignmentAttemptAuthority {
            attempt: 2,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&next_attempt, "worker", &original)
            .is_err());
        let mut parent = fixture.parent.clone();
        parent.worker_assignments[0].assigned_paths = vec!["src".into()];
        let changed_scope = AssignmentAttemptAuthority {
            parent: &parent,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&changed_scope, "worker", &original)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_reauthenticates_claim_and_cancellation() -> Result<()> {
        let fixture = Fixture::new()?;
        let authority = fixture.authority();
        let command = fixture.command("worker")?;
        let admission = authority.admit("worker", &command, SupervisorRuntime::Codex)?;
        fixture.sync_store.release(fixture.claim.token)?;
        assert!(admission
            .revalidate(&authority, "worker", &command)
            .is_err());
        let replacement = fixture.sync_store.claim_paths_for_run(
            &fixture.run_id,
            &fixture.parent.id,
            &fixture.parent.assigned_paths,
        )?;
        assert_ne!(replacement.token, fixture.claim.token);
        assert!(admission
            .revalidate(&authority, "worker", &command)
            .is_err());
        let changed_claim = AssignmentAttemptAuthority {
            claim: &replacement,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&changed_claim, "worker", &command)
            .is_err());
        let fresh = changed_claim.admit("worker", &command, SupervisorRuntime::Codex)?;
        fixture.cancellation.cancel();
        assert!(fresh
            .revalidate(&changed_claim, "worker", &command)
            .is_err());
        let live_cancellation = ProcessCancellation::new();
        let substituted_cancellation = AssignmentAttemptAuthority {
            cancellation: &live_cancellation,
            ..changed_claim
        };
        assert!(fresh
            .revalidate(&substituted_cancellation, "worker", &command)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_refuses_substituted_worktree_lease_parent_and_run() -> Result<()> {
        let fixture = Fixture::new()?;
        let other = Fixture::new()?;
        let command = fixture.command("worker")?;
        let admission = fixture
            .authority()
            .admit("worker", &command, SupervisorRuntime::Codex)?;
        let wrong_lease = AssignmentAttemptAuthority {
            lease: &other.lease,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_lease, "worker", &command)
            .is_err());
        let wrong_store = AssignmentAttemptAuthority {
            sync_store: &other.sync_store,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_store, "worker", &command)
            .is_err());
        let wrong_semantic_store = AssignmentAttemptAuthority {
            semantic_store: &other.semantic_store,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_semantic_store, "worker", &command)
            .is_err());
        let mut worktree = fixture.worktree.clone();
        worktree.branch = "maco/substituted".into();
        let wrong_record = AssignmentAttemptAuthority {
            worktree: &worktree,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_record, "worker", &command)
            .is_err());
        let mut parent = fixture.parent.clone();
        parent.id = "substituted-parent".into();
        let wrong_parent = AssignmentAttemptAuthority {
            parent: &parent,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_parent, "worker", &command)
            .is_err());
        let run_id = RunId::new("other-run")?;
        let wrong_run = AssignmentAttemptAuthority {
            run_id: &run_id,
            ..fixture.authority()
        };
        assert!(admission
            .revalidate(&wrong_run, "worker", &command)
            .is_err());
        fixture.run_cancellation.cancel();
        assert!(admission
            .revalidate(&fixture.authority(), "worker", &command)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_refuses_unbound_claim_and_unverified_command() -> Result<()> {
        let fixture = Fixture::new()?;
        fixture.sync_store.release(fixture.claim.token)?;
        let unbound = fixture
            .sync_store
            .claim_paths(&fixture.parent.id, &fixture.parent.assigned_paths)?;
        let authority = AssignmentAttemptAuthority {
            claim: &unbound,
            ..fixture.authority()
        };
        let command = fixture.command("worker")?;
        assert!(authority
            .admit("worker", &command, SupervisorRuntime::Codex)
            .is_err());
        fixture.sync_store.release(unbound.token)?;
        let claim = fixture.sync_store.claim_paths_for_run(
            &fixture.run_id,
            &fixture.parent.id,
            &fixture.parent.assigned_paths,
        )?;
        let authority = AssignmentAttemptAuthority {
            claim: &claim,
            ..fixture.authority()
        };
        for runtime in [
            SupervisorRuntime::Fake,
            SupervisorRuntime::Cursor,
            SupervisorRuntime::Grok,
        ] {
            assert!(authority.admit("worker", &command, runtime).is_err());
        }
        let mut widened = command.clone();
        widened.worktree_control_exceptions.push("AGENTS.md".into());
        assert!(authority
            .admit("worker", &widened, SupervisorRuntime::Codex)
            .is_err());
        let primary = command.clone().with_writable_launch_target(
            crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree,
        );
        assert!(authority
            .admit("worker", &primary, SupervisorRuntime::Codex)
            .is_err());
        let read_only = command.with_workspace_access(WorkspaceAccess::ReadOnly);
        assert!(authority
            .admit("worker", &read_only, SupervisorRuntime::Codex)
            .is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn direct_worker_retains_its_own_resource_owner_and_writable_record() -> Result<()> {
        let mut fixture = Fixture::new()?;
        fixture.parent.role = AgentRole::Worker;
        fixture.parent.worker_assignments.clear();
        let command = fixture.command("parent")?;
        let authority = fixture.authority();
        let admission = authority.admit("parent", &command, SupervisorRuntime::Codex)?;
        admission.revalidate(&authority, "parent", &command)?;
        let record = worktree_writable_admission_record(
            &fixture.parent.id,
            &fixture.parent.assigned_paths,
            1,
            &fixture.worktree,
            &fixture.claim,
            &fixture.sync_store.snapshot()?,
            &command,
            SupervisorRuntime::Codex,
            AssignmentPhase::Execution,
        )?
        .context("direct worker writable admission")?;
        assert_eq!(record.assignment_id, fixture.parent.id);
        assert_eq!(record.worktree.worktree_id, fixture.parent.id);
        assert_eq!(record.claims.token, fixture.claim.token.get());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_worker_rejects_revoked_or_substituted_semantic_authority() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut request = crate::semantic_coord::SemanticIntentRequest::new("parent");
        request.paths = fixture.parent.assigned_paths.clone();
        let report = fixture.semantic_store.claim(request)?;
        assert!(report.persisted);
        let authority = AssignmentAttemptAuthority {
            held_semantic_token: Some(report.intent.token.get()),
            ..fixture.authority()
        };
        let command = fixture.command("worker")?;
        let admission = authority.admit("worker", &command, SupervisorRuntime::Codex)?;
        admission.revalidate(&authority, "worker", &command)?;
        assert!(admission
            .revalidate(&fixture.authority(), "worker", &command)
            .is_err());
        fixture.semantic_store.release(report.intent.token)?;
        assert!(admission
            .revalidate(&authority, "worker", &command)
            .is_err());
        Ok(())
    }
}
